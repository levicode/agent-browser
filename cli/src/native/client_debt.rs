//! Exact-owner command accounting. The response reader, not an RPC waiter,
//! settles submitted commands. Descriptors contain provenance only, never CDP
//! payloads, text, credentials, URLs, screenshots, or command error strings.
use super::cdp::types::{CdpEvent, CdpMessage};
use super::client_protocol::ProtocolError;
use super::client_session::{CancelSignal, OperationLease};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub(crate) const MAX_INPUT_DEBT: u32 = 32;
pub(crate) const MAX_OBJECT_DEBT: u32 = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) struct OperationKey {
    pub generation: u64,
    pub operation_seq: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionClass {
    Input,
    Reference,
    FixedRead,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CleanupDisposition {
    Complete,
    AccountedRemoteDebt,
    IntegrityLost,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct OperationDebtSnapshot {
    pub mutation_dispatched: bool,
    pub input_debt: u32,
    pub object_debt: u32,
    pub integrity_lost: bool,
    pub local_producers_finished: bool,
    pub submission_revoked: bool,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct OwnerDebtSnapshot {
    pub input_debt: u32,
    pub object_debt: u32,
    pub outstanding_commands: u32,
    pub descriptor_bytes: usize,
    pub integrity_lost: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommandCategory {
    ApplicationInput,
    ApplicationObject,
    ApplicationRead,
    CleanupObject,
    CleanupInput,
    CleanupOther,
    Recording,
    Security,
    Download,
    Enrollment,
    Destroy,
}
impl CommandCategory {
    fn index(self) -> usize {
        self as usize
    }
    fn limits(self) -> (usize, usize) {
        // Non-borrowing pools: application 64/192 KiB, cleanup 64/64 KiB,
        // resident services 128/256 KiB. Final destruction is never borrowed.
        match self {
            Self::ApplicationInput => (16, 64 * 1024),
            Self::ApplicationObject => (32, 96 * 1024),
            Self::ApplicationRead => (16, 32 * 1024),
            Self::CleanupObject => (32, 32 * 1024),
            Self::CleanupInput => (16, 16 * 1024),
            Self::CleanupOther => (16, 16 * 1024),
            Self::Recording => (64, 128 * 1024),
            Self::Security => (32, 64 * 1024),
            Self::Download => (16, 32 * 1024),
            Self::Enrollment => (15, 28 * 1024),
            Self::Destroy => (1, 4 * 1024),
        }
    }
    fn application(self) -> bool {
        matches!(
            self,
            Self::ApplicationInput | Self::ApplicationObject | Self::ApplicationRead
        )
    }
    fn input(self) -> bool {
        matches!(self, Self::ApplicationInput | Self::CleanupInput)
    }
}
#[derive(Clone, Default)]
struct JournalState {
    mutation_dispatched: bool,
    submission_revoked: bool,
    local_producers_finished: bool,
    integrity_lost: bool,
    admission: Option<(Instant, tokio::sync::watch::Receiver<CancelSignal>)>,
}
struct Journal {
    key: OperationKey,
    target: String,
    session: String,
    state: Mutex<JournalState>,
    ledger: std::sync::Weak<OwnerDebtLedger>,
    footprint: usize,
}
impl Drop for Journal {
    fn drop(&mut self) {
        if let Some(ledger) = self.ledger.upgrade() {
            if let Ok(mut state) = ledger.state.lock() {
                state.journal_bytes = state.journal_bytes.saturating_sub(self.footprint);
            }
        }
    }
}
#[derive(Clone)]
pub(crate) struct OperationJournalHandle {
    ledger: Arc<OwnerDebtLedger>,
    journal: Arc<Journal>,
}
tokio::task_local! {
    static CURRENT_OPERATION: OperationJournalHandle;
    static COMMAND_OVERRIDE: CommandOverride;
    static NATIVE_OBJECT_GROUP: String;
}
/// Only existing native group owners call this; never infer authority from a
/// CDP objectId or a caller-provided group string.
pub(crate) async fn native_object_group<F: Future>(group: &str, future: F) -> F::Output {
    NATIVE_OBJECT_GROUP.scope(group.to_owned(), future).await
}
#[derive(Clone, Copy)]
pub(crate) struct CommandOverride {
    pub category: CommandCategory,
    pub mutation: bool,
}
pub(crate) fn current_operation() -> Option<OperationJournalHandle> {
    CURRENT_OPERATION.try_with(Clone::clone).ok()
}
pub(crate) async fn command_scope<F: Future>(
    category: CommandCategory,
    mutation: bool,
    future: F,
) -> F::Output {
    COMMAND_OVERRIDE
        .scope(CommandOverride { category, mutation }, future)
        .await
}
impl OperationJournalHandle {
    pub(crate) fn current() -> Option<Self> {
        current_operation()
    }
    pub(crate) fn bind_operation(&self, operation: &OperationLease) -> Result<(), ProtocolError> {
        if operation.generation != self.key().generation
            || operation.sequence != self.key().operation_seq
        {
            return Err(ProtocolError::StaleScope);
        }
        let mut state = self
            .journal
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.admission.is_some() {
            return Err(ProtocolError::InvalidArguments);
        }
        state.admission = Some((operation.deadline, operation.cancellation.clone()));
        Ok(())
    }
    pub(crate) fn descriptor_bytes(&self) -> usize {
        self.journal.footprint
    }
    pub(crate) fn key(&self) -> OperationKey {
        self.journal.key
    }
    pub(crate) fn ledger(&self) -> Arc<OwnerDebtLedger> {
        self.ledger.clone()
    }
    pub(crate) async fn scope<F: Future>(&self, future: F) -> F::Output {
        CURRENT_OPERATION.scope(self.clone(), future).await
    }
    pub(crate) fn check_application_submission(&self) -> Result<(), ProtocolError> {
        let state = self
            .journal
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state
            .admission
            .as_ref()
            .is_some_and(|(deadline, cancellation)| {
                Instant::now() >= *deadline || *cancellation.borrow() != CancelSignal::None
            })
        {
            return Err(ProtocolError::Cancelled);
        }
        if state.integrity_lost || state.submission_revoked || state.local_producers_finished {
            Err(ProtocolError::Cancelled)
        } else {
            Ok(())
        }
    }
    pub(crate) fn revoke_application_submission(&self) {
        match self.journal.state.lock() {
            Ok(mut state) => state.submission_revoked = true,
            Err(error) => {
                let mut state = error.into_inner();
                state.submission_revoked = true;
                state.integrity_lost = true;
            }
        }
    }
    pub(crate) fn mark_mutation_maybe_submitted(&self) -> Result<(), ProtocolError> {
        let mut state = self
            .journal
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state
            .admission
            .as_ref()
            .is_some_and(|(deadline, cancellation)| {
                Instant::now() >= *deadline || *cancellation.borrow() != CancelSignal::None
            })
        {
            return Err(ProtocolError::Cancelled);
        }
        if state.integrity_lost || state.submission_revoked || state.local_producers_finished {
            return Err(ProtocolError::Cancelled);
        }
        state.mutation_dispatched = true;
        Ok(())
    }
    pub(crate) fn record_cleanup_disposition(&self, disposition: CleanupDisposition) {
        if disposition == CleanupDisposition::IntegrityLost {
            match self.journal.state.lock() {
                Ok(mut state) => state.integrity_lost = true,
                Err(error) => error.into_inner().integrity_lost = true,
            }
        }
        // Neither a complete local producer nor an accounted-debt classification
        // can clear reader-owned remote obligations or earlier integrity loss.
    }
    pub(crate) fn finish_local_producers(&self) {
        match self.journal.state.lock() {
            Ok(mut state) => {
                state.local_producers_finished = true;
                state.submission_revoked = true;
            }
            Err(error) => {
                let mut state = error.into_inner();
                state.local_producers_finished = true;
                state.submission_revoked = true;
                state.integrity_lost = true;
            }
        }
    }
    pub(crate) fn snapshot(&self) -> OperationDebtSnapshot {
        let (input_debt, object_debt, owner_lost) = self.ledger.operation_counts(self.key());
        match self.journal.state.lock() {
            Ok(state) => OperationDebtSnapshot {
                mutation_dispatched: state.mutation_dispatched,
                input_debt,
                object_debt,
                integrity_lost: owner_lost || state.integrity_lost,
                local_producers_finished: state.local_producers_finished,
                submission_revoked: state.submission_revoked,
            },
            Err(_) => OperationDebtSnapshot {
                input_debt,
                object_debt,
                integrity_lost: true,
                ..Default::default()
            },
        }
    }
    pub(crate) fn register_remote_obligation(
        &self,
        method: &str,
        params: Option<&Value>,
        session: Option<&str>,
    ) -> Result<CommandReservation, ProtocolError> {
        self.ledger
            .reserve_command(Some(self), method, params, session)
    }
    pub(crate) fn has_accounted_object_creation(&self, session: &str) -> bool {
        self.ledger.state.lock().is_ok_and(|state| {
            !state.integrity_lost
                && state.commands.values().any(|command| {
                    command.submitted
                        && command.provenance.operation == Some(self.key())
                        && command.provenance.session.as_deref() == Some(session)
                        && command.creation_slots > 0
                })
        })
    }
}
#[derive(Clone, Eq, PartialEq)]
struct Provenance {
    operation: Option<OperationKey>,
    target: Option<String>,
    session: Option<String>,
    // Realm epoch is captured from reader-observed creation. Numeric IDs alone
    // are never destruction authority across a reused execution context ID.
    realm: Option<(i64, u64)>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum CommandStatus {
    Reserved,
    Submitted,
    Acknowledged,
    RetainedRejected,
    Destroyed,
    Abandoned,
    IntegrityLost,
}
#[derive(Clone)]
pub(crate) struct CommandStatusHandle(Arc<AtomicU8>, bool);
impl CommandStatusHandle {
    fn new(object_only: bool) -> Self {
        Self(
            Arc::new(AtomicU8::new(CommandStatus::Reserved as u8)),
            object_only,
        )
    }
    fn set(&self, status: CommandStatus) {
        self.0.store(status as u8, Ordering::SeqCst);
    }
    pub(crate) fn snapshot(&self) -> CommandStatus {
        match self.0.load(Ordering::SeqCst) {
            0 => CommandStatus::Reserved,
            1 => CommandStatus::Submitted,
            2 => CommandStatus::Acknowledged,
            3 => CommandStatus::RetainedRejected,
            4 => CommandStatus::Destroyed,
            5 => CommandStatus::Abandoned,
            _ => CommandStatus::IntegrityLost,
        }
    }
    pub(crate) fn accountably_retained(&self) -> bool {
        matches!(
            self.snapshot(),
            CommandStatus::Submitted | CommandStatus::RetainedRejected
        )
    }
    pub(crate) fn accounted_object_debt(&self) -> bool {
        self.1 && self.accountably_retained()
    }
    pub(crate) fn settled(&self) -> bool {
        matches!(
            self.snapshot(),
            CommandStatus::Acknowledged | CommandStatus::Destroyed
        )
    }
}
struct CommandRecord {
    category: CommandCategory,
    status: CommandStatusHandle,
    provenance: Provenance,
    footprint: usize,
    submitted: bool,
    mutation: bool,
    creation_slots: usize,
    release_object: Option<String>,
    object_group: Option<String>,
    release_group: bool,
    release_group_fence: u64,
    group_id: Option<u64>,
    grouped_creation: bool,
    group_release_proven: bool,
    objects_destroyed: bool,
}
struct ObjectObligation {
    provenance: Provenance,
    object: Option<String>,
    group: Option<String>,
    serial: u64,
    footprint: usize,
}
struct GroupObligation {
    provenance: Provenance,
    name: String,
    footprint: usize,
    pending_creations: usize,
    submitted_creations: usize,
    ever_submitted: bool,
    sealed: bool,
    release_inflight: bool,
    cleanup_issued: bool,
}
#[derive(Default)]
struct LedgerState {
    next_reservation: u64,
    next_realm_epoch: u64,
    next_object_serial: u64,
    next_group: u64,
    groups: HashMap<u64, GroupObligation>,
    commands: HashMap<u64, CommandRecord>,
    objects: Vec<ObjectObligation>,
    realms: HashMap<(String, i64), u64>,
    targets: HashMap<String, String>,
    counts: [usize; 11],
    bytes: [usize; 11],
    object_bytes: usize,
    journal_bytes: usize,
    integrity_lost: bool,
    retired: bool,
    context_id: Option<String>,
}
pub(crate) struct OwnerDebtLedger {
    generation: u64,
    identity_scope: String,
    state: Mutex<LedgerState>,
}
impl OwnerDebtLedger {
    pub(crate) fn new(generation: u64, identity_scope: String) -> Arc<Self> {
        let invalid = generation == 0 || identity_scope.len() > 4096;
        Arc::new(Self {
            generation,
            identity_scope,
            state: Mutex::new(LedgerState {
                integrity_lost: invalid,
                ..Default::default()
            }),
        })
    }
    pub(crate) fn bind_context(&self, context_id: &str) -> Result<(), ProtocolError> {
        if context_id.is_empty() || context_id.len() > 4096 {
            return Err(ProtocolError::StaleScope);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.retired
            || state
                .context_id
                .as_deref()
                .is_some_and(|old| old != context_id)
        {
            return Err(ProtocolError::StaleScope);
        }
        let extra = if state.context_id.is_none() {
            context_id.len()
        } else {
            0
        };
        if metadata_usage(&state).saturating_add(extra) > 64 * 1024
            || descriptor_usage(&state).saturating_add(extra) > 508 * 1024
        {
            return Err(ProtocolError::CapacityExceeded);
        }
        state.context_id = Some(context_id.to_owned());
        Ok(())
    }
    pub(crate) fn same_owner(&self, other: &OwnerDebtLedger) -> bool {
        self.generation == other.generation && self.identity_scope == other.identity_scope
    }
    pub(crate) fn matches_owner(&self, generation: u64, identity_scope: &str) -> bool {
        self.generation == generation && self.identity_scope == identity_scope
    }
    pub(crate) fn operation(
        self: &Arc<Self>,
        key: OperationKey,
        target_id: String,
        session_id: String,
    ) -> Result<OperationJournalHandle, ProtocolError> {
        if key.generation != self.generation
            || key.operation_seq == 0
            || target_id.is_empty()
            || session_id.is_empty()
            || target_id.len() > 4096
            || session_id.len() > 4096
        {
            return Err(ProtocolError::StaleScope);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.integrity_lost {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if state
            .targets
            .get(&session_id)
            .is_some_and(|target| target != &target_id)
        {
            return Err(ProtocolError::StaleScope);
        }
        let footprint = 256 + self.identity_scope.len() + target_id.len() + session_id.len();
        let metadata = if state.targets.contains_key(&session_id) {
            0
        } else {
            64 + session_id.len() + target_id.len()
        };
        if state.targets.len() >= 4096
            || metadata_usage(&state).saturating_add(metadata) > 64 * 1024
            || descriptor_usage(&state)
                .saturating_add(footprint)
                .saturating_add(metadata)
                > 508 * 1024
        {
            return Err(ProtocolError::CapacityExceeded);
        }
        state.journal_bytes += footprint;
        state.targets.insert(session_id.clone(), target_id.clone());
        drop(state);
        Ok(OperationJournalHandle {
            ledger: self.clone(),
            journal: Arc::new(Journal {
                key,
                target: target_id,
                session: session_id,
                state: Mutex::new(JournalState::default()),
                ledger: Arc::downgrade(self),
                footprint,
            }),
        })
    }
    /// Native lifecycle owner calls this only after exact context destruction
    /// acknowledgement. It is never a timeout/recovery or waiter-drop shortcut.
    pub(crate) fn retire_after_context_destroy(
        &self,
        context_id: &str,
    ) -> Result<(), ProtocolError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.context_id.as_deref() != Some(context_id) {
            return Err(ProtocolError::StaleScope);
        }
        for command in state.commands.values() {
            command.status.set(CommandStatus::Destroyed);
        }
        state.commands.clear();
        state.objects.clear();
        state.groups.clear();
        state.realms.clear();
        state.targets.clear();
        state.counts = [0; 11];
        state.bytes = [0; 11];
        state.object_bytes = 0;
        state.retired = true;
        Ok(())
    }
    pub(crate) fn snapshot(&self) -> OwnerDebtSnapshot {
        match self.state.lock() {
            Ok(state) => OwnerDebtSnapshot {
                input_debt: state
                    .commands
                    .values()
                    .filter(|command| command.submitted && command.category.input())
                    .count() as u32,
                object_debt: object_count(&state) as u32,
                outstanding_commands: state.commands.len() as u32,
                descriptor_bytes: descriptor_usage(&state),
                integrity_lost: state.integrity_lost,
            },
            Err(_) => OwnerDebtSnapshot {
                integrity_lost: true,
                ..Default::default()
            },
        }
    }
    pub(crate) fn check_admission(&self, category: AdmissionClass) -> Result<(), ProtocolError> {
        let snapshot = self.snapshot();
        if snapshot.integrity_lost {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if category != AdmissionClass::FixedRead && snapshot.input_debt > 0 {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if category == AdmissionClass::Reference && snapshot.object_debt >= 32 {
            return Err(ProtocolError::CapacityExceeded);
        }
        Ok(())
    }
    fn operation_counts(&self, key: OperationKey) -> (u32, u32, bool) {
        match self.state.lock() {
            Ok(state) => (
                state
                    .commands
                    .values()
                    .filter(|command| {
                        command.submitted
                            && command.provenance.operation == Some(key)
                            && command.category.input()
                    })
                    .count() as u32,
                (state
                    .objects
                    .iter()
                    .filter(|object| object.provenance.operation == Some(key))
                    .count()
                    + state
                        .groups
                        .values()
                        .filter(|group| group.provenance.operation == Some(key))
                        .count()
                    + state
                        .commands
                        .values()
                        .filter(|command| command.provenance.operation == Some(key))
                        .map(|command| command.creation_slots)
                        .sum::<usize>()) as u32,
                state.integrity_lost
                    || state.commands.values().any(|command| {
                        command.submitted
                            && command.provenance.operation == Some(key)
                            && command.mutation
                            && !command.category.input()
                    }),
            ),
            Err(_) => (0, 0, true),
        }
    }
    pub(crate) fn reserve_command(
        self: &Arc<Self>,
        journal: Option<&OperationJournalHandle>,
        method: &str,
        params: Option<&Value>,
        session: Option<&str>,
    ) -> Result<CommandReservation, ProtocolError> {
        if method.len() > 256 || session.is_some_and(|session| session.len() > 4096) {
            return Err(ProtocolError::CapacityExceeded);
        }
        if journal.is_some_and(|journal| !Arc::ptr_eq(&journal.ledger, self)) {
            return Err(ProtocolError::StaleScope);
        }
        let classification = classify(method, params, journal.is_some());
        if classification.category.application() {
            if let Some(journal) = journal {
                journal.check_application_submission()?;
            }
        }
        let release_object = if method == "Runtime.releaseObject" {
            Some(
                params
                    .and_then(|params| params.get("objectId"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty() && value.len() <= 4096)
                    .ok_or(ProtocolError::InvalidArguments)?
                    .to_owned(),
            )
        } else {
            None
        };
        let object_group = params
            .and_then(|params| params.get("objectGroup"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        if object_group
            .as_ref()
            .is_some_and(|group| group.len() > 4096)
        {
            return Err(ProtocolError::CapacityExceeded);
        }
        let native_group = NATIVE_OBJECT_GROUP.try_with(Clone::clone).ok();
        if native_group
            .as_ref()
            .is_some_and(|group| object_group.as_ref().is_some_and(|actual| actual != group))
        {
            return Err(ProtocolError::StaleScope);
        }
        let physical_creation_slots = creation_slots(method, params);
        let creation_slots = if native_group.is_some() {
            0
        } else {
            physical_creation_slots
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        if state.retired
            || (state.integrity_lost && classification.category != CommandCategory::Destroy)
        {
            return Err(ProtocolError::ScopeUnavailable);
        }
        let session = session
            .filter(|session| !session.is_empty())
            .map(str::to_owned);
        let target = session
            .as_ref()
            .and_then(|session| state.targets.get(session))
            .cloned()
            .or_else(|| {
                journal
                    .filter(|journal| session.as_deref() == Some(journal.journal.session.as_str()))
                    .map(|journal| journal.journal.target.clone())
            });
        let context = params
            .and_then(|params| {
                params
                    .get("executionContextId")
                    .or_else(|| params.get("contextId"))
            })
            .and_then(Value::as_i64);
        let realm = session
            .as_ref()
            .zip(context)
            .and_then(|(session, context)| {
                state
                    .realms
                    .get(&(session.clone(), context))
                    .map(|epoch| (context, *epoch))
            });
        let provenance = Provenance {
            operation: journal.map(OperationJournalHandle::key),
            target,
            session,
            realm,
        };
        let group_name = native_group.as_ref().or_else(|| {
            (method == "Runtime.releaseObjectGroup")
                .then_some(object_group.as_ref())
                .flatten()
        });
        let existing_group = group_name.and_then(|name| {
            state
                .groups
                .iter()
                .find(|(_, group)| {
                    group.name == *name
                        && group.provenance.session == provenance.session
                        && group.provenance.operation == provenance.operation
                })
                .map(|(id, _)| *id)
        });
        if existing_group
            .and_then(|id| state.groups.get(&id))
            .is_some_and(|group| {
                group.provenance.realm.is_some()
                    && provenance.realm.is_some()
                    && group.provenance.realm != provenance.realm
            })
        {
            return Err(ProtocolError::StaleScope);
        }
        if native_group.is_some() && journal.is_none() {
            return Err(ProtocolError::StaleScope);
        }
        if existing_group.is_some_and(|id| {
            state
                .groups
                .get(&id)
                .is_some_and(|group| group.sealed && method != "Runtime.releaseObjectGroup")
        }) {
            return Err(ProtocolError::Cancelled);
        }
        let new_group_footprint = if native_group.is_some() && existing_group.is_none() {
            256 + self.identity_scope.len()
                + provenance.session.as_ref().map_or(0, String::len)
                + provenance.target.as_ref().map_or(0, String::len)
                + native_group.as_ref().map_or(0, String::len)
        } else {
            0
        };
        let footprint = 192
            + self.identity_scope.len()
            + provenance.session.as_ref().map_or(0, String::len)
            + provenance.target.as_ref().map_or(0, String::len)
            + release_object.as_ref().map_or(0, String::len)
            + object_group.as_ref().map_or(0, String::len);
        let index = classification.category.index();
        let (maximum_count, maximum_bytes) = classification.category.limits();
        if state.counts[index] >= maximum_count
            || state.bytes[index]
                .checked_add(footprint)
                .is_none_or(|bytes| bytes > maximum_bytes)
            || object_count(&state)
                .checked_add(creation_slots + usize::from(new_group_footprint > 0))
                .is_none_or(|count| count > 32)
            || descriptor_usage(&state)
                .saturating_add(footprint)
                .saturating_add(new_group_footprint)
                .saturating_add(creation_slots * 8448)
                > if classification.category == CommandCategory::Destroy {
                    512 * 1024
                } else {
                    508 * 1024
                }
        {
            return Err(ProtocolError::CapacityExceeded);
        }
        let id = state
            .next_reservation
            .checked_add(1)
            .ok_or(ProtocolError::IdentifierExhausted)?;
        let group_id = if new_group_footprint > 0 {
            let group_id = state
                .next_group
                .checked_add(1)
                .ok_or(ProtocolError::IdentifierExhausted)?;
            state.next_group = group_id;
            state.groups.insert(
                group_id,
                GroupObligation {
                    provenance: provenance.clone(),
                    name: native_group.clone().expect("native group"),
                    footprint: new_group_footprint,
                    pending_creations: 0,
                    submitted_creations: 0,
                    ever_submitted: false,
                    sealed: false,
                    release_inflight: false,
                    cleanup_issued: false,
                },
            );
            Some(group_id)
        } else {
            existing_group
        };
        let grouped_creation = group_id.is_some()
            && physical_creation_slots > 0
            && method != "Runtime.releaseObjectGroup";
        if let Some(group) = group_id.and_then(|id| state.groups.get_mut(&id)) {
            if grouped_creation {
                group.pending_creations += 1;
            }
        }
        state.next_reservation = id;
        state.counts[index] += 1;
        state.bytes[index] += footprint;
        let status =
            CommandStatusHandle::new(physical_creation_slots > 0 && !classification.mutation);
        state.commands.insert(
            id,
            CommandRecord {
                category: classification.category,
                status: status.clone(),
                provenance,
                footprint,
                submitted: false,
                mutation: classification.mutation,
                creation_slots,
                release_object,
                object_group,
                release_group: method == "Runtime.releaseObjectGroup",
                release_group_fence: 0,
                group_id,
                grouped_creation,
                group_release_proven: false,
                objects_destroyed: false,
            },
        );
        Ok(CommandReservation {
            ledger: self.clone(),
            id,
            journal: journal.cloned(),
            status,
            submitted: false,
        })
    }
    pub(crate) fn accounted_object_release(&self, session: &str, object: &str) -> bool {
        self.state.lock().is_ok_and(|state| {
            !state.integrity_lost
                && state.commands.values().any(|command| {
                    command.submitted
                        && command.provenance.session.as_deref() == Some(session)
                        && command.release_object.as_deref() == Some(object)
                })
        })
    }
    pub(crate) fn connection_lost(&self) {
        match self.state.lock() {
            Ok(mut state) => state.integrity_lost = true,
            Err(error) => error.into_inner().integrity_lost = true,
        }
    }
    pub(crate) fn observe_event(&self, event: &CdpEvent) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        match event.method.as_str() {
            "Runtime.executionContextCreated" => {
                if let (Some(session), Some(context)) =
                    (&event.session_id, event.params["context"]["id"].as_i64())
                {
                    let extra = if state.realms.contains_key(&(session.clone(), context)) {
                        0
                    } else {
                        64 + session.len()
                    };
                    if session.is_empty()
                        || session.len() > 4096
                        || state.realms.len() >= 4096
                        || metadata_usage(&state).saturating_add(extra) > 64 * 1024
                        || descriptor_usage(&state).saturating_add(extra) > 508 * 1024
                    {
                        state.integrity_lost = true;
                        return;
                    }
                    let Some(epoch) = state.next_realm_epoch.checked_add(1) else {
                        state.integrity_lost = true;
                        return;
                    };
                    state.next_realm_epoch = epoch;
                    state.realms.insert((session.clone(), context), epoch);
                }
            }
            "Runtime.executionContextDestroyed" => {
                if let (Some(session), Some(context)) = (
                    &event.session_id,
                    event.params["executionContextId"].as_i64(),
                ) {
                    if let Some(epoch) = state.realms.remove(&(session.clone(), context)) {
                        destroy_matching(
                            &mut state,
                            |provenance| {
                                provenance.session.as_ref() == Some(session)
                                    && provenance.realm == Some((context, epoch))
                            },
                            false,
                        );
                    }
                }
            }
            "Runtime.executionContextsCleared" => {
                if let Some(session) = &event.session_id {
                    state.realms.retain(|(owner, _), _| owner != session);
                    destroy_matching(
                        &mut state,
                        |provenance| provenance.session.as_ref() == Some(session),
                        false,
                    );
                }
            }
            "Target.detachedFromTarget" => {
                if let Some(session) = event.params["sessionId"].as_str() {
                    state.targets.remove(session);
                    state.realms.retain(|(owner, _), _| owner != session);
                    destroy_matching(
                        &mut state,
                        |provenance| provenance.session.as_deref() == Some(session),
                        true,
                    );
                }
            }
            "Target.targetDestroyed" => {
                if let Some(target) = event.params["targetId"].as_str() {
                    let sessions: HashSet<String> = state
                        .targets
                        .iter()
                        .filter(|(_, owner)| owner.as_str() == target)
                        .map(|(session, _)| session.clone())
                        .collect();
                    state.targets.retain(|_, owner| owner != target);
                    state
                        .realms
                        .retain(|(session, _), _| !sessions.contains(session));
                    destroy_matching(
                        &mut state,
                        |provenance| provenance.target.as_deref() == Some(target),
                        true,
                    );
                }
            }
            _ => {}
        }
    }
}
fn metadata_usage(state: &LedgerState) -> usize {
    state.context_id.as_ref().map_or(0, String::len)
        + state
            .targets
            .iter()
            .map(|(session, target)| 64 + session.len() + target.len())
            .sum::<usize>()
        + state
            .realms
            .keys()
            .map(|(session, _)| 64 + session.len())
            .sum::<usize>()
}
fn descriptor_usage(state: &LedgerState) -> usize {
    metadata_usage(state)
        + state.journal_bytes
        + state
            .groups
            .values()
            .map(|group| group.footprint)
            .sum::<usize>()
        + state.bytes.iter().sum::<usize>()
        + state.object_bytes
        + state
            .commands
            .values()
            .map(|command| command.creation_slots * 8448)
            .sum::<usize>()
}
fn object_count(state: &LedgerState) -> usize {
    state.objects.len()
        + state.groups.len()
        + state
            .commands
            .values()
            .map(|command| command.creation_slots)
            .sum::<usize>()
}
fn remove_command(state: &mut LedgerState, id: u64) -> Option<CommandRecord> {
    let command = state.commands.remove(&id)?;
    if command.grouped_creation {
        if let Some(group) = command.group_id.and_then(|id| state.groups.get_mut(&id)) {
            group.pending_creations = group.pending_creations.saturating_sub(1);
            if command.submitted {
                group.submitted_creations = group.submitted_creations.saturating_sub(1);
            }
        }
    }
    state.counts[command.category.index()] -= 1;
    state.bytes[command.category.index()] -= command.footprint;
    Some(command)
}
fn destroy_matching(
    state: &mut LedgerState,
    matches: impl Fn(&Provenance) -> bool,
    target_destroyed: bool,
) {
    state.objects.retain(|object| !matches(&object.provenance));
    let groups: HashSet<u64> = state
        .groups
        .iter()
        .filter(|(_, group)| matches(&group.provenance))
        .map(|(id, _)| *id)
        .collect();
    state.groups.retain(|id, _| !groups.contains(id));
    state.object_bytes = state.objects.iter().map(|object| object.footprint).sum();
    // Realm destruction discharges objects, not unrelated input effects. Only
    // exact target/session destruction can discharge pending input commands.
    let ids: Vec<u64> = state
        .commands
        .iter()
        .filter(|(_, command)| {
            matches(&command.provenance)
                && (target_destroyed
                    || (!command.category.input()
                        && (command.creation_slots > 0
                            || command.release_object.is_some()
                            || command.group_id.is_some_and(|id| groups.contains(&id)))))
        })
        .map(|(id, _)| *id)
        .collect();
    if !target_destroyed {
        for command in state.commands.values_mut() {
            if matches(&command.provenance) && command.category.input() {
                command.creation_slots = 0;
                command.objects_destroyed = true;
                command.group_id = None;
                command.grouped_creation = false;
            }
        }
    }
    for id in ids {
        if let Some(command) = remove_command(state, id) {
            command.status.set(CommandStatus::Destroyed);
        }
    }
}
pub(crate) struct CommandReservation {
    ledger: Arc<OwnerDebtLedger>,
    id: u64,
    journal: Option<OperationJournalHandle>,
    status: CommandStatusHandle,
    submitted: bool,
}
impl CommandReservation {
    pub(crate) fn status(&self) -> CommandStatusHandle {
        self.status.clone()
    }
    /// Called with websocket ownership immediately before the send future can
    /// accept bytes. Failed/maybe sends remain reader-owned debt, not rollback.
    pub(crate) fn submit(mut self) -> Result<SubmittedCommand, ProtocolError> {
        let mut state = self
            .ledger
            .state
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let group_fence = state.next_object_serial;
        if let Some(command) = state.commands.get(&self.id) {
            if command.grouped_creation
                && command
                    .group_id
                    .is_some_and(|id| state.groups.get(&id).is_none_or(|group| group.sealed))
            {
                return Err(ProtocolError::Cancelled);
            }
        }
        let release_group = state
            .commands
            .get(&self.id)
            .filter(|command| command.release_group)
            .and_then(|command| command.group_id);
        let group_release_proven = if let Some(group_id) = release_group {
            let group = state
                .groups
                .get_mut(&group_id)
                .ok_or(ProtocolError::StaleScope)?;
            if group.release_inflight {
                return Err(ProtocolError::ScopeUnavailable);
            }
            group.sealed = true;
            group.release_inflight = true;
            group.submitted_creations == 0
        } else {
            false
        };
        let command = state
            .commands
            .get_mut(&self.id)
            .ok_or(ProtocolError::ScopeUnavailable)?;
        if command.category.application() {
            if let Some(journal) = &self.journal {
                if command.mutation {
                    journal.mark_mutation_maybe_submitted()?;
                } else {
                    journal.check_application_submission()?;
                }
            }
        }
        command.release_group_fence = group_fence;
        command.group_release_proven = group_release_proven;
        command.submitted = true;
        command.status.set(CommandStatus::Submitted);
        let group_id = command.group_id;
        let creation = command.grouped_creation;
        if let Some(group) = group_id.and_then(|id| state.groups.get_mut(&id)) {
            group.ever_submitted = true;
            if creation {
                group.submitted_creations += 1;
            }
        }
        self.submitted = true;
        Ok(SubmittedCommand {
            ledger: self.ledger.clone(),
            id: self.id,
        })
    }
}
impl Drop for CommandReservation {
    fn drop(&mut self) {
        if !self.submitted {
            if let Ok(mut state) = self.ledger.state.lock() {
                let removed = remove_command(&mut state, self.id);
                if let Some(id) = removed.and_then(|command| command.group_id) {
                    if state
                        .groups
                        .get(&id)
                        .is_some_and(|group| !group.ever_submitted && group.pending_creations == 0)
                    {
                        state.groups.remove(&id);
                    }
                }
                self.status.set(CommandStatus::Abandoned);
            }
        }
    }
}
pub(crate) struct SubmittedCommand {
    ledger: Arc<OwnerDebtLedger>,
    id: u64,
}
impl SubmittedCommand {
    pub(crate) fn malformed_response(&self) {
        if let Ok(state) = self.ledger.state.lock() {
            if let Some(command) = state.commands.get(&self.id) {
                command.status.set(CommandStatus::IntegrityLost);
            }
        }
        self.ledger.connection_lost();
    }
    pub(crate) fn settle(&self, response: &CdpMessage) {
        let _ = self.settle_for_delivery(response);
    }
    pub(crate) fn settle_for_delivery(&self, response: &CdpMessage) -> Vec<LateDisposal> {
        let Ok(mut state) = self.ledger.state.lock() else {
            return Vec::new();
        };
        let Some(command) = state.commands.get(&self.id) else {
            return Vec::new();
        };
        let valid_envelope = response.method.is_none()
            && response.params.is_none()
            && match (&response.result, &response.error) {
                (Some(Value::Object(_)), None) => true,
                (None, Some(error)) => error.code.is_some(),
                _ => false,
            };
        if !valid_envelope {
            command.status.set(CommandStatus::IntegrityLost);
            state.integrity_lost = true;
            return Vec::new();
        }
        if response.session_id.as_deref() != command.provenance.session.as_deref() {
            // Omission is valid only when both sides are browser-level.
            command.status.set(CommandStatus::IntegrityLost);
            state.integrity_lost = true;
            return Vec::new();
        }
        if response.error.is_some()
            && (command.category.input()
                || command.release_object.is_some()
                || command.release_group)
        {
            command.status.set(CommandStatus::RetainedRejected);
            // A failed cleanup is not a successful release. Keep its bounded
            // exact obligation; no waiter can promote it to clean state.
            return Vec::new();
        }
        let command = remove_command(&mut state, self.id).expect("checked command");
        command.status.set(CommandStatus::Acknowledged);
        if let Some(group_id) = command.group_id {
            if command.release_group && command.group_release_proven {
                state.groups.remove(&group_id);
                return Vec::new();
            }
            if let Some(group) = state.groups.get_mut(&group_id) {
                if command.release_group {
                    group.release_inflight = false;
                }
                if group.sealed
                    && group.submitted_creations == 0
                    && !group.release_inflight
                    && !group.cleanup_issued
                {
                    group.cleanup_issued = true;
                    return vec![LateDisposal {
                        ledger: self.ledger.clone(),
                        provenance: group.provenance.clone(),
                        object: None,
                        abandoned_only: false,
                        group: Some((group_id, group.name.clone())),
                    }];
                }
            }
            return Vec::new();
        }
        if command.objects_destroyed {
            return Vec::new();
        }
        let result = response.result.as_ref().unwrap_or(&Value::Null);
        let mut seen = HashSet::new();
        let handles: Vec<&str> = [
            result["result"]["objectId"].as_str(),
            result["object"]["objectId"].as_str(),
            result["exceptionDetails"]["exception"]["objectId"].as_str(),
        ]
        .into_iter()
        .flatten()
        .filter(|object| seen.insert(*object))
        .collect();
        if handles.len() > command.creation_slots
            || handles.iter().any(|object| object.len() > 4096)
        {
            state.integrity_lost = true;
            // Preserve pre-reserved anonymous creation debt if an invalid
            // response cannot safely be represented, rather than truncating it.
            for _ in 0..command.creation_slots {
                state.objects.push(ObjectObligation {
                    provenance: command.provenance.clone(),
                    object: None,
                    group: command.object_group.clone(),
                    serial: 0,
                    footprint: 256,
                });
                state.object_bytes += 256;
            }
            return Vec::new();
        }
        let mut disposals = Vec::new();
        for object in handles {
            if !state.objects.iter().any(|old| {
                old.provenance.session == command.provenance.session
                    && old.object.as_deref() == Some(object)
            }) {
                let footprint =
                    256 + object.len() + command.object_group.as_ref().map_or(0, String::len);
                let Some(serial) = state.next_object_serial.checked_add(1) else {
                    state.integrity_lost = true;
                    return Vec::new();
                };
                state.next_object_serial = serial;
                state.object_bytes += footprint;
                {
                    disposals.push(LateDisposal {
                        ledger: self.ledger.clone(),
                        provenance: command.provenance.clone(),
                        object: Some(object.to_owned()),
                        abandoned_only: true,
                        group: None,
                    });
                }
                state.objects.push(ObjectObligation {
                    provenance: command.provenance.clone(),
                    object: Some(object.to_owned()),
                    group: command.object_group.clone(),
                    serial,
                    footprint,
                });
            }
        }
        if let Some(object) = &command.release_object {
            state.objects.retain(|old| {
                !(old.provenance.session == command.provenance.session
                    && old.object.as_ref() == Some(object))
            });
            state.object_bytes = state.objects.iter().map(|object| object.footprint).sum();
        }
        if command.release_group {
            state.objects.retain(|old| {
                !(old.provenance.session == command.provenance.session
                    && old.group == command.object_group
                    && old.object.is_some()
                    && old.serial <= command.release_group_fence)
            });
            state.object_bytes = state.objects.iter().map(|object| object.footprint).sum();
        }
        // A group ACK only retires already-known handles captured before that
        // release was submitted. Pending/late unknown creation never borrows it.
        disposals
    }
}
/// One-shot cleanup work derived only from an actual reader-correlated reply.
/// It cannot carry a caller continuation or any executable application payload.
pub(crate) struct LateDisposal {
    ledger: Arc<OwnerDebtLedger>,
    provenance: Provenance,
    object: Option<String>,
    abandoned_only: bool,
    group: Option<(u64, String)>,
}
pub(crate) struct ReservedDisposal {
    pub reservation: CommandReservation,
    pub method: &'static str,
    pub params: Value,
    pub session: Option<String>,
}
impl LateDisposal {
    pub(crate) fn needed_after_delivery(&self, abandoned: bool) -> bool {
        !self.abandoned_only || abandoned
    }
    pub(crate) fn reserve(self) -> Result<ReservedDisposal, ProtocolError> {
        let (method, params) = if let Some((_, group)) = &self.group {
            (
                "Runtime.releaseObjectGroup",
                serde_json::json!({"objectGroup":group}),
            )
        } else {
            (
                "Runtime.releaseObject",
                serde_json::json!({"objectId":self.object}),
            )
        };
        let reservation = self.ledger.reserve_command(
            None,
            method,
            Some(&params),
            self.provenance.session.as_deref(),
        )?;
        {
            let mut state = self
                .ledger
                .state
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            if let Some((id, _)) = &self.group {
                if !state.groups.contains_key(id) {
                    return Err(ProtocolError::StaleScope);
                }
            }
            let command = state
                .commands
                .get_mut(&reservation.id)
                .ok_or(ProtocolError::ScopeUnavailable)?;
            command.provenance = self.provenance.clone();
            command.group_id = self.group.as_ref().map(|(id, _)| *id);
        }
        Ok(ReservedDisposal {
            reservation,
            method,
            params,
            session: self.provenance.session,
        })
    }
}
struct Classification {
    category: CommandCategory,
    mutation: bool,
}
fn creation_slots(method: &str, params: Option<&Value>) -> usize {
    match method {
        "DOM.resolveNode" => 1,
        "Runtime.evaluate"
        | "Runtime.callFunctionOn"
        | "Runtime.runScript"
        | "Runtime.awaitPromise" => {
            if params
                .and_then(|params| params.get("returnByValue"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                1
            } else {
                2
            }
        }
        // getProperties can return an unbounded array of handles. It must not
        // run on the retained path unless a bounded native consumer is added.
        "Runtime.getProperties" => 33,
        _ => 0,
    }
}
fn classify(method: &str, _params: Option<&Value>, operation: bool) -> Classification {
    if let Ok(explicit) = COMMAND_OVERRIDE.try_with(|value| *value) {
        return Classification {
            category: if explicit.mutation && explicit.category.application() {
                CommandCategory::ApplicationInput
            } else {
                explicit.category
            },
            mutation: explicit.mutation,
        };
    }
    let release = matches!(
        method,
        "Runtime.releaseObject" | "Runtime.releaseObjectGroup"
    );
    let category = if release {
        CommandCategory::CleanupObject
    } else if method == "Target.disposeBrowserContext" || method == "Browser.close" {
        CommandCategory::Destroy
    } else if method == "Fetch.getResponseBody" {
        CommandCategory::Download
    } else if method.starts_with("Fetch.") || method == "Page.handleJavaScriptDialog" {
        CommandCategory::Security
    } else if matches!(
        method,
        "Page.screencastFrameAck" | "Page.startScreencast" | "Page.stopScreencast"
    ) {
        CommandCategory::Recording
    } else if matches!(
        method,
        "Browser.setDownloadBehavior"
            | "Browser.cancelDownload"
            | "Network.getResponseBody"
            | "Fetch.getResponseBody"
            | "IO.read"
            | "IO.close"
    ) {
        CommandCategory::Download
    } else if operation {
        if method.starts_with("Input.") {
            CommandCategory::ApplicationInput
        } else if method.starts_with("DOM.") || method.starts_with("Runtime.") {
            CommandCategory::ApplicationObject
        } else {
            CommandCategory::ApplicationRead
        }
    } else {
        CommandCategory::Enrollment
    };
    // Runtime.evaluate is not a fixed safe read. Native action call sites can
    // narrow this only with a static command_scope override.
    let mutation = !release
        && !matches!(
            method,
            "Browser.getVersion"
                | "Page.getFrameTree"
                | "Page.getLayoutMetrics"
                | "Page.getNavigationHistory"
                | "DOM.describeNode"
                | "DOM.resolveNode"
                | "DOM.getBoxModel"
                | "DOM.getContentQuads"
                | "DOM.getDocument"
                | "Accessibility.getFullAXTree"
                | "Accessibility.getPartialAXTree"
                | "Target.getTargets"
                | "Target.getTargetInfo"
                | "Network.getCookies"
                | "Storage.getCookies"
                | "Runtime.getIsolateId"
                | "Page.createIsolatedWorld"
        );
    let category = if operation && mutation && category.application() {
        CommandCategory::ApplicationInput
    } else {
        category
    };
    Classification { category, mutation }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn owner() -> (Arc<OwnerDebtLedger>, OperationJournalHandle) {
        let ledger = OwnerDebtLedger::new(7, "scope".into());
        let journal = ledger
            .operation(
                OperationKey {
                    generation: 7,
                    operation_seq: 1,
                },
                "target".into(),
                "page".into(),
            )
            .unwrap();
        (ledger, journal)
    }
    fn response(result: Value) -> CdpMessage {
        serde_json::from_value(json!({"id":1,"sessionId":"page","result":result})).unwrap()
    }
    async fn grouped(
        ledger: &Arc<OwnerDebtLedger>,
        journal: &OperationJournalHandle,
        group: &str,
        method: &str,
        params: Value,
    ) -> CommandReservation {
        native_object_group(
            group,
            command_scope(CommandCategory::ApplicationObject, false, async {
                ledger
                    .reserve_command(Some(journal), method, Some(&params), Some("page"))
                    .unwrap()
            }),
        )
        .await
    }
    #[test]
    fn submission_not_waiter_lifetime_owns_debt_and_ack_does_not_erase_dispatch() {
        let (ledger, journal) = owner();
        let pending = ledger
            .reserve_command(
                Some(&journal),
                "Input.dispatchMouseEvent",
                Some(&json!({"type":"mousePressed"})),
                Some("page"),
            )
            .unwrap();
        assert!(!journal.snapshot().mutation_dispatched);
        assert_eq!(ledger.snapshot().input_debt, 0);
        let submitted = pending.submit().unwrap();
        assert!(journal.snapshot().mutation_dispatched);
        assert_eq!(ledger.snapshot().input_debt, 1);
        drop(submitted);
        assert_eq!(ledger.snapshot().input_debt, 1);
        let id = *ledger.state.lock().unwrap().commands.keys().next().unwrap();
        SubmittedCommand {
            ledger: ledger.clone(),
            id,
        }
        .settle(&response(json!({})));
        assert_eq!(ledger.snapshot().input_debt, 0);
        assert!(journal.snapshot().mutation_dispatched);
    }
    #[test]
    fn quotas_do_not_borrow_recording_security_or_destroy_slots() {
        let (ledger, journal) = owner();
        let mut input = Vec::new();
        for _ in 0..16 {
            input.push(
                ledger
                    .reserve_command(Some(&journal), "Input.dispatchKeyEvent", None, Some("page"))
                    .unwrap()
                    .submit()
                    .unwrap(),
            );
        }
        assert!(ledger
            .reserve_command(Some(&journal), "Input.dispatchKeyEvent", None, Some("page"))
            .is_err());
        let security = ledger
            .reserve_command(None, "Fetch.continueRequest", None, Some("page"))
            .unwrap()
            .submit()
            .unwrap();
        let recording = ledger
            .reserve_command(None, "Page.screencastFrameAck", None, Some("page"))
            .unwrap()
            .submit()
            .unwrap();
        let destroy = ledger
            .reserve_command(None, "Target.disposeBrowserContext", None, None)
            .unwrap();
        assert_eq!(ledger.snapshot().input_debt, 16);
        drop((input, security, recording, destroy));
        assert_eq!(ledger.snapshot().input_debt, 16);
    }
    #[tokio::test]
    async fn native_group_accounts_many_roots_and_property_handles_as_one_obligation() {
        let (ledger, journal) = owner();
        for index in 0..64 {
            let submitted = grouped(
                &ledger,
                &journal,
                "native-security-1",
                "DOM.resolveNode",
                json!({"objectGroup":"native-security-1","backendNodeId":index}),
            )
            .await
            .submit()
            .unwrap();
            submitted.settle(&response(
                json!({"object":{"objectId":format!("root-{index}")}}),
            ));
            assert_eq!(ledger.snapshot().object_debt, 1);
        }
        let properties = grouped(
            &ledger,
            &journal,
            "native-security-1",
            "Runtime.getProperties",
            json!({"objectId":"array","ownProperties":true}),
        )
        .await
        .submit()
        .unwrap();
        properties.settle(&response(json!({"result":(0..64).map(|index|json!({"name":index.to_string(),"value":{"objectId":format!("node-{index}")}})).collect::<Vec<_>>()})));
        assert_eq!(ledger.snapshot().object_debt, 1);
        let release = ledger
            .reserve_command(
                Some(&journal),
                "Runtime.releaseObjectGroup",
                Some(&json!({"objectGroup":"native-security-1"})),
                Some("page"),
            )
            .unwrap()
            .submit()
            .unwrap();
        release.settle(&response(json!({})));
        assert_eq!(ledger.snapshot().object_debt, 0);
        assert!(!journal.snapshot().mutation_dispatched);
    }
    #[tokio::test]
    async fn early_release_ack_cannot_discharge_late_creation_and_disposal_is_once_only() {
        let (ledger, journal) = owner();
        let creation = grouped(
            &ledger,
            &journal,
            "native-query-1",
            "DOM.resolveNode",
            json!({"objectGroup":"native-query-1"}),
        )
        .await
        .submit()
        .unwrap();
        let release = ledger
            .reserve_command(
                Some(&journal),
                "Runtime.releaseObjectGroup",
                Some(&json!({"objectGroup":"native-query-1"})),
                Some("page"),
            )
            .unwrap()
            .submit()
            .unwrap();
        assert!(release.settle_for_delivery(&response(json!({}))).is_empty());
        assert_eq!(ledger.snapshot().object_debt, 1);
        let mut late =
            creation.settle_for_delivery(&response(json!({"object":{"objectId":"late-root"}})));
        assert_eq!(late.len(), 1);
        assert!(creation
            .settle_for_delivery(&response(json!({})))
            .is_empty());
        let disposal = late
            .pop()
            .unwrap()
            .reserve()
            .unwrap()
            .reservation
            .submit()
            .unwrap();
        disposal.settle(&response(json!({})));
        assert_eq!(ledger.snapshot().object_debt, 0);
    }
    #[tokio::test]
    async fn unsent_old_receipt_never_submits_into_or_drops_a_later_group_lifecycle() {
        let (ledger, journal) = owner();
        let old = grouped(
            &ledger,
            &journal,
            "native-security-1",
            "DOM.resolveNode",
            json!({"objectGroup":"native-security-1"}),
        )
        .await;
        let release = ledger
            .reserve_command(
                Some(&journal),
                "Runtime.releaseObjectGroup",
                Some(&json!({"objectGroup":"native-security-1"})),
                Some("page"),
            )
            .unwrap()
            .submit()
            .unwrap();
        release.settle(&response(json!({})));
        let next = grouped(
            &ledger,
            &journal,
            "native-security-1",
            "DOM.resolveNode",
            json!({"objectGroup":"native-security-1"}),
        )
        .await;
        assert!(old.submit().is_err());
        assert_eq!(ledger.snapshot().object_debt, 1);
        next.submit()
            .unwrap()
            .settle(&response(json!({"object":{"objectId":"fresh"}})));
        assert_eq!(ledger.snapshot().object_debt, 1);
    }
    #[tokio::test]
    async fn abandoning_unsubmitted_group_does_not_leak_an_obligation() {
        let (ledger, journal) = owner();
        drop(
            grouped(
                &ledger,
                &journal,
                "native-query-1",
                "DOM.resolveNode",
                json!({"objectGroup":"native-query-1"}),
            )
            .await,
        );
        assert_eq!(ledger.snapshot().object_debt, 0);
    }
    #[test]
    fn realm_destruction_discharges_object_component_but_not_input_effect() {
        let (ledger, journal) = owner();
        ledger.observe_event(&CdpEvent {
            method: "Runtime.executionContextCreated".into(),
            session_id: Some("page".into()),
            params: json!({"context":{"id":9}}),
        });
        let submitted = ledger
            .reserve_command(
                Some(&journal),
                "Runtime.evaluate",
                Some(&json!({"contextId":9,"returnByValue":false})),
                Some("page"),
            )
            .unwrap()
            .submit()
            .unwrap();
        assert_eq!(
            (ledger.snapshot().input_debt, ledger.snapshot().object_debt),
            (1, 2)
        );
        ledger.observe_event(&CdpEvent {
            method: "Runtime.executionContextDestroyed".into(),
            session_id: Some("page".into()),
            params: json!({"executionContextId":9}),
        });
        assert_eq!(
            (ledger.snapshot().input_debt, ledger.snapshot().object_debt),
            (1, 0)
        );
        submitted.settle(&response(json!({"result":{"objectId":"destroyed"}})));
        assert_eq!(
            (ledger.snapshot().input_debt, ledger.snapshot().object_debt),
            (0, 0)
        );
        assert!(journal.snapshot().mutation_dispatched);
    }
    #[test]
    fn only_exact_context_ack_can_retire_owner_and_eof_never_clears_debt() {
        let (ledger, journal) = owner();
        ledger.bind_context("context").unwrap();
        let _command = ledger
            .reserve_command(Some(&journal), "Input.dispatchKeyEvent", None, Some("page"))
            .unwrap()
            .submit()
            .unwrap();
        assert!(ledger.retire_after_context_destroy("different").is_err());
        ledger.connection_lost();
        assert_eq!(ledger.snapshot().input_debt, 1);
        ledger.retire_after_context_destroy("context").unwrap();
        assert_eq!(ledger.snapshot().input_debt, 0);
        assert!(ledger
            .reserve_command(None, "Page.getFrameTree", None, Some("page"))
            .is_err());
    }
    #[test]
    fn realm_metadata_is_bounded_and_counted_without_borrowing_destroy_reserve() {
        let (ledger, _journal) = owner();
        for id in 1..4097 {
            ledger.observe_event(&CdpEvent {
                method: "Runtime.executionContextCreated".into(),
                session_id: Some("page".into()),
                params: json!({"context":{"id":id}}),
            });
        }
        let state = ledger.state.lock().unwrap();
        assert!(state.integrity_lost);
        assert!(metadata_usage(&state) <= 64 * 1024);
        assert!(state.realms.len() < 4096);
        drop(state);
        assert!(ledger
            .reserve_command(None, "Target.disposeBrowserContext", None, None)
            .is_ok());
    }
    #[tokio::test]
    async fn thirty_third_group_is_rejected_without_losing_existing_native_groups() {
        let (ledger, journal) = owner();
        for id in 0..32 {
            let name = format!("native-query-{id}");
            grouped(
                &ledger,
                &journal,
                &name,
                "DOM.resolveNode",
                json!({"objectGroup":name}),
            )
            .await
            .submit()
            .unwrap()
            .settle(&response(
                json!({"object":{"objectId":format!("root-{id}")}}),
            ));
        }
        let result = native_object_group("native-query-next", async {
            ledger.reserve_command(
                Some(&journal),
                "DOM.resolveNode",
                Some(&json!({"objectGroup":"native-query-next"})),
                Some("page"),
            )
        })
        .await;
        assert!(matches!(result, Err(ProtocolError::CapacityExceeded)));
        assert_eq!(ledger.snapshot().object_debt, MAX_OBJECT_DEBT);
        assert!(ledger
            .reserve_command(None, "Target.disposeBrowserContext", None, None)
            .is_ok());
    }
    #[test]
    fn malformed_or_foreign_response_never_becomes_an_input_ack() {
        for envelope in [
            json!({"id":1,"sessionId":"page"}),
            json!({"id":1,"sessionId":"page","result":{},"error":{"code":-32000,"message":"synthetic"}}),
            json!({"id":1,"sessionId":"foreign","result":{}}),
            json!({"id":1,"sessionId":"page","result":null}),
        ] {
            let (ledger, journal) = owner();
            let command = ledger
                .reserve_command(
                    Some(&journal),
                    "Input.dispatchMouseEvent",
                    None,
                    Some("page"),
                )
                .unwrap()
                .submit()
                .unwrap();
            command.settle(&serde_json::from_value(envelope).unwrap());
            assert!(ledger.snapshot().integrity_lost);
            assert_eq!(ledger.snapshot().input_debt, 1);
        }
        let (ledger, _journal) = owner();
        let command = ledger
            .reserve_command(None, "Target.disposeBrowserContext", None, None)
            .unwrap()
            .submit()
            .unwrap();
        command.settle(&response(json!({})));
        assert!(ledger.snapshot().integrity_lost);
        assert_eq!(ledger.snapshot().outstanding_commands, 1);
    }
    #[test]
    fn receiver_drop_between_settlement_and_delivery_still_selects_exact_disposal() {
        let (ledger, journal) = owner();
        let command = ledger
            .reserve_command(Some(&journal), "DOM.resolveNode", None, Some("page"))
            .unwrap()
            .submit()
            .unwrap();
        let reply = response(json!({"object":{"objectId":"race-object"}}));
        let (sender, receiver) = tokio::sync::oneshot::channel();
        assert!(!sender.is_closed());
        let mut disposals = command.settle_for_delivery(&reply);
        drop(receiver);
        let delivery_failed = sender.send(reply).is_err();
        assert!(delivery_failed);
        assert_eq!(disposals.len(), 1);
        let disposal = disposals.pop().unwrap();
        assert!(disposal.needed_after_delivery(delivery_failed));
        // A full/stopped queue drops only its unsent reservation, never debt.
        drop(disposal.reserve().unwrap());
        assert_eq!(ledger.snapshot().object_debt, 1);
    }
    #[tokio::test]
    async fn revoked_journal_rejects_old_application_step_but_admits_mandatory_cleanup() {
        let (ledger, journal) = owner();
        let command = ledger
            .reserve_command(Some(&journal), "Input.dispatchKeyEvent", None, Some("page"))
            .unwrap()
            .submit()
            .unwrap();
        let old = ledger
            .reserve_command(Some(&journal), "Input.dispatchKeyEvent", None, Some("page"))
            .unwrap();
        journal.revoke_application_submission();
        command.settle(&response(json!({})));
        assert!(old.submit().is_err());
        assert_eq!(ledger.snapshot().input_debt, 0);
        let cleanup = command_scope(CommandCategory::CleanupOther, false, async {
            ledger.reserve_command(
                Some(&journal),
                "Runtime.callFunctionOn",
                Some(&json!({"returnByValue":true})),
                Some("page"),
            )
        })
        .await
        .unwrap()
        .submit()
        .unwrap();
        cleanup.settle(&response(json!({"result":{"type":"boolean","value":true}})));
        assert_eq!(ledger.snapshot().object_debt, 0);
        assert!(journal.snapshot().mutation_dispatched);
    }
    #[test]
    fn rejected_object_release_is_retained_debt_not_cleanup_success() {
        let (ledger, journal) = owner();
        ledger
            .reserve_command(Some(&journal), "DOM.resolveNode", None, Some("page"))
            .unwrap()
            .submit()
            .unwrap()
            .settle(&response(json!({"object":{"objectId":"kept"}})));
        let reservation = ledger
            .reserve_command(
                Some(&journal),
                "Runtime.releaseObject",
                Some(&json!({"objectId":"kept"})),
                Some("page"),
            )
            .unwrap();
        let status = reservation.status();
        reservation.submit().unwrap().settle(
            &serde_json::from_value(
                json!({"id":2,"sessionId":"page","error":{"code":-32000,"message":"synthetic"}}),
            )
            .unwrap(),
        );
        assert_eq!(status.snapshot(), CommandStatus::RetainedRejected);
        assert!(!status.settled());
        assert_eq!(ledger.snapshot().object_debt, 1);
        assert!(!ledger.snapshot().integrity_lost);
    }
}
