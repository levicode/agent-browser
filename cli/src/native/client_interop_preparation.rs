//! Private constructor custody, not a published scope or a new authorization API.
//! The resource lives in a retained supervisor, never in a requesting RPC future.
//! This slice stops at an unpublished owner in the existing owner journal. Runtime
//! initialization/publication must be joined into the same supervisor before wire use.
use super::super::client_session::{ClientSession, OperationLease};
use super::interop_adoption::PreparedInteropBrowser;
use super::*;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot, watch};

type OwnerJournal = Arc<tokio::sync::Mutex<Option<OwnedBrowser>>>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Preparing,
    Ready,
    Adopting,
    Adopted,
    Published,
    Cleaning,
    Cleaned,
    CleanupFailed,
}
struct Entry {
    id: String,
    generation: u64,
    prepare_sequence: u64,
    deadline: Instant,
    phase: Phase,
    cancel: watch::Sender<bool>,
    adopt: mpsc::Sender<Adopt>,
    active_operation: Option<u64>,
}
struct Adopt {
    context: String,
    target: String,
    operation: OperationLease,
    reply: oneshot::Sender<Result<serde_json::Value, ProtocolError>>,
}
/// Minted only by the retained supervisor after dispatch-time revalidation.
/// It carries no RPC watch/sequence authority; the later real lease is still used.
pub(super) struct AdoptionPermit {
    generation: u64,
    prepare_sequence: u64,
    deadline: Instant,
}
impl AdoptionPermit {
    pub(super) fn check(
        &self,
        generation: u64,
        prepare_sequence: u64,
        deadline: Instant,
        operation: &OperationLease,
    ) -> Result<(), ProtocolError> {
        check_lifecycle_budget(operation)?;
        if operation.is_callback
            || self.generation != generation
            || self.prepare_sequence != prepare_sequence
            || self.deadline != deadline
            || operation.generation != generation
            || operation.sequence <= prepare_sequence
            || operation.deadline > deadline
        {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }
}

/// Held only across the synchronous gate publication attempt, never an await.
/// An abort cannot race usable publication and still claim preparation cleanup.
pub(super) struct PreparationPublication<'a> {
    slot: std::sync::MutexGuard<'a, Option<Entry>>,
}
impl PreparationPublication<'_> {
    pub(super) fn published(&mut self) {
        let entry = self.slot.as_mut().expect("publication owns exact entry");
        entry.phase = Phase::Published;
        entry.active_operation = None;
    }
}

/// At most one prepared resource and one retained join. Ordinary browser calls
/// never consult this slot. An exact ticket is routing, not resource ownership.
pub(super) struct InteropPreparation {
    entry: Mutex<Option<Entry>>,
    task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    owner: OwnerJournal,
    broker: Arc<ClientSession>,
    sealed: std::sync::atomic::AtomicBool,
}
impl InteropPreparation {
    pub(super) fn new(owner: OwnerJournal, broker: Arc<ClientSession>) -> Arc<Self> {
        Arc::new(Self {
            entry: Mutex::new(None),
            task: Default::default(),
            owner,
            broker,
            sealed: std::sync::atomic::AtomicBool::new(false),
        })
    }
    fn exact<'a>(
        entry: &'a mut Option<Entry>,
        generation: u64,
        id: &str,
    ) -> Result<&'a mut Entry, ProtocolError> {
        entry
            .as_mut()
            .filter(|entry| entry.generation == generation && entry.id == id)
            .ok_or(ProtocolError::StaleScope)
    }
    /// Metadata-only admission hook. The dispatcher repeats this check before
    /// claiming the resource, so an abort/expiry between the two cannot revive it.
    pub(super) fn admission_deadline_cap(
        &self,
        generation: u64,
        command: &str,
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Instant>, ProtocolError> {
        if !matches!(command, "scope.interop.adopt" | "scope.interop.abort") {
            return Ok(None);
        }
        let id = args
            .get("preparationId")
            .and_then(serde_json::Value::as_str)
            .ok_or(ProtocolError::InvalidArguments)?;
        let mut slot = self
            .entry
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let entry = Self::exact(&mut slot, generation, id)?;
        // Abort is cleanup control and may still join after the creation deadline.
        // It must match the same exact ticket but receives no renewed effect budget.
        if command == "scope.interop.abort" {
            return Ok(None);
        }
        if entry.phase != Phase::Ready || *entry.cancel.borrow() {
            return Err(ProtocolError::StaleScope);
        }
        Ok(Some(entry.deadline))
    }
    /// Caller retains `manager` on any preflight failure. Once taken, the retained
    /// worker owns it, including failures before preparation's ACK. The lifecycle
    /// guard belongs to that worker rather than the disposable RPC waiter.
    #[cfg(test)]
    pub(super) async fn prepare(
        self: &Arc<Self>,
        id: String,
        manager: &mut Option<super::super::browser::BrowserManager>,
        operation: OperationLease,
        transition: tokio::sync::OwnedMutexGuard<()>,
    ) -> Result<(), ProtocolError> {
        self.prepare_inner(id, manager, operation, transition, None)
            .await
    }

    pub(super) async fn prepare_scope(
        self: &Arc<Self>,
        id: String,
        manager: &mut Option<super::super::browser::BrowserManager>,
        operation: OperationLease,
        transition: tokio::sync::OwnedMutexGuard<()>,
        publisher: ScopeStartup,
        options: ScopeCreationOptions,
    ) -> Result<(), ProtocolError> {
        self.prepare_inner(
            id,
            manager,
            operation,
            transition,
            Some((publisher, options)),
        )
        .await
    }

    async fn prepare_inner(
        self: &Arc<Self>,
        id: String,
        manager: &mut Option<super::super::browser::BrowserManager>,
        operation: OperationLease,
        transition: tokio::sync::OwnedMutexGuard<()>,
        publication: Option<(ScopeStartup, ScopeCreationOptions)>,
    ) -> Result<(), ProtocolError> {
        check_lifecycle_budget(&operation)?;
        if operation.is_callback || id.len() != 36 || uuid::Uuid::parse_str(&id).is_err() {
            return Err(ProtocolError::InvalidArguments);
        }
        let mut task = self.task.lock().await;
        if task.as_ref().is_some_and(|task| !task.is_finished()) {
            return Err(ProtocolError::ScopeUnavailable);
        }
        if let Some(previous) = task.as_mut() {
            previous.await.map_err(|_| ProtocolError::CleanupFailed)?;
        }
        *task = None;
        if self.owner.lock().await.is_some() {
            return Err(ProtocolError::ScopeUnavailable);
        }
        let (cancel, lifetime) = watch::channel(false);
        let (adopt, requests) = mpsc::channel(1);
        let (reply, ready) = oneshot::channel();
        {
            let mut slot = self
                .entry
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            if self.sealed.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(ProtocolError::ScopeUnavailable);
            }
            if slot
                .as_ref()
                .is_some_and(|entry| entry.id == id || entry.phase == Phase::CleanupFailed)
            {
                return Err(ProtocolError::StaleScope);
            }
            if manager.is_none() {
                return Err(ProtocolError::InvalidArguments);
            }
            *slot = Some(Entry {
                id,
                generation: operation.generation,
                prepare_sequence: operation.sequence,
                deadline: operation.deadline,
                phase: Phase::Preparing,
                cancel,
                adopt,
                active_operation: Some(operation.sequence),
            });
        }
        let manager = manager
            .take()
            .expect("manager checked before custody transfer");
        let this = self.clone();
        *task = Some(tokio::spawn(async move {
            let _transition = transition;
            this.run(manager, operation, lifetime, requests, reply, publication)
                .await;
        }));
        drop(task);
        ready.await.map_err(|_| ProtocolError::CleanupFailed)?
    }
    async fn run(
        &self,
        manager: super::super::browser::BrowserManager,
        prepare: OperationLease,
        mut lifetime: watch::Receiver<bool>,
        mut requests: mpsc::Receiver<Adopt>,
        ready: oneshot::Sender<Result<(), ProtocolError>>,
        publication: Option<(ScopeStartup, ScopeCreationOptions)>,
    ) {
        let mut failed = None;
        let prepared = match PreparedInteropBrowser::prepare(manager, &prepare, &mut failed).await {
            Ok(prepared) => prepared,
            Err(error) => {
                self.cleanup(failed).await;
                let _ = ready.send(Err(error));
                return;
            }
        };
        if *lifetime.borrow() || check_lifecycle_budget(&prepare).is_err() {
            self.cleanup(Some(prepared.abort())).await;
            let _ = ready.send(Err(ProtocolError::Cancelled));
            return;
        }
        let deadline = prepare.deadline;
        // The old operation is no longer lifetime authority after this ACK. In
        // particular, sender closure after broker settlement must not cancel us.
        drop(prepare);
        let prepared = prepared.detach_request_authority();
        {
            let mut slot = self.entry.lock().unwrap();
            let entry = slot.as_mut().unwrap();
            entry.active_operation = None;
            entry.phase = Phase::Ready;
        }
        if ready.send(Ok(())).is_err() {
            self.cleanup(Some(prepared.abort())).await;
            return;
        }
        let request = tokio::select! {
            biased;
            _ = lifetime.changed() => None,
            _ = tokio::time::sleep_until(deadline.into()) => None,
            request = requests.recv() => request,
        };
        let Some(request) = request else {
            self.cleanup(Some(prepared.abort())).await;
            return;
        };
        let permit = {
            let slot = self.entry.lock().unwrap();
            let entry = slot.as_ref().unwrap();
            AdoptionPermit {
                generation: entry.generation,
                prepare_sequence: entry.prepare_sequence,
                deadline: entry.deadline,
            }
        };
        if *lifetime.borrow() || Instant::now() >= deadline {
            self.cleanup(Some(prepared.abort())).await;
            let _ = request.reply.send(Err(ProtocolError::Cancelled));
            return;
        }
        let result = prepared
            .adopt_retained(
                &request.context,
                &request.target,
                &request.operation,
                &permit,
                &mut failed,
            )
            .await;
        match result {
            Ok(resource) => {
                if *lifetime.borrow() || check_lifecycle_budget(&request.operation).is_err() {
                    self.cleanup(Some(resource)).await;
                    let _ = request.reply.send(Err(ProtocolError::Cancelled));
                    return;
                }
                if let Some((publisher, options)) = publication {
                    let result = publisher
                        .publish(resource, &request.operation, &options, Some(self))
                        .await;
                    if result.is_err() {
                        // The shared publisher has already completed cleanup or
                        // retained the failed owner. Never close a published owner
                        // through preparation's deadline or abort path.
                        let retained = self.owner.lock().await.is_some();
                        let mut slot = self.entry.lock().unwrap();
                        let entry = slot.as_mut().unwrap();
                        if entry.phase != Phase::Published {
                            entry.phase = if retained {
                                Phase::CleanupFailed
                            } else {
                                Phase::Cleaned
                            };
                        }
                    }
                    let _ = request.reply.send(result);
                    return;
                }
                // Constructor-only test handoff, not publication. Resource custody is
                // anchored before notifying the disposable requesting waiter.
                *self.owner.lock().await = Some(resource);
                self.phase(Phase::Adopted);
                let _ = request.reply.send(Ok(serde_json::Value::Null));
                // No runtime publication exists in this slice. Keep custody and
                // the lifecycle guard until expiry/abort/shutdown. Production
                // initialization must run here before returning a usable scope.
                tokio::select! {
                    biased;
                    _ = lifetime.changed() => {},
                    _ = tokio::time::sleep_until(deadline.into()) => {},
                }
                self.cleanup(None).await;
            }
            Err(error) => {
                self.cleanup(failed).await;
                let _ = request.reply.send(Err(error));
            }
        }
    }
    fn phase(&self, phase: Phase) {
        if let Ok(mut slot) = self.entry.lock() {
            if let Some(entry) = slot.as_mut() {
                entry.phase = phase;
            }
        }
    }
    async fn cleanup(&self, failed: Option<OwnedBrowser>) {
        self.phase(Phase::Cleaning);
        let mut owner = self.owner.lock().await;
        if let Some(resource) = failed {
            assert!(owner.is_none());
            *owner = Some(resource);
        }
        let result = match owner.as_mut() {
            Some(owner) => owner.close().await,
            None => Ok(()),
        };
        if result.is_ok() {
            *owner = None;
            self.phase(Phase::Cleaned);
        } else {
            self.phase(Phase::CleanupFailed);
        }
    }
    pub(super) async fn adopt(
        &self,
        generation: u64,
        id: &str,
        context: String,
        target: String,
        operation: OperationLease,
    ) -> Result<serde_json::Value, ProtocolError> {
        check_lifecycle_budget(&operation)?;
        let (reply, result) = oneshot::channel();
        let sender = {
            let mut slot = self
                .entry
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            let entry = Self::exact(&mut slot, generation, id)?;
            if entry.phase != Phase::Ready
                || *entry.cancel.borrow()
                || operation.is_callback
                || operation.generation != generation
                || operation.sequence <= entry.prepare_sequence
                || operation.deadline > entry.deadline
                || Instant::now() >= entry.deadline
            {
                return Err(ProtocolError::StaleScope);
            }
            entry.phase = Phase::Adopting;
            entry.active_operation = Some(operation.sequence);
            entry.adopt.clone()
        };
        sender
            .try_send(Adopt {
                context,
                target,
                operation,
                reply,
            })
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        result.await.map_err(|_| ProtocolError::CleanupFailed)?
    }
    pub(super) fn claim_publication(
        &self,
        operation: &OperationLease,
    ) -> Result<PreparationPublication<'_>, ProtocolError> {
        check_lifecycle_budget(operation)?;
        let slot = self
            .entry
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        let entry = slot.as_ref().ok_or(ProtocolError::StaleScope)?;
        if entry.phase != Phase::Adopting
            || *entry.cancel.borrow()
            || entry.generation != operation.generation
            || entry.active_operation != Some(operation.sequence)
            || operation.deadline > entry.deadline
            || Instant::now() >= entry.deadline
        {
            return Err(ProtocolError::StaleScope);
        }
        Ok(PreparationPublication { slot })
    }

    /// Cancellation requests real active-operation cancellation, then joins the
    /// retained worker. Dropping this waiter never aborts the worker or erases debt.
    /// The constructor slice also closes an unpublished adopted owner here.
    pub(super) async fn abort(&self, generation: u64, id: &str) -> Result<(), ProtocolError> {
        {
            let mut slot = self
                .entry
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            let entry = Self::exact(&mut slot, generation, id)?;
            if entry.phase == Phase::Published {
                // Normal owner lifecycle now owns cleanup. The caller may close
                // the client on an unknown adopt ACK; never race scope.end here.
                return Err(ProtocolError::StaleScope);
            }
            entry.cancel.send_replace(true);
            if let Some(sequence) = entry.active_operation {
                let _ = self.broker.cancel(generation, sequence);
            }
        }
        self.join().await?;
        self.cleaned()
    }
    async fn join(&self) -> Result<(), ProtocolError> {
        let mut task = self.task.lock().await;
        if let Some(task) = task.as_mut() {
            task.await.map_err(|_| ProtocolError::CleanupFailed)?;
        }
        *task = None;
        Ok(())
    }
    fn cleaned(&self) -> Result<(), ProtocolError> {
        let slot = self
            .entry
            .lock()
            .map_err(|_| ProtocolError::ScopeUnavailable)?;
        match slot.as_ref().map(|entry| entry.phase) {
            None | Some(Phase::Cleaned) => Ok(()),
            _ => Err(ProtocolError::CleanupFailed),
        }
    }
    pub(super) async fn shutdown(&self) -> Result<(), ProtocolError> {
        self.sealed.store(true, std::sync::atomic::Ordering::SeqCst);
        let published = {
            let mut slot = self
                .entry
                .lock()
                .map_err(|_| ProtocolError::ScopeUnavailable)?;
            match slot.as_mut() {
                None => return Ok(()),
                Some(entry) if entry.phase == Phase::Published => true,
                Some(entry) => {
                    entry.cancel.send_replace(true);
                    if let Some(sequence) = entry.active_operation {
                        let _ = self.broker.cancel(entry.generation, sequence);
                    }
                    false
                }
            }
        };
        self.join().await?;
        // Published owner cleanup belongs to ClientBrowser.shutdown/scope.end.
        // Never run preparation cleanup a second time after the transfer.
        if published {
            Ok(())
        } else {
            self.cleaned()
        }
    }
}

#[cfg(test)]
mod publication_tests {
    use super::super::super::client_protocol::Effects;
    use super::*;
    use std::time::Duration;

    fn adopting() -> (
        Arc<InteropPreparation>,
        OperationLease,
        Arc<ExecutionGate>,
        LifecycleInitialization,
    ) {
        let broker = Arc::new(ClientSession::new());
        let prepare = broker.admit(1, 1, 5000).unwrap();
        broker.settle(1, 1, Effects::Completed).unwrap();
        let operation = broker
            .admit_callback_capped(1, 2, 5000, None, Ok(Some(prepare.deadline)))
            .unwrap();
        assert!(broker.start(1, 2).unwrap());
        let custody = InteropPreparation::new(Arc::new(tokio::sync::Mutex::new(None)), broker);
        let (cancel, _) = watch::channel(false);
        let (adopt, _) = mpsc::channel(1);
        *custody.entry.lock().unwrap() = Some(Entry {
            id: "publication-ticket".into(),
            generation: 1,
            prepare_sequence: 1,
            deadline: prepare.deadline,
            phase: Phase::Adopting,
            cancel,
            adopt,
            active_operation: Some(2),
        });
        let gate = Arc::new(ExecutionGate::default());
        gate.begin_transition().unwrap();
        let authority = gate
            .initialization(
                super::super::super::client_targets::ClientTargets::new_managed(
                    "exact-context".into(),
                    "exact-scope".into(),
                ),
            )
            .unwrap();
        (custody, operation, gate, authority)
    }

    #[tokio::test]
    async fn usable_publication_atomically_ends_preparation_cleanup_authority() {
        let (custody, operation, gate, authority) = adopting();
        {
            let mut transfer = custody.claim_publication(&operation).unwrap();
            authority.publish().unwrap();
            transfer.published();
        }
        // Expire only the old preparation metadata. A live scope is no longer
        // governed by that timer and cannot be closed by an old ticket's abort.
        custody.entry.lock().unwrap().as_mut().unwrap().deadline =
            Instant::now() - Duration::from_secs(1);
        assert_eq!(
            custody.abort(1, "publication-ticket").await,
            Err(ProtocolError::StaleScope)
        );
        assert_eq!(
            *operation.cancellation.borrow(),
            super::super::super::client_session::CancelSignal::None
        );
        assert!(gate.enter(false).is_ok());
        custody.shutdown().await.unwrap();
        assert_eq!(
            custody.entry.lock().unwrap().as_ref().unwrap().phase,
            Phase::Published
        );
        assert!(
            gate.enter(false).is_ok(),
            "normal owner lifecycle, not preparation, seals this gate"
        );
    }

    #[test]
    fn cancellation_or_expiry_before_publication_keeps_application_closed() {
        for expire in [false, true] {
            let (custody, operation, gate, _authority) = adopting();
            {
                let mut slot = custody.entry.lock().unwrap();
                let entry = slot.as_mut().unwrap();
                if expire {
                    entry.deadline = Instant::now() - Duration::from_secs(1);
                } else {
                    entry.cancel.send_replace(true);
                }
            }
            assert!(matches!(
                custody.claim_publication(&operation),
                Err(ProtocolError::StaleScope)
            ));
            assert!(gate.enter(false).is_err());
            assert_eq!(
                custody.entry.lock().unwrap().as_ref().unwrap().phase,
                Phase::Adopting
            );
        }
    }
}
