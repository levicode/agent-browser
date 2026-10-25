//! Shared protected-read stabilization. Browser conformance is an explicit gate;
//! the existence of this module does not advertise a protected capability.

use super::client_browser::BrowserExecutionLease;
use super::client_debt::{command_scope, CommandCategory};
use super::client_protected_read_residual::{
    MaskRecord, MaskStep, RateRecord, RawState, Record, Records,
};
use super::client_session::{CancelSignal, OperationLease};
use super::client_targets::{ProtectedTargetBarrier, TargetPurpose};
use serde_json::{json, Value};
use std::sync::{Arc, MutexGuard};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedReadReason {
    Cancelled,
    Superseded,
    CleanupFailed,
    Deadline,
    StaleScope,
    IncompleteInventory,
    BrowserFailure,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedReadFailure {
    pub reason: ProtectedReadReason,
    pub identity_scope: String,
    pub cleanup_integrity_lost: bool,
}

/// One stabilization journal shared by semantic and pixel reads. Its enclosing
/// task must be retained by the native owner through restore, even if the RPC
/// receiver is dropped. Admission must already exclude all UI mutations.
/// This does not advertise a capability: target event enrollment and Chromium
/// source-mask/read conformance remain separately required deployment gates.
pub struct ProtectedReadJournal<'a> {
    page: &'a BrowserExecutionLease,
    operation: &'a OperationLease,
    barrier: ProtectedTargetBarrier,
    sessions: Vec<String>,
    record: Arc<Record>,
    cleanup_deadline: Option<Instant>,
    restored: bool,
    started: bool,
    stabilization_completed: bool,
    command_cleanup_lost: std::sync::atomic::AtomicBool,
}
impl<'a> ProtectedReadJournal<'a> {
    pub fn begin(
        page: &'a BrowserExecutionLease,
        operation: &'a OperationLease,
    ) -> Result<Self, ProtectedReadFailure> {
        let failure = |reason| ProtectedReadFailure {
            reason,
            identity_scope: page.identity_scope.clone(),
            cleanup_integrity_lost: false,
        };
        let barrier = page
            .targets
            .protected_read_barrier()
            .map_err(|_| failure(ProtectedReadReason::IncompleteInventory))?;
        if barrier.stamp.identity_scope != page.identity_scope {
            return Err(failure(ProtectedReadReason::StaleScope));
        }
        let mut sessions = Vec::new();
        let mut main = false;
        for target in &barrier.stamp.targets {
            if target.purpose != Some(TargetPurpose::Application) {
                return Err(failure(ProtectedReadReason::IncompleteInventory));
            }
            if matches!(target.kind.as_str(), "page" | "iframe") {
                main |=
                    target.session_id == page.page_session_id && target.target_id == page.target_id;
                sessions.push(target.session_id.clone());
            }
        }
        if !main {
            return Err(failure(ProtectedReadReason::IncompleteInventory));
        }
        sessions.sort();
        sessions.dedup();
        let record = page
            .targets
            .protected_read_residual
            .reserve(
                super::client_debt::OperationKey {
                    generation: operation.generation,
                    operation_seq: operation.sequence,
                },
                &page.page_session_id,
                page.client.clone(),
            )
            .map_err(|_| failure(ProtectedReadReason::CleanupFailed))?;
        let journal = Self {
            page,
            operation,
            barrier,
            sessions,
            record,
            cleanup_deadline: None,
            restored: false,
            started: false,
            stabilization_completed: false,
            command_cleanup_lost: std::sync::atomic::AtomicBool::new(false),
        };
        journal.check().map_err(failure)?;
        Ok(journal)
    }
    fn records(&self) -> Result<MutexGuard<'_, Records>, ProtectedReadReason> {
        self.record
            .data
            .lock()
            .map_err(|_| ProtectedReadReason::CleanupFailed)
    }
    pub(crate) fn begin_cleanup(&mut self) -> Instant {
        *self
            .cleanup_deadline
            .get_or_insert_with(|| Instant::now() + Duration::from_secs(3))
    }
    pub(crate) fn raw_capture_started(&self) -> Result<(), ProtectedReadReason> {
        let mut records = self.records()?;
        if records.raw != RawState::NotStarted {
            return Err(ProtectedReadReason::CleanupFailed);
        }
        records.raw = RawState::Pending;
        Ok(())
    }
    pub(crate) fn raw_capture_completed(&self) -> Result<(), ProtectedReadReason> {
        let mut records = self.records()?;
        if records.raw != RawState::Pending {
            return Err(ProtectedReadReason::CleanupFailed);
        }
        records.raw = RawState::SuccessfulReply;
        Ok(())
    }
    fn raw_unresolved(&self) -> bool {
        self.records()
            .map_or(true, |records| matches!(records.raw, RawState::Pending))
    }
    pub fn check(&self) -> Result<(), ProtectedReadReason> {
        self.page
            .permit
            .check()
            .map_err(|_| ProtectedReadReason::StaleScope)?;
        self.barrier
            .check()
            .map_err(|_| ProtectedReadReason::StaleScope)?;
        if *self.operation.cancellation.borrow() != CancelSignal::None {
            return Err(ProtectedReadReason::Cancelled);
        }
        if Instant::now() >= self.operation.deadline {
            return Err(ProtectedReadReason::Deadline);
        }
        if super::client_observation::capture_superseded() {
            return Err(ProtectedReadReason::Superseded);
        }
        Ok(())
    }
    /// A successful begin is not evidence that animation stabilization completed.
    /// Pixel and semantic consumers use this before reading protected content.
    pub fn require_stabilized(&self) -> Result<(), ProtectedReadReason> {
        if !self.stabilization_completed || self.restored {
            return Err(ProtectedReadReason::IncompleteInventory);
        }
        self.check()
    }
    pub fn contains_session(&self, session: &str) -> bool {
        self.sessions.iter().any(|value| value == session)
    }
    pub async fn command(
        &self,
        session: &str,
        method: &str,
        args: Value,
    ) -> Result<Value, ProtectedReadReason> {
        if self.restored {
            return Err(ProtectedReadReason::StaleScope);
        }
        self.check()?;
        if !self.contains_session(session) {
            return Err(ProtectedReadReason::IncompleteInventory);
        }
        if !super::client_observation::capture_retirement_active() {
            let mut cancellation = self.operation.cancellation.clone();
            return tokio::select! {
                result = self.page.client.send_command(method, Some(args), Some(session)) => {
                    self.check()?;
                    result.map_err(|_| ProtectedReadReason::BrowserFailure)
                }
                _ = cancellation.changed() => Err(ProtectedReadReason::Cancelled),
                _ = tokio::time::sleep_until(self.operation.deadline.into()) => Err(ProtectedReadReason::Deadline),
            };
        }
        let result = super::client_observation::retained_read_command(
            &self.page.client,
            session,
            method,
            args,
            self.operation,
        )
        .await
        .map_err(|error| match error {
            super::client_observation::ObservationError::Cancelled => {
                ProtectedReadReason::Cancelled
            }
            super::client_observation::ObservationError::DeadlineExceeded => {
                ProtectedReadReason::Deadline
            }
            super::client_observation::ObservationError::Superseded => {
                ProtectedReadReason::Superseded
            }
            super::client_observation::ObservationError::CleanupFailed { .. } => {
                self.command_cleanup_lost
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                self.barrier.quarantine();
                ProtectedReadReason::CleanupFailed
            }
            _ => ProtectedReadReason::BrowserFailure,
        });
        if result.is_ok() && !super::client_observation::produces_remote_objects(method) {
            self.check()?;
        }
        result
    }
    async fn read_command(
        &self,
        session: &str,
        method: &str,
        args: Value,
    ) -> Result<Value, ProtectedReadReason> {
        command_scope(
            CommandCategory::ApplicationRead,
            false,
            self.command(session, method, args),
        )
        .await
    }
    pub async fn stabilize_animations(&mut self) -> Result<(), ProtectedReadReason> {
        if self.started || self.restored {
            return Err(ProtectedReadReason::StaleScope);
        }
        self.started = true;
        for session in self.sessions.clone() {
            self.command(&session, "Animation.enable", json!({}))
                .await?;
            let rate = self
                .read_command(&session, "Animation.getPlaybackRate", json!({}))
                .await?["playbackRate"]
                .as_f64()
                .filter(|rate| rate.is_finite())
                .ok_or(ProtectedReadReason::BrowserFailure)?;
            // Journal before delivery: lost acknowledgements may still mutate.
            self.records()?.rates.push(RateRecord {
                session: session.clone(),
                original: rate,
                acknowledged: false,
            });
            self.command(
                &session,
                "Animation.setPlaybackRate",
                json!({"playbackRate":0}),
            )
            .await?;
        }
        self.check()?;
        self.stabilization_completed = true;
        Ok(())
    }
    /// Ownership is recorded before any source stylesheet is inserted. The
    /// object retains exact nodes and native removal methods in an isolated world.
    pub(crate) fn reserve_source_group(
        &mut self,
        session: String,
        group: String,
    ) -> Result<(), ProtectedReadReason> {
        self.require_stabilized()?;
        if !self.contains_session(&session) {
            return Err(ProtectedReadReason::IncompleteInventory);
        }
        let mut records = self.records()?;
        if records.masks.len() >= 4096
            || records
                .masks
                .iter()
                .any(|mask| mask.session == session && mask.group == group)
        {
            return Err(ProtectedReadReason::IncompleteInventory);
        }
        records.masks.push(MaskRecord {
            session,
            holder: None,
            group,
            step: MaskStep::InstalledOrUnknown,
        });
        Ok(())
    }
    pub(crate) fn bind_source_holder(
        &mut self,
        session: &str,
        group: &str,
        object: String,
    ) -> Result<(), ProtectedReadReason> {
        let mut records = self.records()?;
        let mask = records
            .masks
            .iter_mut()
            .find(|mask| mask.session == session && mask.group == group)
            .ok_or(ProtectedReadReason::IncompleteInventory)?;
        if mask.holder.is_some() {
            return Err(ProtectedReadReason::IncompleteInventory);
        }
        mask.holder = Some(object);
        Ok(())
    }
    pub(crate) async fn verify_source_masks(&self) -> Result<(), ProtectedReadReason> {
        let masks = self.records()?.masks.clone();
        for mask in masks {
            if mask.step != MaskStep::InstalledOrUnknown {
                return Err(ProtectedReadReason::IncompleteInventory);
            }
            let object = mask
                .holder
                .as_ref()
                .ok_or(ProtectedReadReason::IncompleteInventory)?;
            let response = self.read_command(&mask.session, "Runtime.callFunctionOn", json!({"objectId":object,"functionDeclaration":"function(){return this.verify()}","returnByValue":true,"objectGroup":mask.group})).await?;
            if response.get("exceptionDetails").is_some() || response["result"]["value"] != true {
                return Err(ProtectedReadReason::BrowserFailure);
            }
        }
        Ok(())
    }
    pub(crate) async fn remove_source_masks(&mut self) -> Result<(), ProtectedReadReason> {
        let deadline = self.begin_cleanup();
        self.remove_source_masks_until(deadline).await
    }
    async fn remove_source_masks_until(
        &mut self,
        deadline: Instant,
    ) -> Result<(), ProtectedReadReason> {
        if self.raw_unresolved() || Instant::now() >= deadline {
            return Err(ProtectedReadReason::CleanupFailed);
        }
        let attempts = self.records()?.masks.clone();
        for mask in attempts.into_iter().rev() {
            if mask.step == MaskStep::GroupReleased {
                continue;
            }
            if Instant::now() >= deadline {
                break;
            }
            if mask.step == MaskStep::InstalledOrUnknown {
                if let Some(handle) = &mask.holder {
                    let result = tokio::time::timeout_at(deadline.into(), command_scope(CommandCategory::CleanupOther, false,
                        self.page.client.send_command("Runtime.callFunctionOn", Some(json!({"objectId":handle,"functionDeclaration":"function(){return this.remove()}","returnByValue":true,"objectGroup":mask.group})), Some(&mask.session)))).await;
                    if !matches!(&result, Ok(Ok(value)) if value.get("exceptionDetails").is_none() && value["result"]["value"] == true)
                    {
                        continue;
                    }
                }
                self.records()?
                    .masks
                    .iter_mut()
                    .find(|owned| owned.session == mask.session && owned.group == mask.group)
                    .ok_or(ProtectedReadReason::CleanupFailed)?
                    .step = MaskStep::Removed;
            }
            if Instant::now() >= deadline {
                break;
            }
            let released = tokio::time::timeout_at(
                deadline.into(),
                self.page.client.send_command(
                    "Runtime.releaseObjectGroup",
                    Some(json!({"objectGroup":mask.group})),
                    Some(&mask.session),
                ),
            )
            .await;
            if matches!(released, Ok(Ok(_))) {
                self.records()?
                    .masks
                    .iter_mut()
                    .find(|owned| owned.session == mask.session && owned.group == mask.group)
                    .ok_or(ProtectedReadReason::CleanupFailed)?
                    .step = MaskStep::GroupReleased;
            }
        }
        if self
            .records()?
            .masks
            .iter()
            .any(|mask| mask.step != MaskStep::GroupReleased)
        {
            self.barrier.quarantine();
            return Err(ProtectedReadReason::BrowserFailure);
        }
        Ok(())
    }
    /// Always call after stabilization, including failure/cancellation. Cleanup
    /// ignores the expired operation budget but has one total three-second cap.
    /// No staged value may escape until both restore and final check succeed.
    pub async fn restore(&mut self) -> Result<(), ProtectedReadFailure> {
        if self.restored {
            return Ok(());
        }
        #[cfg(feature = "acceptance-faults")]
        eprintln!(
            "native-settlement sequence={} phase=ProtectedRestoreBegin",
            self.operation.sequence
        );
        let deadline = self.begin_cleanup();
        if self.raw_unresolved() || Instant::now() >= deadline {
            self.record.leave_residual();
            self.barrier.quarantine();
            return Err(ProtectedReadFailure {
                reason: ProtectedReadReason::CleanupFailed,
                identity_scope: self.page.identity_scope.clone(),
                cleanup_integrity_lost: true,
            });
        }
        let mut complete = self.remove_source_masks_until(deadline).await.is_ok();
        complete &= !self
            .command_cleanup_lost
            .load(std::sync::atomic::Ordering::SeqCst);
        let rates = self
            .records()
            .map(|records| records.rates.clone())
            .unwrap_or_default();
        for (index, rate) in rates.iter().enumerate().rev() {
            if rate.acknowledged {
                continue;
            }
            let session = &rate.session;
            let command_deadline = deadline.min(Instant::now() + Duration::from_millis(500));
            if Instant::now() >= deadline {
                complete = false;
                break;
            }
            let acknowledged = matches!(
                tokio::time::timeout_at(
                    command_deadline.into(),
                    command_scope(
                        CommandCategory::CleanupOther,
                        false,
                        self.page.client.send_command(
                            "Animation.setPlaybackRate",
                            Some(json!({"playbackRate":rate.original})),
                            Some(session)
                        )
                    )
                )
                .await,
                Ok(Ok(_))
            );
            complete &= acknowledged;
            if acknowledged {
                if let Ok(mut records) = self.records() {
                    records.rates[index].acknowledged = true;
                } else {
                    complete = false;
                }
            }
        }
        #[cfg(feature = "acceptance-faults")]
        eprintln!(
            "native-settlement sequence={} phase=ProtectedRestoreEnd integrity={}",
            self.operation.sequence, complete
        );
        if complete {
            complete = self
                .page
                .targets
                .protected_read_residual
                .finish_restored(&self.record)
                .is_ok();
        }
        if !complete {
            self.record.leave_residual();
            self.barrier.quarantine();
            return Err(ProtectedReadFailure {
                reason: ProtectedReadReason::BrowserFailure,
                identity_scope: self.page.identity_scope.clone(),
                cleanup_integrity_lost: true,
            });
        }
        self.restored = true;
        Ok(())
    }
}
impl Drop for ProtectedReadJournal<'_> {
    fn drop(&mut self) {
        if !self.restored {
            if !self.record.has_effects()
                && self
                    .page
                    .targets
                    .protected_read_residual
                    .finish_restored(&self.record)
                    .is_ok()
            {
                return;
            }
            self.record.leave_residual();
            self.barrier.quarantine();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::cdp::client::CdpClient;
    use super::super::client_browser::{ExecutionGate, OwnedBrowser};
    use base64::Engine;
    use serde_json::{json, Value};

    use std::sync::Arc;
    use std::time::Duration;

    async fn journal_fixture(
        fail_restore: bool,
        stale_during_restore: bool,
    ) -> (
        super::super::client_browser::BrowserExecutionLease,
        super::super::client_session::OperationLease,
        tokio::sync::watch::Sender<super::super::client_session::CancelSignal>,
        tokio::task::JoinHandle<()>,
        Arc<std::sync::Mutex<Vec<Value>>>,
    ) {
        use super::super::client_session::{CancelSignal, OperationLease};
        use super::super::client_targets::ClientTargets;
        use futures_util::{SinkExt, StreamExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let targets = ClientTargets::new("context".into(), "scope".into());
        targets
            .attached("context", "target".into(), "session".into(), "page".into())
            .unwrap();
        targets.configured("target").unwrap();
        targets
            .resume_permit("target")
            .await
            .unwrap()
            .complete()
            .unwrap();
        targets.acknowledge_enrollment().unwrap(); // Synthetic fixture only.
        let server_targets = targets.clone();
        let records = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = records.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = ws.next().await {
                let Ok(text) = message.to_text() else {
                    continue;
                };
                let request: Value = serde_json::from_str(text).unwrap();
                recorded.lock().unwrap().push(request.clone());
                let mut response = json!({"id":request["id"],"sessionId":request["sessionId"],"result":if request["method"]=="Animation.getPlaybackRate" {json!({"playbackRate":1})} else {json!({})}});
                if request["method"] == "Runtime.callFunctionOn" {
                    response["result"] = json!({"result":{"value":true}});
                    if request["params"]["objectId"] == "fail-remove"
                        && request["params"]["functionDeclaration"]
                            == "function(){return this.remove()}"
                    {
                        response.as_object_mut().unwrap().remove("result");
                        response["error"] =
                            json!({"code":-32000,"message":"synthetic source cleanup failure"});
                    }
                }
                if request["method"] == "Runtime.releaseObjectGroup"
                    && request["params"]["objectGroup"] == "fail-release"
                {
                    response.as_object_mut().unwrap().remove("result");
                    response["error"] =
                        json!({"code":-32000,"message":"synthetic group release refusal"});
                }
                if stale_during_restore
                    && request["method"] == "Animation.setPlaybackRate"
                    && request["params"]["playbackRate"].as_f64() == Some(1.0)
                {
                    server_targets.invalidate_inventory().unwrap();
                }
                if fail_restore
                    && request["method"] == "Animation.setPlaybackRate"
                    && request["params"]["playbackRate"].as_f64() == Some(1.0)
                {
                    response.as_object_mut().unwrap().remove("result");
                    response["error"] =
                        json!({"code":-32000,"message":"synthetic cleanup failure"});
                }
                if ws
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        response.to_string(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let client = Arc::new(CdpClient::connect(&url).await.unwrap());
        let gate = Arc::new(ExecutionGate::default());
        let page = super::super::client_browser::BrowserExecutionLease {
            client,
            page_session_id: "session".into(),
            target_id: "target".into(),
            identity_scope: "scope".into(),
            permit: gate.enter(false).unwrap(),
            targets,
        };
        let (sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 1,
            deadline: std::time::Instant::now() + Duration::from_secs(5),
            cancellation,
        };
        (page, operation, sender, server, records)
    }
    #[tokio::test]
    async fn residual_poisoned_records_survive_journal_drop() {
        let (page, operation, _sender, server, _requests) = journal_fixture(false, false).await;
        let mut journal = super::ProtectedReadJournal::begin(&page, &operation).unwrap();
        journal.stabilize_animations().await.unwrap();
        let record = journal.record.clone();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = record.data.lock().unwrap();
            panic!("synthetic journal poison");
        }))
        .is_err());
        drop(journal);
        let retained = page
            .targets
            .protected_read_residual
            .snapshot_for_test()
            .unwrap();
        assert!(Arc::ptr_eq(&record, &retained));
        let data = match retained.data.lock() {
            Err(error) => error.into_inner(),
            Ok(_) => panic!("poison must persist"),
        };
        assert_eq!(data.rates[0].original, 1.0);
        assert!(!data.rates[0].acknowledged);
        drop(data);
        assert!(page
            .targets
            .protected_read_residual
            .replacement_safe()
            .is_err());
        page.client.close().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn residual_expired_cleanup_deadline_sends_no_restore_commands() {
        let (page, operation, _sender, server, requests) = journal_fixture(false, false).await;
        let mut journal = super::ProtectedReadJournal::begin(&page, &operation).unwrap();
        journal.stabilize_animations().await.unwrap();
        journal.cleanup_deadline = Some(std::time::Instant::now() - Duration::from_millis(1));
        let before = requests.lock().unwrap().len();
        assert!(journal.restore().await.is_err());
        assert_eq!(requests.lock().unwrap().len(), before);
        drop(journal);
        assert!(page
            .targets
            .protected_read_residual
            .snapshot_for_test()
            .is_some());
        page.client.close().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn residual_group_release_failure_keeps_removed_stage() {
        let (page, operation, _sender, server, _requests) = journal_fixture(false, false).await;
        let mut journal = super::ProtectedReadJournal::begin(&page, &operation).unwrap();
        journal.stabilize_animations().await.unwrap();
        journal
            .reserve_source_group("session".into(), "fail-release".into())
            .unwrap();
        journal
            .bind_source_holder("session", "fail-release", "holder".into())
            .unwrap();
        assert!(journal.restore().await.is_err());
        drop(journal);
        let record = page
            .targets
            .protected_read_residual
            .snapshot_for_test()
            .unwrap();
        let data = record.data.lock().unwrap();
        assert_eq!(data.masks[0].step, super::MaskStep::Removed);
        assert!(data.rates[0].acknowledged);
        drop(data);
        page.client.close().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn residual_owner_binding_rejects_other_client_generation_and_ledger_change() {
        let (page, operation, _sender, server, requests) = journal_fixture(false, false).await;
        let (other, _op, _sender2, server2, _requests2) = journal_fixture(false, false).await;
        drop(super::ProtectedReadJournal::begin(&page, &operation).unwrap());
        let slot = &page.targets.protected_read_residual;
        let key = super::super::client_debt::OperationKey {
            generation: operation.generation,
            operation_seq: operation.sequence,
        };
        assert!(slot.reserve(key, "session", other.client.clone()).is_err());
        assert!(slot
            .reserve(
                super::super::client_debt::OperationKey {
                    generation: 2,
                    ..key
                },
                "session",
                page.client.clone()
            )
            .is_err());
        let ledger = super::super::client_debt::OwnerDebtLedger::new(1, "scope".into());
        page.client.install_debt_ledger(ledger).unwrap();
        assert!(
            slot.reserve(key, "session", page.client.clone()).is_err(),
            "None -> Some must not silently change the bound owner"
        );
        assert!(requests.lock().unwrap().is_empty());
        page.client.close().await;
        other.client.close().await;
        server.await.unwrap();
        server2.await.unwrap();
    }

    #[tokio::test]
    async fn residual_drop_keeps_exact_coordinates_and_refuses_next_read() {
        let (page, operation, _sender, server, requests) = journal_fixture(false, false).await;
        let mut journal = super::ProtectedReadJournal::begin(&page, &operation).unwrap();
        journal.stabilize_animations().await.unwrap();
        journal
            .reserve_source_group("session".into(), "owned-mask".into())
            .unwrap();
        journal
            .bind_source_holder("session", "owned-mask", "holder".into())
            .unwrap();
        journal.raw_capture_started().unwrap();
        let exact = journal.record.clone();
        drop(journal);
        let slot = &page.targets.protected_read_residual;
        let retained = slot.snapshot_for_test().unwrap();
        assert!(Arc::ptr_eq(&exact, &retained));
        assert!(slot.replacement_safe().is_err());
        let data = retained.data.lock().unwrap();
        assert_eq!(data.masks[0].session, "session");
        assert_eq!(data.masks[0].holder.as_deref(), Some("holder"));
        assert_eq!(data.masks[0].group, "owned-mask");
        assert_eq!(data.rates[0].original, 1.0);
        assert!(!data.rates[0].acknowledged);
        assert_eq!(data.raw, super::RawState::Pending);
        drop(data);
        let before = requests.lock().unwrap().len();
        assert!(super::ProtectedReadJournal::begin(&page, &operation).is_err());
        tokio::task::yield_now().await;
        assert_eq!(
            requests.lock().unwrap().len(),
            before,
            "residual must not retry or mutate"
        );
        assert!(Arc::ptr_eq(&exact, &slot.snapshot_for_test().unwrap()));
        // Test harness teardown only AFTER verifying retained custody/no retries.
        page.client.close().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn residual_partial_failure_preserves_acknowledged_and_unresolved_steps() {
        let (page, operation, _sender, server, _requests) = journal_fixture(false, false).await;
        let mut journal = super::ProtectedReadJournal::begin(&page, &operation).unwrap();
        journal.stabilize_animations().await.unwrap();
        journal
            .reserve_source_group("session".into(), "remaining-group".into())
            .unwrap();
        journal
            .bind_source_holder("session", "remaining-group", "fail-remove".into())
            .unwrap();
        assert!(journal.restore().await.is_err());
        drop(journal);
        let retained = page
            .targets
            .protected_read_residual
            .snapshot_for_test()
            .unwrap();
        let data = retained.data.lock().unwrap();
        assert_eq!(data.masks[0].step, super::MaskStep::InstalledOrUnknown);
        assert_eq!(data.masks[0].holder.as_deref(), Some("fail-remove"));
        assert!(
            data.rates[0].acknowledged,
            "successful restore ACK must not be forgotten"
        );
        drop(data);
        assert!(page
            .targets
            .protected_read_residual
            .replacement_safe()
            .is_err());
        page.client.close().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn residual_empty_drop_and_complete_restore_release_only_exact_slot() {
        let (page, operation, _sender, server, _requests) = journal_fixture(false, false).await;
        drop(super::ProtectedReadJournal::begin(&page, &operation).unwrap());
        assert!(page
            .targets
            .protected_read_residual
            .snapshot_for_test()
            .is_none());
        let mut journal = super::ProtectedReadJournal::begin(&page, &operation).unwrap();
        journal.stabilize_animations().await.unwrap();
        journal.restore().await.unwrap();
        drop(journal);
        assert!(page
            .targets
            .protected_read_residual
            .snapshot_for_test()
            .is_none());
        assert!(page
            .targets
            .protected_read_residual
            .replacement_safe()
            .is_ok());
        page.client.close().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn supersession_never_cancels_owned_source_or_animation_restore() {
        use super::super::client_observation::{with_capture_retirement, CaptureRetirement};
        for fail in [false, true] {
            let (page, operation, cancel, server, records) = journal_fixture(fail, false).await;
            let (stop, receiver) = tokio::sync::watch::channel(false);
            with_capture_retirement(Some(CaptureRetirement::new(receiver)), async {
                let mut journal = super::ProtectedReadJournal::begin(&page, &operation).unwrap();
                journal.stabilize_animations().await.unwrap();
                journal
                    .reserve_source_group("session".into(), "retired-source".into())
                    .unwrap();
                journal
                    .bind_source_holder("session", "retired-source", "retired-holder".into())
                    .unwrap();
                stop.send_replace(true);
                assert_eq!(journal.check(), Err(super::ProtectedReadReason::Superseded));
                cancel.send_replace(super::super::client_session::CancelSignal::Requested);
                assert_eq!(journal.check(), Err(super::ProtectedReadReason::Cancelled));
                let restored = journal.restore().await;
                assert_eq!(restored.is_err(), fail);
                if let Err(failure) = restored {
                    assert!(failure.cleanup_integrity_lost);
                }
                let commands = records.lock().unwrap();
                assert_eq!(
                    commands
                        .iter()
                        .filter(|r| r["method"] == "Runtime.callFunctionOn"
                            && r["params"]["objectId"] == "retired-holder"
                            && r["params"]["functionDeclaration"]
                                == "function(){return this.remove()}")
                        .count(),
                    1
                );
                assert_eq!(
                    commands
                        .iter()
                        .filter(|r| r["method"] == "Runtime.releaseObjectGroup"
                            && r["params"]["objectGroup"] == "retired-source")
                        .count(),
                    1
                );
                assert_eq!(
                    commands
                        .iter()
                        .filter(|r| r["method"] == "Animation.setPlaybackRate"
                            && r["params"]["playbackRate"].as_f64() == Some(1.0))
                        .count(),
                    1
                );
            })
            .await;
            assert_eq!(page.targets.inventory().is_err(), fail);
            server.abort();
        }
    }

    #[tokio::test]
    async fn protected_journal_restores_before_releasing_barrier() {
        let (page, operation, _sender, server, _records) = journal_fixture(false, false).await;
        let mut journal = super::ProtectedReadJournal::begin(&page, &operation).unwrap();
        assert!(journal.require_stabilized().is_err());
        journal.stabilize_animations().await.unwrap();
        journal.require_stabilized().unwrap();
        assert!(page.targets.protected_read_barrier().is_err());
        journal.restore().await.unwrap();
        assert!(journal.require_stabilized().is_err());
        journal.check().unwrap();
        drop(journal);
        assert!(page.targets.protected_read_barrier().is_ok());
        server.abort();
    }
    #[tokio::test]
    async fn protected_journal_abandonment_and_cleanup_failure_seal_original_scope() {
        for cleanup in [false, true] {
            let (page, operation, _sender, server, _records) =
                journal_fixture(cleanup, false).await;
            let mut journal = super::ProtectedReadJournal::begin(&page, &operation).unwrap();
            journal.stabilize_animations().await.unwrap();
            if cleanup {
                let error = journal.restore().await.unwrap_err();
                assert!(error.cleanup_integrity_lost);
                assert_eq!(error.identity_scope, "scope");
            }
            drop(journal);
            assert!(page.targets.inventory().is_err());
            server.abort();
        }
    }

    #[tokio::test]
    async fn protected_journal_clean_restore_does_not_authorize_stale_publish() {
        let (page, operation, _sender, server, _records) = journal_fixture(false, true).await;
        let mut journal = super::ProtectedReadJournal::begin(&page, &operation).unwrap();
        journal.stabilize_animations().await.unwrap();
        journal.check().unwrap();
        journal.restore().await.unwrap();
        assert_eq!(journal.check(), Err(super::ProtectedReadReason::StaleScope));
        drop(journal);
        server.abort();
    }

    #[tokio::test]
    async fn failed_mask_removal_retains_mutation_owner_not_just_release_debt() {
        let (page, operation, _sender, server, records) = journal_fixture(false, false).await;
        let mut journal = super::ProtectedReadJournal::begin(&page, &operation).unwrap();
        journal.stabilize_animations().await.unwrap();
        journal
            .reserve_source_group("session".into(), "mutation-owner".into())
            .unwrap();
        journal
            .bind_source_holder("session", "mutation-owner", "fail-remove".into())
            .unwrap();
        journal.verify_source_masks().await.unwrap();
        let failure = journal.restore().await.unwrap_err();
        assert!(failure.cleanup_integrity_lost);
        assert!(!journal.restored);
        assert_eq!(
            journal
                .records()
                .unwrap()
                .masks
                .iter()
                .filter(|mask| mask.step != super::MaskStep::GroupReleased)
                .map(|mask| (
                    mask.session.clone(),
                    mask.holder.clone(),
                    mask.group.clone()
                ))
                .collect::<Vec<_>>(),
            vec![(
                "session".into(),
                Some("fail-remove".into()),
                "mutation-owner".into()
            )]
        );
        let requests = records.lock().unwrap();
        assert!(requests
            .iter()
            .any(|r| r["method"] == "Runtime.callFunctionOn"
                && r["params"]["objectId"] == "fail-remove"
                && r["params"]["functionDeclaration"] == "function(){return this.remove()}"));
        // Releasing the object group would discard the cleanup owner without
        // proving the source mutation was undone. Production correctly keeps it.
        assert!(!requests
            .iter()
            .any(|r| r["method"] == "Runtime.releaseObjectGroup"));
        drop(requests);
        drop(journal);
        server.abort();
    }

    #[tokio::test]
    async fn source_mask_cleanup_drains_all_owned_holders_even_after_cancel_or_failure() {
        for fail in [false, true] {
            let (page, operation, sender, server, records) = journal_fixture(false, false).await;
            let mut journal = super::ProtectedReadJournal::begin(&page, &operation).unwrap();
            journal.stabilize_animations().await.unwrap();
            journal
                .reserve_source_group("session".into(), "clean-group".into())
                .unwrap();
            journal
                .bind_source_holder("session", "clean-group", "clean".into())
                .unwrap();
            journal
                .reserve_source_group("session".into(), "second-group".into())
                .unwrap();
            journal
                .bind_source_holder(
                    "session",
                    "second-group",
                    if fail { "fail-remove" } else { "second" }.into(),
                )
                .unwrap();
            journal.verify_source_masks().await.unwrap();
            sender
                .send(super::super::client_session::CancelSignal::Requested)
                .unwrap();
            let result = journal.restore().await;
            assert_eq!(result.is_err(), fail);
            if let Err(error) = result {
                assert!(error.cleanup_integrity_lost);
            }
            let commands = records.lock().unwrap();
            assert!(commands
                .iter()
                .any(|r| r["method"] == "Runtime.callFunctionOn"
                    && r["params"]["objectId"] == "clean"
                    && r["params"]["functionDeclaration"] == "function(){return this.remove()}"));
            assert!(commands
                .iter()
                .any(|r| r["method"] == "Runtime.releaseObjectGroup"
                    && r["params"]["objectGroup"] == "clean-group"));
            assert!(commands
                .iter()
                .any(|r| r["method"] == "Animation.setPlaybackRate"
                    && r["params"]["playbackRate"].as_f64() == Some(1.0)));
            assert!(!commands
                .iter()
                .any(|r| r["method"] == "Page.setWebLifecycleState"
                    || r["method"] == "Page.bringToFront"));
            drop(commands);
            drop(journal);
            server.abort();
        }
    }

    #[tokio::test]
    async fn pending_source_group_is_released_without_fabricated_holder_after_cancel() {
        let (page, operation, sender, server, records) = journal_fixture(false, false).await;
        let mut journal = super::ProtectedReadJournal::begin(&page, &operation).unwrap();
        journal.stabilize_animations().await.unwrap();
        journal
            .reserve_source_group("session".into(), "unacknowledged-group".into())
            .unwrap();
        sender
            .send(super::super::client_session::CancelSignal::Requested)
            .unwrap();
        journal.restore().await.unwrap();
        let commands = records.lock().unwrap();
        assert!(commands
            .iter()
            .any(|r| r["method"] == "Runtime.releaseObjectGroup"
                && r["params"]["objectGroup"] == "unacknowledged-group"));
        assert!(!commands
            .iter()
            .any(|r| r["method"] == "Runtime.callFunctionOn"));
        drop(commands);
        drop(journal);
        server.abort();
    }

    async fn bounded(
        client: &CdpClient,
        session: &str,
        method: &str,
        args: Value,
    ) -> Result<Value, String> {
        tokio::time::timeout(
            Duration::from_secs(3),
            client.send_command(method, Some(args), Some(session)),
        )
        .await
        .map_err(|_| format!("synthetic probe timed out: {method}"))?
        .map_err(|_| format!("synthetic probe command failed: {method}"))
    }
    async fn counter(client: &CdpClient, session: &str, world: Option<i64>) -> Result<u64, String> {
        let mut args = json!({"expression":"Number(document.body.getAttribute('data-probe-counter'))","returnByValue":true});
        if let Some(world) = world {
            args["contextId"] = json!(world);
        }
        bounded(client, session, "Runtime.evaluate", args).await?["result"]["value"]
            .as_u64()
            .ok_or("invalid synthetic counter".into())
    }
    async fn advances(client: &CdpClient, session: &str, after: u64) -> Result<(), String> {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if counter(client, session, None).await? > after {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| "synthetic timer did not resume".to_owned())?
    }

    /// Required hosted-browser gate, deliberately not a passing default unit test.
    /// Run explicitly with --ignored; all data are synthetic and no network is used.
    #[tokio::test]
    #[ignore = "requires real Chromium; required protected-read browser CI gate"]
    async fn chromium_animation_stabilization_preserves_visibility_and_native_reads() {
        let mut owner = OwnedBrowser::launch(Default::default(), None)
            .await
            .unwrap();
        let gate = Arc::new(ExecutionGate::default());
        let page = owner.lease(gate.enter(false).unwrap()).unwrap();
        let client = &page.client;
        let session = &page.page_session_id;
        let initialized=bounded(client,session,"Runtime.evaluate",json!({"expression":r#"(()=>{document.body.innerHTML='<button>synthetic button</button><div id="probe-host"></div>';const root=document.getElementById('probe-host').attachShadow({mode:'closed'});root.innerHTML='<input id="synthetic-password" type="password" value="synthetic-only">';document.body.setAttribute('data-probe-counter','0');setInterval(()=>document.body.setAttribute('data-probe-counter',String(Number(document.body.getAttribute('data-probe-counter'))+1)),10);return true})()"#,"returnByValue":true})).await;
        let mut touched = false;
        let mut original_rate = None;
        let result: Result<(), String> = async {
            initialized?;
            advances(client, session, 1).await?;
            bounded(client, session, "Animation.enable", json!({})).await?;
            original_rate = bounded(client, session, "Animation.getPlaybackRate", json!({}))
                .await?["playbackRate"]
                .as_f64();
            let rate = original_rate.ok_or("missing animation rate")?;
            if !rate.is_finite() {
                return Err("invalid animation rate".into());
            }
            touched = true;
            bounded(
                client,
                session,
                "Animation.setPlaybackRate",
                json!({"playbackRate":0}),
            )
            .await?;
            let visibility=bounded(client,session,"Runtime.evaluate",json!({"expression":"({visibility:document.visibilityState,focus:document.hasFocus()})","returnByValue":true})).await?["result"]["value"].clone();
            let tree = bounded(client, session, "Page.getFrameTree", json!({})).await?;
            let frame = tree["frameTree"]["frame"]["id"]
                .as_str()
                .ok_or("missing frame")?;
            let loader = tree["frameTree"]["frame"]["loaderId"].clone();
            let world = bounded(
                client,
                session,
                "Page.createIsolatedWorld",
                json!({"frameId":frame,"worldName":"native-protected-read-probe"}),
            )
            .await?["executionContextId"]
                .as_i64()
                .ok_or("missing world")?;
            let before = counter(client, session, Some(world)).await?;
            // Animations may pause, but normal JS scheduling must remain live.
            advances(client,session,before).await?;
            let after_visibility=bounded(client,session,"Runtime.evaluate",json!({"expression":"({visibility:document.visibilityState,focus:document.hasFocus()})","returnByValue":true})).await?["result"]["value"].clone();
            if after_visibility!=visibility{return Err("animation stabilization changed visibility/focus".into());}
            let ax = bounded(
                client,
                session,
                "Accessibility.getFullAXTree",
                json!({"frameId":frame}),
            )
            .await?;
            if !ax["nodes"]
                .as_array()
                .is_some_and(|nodes| nodes.iter().any(|n| n["role"]["value"] == "button"))
            {
                return Err("stabilized AX read lost button".into());
            }
            let dom = bounded(
                client,
                session,
                "DOMSnapshot.captureSnapshot",
                json!({"computedStyles":[]}),
            )
            .await?;
            if !dom["strings"]
                .as_array()
                .is_some_and(|strings| strings.iter().any(|s| s == "synthetic-password"))
            {
                return Err("closed-shadow snapshot incomplete".into());
            }
            let png = bounded(
                client,
                session,
                "Page.captureScreenshot",
                json!({"format":"png","fromSurface":true}),
            )
            .await?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(png["data"].as_str().ok_or("missing synthetic image")?)
                .map_err(|_| "invalid synthetic image")?;
            image::load_from_memory_with_format(&bytes, image::ImageFormat::Png)
                .map_err(|_| "undecodable synthetic image")?;
            let after = bounded(client, session, "Page.getFrameTree", json!({})).await?;
            if after["frameTree"]["frame"]["loaderId"] != loader {
                return Err("document changed during stabilized read".into());
            }
            Ok(())
        }
        .await;
        let cleanup: Result<(), String> = async {
            if touched {
                let rate = bounded(
                    client,
                    session,
                    "Animation.setPlaybackRate",
                    json!({"playbackRate":original_rate.unwrap_or(1.0)}),
                )
                .await;
                rate?;
                if bounded(client, session, "Animation.getPlaybackRate", json!({})).await?
                    ["playbackRate"]
                    .as_f64()
                    != original_rate
                {
                    return Err("animation rate was not restored".into());
                }
                let before = counter(client, session, None).await?;
                advances(client, session, before).await?;
            }
            Ok(())
        }
        .await;
        drop(page);
        let closed = owner.close().await;
        assert!(closed.is_ok(), "owned synthetic context cleanup failed");
        assert!(cleanup.is_ok(), "restoration proof failed: {cleanup:?}");
        assert!(
            result.is_ok(),
            "animation stabilization conformance failed: {result:?}"
        );
    }
}
