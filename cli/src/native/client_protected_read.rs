//! Shared protected-read stabilization. Browser conformance is an explicit gate;
//! the existence of this module does not advertise a protected capability.

use super::client_browser::BrowserExecutionLease;
use super::client_session::{CancelSignal, OperationLease};
use super::client_targets::{ProtectedTargetBarrier, TargetPurpose};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedReadReason {
    Cancelled,
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
    touched: Vec<(String, f64)>,
    source_masks: Vec<(String, Option<String>, String)>,
    restored: bool,
    started: bool,
    stabilization_completed: bool,
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
        let journal = Self {
            page,
            operation,
            barrier,
            sessions,
            touched: Vec::new(),
            source_masks: Vec::new(),
            restored: false,
            started: false,
            stabilization_completed: false,
        };
        journal.check().map_err(failure)?;
        Ok(journal)
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
        let mut cancellation = self.operation.cancellation.clone();
        tokio::select! {
            result=self.page.client.send_command(method,Some(args),Some(session))=>{self.check()?;result.map_err(|_|ProtectedReadReason::BrowserFailure)},
            _=cancellation.changed()=>Err(ProtectedReadReason::Cancelled),
            _=tokio::time::sleep_until(self.operation.deadline.into())=>Err(ProtectedReadReason::Deadline),
        }
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
                .command(&session, "Animation.getPlaybackRate", json!({}))
                .await?["playbackRate"]
                .as_f64()
                .filter(|rate| rate.is_finite())
                .ok_or(ProtectedReadReason::BrowserFailure)?;
            // Journal before delivery: lost acknowledgements may still mutate.
            self.touched.push((session.clone(), rate));
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
        if !self.contains_session(&session)
            || self.source_masks.len() >= 4096
            || self
                .source_masks
                .iter()
                .any(|(s, _, g)| s == &session && g == &group)
        {
            return Err(ProtectedReadReason::IncompleteInventory);
        }
        self.source_masks.push((session, None, group));
        Ok(())
    }
    pub(crate) fn bind_source_holder(
        &mut self,
        session: &str,
        group: &str,
        object: String,
    ) -> Result<(), ProtectedReadReason> {
        // Cleanup ownership accepts a known ACK even after cancellation; the
        // next mutating command independently checks the original operation.
        let entry = self
            .source_masks
            .iter_mut()
            .find(|(s, _, g)| s == session && g == group)
            .ok_or(ProtectedReadReason::IncompleteInventory)?;
        if entry.1.is_some() {
            return Err(ProtectedReadReason::IncompleteInventory);
        }
        entry.1 = Some(object);
        Ok(())
    }
    pub(crate) async fn verify_source_masks(&self) -> Result<(), ProtectedReadReason> {
        for (session, object, group) in &self.source_masks {
            let object = object
                .as_ref()
                .ok_or(ProtectedReadReason::IncompleteInventory)?;
            let response=self.command(session,"Runtime.callFunctionOn",json!({"objectId":object,"functionDeclaration":"function(){return this.verify()}","returnByValue":true,"objectGroup":group})).await?;
            if response.get("exceptionDetails").is_some() || response["result"]["value"] != true {
                return Err(ProtectedReadReason::BrowserFailure);
            }
        }
        Ok(())
    }
    pub(crate) async fn remove_source_masks(&mut self) -> Result<(), ProtectedReadReason> {
        self.remove_source_masks_until(Instant::now() + Duration::from_secs(3))
            .await
    }
    async fn remove_source_masks_until(
        &mut self,
        deadline: Instant,
    ) -> Result<(), ProtectedReadReason> {
        // Keep every ownership record in self across await/caller cancellation.
        // Remove only after exact node removal and group-release ACKs.
        let attempts = self.source_masks.clone();
        for (session, object, group) in attempts.into_iter().rev() {
            if let Some(handle) = &object {
                let result=tokio::time::timeout_at(deadline.into(),self.page.client.send_command("Runtime.callFunctionOn",Some(json!({"objectId":handle,"functionDeclaration":"function(){return this.remove()}","returnByValue":true,"objectGroup":group})),Some(&session))).await;
                let removed = matches!(&result,Ok(Ok(value)) if value.get("exceptionDetails").is_none() && value["result"]["value"]==true);
                if !removed {
                    continue;
                }
            }
            let released = tokio::time::timeout_at(
                deadline.into(),
                self.page.client.send_command(
                    "Runtime.releaseObjectGroup",
                    Some(json!({"objectGroup":group})),
                    Some(&session),
                ),
            )
            .await;
            if matches!(released, Ok(Ok(_))) {
                self.source_masks
                    .retain(|(s, _, g)| s != &session || g != &group);
            }
        }
        if !self.source_masks.is_empty() {
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
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut complete = self.remove_source_masks_until(deadline).await.is_ok();
        for (session, rate) in self.touched.iter().rev() {
            let command_deadline = deadline.min(Instant::now() + Duration::from_millis(500));
            if Instant::now() >= deadline {
                complete = false;
                break;
            }
            complete &= matches!(
                tokio::time::timeout_at(
                    command_deadline.into(),
                    self.page.client.send_command(
                        "Animation.setPlaybackRate",
                        Some(json!({"playbackRate":rate})),
                        Some(session)
                    )
                )
                .await,
                Ok(Ok(_))
            );
        }
        #[cfg(feature = "acceptance-faults")]
        eprintln!(
            "native-settlement sequence={} phase=ProtectedRestoreEnd integrity={}",
            self.operation.sequence, complete
        );
        if !complete {
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
        if !self.restored && (!self.touched.is_empty() || !self.source_masks.is_empty()) {
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
