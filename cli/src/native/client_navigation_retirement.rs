//! The existing navigation producer retains its exact response during bounded
//! cancellation cleanup. These local observations confer no new task authority.
use super::*;
use crate::native::cdp::client::{BoundedCdpEvent, BoundedMethodEvents};
use crate::native::client_debt::CommandStatus;
use crate::native::client_tasks::RetainedTasks;

struct Boundary<'a> {
    session: &'a str,
    frame: &'a str,
    previous_loader: Option<&'a str>,
    requested_url: &'a str,
    loader: Option<String>,
    sequence: u64,
    trigger_sequence: u64,
    stopped: bool,
}
impl Boundary<'_> {
    fn observe(&mut self, event: &BoundedCdpEvent) -> Option<()> {
        self.observe_event(event.sequence(), event)
    }
    fn observe_event(&mut self, sequence: u64, event: &CdpEvent) -> Option<()> {
        if sequence != self.sequence.checked_add(1)? {
            return None;
        }
        self.sequence = sequence;
        if event.method == "Target.detachedFromTarget" {
            return (identity(event.params["sessionId"].as_str())? != self.session).then_some(());
        }
        if event.session_id.as_deref()? != self.session {
            return Some(());
        }
        if event.method == "Inspector.detached" {
            return None;
        }
        let frame = if event.method == "Page.frameNavigated" {
            event.params.pointer("/frame/id").and_then(Value::as_str)
        } else {
            event.params["frameId"].as_str()
        };
        if identity(frame)? != self.frame {
            return Some(());
        }
        match event.method.as_str() {
            "Page.frameStartedNavigating" => {
                let loader = identity(event.params["loaderId"].as_str())?;
                if sequence <= self.trigger_sequence
                    || event.params["url"].as_str() != Some(self.requested_url)
                    || Some(loader) == self.previous_loader
                    || self.loader.as_deref().is_some_and(|old| old != loader)
                {
                    return None;
                }
                self.loader = Some(loader.to_owned());
                self.stopped = false;
            }
            "Page.lifecycleEvent" | "Page.frameNavigated" => {
                let loader = if event.method == "Page.frameNavigated" {
                    event
                        .params
                        .pointer("/frame/loaderId")
                        .and_then(Value::as_str)
                } else {
                    event.params["loaderId"].as_str()
                };
                let loader = identity(loader)?;
                if Some(loader) != self.previous_loader && self.loader.as_deref() != Some(loader) {
                    return None;
                }
            }
            "Page.frameStoppedLoading" => self.stopped = self.loader.is_some(),
            "Page.navigatedWithinDocument" | "Page.frameDetached" => return None,
            _ => {}
        }
        Some(())
    }
    async fn drain(&mut self, events: &mut BoundedMethodEvents, boundary: u64) -> Option<()> {
        while self.sequence < boundary {
            self.observe(&events.recv().await.ok()?)?;
        }
        Some(())
    }
    fn aborted(&self, response: &Value) -> bool {
        response["frameId"].as_str() == Some(self.frame)
            && self.loader.is_some()
            && response["loaderId"].as_str() == self.loader.as_deref()
            && response["errorText"].as_str() == Some("net::ERR_ABORTED")
            && response.get("isDownload") == Some(&Value::Bool(false))
    }
}
fn identity(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty() && value.len() <= 4096)
}

// Successful original ACKs have a different terminal proof from ERR_ABORTED.
// This witness is private to the original producer and never follows a replacement
// loader. Invalid evidence is sticky and does not alter normal navigation success.
struct AcknowledgedBoundary {
    session: String,
    frame: String,
    previous_loader: Option<String>,
    requested_url: String,
    loader: String,
    sequence: u64,
    trigger_sequence: u64,
    started: bool,
    current: bool,
    invalid: bool,
    stop_baseline: Option<u64>,
    stopped: bool,
}
impl AcknowledgedBoundary {
    fn from_ack(
        response: &Value,
        session: &str,
        frame: &str,
        previous_loader: Option<&str>,
        requested_url: String,
        trigger_sequence: u64,
    ) -> Option<Self> {
        let loader = identity(response["loaderId"].as_str())?;
        if identity(response["frameId"].as_str())? != frame
            || Some(loader) == previous_loader
            || response
                .get("errorText")
                .is_some_and(|value| value.as_str() != Some(""))
        {
            return None;
        }
        if !matches!(response.get("isDownload"), None | Some(Value::Bool(false))) {
            return None;
        }
        Some(Self {
            session: session.to_owned(),
            frame: frame.to_owned(),
            previous_loader: previous_loader.map(str::to_owned),
            requested_url,
            loader: loader.to_owned(),
            sequence: 0,
            trigger_sequence,
            started: false,
            current: false,
            invalid: false,
            stop_baseline: None,
            stopped: false,
        })
    }
    fn observe(&mut self, sequence: u64, event: &CdpEvent) {
        if self.invalid {
            return;
        }
        if self.observe_valid(sequence, event).is_none() {
            self.invalid = true;
        }
    }
    fn observe_valid(&mut self, sequence: u64, event: &CdpEvent) -> Option<()> {
        if sequence != self.sequence.checked_add(1)? {
            return None;
        }
        self.sequence = sequence;
        if event.method == "Target.detachedFromTarget" {
            return (identity(event.params["sessionId"].as_str())? != self.session).then_some(());
        }
        if event.session_id.as_deref()? != self.session {
            return Some(());
        }
        if event.method == "Inspector.detached" {
            return None;
        }
        let frame = if event.method == "Page.frameNavigated" {
            event.params.pointer("/frame/id").and_then(Value::as_str)
        } else {
            event.params["frameId"].as_str()
        };
        if identity(frame)? != self.frame {
            return Some(());
        }
        match event.method.as_str() {
            "Page.frameStartedNavigating" => {
                if self.started
                    || sequence <= self.trigger_sequence
                    || event.params["url"].as_str() != Some(self.requested_url.as_str())
                    || event.params["loaderId"].as_str() != Some(self.loader.as_str())
                {
                    return None;
                }
                self.started = true;
            }
            "Page.lifecycleEvent" | "Page.frameNavigated" => {
                let loader = if event.method == "Page.frameNavigated" {
                    event
                        .params
                        .pointer("/frame/loaderId")
                        .and_then(Value::as_str)
                } else {
                    event.params["loaderId"].as_str()
                };
                let loader = identity(loader)?;
                if self.started {
                    // Unlike the pre-ACK boundary, a previous-loader event is
                    // no longer admissible after this ACK loader has started.
                    if loader != self.loader {
                        return None;
                    }
                    // A lifecycle callback alone is not a current-document
                    // commit witness; only frameNavigated binds the ACK loader.
                    if event.method == "Page.frameNavigated" {
                        self.current = true;
                    }
                } else if Some(loader) != self.previous_loader.as_deref() {
                    return None;
                }
            }
            "Page.frameStoppedLoading" => {
                if self.ready()
                    && self
                        .stop_baseline
                        .is_some_and(|baseline| sequence > baseline)
                {
                    self.stopped = true;
                }
            }
            "Page.navigatedWithinDocument" | "Page.frameDetached" => return None,
            _ => return None,
        }
        Some(())
    }
    fn ready(&self) -> bool {
        !self.invalid && self.started && self.current
    }
    fn begin_stop(&mut self) -> Option<()> {
        if !self.ready() || self.stop_baseline.is_some() {
            return None;
        }
        self.stop_baseline = Some(self.sequence);
        self.stopped = false;
        Some(())
    }
    fn terminal(&self) -> bool {
        self.ready() && self.stop_baseline.is_some() && self.stopped
    }
    async fn drain(&mut self, events: &mut BoundedMethodEvents, boundary: u64) -> Option<()> {
        while self.sequence < boundary {
            let event = events.recv().await.ok()?;
            self.observe(event.sequence(), &event);
            if self.invalid {
                return None;
            }
        }
        (!self.invalid).then_some(())
    }
}

// Freeze the same deadline precedence as the Submitted branch at interruption
// entry, before cleanup consumes time. A receipt must not bypass the dispatcher's
// old timeout normalization and accidentally turn an expired operation Cancelled.
pub(super) fn acknowledged_interruption_reason(
    reason: ProtocolError,
    deadline_elapsed: bool,
) -> ProtocolError {
    if deadline_elapsed && matches!(reason, ProtocolError::Cancelled) {
        ProtocolError::DeadlineExceeded
    } else {
        reason
    }
}

pub(super) struct AcknowledgedNavigation {
    boundary: AcknowledgedBoundary,
    original: crate::native::client_debt::CommandStatusHandle,
    attachment: crate::native::client_targets::OwnedTarget,
    journal: OperationJournalHandle,
}
impl AcknowledgedNavigation {
    pub(super) fn observe(&mut self, event: &BoundedCdpEvent) {
        self.boundary.observe(event.sequence(), event);
    }
    fn exact_owner(&self, page: &BrowserExecutionLease, operation: &OperationLease) -> Option<()> {
        page.permit.check().ok()?;
        let current = page.targets.owned_target(&page.target_id).ok()?;
        if self.journal.key()
            != (OperationKey {
                generation: operation.generation,
                operation_seq: operation.sequence,
            })
            || !self
                .journal
                .ledger()
                .matches_owner(operation.generation, &page.identity_scope)
            || !self.attachment.same_attachment(&current)
            || current.session_id != page.page_session_id
            || self.journal.snapshot().integrity_lost
            || self.original.snapshot() != CommandStatus::Acknowledged
            || self.original.is_error_ack()
        {
            return None;
        }
        Some(())
    }
    // Consuming self makes a second stop impossible, including top-check/select
    // cancellation races. The original subscriber and absolute bound stay owned.
    pub(super) async fn retire(
        self,
        page: &BrowserExecutionLease,
        operation: &OperationLease,
        tasks: &RetainedTasks,
        events: &mut BoundedMethodEvents,
    ) -> Option<NavigationInterruptionProof> {
        self.retire_before(
            page,
            operation,
            tasks,
            events,
            Instant::now() + Duration::from_secs(2),
        )
        .await
    }
    async fn retire_before(
        mut self,
        page: &BrowserExecutionLease,
        operation: &OperationLease,
        tasks: &RetainedTasks,
        events: &mut BoundedMethodEvents,
        stop_by: Instant,
    ) -> Option<NavigationInterruptionProof> {
        self.exact_owner(page, operation)?;
        let key = self.journal.key();
        tasks.cancel_operation_producer(key);
        let retained = tasks
            .operation_retention_status(key)
            .proof()
            .filter(|proof| proof.matches(key))?;
        let deadline = retained.retirement_deadline().min(stop_by);
        let cleanup = async {
            let watermark = events.watermark();
            self.boundary
                .drain(events, watermark.received().ok()?)
                .await?;
            self.exact_owner(page, operation)?;
            if Instant::now() >= deadline {
                return None;
            }
            self.boundary.begin_stop()?;
            let stop = page
                .client
                .stop_retiring_navigation(&page.page_session_id, key, deadline)
                .await
                .ok()?;
            if stop.snapshot() != CommandStatus::Acknowledged || stop.is_error_ack() {
                return None;
            }
            self.boundary
                .drain(events, watermark.received().ok()?)
                .await?;
            while !self.boundary.terminal() {
                let event = events.recv().await.ok()?;
                self.boundary.observe(event.sequence(), &event);
                if self.boundary.invalid {
                    return None;
                }
            }
            self.boundary
                .drain(events, watermark.received().ok()?)
                .await?;
            self.exact_owner(page, operation)?;
            if !self.boundary.terminal() || Instant::now() >= deadline {
                return None;
            }
            Some(NavigationInterruptionProof {
                key,
                identity_scope: page.identity_scope.clone(),
                attachment: self.attachment.clone(),
            })
        };
        tokio::time::timeout_at(deadline.into(), cleanup)
            .await
            .ok()
            .flatten()
    }
}

// Native caller projects its own typed signal; the CDP diagnostic interface
// receives only closed strings/bools. No watch borrow survives the call.
#[cfg(test)]
fn observe_trigger_interruption(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
    entry_deadline_elapsed: bool,
) {
    let signal = {
        let signal = *operation.cancellation.borrow();
        match signal {
            CancelSignal::None => "none",
            CancelSignal::Requested => "requested",
            CancelSignal::DeadlineExceeded => "deadline-exceeded",
            CancelSignal::SessionClosed => "session-closed",
            CancelSignal::OwnerRetirement => "owner-retirement",
        }
    };
    page.client
        .activation_interruption_diagnostic(signal, entry_deadline_elapsed);
}

// Keep the original trigger, frame/loader baseline, bounded subscription and
// existing producer explicit. No generic cleanup envelope or caller retry.
#[allow(clippy::too_many_arguments)]
pub(super) async fn trigger(
    page: &BrowserExecutionLease,
    operation: &OperationLease,
    method: &str,
    args: Value,
    frame: &str,
    previous_loader: Option<&str>,
    events: &mut BoundedMethodEvents,
    retirement: Option<(&RetainedTasks, &mut Option<NavigationInterruptionProof>)>,
    acknowledged: &mut Option<AcknowledgedNavigation>,
    committed: &mut bool,
    submitted: &mut bool,
) -> Result<Value, ProtocolError> {
    let Some((tasks, receipt)) = retirement else {
        return command(page, operation, Some(&page.page_session_id), method, args).await;
    };
    if method != "Page.navigate" {
        return Err(ProtocolError::InvalidArguments);
    }
    let checked = check(page, operation);
    #[cfg(test)]
    if matches!(
        &checked,
        Err(ProtocolError::Cancelled | ProtocolError::DeadlineExceeded)
    ) {
        observe_trigger_interruption(page, operation, Instant::now() >= operation.deadline);
    }
    checked?;
    let attachment = page.targets.owned_target(&page.target_id)?;
    let journal = OperationJournalHandle::current().ok_or(ProtocolError::ScopeUnavailable)?;
    if journal.key()
        != (OperationKey {
            generation: operation.generation,
            operation_seq: operation.sequence,
        })
        || !journal
            .ledger()
            .matches_owner(operation.generation, &page.identity_scope)
        || attachment.session_id != page.page_session_id
        || attachment.kind != "page"
        || !attachment.capture_ready()
    {
        return Err(ProtocolError::StaleScope);
    }
    let requested_url = args["url"]
        .as_str()
        .ok_or(ProtocolError::InvalidArguments)?;
    let requested_url = url::Url::parse(requested_url)
        .map_err(|_| ProtocolError::InvalidArguments)?
        .to_string();
    let reservation = page
        .client
        .reserve_tracked_command(method, Some(&args), Some(&page.page_session_id))
        .map_err(|_| ProtocolError::ScopeUnavailable)?
        .ok_or(ProtocolError::ScopeUnavailable)?;
    let status = reservation.status();
    // A queued start predating this trigger is never its loader witness. Old
    // loader lifecycle events remain admissible, but still consume sequence.
    let trigger_sequence = events
        .watermark()
        .received()
        .map_err(|_| ProtocolError::ScopeUnavailable)?;
    let original = page.client.send_reserved_command(
        method,
        Some(args),
        Some(&page.page_session_id),
        Some(reservation),
    );
    tokio::pin!(original);
    let mut cancellation = operation.cancellation.clone();
    let mut interrupted_response = None;
    let reason = tokio::select! {
        value = &mut original => {
            #[cfg(test)]
            tests::pause_after_original_response().await;
            let checked = check(page, operation);
            #[cfg(test)]
            if matches!(&checked, Err(ProtocolError::Cancelled | ProtocolError::DeadlineExceeded)) {
                observe_trigger_interruption(page, operation, Instant::now() >= operation.deadline);
            }
            match checked {
                Ok(()) => {
                    let response = value.map_err(|_| ProtocolError::BrowserFailure)?;
                    // A returned original response proves this exact command
                    // reached the transport, whatever its ACK class.
                    *submitted = true;
                    if status.snapshot() == CommandStatus::Acknowledged && !status.is_error_ack() {
                        *acknowledged = AcknowledgedBoundary::from_ack(
                            &response, &page.page_session_id, frame, previous_loader,
                            requested_url, trigger_sequence,
                        ).map(|boundary| AcknowledgedNavigation {
                            boundary, original: status, attachment, journal,
                        });
                        *committed = acknowledged.is_some();
                    }
                    return Ok(response);
                }
                Err(reason @ (ProtocolError::Cancelled | ProtocolError::DeadlineExceeded)) => {
                    // This exact response is already consumed. Preserve it for
                    // the same terminal proof used by cancellation after ACK.
                    interrupted_response = Some(value.map_err(|_| ProtocolError::BrowserFailure));
                    acknowledged_interruption_reason(reason, Instant::now() >= operation.deadline)
                }
                Err(reason) => return Err(reason),
            }
        },
        _ = cancellation.changed() => {
            let entry_deadline_elapsed = Instant::now() >= operation.deadline;
            #[cfg(test)]
            observe_trigger_interruption(page, operation, entry_deadline_elapsed);
            if entry_deadline_elapsed {
                ProtocolError::DeadlineExceeded
            } else {
                ProtocolError::Cancelled
            }
        },
        _ = tokio::time::sleep_until(operation.deadline.into()) => {
            #[cfg(test)]
            observe_trigger_interruption(page, operation, Instant::now() >= operation.deadline);
            ProtocolError::DeadlineExceeded
        },
    };
    // Reserved/abandoned work never grants stop authority. A submitted command
    // remains owned by the exact CDP reader even if this waiter later expires.
    // The caller needs this exact distinction: an interrupted command that was
    // never submitted cannot have committed an application effect.
    let was_submitted = matches!(
        status.snapshot(),
        CommandStatus::Submitted | CommandStatus::Acknowledged
    );
    *submitted = was_submitted;
    if !was_submitted {
        return Err(reason);
    }
    let key = journal.key();
    tasks.cancel_operation_producer(key);
    let Some(retained) = tasks
        .operation_retention_status(key)
        .proof()
        .filter(|proof| proof.matches(key))
    else {
        return Err(reason);
    };
    let deadline = retained
        .retirement_deadline()
        .min(Instant::now() + Duration::from_secs(2));
    if status.snapshot() == CommandStatus::Acknowledged {
        // The reader may have acknowledged before either select branch won.
        // ACK alone grants nothing: require the original successful response,
        // exact ownership and the unchanged post-stop event/debt proof.
        let response = match interrupted_response {
            Some(value) => value,
            None => match tokio::time::timeout_at(deadline.into(), &mut original).await {
                Ok(value) => value.map_err(|_| ProtocolError::BrowserFailure),
                Err(_) => return Err(reason),
            },
        };
        if !status.is_error_ack() {
            if let Ok(response) = response {
                if let Some(boundary) = AcknowledgedBoundary::from_ack(
                    &response,
                    &page.page_session_id,
                    frame,
                    previous_loader,
                    requested_url,
                    trigger_sequence,
                ) {
                    // The accepted original response proves this exact
                    // navigation committed. A later stop witness is cleanup
                    // evidence, not the effect boundary.
                    *committed = true;
                    *receipt = AcknowledgedNavigation {
                        boundary,
                        original: status,
                        attachment,
                        journal,
                    }
                    .retire_before(page, operation, tasks, events, deadline)
                    .await;
                }
            }
        }
        return Err(reason);
    }
    let cleanup = async {
        let exact_owner = || {
            page.permit.check().ok()?;
            let current = page.targets.owned_target(&page.target_id).ok()?;
            if !attachment.same_attachment(&current) || journal.snapshot().integrity_lost {
                return None;
            }
            Some(())
        };
        exact_owner()?;
        let watermark = events.watermark();
        let mut boundary = Boundary {
            session: &page.page_session_id,
            frame,
            previous_loader,
            requested_url: &requested_url,
            loader: None,
            sequence: 0,
            trigger_sequence,
            stopped: false,
        };
        boundary.drain(events, watermark.received().ok()?).await?;
        boundary.loader.as_ref()?;
        exact_owner()?;
        if status.snapshot() != CommandStatus::Submitted || Instant::now() >= deadline {
            return None;
        }
        boundary.stopped = false;
        let stop = page
            .client
            .stop_retiring_navigation(&page.page_session_id, key, deadline);
        // Poll both exact commands under one cleanup bound. Neither a caller
        // cancellation nor a stop ACK drops the original navigation response.
        let (response, stopped) = tokio::join!(&mut original, stop);
        let response = response.ok()?;
        // A successful original ACK proves the exact navigation committed even
        // when its loader did not report ERR_ABORTED.
        if AcknowledgedBoundary::from_ack(
            &response,
            &page.page_session_id,
            frame,
            previous_loader,
            requested_url.clone(),
            trigger_sequence,
        )
        .is_some()
        {
            *committed = true;
        }
        let stop_status = stopped.ok()?;
        if status.snapshot() != CommandStatus::Acknowledged
            || stop_status.snapshot() != CommandStatus::Acknowledged
            || !boundary.aborted(&response)
        {
            return None;
        }
        boundary.drain(events, watermark.received().ok()?).await?;
        while !boundary.stopped {
            boundary.observe(&events.recv().await.ok()?)?;
        }
        boundary.drain(events, watermark.received().ok()?).await?;
        exact_owner()?;
        if !boundary.stopped || !boundary.aborted(&response) || Instant::now() >= deadline {
            return None;
        }
        Some(NavigationInterruptionProof {
            key,
            identity_scope: page.identity_scope.clone(),
            attachment,
        })
    };
    *receipt = tokio::time::timeout_at(deadline.into(), cleanup)
        .await
        .ok()
        .flatten();
    Err(reason)
}

#[cfg(test)]
#[path = "client_navigation_retirement_tests.rs"]
mod tests;
