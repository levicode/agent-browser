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
) -> Result<Value, ProtocolError> {
    let Some((tasks, receipt)) = retirement else {
        return command(page, operation, Some(&page.page_session_id), method, args).await;
    };
    if method != "Page.navigate" {
        return Err(ProtocolError::InvalidArguments);
    }
    check(page, operation)?;
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
    let reason = tokio::select! {
        value = &mut original => {
            check(page, operation)?;
            return value.map_err(|_| ProtocolError::BrowserFailure);
        },
        _ = cancellation.changed() => {
            if Instant::now() >= operation.deadline {
                ProtocolError::DeadlineExceeded
            } else {
                ProtocolError::Cancelled
            }
        },
        _ = tokio::time::sleep_until(operation.deadline.into()) => ProtocolError::DeadlineExceeded,
    };
    // Reserved/abandoned work never grants stop authority. A submitted command
    // remains owned by the exact CDP reader even if this waiter later expires.
    if status.snapshot() != CommandStatus::Submitted {
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
