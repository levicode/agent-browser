//! Bounded, failure-only observations for one browser action.
//!
//! A `browser.perform` receipt carries only its closed error code. When that
//! code is `browser-failure`, the receipt cannot say which action, which
//! resolution stage, or which CDP command produced it. This module keeps the
//! last closed stage and command failure for the action's own operation so the
//! settlement trace can name them without recording a selector, node identity,
//! coordinate, or renderer prose.
//!
//! The operation is already the existing `CURRENT_OPERATION` task-local, so
//! this adds no new future layer to the action. Every setter is a no-op
//! outside an admitted action operation. Nothing here grants, retries, or
//! settles authority.
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use super::cdp::types::StaleBrowserObject;
use super::client_protocol::{Effects, ProtocolError};
use super::client_settlement_trace::{
    self as trace, ActionCdpFailure, ActionCdpMethod, ActionFailureObservation, ActionKind,
    ActionStage, ActionStaleObject,
};

#[derive(Clone, Copy)]
struct State {
    kind: ActionKind,
    stage: ActionStage,
    method: Option<ActionCdpMethod>,
    failure: Option<ActionCdpFailure>,
    stale_object: Option<ActionStaleObject>,
}

type Key = (u64, u64);

fn active() -> &'static Mutex<HashMap<Key, State>> {
    static ACTIVE: OnceLock<Mutex<HashMap<Key, State>>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn current_key() -> Option<Key> {
    let handle = super::client_debt::current_operation()?;
    Some((handle.key().generation, handle.key().operation_seq))
}

/// One action's live diagnostic state. Dropping it removes the entry even when
/// the operation future is cancelled before a result is classified.
pub(crate) struct ActionRegistration {
    key: Key,
    kind: ActionKind,
    emitted: bool,
}

impl ActionRegistration {
    /// Emit one unconditional record for the settled failure. Called from the
    /// one place that produces the public `ActionFailure`, so no failure branch
    /// can stay silent.
    pub(crate) fn emit(&mut self, error: ProtocolError, effects: Effects) {
        let state = active()
            .lock()
            .ok()
            .and_then(|mut map| map.remove(&self.key));
        let state = state.unwrap_or(State {
            kind: self.kind,
            stage: ActionStage::Unknown,
            method: None,
            failure: None,
            stale_object: None,
        });
        self.emitted = true;
        trace::action_failure(
            self.key.1,
            ActionFailureObservation {
                kind: state.kind,
                stage: state.stage,
                method: state.method,
                failure: state.failure,
                stale_object: state.stale_object,
                error,
                effects,
            },
        );
    }
}

impl Drop for ActionRegistration {
    fn drop(&mut self) {
        // Emit already removed the entry; an unemitted registration (cancelled
        // or failed before classification) is removed here.
        if !self.emitted {
            if let Ok(mut map) = active().lock() {
                map.remove(&self.key);
            }
        }
    }
}

/// Register one `browser.perform` operation when cleanup diagnostics are on.
pub(crate) fn register(
    generation: u64,
    sequence: u64,
    kind: ActionKind,
) -> Option<ActionRegistration> {
    if !trace::cleanup_diagnostics_enabled() {
        return None;
    }
    active().lock().ok()?.insert(
        (generation, sequence),
        State {
            kind,
            stage: ActionStage::Unknown,
            method: None,
            failure: None,
            stale_object: None,
        },
    );
    Some(ActionRegistration {
        key: (generation, sequence),
        kind,
        emitted: false,
    })
}

/// Whether the last command failure in this action was a closed gone-object
/// answer. Used only to classify an already-failed read; it never retries.
pub(crate) fn exact_target_gone() -> bool {
    let Some(key) = current_key() else {
        return false;
    };
    active()
        .lock()
        .ok()
        .and_then(|map| map.get(&key).copied())
        .is_some_and(|state| state.stale_object.is_some())
}
fn update(change: impl FnOnce(&mut State)) {
    let Some(key) = current_key() else { return };
    let Ok(mut map) = active().lock() else { return };
    if let Some(state) = map.get_mut(&key) {
        change(state);
    }
}

/// The last fallible action step that started.
pub(crate) fn stage(value: ActionStage) {
    update(|state| state.stage = value);
}

/// One action-context CDP command failed before its reply could authorize
/// anything. The message is classified here and never retained.
pub(crate) fn command_failed(method: &str, message: &str) {
    let (failure, stale_object) = classify(message);
    update(|state| {
        state.method = Some(ActionCdpMethod::from_method(method));
        state.failure = Some(failure);
        state.stale_object = stale_object;
    });
}

/// A command succeeded but its reply shape was not the fixed contract.
pub(crate) fn reply_malformed(method: &str) {
    update(|state| {
        state.method = Some(ActionCdpMethod::from_method(method));
        state.failure = Some(ActionCdpFailure::MissingReply);
        state.stale_object = None;
    });
}

/// The evaluated function threw. The browser exception text is page data.
pub(crate) fn script_threw() {
    update(|state| {
        state.method = Some(ActionCdpMethod::RuntimeCallFunctionOn);
        state.failure = Some(ActionCdpFailure::Exception);
        state.stale_object = None;
    });
}

fn classify(message: &str) -> (ActionCdpFailure, Option<ActionStaleObject>) {
    if let Some(object) = StaleBrowserObject::from_message(message) {
        return (
            ActionCdpFailure::RemoteError,
            Some(ActionStaleObject::from_browser_object(object)),
        );
    }
    let failure = if message.starts_with("CDP error (") {
        ActionCdpFailure::RemoteError
    } else {
        match message {
            "Native CDP command admission refused" => ActionCdpFailure::AdmissionRefused,
            "Native CDP command admission revoked" => ActionCdpFailure::AdmissionRevoked,
            "Native CDP owner changed" | "Native CDP reservation owner changed" => {
                ActionCdpFailure::OwnerChanged
            }
            "Native CDP requires an owner-bound view" => ActionCdpFailure::OwnerRequired,
            "CDP response channel closed" => ActionCdpFailure::ChannelClosed,
            "CDP command timed out" => ActionCdpFailure::Deadline,
            _ if message.starts_with("CDP command timed out: ") => ActionCdpFailure::Deadline,
            "Unvalidated network terminal reply" => ActionCdpFailure::LocalFailure,
            _ => ActionCdpFailure::Other,
        }
    };
    (failure, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key {
        (1, 7)
    }

    fn register_test(kind: ActionKind) -> ActionRegistration {
        active().lock().unwrap().insert(
            key(),
            State {
                kind,
                stage: ActionStage::Unknown,
                method: None,
                failure: None,
                stale_object: None,
            },
        );
        ActionRegistration {
            key: key(),
            kind,
            emitted: false,
        }
    }

    fn state(key: Key) -> Option<State> {
        active().lock().unwrap().get(&key).copied()
    }

    #[test]
    fn stale_object_answers_name_the_closed_object() {
        for (message, object) in [
            (
                "CDP error (DOM.resolveNode): No node with given id found",
                ActionStaleObject::Node,
            ),
            (
                "CDP error (Runtime.callFunctionOn): Could not find object with given id",
                ActionStaleObject::Object,
            ),
            (
                "CDP error (Page.createIsolatedWorld): Frame with the given id was not found",
                ActionStaleObject::Frame,
            ),
            (
                "Session with given id not found.",
                ActionStaleObject::Session,
            ),
        ] {
            let (failure, stale) = classify(message);
            assert_eq!(failure, ActionCdpFailure::RemoteError);
            assert_eq!(stale, Some(object));
        }
        assert_eq!(
            classify("CDP error (DOM.getBoxModel): Could not compute box model."),
            (ActionCdpFailure::RemoteError, None)
        );
        assert_eq!(
            classify("Native CDP command admission refused"),
            (ActionCdpFailure::AdmissionRefused, None)
        );
        assert_eq!(
            classify("CDP command timed out: DOM.getBoxModel"),
            (ActionCdpFailure::Deadline, None)
        );
    }

    #[test]
    fn dropping_an_unemitted_registration_removes_the_entry() {
        let registration = register_test(ActionKind::Tap);
        assert!(state(key()).is_some());
        drop(registration);
        assert!(state(key()).is_none());
    }

    #[test]
    fn registration_carries_the_wire_kind() {
        let _registration = register_test(ActionKind::from_wire(Some("swipe")));
        assert_eq!(state(key()).unwrap().kind, ActionKind::Swipe);
        assert_eq!(
            ActionKind::from_wire(Some("not-a-verb")),
            ActionKind::Unknown
        );
    }
}
