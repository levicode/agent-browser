//! Explicitly negotiated client protocol. Legacy CLI envelopes are unchanged.
//! Browser capabilities are advertised separately, only after implementation.
use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
use serde_json::{Map, Value};

pub const SOCKET_PREFACE: &[u8] = b"AGENT_BROWSER_SESSION/1\n";

pub const PROTOCOL: &str = "agent-browser-session/1";
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_SAFE_SEQUENCE: u64 = 9_007_199_254_740_991;
pub const MAX_TIMEOUT_MS: u64 = 3_600_000;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ClientMessage {
    Hello {
        id: String,
        protocol: String,
        #[serde(rename = "requiredCapabilities")]
        required_capabilities: Vec<String>,
    },
    Request {
        id: String,
        generation: u64,
        #[serde(rename = "operationSeq")]
        operation_seq: u64,
        #[serde(rename = "timeoutMs")]
        timeout_ms: u64,
        command: String,
        #[serde(rename = "callbackToken", default)]
        callback_token: Option<String>,
        args: Map<String, Value>,
    },
    Cancel {
        id: String,
        generation: u64,
        #[serde(rename = "operationSeq")]
        operation_seq: u64,
    },
    Decision {
        id: String,
        generation: u64,
        token: String,
        decision: Decision,
    },
    Close {
        id: String,
        generation: u64,
    },
}

/// Decision payloads never contain arbitrary browser commands or raw CDP IDs.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Decision {
    Continue {
        #[serde(default)]
        overrides: RequestOverrides,
    },
    Fulfill {
        status: u16,
        headers: Vec<Header>,
        #[serde(
            rename = "bodyBase64",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        body_base64: Option<String>,
        #[serde(
            rename = "bodyHandle",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        body_handle: Option<String>,
    },
    Abort {},
    Fallback {
        #[serde(default)]
        overrides: RequestOverrides,
    },
    Auth {
        username: String,
        password: String,
    },
    CancelAuth {},
    Dialog {
        accept: bool,
        #[serde(rename = "promptText", default)]
        prompt_text: Option<String>,
    },
}

impl Decision {
    pub fn body_handle(&self) -> Option<&str> {
        match self {
            Self::Fulfill { body_handle, .. } => body_handle.as_deref(),
            Self::Continue { overrides } | Self::Fallback { overrides } => {
                overrides.body_handle.as_deref()
            }
            _ => None,
        }
    }
    /// Validate semantic payloads before consuming a one-use resource token.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        use base64::Engine;
        fn headers_valid(headers: &[Header]) -> bool {
            headers.len() <= 1024
                && headers.iter().all(|h| {
                    !h.name.is_empty()
                        && h.name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                        && !h.value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
                })
        }
        fn body_valid(body: &str) -> bool {
            body.len() <= MAX_FRAME_BYTES
                && base64::engine::general_purpose::STANDARD
                    .decode(body)
                    .is_ok()
        }
        fn handle_valid(handle: &str) -> bool {
            !handle.is_empty()
                && handle.len() <= 128
                && handle
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        }
        let valid = match self {
            Self::Fulfill {
                status,
                headers,
                body_base64,
                body_handle,
            } => {
                (100..=599).contains(status)
                    && headers_valid(headers)
                    && (body_base64.is_some() ^ body_handle.is_some())
                    && body_base64.as_ref().is_none_or(|b| body_valid(b))
                    && body_handle.as_ref().is_none_or(|h| handle_valid(h))
            }
            Self::Continue { overrides } | Self::Fallback { overrides } => {
                !(overrides.body_base64.is_some() && overrides.body_handle.is_some())
                    && overrides
                        .body_handle
                        .as_ref()
                        .is_none_or(|h| handle_valid(h))
                    && overrides.headers.as_ref().is_none_or(|h| headers_valid(h))
                    && overrides.body_base64.as_ref().is_none_or(|b| body_valid(b))
                    && overrides.method.as_ref().is_none_or(|m| {
                        !m.is_empty()
                            && m.bytes().all(|b| {
                                b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
                            })
                    })
                    && overrides
                        .url
                        .as_ref()
                        .is_none_or(|u| !u.is_empty() && !u.chars().any(char::is_control))
            }
            Self::Dialog {
                accept,
                prompt_text,
            } => *accept || prompt_text.is_none(),
            Self::Abort {} | Self::Auth { .. } | Self::CancelAuth {} => true,
        };
        if valid {
            Ok(())
        } else {
            Err(ProtocolError::InvalidFrame)
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestOverrides {
    pub url: Option<String>,
    pub method: Option<String>,
    pub headers: Option<Vec<Header>>,
    pub body_base64: Option<String>,
    pub body_handle: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Effects {
    NotDispatched,
    Completed,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ScopeState {
    Usable,
    Quarantined,
    Closed,
}

/// Same hard ceiling used by the complete author-query candidate inventory.
pub const MAX_FRAME_SELECTION_COUNT: usize = 100_000;

/// A checked original frame-chain ordinal, with no renderer or selector data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FrameSelectionIndex(u8);
impl FrameSelectionIndex {
    pub fn new(index: usize) -> Option<Self> {
        u8::try_from(index)
            .ok()
            .filter(|index| *index < 64)
            .map(Self)
    }
}

/// Only true ambiguity can be constructed; count one is never a frame error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FrameAmbiguity {
    index: FrameSelectionIndex,
    count: usize,
}
impl FrameAmbiguity {
    pub fn new(index: usize, count: usize) -> Option<Self> {
        if !(2..=MAX_FRAME_SELECTION_COUNT).contains(&count) {
            return None;
        }
        Some(Self {
            index: FrameSelectionIndex::new(index)?,
            count,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidFrame,
    UnsupportedProtocol,
    UnsupportedCapability,
    StaleGeneration,
    ScopeUnavailable,
    SequenceReused,
    InvalidSequence,
    InvalidTimeout,
    CapacityExceeded,
    OperationMissing,
    DecisionMissing,
    DecisionExpired,
    DecisionKindMismatch,
    RegistryMissing,
    RegistryInUse,
    IdentifierExhausted,
    UnsupportedCommand,
    DeadlineExceeded,
    Cancelled,
    InvalidArguments,
    BrowserFailure,
    StaleScope,
    CleanupFailed,
    StaleReference,
    PolicyDenied,
    NotActionable,
    LocatorNotFound,
    ContentLengthMismatch,
    RedirectBodyUnavailable,
    InterceptedPointer,
    CheckedStateUnchanged,
    CheckedControlReplaced,
    FrameNotFound(FrameSelectionIndex),
    FrameAmbiguous(FrameAmbiguity),
}

// Scalar consumers (including acceptance traces) always receive closed strings.
impl Serialize for ProtocolError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            Self::InvalidFrame => "invalid-frame",
            Self::UnsupportedProtocol => "unsupported-protocol",
            Self::UnsupportedCapability => "unsupported-capability",
            Self::StaleGeneration => "stale-generation",
            Self::ScopeUnavailable => "scope-unavailable",
            Self::SequenceReused => "sequence-reused",
            Self::InvalidSequence => "invalid-sequence",
            Self::InvalidTimeout => "invalid-timeout",
            Self::CapacityExceeded => "capacity-exceeded",
            Self::OperationMissing => "operation-missing",
            Self::DecisionMissing => "decision-missing",
            Self::DecisionExpired => "decision-expired",
            Self::DecisionKindMismatch => "decision-kind-mismatch",
            Self::RegistryMissing => "registry-missing",
            Self::RegistryInUse => "registry-in-use",
            Self::IdentifierExhausted => "identifier-exhausted",
            Self::UnsupportedCommand => "unsupported-command",
            Self::DeadlineExceeded => "deadline-exceeded",
            Self::Cancelled => "cancelled",
            Self::InvalidArguments => "invalid-arguments",
            Self::BrowserFailure => "browser-failure",
            Self::StaleScope => "stale-scope",
            Self::CleanupFailed => "cleanup-failed",
            Self::StaleReference => "stale-reference",
            Self::PolicyDenied => "policy-denied",
            Self::NotActionable => "not-actionable",
            Self::LocatorNotFound => "locator-not-found",
            Self::ContentLengthMismatch => "content-length-mismatch",
            Self::RedirectBodyUnavailable => "redirect-body-unavailable",
            Self::InterceptedPointer => "intercepted-pointer",
            Self::CheckedStateUnchanged => "checked-state-unchanged",
            Self::CheckedControlReplaced => "checked-control-replaced",
            Self::FrameNotFound(_) => "frame-not-found",
            Self::FrameAmbiguous(_) => "frame-ambiguous",
        })
    }
}

/// A usable owner is not per-command admission or proof that debt is empty.
/// Negotiation is required; legacy clients retain terminal uncertainty behavior.
pub const EXACT_OWNER_CONTINUATION: &str = "operation.continue-exact-owner/1";
/// Independent opt-in: a quarantined result may permit one explicit reconnect.
pub const DISCONNECTED_RECOVERY: &str = "scope.reconnect-quarantined/1";
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryDescriptor {
    pub version: u8,
    pub identity_scope: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RetentionProducerState {
    Retired,
    Retiring,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionDescriptor {
    pub version: u8,
    pub retired_operation_seq: u64,
    pub producer_state: RetentionProducerState,
    /// Informational operation snapshot, including the cleanup input lane.
    pub input_debt: u32,
    /// Bounded native obligations (exact handles or native-exclusive groups),
    /// never a physical DOM-node count or caller-chosen admission policy.
    pub object_debt: u32,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ServerMessage {
    Ready {
        id: String,
        protocol: String,
        #[serde(rename = "sessionId")]
        session_id: String,
        generation: u64,
        capabilities: Vec<String>,
        limits: Limits,
        #[serde(rename = "scopeState")]
        scope_state: ScopeState,
    },
    Result {
        id: String,
        generation: u64,
        #[serde(rename = "operationSeq")]
        operation_seq: u64,
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<WireError>,
        effects: Effects,
        #[serde(skip_serializing_if = "Option::is_none")]
        retention: Option<RetentionDescriptor>,
        #[serde(skip_serializing_if = "Option::is_none")]
        recovery: Option<RecoveryDescriptor>,
        #[serde(rename = "scopeState")]
        scope_state: ScopeState,
    },
    ControlResult {
        id: String,
        generation: u64,
        accepted: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<WireError>,
        #[serde(rename = "scopeState")]
        scope_state: ScopeState,
    },
    Event {
        generation: u64,
        sequence: u64,
        event: String,
        payload: Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        decision: Option<DecisionNotice>,
    },
    Error {
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        error: WireError,
        #[serde(rename = "scopeState")]
        scope_state: ScopeState,
    },
    Closed {
        id: String,
        generation: u64,
        #[serde(rename = "scopeState")]
        scope_state: ScopeState,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    pub max_frame_bytes: usize,
    pub max_pending_operations: usize,
    pub max_pending_decisions: usize,
    pub max_timeout_ms: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionNotice {
    pub token: String,
    pub timeout_ms: u64,
}

/// No arbitrary diagnostic text: codes are static and cannot echo secrets.
#[derive(Debug)]
pub struct WireError {
    pub code: ProtocolError,
}
impl Serialize for WireError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let selection = match &self.code {
            ProtocolError::FrameNotFound(index) => Some((*index, 0)),
            ProtocolError::FrameAmbiguous(facts) => Some((facts.index, facts.count)),
            _ => None,
        };
        let mut error =
            serializer.serialize_struct("WireError", if selection.is_some() { 2 } else { 1 })?;
        error.serialize_field("code", &self.code)?;
        if let Some((index, count)) = selection {
            #[derive(Serialize)]
            struct Selection {
                index: FrameSelectionIndex,
                count: usize,
            }
            error.serialize_field("frameSelection", &Selection { index, count })?;
        }
        error.end()
    }
}

/// Parse a single frame before any dispatch. Framing readers must impose this
/// limit while reading, rather than buffering an unbounded line first.
pub fn parse_frame(bytes: &[u8]) -> Result<ClientMessage, ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::InvalidFrame);
    }
    let message: ClientMessage =
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidFrame)?;
    let id = match &message {
        ClientMessage::Hello { id, .. }
        | ClientMessage::Request { id, .. }
        | ClientMessage::Cancel { id, .. }
        | ClientMessage::Decision { id, .. }
        | ClientMessage::Close { id, .. } => id,
    };
    if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
        return Err(ProtocolError::InvalidFrame);
    }
    let generation = match &message {
        ClientMessage::Hello { .. } => None,
        ClientMessage::Request { generation, .. }
        | ClientMessage::Cancel { generation, .. }
        | ClientMessage::Decision { generation, .. }
        | ClientMessage::Close { generation, .. } => Some(*generation),
    };
    if generation.is_some_and(|g| g == 0 || g > MAX_SAFE_SEQUENCE) {
        return Err(ProtocolError::InvalidFrame);
    }
    Ok(message)
}

pub fn validate_hello(
    protocol: &str,
    required: &[String],
    supported: &[&str],
) -> Result<(), ProtocolError> {
    if protocol != PROTOCOL {
        return Err(ProtocolError::UnsupportedProtocol);
    }
    if required.len() > 64
        || required
            .iter()
            .any(|item| !supported.contains(&item.as_str()))
    {
        return Err(ProtocolError::UnsupportedCapability);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_serialization_preserves_every_legacy_shape_and_closed_scalar() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/client-protocol-v1.json"))
                .unwrap();
        let old = [
            (ProtocolError::InvalidFrame, "invalid-frame"),
            (ProtocolError::UnsupportedProtocol, "unsupported-protocol"),
            (
                ProtocolError::UnsupportedCapability,
                "unsupported-capability",
            ),
            (ProtocolError::StaleGeneration, "stale-generation"),
            (ProtocolError::ScopeUnavailable, "scope-unavailable"),
            (ProtocolError::SequenceReused, "sequence-reused"),
            (ProtocolError::InvalidSequence, "invalid-sequence"),
            (ProtocolError::InvalidTimeout, "invalid-timeout"),
            (ProtocolError::CapacityExceeded, "capacity-exceeded"),
            (ProtocolError::OperationMissing, "operation-missing"),
            (ProtocolError::DecisionMissing, "decision-missing"),
            (ProtocolError::DecisionExpired, "decision-expired"),
            (
                ProtocolError::DecisionKindMismatch,
                "decision-kind-mismatch",
            ),
            (ProtocolError::RegistryMissing, "registry-missing"),
            (ProtocolError::RegistryInUse, "registry-in-use"),
            (ProtocolError::IdentifierExhausted, "identifier-exhausted"),
            (ProtocolError::UnsupportedCommand, "unsupported-command"),
            (ProtocolError::DeadlineExceeded, "deadline-exceeded"),
            (ProtocolError::Cancelled, "cancelled"),
            (ProtocolError::InvalidArguments, "invalid-arguments"),
            (ProtocolError::BrowserFailure, "browser-failure"),
            (ProtocolError::StaleScope, "stale-scope"),
            (ProtocolError::CleanupFailed, "cleanup-failed"),
            (ProtocolError::StaleReference, "stale-reference"),
            (ProtocolError::PolicyDenied, "policy-denied"),
            (ProtocolError::NotActionable, "not-actionable"),
            (ProtocolError::LocatorNotFound, "locator-not-found"),
            (
                ProtocolError::ContentLengthMismatch,
                "content-length-mismatch",
            ),
            (
                ProtocolError::RedirectBodyUnavailable,
                "redirect-body-unavailable",
            ),
            (ProtocolError::InterceptedPointer, "intercepted-pointer"),
            (
                ProtocolError::CheckedStateUnchanged,
                "checked-state-unchanged",
            ),
            (
                ProtocolError::CheckedControlReplaced,
                "checked-control-replaced",
            ),
        ];
        assert_eq!(old.len(), vectors["errorCodes"].as_array().unwrap().len());
        for (code, expected) in old {
            assert!(vectors["errorCodes"]
                .as_array()
                .unwrap()
                .contains(&Value::String(expected.into())));
            assert_eq!(serde_json::to_value(&code).unwrap(), expected);
            assert_eq!(
                serde_json::to_value(WireError { code }).unwrap(),
                serde_json::json!({"code":expected})
            );
        }
    }

    #[test]
    fn frame_error_facts_are_checked_and_terminal_vectors_match() {
        for index in [64, usize::MAX] {
            assert!(FrameSelectionIndex::new(index).is_none());
        }
        for count in [0, 1, MAX_FRAME_SELECTION_COUNT + 1, usize::MAX] {
            assert!(FrameAmbiguity::new(0, count).is_none());
        }
        assert!(FrameAmbiguity::new(64, 2).is_none());
        let vectors: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/client-protocol-v1.json"))
                .unwrap();
        for vector in vectors["frameErrors"].as_array().unwrap() {
            let facts = &vector["error"]["frameSelection"];
            let index = facts["index"].as_u64().unwrap() as usize;
            let count = facts["count"].as_u64().unwrap() as usize;
            let code = if count == 0 {
                ProtocolError::FrameNotFound(FrameSelectionIndex::new(index).unwrap())
            } else {
                ProtocolError::FrameAmbiguous(FrameAmbiguity::new(index, count).unwrap())
            };
            assert_eq!(
                serde_json::to_value(&code).unwrap(),
                vector["error"]["code"]
            );
            let message = ServerMessage::Result {
                recovery: None,
                retention: None,
                id: "frame".into(),
                generation: 1,
                operation_seq: 1,
                ok: false,
                data: None,
                error: Some(WireError { code }),
                effects: if vector["effects"] == "unknown" {
                    Effects::Unknown
                } else {
                    Effects::NotDispatched
                },
                scope_state: if vector["scopeState"] == "quarantined" {
                    ScopeState::Quarantined
                } else {
                    ScopeState::Usable
                },
            };
            assert_eq!(serde_json::to_value(message).unwrap(), *vector);
        }
    }

    #[test]
    fn shared_client_vectors_match_parser() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/client-protocol-v1.json"))
                .unwrap();
        for value in vectors["validClient"].as_array().unwrap() {
            assert!(parse_frame(&serde_json::to_vec(value).unwrap()).is_ok());
        }
        for value in vectors["invalidClient"].as_array().unwrap() {
            assert!(parse_frame(&serde_json::to_vec(value).unwrap()).is_err());
        }
    }

    #[test]
    fn shared_decision_vectors_enforce_exclusive_body_sources() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/client-protocol-v1.json"))
                .unwrap();
        for value in vectors["validDecision"].as_array().unwrap() {
            let decision: Decision = serde_json::from_value(value.clone()).unwrap();
            assert!(decision.validate().is_ok());
        }
        for value in vectors["invalidDecision"].as_array().unwrap() {
            let decision: Decision = serde_json::from_value(value.clone()).unwrap();
            assert!(decision.validate().is_err());
        }
    }

    #[test]
    fn accepts_extension_http_method_but_not_header_injection() {
        let mut overrides = RequestOverrides {
            method: Some("M-SEARCH".into()),
            ..Default::default()
        };
        assert!(Decision::Continue {
            overrides: overrides.clone()
        }
        .validate()
        .is_ok());
        overrides.method = Some("GET\r\nInjected: true".into());
        assert!(Decision::Continue { overrides }.validate().is_err());
    }

    #[test]
    fn rejects_unknown_fields_and_legacy_envelopes() {
        assert!(parse_frame(
            br#"{"type":"cancel","id":"c","generation":1,"operationSeq":2,"action":"click"}"#
        )
        .is_err());
        assert!(parse_frame(br#"{"id":"c","action":"click"}"#).is_err());
        assert!(parse_frame(br#"{"type":"decision","id":"c","generation":1,"token":"t","decision":{"kind":"abort","script":"bad"}}"#).is_err());
    }

    #[test]
    fn capability_negotiation_does_not_invent_browser_support() {
        assert_eq!(
            validate_hello(PROTOCOL, &["protected-capture".into()], &[]),
            Err(ProtocolError::UnsupportedCapability)
        );
        assert!(validate_hello(PROTOCOL, &[], &[]).is_ok());
        assert_eq!(
            validate_hello("other", &[], &[]),
            Err(ProtocolError::UnsupportedProtocol)
        );
    }

    #[test]
    fn rejects_oversized_frames() {
        assert!(parse_frame(&vec![b' '; MAX_FRAME_BYTES + 1]).is_err());
    }
}
