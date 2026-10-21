//! Explicitly negotiated client protocol. Legacy CLI envelopes are unchanged.
//! Browser capabilities are advertised separately, only after implementation.
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
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
}

/// Server envelopes are strict and correlated. A result terminates an RPC;
/// only scope_state describes whether native resources can be reused.
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
#[derive(Debug, Serialize)]
pub struct WireError {
    pub code: ProtocolError,
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
