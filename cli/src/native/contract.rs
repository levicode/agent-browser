//! One compiled downstream contract, not a runtime compatibility mode.
//!
//! Capability queries never connect to a browser. Clients can require this
//! contract on every request, including an existing daemon, before any effects.
use serde_json::{json, Value};

pub const CONTRACT_VERSION: &str = "e2e-exact-1";
pub const CONTRACT_MISMATCH_PREFIX: &str = "contract_mismatch: ";
pub const REQUIRED_CAPABILITIES: &[&str] = &[
    "exact-refs",
    "passive-scoped-cdp",
    "pre-dispatch-stale",
    "outcome-unknown",
];

pub fn capabilities() -> Value {
    json!({
        "contractVersion": CONTRACT_VERSION,
        "nativeVersion": env!("CARGO_PKG_VERSION"),
        "capabilities": REQUIRED_CAPABILITIES,
        "refModes": ["semantic", "exact"],
        "passiveScope": {
            "requiresDedicatedEndpoint": true,
            "requiresTargetAndContext": true,
            "ownsDebuggerPause": false,
            "ownsFetch": false
        }
    })
}

/// An omitted expectation is an ordinary upstream-compatible request. A
/// provided expectation must match exactly; nulls and nonstrings fail closed.
pub fn validate_expected_contract(command: &Value) -> Result<(), String> {
    let Some(expected) = command.get("expectedContract") else {
        return Ok(());
    };
    if expected.as_str() != Some(CONTRACT_VERSION) {
        return Err(format!(
            "{CONTRACT_MISMATCH_PREFIX}requested {expected}, native provides {CONTRACT_VERSION}"
        ));
    }
    Ok(())
}

pub fn validate_capabilities(data: Option<&Value>, expected: &str) -> Result<(), String> {
    let complete = data.is_some_and(|descriptor| {
        descriptor.get("contractVersion").and_then(Value::as_str) == Some(expected)
            && descriptor.get("nativeVersion").and_then(Value::as_str)
                == Some(env!("CARGO_PKG_VERSION"))
            && descriptor
                .get("capabilities")
                .and_then(Value::as_array)
                .is_some_and(|provided| {
                    REQUIRED_CAPABILITIES.iter().all(|required| {
                        provided
                            .iter()
                            .any(|value| value.as_str() == Some(*required))
                    })
                })
            && descriptor["passiveScope"]["requiresDedicatedEndpoint"] == true
            && descriptor["passiveScope"]["requiresTargetAndContext"] == true
            && descriptor["passiveScope"]["ownsDebuggerPause"] == false
            && descriptor["passiveScope"]["ownsFetch"] == false
    });
    if !complete {
        return Err(format!(
            "{CONTRACT_MISMATCH_PREFIX}running daemon does not provide the complete {expected} bundle; close that session explicitly or use a new session"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_contract_has_no_runtime_profile_switch() {
        let descriptor = capabilities();
        assert_eq!(descriptor["contractVersion"], CONTRACT_VERSION);
        assert!(descriptor.get("profiles").is_none());
        assert_eq!(descriptor["passiveScope"]["ownsFetch"], false);
        assert_eq!(descriptor["passiveScope"]["ownsDebuggerPause"], false);
    }

    #[test]
    fn contract_expectation_is_optional_but_never_coerced() {
        assert!(validate_expected_contract(&json!({})).is_ok());
        assert!(validate_expected_contract(&json!({"expectedContract":CONTRACT_VERSION})).is_ok());
        for expected in [json!("e2e-exact-0"), json!(null), json!(true), json!(1)] {
            assert!(validate_expected_contract(&json!({"expectedContract": expected})).is_err());
        }
    }

    #[test]
    fn old_or_unidentified_daemons_are_not_accepted() {
        assert!(validate_capabilities(Some(&capabilities()), CONTRACT_VERSION).is_ok());
        assert!(validate_capabilities(None, CONTRACT_VERSION).is_err());
        assert!(validate_capabilities(Some(&json!({})), CONTRACT_VERSION).is_err());
        assert!(validate_capabilities(
            Some(&json!({"contractVersion":"e2e-exact-0"})),
            CONTRACT_VERSION
        )
        .is_err());
        for field in ["nativeVersion", "capabilities", "passiveScope"] {
            let mut incomplete = capabilities();
            incomplete.as_object_mut().unwrap().remove(field);
            assert!(validate_capabilities(Some(&incomplete), CONTRACT_VERSION).is_err());
        }
        let mut owns_fetch = capabilities();
        owns_fetch["passiveScope"]["ownsFetch"] = json!(true);
        assert!(validate_capabilities(Some(&owns_fetch), CONTRACT_VERSION).is_err());
    }
}
