//! Pure provenance predicates only: no mock receipt, browser, or fresh owner.
//! The exact NavigationInterruptionProof::confirms gate remains production code.
use super::*;

#[test]
fn activation_origin_is_bound_to_the_original_command_not_a_family_allowlist() {
    for (origin, accepted) in [
        (ActivationCommand::Activate, "page.activate"),
        (ActivationCommand::Navigate, "page.navigate"),
    ] {
        for command in [
            "page.activate",
            "page.navigate",
            "recording.start",
            "page.reload",
            "page.evaluate",
            "",
            "Page.navigate",
        ] {
            assert_eq!(origin.matches(command), command == accepted);
        }
    }
}
#[test]
fn only_blank_navigation_interruption_can_transfer_an_existing_receipt() {
    assert!(!activation_navigation_error(None));
    for error in [ProtocolError::Cancelled, ProtocolError::DeadlineExceeded] {
        assert!(activation_navigation_error(Some(&error)));
    }
    for error in [
        ProtocolError::BrowserFailure,
        ProtocolError::CleanupFailed,
        ProtocolError::StaleScope,
        ProtocolError::ScopeUnavailable,
        ProtocolError::InvalidArguments,
        ProtocolError::UnsupportedCommand,
    ] {
        assert!(!activation_navigation_error(Some(&error)));
    }
}
