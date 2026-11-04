//! Pure closed-payload controls; no CDP transport, broker, or operation owner.
use super::*;
#[test]
fn interruption_projection_is_closed_and_never_emits_arbitrary_text() {
    for value in [
        "none",
        "requested",
        "deadline-exceeded",
        "session-closed",
        "owner-retirement",
    ] {
        assert_eq!(activation_signal_fact(value), value);
    }
    for value in [
        "",
        "arbitrary payload",
        "Requested",
        "https://not-a-diagnostic.invalid",
    ] {
        assert_eq!(activation_signal_fact(value), "unknown");
    }
}
#[test]
fn facts_preserve_false_and_unknown_without_inferring_a_cause() {
    for closed in [false, true] {
        for remote in [false, true] {
            let mut record = serde_json::json!({});
            ActivationDiagnosticFacts {
                transport_closed: Some(closed),
                remote_closed_observed: Some(remote),
                ..Default::default()
            }
            .insert_into(&mut record);
            assert_eq!(
                record,
                serde_json::json!({"transportClosed":closed,"remoteClosedObserved":remote})
            );
        }
    }
}
#[test]
fn old_rows_gain_no_fields_and_cancel_deadline_facts_are_independent() {
    let mut unchanged = serde_json::json!({"sequence":1});
    ActivationDiagnosticFacts::default().insert_into(&mut unchanged);
    assert_eq!(unchanged, serde_json::json!({"sequence":1}));
    for elapsed in [false, true] {
        let mut record = serde_json::json!({});
        ActivationDiagnosticFacts {
            cancel_signal: Some("requested"),
            entry_deadline_elapsed: Some(elapsed),
            ..Default::default()
        }
        .insert_into(&mut record);
        assert_eq!(
            record,
            serde_json::json!({"cancelSignal":"requested","entryDeadlineElapsed":elapsed})
        );
    }
}
