//! Diagnostic-only unit controls. No transport or browser is created.
use super::diagnostic::{
    EvalPreparationRefusal as Refused, PopupReceiptStage as Stage, PopupSetupCheckpoint as Point,
};
use super::*;

#[test]
fn popup_setup_checkpoints_never_infer_ack_from_entered_or_rewrite_first_failure() {
    let progress = PopupSetupProgress::default();
    assert_eq!(progress.unconfigured_refusal(0), Refused::Unconfigured);
    progress.advance(Point::ConfigurationEntered);
    progress.advance(Point::RuntimeEnableEntered);
    let first = PopupPreparationFailure::new(
        ProtocolError::ScopeUnavailable,
        progress.unconfigured_refusal(0),
    );
    assert_eq!(
        first.reason,
        Refused::UnconfiguredAt(Point::RuntimeEnableEntered, Stage::Unissued)
    );
    progress.advance(Point::RuntimeEnableAcknowledged);
    progress.advance(Point::ScriptsAcknowledged);
    progress.advance(Point::RecursiveAttachAcknowledged);
    progress.advance(Point::ConfiguredCommitObserved);
    assert_eq!(
        first.reason,
        Refused::UnconfiguredAt(Point::RuntimeEnableEntered, Stage::Unissued)
    );
    assert_eq!(first.error, ProtocolError::ScopeUnavailable);
    assert_eq!(
        progress.unconfigured_refusal(2),
        Refused::UnconfiguredAt(Point::ConfiguredCommitObserved, Stage::Completed)
    );
    assert_eq!(
        progress.unconfigured_refusal(255),
        Refused::UnconfiguredAt(Point::ConfiguredCommitObserved, Stage::Unknown)
    );
}

#[test]
fn popup_setup_missing_duplicate_or_reordered_checkpoints_stay_unknown() {
    for steps in [
        vec![Point::RuntimeEnableAcknowledged],
        vec![Point::ConfigurationEntered, Point::ConfigurationEntered],
        vec![
            Point::ConfigurationEntered,
            Point::RuntimeEnableEntered,
            Point::ScriptsAcknowledged,
        ],
    ] {
        let progress = PopupSetupProgress::default();
        for step in steps {
            progress.advance(step);
        }
        assert_eq!(progress.unconfigured_refusal(0), Refused::Unconfigured);
        progress.advance(Point::ConfiguredCommitObserved);
        assert_eq!(progress.unconfigured_refusal(0), Refused::Unconfigured);
    }
    for invalid in [0, 7, 255] {
        assert_eq!(Point::from_code(invalid), None);
    }
}

#[test]
fn popup_setup_diagnostic_instances_do_not_complete_or_contaminate_other_tickets() {
    let first = PopupSetupProgress::default();
    let second = PopupSetupProgress::default();
    first.advance(Point::ConfigurationEntered);
    first.advance(Point::RuntimeEnableEntered);
    assert_eq!(second.unconfigured_refusal(0), Refused::Unconfigured);
    assert_eq!(
        first.unconfigured_refusal(3),
        Refused::UnconfiguredAt(Point::RuntimeEnableEntered, Stage::Released)
    );
    // Observed stage is carried, not manufactured from the checkpoint.
    assert_eq!(
        first.unconfigured_refusal(1),
        Refused::UnconfiguredAt(Point::RuntimeEnableEntered, Stage::Issued)
    );
}

#[test]
fn popup_setup_stale_foreign_sealed_or_contended_ticket_loses_detail_only() {
    for obstruction in [
        "replaced",
        "foreign",
        "wrong-target",
        "wrong-session",
        "sealed",
        "contended",
    ] {
        let registry = ClientTargets::new("ctx".into(), "scope".into());
        registry
            .attached("ctx", "popup".into(), "popup-session".into(), "page".into())
            .unwrap();
        let mut original = registry.owned_target("popup").unwrap();
        let progress = PopupSetupProgress::default();
        progress.observe_bound(&registry, &original, Point::ConfigurationEntered);
        assert_eq!(
            progress.unconfigured_refusal(0),
            Refused::UnconfiguredAt(Point::ConfigurationEntered, Stage::Unissued)
        );
        if obstruction == "replaced" {
            registry.detach("popup").unwrap();
            registry
                .attached("ctx", "popup".into(), "popup-session".into(), "page".into())
                .unwrap();
        } else if obstruction == "foreign" {
            let other = ClientTargets::new("ctx".into(), "scope".into());
            other
                .attached("ctx", "popup".into(), "popup-session".into(), "page".into())
                .unwrap();
            original = other.owned_target("popup").unwrap();
        } else if obstruction == "wrong-target" {
            original.target_id = "other-target".into();
        } else if obstruction == "wrong-session" {
            original.session_id = "other-session".into();
        } else if obstruction == "sealed" {
            registry.seal();
        }
        let before = registry.state.lock().unwrap().targets["popup"].clone();
        {
            let _held = (obstruction == "contended").then(|| registry.state.lock().unwrap());
            progress.observe_bound(&registry, &original, Point::RuntimeEnableEntered);
        }
        assert_eq!(progress.unconfigured_refusal(0), Refused::Unconfigured);
        let after = registry.state.lock().unwrap().targets["popup"].clone();
        assert!(before.same_initialization_attachment(&after));
        assert_eq!(
            (before.configured, before.resumed, before.resume_pending),
            (after.configured, after.resumed, after.resume_pending)
        );
        progress.advance(Point::RuntimeEnableAcknowledged);
        assert_eq!(progress.unconfigured_refusal(0), Refused::Unconfigured);
    }
}
