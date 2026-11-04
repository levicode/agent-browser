//! Metadata controls supplement, not replace, real framed initializer controls.
use super::*;
#[test]
fn popup_configuration_proof_requires_same_revision_and_observed_frontier() {
    let proof = PopupConfigurationApplied {
        revision: 7,
        received: 12,
    };
    assert!(proof.matches((12, 7)));
    assert!(proof.matches((13, 7)));
    assert!(!proof.matches((11, 7)));
    assert!(!proof.matches((12, 8)));
    assert!(!proof.matches((12, 6)));
}
#[test]
fn popup_configuration_proof_is_one_shot_not_rebased_after_revision_or_frontier_change() {
    let slot = std::sync::OnceLock::new();
    assert!(slot
        .set(PopupConfigurationApplied {
            revision: 7,
            received: 12
        })
        .is_ok());
    assert!(slot
        .set(PopupConfigurationApplied {
            revision: 8,
            received: 14
        })
        .is_err());
    let proof = slot.get().unwrap();
    assert!(proof.matches((12, 7)));
    assert!(!proof.matches((14, 8)));
}
