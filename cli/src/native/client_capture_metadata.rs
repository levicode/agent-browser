//! Closed capture outcome metadata shared by capture and bounded diagnostics.
//! No browser, capture runtime, or cleanup authority lives in this module.
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureReason {
    Cancelled,
    Superseded,
    Deadline,
    StaleScope,
    IncompleteFrames,
    UnsafeGeometry,
    UninspectableContent,
    MaskingUnproven,
    BrowserFailure,
    BoundsExceeded,
    CleanupFailed,
}
/// Internal provenance, not a public error category. In particular, a failed
/// initial coverage probe is not a failed source-mask or post-capture proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CapturePhase {
    Admission,
    IndependentCoverage,
    SourceProtection,
    RawCapture,
    PostCaptureValidation,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CaptureAttemptFailure {
    pub phase: CapturePhase,
    pub reason: CaptureReason,
}
