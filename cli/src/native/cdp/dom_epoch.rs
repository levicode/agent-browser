//! A renderer frontend tree is reusable only while Chromium still maintains
//! the exact deep DOM binding. Advance before any frontend reset is submitted,
//! and before delivering any event that could affect that binding.
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub(crate) struct DomEpoch(AtomicU64);

impl DomEpoch {
    pub(crate) fn stamp(&self) -> Option<u64> {
        let value = self.0.load(Ordering::Acquire);
        (value != u64::MAX).then_some(value)
    }

    pub(crate) fn invalidate(&self) {
        let mut observed = self.0.load(Ordering::Acquire);
        while let Some(next) = observed.checked_add(1) {
            match self
                .0
                .compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(current) => observed = current,
            }
        }
    }

    pub(crate) fn stop(&self) {
        self.0.store(u64::MAX, Ordering::Release);
    }

    pub(crate) fn command(&self, method: &str) {
        if matches!(
            method,
            "DOM.getDocument" | "DOM.getFlattenedDocument" | "DOM.disable" | "DOM.enable"
        ) {
            self.invalidate();
        }
    }

    pub(crate) fn event(&self, method: &str) {
        if method.starts_with("DOM.")
            || method.starts_with("Inspector.")
            || method.starts_with("Target.")
            || method.starts_with("Page.frame")
            || method.starts_with("Page.navigated")
            || matches!(
                method,
                "Runtime.executionContextsCleared" | "Runtime.executionContextDestroyed"
            )
        {
            self.invalidate();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_changes_and_frontend_resets_revoke_but_unrelated_commands_do_not() {
        let epoch = DomEpoch::default();
        for method in [
            "DOM.childNodeRemoved",
            "DOM.attributeModified",
            "DOM.characterDataModified",
            "DOM.shadowRootPushed",
            "DOM.pseudoElementRemoved",
            "DOM.documentUpdated",
            "Page.frameNavigated",
            "Target.detachedFromTarget",
            "Runtime.executionContextDestroyed",
        ] {
            let old = epoch.stamp();
            epoch.event(method);
            assert_ne!(epoch.stamp(), old, "{method}");
        }
        let saved = epoch.stamp();
        epoch.command("DOM.pushNodesByBackendIdsToFrontend");
        epoch.event("Network.loadingFinished");
        assert_eq!(saved, epoch.stamp());
        epoch.command("DOM.getDocument");
        assert_ne!(saved, epoch.stamp());
        epoch.stop();
        epoch.invalidate();
        assert_eq!(epoch.stamp(), None);
    }
}
