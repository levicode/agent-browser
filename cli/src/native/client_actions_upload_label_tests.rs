use super::*;

async fn upload(mode: &'static str) -> (Fixture, Result<Value, ActionFailure>) {
    let f = fixture(mode).await;
    let actions = ClientActions::default();
    let result = actions
        .execute(
            f.context(),
            "browser.perform",
            &json!({
                "identityScope":"scope", "ref":{"id":"@e1","revision":"1"},
                "action":{"kind":"setInputFiles", "files":[]}
            }),
        )
        .await;
    actions.cleanup().await.unwrap();
    (f, result)
}

#[tokio::test]
async fn upload_label_uses_only_its_captured_control_and_releases_both_handles() {
    for (mode, target) in [
        ("upload-label", "upload-control"),
        ("upload-direct", "exact-node"),
    ] {
        let (f, result) = upload(mode).await;
        assert!(result.is_ok(), "{mode}: {result:?}");
        let log = f.log.lock().unwrap();
        let writes = log
            .iter()
            .filter(|r| r["method"] == "DOM.setFileInputFiles")
            .collect::<Vec<_>>();
        assert_eq!(writes.len(), 1, "{mode}");
        assert_eq!(writes[0]["params"]["objectId"], target);
        assert_eq!(writes[0]["sessionId"], "page");
        assert_eq!(writes[0]["params"]["files"], json!([]));
        for object in if mode == "upload-label" {
            vec!["exact-node", "upload-control"]
        } else {
            vec!["exact-node"]
        } {
            assert_eq!(
                log.iter()
                    .filter(|r| r["method"] == "Runtime.releaseObject"
                        && r["params"]["objectId"] == object)
                    .count(),
                1,
                "{mode}: {object}"
            );
        }
        assert!(!log
            .iter()
            .any(|r| r["method"] == "Runtime.evaluate" || r["method"] == "DOM.querySelector"));
        assert_eq!(
            log.iter()
                .filter(|r| r["method"] == "DOM.resolveNode")
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn upload_label_refusal_and_lost_authority_never_dispatch_or_retry() {
    for (mode, error, cleanup, objects) in [
        (
            "upload-label-missing",
            ProtocolError::NotActionable,
            false,
            vec!["exact-node"],
        ),
        (
            "upload-label-stale",
            ProtocolError::StaleReference,
            false,
            vec!["exact-node"],
        ),
        (
            "upload-label-disabled",
            ProtocolError::NotActionable,
            false,
            vec!["exact-node", "upload-control"],
        ),
        (
            "upload-label-release-failed",
            ProtocolError::CleanupFailed,
            true,
            vec!["exact-node", "upload-control"],
        ),
        (
            "upload-label-exception",
            ProtocolError::BrowserFailure,
            false,
            vec!["exact-node", "upload-control", "upload-exception"],
        ),
    ] {
        let (f, result) = upload(mode).await;
        let failure = result.unwrap_err();
        assert_eq!(failure.error, error, "{mode}");
        assert_eq!(failure.effects, Effects::NotDispatched, "{mode}");
        assert_eq!(failure.cleanup_failed, cleanup, "{mode}");
        assert_eq!(failure.reason, None, "no fill fallback: {mode}");
        let log = f.log.lock().unwrap();
        assert!(!log.iter().any(|r| r["method"] == "DOM.setFileInputFiles"));
        for object in objects {
            assert_eq!(
                log.iter()
                    .filter(|r| r["method"] == "Runtime.releaseObject"
                        && r["params"]["objectId"] == object)
                    .count(),
                1,
                "{mode}: {object}"
            );
        }
    }
    let (f, result) = upload("upload-label-retired").await;
    let failure = result.unwrap_err();
    assert_eq!(failure.effects, Effects::NotDispatched);
    assert!(!f
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["method"] == "DOM.setFileInputFiles"));
    assert!(f
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["method"] == "Runtime.releaseObject"
            && r["params"]["objectId"] == "upload-control"));
}

#[tokio::test]
async fn upload_control_release_failure_preserves_dispatched_effects() {
    let (f, result) = upload("upload-control-release-failed").await;
    let failure = result.unwrap_err();
    assert_eq!(failure.error, ProtocolError::CleanupFailed);
    assert!(failure.cleanup_failed);
    assert_eq!(failure.effects, Effects::Unknown);
    assert_eq!(failure.reason, None);
    assert_eq!(
        f.log
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["method"] == "DOM.setFileInputFiles")
            .count(),
        1
    );
}

#[tokio::test]
async fn upload_label_mapping_cannot_bypass_opaque_scope_or_revision_guards() {
    for request in [
        json!({"identityScope":"other","ref":{"id":"@e1","revision":"1"},"action":{"kind":"setInputFiles","files":[]}}),
        json!({"identityScope":"scope","ref":{"id":"@missing","revision":"1"},"action":{"kind":"setInputFiles","files":[]}}),
        json!({"identityScope":"scope","ref":{"id":"@e1","revision":"0"},"action":{"kind":"setInputFiles","files":[]}}),
    ] {
        let f = fixture("upload-label").await;
        let failure = ClientActions::default()
            .execute(f.context(), "browser.perform", &request)
            .await
            .unwrap_err();
        assert_eq!(failure.effects, Effects::NotDispatched);
        assert!(!f
            .log
            .lock()
            .unwrap()
            .iter()
            .any(
                |r| r["params"]["functionDeclaration"] == UPLOAD_LABEL_CONTROL
                    || r["method"] == "DOM.setFileInputFiles"
            ));
    }
}
