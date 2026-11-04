//! Real owned attempts and real recorder/encoder; only completion scheduling is held.
use super::super::client_actions::{fixture_configuration, fixture_scope_open, FixtureOperations};
use super::super::client_transport::ClientExecutor;
use super::*;
use serde_json::{json, Value};

async fn command(
    browser: &ClientBrowser,
    ops: &mut FixtureOperations,
    name: &str,
    args: Value,
) -> Result<Value, String> {
    ops.execute_written(
        browser,
        browser.event_sink.get().ok_or("missing sink")?,
        name,
        args,
        30,
    )
    .await
    .map_err(|error| format!("{name} settlement: {error:?}"))?
    .result
    .map_err(|error| format!("{name}: {error:?}"))
}
async fn paint(browser: &ClientBrowser, color: &str) -> Result<(), String> {
    let page = browser
        .page_lease(false)
        .await
        .map_err(|e| format!("page lease: {e:?}"))?;
    super::super::browser::evaluate_on(&page.client, &page.page_session_id,
        &format!("document.documentElement.style.background='{color}'; document.body.style.margin='0'; document.body.innerHTML='<div style=\"width:100vw;height:100vh;background:{color}\"></div>'; true")).await?;
    page.permit
        .check()
        .map_err(|e| format!("paint permit: {e:?}"))
}

#[tokio::test]
#[ignore = "requires hosted Chromium and ffmpeg; real two-attempt capture/encoding and joined old owner"]
async fn chromium_two_attempt_recording_late_old_completion_cannot_mutate_new_artifact() {
    let mut host = super::super::browser::BrowserManager::launch(Default::default(), None)
        .await
        .unwrap();
    let browser = Arc::new(ClientBrowser::new(Arc::new(
        super::super::client_session::ClientSession::new(),
    )));
    let (sink, _events) =
        super::super::client_transport::ClientEventSink::test_channel(browser.broker.clone());
    browser.set_event_sink(sink).unwrap();
    let mut ops = FixtureOperations::new(browser.broker.clone());
    let result: Result<(), String> = async {
        let first = command(
            &browser,
            &mut ops,
            "scope.open",
            fixture_scope_open("connect", Some(host.get_cdp_url())),
        )
        .await?;
        let old_scope = first["identityScope"]
            .as_str()
            .ok_or("missing old identity")?
            .to_owned();
        command(
            &browser,
            &mut ops,
            "scope.configure",
            fixture_configuration(&old_scope, None),
        )
        .await?;
        command(
            &browser,
            &mut ops,
            "page.activate",
            json!({"identityScope":old_scope}),
        )
        .await?;
        paint(&browser, "rgb(200,20,20)").await?;
        command(
            &browser,
            &mut ops,
            "recording.start",
            json!({"identityScope":old_scope,"size":{"width":320,"height":200},"quality":70}),
        )
        .await?;
        let (old_actions, old_targets, old_context) = {
            let owner = browser.owner.lock().await;
            let owner = owner.as_ref().ok_or("old owner missing")?;
            (
                owner
                    .runtime
                    .as_ref()
                    .ok_or("old runtime missing")?
                    .actions
                    .clone(),
                owner.targets.clone(),
                owner.context_id.clone(),
            )
        };
        if !old_actions
            .is_recording_armed()
            .await
            .map_err(|e| format!("old recording: {e:?}"))?
        {
            return Err("old recorder never armed".into());
        }
        let (capture_arrived, release_capture, old_directory) =
            old_actions.hold_recording_completion_for_test().await;
        // Queue an old lifecycle callback NOW, retaining the actual old runtime.
        // It is delivered after the new recorder starts, not rebound to new actions.
        let (release_late, late_released) = tokio::sync::oneshot::channel();
        let callback_actions = old_actions.clone();
        let callback_scope = old_scope.clone();
        let callback_blobs = browser.blobs.clone();
        let late = tokio::spawn(async move {
            late_released
                .await
                .map_err(|_| ProtocolError::CleanupFailed)?;
            callback_actions
                .recording_page_closing(&callback_scope, &callback_blobs)
                .await?;
            callback_actions.abandon_recording().await
        });
        let closing_browser = browser.clone();
        let end_scope = old_scope.clone();
        let ending = tokio::spawn(async move {
            let result = command(
                &closing_browser,
                &mut ops,
                "scope.end",
                json!({"identityScope":end_scope}),
            )
            .await;
            (ops, result)
        });
        // The real encoder must finish first. Its retained join is still pending;
        // cleanup must not publish a reusable browser or next-attempt authority.
        let arrived =
            tokio::time::timeout(std::time::Duration::from_secs(20), capture_arrived).await;
        if !matches!(arrived, Ok(Ok(()))) {
            let _ = release_capture.send(());
            let _ = ending.await;
            let _ = release_late.send(());
            let _ = late.await;
            return Err("real old recorder did not reach held completion".into());
        }
        let premature_end = ending.is_finished();
        let premature_reuse = browser.retained_browser.lock().await.is_some();
        let _ = release_capture.send(());
        let (mut ops, ended) = ending.await.map_err(|e| format!("scope.end join: {e}"))?;
        ended?;
        if premature_end || premature_reuse {
            return Err("attempt retirement overtook retained recorder join".into());
        }
        if old_directory.exists() || old_targets.inventory().is_ok() {
            return Err("old recorder resources survived confirmed end".into());
        }
        let contexts = host
            .client
            .send_command_no_params("Target.getBrowserContexts", None)
            .await?;
        if contexts["browserContextIds"]
            .as_array()
            .ok_or("missing contexts")?
            .contains(&json!(old_context))
        {
            return Err("old context survives end".into());
        }
        let second = command(
            &browser,
            &mut ops,
            "scope.open",
            fixture_scope_open("reuse", None),
        )
        .await?;
        let scope = second["identityScope"]
            .as_str()
            .ok_or("missing next identity")?
            .to_owned();
        if scope == old_scope {
            return Err("attempt identity reused".into());
        }
        command(
            &browser,
            &mut ops,
            "scope.configure",
            fixture_configuration(&scope, None),
        )
        .await?;
        command(
            &browser,
            &mut ops,
            "page.activate",
            json!({"identityScope":scope}),
        )
        .await?;
        paint(&browser, "rgb(20,40,180)").await?;
        command(
            &browser,
            &mut ops,
            "recording.start",
            json!({"identityScope":scope,"size":{"width":320,"height":200},"quality":70}),
        )
        .await?;
        let (new_actions, new_blob_scope) = {
            let owner = browser.owner.lock().await;
            let runtime = owner
                .as_ref()
                .ok_or("new owner missing")?
                .runtime
                .as_ref()
                .ok_or("new runtime missing")?;
            (runtime.actions.clone(), runtime.scope.clone())
        };
        if Arc::ptr_eq(&old_actions, &new_actions) {
            return Err("next attempt reused old recorder ledger".into());
        }
        release_late
            .send(())
            .map_err(|_| "late callback disappeared")?;
        late.await
            .map_err(|e| format!("late callback join: {e}"))?
            .map_err(|e| format!("old callback: {e:?}"))?;
        if !new_actions
            .is_recording_armed()
            .await
            .map_err(|e| format!("new recorder: {e:?}"))?
        {
            return Err("old completion disarmed new recording".into());
        }
        let output = command(
            &browser,
            &mut ops,
            "recording.stop",
            json!({"identityScope":scope}),
        )
        .await?;
        let segments = output["segments"]
            .as_array()
            .ok_or("missing new segments")?;
        if segments.len() != 1 || segments[0]["identityScope"] != scope {
            return Err("old artifact mixed into new attempt".into());
        }
        let segment = &segments[0];
        let handle = segment["handle"]
            .as_str()
            .ok_or("missing artifact handle")?;
        let size = segment["size"].as_u64().ok_or("missing artifact size")? as usize;
        let mut bytes = Vec::new();
        while bytes.len() < size {
            let chunk = browser
                .blobs
                .read(
                    &new_blob_scope,
                    handle,
                    bytes.len(),
                    (size - bytes.len()).min(super::super::client_blobs::MAX_CHUNK_BYTES),
                )
                .map_err(|e| format!("artifact read: {e:?}"))?;
            if chunk.is_empty() {
                return Err("artifact read made no progress".into());
            }
            bytes.extend(chunk);
        }
        browser
            .blobs
            .release(&new_blob_scope, handle)
            .map_err(|e| format!("artifact release: {e:?}"))?;
        let directory = tempfile::tempdir().map_err(|e| e.to_string())?;
        let video = directory.path().join("new-attempt.webm");
        let image_path = directory.path().join("first-frame.png");
        tokio::fs::write(&video, bytes)
            .await
            .map_err(|e| e.to_string())?;
        let decoded = tokio::process::Command::new("ffmpeg")
            .args(["-v", "error", "-i"])
            .arg(&video)
            .args(["-frames:v", "1"])
            .arg(&image_path)
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if !decoded.status.success() {
            return Err("new video failed real decode".into());
        }
        let image = image::open(image_path)
            .map_err(|e| e.to_string())?
            .to_rgb8();
        if image.dimensions() != (320, 200) {
            return Err("new recording dimensions changed".into());
        }
        for (actual, expected) in image.get_pixel(160, 100).0.into_iter().zip([20u8, 40, 180]) {
            if actual.abs_diff(expected) >= 20 {
                return Err("new artifact contains wrong/old first frame".into());
            }
        }
        if command(
            &browser,
            &mut ops,
            "recording.stop",
            json!({"identityScope":scope}),
        )
        .await?["segments"]
            != json!([])
        {
            return Err("artifact collected twice".into());
        }
        directory.close().map_err(|e| e.to_string())?;
        Ok(())
    }
    .await;
    let cleanup = browser.shutdown().await;
    let host_cleanup = host.close().await;
    result.unwrap();
    cleanup.unwrap();
    host_cleanup.unwrap();
}
