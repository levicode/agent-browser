//! Shared protected-read stabilization. Browser conformance is an explicit gate;
//! the existence of this module does not advertise a protected capability.

#[cfg(test)]
mod tests {
    use super::super::cdp::client::CdpClient;
    use super::super::client_browser::{ExecutionGate, OwnedBrowser};
    use base64::Engine;
    use serde_json::{json, Value};
    use std::sync::Arc;
    use std::time::Duration;

    async fn bounded(
        client: &CdpClient,
        session: &str,
        method: &str,
        args: Value,
    ) -> Result<Value, String> {
        tokio::time::timeout(
            Duration::from_secs(3),
            client.send_command(method, Some(args), Some(session)),
        )
        .await
        .map_err(|_| format!("synthetic probe timed out: {method}"))?
        .map_err(|_| format!("synthetic probe command failed: {method}"))
    }
    async fn counter(client: &CdpClient, session: &str, world: Option<i64>) -> Result<u64, String> {
        let mut args = json!({"expression":"Number(document.body.getAttribute('data-probe-counter'))","returnByValue":true});
        if let Some(world) = world {
            args["contextId"] = json!(world);
        }
        bounded(client, session, "Runtime.evaluate", args).await?["result"]["value"]
            .as_u64()
            .ok_or("invalid synthetic counter".into())
    }
    async fn advances(client: &CdpClient, session: &str, after: u64) -> Result<(), String> {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if counter(client, session, None).await? > after {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| "synthetic timer did not resume".to_owned())?
    }

    /// Required hosted-browser gate, deliberately not a passing default unit test.
    /// Run explicitly with --ignored; all data are synthetic and no network is used.
    #[tokio::test]
    #[ignore = "requires real Chromium; required protected-read browser CI gate"]
    async fn chromium_frozen_page_keeps_native_read_lane_and_restores() {
        let mut owner = OwnedBrowser::launch(Default::default(), None)
            .await
            .unwrap();
        let gate = Arc::new(ExecutionGate::default());
        let page = owner.lease(gate.enter(false).unwrap()).unwrap();
        let client = &page.client;
        let session = &page.page_session_id;
        let initialized=bounded(client,session,"Runtime.evaluate",json!({"expression":r#"(()=>{document.body.innerHTML='<button>synthetic button</button><div id="probe-host"></div>';const root=document.getElementById('probe-host').attachShadow({mode:'closed'});root.innerHTML='<input id="synthetic-password" type="password" value="synthetic-only">';document.body.setAttribute('data-probe-counter','0');setInterval(()=>document.body.setAttribute('data-probe-counter',String(Number(document.body.getAttribute('data-probe-counter'))+1)),10);return true})()"#,"returnByValue":true})).await;
        let mut touched = false;
        let mut original_rate = None;
        let result: Result<(), String> = async {
            initialized?;
            advances(client, session, 1).await?;
            bounded(client, session, "Animation.enable", json!({})).await?;
            original_rate = bounded(client, session, "Animation.getPlaybackRate", json!({}))
                .await?["playbackRate"]
                .as_f64();
            let rate = original_rate.ok_or("missing animation rate")?;
            if !rate.is_finite() {
                return Err("invalid animation rate".into());
            }
            touched = true;
            bounded(
                client,
                session,
                "Animation.setPlaybackRate",
                json!({"playbackRate":0}),
            )
            .await?;
            bounded(
                client,
                session,
                "Page.setWebLifecycleState",
                json!({"state":"frozen"}),
            )
            .await?;
            let tree = bounded(client, session, "Page.getFrameTree", json!({})).await?;
            let frame = tree["frameTree"]["frame"]["id"]
                .as_str()
                .ok_or("missing frame")?;
            let loader = tree["frameTree"]["frame"]["loaderId"].clone();
            let world = bounded(
                client,
                session,
                "Page.createIsolatedWorld",
                json!({"frameId":frame,"worldName":"native-protected-read-probe"}),
            )
            .await?["executionContextId"]
                .as_i64()
                .ok_or("missing world")?;
            let before = counter(client, session, Some(world)).await?;
            // This delay measures scheduler suspension, never readiness/state restoration.
            tokio::time::sleep(Duration::from_millis(80)).await;
            if counter(client, session, Some(world)).await? != before {
                return Err("page timer advanced while frozen".into());
            }
            let ax = bounded(
                client,
                session,
                "Accessibility.getFullAXTree",
                json!({"frameId":frame}),
            )
            .await?;
            if !ax["nodes"]
                .as_array()
                .is_some_and(|nodes| nodes.iter().any(|n| n["role"]["value"] == "button"))
            {
                return Err("frozen AX read lost button".into());
            }
            let dom = bounded(
                client,
                session,
                "DOMSnapshot.captureSnapshot",
                json!({"computedStyles":[]}),
            )
            .await?;
            if !dom["strings"]
                .as_array()
                .is_some_and(|strings| strings.iter().any(|s| s == "synthetic-password"))
            {
                return Err("closed-shadow snapshot incomplete".into());
            }
            let png = bounded(
                client,
                session,
                "Page.captureScreenshot",
                json!({"format":"png","fromSurface":true}),
            )
            .await?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(png["data"].as_str().ok_or("missing synthetic image")?)
                .map_err(|_| "invalid synthetic image")?;
            image::load_from_memory_with_format(&bytes, image::ImageFormat::Png)
                .map_err(|_| "undecodable synthetic image")?;
            let after = bounded(client, session, "Page.getFrameTree", json!({})).await?;
            if after["frameTree"]["frame"]["loaderId"] != loader {
                return Err("document changed during frozen read".into());
            }
            Ok(())
        }
        .await;
        let cleanup: Result<(), String> = async {
            if touched {
                let active = bounded(
                    client,
                    session,
                    "Page.setWebLifecycleState",
                    json!({"state":"active"}),
                )
                .await;
                let rate = bounded(
                    client,
                    session,
                    "Animation.setPlaybackRate",
                    json!({"playbackRate":original_rate.unwrap_or(1.0)}),
                )
                .await;
                active?;
                rate?;
                if bounded(client, session, "Animation.getPlaybackRate", json!({})).await?
                    ["playbackRate"]
                    .as_f64()
                    != original_rate
                {
                    return Err("animation rate was not restored".into());
                }
                let before = counter(client, session, None).await?;
                advances(client, session, before).await?;
            }
            Ok(())
        }
        .await;
        drop(page);
        let closed = owner.close().await;
        assert!(closed.is_ok(), "owned synthetic context cleanup failed");
        assert!(cleanup.is_ok(), "restoration proof failed: {cleanup:?}");
        assert!(result.is_ok(), "frozen read conformance failed: {result:?}");
    }
}
