//! Real framed ClientBrowser dispatch against a deterministic, owned CDP peer.
use super::*;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

fn info(id: &str, context: &str) -> Value {
    json!({"targetId":id,"type":"page","browserContextId":context,"url":"about:blank","title":""})
}
fn attachment(id: &str, session: &str) -> Value {
    json!({"method":"Target.attachedToTarget","params":{"sessionId":session,"targetInfo":info(id,"persistent-context"),"waitingForDebugger":true}})
}
async fn peer() -> (String, Arc<Mutex<Vec<Value>>>, tokio::task::JoinHandle<()>) {
    peer_with_navigation(false, false).await
}
async fn peer_with_navigation(
    fenced_navigation: bool,
    close_during_navigation: bool,
) -> (String, Arc<Mutex<Vec<Value>>>, tokio::task::JoinHandle<()>) {
    peer_with_mode(fenced_navigation, close_during_navigation, false).await
}
async fn peer_with_mode(
    fenced_navigation: bool,
    close_during_navigation: bool,
    isolated: bool,
) -> (String, Arc<Mutex<Vec<Value>>>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let log = Arc::new(Mutex::new(Vec::new()));
    let recorded = log.clone();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        socket.set_nodelay(true).unwrap();
        let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
        let mut pages = std::collections::BTreeMap::from([
            (
                "application".to_owned(),
                info("application", "persistent-context"),
            ),
            (
                "unrelated-host".to_owned(),
                info("unrelated-host", "persistent-context"),
            ),
            (
                "foreign-host".to_owned(),
                info("foreign-host", "foreign-context"),
            ),
        ]);
        if isolated {
            pages.remove("application");
            pages.remove("unrelated-host");
        }
        let mut context_live = false;
        let mut initial_created = false;
        let mut watching = false;
        let mut navigations = 0;
        while let Some(Ok(Message::Text(text))) = socket.next().await {
            let request: Value = serde_json::from_str(&text).unwrap();
            recorded.lock().unwrap().push(request.clone());
            let method = request["method"].as_str().unwrap();
            let session = request["sessionId"].as_str().unwrap_or_default();
            let mut before = Vec::new();
            let mut after = Vec::new();
            let mut navigation_closed = false;
            let result = match method {
                "Target.createBrowserContext" if isolated => {
                    context_live = true;
                    json!({"browserContextId":"persistent-context"})
                }
                "Target.disposeBrowserContext" if isolated => {
                    assert_eq!(request["params"]["browserContextId"], "persistent-context");
                    context_live = false;
                    for (target, sid) in [
                        ("application", "initial-session"),
                        ("replacement", "replacement-session"),
                    ] {
                        if pages.remove(target).is_some() {
                            after.push(json!({"method":"Target.detachedFromTarget","params":{"sessionId":sid,"targetId":target}}));
                        }
                    }
                    json!({})
                }
                "Target.getBrowserContexts" => {
                    json!({"browserContextIds":if isolated && context_live { vec!["foreign-context", "persistent-context"] } else { vec!["foreign-context"] },"defaultBrowserContextId":"persistent-context"})
                }
                "Target.getTargets" => {
                    json!({"targetInfos":pages.values().cloned().collect::<Vec<_>>()})
                }
                "Target.getTargetInfo" => {
                    let target = request["params"]["targetId"]
                        .as_str()
                        .unwrap_or(match session {
                            "initial-session" => "application",
                            "replacement-session" => "replacement",
                            _ => "unrelated-host",
                        });
                    json!({"targetInfo":pages.get(target).unwrap()})
                }
                "Target.attachToTarget" => {
                    assert_eq!(request["params"]["targetId"], "application");
                    json!({"sessionId":"initial-session"})
                }
                "Target.setAutoAttach" => {
                    if session.is_empty() && request["params"]["autoAttach"] == true && !watching {
                        watching = true;
                        if !isolated {
                            after.push(attachment("unrelated-host", "host-observer"));
                        }
                    }
                    json!({})
                }
                "Target.createTarget" if isolated && !initial_created => {
                    assert_eq!(
                        request["params"],
                        json!({"browserContextId":"persistent-context","url":"about:blank"})
                    );
                    initial_created = true;
                    pages.insert(
                        "application".into(),
                        info("application", "persistent-context"),
                    );
                    json!({"targetId":"application"})
                }
                "Target.createTarget" => {
                    assert_eq!(
                        request["params"],
                        json!({"browserContextId":"persistent-context","url":"about:blank"})
                    );
                    assert!(!pages.contains_key("replacement"));
                    pages.insert(
                        "replacement".into(),
                        info("replacement", "persistent-context"),
                    );
                    after.push(attachment("replacement", "replacement-session"));
                    json!({"targetId":"replacement"})
                }
                "Target.closeTarget" => {
                    assert_eq!(
                        request["params"]["targetId"], "application",
                        "reopen/cleanup must not close another host page"
                    );
                    pages.remove("application");
                    after.push(json!({"method":"Target.detachedFromTarget","params":{"sessionId":"initial-session","targetId":"application"}}));
                    json!({"success":true})
                }
                "Target.detachFromTarget" => {
                    let sid = request["params"]["sessionId"].as_str().unwrap();
                    after.push(
                        json!({"method":"Target.detachedFromTarget","params":{"sessionId":sid}}),
                    );
                    json!({})
                }
                "Page.getFrameTree" => {
                    json!({"frameTree":{"frame":{"id":format!("frame-{session}"),"loaderId":"blank-loader","url":"about:blank","securityOrigin":"null"}}})
                }
                "Page.addScriptToEvaluateOnNewDocument" => json!({"identifier":"test-script"}),
                "Page.navigate" => {
                    navigations += 1;
                    let target = match session {
                        "initial-session" => "application",
                        "replacement-session" if fenced_navigation => "replacement",
                        _ => panic!("unexpected navigation session"),
                    };
                    assert!(
                        pages.contains_key(target),
                        "navigation reached a closed target"
                    );
                    assert_eq!(request["params"]["url"], "about:blank");
                    let frame = format!("frame-{session}");
                    let loader = if fenced_navigation {
                        format!("fresh-loader-{navigations}")
                    } else {
                        "fresh-loader".into()
                    };
                    if close_during_navigation && navigations > 1 {
                        // A real peer event after native has sent Page.navigate,
                        // not a test-written native target/lease state.
                        pages.remove(target);
                        before.push(json!({"method":"Target.detachedFromTarget","params":{"sessionId":session,"targetId":target}}));
                        navigation_closed = true;
                    } else {
                        after.push(json!({"method":"Page.frameNavigated","sessionId":session,"params":{"frame":{"id":frame,"loaderId":loader,"url":"about:blank","securityOrigin":"null"}}}));
                        after.push(json!({"method":"Page.lifecycleEvent","sessionId":session,"params":{"frameId":frame,"loaderId":loader,"name":"DOMContentLoaded"}}));
                    }
                    json!({"frameId":frame,"loaderId":loader})
                }
                "Runtime.evaluate" => {
                    let target = if session == "initial-session" {
                        "application"
                    } else {
                        assert_eq!(session, "replacement-session");
                        "replacement"
                    };
                    assert!(
                        pages.contains_key(target),
                        "caller operation was dispatched to a closed page"
                    );
                    let expression = request["params"]["expression"].as_str().unwrap();
                    assert!(matches!(expression, "document.title" | "location.href"));
                    json!({"result":{"type":"string","value":if expression=="document.title" { session } else { "about:blank" }}})
                }
                "Network.disable" => {
                    // Borrowed-page cleanup releases observation only for the
                    // application's exact session, never another host tab.
                    assert!(matches!(session, "initial-session" | "replacement-session"));
                    assert_eq!(request["params"], json!({}));
                    json!({})
                }
                "Page.enable"
                | "Runtime.enable"
                | "Network.enable"
                | "WebMCP.enable"
                | "DOM.enable"
                | "DOM.disable"
                | "Network.setBypassServiceWorker"
                | "Fetch.enable"
                | "Fetch.disable"
                | "Browser.setDownloadBehavior"
                | "Page.setLifecycleEventsEnabled"
                | "Emulation.setEmulatedMedia"
                | "Emulation.setDeviceMetricsOverride"
                | "Target.setDiscoverTargets"
                | "Runtime.runIfWaitingForDebugger"
                | "Page.removeScriptToEvaluateOnNewDocument" => json!({}),
                other => panic!("unmodeled reopen CDP method {other}: {request}"),
            };
            let mut reply = if navigation_closed {
                json!({"id":request["id"],"error":{"code":-32000,"message":"scripted target closed during navigation"}})
            } else {
                json!({"id":request["id"],"result":result})
            };
            if let Some(session) = request.get("sessionId") {
                reply["sessionId"] = session.clone();
            }
            for event in before {
                if socket.send(Message::Text(event.to_string())).await.is_err() {
                    return;
                }
            }
            if socket.send(Message::Text(reply.to_string())).await.is_err() {
                return;
            }
            for event in after {
                if socket.send(Message::Text(event.to_string())).await.is_err() {
                    return;
                }
            }
        }
    });
    (endpoint, log, server)
}

#[tokio::test]
async fn persistent_closed_page_dispatch_is_negotiated_and_refresh_precedes_results() {
    closed_page_dispatch_for_mode(false).await;
}

#[tokio::test]
async fn isolated_closed_page_dispatch_is_negotiated_and_preserves_context_owner() {
    closed_page_dispatch_for_mode(true).await;
}

async fn closed_page_dispatch_for_mode(isolated: bool) {
    for negotiated in [false, true] {
        let (endpoint, log, peer) = peer_with_mode(false, false, isolated).await;
        let broker = Arc::new(ClientSession::new());
        let browser = Arc::new(ClientBrowser::new(broker.clone()));
        let capabilities = if negotiated {
            vec![if isolated {
                super::super::super::client_protocol::ISOLATED_PAGE_REOPEN.into()
            } else {
                super::super::super::client_protocol::PERSISTENT_PAGE_REOPEN.into()
            }]
        } else {
            vec![if isolated {
                super::super::super::client_protocol::PERSISTENT_PAGE_REOPEN.into()
            } else {
                super::super::super::client_protocol::ISOLATED_PAGE_REOPEN.into()
            }]
        };
        let mut fixture = FramedFixture::with_capabilities(broker, browser.clone(), capabilities);
        let result: Result<(), String> = async {
            fixture.ready().await?;
            let mut args = fixture_scope_open("connect",Some(&endpoint));
            args["context"] = if isolated { "isolated" } else { "persistent" }.into();
            let opened = fixture.command("scope.open",args,5).await?;
            let scope = opened["identityScope"].as_str().unwrap().to_owned();
            fixture.scope = Some(scope.clone());
            fixture.command("scope.configure",fixture_configuration(&scope,None),5).await?;
            fixture.command("network.routes.replace",fixture_routes(&scope),5).await?;
            fixture.registry = 1;
            // Supported provider activation preserves the original ensurePage
            // contract without inventing a cold-title activation requirement.
            fixture.command("page.activate",json!({"identityScope":scope}),5).await?;
            let first = fixture.command("page.title",json!({"identityScope":scope}),5).await?;
            assert_eq!(first["title"],"initial-session");
            let client = browser.owner.lock().await.as_ref().unwrap().manager.client.clone();
            client.send_command("Target.closeTarget",Some(json!({"targetId":"application"})),None).await.unwrap();
            let start = fixture.sequence + 1;
            for seq in start..=start+u64::from(negotiated) {
                fixture.write(json!({"type":"request","id":format!("reopen-{seq}"),"generation":1,"operationSeq":seq,"timeoutMs":5000,"command":"page.activate","args":{"identityScope":scope}})).await?;
                fixture.sequence = seq;
            }
            let mut refresh = None;
            let mut results = 0;
            for _ in 0..32 {
                let frame = tokio::time::timeout(Duration::from_secs(7),fixture.read()).await.map_err(|_|"reopen framed deadline")??;
                if frame["type"] == "event" { fixture.event_sequence = frame["sequence"].as_u64().unwrap(); }
                match frame["type"].as_str() {
                    Some("event") if frame["event"] == "scope.page-reopened" => {
                        assert!(negotiated && refresh.is_none() && results == 0);
                        assert_eq!(frame["generation"],1);
                        assert_eq!(frame["payload"]["version"],1);
                        assert_eq!(frame["payload"]["identityScope"],scope);
                        assert_eq!(frame["payload"]["previousPageIdentity"],opened["recoveryIdentity"]["page"]);
                        assert_eq!(frame["payload"]["recoveryIdentity"]["browser"],opened["recoveryIdentity"]["browser"]);
                        assert_eq!(frame["payload"]["recoveryIdentity"]["context"],opened["recoveryIdentity"]["context"]);
                        assert_ne!(frame["payload"]["recoveryIdentity"]["page"],opened["recoveryIdentity"]["page"]);
                        refresh = Some(frame["payload"]["recoveryIdentity"].clone());
                    }
                    Some("event") => validate_fixture_notice(&frame)?,
                    Some("result") => {
                        if negotiated {
                            assert!(refresh.is_some());
                            assert_eq!(frame["ok"],true);
                            assert_eq!(frame["data"],json!({"activated":true}));
                        } else {
                            assert_eq!(frame["ok"],false);
                            assert_eq!(frame["error"]["code"],"unsupported-capability");
                            assert_eq!(frame["effects"],"not-dispatched");
                        }
                        results += 1;
                        if results == if negotiated {2} else {1} { break; }
                    }
                    _ => return Err("unexpected framed reopen response".into()),
                }
            }
            assert_eq!(results,if negotiated {2} else {1});
            if let Some(identity) = refresh {
                assert_eq!(browser.owner.lock().await.as_ref().unwrap().recovery_identity(),identity);
                assert_eq!(fixture.command("page.title",json!({"identityScope":scope}),5).await?["title"],"replacement-session");
            }
            let commands = log.lock().unwrap().clone();
            assert_eq!(commands.iter().filter(|c| c["method"]=="Target.createTarget").count(),usize::from(negotiated) + usize::from(isolated));
            assert_eq!(commands.iter().filter(|c| c["method"]=="Page.navigate").count(),1);
            assert_eq!(commands.iter().filter(|c| c["method"] == "Target.createBrowserContext").count(), usize::from(isolated));
            assert!(!commands.iter().any(|c| c["method"] == "Target.disposeBrowserContext"));
            let owner = browser.owner.lock().await;
            let owner = owner.as_ref().unwrap();
            assert_eq!(owner.owns_context, isolated);
            assert_eq!(owner.borrowed_targets.is_none(), isolated);
            assert_eq!(owner.context_id, "persistent-context");
            Ok(())
        }.await;
        let cleaned = fixture.finish().await;
        peer.abort();
        result.unwrap();
        cleaned.unwrap();
    }
}

#[tokio::test]
#[ignore = "launches an owned temporary Chromium; execute in the native browser producer lane"]
async fn chromium_persistent_page_close_reopens_without_adopting_another_host_tab() {
    let mut host = super::super::super::browser::BrowserManager::launch(Default::default(), None)
        .await
        .unwrap();
    host.evaluate("document.title = 'original application document'", None)
        .await
        .unwrap();
    let endpoint = host.get_cdp_url().to_owned();
    let broker = Arc::new(ClientSession::new());
    let browser = Arc::new(ClientBrowser::new(broker.clone()));
    let mut fixture = FramedFixture::with_capabilities(
        broker,
        browser.clone(),
        vec![super::super::super::client_protocol::PERSISTENT_PAGE_REOPEN.into()],
    );
    let result: Result<(),String> = async {
        fixture.ready().await?;
        println!("PERSISTENT_REOPEN_PHASE ready");
        let mut args = fixture_scope_open("connect",Some(&endpoint));
        args["context"] = "persistent".into();
        let opened = fixture.command("scope.open",args,10).await?;
        let scope = opened["identityScope"].as_str().unwrap().to_owned();
        fixture.scope = Some(scope.clone());
        fixture.command("scope.configure",fixture_configuration(&scope,None),10).await?;
        fixture.command("network.routes.replace",fixture_routes(&scope),10).await?;
        fixture.registry = 1;
        let activation_client = browser.owner.lock().await.as_ref().unwrap().manager.client.clone();
        activation_client.set_activation_diagnostics_for_test(true);
        let activation = fixture.command("page.activate",json!({"identityScope":scope}),10).await;
        activation_client.set_activation_diagnostics_for_test(false);
        activation?;
        assert_eq!(fixture.command("page.title",json!({"identityScope":scope}),10).await?["title"],"");
        println!("PERSISTENT_REOPEN_PHASE initial-title-complete");
        let (old_target, old_context) = {
            let owner = browser.owner.lock().await;
            let owner = owner.as_ref().unwrap();
            (owner.manager.active_target_id().unwrap().to_owned(),owner.context_id.clone())
        };
        let other = host.client.send_command("Target.createTarget",Some(json!({"url":"about:blank"})),None).await.map_err(|_|"host fixture tab create")?;
        let other = other["targetId"].as_str().unwrap().to_owned();
        assert_ne!(other,old_target);
        let closed = host.client.send_command("Target.closeTarget",Some(json!({"targetId":old_target})),None).await.map_err(|_|"application fixture tab close")?;
        assert_eq!(closed["success"],true);
        println!("PERSISTENT_REOPEN_PHASE original-target-closed");
        fixture.sequence += 1;
        let sequence = fixture.sequence;
        fixture.write(json!({"type":"request","id":"real-reopen","generation":1,"operationSeq":sequence,"timeoutMs":15000,"command":"page.activate","args":{"identityScope":scope}})).await?;
        let mut refreshed = false;
        let mut completed = false;
        for _ in 0..64 {
            let frame = tokio::time::timeout(Duration::from_secs(17),fixture.read()).await.map_err(|_|"real reopen framed deadline")??;
            if frame["type"] == "event" { fixture.event_sequence = frame["sequence"].as_u64().unwrap(); }
            match frame["type"].as_str() {
                Some("event") if frame["event"]=="scope.page-reopened" => {
                    assert!(!refreshed);
                    assert_eq!(frame["payload"]["previousPageIdentity"],opened["recoveryIdentity"]["page"]);
                    assert_eq!(frame["payload"]["recoveryIdentity"]["context"],opened["recoveryIdentity"]["context"]);
                    refreshed = true;
                }
                Some("event") => validate_fixture_notice(&frame)?,
                Some("result") => {
                    assert!(refreshed);
                    assert_eq!(frame["id"],"real-reopen");
                    assert_eq!(frame["ok"],true,"{frame}");
                    assert_eq!(frame["data"],json!({"activated":true}));
                    assert_eq!(frame["scopeState"],"usable");
                    completed = true;
                    break;
                }
                _ => return Err("unexpected real reopen response".into()),
            }
        }
        assert!(completed);
        println!("PERSISTENT_REOPEN_PHASE reopen-result-complete");
        assert_eq!(fixture.command("page.title",json!({"identityScope":scope}),10).await?["title"],"");
        println!("PERSISTENT_REOPEN_PHASE replacement-title-complete");
        let owner = browser.owner.lock().await;
        let owner = owner.as_ref().unwrap();
        assert_eq!(owner.identity_scope,scope);
        assert_eq!(owner.context_id,old_context);
        let replacement = owner.manager.active_target_id().unwrap();
        assert_ne!(replacement,old_target);
        assert_ne!(replacement,other);
        let targets = host.client.send_command_no_params("Target.getTargets",None).await.map_err(|_|"host fixture final inventory")?;
        let targets = targets["targetInfos"].as_array().unwrap();
        assert!(targets.iter().any(|info|info["targetId"]==other));
        assert!(targets.iter().any(|info|info["targetId"]==replacement));
        assert!(!targets.iter().any(|info|info["targetId"]==old_target));
        Ok(())
    }.await;
    let cleaned = fixture.finish().await;
    let host_cleaned = host.close().await;
    result.unwrap();
    cleaned.unwrap();
    host_cleaned.unwrap();
}

include!("client_browser_page_fence_tests.rs");
