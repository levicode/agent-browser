// Exact navigation fencing through real framed dispatch and native leases.
// Only the CDP peer is scripted; no target/owner/publication state is seeded.

struct PageFenceFixture {
    wire: FramedFixture,
    browser: Arc<ClientBrowser>,
    scope: String,
    log: Arc<Mutex<Vec<Value>>>,
    peer: tokio::task::JoinHandle<()>,
}
impl PageFenceFixture {
    async fn open(close_during_navigation: bool) -> Result<Self, String> {
        let (endpoint, log, peer) = peer_with_navigation(true, close_during_navigation).await;
        let broker = Arc::new(ClientSession::new());
        let browser = Arc::new(ClientBrowser::new(broker.clone()));
        let mut wire = FramedFixture::with_capabilities(
            broker,
            browser.clone(),
            vec![
                crate::native::client_protocol::PERSISTENT_PAGE_REOPEN.into(),
                crate::native::client_protocol::PAGE_IDENTITY_FENCE.into(),
            ],
        );
        let setup: Result<String, String> = async {
            wire.ready().await?;
            let mut args = fixture_scope_open("connect", Some(&endpoint));
            args["context"] = "persistent".into();
            let opened = wire.command("scope.open", args, 5).await?;
            let scope = opened["identityScope"]
                .as_str()
                .ok_or("fence setup scope")?
                .to_owned();
            wire.scope = Some(scope.clone());
            wire.command("scope.configure", fixture_configuration(&scope, None), 5)
                .await?;
            wire.command("network.routes.replace", fixture_routes(&scope), 5)
                .await?;
            wire.registry = 1;
            wire.command("page.activate", json!({"identityScope":scope}), 5)
                .await?;
            Ok(scope)
        }
        .await;
        match setup {
            Ok(scope) => Ok(Self {
                wire,
                browser,
                scope,
                log,
                peer,
            }),
            Err(error) => {
                let cleanup = wire.finish().await;
                peer.abort();
                let _ = peer.await;
                Err(format!("fence setup={error}; cleanup={cleanup:?}"))
            }
        }
    }
    fn args(&self, target: &str) -> Value {
        json!({"identityScope":self.scope,"url":"about:blank","waitUntil":"domcontentloaded",
            "expectedPage":{"contextId":"persistent-context","targetId":target}})
    }
    async fn send(&mut self, command: &str, args: Value) -> Result<u64, String> {
        self.wire.sequence += 1;
        let seq = self.wire.sequence;
        self.wire
            .write(
                json!({"type":"request","id":format!("fence-{seq}"),"generation":1,
            "operationSeq":seq,"timeoutMs":5000,"command":command,"args":args}),
            )
            .await?;
        Ok(seq)
    }
    async fn receive(
        &mut self,
        seq: u64,
        allow_reopen: bool,
    ) -> Result<(Value, Option<Value>), String> {
        let mut reopened = None;
        for _ in 0..64 {
            let frame = tokio::time::timeout(Duration::from_secs(7), self.wire.read())
                .await
                .map_err(|_| "fence result timeout")??;
            if frame["generation"] != 1 {
                return Err("fence generation changed".into());
            }
            match frame["type"].as_str() {
                Some("event") => {
                    if frame["sequence"] != self.wire.event_sequence + 1 {
                        return Err("fence event sequence changed".into());
                    }
                    self.wire.event_sequence += 1;
                    if frame["event"] == "scope.page-reopened" {
                        if !allow_reopen
                            || reopened.is_some()
                            || frame["payload"]["identityScope"] != self.scope
                            || frame["payload"]["version"] != 1
                            || frame.get("decision").is_some()
                        {
                            return Err(
                                "fenced navigation silently reopened or changed owner".into()
                            );
                        }
                        reopened = Some(frame["payload"].clone());
                    } else {
                        validate_fixture_notice(&frame)?;
                        if frame["payload"]["identityScope"] != self.scope {
                            return Err("fence notice changed owner".into());
                        }
                    }
                }
                Some("result") => {
                    if frame["id"] != format!("fence-{seq}") || frame["operationSeq"] != seq {
                        return Err("fence result correlation changed".into());
                    }
                    return Ok((frame, reopened));
                }
                _ => return Err("unexpected fenced navigation wire frame".into()),
            }
        }
        Err("fence frame bound exceeded".into())
    }
    async fn navigate(&mut self, args: Value) -> Result<Value, String> {
        let seq = self.send("page.navigate", args).await?;
        Ok(self.receive(seq, false).await?.0)
    }
    fn count(&self, method: &str) -> usize {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["method"] == method)
            .count()
    }
    async fn close_application(&self) -> Result<(), String> {
        let (client, targets) = {
            let owner = self.browser.owner.lock().await;
            let owner = owner
                .as_ref()
                .ok_or("fence owner vanished before peer close")?;
            (owner.manager.client.clone(), owner.targets.clone())
        };
        let closed = client
            .send_command(
                "Target.closeTarget",
                Some(json!({"targetId":"application"})),
                None,
            )
            .await
            .map_err(|_| "actual peer close failed")?;
        if closed != json!({"success":true}) {
            return Err("actual close ACK missing".into());
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while targets.owned_target("application").is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| "actual detached event did not retire target")?;
        Ok(())
    }
    async fn finish(self) -> Result<(), String> {
        let cleanup = self.wire.finish().await;
        self.peer.abort();
        let peer = self.peer.await;
        if peer
            .as_ref()
            .err()
            .is_some_and(|error| !error.is_cancelled())
        {
            return Err(format!("fence peer failed; cleanup={cleanup:?}"));
        }
        cleanup
    }
}
fn fence_refused(frame: &Value, code: &str) -> Result<(), String> {
    if frame["ok"] != false
        || frame["effects"] != "not-dispatched"
        || frame["scopeState"] != "usable"
        || frame["error"]["code"] != code
        || frame.get("retention").is_some()
        || frame.get("recovery").is_some()
    {
        return Err(format!("fence refusal contract mismatch: expected={code}; ok={}; effects={}; state={}; code={}",
        frame["ok"],frame["effects"],frame["scopeState"],frame["error"]["code"]));
    }
    Ok(())
}
fn fence_completed(frame: &Value) -> Result<(), String> {
    if frame["ok"] != true
        || frame["effects"] != "completed"
        || frame["scopeState"] != "usable"
        || frame.get("error").is_some()
        || frame.get("retention").is_some()
        || frame.get("recovery").is_some()
    {
        return Err("exact fenced navigation did not complete".into());
    }
    Ok(())
}

#[tokio::test]
async fn navigation_page_fence_rejects_malformed_foreign_and_other_owner_before_dispatch() {
    let mut first = PageFenceFixture::open(false).await.unwrap();
    let second = PageFenceFixture::open(false).await.unwrap();
    let proof: Result<(), String> = async {
        let initial_navigation = first.count("Page.navigate");
        // Compare two genuinely admitted native owners, not authored target
        // registries. Identical peer strings cannot make their leases fungible.
        let page = first
            .browser
            .page_lease(false)
            .await
            .map_err(|_| "capture actual fence lease")?;
        let mut identity_args = json!({"url":"about:blank","waitUntil":"domcontentloaded",
            "expectedPage":{"contextId":"persistent-context","targetId":"application"}})
        .as_object()
        .unwrap()
        .clone();
        let expected = ExpectedNavigationPage::take(&mut identity_args)
            .map_err(|_| "decode actual fence")?
            .ok_or("actual fence missing")?;
        {
            let owner = first.browser.owner.lock().await;
            if !expected.matches(owner.as_ref().ok_or("first owner missing")?, &page) {
                return Err("actual matching owner lease refused".into());
            }
        }
        {
            let owner = second.browser.owner.lock().await;
            let owner = owner.as_ref().ok_or("second owner missing")?;
            if Arc::ptr_eq(&owner.targets, &page.targets) || expected.matches(owner, &page) {
                return Err("foreign actual owner authorized the captured lease".into());
            }
        }
        drop(page);
        for value in [
            Value::Null,
            json!(7),
            json!({}),
            json!({"contextId":"persistent-context","targetId":false}),
            json!({"contextId":"persistent-context","targetId":"application","extra":true}),
            json!({"contextId":"","targetId":"application"}),
            json!({"contextId":"persistent-context","targetId":"bad\nidentity"}),
            json!({"contextId":"persistent-context","targetId":"x".repeat(257)}),
        ] {
            let mut args = first.args("application");
            args["expectedPage"] = value;
            fence_refused(&first.navigate(args).await?, "invalid-arguments")?;
        }
        let mut extra_navigation = first.args("application");
        extra_navigation["extra"] = true.into();
        fence_refused(
            &first.navigate(extra_navigation).await?,
            "invalid-arguments",
        )?;
        for expected in [
            json!({"contextId":"foreign-context","targetId":"application"}),
            json!({"contextId":"persistent-context","targetId":"unrelated-host"}),
            json!({"contextId":"foreign-context","targetId":"foreign-host"}),
        ] {
            let mut args = first.args("application");
            args["expectedPage"] = expected;
            fence_refused(&first.navigate(args).await?, "stale-scope")?;
        }
        // Both peers deliberately have identical raw context/target strings.
        // A real different native owner/scope must still not authorize dispatch.
        if first.scope == second.scope {
            return Err("independent native owners unexpectedly alias".into());
        }
        let mut wrong_owner = first.args("application");
        wrong_owner["identityScope"] = json!(second.scope);
        fence_refused(&first.navigate(wrong_owner).await?, "stale-scope")?;
        if first.count("Page.navigate") != initial_navigation
            || first.count("Target.createTarget") != 0
            || second.count("Page.navigate") != 1
            || second.count("Target.createTarget") != 0
        {
            return Err("rejected fence acquired, navigated or retargeted a page".into());
        }
        let valid = first.args("application");
        fence_completed(&first.navigate(valid).await?)?;
        if first.count("Page.navigate") != initial_navigation + 1
            || first.count("Target.createTarget") != 0
        {
            return Err(
                "correct exact fence did not dispatch exactly once without allocation".into(),
            );
        }
        Ok(())
    }
    .await;
    let clean_first = first.finish().await;
    let clean_second = second.finish().await;
    assert!(
        proof.is_ok() && clean_first.is_ok() && clean_second.is_ok(),
        "proof={proof:?}; firstCleanup={clean_first:?}; secondCleanup={clean_second:?}"
    );
}

#[tokio::test]
async fn navigation_page_fence_closed_after_activation_never_silently_retargets() {
    let mut fixture = PageFenceFixture::open(false).await.unwrap();
    let proof: Result<(), String> = async {
        fixture.close_application().await?;
        // Explicit null must not be treated as absent and reopen a closed page.
        let mut malformed = fixture.args("application");
        malformed["expectedPage"] = Value::Null;
        fence_refused(&fixture.navigate(malformed).await?, "invalid-arguments")?;
        let args = fixture.args("application");
        fence_refused(&fixture.navigate(args).await?, "stale-reference")?;
        if fixture.count("Page.navigate") != 1 || fixture.count("Target.createTarget") != 0 {
            return Err("closed fenced page silently ensured or navigated another page".into());
        }
        // Legacy native callers omitting the fence still automatically ensure
        // then navigate. This empty-route peer does not claim routed E2E proof.
        let seq = fixture
            .send(
                "page.navigate",
                json!({"identityScope":fixture.scope,
            "url":"about:blank","waitUntil":"domcontentloaded"}),
            )
            .await?;
        let (navigated, refresh) = fixture.receive(seq, true).await?;
        fence_completed(&navigated)?;
        if refresh.is_none()
            || fixture.count("Target.createTarget") != 1
            || fixture.count("Page.navigate") != 2
        {
            return Err("unfenced native ensure-then-navigate regressed".into());
        }
        let old = fixture.args("application");
        fence_refused(&fixture.navigate(old).await?, "stale-scope")?;
        let fresh = fixture.args("replacement");
        fence_completed(&fixture.navigate(fresh).await?)?;
        let log = fixture.log.lock().unwrap();
        let navigations = log
            .iter()
            .filter(|r| r["method"] == "Page.navigate")
            .collect::<Vec<_>>();
        if navigations.len() != 3
            || navigations[1]["sessionId"] != "replacement-session"
            || navigations[2]["sessionId"] != "replacement-session"
        {
            return Err("fence did not bind the newly acknowledged exact replacement".into());
        }
        if log.iter().any(|r| {
            matches!(
                r["method"].as_str(),
                Some("Target.createBrowserContext" | "Target.disposeBrowserContext")
            )
        }) {
            return Err("persistent fence touched browser context ownership".into());
        }
        Ok(())
    }
    .await;
    let cleanup = fixture.finish().await;
    assert!(
        proof.is_ok() && cleanup.is_ok(),
        "proof={proof:?}; cleanup={cleanup:?}"
    );
}

#[tokio::test]
async fn navigation_page_fence_rechecks_real_target_after_captured_lease_wait() {
    let mut fixture = PageFenceFixture::open(false).await.unwrap();
    let proof: Result<(), String> = async {
        let ui = fixture
            .browser
            .owner
            .lock()
            .await
            .as_ref()
            .ok_or("fence owner missing")?
            .ui
            .clone();
        let (_cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let held = ui
            .enter(
                true,
                false,
                Instant::now() + Duration::from_secs(5),
                cancellation,
            )
            .await
            .map_err(|_| "hold real UI gate")?;
        let args = fixture.args("application");
        let seq = fixture.send("page.navigate", args).await?;
        let key = crate::native::client_debt::OperationKey {
            generation: 1,
            operation_seq: seq,
        };
        // Registration follows page_lease, exact owner/fence and owned-target
        // capture. The actual UI permit prevents dispatch, not those checks.
        let journal = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some((journal, fixed)) =
                    fixture.browser.tasks.operation_journal_result_for_test(key)
                {
                    if fixed {
                        return Err("fenced operation completed before UI release");
                    }
                    return Ok(journal);
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| "fenced operation never captured a real lease")??;
        if journal.snapshot().mutation_dispatched || fixture.count("Page.navigate") != 1 {
            return Err("fenced operation dispatched through held UI gate".into());
        }
        fixture.close_application().await?;
        drop(held);
        let (refused, _) = fixture.receive(seq, false).await?;
        fence_refused(&refused, "stale-reference")?;
        if journal.snapshot().mutation_dispatched
            || fixture.count("Page.navigate") != 1
            || fixture.count("Target.createTarget") != 0
        {
            return Err("captured fence revived after actual close while queued".into());
        }
        Ok(())
    }
    .await;
    let cleanup = fixture.finish().await;
    assert!(
        proof.is_ok() && cleanup.is_ok(),
        "proof={proof:?}; cleanup={cleanup:?}"
    );
}

#[tokio::test]
async fn navigation_page_fence_does_not_relabel_close_after_dispatch_as_not_dispatched() {
    let mut fixture = PageFenceFixture::open(true).await.unwrap();
    let proof: Result<(), String> = async {
        let args = fixture.args("application");
        let frame = fixture.navigate(args).await?;
        if frame["ok"] != false
            || frame["effects"] != "unknown"
            || frame["scopeState"] != "quarantined"
            || frame["error"]["code"] != "browser-failure"
            || frame.get("recovery").is_some()
        {
            return Err(
                "actual dispatched navigation closure lost original Unknown classification".into(),
            );
        }
        if fixture.count("Page.navigate") != 2 || fixture.count("Target.createTarget") != 0 {
            return Err("dispatched fenced navigation was replayed or silently ensured".into());
        }
        Ok(())
    }
    .await;
    let cleanup = fixture.finish().await;
    assert!(
        proof.is_ok() && cleanup.is_ok(),
        "proof={proof:?}; cleanup={cleanup:?}"
    );
}
