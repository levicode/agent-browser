//! Public queued-media obligation through the actual framed transport and
//! ClientBrowser executor. The peer controls native ACKs, never producer state.
//! These are intentional pending regressions until queued admission is repaired.
use super::*;
use crate::native::client_debt::{OperationKey, OwnerDebtLedger};
use crate::native::client_operation_state::OperationRetentionStatus;

const MEDIA: &str = "Emulation.setEmulatedMedia";

async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("actual queued-media fixture stalled")
}

struct Fixture {
    framed: FramedFixture,
    browser: Arc<ClientBrowser>,
    scope: String,
    ledger: Arc<OwnerDebtLedger>,
    media: tokio::sync::mpsc::UnboundedReceiver<Value>,
    replies: tokio::sync::mpsc::UnboundedSender<Value>,
    log: Arc<Mutex<Vec<Value>>>,
    peer: tokio::task::JoinHandle<()>,
}
impl Fixture {
    async fn new() -> Self {
        let (seen, media) = tokio::sync::mpsc::unbounded_channel();
        let (replies, incoming) = tokio::sync::mpsc::unbounded_channel();
        let (endpoint, log, peer) = peer_with_media_replies(
            false,
            None,
            false,
            None,
            None,
            Some(incoming),
            false,
            Some(seen),
        )
        .await;
        let broker = Arc::new(ClientSession::new());
        let browser = Arc::new(ClientBrowser::new(broker.clone()));
        let mut framed = framed(browser.clone(), broker, Arc::new(RestartFlush::default()));
        framed.ready().await.unwrap();
        let opened = framed
            .command(
                "scope.open",
                fixture_scope_open("connect", Some(&endpoint)),
                5,
            )
            .await
            .unwrap();
        let scope = opened["identityScope"].as_str().unwrap().to_owned();
        framed.scope = Some(scope.clone());
        framed
            .command("scope.configure", fixture_configuration(&scope, None), 5)
            .await
            .unwrap();
        framed
            .command("network.routes.replace", fixture_routes(&scope), 5)
            .await
            .unwrap();
        framed.registry = 1;
        framed
            .command("page.activate", json!({"identityScope":scope}), 5)
            .await
            .unwrap();
        let page = browser.page_lease(false).await.unwrap();
        let ledger = page.client.debt_ledger().unwrap();
        drop(page);
        Self {
            framed,
            browser,
            scope,
            ledger,
            media,
            replies,
            log,
            peer,
        }
    }

    async fn send(&mut self, update: Value) -> OperationKey {
        self.send_with_budget(update, 5000).await
    }

    async fn send_with_budget(&mut self, update: Value, timeout_ms: u64) -> OperationKey {
        self.send_command("context.media", update, timeout_ms).await
    }

    async fn send_command(
        &mut self,
        command: &str,
        update: Value,
        timeout_ms: u64,
    ) -> OperationKey {
        self.framed.sequence += 1;
        let key = OperationKey {
            generation: 1,
            operation_seq: self.framed.sequence,
        };
        let mut args = update.as_object().unwrap().clone();
        args.insert("identityScope".into(), json!(self.scope));
        self.framed
            .write(
                json!({"type":"request", "id":format!("media-{}",key.operation_seq),
            "generation":1, "operationSeq":key.operation_seq, "timeoutMs":timeout_ms,
            "command":command, "args":args}),
            )
            .await
            .unwrap();
        key
    }

    async fn queue_second(&mut self, timeout_ms: u64) -> OperationKey {
        let key = OperationKey {
            generation: 1,
            operation_seq: self.framed.sequence + 1,
        };
        let (reached, mut waiting) = tokio::sync::oneshot::channel();
        *self.browser.generic_admission_probe.lock().unwrap() =
            Some(GenericAdmissionProbe { key, reached });
        assert_eq!(
            self.send_with_budget(json!({"reducedMotion":"reduce"}), timeout_ms)
                .await,
            key
        );
        // This exact-key notification means the genuine config guard future
        // returned Pending. A sleep, manually held lock or fabricated queued
        // flag cannot satisfy it. Current pre-lock admission returns an error
        // instead, which this branch reports immediately as the product gap.
        bounded(async {
            loop {
                tokio::select! {
                    ready = &mut waiting => { ready.expect("queue probe dropped"); break; }
                    frame = self.framed.read() => {
                        let frame = frame.unwrap();
                        assert_eq!(frame["type"], "event", "second media must queue while first ACK is held, not return early: {frame}");
                        self.notice(&frame);
                    }
                }
            }
        }).await;
        assert_eq!(self.ledger.snapshot().input_debt, 1);
        assert!(matches!(
            self.browser.operation_retention_status(key),
            OperationRetentionStatus::KnownActive {
                mutation_dispatched: false
            }
        ));
        assert_eq!(self.media_writes(), 1);
        key
    }

    fn notice(&mut self, frame: &Value) {
        self.framed.event_sequence += 1;
        assert_eq!(frame["sequence"], self.framed.event_sequence);
        assert_eq!(frame["payload"]["identityScope"], self.scope);
        validate_fixture_notice(frame).unwrap();
    }

    async fn pair(&mut self, keys: [OperationKey; 2]) -> [Value; 2] {
        bounded(async {
            let mut results = [None, None];
            for _ in 0..16 {
                let frame = self.framed.read().await.unwrap();
                assert_eq!(frame["generation"], 1);
                match frame["type"].as_str() {
                    Some("event") => self.notice(&frame),
                    Some("result") => {
                        let index = keys
                            .iter()
                            .position(|key| frame["operationSeq"] == key.operation_seq)
                            .expect("unrelated result");
                        assert!(results[index].is_none(), "duplicate media result");
                        assert_eq!(frame["id"], format!("media-{}", keys[index].operation_seq));
                        results[index] = Some(frame);
                    }
                    _ => panic!("unexpected media frame: {frame}"),
                }
                if results.iter().all(Option::is_some) {
                    return results.map(Option::unwrap);
                }
            }
            panic!("bounded media result pair missing")
        })
        .await
    }

    async fn one(&mut self, key: OperationKey, explicit_cancel: bool) -> Value {
        bounded(async {
            let mut result = None;
            let mut cancel_ack = false;
            for _ in 0..16 {
                let frame = self.framed.read().await.unwrap();
                assert_eq!(frame["generation"], 1);
                match frame["type"].as_str() {
                    Some("event") => self.notice(&frame),
                    Some("control-result") => {
                        assert!(explicit_cancel && !cancel_ack);
                        assert_eq!(frame["id"], "cancel-queued-media");
                        assert_eq!(frame["accepted"], true);
                        assert_eq!(frame["scopeState"], "usable");
                        cancel_ack = true;
                    }
                    Some("result") => {
                        assert!(result.is_none());
                        assert_eq!(frame["id"], format!("media-{}", key.operation_seq));
                        assert_eq!(frame["operationSeq"], key.operation_seq);
                        result = Some(frame);
                    }
                    _ => panic!("unexpected queued-media interruption frame: {frame}"),
                }
                if result.is_some() && (!explicit_cancel || cancel_ack) {
                    return result.unwrap();
                }
            }
            panic!("bounded media result/control pair missing")
        })
        .await
    }

    fn ack(&self, request: &Value, accepted: bool) {
        let mut response = json!({"id":request["id"], "sessionId":request["sessionId"]});
        if accepted {
            response["result"] = json!({});
        } else {
            response["error"] = json!({"code":-32000, "message":"synthetic media rejection"});
        }
        self.replies.send(response).unwrap();
    }

    fn media_writes(&self) -> usize {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request["method"] == MEDIA)
            .count()
    }

    async fn finish(self) {
        let cleanup = bounded(self.framed.finish()).await;
        self.peer.abort();
        match self.peer.await {
            Ok(()) => {}
            Err(error) if error.is_cancelled() => {}
            Err(error) => panic!("CDP peer panicked: {error}"),
        }
        cleanup.unwrap();
    }
}

fn features(request: &Value, merged: bool) {
    assert_eq!(request["method"], MEDIA);
    let expected = if merged {
        json!([
            {"name":"prefers-color-scheme", "value":"dark"},
            {"name":"prefers-reduced-motion", "value":"reduce"}
        ])
    } else {
        json!([{"name":"prefers-color-scheme", "value":"dark"}])
    };
    assert_eq!(request["params"]["features"], expected);
}

#[tokio::test]
async fn actual_queued_media_merges_partial_updates_and_new_attachment_inherits_both() {
    let mut f = Fixture::new().await;
    let first_key = f.send(json!({"colorScheme":"dark"})).await;
    let first = bounded(f.media.recv()).await.unwrap();
    features(&first, false);
    assert_eq!(first["sessionId"], "session-1");
    let second_key = f.queue_second(5000).await;
    f.ack(&first, true);
    let second = bounded(f.media.recv()).await.unwrap();
    features(&second, true);
    assert_eq!(second["sessionId"], "session-1");
    f.ack(&second, true);
    for result in f.pair([first_key, second_key]).await {
        assert_eq!(result["ok"], true);
        assert_eq!(result["effects"], "completed");
        assert_eq!(result["scopeState"], "usable");
        assert!(result.get("error").is_none());
    }
    // Use the actual reader and enrollment supervisor. Never manually register
    // this target or copy media state into a replacement test executor.
    f.replies.send(attach("popup", "popup", "page")).unwrap();
    let inherited = bounded(f.media.recv()).await.unwrap();
    features(&inherited, true);
    assert_eq!(inherited["sessionId"], "popup");
    f.ack(&inherited, true);
    let page = f.browser.page_lease(false).await.unwrap();
    bounded(async {
        while !page
            .targets
            .owned_target("popup")
            .is_ok_and(|target| target.capture_ready())
        {
            tokio::task::yield_now().await;
        }
    })
    .await;
    drop(page);
    assert_eq!(f.media_writes(), 3);
    assert_eq!(f.ledger.snapshot().input_debt, 0);
    assert_eq!(f.ledger.snapshot().object_debt, 0);
    assert!(!f.ledger.snapshot().integrity_lost);
    f.finish().await;
}

#[tokio::test]
async fn actual_queued_media_does_not_dispatch_after_predecessor_configuration_failure() {
    let mut f = Fixture::new().await;
    let first_key = f.send(json!({"colorScheme":"dark"})).await;
    let first = bounded(f.media.recv()).await.unwrap();
    features(&first, false);
    let second_key = f.queue_second(5000).await;
    f.ack(&first, false);
    let [first, second] = f.pair([first_key, second_key]).await;
    assert_eq!(first["ok"], false);
    assert_eq!(first["effects"], "unknown");
    assert_eq!(second["ok"], false);
    assert_eq!(second["effects"], "not-dispatched");
    assert_eq!(
        f.media_writes(),
        1,
        "failed predecessor must not permit a replay or second media mutation"
    );
    f.finish().await;
}

async fn queued_interruption_case(explicit_cancel: bool) {
    let mut f = Fixture::new().await;
    let first_key = f.send(json!({"colorScheme":"dark"})).await;
    let first = bounded(f.media.recv()).await.unwrap();
    features(&first, false);
    let second_key = f
        .queue_second(if explicit_cancel { 5000 } else { 1000 })
        .await;
    if explicit_cancel {
        f.framed
            .write(
                json!({"type":"cancel", "id":"cancel-queued-media", "generation":1,
            "operationSeq":second_key.operation_seq}),
            )
            .await
            .unwrap();
    }
    let interrupted = f.one(second_key, explicit_cancel).await;
    assert_eq!(interrupted["ok"], false);
    assert_eq!(
        interrupted["error"]["code"],
        if explicit_cancel {
            "cancelled"
        } else {
            "deadline-exceeded"
        }
    );
    assert_eq!(interrupted["effects"], "not-dispatched");
    assert_eq!(interrupted["scopeState"], "usable");
    assert_eq!(f.media_writes(), 1);
    assert_eq!(
        f.ledger.snapshot().input_debt,
        1,
        "queued interruption must not forgive its predecessor's unacknowledged mutation"
    );
    f.ack(&first, true);
    let completed = f.one(first_key, false).await;
    assert_eq!(completed["ok"], true);
    assert_eq!(completed["effects"], "completed");
    // Empty update exposes the committed media without adding either field.
    // The cancelled/timed-out queued reducedMotion must never have merged early.
    let probe_key = f.send(json!({})).await;
    let probe = bounded(f.media.recv()).await.unwrap();
    features(&probe, false);
    f.ack(&probe, true);
    let completed = f.one(probe_key, false).await;
    assert_eq!(completed["ok"], true);
    assert_eq!(completed["effects"], "completed");
    assert_eq!(f.media_writes(), 2);
    assert_eq!(f.ledger.snapshot().input_debt, 0);
    assert!(!f.ledger.snapshot().integrity_lost);
    f.finish().await;
}

#[tokio::test]
async fn actual_queued_media_cancel_does_not_merge_or_clear_predecessor_debt() {
    queued_interruption_case(true).await;
}

#[tokio::test]
async fn actual_queued_media_deadline_does_not_merge_or_clear_predecessor_debt() {
    queued_interruption_case(false).await;
}

#[tokio::test]
async fn actual_media_refuses_unresolved_navigation_without_waiting_or_dispatching() {
    let mut f = Fixture::new().await;
    let navigation_key = f
        .send_command(
            "page.navigate",
            json!({
                "url":"https://synthetic.test/held-non-media", "waitUntil":"load"
            }),
            5000,
        )
        .await;
    let navigation = bounded(f.media.recv()).await.unwrap();
    assert_eq!(navigation["method"], "Page.navigate");
    assert_eq!(navigation["sessionId"], "session-1");
    assert_eq!(f.ledger.snapshot().input_debt, 1);
    assert!(matches!(
        f.browser.operation_retention_status(navigation_key),
        OperationRetentionStatus::KnownActive {
            mutation_dispatched: true
        }
    ));
    let media_key = f.send(json!({"colorScheme":"dark"})).await;
    // The predecessor is still genuinely unresolved. A successful response or
    // a wait-until-timeout cannot satisfy this precise immediate refusal code.
    let refused = f.one(media_key, false).await;
    assert_eq!(refused["ok"], false);
    assert_eq!(refused["error"]["code"], "scope-unavailable");
    assert_eq!(refused["effects"], "not-dispatched");
    assert_eq!(refused["scopeState"], "usable");
    assert_eq!(f.media_writes(), 0);
    assert_eq!(f.ledger.snapshot().input_debt, 1);
    assert!(matches!(
        f.browser.operation_retention_status(navigation_key),
        OperationRetentionStatus::KnownActive {
            mutation_dispatched: true
        }
    ));
    // Only now does the actual peer acknowledge and complete the original
    // navigation; no test mutates a journal or marks a producer as finished.
    f.replies
        .send(json!({"id":navigation["id"], "sessionId":"session-1",
        "result":{"frameId":"frame-session-1", "loaderId":"held-nav-loader"}}))
        .unwrap();
    f.replies.send(json!({"method":"Page.frameNavigated", "sessionId":"session-1", "params":{
        "frame":{"id":"frame-session-1", "loaderId":"held-nav-loader",
        "url":"https://synthetic.test/held-non-media", "securityOrigin":"https://synthetic.test"}}})).unwrap();
    f.replies
        .send(
            json!({"method":"Page.lifecycleEvent", "sessionId":"session-1", "params":{
        "frameId":"frame-session-1", "loaderId":"held-nav-loader", "name":"load"}}),
        )
        .unwrap();
    let completed = f.one(navigation_key, false).await;
    assert_eq!(completed["ok"], true);
    assert_eq!(completed["effects"], "completed");
    let fresh_key = f.send(json!({"colorScheme":"dark"})).await;
    let fresh = bounded(f.media.recv()).await.unwrap();
    features(&fresh, false);
    f.ack(&fresh, true);
    let completed = f.one(fresh_key, false).await;
    assert_eq!(completed["ok"], true);
    assert_eq!(completed["effects"], "completed");
    assert_eq!(f.media_writes(), 1);
    assert_eq!(f.ledger.snapshot().input_debt, 0);
    assert!(!f.ledger.snapshot().integrity_lost);
    f.finish().await;
}
