// Exercise the real bounded CDP reader, enrollment owner and 500ms waiter.
// No terminal network event is fabricated for a retired document's requests.
async fn document_idle_request(
    owner: &Arc<ClientEnrollment>,
    emit: &tokio::sync::mpsc::Sender<Value>,
    id: &str,
    frame: Value,
    loader: Value,
) {
    realm_emit(
        owner,
        emit,
        json!({
            "method":"Network.requestWillBeSent", "sessionId":"initial",
            "params":{"requestId":id, "frameId":frame, "loaderId":loader,
            "type":"Fetch", "request":{"url":"https://synthetic.test/pending", "method":"GET"}}
        }),
    )
    .await;
}

async fn document_idle_finish(
    owner: &Arc<ClientEnrollment>,
    emit: &tokio::sync::mpsc::Sender<Value>,
    id: &str,
) {
    realm_emit(
        owner,
        emit,
        json!({
            "method":"Network.loadingFinished", "sessionId":"initial",
            "params":{"requestId":id}
        }),
    )
    .await;
}

async fn document_idle_commit(
    owner: &Arc<ClientEnrollment>,
    emit: &tokio::sync::mpsc::Sender<Value>,
    mut frame: Value,
) {
    frame["url"] = json!("https://synthetic.test/current");
    realm_emit(
        owner,
        emit,
        json!({
            "method":"Page.frameNavigated", "sessionId":"initial",
            "params":{"frame":frame}
        }),
    )
    .await;
}

async fn document_idle_wait(
    owner: &Arc<ClientEnrollment>,
    page: &BrowserExecutionLease,
    budget: Duration,
) -> Result<(), ProtocolError> {
    let mut op = owner.operation();
    op.deadline = Instant::now() + budget;
    owner.page.wait_network_idle(page, &op).await
}

async fn document_idle_blocked(owner: &Arc<ClientEnrollment>, page: &BrowserExecutionLease) {
    assert_eq!(
        document_idle_wait(owner, page, Duration::from_millis(650)).await,
        Err(ProtocolError::DeadlineExceeded),
        "a request without proven document/frame retirement must keep the real waiter pending"
    );
}

#[tokio::test]
async fn networkidle_document_commit_retires_only_proven_old_loader_and_late_events() {
    let (owner, page, _notices, emit, server) = realm_test_owner().await;
    // Enrollment's real Page.getFrameTree ACK, not this request, establishes
    // synthetic-loader as the current document of frame-initial.
    document_idle_request(
        &owner,
        &emit,
        "old-pending",
        json!("frame-initial"),
        json!("synthetic-loader"),
    )
    .await;
    document_idle_request(
        &owner,
        &emit,
        "next-pending",
        json!("frame-initial"),
        json!("next-loader"),
    )
    .await;
    document_idle_blocked(&owner, &page).await;
    document_idle_commit(
        &owner,
        &emit,
        json!({"id":"frame-initial","loaderId":"next-loader"}),
    )
    .await;
    // A request started before its own commit is still part of the new document.
    document_idle_blocked(&owner, &page).await;
    document_idle_finish(&owner, &emit, "next-pending").await;
    let started = Instant::now();
    let result = document_idle_wait(&owner, &page, Duration::from_millis(1500)).await;
    assert_eq!(
        result,
        Ok(()),
        "the old document still has an unfinished request after the exact new-document commit"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(450),
        "retirement must preserve the 500ms quiet window"
    );
    document_idle_request(
        &owner,
        &emit,
        "late-old-pending",
        json!("frame-initial"),
        json!("synthetic-loader"),
    )
    .await;
    assert_eq!(
        document_idle_wait(&owner, &page, Duration::from_millis(80)).await,
        Ok(()),
        "late events for the proven retired loader must not restart the quiet window"
    );
    // A loader that was never current is a possible future navigation, not an
    // old request merely because it differs from the current loader.
    document_idle_request(
        &owner,
        &emit,
        "future-pending",
        json!("frame-initial"),
        json!("future-loader"),
    )
    .await;
    document_idle_blocked(&owner, &page).await;
    drop(page);
    owner.close().await.unwrap();
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn networkidle_document_same_document_and_missing_identity_remain_counted() {
    let (owner, page, _notices, emit, server) = realm_test_owner().await;
    document_idle_request(
        &owner,
        &emit,
        "same-document",
        json!("frame-initial"),
        json!("synthetic-loader"),
    )
    .await;
    realm_emit(&owner, &emit, json!({"method":"Page.navigatedWithinDocument", "sessionId":"initial", "params":{"frameId":"frame-initial", "url":"https://synthetic.test/#hash"}})).await;
    document_idle_blocked(&owner, &page).await;
    // Missing/malformed commit loader cannot establish document replacement.
    for loader in [Value::Null, json!(""), json!(5)] {
        document_idle_commit(
            &owner,
            &emit,
            json!({"id":"frame-initial", "loaderId":loader}),
        )
        .await;
        document_idle_blocked(&owner, &page).await;
    }
    document_idle_finish(&owner, &emit, "same-document").await;
    for (ordinal, frame, loader) in [
        (0, Value::Null, json!("synthetic-loader")),
        (1, json!("frame-initial"), Value::Null),
        (2, json!("frame-initial"), json!("")),
        (3, json!("frame-initial"), json!(5)),
        (4, json!(""), json!("synthetic-loader")),
        (5, json!(5), json!("synthetic-loader")),
    ] {
        document_idle_request(&owner, &emit, &format!("unknown-{ordinal}"), frame, loader).await;
    }
    document_idle_commit(
        &owner,
        &emit,
        json!({"id":"frame-initial","loaderId":"next-loader"}),
    )
    .await;
    for ordinal in 0..6 {
        document_idle_blocked(&owner, &page).await;
        document_idle_finish(&owner, &emit, &format!("unknown-{ordinal}")).await;
    }
    assert_eq!(
        document_idle_wait(&owner, &page, Duration::from_millis(1500)).await,
        Ok(())
    );
    for (ordinal, reason) in [Value::Null, json!("unknown"), json!(5)]
        .into_iter()
        .enumerate()
    {
        let frame = format!("uncertain-detach-{ordinal}");
        document_idle_commit(
            &owner,
            &emit,
            json!({"id":frame, "parentId":"frame-initial", "loaderId":"known-loader"}),
        )
        .await;
        document_idle_request(&owner, &emit, &frame, json!(frame), json!("known-loader")).await;
        realm_emit(&owner, &emit, json!({"method":"Page.frameDetached", "sessionId":"initial", "params":{"frameId":frame, "reason":reason}})).await;
        document_idle_blocked(&owner, &page).await;
        document_idle_finish(&owner, &emit, &frame).await;
    }
    // The request cannot seed an authoritative old/current loader by itself.
    document_idle_request(
        &owner,
        &emit,
        "unseeded-old",
        json!("unseeded-frame"),
        json!("request-only-loader"),
    )
    .await;
    document_idle_commit(
        &owner,
        &emit,
        json!({"id":"unseeded-frame","parentId":"frame-initial","loaderId":"first-proven-loader"}),
    )
    .await;
    document_idle_blocked(&owner, &page).await;
    drop(page);
    owner.close().await.unwrap();
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn networkidle_document_bfcache_commit_reactivates_current_loader_requests() {
    let (owner, page, _notices, emit, server) = realm_test_owner().await;
    document_idle_request(
        &owner,
        &emit,
        "old-pending",
        json!("frame-initial"),
        json!("synthetic-loader"),
    )
    .await;
    document_idle_commit(
        &owner,
        &emit,
        json!({"id":"frame-initial", "loaderId":"next-loader"}),
    )
    .await;
    assert_eq!(
        document_idle_wait(&owner, &page, Duration::from_millis(1500)).await,
        Ok(())
    );
    realm_emit(&owner, &emit, json!({"method":"Page.frameNavigated", "sessionId":"initial", "params":{"frame":{"id":"frame-initial", "loaderId":"synthetic-loader", "url":"https://synthetic.test/restored"}, "type":"BackForwardCacheRestore"}})).await;
    document_idle_blocked(&owner, &page).await;
    document_idle_finish(&owner, &emit, "old-pending").await;
    assert_eq!(
        document_idle_wait(&owner, &page, Duration::from_millis(1500)).await,
        Ok(())
    );
    document_idle_request(
        &owner,
        &emit,
        "current-restored",
        json!("frame-initial"),
        json!("synthetic-loader"),
    )
    .await;
    document_idle_blocked(&owner, &page).await;
    document_idle_finish(&owner, &emit, "current-restored").await;
    assert_eq!(
        document_idle_wait(&owner, &page, Duration::from_millis(1500)).await,
        Ok(())
    );
    document_idle_request(
        &owner,
        &emit,
        "late-replaced",
        json!("frame-initial"),
        json!("next-loader"),
    )
    .await;
    assert_eq!(
        document_idle_wait(&owner, &page, Duration::from_millis(80)).await,
        Ok(())
    );
    drop(page);
    owner.close().await.unwrap();
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn networkidle_document_detach_and_swap_keep_unfinished_requests_counted() {
    let (owner, page, _notices, emit, server) = realm_test_owner().await;
    owner
        .enroll_existing("popup-target", "popup", "page", &owner.operation())
        .await
        .unwrap();
    for (frame, parent) in [
        ("child-frame", "frame-initial"),
        ("grandchild-frame", "child-frame"),
    ] {
        document_idle_commit(
            &owner,
            &emit,
            json!({"id":frame, "parentId":parent, "loaderId":"child-loader"}),
        )
        .await;
        document_idle_request(&owner, &emit, frame, json!(frame), json!("child-loader")).await;
    }
    document_idle_request(
        &owner,
        &emit,
        "root-pending",
        json!("frame-initial"),
        json!("synthetic-loader"),
    )
    .await;
    // The popup owns its own root. Its event cannot detach initial's frame.
    realm_emit(&owner, &emit, json!({"method":"Page.frameDetached", "sessionId":"popup", "params":{"frameId":"child-frame", "reason":"remove"}})).await;
    document_idle_finish(&owner, &emit, "root-pending").await;
    document_idle_blocked(&owner, &page).await;
    document_idle_request(
        &owner,
        &emit,
        "root-pending-2",
        json!("frame-initial"),
        json!("synthetic-loader"),
    )
    .await;
    realm_emit(&owner, &emit, json!({"method":"Page.frameDetached", "sessionId":"initial", "params":{"frameId":"child-frame", "reason":"remove"}})).await;
    document_idle_blocked(&owner, &page).await;
    document_idle_finish(&owner, &emit, "root-pending-2").await;
    // Detach is deliberately conservative. The earlier failing expected-Ok
    // contract is preserved separately as evidence, not claimed as repaired.
    document_idle_blocked(&owner, &page).await;
    document_idle_request(
        &owner,
        &emit,
        "late-detached",
        json!("child-frame"),
        Value::Null,
    )
    .await;
    document_idle_blocked(&owner, &page).await;
    for id in ["child-frame", "grandchild-frame", "late-detached"] {
        document_idle_finish(&owner, &emit, id).await;
    }
    assert_eq!(
        document_idle_wait(&owner, &page, Duration::from_millis(1500)).await,
        Ok(())
    );
    document_idle_commit(
        &owner,
        &emit,
        json!({"id":"swap-frame", "parentId":"frame-initial", "loaderId":"swap-loader"}),
    )
    .await;
    document_idle_request(
        &owner,
        &emit,
        "swap-pending",
        json!("swap-frame"),
        json!("swap-loader"),
    )
    .await;
    realm_emit(&owner, &emit, json!({"method":"Page.frameDetached", "sessionId":"initial", "params":{"frameId":"swap-frame", "reason":"swap"}})).await;
    document_idle_blocked(&owner, &page).await;
    document_idle_finish(&owner, &emit, "swap-pending").await;
    assert_eq!(
        document_idle_wait(&owner, &page, Duration::from_millis(1500)).await,
        Ok(())
    );
    drop(page);
    owner.close().await.unwrap();
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn networkidle_document_reattach_counts_new_unknown_and_reused_loader_before_commit() {
    let (owner, page, _notices, emit, server) = realm_test_owner().await;
    owner
        .enroll_existing("popup-target", "popup", "page", &owner.operation())
        .await
        .unwrap();
    document_idle_commit(
        &owner,
        &emit,
        json!({"id":"child-frame", "parentId":"frame-initial", "loaderId":"old-child"}),
    )
    .await;
    document_idle_request(
        &owner,
        &emit,
        "old-pending",
        json!("child-frame"),
        json!("old-child"),
    )
    .await;
    document_idle_commit(
        &owner,
        &emit,
        json!({"id":"child-frame", "parentId":"frame-initial", "loaderId":"next-child"}),
    )
    .await;
    assert_eq!(
        document_idle_wait(&owner, &page, Duration::from_millis(1500)).await,
        Ok(())
    );
    realm_emit(&owner, &emit, json!({"method":"Page.frameAttached", "sessionId":"popup", "params":{"frameId":"child-frame", "parentFrameId":"frame-popup"}})).await;
    assert_eq!(
        document_idle_wait(&owner, &page, Duration::from_millis(80)).await,
        Ok(()),
        "another page's attachment must not reset the initial root's loader evidence"
    );
    realm_emit(&owner, &emit, json!({"method":"Page.frameDetached", "sessionId":"initial", "params":{"frameId":"child-frame", "reason":"remove"}})).await;
    document_idle_request(
        &owner,
        &emit,
        "late-old",
        json!("child-frame"),
        json!("old-child"),
    )
    .await;
    assert_eq!(
        document_idle_wait(&owner, &page, Duration::from_millis(80)).await,
        Ok(())
    );
    for (id, loader) in [
        ("before-attach-new", json!("future-loader")),
        ("before-attach-unknown", Value::Null),
    ] {
        document_idle_request(&owner, &emit, id, json!("child-frame"), loader).await;
        document_idle_blocked(&owner, &page).await;
        document_idle_finish(&owner, &emit, id).await;
        assert_eq!(
            document_idle_wait(&owner, &page, Duration::from_millis(1500)).await,
            Ok(())
        );
    }
    realm_emit(&owner, &emit, json!({"method":"Page.frameAttached", "sessionId":"initial", "params":{"frameId":"child-frame", "parentFrameId":"frame-initial"}})).await;
    document_idle_finish(&owner, &emit, "old-pending").await;
    document_idle_finish(&owner, &emit, "late-old").await;
    assert_eq!(
        document_idle_wait(&owner, &page, Duration::from_millis(1500)).await,
        Ok(())
    );
    for (id, loader) in [
        ("new-tenure-new", json!("future-loader")),
        ("new-tenure-unknown", Value::Null),
        ("new-tenure-reused", json!("old-child")),
    ] {
        document_idle_request(&owner, &emit, id, json!("child-frame"), loader).await;
        document_idle_blocked(&owner, &page).await;
        document_idle_finish(&owner, &emit, id).await;
        assert_eq!(
            document_idle_wait(&owner, &page, Duration::from_millis(1500)).await,
            Ok(())
        );
    }
    drop(page);
    owner.close().await.unwrap();
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn networkidle_document_attach_unknown_or_other_root_parent_only_restores_counting() {
    for parent in ["missing-parent", "frame-popup"] {
        let (owner, page, _notices, emit, server) = realm_test_owner().await;
        owner
            .enroll_existing("popup-target", "popup", "page", &owner.operation())
            .await
            .unwrap();
        document_idle_commit(
            &owner,
            &emit,
            json!({"id":"child-frame", "parentId":"frame-initial", "loaderId":"old-child"}),
        )
        .await;
        document_idle_request(
            &owner,
            &emit,
            "old-pending",
            json!("child-frame"),
            json!("old-child"),
        )
        .await;
        document_idle_commit(
            &owner,
            &emit,
            json!({"id":"child-frame", "parentId":"frame-initial", "loaderId":"next-child"}),
        )
        .await;
        assert_eq!(
            document_idle_wait(&owner, &page, Duration::from_millis(1500)).await,
            Ok(())
        );
        realm_emit(&owner, &emit, json!({"method":"Page.frameAttached", "sessionId":"initial", "params":{"frameId":"child-frame", "parentFrameId":parent}})).await;
        document_idle_blocked(&owner, &page).await;
        document_idle_finish(&owner, &emit, "old-pending").await;
        assert_eq!(
            document_idle_wait(&owner, &page, Duration::from_millis(1500)).await,
            Ok(())
        );
        drop(page);
        owner.close().await.unwrap();
        server.abort();
        let _ = server.await;
    }
}

#[tokio::test]
async fn networkidle_document_metadata_limits_fail_closed_and_forget_clears_tenure() {
    for limit in ["frames", "loaders", "requests"] {
        let (owner, page, _notices, emit, server) = realm_test_owner().await;
        assert_eq!(
            owner.page.record_network_frame(
                "other",
                "initial",
                "frame-initial",
                Some("foreign"),
                true
            ),
            Err(ProtocolError::StaleScope)
        );
        assert_eq!(
            owner
                .page
                .reset_network_frame("other", "initial", "frame-initial"),
            Err(ProtocolError::StaleScope)
        );
        let overflow = match limit {
            "frames" => {
                for ordinal in 1..4096 {
                    owner
                        .page
                        .record_network_frame(
                            "initial",
                            "initial",
                            &format!("bounded-{ordinal}"),
                            Some("loader"),
                            false,
                        )
                        .unwrap();
                }
                owner.page.record_network_frame(
                    "initial",
                    "initial",
                    "overflow",
                    Some("loader"),
                    false,
                )
            }
            "loaders" => {
                for ordinal in 1..=8192 {
                    owner
                        .page
                        .record_network_frame(
                            "initial",
                            "initial",
                            "frame-initial",
                            Some(&format!("bounded-{ordinal}")),
                            true,
                        )
                        .unwrap();
                }
                // Reusing one retired loader at the limit has zero net growth.
                owner
                    .page
                    .record_network_frame(
                        "initial",
                        "initial",
                        "frame-initial",
                        Some("synthetic-loader"),
                        true,
                    )
                    .unwrap();
                owner.page.record_network_frame(
                    "initial",
                    "initial",
                    "frame-initial",
                    Some("overflow"),
                    true,
                )
            }
            _ => {
                let mut request = CdpEvent {
                    method: "Network.requestWillBeSent".into(),
                    session_id: Some("initial".into()),
                    params: json!({"requestId":"", "frameId":"frame-initial", "loaderId":"synthetic-loader", "type":"Fetch", "request":{"method":"GET", "url":"https://synthetic.test/bounded"}}),
                };
                for ordinal in 0..8192 {
                    request.params["requestId"] = json!(format!("bounded-{ordinal}"));
                    owner.page.network_event("initial", &request).unwrap();
                }
                request.params["requestId"] = json!("overflow");
                owner.page.network_event("initial", &request)
            }
        };
        assert_eq!(overflow, Err(ProtocolError::CapacityExceeded), "{limit}");
        assert_eq!(
            document_idle_wait(&owner, &page, Duration::from_millis(650)).await,
            Err(ProtocolError::ScopeUnavailable)
        );
        assert_eq!(
            owner
                .page
                .reset_network_frame("initial", "initial", "frame-initial"),
            Err(ProtocolError::ScopeUnavailable)
        );
        owner.page.forget_session("initial").unwrap();
        assert_eq!(
            owner.page.record_network_frame(
                "initial",
                "initial",
                "frame-initial",
                Some("fresh"),
                false
            ),
            Err(ProtocolError::StaleScope)
        );
        owner
            .page
            .register_network_session("initial", "initial")
            .unwrap();
        owner
            .page
            .record_network_frame("initial", "initial", "frame-initial", Some("fresh"), false)
            .unwrap();
        document_idle_request(
            &owner,
            &emit,
            "fresh-old-loader",
            json!("frame-initial"),
            json!("synthetic-loader"),
        )
        .await;
        document_idle_blocked(&owner, &page).await;
        document_idle_finish(&owner, &emit, "fresh-old-loader").await;
        assert_eq!(
            document_idle_wait(&owner, &page, Duration::from_millis(1500)).await,
            Ok(())
        );
        drop(page);
        owner.close().await.unwrap();
        server.abort();
        let _ = server.await;
    }
}

#[tokio::test]
async fn networkidle_document_redirect_and_favicon_exclusions_remain_stable() {
    let (owner, page, _notices, emit, server) = realm_test_owner().await;
    for (id, urls) in [
        (
            "favicon-first",
            vec![
                "https://synthetic.test/favicon.ico",
                "https://synthetic.test/redirected",
            ],
        ),
        (
            "favicon-middle",
            vec![
                "https://synthetic.test/start",
                "https://synthetic.test/favicon.ico",
                "https://synthetic.test/end",
            ],
        ),
        (
            "counted-redirect",
            vec![
                "https://synthetic.test/first",
                "https://synthetic.test/second",
            ],
        ),
    ] {
        for (ordinal, url) in urls.into_iter().enumerate() {
            let mut params = json!({"requestId":id, "frameId":"frame-initial", "loaderId":"synthetic-loader", "type":"Fetch", "request":{"method":"GET", "url":url}});
            if ordinal > 0 {
                params["redirectResponse"] =
                    json!({"url":"https://synthetic.test/previous", "status":302, "headers":{}});
            }
            realm_emit(&owner, &emit, json!({"method":"Network.requestWillBeSent", "sessionId":"initial", "params":params})).await;
        }
    }
    document_idle_commit(
        &owner,
        &emit,
        json!({"id":"frame-initial", "loaderId":"next-loader"}),
    )
    .await;
    assert_eq!(
        document_idle_wait(&owner, &page, Duration::from_millis(1500)).await,
        Ok(())
    );
    for id in ["favicon-first", "favicon-middle"] {
        // A redirect with incomplete document metadata remains excluded by the
        // original favicon identity, independently of loader retirement.
        document_idle_request(&owner, &emit, id, Value::Null, Value::Null).await;
    }
    assert_eq!(
        document_idle_wait(&owner, &page, Duration::from_millis(80)).await,
        Ok(())
    );
    document_idle_request(&owner, &emit, "counted-redirect", Value::Null, Value::Null).await;
    document_idle_blocked(&owner, &page).await;
    realm_emit(&owner, &emit, json!({"method":"Network.loadingFailed", "sessionId":"initial", "params":{"requestId":"counted-redirect", "errorText":"net::ERR_ABORTED", "canceled":true}})).await;
    assert_eq!(
        document_idle_wait(&owner, &page, Duration::from_millis(1500)).await,
        Ok(())
    );
    drop(page);
    owner.close().await.unwrap();
    server.abort();
    let _ = server.await;
}
