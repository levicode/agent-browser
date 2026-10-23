// These fixtures exercise the real bounded CDP reader, enrollment supervisor,
// configure/resume tasks and registry. Only local synthetic ACKs are controlled.
mod restart_readiness {
    use super::*;

    async fn until(mut ready: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !ready() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    async fn emit_held(f: &CaptureWireFixture, target: &str, session: &str, kind: &str) {
        f.held
            .lock()
            .unwrap()
            .insert(("Runtime.enable".into(), session.into()));
        let mut event = capture_attach_event(target, session, kind);
        if kind == "iframe" {
            event["sessionId"] = json!("initial");
        }
        f.emit.send(event).await.unwrap();
    }

    async fn held_request(f: &CaptureWireFixture, session: &str) -> Value {
        until(|| {
            f.requests("Runtime.enable")
                .iter()
                .any(|request| request["sessionId"] == session)
        })
        .await;
        f.requests("Runtime.enable")
            .into_iter()
            .find(|request| request["sessionId"] == session)
            .unwrap()
    }

    async fn acknowledge(f: &CaptureWireFixture, request: &Value) {
        f.emit
            .send(json!({"id":request["id"], "result":{}}))
            .await
            .unwrap();
    }

    fn publish(
        f: &CaptureWireFixture,
        op: OperationLease,
        published: Arc<AtomicBool>,
    ) -> JoinHandle<Result<(), ProtocolError>> {
        let owner = f.owner.clone();
        let replacement = owner.targets.owned_target("target").unwrap();
        tokio::spawn(async move {
            owner
                .publish_restart_ready(&replacement, &op, || {
                    assert!(!published.swap(true, Ordering::SeqCst));
                    Ok(())
                })
                .await
        })
    }

    #[tokio::test]
    async fn all_observed_sibling_acks_are_required_without_kind_exemptions() {
        for kind in ["browser-ui", "worker", "service_worker", "iframe"] {
            let f = CaptureWireFixture::new(false).await;
            let replacement = f.owner.targets.owned_target("target").unwrap();
            assert!(replacement.capture_ready());
            emit_held(&f, "first", "first-session", kind).await;
            let first = held_request(&f, "first-session").await;
            emit_held(&f, "second", "second-session", "browser-ui").await;
            until(|| f.owner.index.lock().unwrap().pending_enrollment.len() == 2).await;

            let published = Arc::new(AtomicBool::new(false));
            let waiting = f.gate(CaptureTestPoint::RestartWaiting);
            let task = publish(&f, f.owner.operation(), published.clone());
            waiting.wait_entered().await;
            assert!(!published.load(Ordering::SeqCst));
            // The generic settlement gate still rejects this same inventory.
            assert_eq!(
                f.owner.targets.check_settlement_integrity(),
                Err(ProtocolError::ScopeUnavailable)
            );
            assert!(!f.owner.targets.inventory_diagnostic().sealed);

            acknowledge(&f, &first).await;
            let second = held_request(&f, "second-session").await;
            assert!(!task.is_finished());
            assert!(!published.load(Ordering::SeqCst));
            acknowledge(&f, &second).await;
            assert_eq!(task.await.unwrap(), Ok(()));
            assert!(published.load(Ordering::SeqCst));
            f.owner.targets.check_settlement_integrity().unwrap();
            assert!(f
                .owner
                .targets
                .owned_target("first")
                .unwrap()
                .capture_ready());
            assert!(f
                .owner
                .targets
                .owned_target("second")
                .unwrap()
                .capture_ready());
            f.finish().await;
        }
    }

    #[tokio::test]
    async fn child_received_after_first_ready_check_blocks_final_publication() {
        let f = CaptureWireFixture::new(false).await;
        let replacement = f.owner.targets.owned_target("target").unwrap();
        f.owner
            .publish_restart_ready(&replacement, &f.owner.operation(), || Ok(()))
            .await
            .unwrap();
        let before_apply = f.gate(CaptureTestPoint::BeforeEventApply);
        emit_held(&f, "late-child", "late-session", "worker").await;
        before_apply.wait_entered().await;
        // Reader has admitted the child, but supervisor has not registered it.
        assert!(f.owner.index.lock().unwrap().pending_enrollment.is_empty());
        let published = Arc::new(AtomicBool::new(false));
        let waiting = f.gate(CaptureTestPoint::RestartWaiting);
        let task = publish(&f, f.owner.operation(), published.clone());
        waiting.wait_entered().await;
        assert!(!published.load(Ordering::SeqCst));
        before_apply.release();
        let child = held_request(&f, "late-session").await;
        assert!(!published.load(Ordering::SeqCst));
        acknowledge(&f, &child).await;
        assert_eq!(task.await.unwrap(), Ok(()));
        assert!(published.load(Ordering::SeqCst));
        f.owner.targets.check_settlement_integrity().unwrap();
        f.finish().await;
    }

    #[tokio::test]
    async fn held_ack_obeys_original_cancellation_and_deadline() {
        for cancelled in [true, false] {
            let f = CaptureWireFixture::new(false).await;
            emit_held(&f, "held", "held-session", "browser-ui").await;
            let request = held_request(&f, "held-session").await;
            let (cancel, cancellation) = watch::channel(CancelSignal::None);
            let mut op = f.owner.operation();
            op.cancellation = cancellation;
            if !cancelled {
                op.deadline = Instant::now() + Duration::from_millis(200);
            }
            let published = Arc::new(AtomicBool::new(false));
            let waiting = f.gate(CaptureTestPoint::RestartWaiting);
            let task = publish(&f, op, published.clone());
            waiting.wait_entered().await;
            if cancelled {
                cancel.send_replace(CancelSignal::Requested);
            }
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), task)
                    .await
                    .unwrap()
                    .unwrap(),
                Err(if cancelled {
                    ProtocolError::Cancelled
                } else {
                    ProtocolError::DeadlineExceeded
                })
            );
            assert!(!published.load(Ordering::SeqCst));
            assert!(!f.owner.targets.inventory_diagnostic().sealed);
            acknowledge(&f, &request).await;
            f.owner
                .drain_capture_watermark(&f.owner.realm_watermark().unwrap(), &f.owner.operation())
                .await
                .unwrap();
            f.finish().await;
        }
    }

    #[tokio::test]
    async fn held_ack_failure_preserves_cause_and_cannot_publish() {
        let f = CaptureWireFixture::new(false).await;
        emit_held(&f, "failed", "failed-session", "browser-ui").await;
        let request = held_request(&f, "failed-session").await;
        let (_cancel, cancellation) = watch::channel(CancelSignal::None);
        let mut op = f.owner.operation();
        op.cancellation = cancellation;
        let published = Arc::new(AtomicBool::new(false));
        let waiting = f.gate(CaptureTestPoint::RestartWaiting);
        let task = publish(&f, op, published.clone());
        waiting.wait_entered().await;
        f.emit.send(json!({"id":request["id"], "error":{"code":-32000,"message":"synthetic configure failure"}})).await.unwrap();
        assert_eq!(task.await.unwrap(), Err(ProtocolError::BrowserFailure));
        assert!(!published.load(Ordering::SeqCst));
        assert!(f.owner.targets.inventory_diagnostic().sealed);
        f.finish().await;
    }

    #[tokio::test]
    async fn seal_wakes_waiter_and_never_becomes_a_pending_configuration() {
        for coordinator in [true, false] {
            let f = CaptureWireFixture::new(false).await;
            emit_held(&f, "held", "held-session", "browser-ui").await;
            let _request = held_request(&f, "held-session").await;
            let (_cancel, cancellation) = watch::channel(CancelSignal::None);
            let mut op = f.owner.operation();
            op.cancellation = cancellation;
            let published = Arc::new(AtomicBool::new(false));
            let waiting = f.gate(CaptureTestPoint::RestartWaiting);
            let task = publish(&f, op, published.clone());
            waiting.wait_entered().await;
            if coordinator {
                f.owner.seal();
            } else {
                f.owner.targets.seal();
            }
            assert!(tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .is_err());
            assert!(!published.load(Ordering::SeqCst));
            f.finish().await;
        }
    }

    #[tokio::test]
    async fn unknown_inventory_and_same_id_reattachment_refuse_without_publication() {
        for case in ["unknown", "reattached", "generation", "session", "stream"] {
            let f = CaptureWireFixture::new(false).await;
            let replacement = f.owner.targets.owned_target("target").unwrap();
            let mut op = f.owner.operation();
            match case {
                "unknown" => {
                    f.owner
                        .targets
                        .attached(
                            "owned-context",
                            "unknown".into(),
                            "unknown-session".into(),
                            "browser-ui".into(),
                        )
                        .unwrap();
                }
                "reattached" => {
                    f.owner.targets.detach("target").unwrap();
                    f.owner
                        .targets
                        .attached(
                            "owned-context",
                            "target".into(),
                            "initial".into(),
                            "page".into(),
                        )
                        .unwrap();
                    f.owner.targets.configured("target").unwrap();
                    f.owner
                        .targets
                        .resume_permit("target")
                        .await
                        .unwrap()
                        .complete()
                        .unwrap();
                }
                "generation" => op.generation += 1,
                "session" => {
                    f.owner
                        .index
                        .lock()
                        .unwrap()
                        .sessions
                        .get_mut("initial")
                        .unwrap()
                        .target = "changed".into()
                }
                _ => {
                    f.owner.event_watermark.lock().unwrap().take();
                }
            }
            let published = AtomicBool::new(false);
            let result = f
                .owner
                .publish_restart_ready(&replacement, &op, || {
                    published.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .await;
            assert!(result.is_err(), "{case}");
            assert!(!published.load(Ordering::SeqCst), "{case}");
            f.finish().await;
        }
    }
}
