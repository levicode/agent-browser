//! Registration receipt controls only: no browser, AX, role, or lifecycle fixture.
use super::*;

fn seeded_target(name: &str, session: &str, ordinal: u64) -> OwnedTarget {
    OwnedTarget {
        target_id: name.into(),
        session_id: session.into(),
        kind: "page".into(),
        purpose: Some(TargetPurpose::Application),
        configured: false,
        resumed: false,
        resume_pending: false,
        tenure: Arc::new(AttachmentTenure::default()),
        diagnostic: Some(diagnostic::DiagnosticAttachment {
            attachment: ordinal,
            target: ordinal + 100,
            ..Default::default()
        }),
    }
}
fn context<'a>(root: (&'a str, &'a str)) -> RegistrationDiagnosticContext<'a> {
    RegistrationDiagnosticContext {
        generation: 7,
        origin: diagnostic::DiagnosticTargetOrigin::AutoAttach,
        parent: None,
        root: Some(root),
        lineage_complete: true,
    }
}
#[test]
fn registration_receipt_self_root_uses_new_attachment_and_original_fields() {
    let mut state = Registry::default();
    let mut target = seeded_target("page", "session", 12);
    let receipt = state
        .registration_diagnostic(&mut target, &context(("page", "session")))
        .unwrap();
    assert_eq!(
        (
            receipt.attachment,
            receipt.root,
            receipt.parent,
            receipt.generation
        ),
        (12, 12, 0, 7)
    );
    assert_eq!(receipt.stage, diagnostic::DiagnosticTargetStage::Registered);
    assert!(!receipt.configured && !receipt.resumed);
    target.configured = true;
    target.resumed = true;
    target.diagnostic.as_mut().unwrap().attachment = 99;
    assert_eq!(receipt.attachment, 12);
    assert!(!receipt.configured && !receipt.resumed);
    assert!(!state.diagnostic_lost);
}
#[test]
fn registration_receipt_parent_and_root_require_exact_session_and_owner() {
    for obstruction in ["none", "session", "owner", "absent", "zero", "incomplete"] {
        let mut state = Registry::default();
        let mut child = seeded_target("child", "child-session", 20);
        let mut root = seeded_target("root", "root-session", 10);
        if obstruction != "owner" {
            root.tenure = child.tenure.clone();
        }
        if obstruction == "session" {
            root.session_id = "replacement".into();
        }
        if obstruction == "zero" {
            root.diagnostic.as_mut().unwrap().attachment = 0;
        }
        if obstruction != "absent" {
            state.targets.insert("root".into(), root);
        }
        let mut input = context(("root", "root-session"));
        input.parent = Some(("root", "root-session"));
        input.lineage_complete = obstruction != "incomplete";
        let receipt = state.registration_diagnostic(&mut child, &input);
        assert_eq!(receipt.is_some(), obstruction == "none", "{obstruction}");
        assert_eq!(
            state.diagnostic_lost,
            obstruction != "none",
            "{obstruction}"
        );
        if let Some(receipt) = receipt {
            assert_eq!((receipt.parent, receipt.root), (10, 10));
        }
    }
}
#[test]
fn registration_receipt_is_not_rebound_after_detach_or_same_id_replacement() {
    let mut state = Registry::default();
    let mut target = seeded_target("page", "session", 11);
    let original = state
        .registration_diagnostic(&mut target, &context(("page", "session")))
        .unwrap();
    state.targets.insert("page".into(), target);
    state.targets.remove("page");
    state
        .targets
        .insert("page".into(), seeded_target("page", "session", 27));
    let saved = RegistrationDiagnosticReceipt::Committed(original)
        .snapshot()
        .unwrap();
    assert_eq!((saved.attachment, saved.root), (11, 11));
    assert_eq!(state.targets["page"].diagnostic.unwrap().attachment, 27);
}
fn attachment(context: &str) -> RegistrationAttachment<'_> {
    RegistrationAttachment {
        context,
        target: "page".into(),
        session: "session".into(),
        kind: "page".into(),
    }
}
#[test]
fn registration_receipt_precommit_refusal_and_duplicate_do_not_fabricate_commit() {
    let registry = ClientTargets::new("ctx".into(), "scope".into());
    let input = context(("page", "session"));
    let mut slot = RegistrationDiagnosticReceipt::default();
    assert!(!registry
        .attached_enrolled_observed(
            attachment("foreign"),
            None,
            false,
            Some((&input, &mut slot))
        )
        .unwrap());
    assert!(matches!(slot, RegistrationDiagnosticReceipt::NotCommitted));
    registry
        .attached_enrolled_observed(attachment("ctx"), None, false, Some((&input, &mut slot)))
        .unwrap();
    assert!(!matches!(slot, RegistrationDiagnosticReceipt::NotCommitted));
    let mut duplicate = RegistrationDiagnosticReceipt::default();
    assert_eq!(
        registry.attached_enrolled_observed(
            attachment("ctx"),
            None,
            false,
            Some((&input, &mut duplicate))
        ),
        Err(ProtocolError::InvalidArguments)
    );
    assert!(matches!(
        duplicate,
        RegistrationDiagnosticReceipt::NotCommitted
    ));
    assert!(registry.state.try_lock().is_ok());
}
#[test]
fn registration_receipt_opt_out_keeps_slot_and_legacy_entry_unchanged() {
    let registry = ClientTargets::new("ctx".into(), "scope".into());
    assert!(registry
        .attached_enrolled("ctx", "page".into(), "session".into(), "page".into())
        .unwrap());
    assert!(registry.state.try_lock().is_ok());
    assert!(RegistrationDiagnosticReceipt::default()
        .snapshot()
        .is_none());
}
#[tokio::test]
async fn registration_receipt_survives_actual_postinsert_once_lock_refusal() {
    // A transport only supplies the existing watermark value. No protocol calls
    // or synthetic enrollment/AX responses participate in this state control.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let socket = tokio_tungstenite::accept_async(socket).await.unwrap();
        let _ = stopped.await;
        drop(socket);
    });
    let client = super::super::cdp::client::CdpClient::connect(&format!("ws://{address}"))
        .await
        .unwrap();
    let events = client
        .subscribe_bounded_methods(&["Target.attachedToTarget"], 1, 1024)
        .unwrap();
    let registry = ClientTargets::new("ctx".into(), "scope".into());
    let progress = PopupInitializationReceipt(Arc::new(PopupInitializationProgress {
        registry: Arc::downgrade(&registry),
        ledger: std::sync::Weak::new(),
        generation: 7,
        stream: events.watermark(),
        origin: 1,
        target: std::sync::OnceLock::new(),
        stage: AtomicU8::new(0),
        terminal: AtomicU8::new(0),
        setup_diagnostic: PopupSetupProgress::default(),
        configuration_applied: std::sync::OnceLock::new(),
    }));
    assert!(progress
        .0
        .target
        .set(seeded_target("old", "old-session", 1))
        .is_ok());
    let mut custody = RetainedInitialization::new(registry.clone());
    custody.popup_progress = Some(progress);
    let mut slot = RegistrationDiagnosticReceipt::default();
    let input = context(("page", "session"));
    assert_eq!(
        custody.attach_with_ancestry_observed(
            &registry,
            attachment("ctx"),
            AttachmentAncestry {
                root: None,
                verified_self_root: false
            },
            Some((&input, &mut slot))
        ),
        Err(ProtocolError::StaleScope)
    );
    assert!(!matches!(slot, RegistrationDiagnosticReceipt::NotCommitted));
    assert!(registry.state.lock().unwrap().targets.contains_key("page"));
    assert!(registry.state.try_lock().is_ok());
    // The committed fact is retained despite failure, without granting readiness.
    assert!(!registry.state.lock().unwrap().targets["page"].capture_ready());
    drop(custody);
    drop(events);
    drop(client);
    stop.send(()).unwrap();
    server.await.unwrap();
}

#[test]
fn registration_committed_receipt_survives_local_transaction_postinsert_error() {
    // Local registry/OnceLock layering: does not claim to enable the global sink
    // or exercise attach_inner's opt-in allocation. The separate async control
    // covers the real retained attach path's outslot placement.
    for ancestry in ["self-root", "child"] {
        let registry = ClientTargets::new("ctx".into(), "scope".into());
        let mut original = seeded_target("page", "session", 12);
        let mut root = seeded_target("root", "root-session", 8);
        root.tenure = original.tenure.clone();
        let occupied = std::sync::OnceLock::new();
        assert!(occupied.set(seeded_target("old", "old-session", 1)).is_ok());
        let mut slot = RegistrationDiagnosticReceipt::NotCommitted;
        let result: Result<(), ProtocolError> = (|| {
            let mut state = registry.state.lock().unwrap();
            let mut input = context(("page", "session"));
            if ancestry == "child" {
                state.targets.insert("root".into(), root);
                input.parent = Some(("root", "root-session"));
                input.root = Some(("root", "root-session"));
            }
            let snapshot = state
                .registration_diagnostic(&mut original, &input)
                .unwrap();
            state.targets.insert("page".into(), original.clone());
            slot = RegistrationDiagnosticReceipt::Committed(snapshot);
            drop(state);
            occupied
                .set(original.clone())
                .map_err(|_| ProtocolError::StaleScope)?;
            Ok(())
        })();
        assert_eq!(result, Err(ProtocolError::StaleScope));
        let RegistrationDiagnosticReceipt::Committed(saved) = slot else {
            panic!("a concrete Registered receipt must survive the postinsert refusal");
        };
        assert_eq!(saved.stage, diagnostic::DiagnosticTargetStage::Registered);
        assert_eq!(saved.origin, diagnostic::DiagnosticTargetOrigin::AutoAttach);
        assert_eq!(
            (saved.generation, saved.attachment, saved.target),
            (7, 12, 112)
        );
        assert_eq!(
            (saved.parent, saved.root),
            if ancestry == "child" { (8, 8) } else { (0, 12) }
        );
        assert!(!saved.configured && !saved.resumed);
        let mut state = registry.state.try_lock().unwrap();
        assert_eq!(state.targets["page"].session_id, "session");
        let detached = state.targets.remove("page").unwrap();
        assert_eq!(detached.session_id, "session");
        assert_eq!(slot.snapshot().unwrap().attachment, 12);
        state.targets.insert(
            "page".into(),
            seeded_target("page", "replacement-session", 99),
        );
        assert_eq!(slot.snapshot().unwrap().attachment, 12);
        assert_eq!(occupied.get().unwrap().session_id, "old-session");
    }
}
