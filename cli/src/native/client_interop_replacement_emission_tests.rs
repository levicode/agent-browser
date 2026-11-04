use super::*;
use crate::native::client_session::{DecisionKind, DecisionOwner};

#[test]
fn private_replacement_emission_does_not_revive_stale_or_staged_sinks() {
    let broker = std::sync::Arc::new(ClientSession::new());
    let (root, mut events) = ClientEventSink::test_channel(broker.clone());
    let old = live_scope_sink(&root, 7, "old");
    old.retire_scope_callbacks(1, "old").unwrap();
    assert!(
        matches!(events.try_recv().unwrap(), ServerMessage::Event { event, .. }
        if event == "scope.callbacks-retired")
    );

    let operation = broker.admit(1, 8, 5000).unwrap();
    assert!(broker.start(1, 8).unwrap());
    let staged = root.stage_until_result(&operation, "unpublished").unwrap();
    let lease = broker
        .decision(
            1,
            DecisionOwner::Operation(8),
            DecisionKind::InteropRetire,
            5000,
            None,
        )
        .unwrap();
    for sink in [&old, &staged] {
        assert_eq!(
            sink.emit_interop_decision(
                &operation,
                "old",
                DecisionKind::InteropRetire,
                &lease,
                Some("old-context")
            ),
            Err(ProtocolError::StaleScope)
        );
    }
    let (_foreign_sender, foreign_receiver) =
        tokio::sync::watch::channel(super::super::super::client_session::CancelSignal::None);
    let forged = OperationLease {
        generation: operation.generation,
        sequence: operation.sequence,
        deadline: operation.deadline,
        cancellation: foreign_receiver,
        is_callback: false,
    };
    assert!(root
        .emit_interop_decision(
            &forged,
            "old",
            DecisionKind::InteropRetire,
            &lease,
            Some("old-context")
        )
        .is_err());
    assert!(events.try_recv().is_err());

    root.emit_interop_decision(
        &operation,
        "old",
        DecisionKind::InteropRetire,
        &lease,
        Some("old-context"),
    )
    .unwrap();
    match events.try_recv().unwrap() {
        ServerMessage::Event {
            generation,
            event,
            payload,
            decision: Some(notice),
            ..
        } => {
            assert_eq!(generation, operation.generation);
            assert_eq!(event, "scope.interop.replacement");
            assert_eq!(
                payload,
                serde_json::json!({"version":1,"identityScope":"old","operationSeq":8,"phase":"retire","contextId":"old-context"})
            );
            assert_eq!(notice.token, lease.token);
            assert!(notice.timeout_ms > 0 && notice.timeout_ms <= 5000);
        }
        _ => panic!("missing private operation-owned event"),
    }
    assert_eq!(
        old.emit(
            "late".into(),
            serde_json::json!({"identityScope":"old"}),
            None
        ),
        Err(ProtocolError::StaleScope)
    );
    broker
        .resolve(
            1,
            &lease.token,
            super::super::super::client_protocol::Decision::InteropRetired {},
        )
        .unwrap();
    assert!(root
        .emit_interop_decision(
            &operation,
            "old",
            DecisionKind::InteropRetire,
            &lease,
            Some("old-context")
        )
        .is_err());
    assert!(events.try_recv().is_err());

    // Closing publication cannot be undone by another otherwise valid private
    // decision. A staged scope still has no success/flush authority either.
    let creating = broker
        .decision(
            1,
            DecisionOwner::Operation(8),
            DecisionKind::InteropCreate,
            5000,
            None,
        )
        .unwrap();
    root.close_publications();
    assert!(root
        .emit_interop_decision(
            &operation,
            "old",
            DecisionKind::InteropCreate,
            &creating,
            None
        )
        .is_err());
    assert!(staged
        .emit(
            "late".into(),
            serde_json::json!({"identityScope":"unpublished"}),
            None
        )
        .is_err());
    assert!(events.try_recv().is_err());
    broker.revoke_decision(&creating.token).unwrap();
}
