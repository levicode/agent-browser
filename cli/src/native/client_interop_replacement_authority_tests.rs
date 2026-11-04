// Included in the existing private-decision tests. These exercise the real
// broker, not forged pending-decision state or a renewed operation deadline.

#[tokio::test]
async fn private_replacement_tokens_are_one_use_and_expire_on_original_budget() {
    let broker = ClientSession::new();
    let operation = started(&broker);
    let retired = broker
        .decision(
            1,
            DecisionOwner::Operation(1),
            DecisionKind::InteropRetire,
            1000,
            None,
        )
        .unwrap();
    broker
        .resolve(1, &retired.token, Decision::InteropRetired {})
        .unwrap();
    assert_eq!(
        broker.resolve(1, &retired.token, Decision::InteropRetired {}),
        Err(ProtocolError::DecisionMissing)
    );
    assert!(broker
        .validate_interop_decision(&operation, &retired.token, DecisionKind::InteropRetire)
        .is_err());
    assert!(matches!(
        retired.outcome.await.unwrap(),
        DecisionOutcome::Selected(Decision::InteropRetired {})
    ));

    // An oversized policy allowance must not extend this actually admitted
    // operation. Let the real clock expire it; do not edit broker internals.
    let broker = ClientSession::new();
    let operation = broker.admit(1, 1, 500).unwrap();
    assert!(broker.start(1, 1).unwrap());
    let created = broker
        .decision(
            1,
            DecisionOwner::Operation(1),
            DecisionKind::InteropCreate,
            5000,
            None,
        )
        .unwrap();
    assert_eq!(created.deadline, operation.deadline);
    tokio::time::sleep_until(operation.deadline.into()).await;
    assert_eq!(
        broker.resolve(
            1,
            &created.token,
            Decision::InteropCreated {
                context_id: "late-context".into(),
                target_id: "late-page".into(),
            },
        ),
        Err(ProtocolError::DecisionExpired)
    );
    assert!(matches!(
        created.outcome.await.unwrap(),
        DecisionOutcome::Expired
    ));
    assert!(broker
        .decision(
            1,
            DecisionOwner::Operation(1),
            DecisionKind::InteropCreate,
            5000,
            None,
        )
        .is_err());
}

#[test]
fn private_replacement_authority_rejects_foreign_leases_and_callback_owners() {
    let broker = ClientSession::new();
    let operation = started(&broker);
    let decision = broker
        .decision(
            1,
            DecisionOwner::Operation(1),
            DecisionKind::InteropRetire,
            1000,
            None,
        )
        .unwrap();
    let (_foreign_sender, foreign_receiver) = watch::channel(CancelSignal::None);
    for wrong in ["generation", "sequence", "channel", "callback"] {
        let forged = OperationLease {
            generation: if wrong == "generation" { 2 } else { 1 },
            sequence: if wrong == "sequence" { 2 } else { 1 },
            deadline: operation.deadline,
            cancellation: if wrong == "channel" {
                foreign_receiver.clone()
            } else {
                operation.cancellation.clone()
            },
            is_callback: wrong == "callback",
        };
        assert!(
            broker
                .validate_interop_decision(&forged, &decision.token, DecisionKind::InteropRetire)
                .is_err(),
            "accepted forged {wrong}"
        );
        broker
            .validate_interop_decision(&operation, &decision.token, DecisionKind::InteropRetire)
            .unwrap();
    }
    assert_eq!(
        broker.resolve(2, &decision.token, Decision::InteropRetired {}),
        Err(ProtocolError::StaleGeneration)
    );
    broker.revoke_decision(&decision.token).unwrap();
    assert!(matches!(
        broker.decision(
            1,
            DecisionOwner::Operation(1),
            DecisionKind::InteropRetire,
            1000,
            Some(9),
        ),
        Err(ProtocolError::InvalidArguments)
    ));

    // A genuinely admitted public callback child must still be unable to mint
    // a private lifecycle token for itself.
    let public = broker
        .decision(1, DecisionOwner::Scope, DecisionKind::Request, 1000, None)
        .unwrap();
    broker
        .admit_callback(1, 2, 1000, Some(&public.token))
        .unwrap();
    assert!(broker.start(1, 2).unwrap());
    assert!(matches!(
        broker.decision(
            1,
            DecisionOwner::Operation(2),
            DecisionKind::InteropCreate,
            1000,
            None,
        ),
        Err(ProtocolError::InvalidArguments)
    ));
    broker.cancel(1, 2).unwrap();
    broker.revoke_decision(&public.token).unwrap();
}
