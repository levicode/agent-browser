use super::*;

#[test]
fn later_rpc_has_real_new_identity_but_same_original_deadline() {
    let broker = ClientSession::new();
    let prepare = broker.admit(1, 1, 5000).unwrap();
    assert!(broker.start(1, 1).unwrap());
    broker.settle(1, 1, Effects::Completed).unwrap();
    let adopt = broker
        .admit_callback_capped(1, 2, 60000, None, Ok(Some(prepare.deadline)))
        .unwrap();
    assert_eq!(adopt.sequence, 2);
    assert!(!adopt.cancellation.same_channel(&prepare.cancellation));
    assert_eq!(adopt.deadline, prepare.deadline);
    assert_eq!(
        broker.lock().unwrap().operations.get(&2).unwrap().deadline,
        prepare.deadline
    );
    // The prepare operation is gone, not kept as a fake lifetime lease.
    assert!(!broker.lock().unwrap().operations.contains_key(&1));
    assert_eq!(broker.cancel(1, 1), Err(ProtocolError::OperationMissing));
    assert_eq!(*adopt.cancellation.borrow(), CancelSignal::None);
    assert!(broker.start(1, 2).unwrap());
    broker.cancel(1, 2).unwrap();
    assert_eq!(*adopt.cancellation.borrow(), CancelSignal::Requested);
}

#[test]
fn expired_lifetime_and_mismatched_ticket_reject_and_consume_sequence() {
    for cap in [
        Ok(Some(Instant::now() - Duration::from_secs(1))),
        Err(ProtocolError::StaleScope),
    ] {
        let expected = if cap.is_ok() {
            ProtocolError::DeadlineExceeded
        } else {
            ProtocolError::StaleScope
        };
        let broker = ClientSession::new();
        assert!(matches!(
            broker.admit_callback_capped(1, 1, 5000, None, cap),
            Err(error) if error == expected
        ));
        assert!(broker.lock().unwrap().operations.is_empty());
        assert!(matches!(
            broker.admit(1, 1, 5000),
            Err(ProtocolError::SequenceReused)
        ));
        // An unrelated ordinary operation is neither capped nor rejected.
        assert!(broker.admit(1, 2, 5000).is_ok());
    }
}

#[test]
fn cap_never_extends_requested_or_callback_parent_deadline() {
    let broker = ClientSession::new();
    let before = Instant::now();
    let parent = broker
        .admit_callback_capped(1, 1, 5000, None, Ok(Some(before + Duration::from_secs(60))))
        .unwrap();
    assert!(parent.deadline < before + Duration::from_secs(6));
    let decision = broker
        .decision(
            1,
            DecisionOwner::Operation(1),
            DecisionKind::Request,
            5000,
            None,
        )
        .unwrap();
    let child = broker
        .admit_callback_capped(
            1,
            2,
            60000,
            Some(&decision.token),
            Ok(Some(before + Duration::from_secs(30))),
        )
        .unwrap();
    assert!(child.deadline <= parent.deadline);
    assert_eq!(
        broker.lock().unwrap().operations.get(&2).unwrap().deadline,
        child.deadline
    );
}
