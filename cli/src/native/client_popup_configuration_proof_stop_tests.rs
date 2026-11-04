// Exact proof-guard provenance, using real retained popup receipts and supervisor.
mod configuration_proof_stop_tests {
    use super::*;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ProofGuardCase {
        Owner,
        Requested,
        Deadline,
        HardThenOwner,
        RequestedThenOwner,
        DeadlineThenOwner,
        OwnerThenDeadline,
    }

    async fn proof_guard_case(case: ProofGuardCase) {
        let (owner, _notices, log, emit, server, _broker, connection) =
            fixture_with_explicit_context_ownership("owner-retirement", true, true).await;
        owner
            .enroll_existing("initial-target", "initial", "page", &owner.operation())
            .await
            .unwrap();
        owner.start(&owner.operation()).await.unwrap();
        let gate = CaptureTestGate::new();
        owner.capture_test_gates.lock().unwrap().insert(
            CaptureTestPoint::BeforePopupConfigurationProof,
            gate.clone(),
        );
        emit.send(json!({"method":"Target.attachedToTarget","params":{
            "sessionId":"proof-stop-popup", "waitingForDebugger":true,
            "targetInfo":{"targetId":"proof-stop-target", "type":"page",
                "browserContextId":"owned-context", "openerId":"initial-target"}
        }}))
        .await
        .unwrap();
        gate.wait_entered().await;
        // This exact gate uses timeout_at only: it cannot consume cancellation.
        // On release the next production decision is the proof guard itself.
        let entry = {
            let index = owner.index.lock().unwrap();
            assert!(index.pending_enrollment.contains_key("proof-stop-popup"));
            assert!(index
                .pending_eval_initialization
                .contains_key("proof-stop-popup"));
            index.sessions["proof-stop-popup"].clone()
        };
        assert_eq!(
            owner
                .targets
                .retained_initialization_state_for_test("proof-stop-target"),
            (true, None, false)
        );
        let commands_before = {
            let commands = log.lock().unwrap();
            commands
                .iter()
                .filter(|r| r["sessionId"] == "proof-stop-popup")
                .map(|r| r["method"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        };
        assert!(commands_before.iter().any(|m| m == "Runtime.enable"));
        assert!(!commands_before.iter().any(|m| m == "Target.setAutoAttach"));
        assert!(!commands_before
            .iter()
            .any(|m| m == "Runtime.runIfWaitingForDebugger"));
        let revision = owner.page.config_revision().unwrap();

        // The direct cases call the real proof method on the original retained
        // receipt before conversion; no forged OperationStopObservation is used.
        // The actual supervisor remains held and later retires its own custody.
        let observed = match case {
            ProofGuardCase::HardThenOwner => {
                let mut wrong_generation = owner.operation();
                wrong_generation.generation += 1;
                let first = owner
                    .mark_popup_configuration_applied(&entry, &wrong_generation, revision)
                    .unwrap_err();
                let mut callback = owner.operation();
                callback.is_callback = true;
                let second = owner
                    .mark_popup_configuration_applied(&entry, &callback, revision)
                    .unwrap_err();
                Some((first, Some(second)))
            }
            ProofGuardCase::RequestedThenOwner | ProofGuardCase::DeadlineThenOwner => {
                owner
                    .stop
                    .send_replace(if case == ProofGuardCase::RequestedThenOwner {
                        CancelSignal::Requested
                    } else {
                        CancelSignal::DeadlineExceeded
                    });
                Some((
                    owner
                        .mark_popup_configuration_applied(&entry, &owner.operation(), revision)
                        .unwrap_err(),
                    None,
                ))
            }
            ProofGuardCase::OwnerThenDeadline => {
                owner.stop.send_replace(CancelSignal::OwnerRetirement);
                let mut expired = owner.operation();
                expired.deadline = Instant::now() - Duration::from_millis(1);
                Some((
                    owner
                        .mark_popup_configuration_applied(&entry, &expired, revision)
                        .unwrap_err(),
                    None,
                ))
            }
            _ => None,
        };
        if case == ProofGuardCase::Requested {
            owner.stop.send_replace(CancelSignal::Requested);
        } else if case == ProofGuardCase::Deadline {
            owner.stop.send_replace(CancelSignal::DeadlineExceeded);
        }
        owner.seal_for_owner_retirement(
            &super::super::super::client_browser::OwnerRetirement::for_test(&owner.targets),
        );
        if let Some((first, second)) = observed {
            // Deliberately change the channel after the exact guard decided.
            // Neither an earlier hard error nor Requested/Deadline can borrow
            // this later OwnerRetirement, and an owner stop cannot turn deadline.
            owner
                .stop
                .send_replace(if case == ProofGuardCase::OwnerThenDeadline {
                    CancelSignal::DeadlineExceeded
                } else {
                    CancelSignal::OwnerRetirement
                });
            let classified = owner.popup_configuration_failure(first);
            match case {
                ProofGuardCase::HardThenOwner => {
                    assert!(matches!(
                        classified,
                        InitFailure::Operation(ProtocolError::StaleScope)
                    ));
                    assert!(matches!(
                        owner.popup_configuration_failure(second.unwrap()),
                        InitFailure::Operation(ProtocolError::StaleScope)
                    ));
                }
                ProofGuardCase::RequestedThenOwner => {
                    assert!(matches!(
                        classified,
                        InitFailure::Operation(ProtocolError::Cancelled)
                    ));
                }
                ProofGuardCase::DeadlineThenOwner => {
                    assert!(matches!(
                        classified,
                        InitFailure::Operation(ProtocolError::DeadlineExceeded)
                    ));
                }
                ProofGuardCase::OwnerThenDeadline => {
                    assert!(
                        matches!(classified, InitFailure::OwnedStop(proof) if proof.authorizes(&owner))
                    );
                }
                _ => unreachable!(),
            }
            // Direct negative probes never mutated custody or initialized the
            // popup. Let its still-held real producer observe exact retirement.
            owner.stop.send_replace(CancelSignal::OwnerRetirement);
        }
        gate.release();
        gate.wait_passed().await;
        let drained = tokio::time::timeout(Duration::from_secs(2), owner.drain()).await;
        let (failure, pending, proof_pending) = {
            let index = owner.index.lock().unwrap();
            (
                index.failure.clone(),
                index.pending_enrollment.len(),
                index.pending_eval_initialization.len(),
            )
        };
        let expected = match case {
            ProofGuardCase::Requested => Some(ProtocolError::Cancelled),
            ProofGuardCase::Deadline => Some(ProtocolError::DeadlineExceeded),
            _ => None,
        };
        let retained = if expected.is_none() {
            Some(
                owner
                    .targets
                    .retained_initialization_state_for_test("proof-stop-target"),
            )
        } else {
            None
        };
        let commands_after = {
            let commands = log.lock().unwrap();
            commands
                .iter()
                .filter(|r| r["sessionId"] == "proof-stop-popup")
                .map(|r| r["method"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        };
        let _ = owner.close().await;
        connection.close().await;
        server.abort();
        let _ = server.await;
        assert_eq!(failure, expected);
        assert_eq!(drained.unwrap(), expected.map_or(Ok(()), Err));
        assert_eq!((pending, proof_pending), (0, 0));
        if let Some(retained) = retained {
            // Only actual supervisor custody.stop_retired releases this retained
            // initializer without losing integrity. A generic Cancelled poisons.
            assert_eq!(retained, (false, Some(false), false));
        }
        assert!(!commands_after.iter().any(|m| m == "Target.setAutoAttach"));
        assert!(!commands_after
            .iter()
            .any(|m| m == "Runtime.runIfWaitingForDebugger"));
    }

    async fn bounded_proof_guard_case(case: ProofGuardCase) {
        tokio::time::timeout(Duration::from_secs(15), proof_guard_case(case))
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn popup_configuration_guard_owner_stop_releases_supervisor_custody_without_poison() {
        bounded_proof_guard_case(ProofGuardCase::Owner).await;
    }
    #[tokio::test]
    async fn popup_configuration_guard_requested_stop_remains_supervisor_failure() {
        bounded_proof_guard_case(ProofGuardCase::Requested).await;
    }
    #[tokio::test]
    async fn popup_configuration_guard_deadline_stop_remains_supervisor_deadline() {
        bounded_proof_guard_case(ProofGuardCase::Deadline).await;
    }
    #[tokio::test]
    async fn popup_configuration_guard_hard_errors_cannot_borrow_later_owner_stop() {
        bounded_proof_guard_case(ProofGuardCase::HardThenOwner).await;
    }
    #[tokio::test]
    async fn popup_configuration_guard_captured_requested_cannot_become_later_owner_stop() {
        bounded_proof_guard_case(ProofGuardCase::RequestedThenOwner).await;
    }
    #[tokio::test]
    async fn popup_configuration_guard_captured_deadline_cannot_become_later_owner_stop() {
        bounded_proof_guard_case(ProofGuardCase::DeadlineThenOwner).await;
    }
    #[tokio::test]
    async fn popup_configuration_guard_captured_owner_stop_precedes_expiry_and_later_deadline() {
        bounded_proof_guard_case(ProofGuardCase::OwnerThenDeadline).await;
    }
}
