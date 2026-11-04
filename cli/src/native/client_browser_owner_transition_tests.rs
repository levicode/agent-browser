//! Managed-owner route replacement boundary. Execution belongs to central validation.
use super::*;
use crate::native::client_blobs::{BlobLimits, BlobScope, BlobStore};
use crate::native::client_debt::{OwnerCleanupCommand, OwnerDebtLedger};
use crate::native::client_network::{ClientNetwork, NetworkPolicy};
use crate::native::client_session::{CancelSignal, OperationLease};
use crate::native::client_transport::ClientEventSink;

fn copy_operation(operation: &OperationLease) -> OperationLease {
    OperationLease {
        is_callback: operation.is_callback,
        generation: operation.generation,
        sequence: operation.sequence,
        deadline: operation.deadline,
        cancellation: operation.cancellation.clone(),
    }
}

#[tokio::test]
async fn managed_context_replacement_transfers_routes_without_reusing_old_facade() {
    for registered_routes in [false, true] {
        let (endpoint, log, peer) = peer(true).await;
        let mut owner = OwnedBrowser::connect(&endpoint, None).await.unwrap();
        let old_scope = owner.identity_scope.clone();
        let old_context = owner.context_id.clone();
        let old = OwnerDebtLedger::new(1, old_scope.clone());
        old.bind_context(&old_context).unwrap();
        owner.manager.bind_native_owner(old.clone()).unwrap();
        let old_client = owner.manager.client.clone();
        let broker = Arc::new(ClientSession::new());
        let (sink, _events) = ClientEventSink::test_channel(broker.clone());
        let blobs = Arc::new(BlobStore::new(BlobLimits::default()).unwrap());
        let network = |client, scope| {
            Arc::new(ClientNetwork::new(
                client,
                broker.clone(),
                sink.clone(),
                BlobScope {
                    generation: 1,
                    identity_scope: scope,
                },
                blobs.clone(),
                Arc::new(crate::native::client_ui::UiGate::default()),
                NetworkPolicy::default(),
            ))
        };
        let source = network(old_client.clone(), old_scope);
        if registered_routes {
            source
                .replace_routes(1, vec!["retained-route".into()])
                .unwrap();
        }
        let (cancel, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 2,
            deadline: std::time::Instant::now() + Duration::from_secs(5),
            cancellation,
        };
        assert!(matches!(
            ReplacementLease::begin(&mut owner.manager, &operation),
            Err(ProtocolError::CleanupFailed)
        ));
        assert!(Arc::ptr_eq(&old_client, &owner.manager.client));
        let mut routes = source.capture_route_transfer(&operation).unwrap();
        source.close().await.unwrap();
        owner.dispose_context().await.unwrap();
        // Context destruction alone is not a complete prior-owner proof.
        assert!(matches!(
            ReplacementLease::begin(&mut owner.manager, &operation),
            Err(ProtocolError::CleanupFailed)
        ));
        owner
            .manager
            .client
            .send_owner_cleanup(
                Some(old.clone()),
                OwnerCleanupCommand::DisableAutoAttach,
                operation.deadline,
            )
            .await
            .unwrap();
        assert!(old.replacement_ready());
        // Exercise the actual manager-owned issuer, not an unmanaged fixture
        // that copies source.client into the replacement.
        let replacement = ReplacementLease::begin(&mut owner.manager, &operation).unwrap();
        let new_client = owner.manager.client.clone();
        assert!(!Arc::ptr_eq(&old_client, &new_client));
        let destination = network(new_client.clone(), replacement.identity_scope.clone());
        let check =
            |previous: &Arc<CdpClient>, next: &Arc<CdpClient>, scope: &str, op: &OperationLease| {
                replacement.check_route_replacement(previous, next, scope, op)
            };
        assert_eq!(
            check(
                &old_client,
                &new_client,
                &replacement.identity_scope,
                &operation
            ),
            Ok(())
        );
        assert_eq!(
            check(
                &new_client,
                &new_client,
                &replacement.identity_scope,
                &operation
            ),
            Err(ProtocolError::StaleScope)
        );
        assert_eq!(
            check(
                &old_client,
                &old_client,
                &replacement.identity_scope,
                &operation
            ),
            Err(ProtocolError::StaleScope)
        );
        let wrong_scope = network(new_client.clone(), "foreign-replacement".into());
        assert_eq!(
            routes.bind_replacement(&wrong_scope, &replacement, &operation),
            Err(ProtocolError::StaleScope)
        );
        for wrong in [
            "generation",
            "sequence",
            "deadline",
            "channel",
            "callback",
            "expired",
        ] {
            let mut candidate = copy_operation(&operation);
            let (_other_cancel, other_channel) = tokio::sync::watch::channel(CancelSignal::None);
            match wrong {
                "generation" => candidate.generation += 1,
                "sequence" => candidate.sequence += 1,
                "deadline" => candidate.deadline += Duration::from_millis(1),
                "channel" => candidate.cancellation = other_channel,
                "callback" => candidate.is_callback = true,
                "expired" => candidate.deadline = std::time::Instant::now(),
                _ => unreachable!(),
            }
            assert!(
                check(
                    &old_client,
                    &new_client,
                    &replacement.identity_scope,
                    &candidate
                )
                .is_err(),
                "replacement issuer accepted foreign {wrong}"
            );
            assert!(
                routes
                    .bind_replacement(&destination, &replacement, &candidate)
                    .is_err(),
                "route transfer accepted foreign {wrong}"
            );
        }
        // Even another facade of the exact same physical transport AND owner
        // ledger is not the destination captured at the replacement boundary.
        owner
            .manager
            .bind_native_owner(replacement.debt.clone())
            .unwrap();
        let alternate = owner.manager.client.clone();
        assert!(!Arc::ptr_eq(&new_client, &alternate));
        let alternate_network = network(alternate, replacement.identity_scope.clone());
        assert_eq!(
            routes.bind_replacement(&alternate_network, &replacement, &operation),
            Err(ProtocolError::StaleScope)
        );
        let bound = routes.bind_replacement(&destination, &replacement, &operation);
        let adopted = if bound.is_ok() {
            routes.adopt(&operation)
        } else {
            routes.retire().unwrap();
            bound.clone()
        };
        assert_eq!(
            routes.bind_replacement(&destination, &replacement, &operation),
            Err(ProtocolError::StaleScope)
        );
        let old_submission = old_client.reserve_tracked_command(
            "Runtime.evaluate",
            Some(&json!({"expression":"must_not_revive()","returnByValue":true})),
            Some("session-1"),
        );
        // Publication and cancellation cannot be turned into another transfer.
        replacement.debt.publish_initialization(|| Ok(())).unwrap();
        assert_eq!(
            check(
                &old_client,
                &new_client,
                &replacement.identity_scope,
                &operation
            ),
            Err(ProtocolError::InvalidSequence)
        );
        cancel.send_replace(CancelSignal::Requested);
        assert_eq!(
            check(
                &old_client,
                &new_client,
                &replacement.identity_scope,
                &operation
            ),
            Err(ProtocolError::Cancelled)
        );
        destination.close().await.unwrap();
        owner.manager.disconnect_transport().await;
        peer.await.unwrap();
        assert!(old_submission.is_err(), "old application facade revived");
        assert!(!log.lock().unwrap().iter().any(|request| {
            request["method"] == "Runtime.evaluate"
                && request["params"]["expression"] == "must_not_revive()"
        }));
        assert_eq!(
            bound,
            Ok(()),
            "route transfer rejected exact replacement facade"
        );
        assert_eq!(adopted, Ok(()));
    }
}
