//! Both public query purposes refuse unsupported/oversized compositions before browser facts or IDs.
use super::*;
use crate::native::cdp::client::CdpClient;
use crate::native::client_browser::ExecutionGate;
use crate::native::client_targets::ClientTargets;
use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::AtomicUsize;

#[tokio::test]
async fn unsupported_composition_never_dispatches_cdp_or_stages_references() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let commands = Arc::new(AtomicUsize::new(0));
    let observed = commands.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        while let Some(Ok(message)) = ws.next().await {
            let Ok(text) = message.to_text() else {
                continue;
            };
            let request: Value = serde_json::from_str(text).unwrap();
            observed.fetch_add(1, Ordering::SeqCst);
            // A regression receives a prompt failure instead of a test timeout.
            if ws.send(tokio_tungstenite::tungstenite::Message::Text(
                json!({"id":request["id"],"error":{"code":-32601,"message":"No CDP commands allowed"}}).to_string(),
            )).await.is_err() { break; }
        }
    });
    let client = Arc::new(CdpClient::connect(&endpoint).await.unwrap());
    let targets = ClientTargets::new("context".into(), "scope".into());
    targets
        .attached("context", "target".into(), "session".into(), "page".into())
        .unwrap();
    targets.configured("target").unwrap();
    targets
        .resume_permit("target")
        .await
        .unwrap()
        .complete()
        .unwrap();
    targets.acknowledge_enrollment().unwrap();
    let gate = Arc::new(ExecutionGate::default());
    let scope = BlobScope {
        generation: 1,
        identity_scope: "scope".into(),
    };
    let blobs = Arc::new(BlobStore::new(Default::default()).unwrap());
    blobs.activate_scope(scope.clone()).unwrap();
    let refs = Arc::new(Mutex::new(RefMap::new()));
    let before = {
        let refs = refs.lock().unwrap();
        (
            refs.ref_ids(),
            refs.retained_identity_counts(),
            refs.next_ref_num(),
        )
    };
    let dispatch = ObservationDispatch::new(refs.clone());
    let (_sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
    let mut sequence = 0;
    for purpose in [QueryPurpose::Fixture, QueryPurpose::Protected] {
        let refusals = observation::composition_tests::unsupported_expressions()
            .into_iter()
            .map(|expression| (expression, ProtocolError::UnsupportedCapability))
            .chain(std::iter::once((
                observation::composition_tests::oversized_expression(),
                ProtocolError::CapacityExceeded,
            )));
        for (expression, expected_error) in refusals {
            sequence += 1;
            let operation = OperationLease {
                generation: 1,
                sequence,
                is_callback: false,
                deadline: Instant::now() + Duration::from_secs(5),
                cancellation: cancellation.clone(),
            };
            let task = dispatch.clone().start(
                DispatchContext {
                    #[cfg(feature = "acceptance-faults")]
                    faults: Arc::new(super::super::client_test_faults::FaultController::default()),
                    attachment: targets.owned_target("target").unwrap(),
                    page: BrowserExecutionLease {
                        client: client.clone(),
                        page_session_id: "session".into(),
                        target_id: "target".into(),
                        identity_scope: "scope".into(),
                        permit: gate.enter(false).unwrap(),
                        targets: targets.clone(),
                    },
                    ui: Arc::new(UiGate::default()),
                    blobs: blobs.clone(),
                    scope: scope.clone(),
                    policy: ReadPolicy {
                        test_id_attribute: "data-testid".into(),
                        secure_field_selector: "input[type=password]".into(),
                    },
                },
                DispatchRequest::Query(QueryRequest {
                    purpose,
                    options: QueryOptions {
                        expression,
                        test_id_attribute: "data-testid".into(),
                        secure_field_selector: "input[type=password]".into(),
                    },
                }),
                operation,
            );
            let failure = task.result.await.unwrap().unwrap_err();
            task.join.await.unwrap().unwrap();
            assert_eq!(failure.error, expected_error);
            assert!(!failure.cleanup_integrity_lost);
            let after = {
                let refs = refs.lock().unwrap();
                (
                    refs.ref_ids(),
                    refs.retained_identity_counts(),
                    refs.next_ref_num(),
                )
            };
            assert_eq!(after, before);
            let publication = dispatch.publication.lock().await;
            assert_eq!(
                (
                    publication.revision,
                    publication.published_revision,
                    publication.observed_revision
                ),
                (0, 0, 0)
            );
            assert_eq!(commands.load(Ordering::SeqCst), 0);
        }
    }
    server.abort();
    let _ = server.await;
}
