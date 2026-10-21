//! Reconnect to exact retained native objects, never to an equivalent URL/page.
//! The lifecycle supervisor retains this future through settlement. Success is
//! an unpublished transport/page binding: central enrollment must install its
//! controls before publishing the new scope or retiring the old connection.
use std::future::Future;
use std::sync::Arc;
use std::time::Instant;

use serde_json::{json, Value};

use super::browser::BrowserManager;
use super::client_protocol::ProtocolError;
use super::client_session::{CancelSignal, OperationLease};

const MAX_ID_BYTES: usize = 1024;
const MAX_ENDPOINT_BYTES: usize = 16 * 1024;
const MAX_CONTEXTS: usize = 8192;

/// Captured from the retained native owner, not reconstructed from wire
/// fingerprints. The caller has already proved this is the default context.
/// Opaque browser-tenure fingerprints remain the lifecycle owner's authority.
#[derive(Debug)]
pub(super) struct RetainedIdentity {
    context_id: String,
    target_id: String,
}

impl RetainedIdentity {
    pub(super) fn capture(
        manager: &BrowserManager,
        context_id: &str,
    ) -> Result<Self, ProtocolError> {
        let target_id = manager
            .active_target_id()
            .map_err(|_| ProtocolError::StaleScope)?;
        valid_id(context_id).map_err(|_| ProtocolError::StaleScope)?;
        valid_id(target_id).map_err(|_| ProtocolError::StaleScope)?;
        Ok(Self {
            context_id: context_id.to_owned(),
            target_id: target_id.to_owned(),
        })
    }
}

/// Owns only the newly connected transport and its exact attached session.
/// This does not own the host browser, context, or page. On any subsequent
/// initialization/publication failure, await manager.client.close(), without
/// disposing the context or closing any host target. Keep the old owner until
/// its independent detach-only retirement has settled.
pub(super) struct VerifiedReconnect {
    pub(super) manager: BrowserManager,
    pub(super) context_id: String,
    pub(super) target_id: String,
    proof: VerifiedReconnectProof,
}

/// Non-wire authority retained after the manager moves into the lifecycle
/// journal. Only successful native reconnect verification can construct it.
pub(super) struct VerifiedReconnectProof {
    client: Arc<super::cdp::client::CdpClient>,
    context_id: String,
    target_id: String,
    session_id: String,
    generation: u64,
    sequence: u64,
    deadline: Instant,
    cancellation: tokio::sync::watch::Receiver<CancelSignal>,
}
impl VerifiedReconnect {
    pub(super) fn into_parts(self) -> (BrowserManager, String, String, VerifiedReconnectProof) {
        (self.manager, self.context_id, self.target_id, self.proof)
    }
}
impl VerifiedReconnectProof {
    pub(super) fn check(
        &self,
        client: &Arc<super::cdp::client::CdpClient>,
        context_id: &str,
        target_id: &str,
        operation: &OperationLease,
    ) -> Result<(), ProtocolError> {
        if operation.generation != self.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if operation.sequence != self.sequence
            || operation.deadline != self.deadline
            || !operation.cancellation.same_channel(&self.cancellation)
        {
            return Err(ProtocolError::InvalidSequence);
        }
        check_operation(operation)?;
        if !Arc::ptr_eq(client, &self.client)
            || context_id != self.context_id
            || target_id != self.target_id
            || self.session_id.is_empty()
            || *client.remote_connection_closed().borrow()
        {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }
}

/// Connect without page discovery, prove the retained default context/page,
/// then attach only that page. No creation, navigation, or action replay occurs.
/// Every network step uses the caller's original deadline and cancellation.
/// Failure closes only this function's new transport, including after an
/// uncertain attach acknowledgement. The old connection is never touched.
///
/// Browser identity is proved by exact retained lifetime context/target IDs,
/// not endpoint equality, document contents, tab order, version, or PID. A
/// browser-root Target ID is connection-local; websocket path tokens can be
/// rewritten/hidden by provider proxies. Neither is a universal browser UUID.
/// Transfer the retained private browser-tenure nonce only after this succeeds.
/// This is protocol identity under the same trusted CDP host, not protection
/// against a hostile server forging arbitrary protocol responses.
///
/// Target.getBrowserContexts may advertise an experimental optional
/// defaultBrowserContextId. If present it must match; absence does not discard
/// the stronger retained exact page/context proof. The original reconnect-only
/// dedicated-browser restriction still rejects any nondefault contexts.
///
/// Protocol/implementation sources:
/// https://raw.githubusercontent.com/ChromeDevTools/devtools-protocol/master/pdl/domains/Target.pdl
/// https://raw.githubusercontent.com/chromium/chromium/main/content/browser/browser_context_impl.h
/// https://raw.githubusercontent.com/chromium/chromium/main/content/browser/devtools/browser_devtools_agent_host.cc
pub(super) async fn reconnect(
    endpoint: &str,
    retained: &RetainedIdentity,
    operation: &OperationLease,
) -> Result<VerifiedReconnect, ProtocolError> {
    check_operation(operation)?;
    if endpoint.trim().is_empty() || endpoint.len() > MAX_ENDPOINT_BYTES || endpoint.contains('\0')
    {
        return Err(ProtocolError::InvalidArguments);
    }
    valid_id(&retained.context_id).map_err(|_| ProtocolError::StaleScope)?;
    valid_id(&retained.target_id).map_err(|_| ProtocolError::StaleScope)?;
    let mut manager = bounded(
        operation,
        BrowserManager::connect_owned_browser(endpoint, None),
    )
    .await?;
    let result = verify_and_attach(&mut manager, retained, operation).await;
    match result {
        Ok(session_id) => {
            // verify_and_attach checked this exact binding and operation after
            // the last protocol ACK. Moving the manager cannot forge the proof.
            let proof = VerifiedReconnectProof {
                client: manager.client.clone(),
                context_id: retained.context_id.clone(),
                target_id: retained.target_id.clone(),
                session_id,
                generation: operation.generation,
                sequence: operation.sequence,
                deadline: operation.deadline,
                cancellation: operation.cancellation.clone(),
            };
            Ok(VerifiedReconnect {
                manager,
                context_id: retained.context_id.clone(),
                target_id: retained.target_id.clone(),
                proof,
            })
        }
        Err(error) => {
            // Unconditional, awaited, transport-only containment, independent
            // of the expired operation budget. CdpClient::close bounds its
            // socket/task teardown internally. Never invoke host close methods.
            manager.client.close().await;
            Err(error)
        }
    }
}

async fn verify_and_attach(
    manager: &mut BrowserManager,
    retained: &RetainedIdentity,
    operation: &OperationLease,
) -> Result<String, ProtocolError> {
    if manager.has_pages() {
        return Err(ProtocolError::StaleScope);
    }
    verify_contexts(manager, retained, operation).await?;
    verify_page(manager, retained, operation).await?;
    // This is a strict bind only. Central ClientEnrollment owns domain hooks,
    // autoattach, policy application, and resume after reconnect verification.
    bounded(
        operation,
        manager.adopt_verified_page(&retained.target_id, &retained.context_id),
    )
    .await?;
    // Recheck after attachment so changes during the handshake cannot publish
    // the earlier proof. Missing original page never triggers replacement.
    verify_contexts(manager, retained, operation).await?;
    verify_page(manager, retained, operation).await?;
    if manager
        .active_target_id()
        .map_err(|_| ProtocolError::StaleScope)?
        != retained.target_id
    {
        return Err(ProtocolError::StaleScope);
    }
    let session_id = manager
        .active_session_id()
        .map_err(|_| ProtocolError::StaleScope)?;
    valid_id(session_id)?;
    check_operation(operation)?;
    Ok(session_id.to_owned())
}

async fn verify_contexts(
    manager: &BrowserManager,
    retained: &RetainedIdentity,
    operation: &OperationLease,
) -> Result<(), ProtocolError> {
    let result = bounded(
        operation,
        manager
            .client
            .send_command("Target.getBrowserContexts", Some(json!({})), None),
    )
    .await?;
    dedicated_default_context(&result, &retained.context_id)
}

/// Preserve the legacy cdp-recovery.ts attachPersistent reconnect restriction.
/// This predicate intentionally differs from initial persistent attachment,
/// which can prove the default context without rejecting unrelated contexts.
fn dedicated_default_context(value: &Value, expected_context: &str) -> Result<(), ProtocolError> {
    let contexts = value
        .get("browserContextIds")
        .and_then(Value::as_array)
        .ok_or(ProtocolError::BrowserFailure)?;
    if contexts.len() > MAX_CONTEXTS {
        return Err(ProtocolError::CapacityExceeded);
    }
    for context in contexts {
        valid_id(context.as_str().ok_or(ProtocolError::BrowserFailure)?)?;
    }
    if !contexts.is_empty() {
        return Err(ProtocolError::PolicyDenied);
    }
    if let Some(default_context) = value.get("defaultBrowserContextId") {
        let default_context = default_context
            .as_str()
            .ok_or(ProtocolError::BrowserFailure)?;
        valid_id(default_context)?;
        if default_context != expected_context {
            return Err(ProtocolError::StaleScope);
        }
    }
    Ok(())
}

async fn verify_page(
    manager: &BrowserManager,
    retained: &RetainedIdentity,
    operation: &OperationLease,
) -> Result<(), ProtocolError> {
    let result = bounded(
        operation,
        manager.client.send_command(
            "Target.getTargetInfo",
            Some(json!({"targetId": retained.target_id})),
            None,
        ),
    )
    .await?;
    exact_page(&result, retained)
}

fn exact_page(value: &Value, retained: &RetainedIdentity) -> Result<(), ProtocolError> {
    let info = value
        .get("targetInfo")
        .ok_or(ProtocolError::BrowserFailure)?;
    let target = info
        .get("targetId")
        .and_then(Value::as_str)
        .ok_or(ProtocolError::BrowserFailure)?;
    let context = info
        .get("browserContextId")
        .and_then(Value::as_str)
        .ok_or(ProtocolError::BrowserFailure)?;
    valid_id(target)?;
    valid_id(context)?;
    if target != retained.target_id
        || context != retained.context_id
        || info.get("type").and_then(Value::as_str) != Some("page")
        || info.get("subtype").is_some()
    {
        return Err(ProtocolError::StaleScope);
    }
    Ok(())
}

fn valid_id(id: &str) -> Result<(), ProtocolError> {
    if id.is_empty() || id.len() > MAX_ID_BYTES || id.contains('\0') {
        Err(ProtocolError::BrowserFailure)
    } else {
        Ok(())
    }
}

fn check_operation(operation: &OperationLease) -> Result<(), ProtocolError> {
    if operation.is_callback {
        return Err(ProtocolError::InvalidArguments);
    }
    if *operation.cancellation.borrow() != CancelSignal::None {
        return Err(ProtocolError::Cancelled);
    }
    if Instant::now() >= operation.deadline {
        return Err(ProtocolError::DeadlineExceeded);
    }
    Ok(())
}

async fn bounded<T>(
    operation: &OperationLease,
    work: impl Future<Output = Result<T, String>>,
) -> Result<T, ProtocolError> {
    check_operation(operation)?;
    let mut cancellation = operation.cancellation.clone();
    tokio::select! {
        biased;
        _ = cancellation.changed() => Err(ProtocolError::Cancelled),
        _ = tokio::time::sleep_until(operation.deadline.into()) => Err(ProtocolError::DeadlineExceeded),
        result = work => result.map_err(|_| ProtocolError::BrowserFailure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::{mpsc, watch};
    use tokio::task::JoinHandle;
    use tokio_tungstenite::tungstenite::Message;

    fn retained() -> RetainedIdentity {
        RetainedIdentity {
            context_id: "original-default-context".into(),
            target_id: "original-page".into(),
        }
    }

    fn page() -> Value {
        json!({"targetInfo":{"targetId":"original-page","type":"page","browserContextId":"original-default-context"}})
    }

    fn operation(timeout: Duration) -> (OperationLease, watch::Sender<CancelSignal>) {
        let (send, cancellation) = watch::channel(CancelSignal::None);
        (
            OperationLease {
                is_callback: false,
                generation: 1,
                sequence: 1,
                deadline: Instant::now() + timeout,
                cancellation,
            },
            send,
        )
    }

    #[test]
    fn reconnect_optional_default_metadata_still_requires_dedicated_context() {
        for value in [
            json!({"browserContextIds":[]}),
            json!({"browserContextIds":[],"defaultBrowserContextId":"original-default-context"}),
        ] {
            assert_eq!(
                dedicated_default_context(&value, &retained().context_id),
                Ok(())
            );
        }
        // Source contract: packages/web/src/cdp-recovery.ts attachPersistent
        // rejects every nondefault context on reconnect, never closes it.
        assert_eq!(
            dedicated_default_context(
                &json!({"browserContextIds":["unrelated-incognito"]}),
                &retained().context_id,
            ),
            Err(ProtocolError::PolicyDenied)
        );
        assert_eq!(
            dedicated_default_context(
                &json!({"browserContextIds":[],"defaultBrowserContextId":"different-default"}),
                &retained().context_id,
            ),
            Err(ProtocolError::StaleScope)
        );
        for value in [
            json!({}),
            json!({"browserContextIds":null}),
            json!({"browserContextIds":[null]}),
            json!({"browserContextIds":[],"defaultBrowserContextId":null}),
            json!({"browserContextIds":[],"defaultBrowserContextId":""}),
        ] {
            assert!(dedicated_default_context(&value, &retained().context_id).is_err());
        }
    }

    #[test]
    fn reconnect_page_proof_requires_exact_native_ids_not_page_contents() {
        assert_eq!(exact_page(&page(), &retained()), Ok(()));
        for field in ["targetId", "browserContextId", "type", "subtype"] {
            let mut value = page();
            value["targetInfo"][field] = "different".into();
            assert_eq!(
                exact_page(&value, &retained()),
                Err(ProtocolError::StaleScope)
            );
        }
        for field in ["targetId", "browserContextId"] {
            let mut value = page();
            value["targetInfo"].as_object_mut().unwrap().remove(field);
            assert_eq!(
                exact_page(&value, &retained()),
                Err(ProtocolError::BrowserFailure)
            );
        }
        let mut value = page();
        value["targetInfo"]["url"] = "https://new-document.invalid/".into();
        value["targetInfo"]["title"] = "A different title".into();
        assert_eq!(exact_page(&value, &retained()), Ok(()));
        value["targetInfo"]["subtype"] = Value::Null;
        assert_eq!(
            exact_page(&value, &retained()),
            Err(ProtocolError::StaleScope)
        );
    }

    #[test]
    fn reconnect_identity_inputs_are_bounded() {
        assert!(valid_id("").is_err());
        assert!(valid_id("nul\0suffix").is_err());
        assert!(valid_id(&"a".repeat(MAX_ID_BYTES + 1)).is_err());
        assert_eq!(
            dedicated_default_context(
                &json!({"browserContextIds":vec!["id"; MAX_CONTEXTS + 1]}),
                "default",
            ),
            Err(ProtocolError::CapacityExceeded)
        );
    }

    struct Fixture {
        contexts: VecDeque<Value>,
        pages: VecDeque<Value>,
        fail_method: Option<&'static str>,
        hold_method: Option<&'static str>,
    }

    impl Default for Fixture {
        fn default() -> Self {
            Self {
                contexts: VecDeque::from([json!({"browserContextIds":[]})]),
                pages: VecDeque::from([page()]),
                fail_method: None,
                hold_method: None,
            }
        }
    }

    type Commands = Arc<Mutex<Vec<Value>>>;

    struct Server {
        endpoint: String,
        commands: Commands,
        received: mpsc::UnboundedReceiver<String>,
        task: JoinHandle<()>,
    }

    fn next_or_last(values: &mut VecDeque<Value>) -> Value {
        if values.len() > 1 {
            values.pop_front().unwrap()
        } else {
            values.front().unwrap().clone()
        }
    }

    async fn server(mut fixture: Fixture, path: &str) -> Server {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}{}", listener.local_addr().unwrap(), path);
        let commands = Arc::new(Mutex::new(Vec::new()));
        let observed = commands.clone();
        let (send, received) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(message) = socket.next().await {
                let message = match message {
                    Ok(Message::Text(message)) => message,
                    Ok(Message::Close(_)) | Err(_) => break,
                    _ => continue,
                };
                let command: Value = serde_json::from_str(&message).unwrap();
                observed.lock().unwrap().push(command.clone());
                let method = command["method"].as_str().unwrap();
                let _ = send.send(method.to_owned());
                if fixture.hold_method == Some(method) {
                    continue;
                }
                let response = if fixture.fail_method == Some(method) {
                    json!({"id":command["id"],"error":{"code":-32000,"message":"synthetic missing target or transport failure"}})
                } else {
                    let result = match method {
                        "Target.getBrowserContexts" => next_or_last(&mut fixture.contexts),
                        "Target.getTargetInfo" => next_or_last(&mut fixture.pages),
                        "Target.attachToTarget" => json!({"sessionId":"exact-new-session"}),
                        _ => json!({}),
                    };
                    json!({"id":command["id"],"result":result})
                };
                if socket
                    .send(Message::Text(response.to_string()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Server {
            endpoint,
            commands,
            received,
            task,
        }
    }

    #[tokio::test]
    async fn reconnect_proof_survives_manager_move_but_rejects_other_identity_or_operation() {
        let source_server = server(Fixture::default(), "/proof").await;
        let (operation, cancel) = operation(Duration::from_secs(5));
        let verified = reconnect(&source_server.endpoint, &retained(), &operation)
            .await
            .unwrap();
        let (manager, context, target, proof) = verified.into_parts();
        assert_eq!(
            proof.check(&manager.client, &context, &target, &operation),
            Ok(())
        );
        assert_eq!(
            proof.check(&manager.client, "different", &target, &operation),
            Err(ProtocolError::StaleScope)
        );
        assert_eq!(
            proof.check(&manager.client, &context, "different", &operation),
            Err(ProtocolError::StaleScope)
        );
        let (_send, cancellation) = watch::channel(CancelSignal::None);
        let mut other_operation = OperationLease {
            is_callback: false,
            generation: operation.generation,
            sequence: operation.sequence,
            deadline: operation.deadline,
            cancellation,
        };
        assert_eq!(
            proof.check(&manager.client, &context, &target, &other_operation),
            Err(ProtocolError::InvalidSequence)
        );
        other_operation.cancellation = operation.cancellation.clone();
        other_operation.generation = 2;
        assert_eq!(
            proof.check(&manager.client, &context, &target, &other_operation),
            Err(ProtocolError::StaleGeneration)
        );
        let foreign_server = server(Fixture::default(), "/foreign").await;
        let foreign_client = Arc::new(
            super::super::cdp::client::CdpClient::connect(&foreign_server.endpoint)
                .await
                .unwrap(),
        );
        assert_eq!(
            proof.check(&foreign_client, &context, &target, &operation),
            Err(ProtocolError::StaleScope)
        );
        foreign_client.close().await;
        finish(foreign_server).await;
        cancel.send_replace(CancelSignal::Requested);
        assert_eq!(
            proof.check(&manager.client, &context, &target, &operation),
            Err(ProtocolError::Cancelled)
        );
        manager.client.close().await;
        finish(source_server).await;
    }

    async fn finish(server: Server) -> Vec<Value> {
        tokio::time::timeout(Duration::from_secs(3), server.task)
            .await
            .expect("reconnect must close its new transport")
            .unwrap();
        let commands = server.commands.lock().unwrap().clone();
        assert!(!commands.iter().any(|command| matches!(
            command["method"].as_str(),
            Some(
                "Browser.close"
                    | "Target.createBrowserContext"
                    | "Target.disposeBrowserContext"
                    | "Target.createTarget"
                    | "Target.closeTarget"
                    | "Target.getTargets"
                    | "Page.navigate"
                    | "Runtime.evaluate"
                    | "Page.enable"
                    | "Runtime.enable"
                    | "Network.enable"
                    | "Target.setAutoAttach"
                    | "Runtime.runIfWaitingForDebugger"
            )
        )));
        for command in &commands {
            if matches!(
                command["method"].as_str(),
                Some("Target.getTargetInfo" | "Target.attachToTarget")
            ) {
                assert_eq!(command["params"]["targetId"], "original-page");
            }
        }
        commands
    }

    #[tokio::test]
    async fn reconnect_alias_preserves_exact_objects_and_old_transport() {
        let old = server(Fixture::default(), "/devtools/browser/old-proxy-token").await;
        let mut manager = BrowserManager::connect_owned_browser(&old.endpoint, None)
            .await
            .unwrap();
        manager
            .adopt_verified_page("original-page", "original-default-context")
            .await
            .unwrap();
        let identity = RetainedIdentity::capture(&manager, "original-default-context").unwrap();
        let new = server(
            Fixture::default(),
            "/devtools/browser/different-proxy-token?lease=new",
        )
        .await;
        let (operation, _cancel) = operation(Duration::from_secs(3));
        let verified = reconnect(&new.endpoint, &identity, &operation)
            .await
            .unwrap();
        assert_eq!(verified.context_id, "original-default-context");
        assert_eq!(verified.target_id, "original-page");
        assert_eq!(
            verified.manager.active_target_id().unwrap(),
            "original-page"
        );
        assert!(!old.task.is_finished());
        manager
            .client
            .send_command_no_params("Browser.getVersion", None)
            .await
            .unwrap();
        verified.manager.client.close().await;
        let commands = finish(new).await;
        assert_eq!(
            commands
                .iter()
                .filter(|c| c["method"] == "Target.attachToTarget")
                .count(),
            1
        );
        manager.client.close().await;
        finish(old).await;
    }

    #[tokio::test]
    async fn reconnect_rejects_wrong_objects_or_incognito_without_adoption() {
        let mut mismatch = page();
        mismatch["targetInfo"]["browserContextId"] = "other-context".into();
        let mut replacement = page();
        replacement["targetInfo"]["targetId"] = "replacement-page".into();
        for fixture in [
            Fixture {
                pages: VecDeque::from([mismatch]),
                ..Default::default()
            },
            Fixture {
                pages: VecDeque::from([replacement]),
                ..Default::default()
            },
            Fixture {
                contexts: VecDeque::from([json!({"browserContextIds":["unrelated-incognito"]})]),
                ..Default::default()
            },
            Fixture {
                contexts: VecDeque::from([
                    json!({"browserContextIds":[],"defaultBrowserContextId":"other-default"}),
                ]),
                ..Default::default()
            },
            Fixture {
                fail_method: Some("Target.getTargetInfo"),
                ..Default::default()
            },
        ] {
            let server = server(fixture, "/new").await;
            let (operation, _cancel) = operation(Duration::from_secs(3));
            assert!(reconnect(&server.endpoint, &retained(), &operation)
                .await
                .is_err());
            let commands = finish(server).await;
            assert!(!commands
                .iter()
                .any(|c| c["method"] == "Target.attachToTarget"));
        }
    }

    #[tokio::test]
    async fn reconnect_rechecks_identity_and_dedicated_context_after_attachment() {
        let mut mismatch = page();
        mismatch["targetInfo"]["browserContextId"] = "changed-context".into();
        for fixture in [
            // First proof, strict adopt's proof, then final proof.
            Fixture {
                pages: VecDeque::from([page(), page(), mismatch]),
                ..Default::default()
            },
            Fixture {
                contexts: VecDeque::from([
                    json!({"browserContextIds":[]}),
                    json!({"browserContextIds":["late-incognito"]}),
                ]),
                ..Default::default()
            },
        ] {
            let server = server(fixture, "/new").await;
            let (operation, _cancel) = operation(Duration::from_secs(3));
            assert!(reconnect(&server.endpoint, &retained(), &operation)
                .await
                .is_err());
            let commands = finish(server).await;
            assert_eq!(
                commands
                    .iter()
                    .filter(|c| c["method"] == "Target.attachToTarget")
                    .count(),
                1
            );
        }
    }

    #[tokio::test]
    async fn reconnect_deadline_closes_transport_without_replacing_missing_page() {
        let server = server(
            Fixture {
                hold_method: Some("Target.getTargetInfo"),
                ..Default::default()
            },
            "/new",
        )
        .await;
        let (operation, _cancel) = operation(Duration::from_millis(100));
        assert!(matches!(
            reconnect(&server.endpoint, &retained(), &operation).await,
            Err(ProtocolError::DeadlineExceeded)
        ));
        let commands = finish(server).await;
        assert!(!commands
            .iter()
            .any(|c| c["method"] == "Target.attachToTarget"));
    }

    #[tokio::test]
    async fn reconnect_cancelled_uncertain_attach_closes_only_new_transport() {
        let mut server = server(
            Fixture {
                hold_method: Some("Target.attachToTarget"),
                ..Default::default()
            },
            "/new",
        )
        .await;
        let (operation, cancel) = operation(Duration::from_secs(3));
        let endpoint = server.endpoint.clone();
        let attempt =
            tokio::spawn(async move { reconnect(&endpoint, &retained(), &operation).await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while server
                .received
                .recv()
                .await
                .expect("synthetic server closed")
                != "Target.attachToTarget"
            {}
        })
        .await
        .unwrap();
        cancel.send(CancelSignal::Requested).unwrap();
        assert!(matches!(
            attempt.await.unwrap(),
            Err(ProtocolError::Cancelled)
        ));
        let commands = finish(server).await;
        assert_eq!(
            commands
                .iter()
                .filter(|c| c["method"] == "Target.attachToTarget")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn reconnect_rejects_cancelled_expired_and_callback_before_connecting() {
        let (mut operation, cancel) = operation(Duration::from_secs(3));
        cancel.send(CancelSignal::Requested).unwrap();
        assert!(matches!(
            reconnect("ws://127.0.0.1:1", &retained(), &operation).await,
            Err(ProtocolError::Cancelled)
        ));
        cancel.send(CancelSignal::None).unwrap();
        operation.deadline = Instant::now();
        assert!(matches!(
            reconnect("ws://127.0.0.1:1", &retained(), &operation).await,
            Err(ProtocolError::DeadlineExceeded)
        ));
        operation.deadline = Instant::now() + Duration::from_secs(3);
        operation.is_callback = true;
        assert!(matches!(
            reconnect("ws://127.0.0.1:1", &retained(), &operation).await,
            Err(ProtocolError::InvalidArguments)
        ));
    }
}
