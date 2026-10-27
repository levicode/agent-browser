//! Scripted-CDP constructor tests, not browser/interoperability conformance.
use super::*;
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Valid,
    WrongContext,
    ChangedAfterAttach,
    MissingContext,
    HoldBeforeIdentity,
    HoldAfterAttach,
    DisposeFailure,
    HoldPreparation,
}
struct Peer {
    commands: Arc<Mutex<Vec<Value>>>,
    held: mpsc::UnboundedReceiver<()>,
    release: mpsc::UnboundedSender<()>,
    task: tokio::task::JoinHandle<()>,
}
async fn peer(mode: Mode) -> (super::super::super::browser::BrowserManager, Peer) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let commands = Arc::new(Mutex::new(Vec::new()));
    let recorded = commands.clone();
    let (held_tx, held) = mpsc::unbounded_channel();
    let (release, mut released) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut context_reads = 0;
        let mut info_reads = 0;
        let mut pending: Option<Value> = None;
        loop {
            tokio::select! {
                Some(()) = released.recv(), if pending.is_some() => {
                    let response = pending.take().unwrap();
                    if socket.send(Message::Text(response.to_string().into())).await.is_err() { break; }
                }
                next = socket.next() => {
                    let Some(Ok(Message::Text(text))) = next else { break; };
                    let request: Value = serde_json::from_str(&text).unwrap();
                    recorded.lock().unwrap().push(request.clone());
                    let method = request["method"].as_str().unwrap();
                    let reply = match method {
                        "Target.getBrowserContexts" => {
                            context_reads += 1;
                            if context_reads == 1 || mode == Mode::MissingContext {
                                json!({"browserContextIds":["host-context"]})
                            } else { json!({"browserContextIds":["host-context","pw-context"]}) }
                        }
                        "Target.getTargetInfo" => {
                            info_reads += 1;
                            let context = if mode == Mode::WrongContext || (mode == Mode::ChangedAfterAttach && info_reads > 1) {
                                "host-context"
                            } else { "pw-context" };
                            json!({"targetInfo":{"targetId":"pw-page", "browserContextId":context,
                                "type":"page", "url":"about:blank"}})
                        }
                        "Target.attachToTarget" => json!({"sessionId":"native-session"}),
                        "Target.setAutoAttach" => {
                            assert_eq!(request["params"], json!({"autoAttach":false,"waitForDebuggerOnStart":false,"flatten":true}));
                            json!({})
                        }
                        "Target.detachFromTarget" | "Target.disposeBrowserContext" | "Browser.close" => json!({}),
                        other => panic!("constructor issued unexpected command {other}"),
                    };
                    let response = if mode == Mode::DisposeFailure && method == "Target.disposeBrowserContext" {
                        json!({"id":request["id"],"error":{"code":-32000,"message":"scripted disposal failure"}})
                    } else { json!({"id":request["id"],"result":reply}) };
                    let hold = (mode == Mode::HoldPreparation && method == "Target.getBrowserContexts" && context_reads == 1)
                        || (mode == Mode::HoldBeforeIdentity && method == "Target.getTargetInfo" && info_reads == 1)
                        || (mode == Mode::HoldAfterAttach && method == "Target.getBrowserContexts" && context_reads == 3);
                    if hold { pending = Some(response); let _ = held_tx.send(()); }
                    else if socket.send(Message::Text(response.to_string().into())).await.is_err() { break; }
                }
            }
        }
    });
    let manager =
        super::super::super::browser::BrowserManager::connect_owned_browser(&endpoint, None)
            .await
            .unwrap();
    (
        manager,
        Peer {
            commands,
            held,
            release,
            task,
        },
    )
}
fn operation() -> (watch::Sender<CancelSignal>, OperationLease) {
    let (cancel, cancellation) = watch::channel(CancelSignal::None);
    (
        cancel,
        OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 1,
            deadline: Instant::now() + Duration::from_secs(5),
            cancellation,
        },
    )
}
fn methods(peer: &Peer) -> Vec<String> {
    peer.commands
        .lock()
        .unwrap()
        .iter()
        .map(|v| v["method"].as_str().unwrap().to_owned())
        .collect()
}
async fn joined(peer: Peer) {
    tokio::time::timeout(Duration::from_secs(3), peer.task)
        .await
        .unwrap()
        .unwrap();
}
fn assert_no_host_destruction(peer: &Peer) {
    for request in peer.commands.lock().unwrap().iter() {
        assert_ne!(request["method"], "Browser.close");
        assert_ne!(request["method"], "Target.closeTarget");
        assert_ne!(request["method"], "Target.setAutoAttach");
        if request["method"] == "Target.disposeBrowserContext" {
            assert_eq!(request["params"]["browserContextId"], "pw-context");
        }
        assert!(!matches!(
            request["method"].as_str(),
            Some(
                "Target.createTarget"
                    | "Target.createBrowserContext"
                    | "Page.navigate"
                    | "Runtime.runIfWaitingForDebugger"
            )
        ));
    }
}

#[tokio::test]
async fn exact_fresh_context_adopts_reserved_page_without_creation_or_enrollment() {
    let (manager, peer) = peer(Mode::Valid).await;
    let (_cancel, op) = operation();
    let mut failed = None;
    let prepared = PreparedInteropBrowser::prepare(manager, &op, &mut failed)
        .await
        .unwrap();
    let mut owner = prepared
        .adopt("pw-context", "pw-page", &op, &mut failed)
        .await
        .unwrap();
    assert!(failed.is_none());
    assert!(owner.owns_context);
    assert!(owner.runtime.is_none());
    assert_eq!(owner.context_id, "pw-context");
    assert_eq!(owner.manager.active_target_id().unwrap(), "pw-page");
    assert_eq!(owner.manager.active_session_id().unwrap(), "native-session");
    let debt = owner.manager.client.debt_ledger().unwrap();
    assert_eq!(debt.bound_context().as_deref(), Some("pw-context"));
    assert!(debt.matches_owner(op.generation, &owner.identity_scope));
    // Adoption must not weaken the existing unpublished target guard.
    assert!(owner
        .manager
        .client
        .send_command(
            "Target.attachToTarget",
            Some(json!({"targetId":"foreign-page","flatten":true})),
            None
        )
        .await
        .is_err());
    owner.close().await.unwrap();
    assert_no_host_destruction(&peer);
    assert_eq!(
        methods(&peer)
            .iter()
            .filter(|m| *m == "Target.attachToTarget")
            .count(),
        1
    );
    assert_eq!(
        methods(&peer)
            .iter()
            .filter(|m| *m == "Target.disposeBrowserContext")
            .count(),
        1
    );
    joined(peer).await;
}

#[tokio::test]
async fn preexisting_or_wrong_or_missing_context_never_gains_destruction_authority() {
    for (mode, context, expected) in [
        (Mode::Valid, "host-context", ProtocolError::PolicyDenied),
        (Mode::WrongContext, "pw-context", ProtocolError::StaleScope),
        (
            Mode::MissingContext,
            "pw-context",
            ProtocolError::StaleScope,
        ),
    ] {
        let (manager, peer) = peer(mode).await;
        let (_cancel, op) = operation();
        let mut failed = None;
        let prepared = PreparedInteropBrowser::prepare(manager, &op, &mut failed)
            .await
            .unwrap();
        assert_eq!(
            prepared
                .adopt(context, "pw-page", &op, &mut failed)
                .await
                .err(),
            Some(expected)
        );
        let mut owner = failed.take().unwrap();
        assert!(!owner.owns_context);
        assert!(owner.context_id.is_empty());
        owner.close().await.unwrap();
        assert_no_host_destruction(&peer);
        assert!(!methods(&peer).contains(&"Target.attachToTarget".into()));
        assert!(!methods(&peer).contains(&"Target.disposeBrowserContext".into()));
        joined(peer).await;
    }
}

#[tokio::test]
async fn changed_target_after_attach_detaches_session_and_disposes_only_proven_new_context() {
    let (manager, peer) = peer(Mode::ChangedAfterAttach).await;
    let (_cancel, op) = operation();
    let mut failed = None;
    let prepared = PreparedInteropBrowser::prepare(manager, &op, &mut failed)
        .await
        .unwrap();
    assert_eq!(
        prepared
            .adopt("pw-context", "pw-page", &op, &mut failed)
            .await
            .err(),
        Some(ProtocolError::BrowserFailure)
    );
    let mut owner = failed.take().unwrap();
    assert!(owner.owns_context);
    owner.close().await.unwrap();
    assert_no_host_destruction(&peer);
    assert!(methods(&peer).contains(&"Target.detachFromTarget".into()));
    assert!(methods(&peer).contains(&"Target.disposeBrowserContext".into()));
    joined(peer).await;
}

#[tokio::test]
async fn cancellation_before_and_after_exact_identity_retains_original_cleanup_owner() {
    for mode in [Mode::HoldBeforeIdentity, Mode::HoldAfterAttach] {
        let (manager, mut peer) = peer(mode).await;
        let (cancel, op) = operation();
        let mut failed = None;
        let prepared = PreparedInteropBrowser::prepare(manager, &op, &mut failed)
            .await
            .unwrap();
        let task = tokio::spawn(async move {
            let mut failed = None;
            let error = prepared
                .adopt("pw-context", "pw-page", &op, &mut failed)
                .await
                .err();
            (error, failed.unwrap())
        });
        tokio::time::timeout(Duration::from_secs(2), peer.held.recv())
            .await
            .unwrap()
            .unwrap();
        cancel.send_replace(CancelSignal::Requested);
        let (error, mut owner) = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(error, Some(ProtocolError::Cancelled));
        assert_eq!(owner.owns_context, mode == Mode::HoldAfterAttach);
        // A late response has no remaining constructor future/publication owner.
        peer.release.send(()).unwrap();
        owner.close().await.unwrap();
        assert!(owner.runtime.is_none());
        assert_no_host_destruction(&peer);
        assert_eq!(
            methods(&peer).contains(&"Target.disposeBrowserContext".into()),
            mode == Mode::HoldAfterAttach
        );
        joined(peer).await;
    }
}

#[tokio::test]
async fn explicit_abort_and_changed_operation_are_transport_only_for_borrowed_browser() {
    for changed in [false, true] {
        let (manager, peer) = peer(Mode::Valid).await;
        let (_cancel, mut op) = operation();
        let mut failed = None;
        let prepared = PreparedInteropBrowser::prepare(manager, &op, &mut failed)
            .await
            .unwrap();
        let mut owner = if changed {
            op.sequence += 1;
            assert_eq!(
                prepared
                    .adopt("pw-context", "pw-page", &op, &mut failed)
                    .await
                    .err(),
                Some(ProtocolError::StaleScope)
            );
            failed.take().unwrap()
        } else {
            prepared.abort()
        };
        owner.close().await.unwrap();
        assert_no_host_destruction(&peer);
        assert_eq!(methods(&peer), ["Target.getBrowserContexts"]);
        joined(peer).await;
    }
}

#[test]
fn malformed_context_inventory_and_page_metadata_do_not_mint_ownership() {
    for value in [
        json!({}),
        json!({"browserContextIds":[""]}),
        json!({"browserContextIds":["same","same"]}),
        json!({"browserContextIds":[null]}),
    ] {
        assert!(contexts(&value).is_err());
    }
    let good = json!({"targetInfo":{"targetId":"page","browserContextId":"context","type":"page","url":"about:blank"}});
    assert!(verify_page(&good, "context", "page").is_ok());
    for key in ["targetId", "browserContextId", "type", "url"] {
        let mut value = good.clone();
        value["targetInfo"][key] = "different".into();
        assert!(verify_page(&value, "context", "page").is_err());
    }
    let mut subtype = good;
    subtype["targetInfo"]["subtype"] = "prerender".into();
    assert!(verify_page(&subtype, "context", "page").is_err());
}

#[tokio::test]
async fn cancelled_expired_or_callback_prepare_never_queries_or_deletes_host_resources() {
    for mode in [0, 1, 2] {
        let (manager, peer) = peer(Mode::Valid).await;
        let (cancel, mut op) = operation();
        let expected = match mode {
            0 => {
                cancel.send_replace(CancelSignal::Requested);
                ProtocolError::Cancelled
            }
            1 => {
                op.deadline = Instant::now() - Duration::from_millis(1);
                ProtocolError::DeadlineExceeded
            }
            _ => {
                op.is_callback = true;
                ProtocolError::InvalidArguments
            }
        };
        let mut failed = None;
        assert_eq!(
            PreparedInteropBrowser::prepare(manager, &op, &mut failed)
                .await
                .err(),
            Some(expected)
        );
        let mut owner = failed.take().unwrap();
        assert!(!owner.owns_context);
        owner.close().await.unwrap();
        assert!(methods(&peer).is_empty());
        joined(peer).await;
    }
}

#[path = "client_interop_preparation_tests.rs"]
mod custody_tests;

/// Scripted old scope disposal and phase-two ACKs, not fabricated cleanup flags.
async fn retained_manager(
    phase_two: bool,
) -> (
    super::super::super::browser::BrowserManager,
    Arc<super::super::super::client_debt::OwnerDebtLedger>,
    Peer,
) {
    retained_manager_with_mode(phase_two, Mode::Valid).await
}

async fn retained_manager_with_mode(
    phase_two: bool,
    mode: Mode,
) -> (
    super::super::super::browser::BrowserManager,
    Arc<super::super::super::client_debt::OwnerDebtLedger>,
    Peer,
) {
    let (mut manager, peer) = peer(mode).await;
    let (_cancel, op) = operation();
    let old = super::super::super::client_debt::OwnerDebtLedger::unpublished(
        &op,
        "old-scope".into(),
        true,
    )
    .unwrap();
    old.bind_context("old-context").unwrap();
    manager.bind_native_owner(old.clone()).unwrap();
    manager
        .client
        .send_command(
            "Target.disposeBrowserContext",
            Some(json!({"browserContextId":"old-context"})),
            None,
        )
        .await
        .unwrap();
    old.retire_after_context_destroy("old-context").unwrap();
    if phase_two {
        manager
            .client
            .send_owner_cleanup(
                Some(old.clone()),
                super::super::super::client_debt::OwnerCleanupCommand::DisableAutoAttach,
                op.deadline,
            )
            .await
            .unwrap();
    }
    (manager, old, peer)
}

mod replacement_tests {
    include!("client_interop_replacement_adoption_tests.rs");
}

#[tokio::test]
async fn retired_manager_reuse_keeps_transport_and_replaces_only_verified_owner() {
    let (manager, old, peer) = retained_manager(true).await;
    let old_client = manager.client.clone();
    assert!(old.replacement_ready());
    let (_cancel, mut op) = operation();
    op.sequence = 2;
    let mut failed = None;
    let prepared = PreparedInteropBrowser::prepare(manager, &op, &mut failed)
        .await
        .unwrap();
    assert!(old.replacement_ready());
    let mut owner = prepared
        .adopt("pw-context", "pw-page", &op, &mut failed)
        .await
        .unwrap();
    assert!(failed.is_none());
    assert!(!Arc::ptr_eq(&old_client, &owner.manager.client));
    assert!(old.replacement_ready());
    let debt = owner.manager.client.debt_ledger().unwrap();
    assert!(!Arc::ptr_eq(&old, &debt));
    assert_eq!(debt.bound_context().as_deref(), Some("pw-context"));
    debt.check_unpublished_operation(&op).unwrap();
    assert!(old_client
        .send_command("Target.getBrowserContexts", Some(json!({})), None)
        .await
        .is_err());
    assert!(owner
        .manager
        .client
        .send_command(
            "Target.attachToTarget",
            Some(json!({"targetId":"foreign-page","flatten":true})),
            None
        )
        .await
        .is_err());
    owner.close().await.unwrap();
    for request in peer.commands.lock().unwrap().iter() {
        assert!(!matches!(
            request["method"].as_str(),
            Some(
                "Browser.close"
                    | "Target.createBrowserContext"
                    | "Target.createTarget"
                    | "Page.navigate"
            )
        ));
        if request["method"] == "Target.disposeBrowserContext" {
            assert!(matches!(
                request["params"]["browserContextId"].as_str(),
                Some("old-context" | "pw-context")
            ));
        }
    }
    assert_eq!(
        methods(&peer)
            .iter()
            .filter(|method| *method == "Target.attachToTarget")
            .count(),
        1
    );
    joined(peer).await;
}

#[tokio::test]
async fn retired_manager_without_phase_two_refuses_reuse_without_clearing_debt() {
    let (manager, old, peer) = retained_manager(false).await;
    assert!(!old.replacement_ready());
    let old_client = manager.client.clone();
    let (_cancel, mut op) = operation();
    op.sequence = 2;
    let mut failed = None;
    assert_eq!(
        PreparedInteropBrowser::prepare(manager, &op, &mut failed)
            .await
            .err(),
        Some(ProtocolError::CleanupFailed)
    );
    let mut owner = failed.take().unwrap();
    assert!(Arc::ptr_eq(&old_client, &owner.manager.client));
    assert!(!methods(&peer).contains(&"Target.getBrowserContexts".to_owned()));
    assert!(!old.replacement_ready());
    // The original owner must still discharge its actual phase-two obligation.
    owner
        .manager
        .client
        .send_owner_cleanup(
            Some(old.clone()),
            super::super::super::client_debt::OwnerCleanupCommand::DisableAutoAttach,
            op.deadline,
        )
        .await
        .unwrap();
    assert!(old.replacement_ready());
    owner.close().await.unwrap();
    joined(peer).await;
}

#[tokio::test]
async fn reused_manager_inventory_cannot_adopt_a_preexisting_host_context() {
    let (manager, old, peer) = retained_manager(true).await;
    let (_cancel, mut op) = operation();
    op.sequence = 2;
    let mut failed = None;
    let prepared = PreparedInteropBrowser::prepare(manager, &op, &mut failed)
        .await
        .unwrap();
    assert_eq!(
        prepared
            .adopt("host-context", "pw-page", &op, &mut failed)
            .await
            .err(),
        Some(ProtocolError::PolicyDenied)
    );
    let mut owner = failed.take().unwrap();
    assert!(!owner.owns_context);
    assert!(old.replacement_ready());
    owner.close().await.unwrap();
    assert!(!methods(&peer).contains(&"Target.attachToTarget".to_owned()));
    for request in peer.commands.lock().unwrap().iter() {
        if request["method"] == "Target.disposeBrowserContext" {
            assert_eq!(request["params"]["browserContextId"], "old-context");
        }
        assert_ne!(request["method"], "Browser.close");
    }
    joined(peer).await;
}
