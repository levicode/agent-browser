//! Exact default-context attachment without owning the host browser or pages.
//! Optional default-context metadata is used when available. Otherwise, only a
//! newly created default-context blank can prove the real BrowserContextID.
use std::collections::HashSet;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::browser::BrowserManager;
use super::cdp::client::CdpClient;
use super::client_enrollment::ScopeOwnership;
use super::client_protocol::ProtocolError;

const PREPARE_TIMEOUT: Duration = Duration::from_secs(30);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_TARGETS: usize = 8192;
const MAX_ID_BYTES: usize = 1024;

/// A retained lifecycle owner must keep this journal until publication or
/// explicitly awaited cleanup. Dropping it does not perform asynchronous work.
#[derive(Debug, Default)]
pub(super) struct OwnedProbeJournal {
    state: ProbeState,
}

#[derive(Debug, Default)]
enum ProbeState {
    #[default]
    Empty,
    CreationUncertain,
    Created(String),
    CloseUncertain(String),
}

impl OwnedProbeJournal {
    pub(super) fn exact_target_id(&self) -> Option<&str> {
        match &self.state {
            ProbeState::Created(id) | ProbeState::CloseUncertain(id) => Some(id),
            ProbeState::Empty | ProbeState::CreationUncertain => None,
        }
    }

    pub(super) fn creation_uncertain(&self) -> bool {
        matches!(self.state, ProbeState::CreationUncertain)
    }

    pub(super) fn close_uncertain(&self) -> bool {
        matches!(self.state, ProbeState::CloseUncertain(_))
    }

    /// Transfer only the exact newly created initial page to persistent host
    /// lifetime after successful publication. Subsequent cleanup is detach-only.
    pub(super) fn commit(&mut self, selected_target: &str) -> Result<(), ProtocolError> {
        match &self.state {
            ProbeState::Empty => Ok(()),
            ProbeState::Created(id) if id == selected_target => {
                self.state = ProbeState::Empty;
                Ok(())
            }
            _ => Err(ProtocolError::CleanupFailed),
        }
    }

    /// Close only an acknowledged synthetic target created by this attempt.
    /// Journal before dispatch; an uncertain outcome is never blindly retried or
    /// rewritten as success merely because the browser transport disconnects.
    pub(super) async fn cleanup(&mut self, client: &CdpClient) -> Result<(), ProtocolError> {
        let target_id = match &self.state {
            ProbeState::Empty => return Ok(()),
            ProbeState::Created(id) => id.clone(),
            ProbeState::CreationUncertain | ProbeState::CloseUncertain(_) => {
                return Err(ProtocolError::CleanupFailed);
            }
        };
        self.state = ProbeState::CloseUncertain(target_id.clone());
        let result = tokio::time::timeout(
            CLEANUP_TIMEOUT,
            client.send_command(
                "Target.closeTarget",
                Some(json!({"targetId": target_id})),
                None,
            ),
        )
        .await
        .map_err(|_| ProtocolError::CleanupFailed)?
        .map_err(|_| ProtocolError::CleanupFailed)?;
        if result.get("success").and_then(Value::as_bool) != Some(true) {
            return Err(ProtocolError::CleanupFailed);
        }
        self.state = ProbeState::Empty;
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct PersistentAttachment {
    pub(super) context_id: String,
    pub(super) target_id: String,
    /// Nonempty only when this attempt created the initial blank page. Retain
    /// through runtime initialization, then commit immediately upon publication.
    pub(super) probe: OwnedProbeJournal,
}

impl PersistentAttachment {
    /// Only the exact root is borrowed. Enrollment may subsequently authorize
    /// same-context descendants through proven opener/parent-session ancestry.
    pub(super) fn ownership(&self) -> ScopeOwnership {
        ScopeOwnership::BorrowedTargets(vec![self.target_id.clone()])
    }
}

#[derive(Debug)]
pub(super) struct PersistentAttachFailure {
    pub(super) error: ProtocolError,
    /// Keep unresolved target identity/dispatch evidence in lifecycle state.
    pub(super) probe: OwnedProbeJournal,
}

/// Call only from a retained startup supervisor, with an unadopted external
/// BrowserManager. The caller must disconnect on failure and retain unresolved
/// probe evidence; connection close alone cannot prove deletion of a new page.
///
/// This helper does not navigate an existing host page, dispose a context, close
/// the host browser, or configure downloads. The owner installs runtime hooks
/// before navigating the selected page to about:blank. Provider downloads remain
/// context-level allowAndName using the proven context ID; detach does not claim
/// restoration of arbitrary preexisting host policy.
///
/// Protocol sources:
/// https://raw.githubusercontent.com/ChromeDevTools/devtools-protocol/master/pdl/domains/Target.pdl
/// https://raw.githubusercontent.com/chromium/chromium/main/content/browser/devtools/protocol/target_handler.cc
pub(super) async fn prepare_persistent(
    manager: &mut BrowserManager,
) -> Result<PersistentAttachment, PersistentAttachFailure> {
    prepare_before(manager, Instant::now() + PREPARE_TIMEOUT).await
}

async fn prepare_before(
    manager: &mut BrowserManager,
    deadline: Instant,
) -> Result<PersistentAttachment, PersistentAttachFailure> {
    let mut probe = OwnedProbeJournal::default();
    let result = prepare_with_journal(manager, &mut probe, deadline).await;
    match result {
        Ok((context_id, target_id)) => Ok(PersistentAttachment {
            context_id,
            target_id,
            probe,
        }),
        Err(error) => {
            let error = if probe.cleanup(&manager.client).await.is_err() {
                ProtocolError::CleanupFailed
            } else {
                error
            };
            Err(PersistentAttachFailure { error, probe })
        }
    }
}

async fn prepare_with_journal(
    manager: &mut BrowserManager,
    probe: &mut OwnedProbeJournal,
    deadline: Instant,
) -> Result<(String, String), ProtocolError> {
    // Refuse to repurpose a manager that has already adopted host targets.
    if manager.has_pages() {
        return Err(ProtocolError::InvalidArguments);
    }
    let contexts = command(
        &manager.client,
        "Target.getBrowserContexts",
        json!({}),
        deadline,
    )
    .await?;
    let advertised_context = default_context(&contexts)?;
    let targets = command(
        &manager.client,
        "Target.getTargets",
        json!({"filter":[{"type":"browser","exclude":true},{"type":"tab","exclude":true},{}]}),
        deadline,
    )
    .await?;
    let inventory = Inventory::parse(&targets)?;
    let selected = advertised_context
        .as_deref()
        .and_then(|context| inventory.page_in(context));
    let (context_id, target_id) = match (advertised_context, selected) {
        (Some(context), Some(target)) => (context, target),
        (advertised, None) => {
            // This request's omitted browserContextId selects the default
            // context. Never infer it by subtracting getBrowserContexts IDs,
            // and never use the returned targetId as a browserContextId.
            if Instant::now() >= deadline {
                return Err(ProtocolError::DeadlineExceeded);
            }
            probe.state = ProbeState::CreationUncertain;
            let created = command(
                &manager.client,
                "Target.createTarget",
                json!({"url":"about:blank","background":true}),
                deadline,
            )
            .await?;
            let created_id = id(&created, "targetId")?.to_owned();
            // A faulty host must never cause cleanup to close a known preexisting
            // target. Its inconsistent create ACK leaves the outcome uncertain.
            if inventory.target_ids.contains(&created_id) {
                return Err(ProtocolError::BrowserFailure);
            }
            probe.state = ProbeState::Created(created_id.clone());
            let info = command(
                &manager.client,
                "Target.getTargetInfo",
                json!({"targetId": created_id}),
                deadline,
            )
            .await?;
            let context = probe_context(&info, &created_id)?;
            if advertised.as_ref().is_some_and(|id| id != &context) {
                return Err(ProtocolError::PolicyDenied);
            }
            match inventory.page_in(&context) {
                Some(existing) => {
                    // The probe has served its sole purpose. Contain it before
                    // attaching any preexisting host page.
                    probe.cleanup(&manager.client).await?;
                    (context, existing)
                }
                None => (context, created_id),
            }
        }
        (None, Some(_)) => return Err(ProtocolError::BrowserFailure),
    };
    if Instant::now() >= deadline {
        return Err(ProtocolError::DeadlineExceeded);
    }
    tokio::time::timeout_at(
        deadline.into(),
        manager.adopt_verified_page(&target_id, &context_id),
    )
    .await
    .map_err(|_| ProtocolError::DeadlineExceeded)?
    .map_err(|_| ProtocolError::BrowserFailure)?;
    Ok((context_id, target_id))
}

async fn command(
    client: &CdpClient,
    method: &str,
    params: Value,
    deadline: Instant,
) -> Result<Value, ProtocolError> {
    if Instant::now() >= deadline {
        return Err(ProtocolError::DeadlineExceeded);
    }
    tokio::time::timeout_at(
        deadline.into(),
        client.send_command(method, Some(params), None),
    )
    .await
    .map_err(|_| ProtocolError::DeadlineExceeded)?
    .map_err(|_| ProtocolError::BrowserFailure)
}

fn id<'a>(value: &'a Value, field: &str) -> Result<&'a str, ProtocolError> {
    let id = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ProtocolError::BrowserFailure)?;
    validate_id(id)?;
    Ok(id)
}

fn validate_id(id: &str) -> Result<(), ProtocolError> {
    if id.is_empty() || id.len() > MAX_ID_BYTES || id.contains('\0') {
        Err(ProtocolError::BrowserFailure)
    } else {
        Ok(())
    }
}

fn default_context(value: &Value) -> Result<Option<String>, ProtocolError> {
    let contexts = value
        .get("browserContextIds")
        .and_then(Value::as_array)
        .ok_or(ProtocolError::BrowserFailure)?;
    if contexts.len() > MAX_TARGETS {
        return Err(ProtocolError::CapacityExceeded);
    }
    for context in contexts {
        validate_id(context.as_str().ok_or(ProtocolError::BrowserFailure)?)?;
    }
    // This is optional in CDP, not a required provider extension. Unrelated
    // incognito contexts neither authorize adoption nor block the default one.
    value
        .get("defaultBrowserContextId")
        .map(|_| id(value, "defaultBrowserContextId").map(str::to_owned))
        .transpose()
}

fn probe_context(value: &Value, target_id: &str) -> Result<String, ProtocolError> {
    let info = value
        .get("targetInfo")
        .ok_or(ProtocolError::BrowserFailure)?;
    if id(info, "targetId")? != target_id
        || info.get("type").and_then(Value::as_str) != Some("page")
        || info.get("subtype").is_some()
    {
        return Err(ProtocolError::PolicyDenied);
    }
    id(info, "browserContextId").map(str::to_owned)
}

struct Inventory {
    target_ids: HashSet<String>,
    pages: Vec<(String, String)>,
}

impl Inventory {
    fn parse(value: &Value) -> Result<Self, ProtocolError> {
        let infos = value
            .get("targetInfos")
            .and_then(Value::as_array)
            .ok_or(ProtocolError::BrowserFailure)?;
        if infos.len() > MAX_TARGETS {
            return Err(ProtocolError::CapacityExceeded);
        }
        let mut target_ids = HashSet::new();
        let mut pages = Vec::new();
        for info in infos {
            let target = id(info, "targetId")?;
            if !target_ids.insert(target.to_owned()) {
                return Err(ProtocolError::BrowserFailure);
            }
            if info.get("type").and_then(Value::as_str) != Some("page")
                || info.get("subtype").is_some()
            {
                continue;
            }
            // Optional/missing metadata is not permission to adopt this target.
            if info.get("browserContextId").is_some() {
                pages.push((target.to_owned(), id(info, "browserContextId")?.to_owned()));
            }
        }
        Ok(Self { target_ids, pages })
    }

    fn page_in(&self, context: &str) -> Option<String> {
        self.pages
            .iter()
            .find(|(_, candidate)| candidate == context)
            .map(|(target, _)| target.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use std::sync::{Arc, Mutex};
    use tokio::task::JoinHandle;
    use tokio_tungstenite::tungstenite::Message;

    fn page(target: &str, context: &str) -> Value {
        json!({"targetId":target,"type":"page","browserContextId":context,"url":"https://synthetic.invalid/","title":"synthetic","attached":false})
    }

    #[test]
    fn persistent_optional_default_identity_is_compatible_with_incognito_contexts() {
        assert_eq!(
            default_context(&json!({"browserContextIds":["foreign"]})).unwrap(),
            None
        );
        assert_eq!(
            default_context(&json!({"browserContextIds":["foreign"],"defaultBrowserContextId":"default-context"})).unwrap(),
            Some("default-context".into())
        );
        for malformed in [
            json!({}),
            json!({"browserContextIds":null}),
            json!({"browserContextIds":[null]}),
            json!({"browserContextIds":[],"defaultBrowserContextId":""}),
            json!({"browserContextIds":[],"defaultBrowserContextId":null}),
        ] {
            assert!(default_context(&malformed).is_err());
        }
    }

    #[test]
    fn persistent_inventory_never_guesses_context_or_adopts_prerender() {
        let inventory = Inventory::parse(&json!({"targetInfos":[
            page("foreign-page", "foreign-context"),
            {"targetId":"unknown-context","type":"page"},
            {"targetId":"prerender","type":"page","browserContextId":"default-context","subtype":"prerender"},
            page("first-default", "default-context"),
            page("second-default", "default-context")
        ]}))
        .unwrap();
        assert_eq!(
            inventory.page_in("default-context"),
            Some("first-default".into())
        );
        assert_eq!(inventory.page_in("unknown-context"), None);
        assert!(Inventory::parse(
            &json!({"targetInfos":[page("duplicate", "a"),page("duplicate", "b")]})
        )
        .is_err());
        assert!(probe_context(
            &json!({"targetInfo":{"targetId":"probe","type":"page"}}),
            "probe"
        )
        .is_err());
        assert!(probe_context(
            &json!({"targetInfo":page("wrong-target", "default-context")}),
            "probe"
        )
        .is_err());
        assert_eq!(
            probe_context(
                &json!({"targetInfo":page("probe", "real-context")}),
                "probe"
            )
            .unwrap(),
            "real-context"
        );
    }

    #[test]
    fn persistent_probe_commit_requires_exact_known_created_target() {
        let mut journal = OwnedProbeJournal {
            state: ProbeState::Created("new-page".into()),
        };
        assert_eq!(
            journal.commit("host-page"),
            Err(ProtocolError::CleanupFailed)
        );
        assert_eq!(journal.exact_target_id(), Some("new-page"));
        journal.commit("new-page").unwrap();
        assert!(journal.exact_target_id().is_none());
        for state in [
            ProbeState::CreationUncertain,
            ProbeState::CloseUncertain("new-page".into()),
        ] {
            let mut journal = OwnedProbeJournal { state };
            assert_eq!(
                journal.commit("new-page"),
                Err(ProtocolError::CleanupFailed)
            );
        }
    }

    struct Fixture {
        contexts: Value,
        targets: Value,
        created_id: String,
        probe_info: Value,
        adopted_info: Value,
        fail_method: Option<&'static str>,
        lose_create_ack: bool,
    }

    impl Fixture {
        fn existing(advertised: bool) -> Self {
            Self {
                contexts: if advertised {
                    json!({"browserContextIds":["foreign-context"],"defaultBrowserContextId":"default-context"})
                } else {
                    json!({"browserContextIds":["foreign-context"]})
                },
                targets: json!({"targetInfos":[page("foreign-page", "foreign-context"),page("host-page", "default-context"),page("other-host-page", "default-context")]}),
                created_id: "probe-page".into(),
                probe_info: page("probe-page", "default-context"),
                adopted_info: page("host-page", "default-context"),
                fail_method: None,
                lose_create_ack: false,
            }
        }

        fn empty(advertised: bool) -> Self {
            let mut fixture = Self::existing(advertised);
            fixture.targets = json!({"targetInfos":[page("foreign-page", "foreign-context")]});
            fixture.adopted_info = fixture.probe_info.clone();
            fixture
        }
    }

    type Commands = Arc<Mutex<Vec<Value>>>;

    async fn fixture_server(fixture: Fixture) -> (BrowserManager, Commands, JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let commands = Arc::new(Mutex::new(Vec::new()));
        let observed = commands.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut attached = false;
            while let Some(message) = socket.next().await {
                let message = match message {
                    Ok(Message::Text(message)) => message,
                    Ok(Message::Close(_)) | Err(_) => break,
                    _ => continue,
                };
                let command: Value = serde_json::from_str(&message).unwrap();
                observed.lock().unwrap().push(command.clone());
                let method = command["method"].as_str().unwrap();
                if fixture.lose_create_ack && method == "Target.createTarget" {
                    continue;
                }
                let response = if fixture.fail_method == Some(method) {
                    json!({"id":command["id"],"error":{"code":-32000,"message":"synthetic failure"}})
                } else {
                    let result = match method {
                        "Target.getBrowserContexts" => fixture.contexts.clone(),
                        "Target.getTargets" => fixture.targets.clone(),
                        "Target.createTarget" => json!({"targetId":fixture.created_id}),
                        "Target.getTargetInfo" => {
                            json!({"targetInfo":if attached {fixture.adopted_info.clone()} else {fixture.probe_info.clone()}})
                        }
                        "Target.attachToTarget" => {
                            attached = true;
                            json!({"sessionId":"borrowed-session"})
                        }
                        "Target.closeTarget" => json!({"success":true}),
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
        let manager = BrowserManager::connect_owned_browser(&endpoint, None)
            .await
            .unwrap();
        (manager, commands, server)
    }

    async fn finish(
        mut manager: BrowserManager,
        commands: Commands,
        server: JoinHandle<()>,
    ) -> Vec<Value> {
        manager.close().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        let commands = commands.lock().unwrap().clone();
        assert!(!commands.iter().any(|command| matches!(
            command["method"].as_str(),
            Some(
                "Browser.close"
                    | "Target.disposeBrowserContext"
                    | "Page.navigate"
                    | "Runtime.evaluate"
                    | "Page.enable"
                    | "Runtime.enable"
                    | "Network.enable"
                    | "Target.setAutoAttach"
                    | "Runtime.runIfWaitingForDebugger"
            )
        )));
        commands
    }

    fn targets_for(commands: &[Value], method: &str) -> Vec<String> {
        commands
            .iter()
            .filter(|command| command["method"] == method)
            .map(|command| command["params"]["targetId"].as_str().unwrap().to_owned())
            .collect()
    }

    #[tokio::test]
    async fn persistent_advertised_identity_reuses_only_exact_host_page() {
        let (mut manager, commands, server) = fixture_server(Fixture::existing(true)).await;
        let attachment = prepare_persistent(&mut manager).await.unwrap();
        assert_eq!(attachment.context_id, "default-context");
        assert_eq!(attachment.target_id, "host-page");
        assert!(attachment.probe.exact_target_id().is_none());
        assert!(
            matches!(attachment.ownership(), ScopeOwnership::BorrowedTargets(ids) if ids == vec!["host-page"])
        );
        assert_eq!(manager.active_target_id().unwrap(), "host-page");
        let commands = finish(manager, commands, server).await;
        assert_eq!(
            targets_for(&commands, "Target.attachToTarget"),
            ["host-page"]
        );
        assert!(targets_for(&commands, "Target.closeTarget").is_empty());
        assert!(!commands
            .iter()
            .any(|command| command["method"] == "Target.createTarget"));
    }

    #[tokio::test]
    async fn persistent_missing_optional_identity_closes_only_owned_probe() {
        let (mut manager, commands, server) = fixture_server(Fixture::existing(false)).await;
        let attachment = prepare_persistent(&mut manager).await.unwrap();
        assert_eq!(attachment.context_id, "default-context");
        assert_eq!(attachment.target_id, "host-page");
        assert!(attachment.probe.exact_target_id().is_none());
        let commands = finish(manager, commands, server).await;
        assert_eq!(targets_for(&commands, "Target.closeTarget"), ["probe-page"]);
        assert_eq!(
            targets_for(&commands, "Target.attachToTarget"),
            ["host-page"]
        );
        let create = commands
            .iter()
            .find(|command| command["method"] == "Target.createTarget")
            .unwrap();
        assert_eq!(create["params"]["url"], "about:blank");
        assert!(create["params"].get("browserContextId").is_none());
        let close = commands
            .iter()
            .position(|command| command["method"] == "Target.closeTarget")
            .unwrap();
        let attach = commands
            .iter()
            .position(|command| command["method"] == "Target.attachToTarget")
            .unwrap();
        assert!(close < attach);
    }

    #[tokio::test]
    async fn persistent_new_initial_blank_keeps_cleanup_authority_until_commit() {
        for advertised in [false, true] {
            let (mut manager, commands, server) = fixture_server(Fixture::empty(advertised)).await;
            let mut attachment = prepare_persistent(&mut manager).await.unwrap();
            assert_eq!(attachment.context_id, "default-context");
            assert_eq!(attachment.target_id, "probe-page");
            assert_eq!(attachment.probe.exact_target_id(), Some("probe-page"));
            attachment.probe.commit(&attachment.target_id).unwrap();
            attachment.probe.cleanup(&manager.client).await.unwrap();
            let commands = finish(manager, commands, server).await;
            assert!(targets_for(&commands, "Target.closeTarget").is_empty());
            assert_eq!(
                targets_for(&commands, "Target.attachToTarget"),
                ["probe-page"]
            );
        }
    }

    #[tokio::test]
    async fn persistent_unpublished_blank_is_the_only_cleanup_target() {
        let (mut manager, commands, server) = fixture_server(Fixture::empty(true)).await;
        let mut attachment = prepare_persistent(&mut manager).await.unwrap();
        attachment.probe.cleanup(&manager.client).await.unwrap();
        assert!(attachment.probe.exact_target_id().is_none());
        let commands = finish(manager, commands, server).await;
        assert_eq!(targets_for(&commands, "Target.closeTarget"), ["probe-page"]);
    }

    #[tokio::test]
    async fn persistent_invalid_probe_metadata_never_adopts_a_host_page() {
        for probe_info in [
            json!({"targetId":"probe-page","type":"page"}),
            page("wrong-target", "default-context"),
            json!({"targetId":"probe-page","type":"worker","browserContextId":"default-context"}),
        ] {
            let mut fixture = Fixture::existing(false);
            fixture.probe_info = probe_info;
            let (mut manager, commands, server) = fixture_server(fixture).await;
            let failure = prepare_persistent(&mut manager).await.unwrap_err();
            assert_ne!(failure.error, ProtocolError::CleanupFailed);
            assert!(failure.probe.exact_target_id().is_none());
            let commands = finish(manager, commands, server).await;
            assert_eq!(targets_for(&commands, "Target.closeTarget"), ["probe-page"]);
            assert!(targets_for(&commands, "Target.attachToTarget").is_empty());
        }
    }

    #[tokio::test]
    async fn persistent_failed_probe_close_preserves_exact_uncertain_evidence() {
        let mut fixture = Fixture::existing(false);
        fixture.fail_method = Some("Target.closeTarget");
        let (mut manager, commands, server) = fixture_server(fixture).await;
        let mut failure = prepare_persistent(&mut manager).await.unwrap_err();
        assert_eq!(failure.error, ProtocolError::CleanupFailed);
        assert_eq!(failure.probe.exact_target_id(), Some("probe-page"));
        assert!(failure.probe.close_uncertain());
        assert!(!failure.probe.creation_uncertain());
        assert_eq!(
            failure.probe.cleanup(&manager.client).await,
            Err(ProtocolError::CleanupFailed)
        );
        let commands = finish(manager, commands, server).await;
        assert_eq!(targets_for(&commands, "Target.closeTarget"), ["probe-page"]);
        assert!(targets_for(&commands, "Target.attachToTarget").is_empty());
    }

    #[tokio::test]
    async fn persistent_lost_probe_create_ack_never_fabricates_cleanup_identity() {
        let mut fixture = Fixture::existing(false);
        fixture.lose_create_ack = true;
        let (mut manager, commands, server) = fixture_server(fixture).await;
        let failure = prepare_before(&mut manager, Instant::now() + Duration::from_millis(100))
            .await
            .unwrap_err();
        assert_eq!(failure.error, ProtocolError::CleanupFailed);
        assert!(failure.probe.creation_uncertain());
        assert!(failure.probe.exact_target_id().is_none());
        let commands = finish(manager, commands, server).await;
        assert!(targets_for(&commands, "Target.closeTarget").is_empty());
        assert!(targets_for(&commands, "Target.attachToTarget").is_empty());
    }

    #[tokio::test]
    async fn persistent_inconsistent_create_ack_never_owns_preexisting_host_target() {
        let mut fixture = Fixture::existing(false);
        fixture.created_id = "host-page".into();
        let (mut manager, commands, server) = fixture_server(fixture).await;
        let failure = prepare_persistent(&mut manager).await.unwrap_err();
        assert_eq!(failure.error, ProtocolError::CleanupFailed);
        assert!(failure.probe.creation_uncertain());
        let commands = finish(manager, commands, server).await;
        assert!(targets_for(&commands, "Target.closeTarget").is_empty());
        assert!(targets_for(&commands, "Target.attachToTarget").is_empty());
    }

    #[tokio::test]
    async fn persistent_adoption_rechecks_exact_context_before_enabling_page_domains() {
        for adopted_info in [
            json!({"targetId":"host-page","type":"page"}),
            page("host-page", "foreign-context"),
            page("different-page", "default-context"),
        ] {
            let mut fixture = Fixture::existing(true);
            fixture.adopted_info = adopted_info;
            let (mut manager, commands, server) = fixture_server(fixture).await;
            let failure = prepare_persistent(&mut manager).await.unwrap_err();
            assert_eq!(failure.error, ProtocolError::BrowserFailure);
            assert!(!manager.has_pages());
            let commands = finish(manager, commands, server).await;
            assert!(commands
                .iter()
                .any(|command| command["method"] == "Target.detachFromTarget"
                    && command["params"]["sessionId"] == "borrowed-session"));
            assert!(!commands
                .iter()
                .any(|command| command["method"] == "Page.enable"));
            assert!(targets_for(&commands, "Target.closeTarget").is_empty());
        }
    }

    #[tokio::test]
    async fn persistent_failed_initial_page_recheck_cleans_only_new_blank() {
        let mut fixture = Fixture::empty(true);
        fixture.adopted_info = page("probe-page", "wrong-context");
        let (mut manager, commands, server) = fixture_server(fixture).await;
        let failure = prepare_persistent(&mut manager).await.unwrap_err();
        assert_eq!(failure.error, ProtocolError::BrowserFailure);
        assert!(failure.probe.exact_target_id().is_none());
        let commands = finish(manager, commands, server).await;
        assert_eq!(targets_for(&commands, "Target.closeTarget"), ["probe-page"]);
        assert!(commands
            .iter()
            .any(|command| command["method"] == "Target.detachFromTarget"));
    }
}
