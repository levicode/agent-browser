//! Constructor-only prototype for a real PW-created isolated context and its
//! reserved own Page. No wire entry point/capability is published by this module.
//! The lifecycle supervisor must retain the returned/failure owner through cleanup.
use super::super::client_session::{CancelSignal, OperationLease};
use super::*;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::future::Future;
use std::time::Instant;

/// Native-private, non-cloneable preparation. Fresh managers are unbound;
/// reused managers must retain their exact retired ledger and phase-two proof.
/// Neither path reconnects the native transport or erases the previous owner.
pub(super) struct PreparedInteropBrowser {
    owner: OwnedBrowser,
    contexts_before: HashSet<String>,
    generation: u64,
    sequence: u64,
    deadline: Instant,
    cancellation: Option<tokio::sync::watch::Receiver<CancelSignal>>,
}

fn valid_id(id: &str) -> Result<(), ProtocolError> {
    if id.is_empty() || id.len() > 1024 || id.contains('\0') {
        Err(ProtocolError::InvalidArguments)
    } else {
        Ok(())
    }
}
fn contexts(value: &Value) -> Result<HashSet<String>, ProtocolError> {
    let ids = value
        .get("browserContextIds")
        .and_then(Value::as_array)
        .ok_or(ProtocolError::BrowserFailure)?;
    if ids.len() > 8192 {
        return Err(ProtocolError::CapacityExceeded);
    }
    let mut result = HashSet::new();
    for value in ids {
        let id = value.as_str().ok_or(ProtocolError::BrowserFailure)?;
        valid_id(id).map_err(|_| ProtocolError::BrowserFailure)?;
        if !result.insert(id.to_owned()) {
            return Err(ProtocolError::BrowserFailure);
        }
    }
    Ok(result)
}
fn verify_page(value: &Value, context: &str, target: &str) -> Result<(), ProtocolError> {
    let info = value
        .get("targetInfo")
        .ok_or(ProtocolError::BrowserFailure)?;
    if info.get("targetId").and_then(Value::as_str) != Some(target)
        || info.get("browserContextId").and_then(Value::as_str) != Some(context)
        || info.get("type").and_then(Value::as_str) != Some("page")
        || info.get("subtype").is_some()
        || info.get("url").and_then(Value::as_str) != Some("about:blank")
    {
        return Err(ProtocolError::StaleScope);
    }
    Ok(())
}
async fn bounded<T>(
    op: &OperationLease,
    work: impl Future<Output = Result<T, String>>,
) -> Result<T, ProtocolError> {
    check_lifecycle_budget(op)?;
    let mut cancellation = op.cancellation.clone();
    let result = tokio::select! {
        biased;
        _ = cancellation.changed() => Err(ProtocolError::Cancelled),
        result = tokio::time::timeout_at(op.deadline.into(), work) =>
            result.map_err(|_| ProtocolError::DeadlineExceeded)?
                .map_err(|_| ProtocolError::BrowserFailure),
    };
    result.and_then(|value| {
        check_lifecycle_budget(op)?;
        Ok(value)
    })
}

impl PreparedInteropBrowser {
    /// The caller already owns this manager; failure always returns it in `failed`.
    /// No Page, context, navigation, script or browser process is created here.
    pub(super) async fn prepare(
        manager: super::super::browser::BrowserManager,
        operation: &OperationLease,
        failed: &mut Option<OwnedBrowser>,
    ) -> Result<Self, ProtocolError> {
        let owner = OwnedBrowser {
            manager,
            context_id: String::new(),
            owns_context: false,
            identity_scope: String::new(),
            targets: super::super::client_targets::ClientTargets::new_managed(
                String::new(),
                String::new(),
            ),
            page_state: Arc::new(super::super::client_page::ClientPageState::new(
                String::new(),
                String::new(),
            )),
            ui: Arc::new(super::super::client_ui::UiGate::default()),
            runtime: None,
            replacement_actions: None,
            replacement_routes: None,
            disconnected_routes: None,
            reconnect_proof: None,
            persistent_probe: Default::default(),
            borrowed_targets: None,
            browser_tenure: uuid::Uuid::new_v4().to_string(),
        };
        let result =
            async {
                check_lifecycle_budget(operation)?;
                if operation.is_callback || owner.manager.has_pages() {
                    return Err(ProtocolError::InvalidArguments);
                }
                let reply =
                    if let Some(previous) = owner.manager.client.debt_ledger() {
                        if !previous.replacement_ready() {
                            return Err(ProtocolError::CleanupFailed);
                        }
                        // One fixed metadata read; the old immutable facade remains
                        // retired. The writer rechecks exact ownership and deadline.
                        bounded(operation, owner.manager.client.send_owner_cleanup(
                    Some(previous),
                    super::super::client_debt::OwnerCleanupCommand::InteropContextInventory,
                    operation.deadline,
                )).await?
                    } else {
                        bounded(
                            operation,
                            owner.manager.client.send_command(
                                "Target.getBrowserContexts",
                                Some(json!({})),
                                None,
                            ),
                        )
                        .await?
                    };
                contexts(&reply)
            }
            .await;
        match result {
            Ok(contexts_before) => Ok(Self {
                owner,
                contexts_before,
                generation: operation.generation,
                sequence: operation.sequence,
                deadline: operation.deadline,
                cancellation: Some(operation.cancellation.clone()),
            }),
            Err(error) => {
                *failed = Some(owner);
                Err(error)
            }
        }
    }

    /// A settled prepare RPC is not a lifetime operation. Retained custody uses
    /// its own cancellation owner and a later genuinely admitted operation.
    pub(super) fn detach_request_authority(mut self) -> Self {
        self.cancellation = None;
        self
    }

    fn check(&self, op: &OperationLease) -> Result<(), ProtocolError> {
        check_lifecycle_budget(op)?;
        if op.is_callback
            || op.generation != self.generation
            || op.sequence != self.sequence
            || op.deadline != self.deadline
            || !self
                .cancellation
                .as_ref()
                .is_some_and(|original| op.cancellation.same_channel(original))
        {
            return Err(ProtocolError::StaleScope);
        }
        Ok(())
    }

    /// `context`/`target` come from the trusted bridge's actual newly created PW
    /// context+Page, not a URL guess. Native independently verifies membership,
    /// freshness and exact target/context before granting context disposal.
    pub(super) async fn adopt(
        self,
        context: &str,
        target: &str,
        op: &OperationLease,
        failed: &mut Option<OwnedBrowser>,
    ) -> Result<OwnedBrowser, ProtocolError> {
        self.adopt_inner(context, target, op, None, failed).await
    }

    pub(super) async fn adopt_retained(
        self,
        context: &str,
        target: &str,
        op: &OperationLease,
        permit: &super::interop_preparation::AdoptionPermit,
        failed: &mut Option<OwnedBrowser>,
    ) -> Result<OwnedBrowser, ProtocolError> {
        self.adopt_inner(context, target, op, Some(permit), failed)
            .await
    }

    fn check_authority(
        &self,
        op: &OperationLease,
        permit: Option<&super::interop_preparation::AdoptionPermit>,
    ) -> Result<(), ProtocolError> {
        match permit {
            Some(permit) => permit.check(self.generation, self.sequence, self.deadline, op),
            None => self.check(op),
        }
    }

    async fn adopt_inner(
        mut self,
        context: &str,
        target: &str,
        op: &OperationLease,
        permit: Option<&super::interop_preparation::AdoptionPermit>,
        failed: &mut Option<OwnedBrowser>,
    ) -> Result<OwnedBrowser, ProtocolError> {
        let result = async {
            self.check_authority(op, permit)?;
            valid_id(context)?;
            valid_id(target)?;
            if self.contexts_before.contains(context) {
                return Err(ProtocolError::PolicyDenied);
            }
            // Reuse installs the new unpublished facade only under this real
            // adoption RPC, never under the already-settled prepare lease.
            let replacement = if self.owner.manager.client.debt_ledger().is_some() {
                let lease = ReplacementLease::begin(&mut self.owner.manager, op)?;
                self.owner.identity_scope = lease.identity_scope.clone();
                Some(lease)
            } else {
                None
            };
            let inventory = bounded(
                op,
                self.owner.manager.client.send_command(
                    "Target.getBrowserContexts",
                    Some(json!({})),
                    None,
                ),
            )
            .await?;
            if !contexts(&inventory)?.contains(context) {
                return Err(ProtocolError::StaleScope);
            }
            let info = bounded(
                op,
                self.owner.manager.client.send_command(
                    "Target.getTargetInfo",
                    Some(json!({"targetId": target})),
                    None,
                ),
            )
            .await?;
            verify_page(&info, context, target)?;
            self.check_authority(op, permit)?;
            // Retain exact validated context ownership before any attach effect.
            // The supervisor, not a dropped RPC waiter, owns this failed resource.
            self.owner.context_id = context.to_owned();
            self.owner.owns_context = true;
            if let Some(lease) = &replacement {
                lease.debt.bind_context(context)?;
                lease.debt.bind_adopted_blank_target(context, target, op)?;
            }
            bounded(op, self.owner.manager.adopt_verified_page(target, context)).await?;
            // Recheck existence and blank-page identity after attachment.
            let inventory = bounded(
                op,
                self.owner.manager.client.send_command(
                    "Target.getBrowserContexts",
                    Some(json!({})),
                    None,
                ),
            )
            .await?;
            if !contexts(&inventory)?.contains(context) {
                return Err(ProtocolError::StaleScope);
            }
            let info = bounded(
                op,
                self.owner.manager.client.send_command(
                    "Target.getTargetInfo",
                    Some(json!({"targetId": target})),
                    None,
                ),
            )
            .await?;
            verify_page(&info, context, target)?;
            self.check_authority(op, permit)?;
            let session = self
                .owner
                .manager
                .active_session_id()
                .map_err(|_| ProtocolError::StaleScope)?
                .to_owned();
            // Fresh attachment precedes its unpublished facade, as in native
            // reconnect. Reuse already installed one under this exact adopt RPC;
            // never replace it with another owner or relax its target guards.
            let lease = match replacement {
                Some(lease) => lease,
                None => ReplacementLease::begin(&mut self.owner.manager, op)?,
            };
            self.owner.identity_scope = lease.identity_scope.clone();
            lease.debt.bind_context(context)?;
            lease.debt.bind_session(context, target, &session)?;
            self.owner.targets = super::super::client_targets::ClientTargets::new_managed(
                context.to_owned(),
                lease.identity_scope.clone(),
            );
            self.owner.page_state = Arc::new(super::super::client_page::ClientPageState::new(
                lease.identity_scope.clone(),
                context.to_owned(),
            ));
            Ok(())
        }
        .await;
        match result {
            Ok(()) => Ok(self.owner),
            Err(error) => {
                *failed = Some(self.owner);
                Err(error)
            }
        }
    }

    /// Explicit abort consumes the preparation. Context creation before adoption
    /// remains bridge-owned; native preparation owns no foreign destruction.
    pub(super) fn abort(self) -> OwnedBrowser {
        self.owner
    }
}

#[cfg(test)]
#[path = "client_interop_adoption_tests.rs"]
mod tests;
