//! Bounded wire orchestration of the one native storage-state primitive.
//! The lifecycle owner retains execution/UI permits and this future through
//! settlement, even after an RPC disconnect or cancellation. This module never
//! replaces a scope, creates its own task, or claims browser conformance.
use super::client_blobs::{BlobError, BlobInfo, BlobLease, BlobScope, BlobStore};
use super::client_browser::BrowserExecutionLease;
use super::client_protocol::ProtocolError;
use super::client_session::{CancelSignal, OperationLease};
use super::client_state::{self, NativeState, NativeStateContext, StateError, StateFailure};
use super::client_targets::TargetPurpose;
use super::client_ui::{UiGate, UiPermit};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::fmt;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Instant;

const MAX_STATE_BYTES: usize = 32 * 1024 * 1024;

/// Supplied from lifecycle ownership, never decoded from a request. A nonempty
/// context ID does not prove isolation: persistent default contexts have IDs.
/// Persistent authority permits capture only, never replacement/import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateContextKind {
    Isolated,
    Persistent,
}

/// Every borrowed resource is captured from one owner before browser I/O.
/// `context.origins` must be the exact immutable ClientPageState::visited_origins
/// snapshot, including closed documents. `origins_complete` additionally needs
/// the owner's healthy enrollment attestation: initial frame-tree reconciliation,
/// exact authorized application frame/loader inventory, drained event watermarks,
/// no pending application enrollment, and uninterrupted bounded event delivery.
/// For persistent contexts, completeness covers observed non-initial new-document
/// origins during this attachment tenure plus imported origins, not pre-attachment
/// profile history, unadopted host pages, or origins inferred from initial URLs.
/// A successful vector read alone is not completeness evidence. The owner must
/// recheck that same attestation and origin snapshot before publishing the blob.
///
/// StateBootstrap is reserved by the shared client_state primitive and excluded
/// from application event routing. Persistent enrollment admits only its native
/// create ACK followed by exact target/context/type/about:blank metadata proof;
/// it never adopts all host pages or grants host context/page-close authority.
/// Do not hold a protected target-read barrier: it prevents bootstrap creation.
pub struct CapturedStateContext<'a> {
    page: &'a BrowserExecutionLease,
    ui_gate: &'a Arc<UiGate>,
    ui: &'a UiPermit,
    context: NativeStateContext<'a>,
    kind: StateContextKind,
}
impl<'a> CapturedStateContext<'a> {
    pub fn new(
        page: &'a BrowserExecutionLease,
        ui_gate: &'a Arc<UiGate>,
        ui: &'a UiPermit,
        context: NativeStateContext<'a>,
        kind: StateContextKind,
    ) -> Result<Self, StateDispatchFailure> {
        let result = Self {
            page,
            ui_gate,
            ui,
            context,
            kind,
        };
        if !std::ptr::eq(result.context.client, page.client.as_ref())
            || !Arc::ptr_eq(result.context.targets, &page.targets)
            || result.context.context_id.is_empty()
            || result.context.context_id != page.targets.context_id
            || page.identity_scope != page.targets.identity_scope
        {
            return Err(result.failure(ProtocolError::StaleScope));
        }
        if !result.context.origins_complete {
            return Err(result.failure(ProtocolError::ScopeUnavailable));
        }
        page.permit.check().map_err(|error| result.failure(error))?;
        ui.check_exclusive(ui_gate)
            .map_err(|error| result.failure(error))?;
        result.check_inventory()?;
        Ok(result)
    }
    fn failure(&self, error: ProtocolError) -> StateDispatchFailure {
        StateDispatchFailure::unchanged(&self.page.identity_scope, error)
    }
    fn capture_failure(&self, outcome: StateFailure) -> StateDispatchFailure {
        let mut failure = StateDispatchFailure::outcome(&self.page.identity_scope, outcome, false);
        if self.kind == StateContextKind::Persistent {
            // Cleanup uncertainty must stay visible and owner-journaled, but a
            // capture-only borrow can never authorize disposal of host storage.
            failure.discard_context = false;
        }
        failure
    }
    fn check_inventory(&self) -> Result<(), StateDispatchFailure> {
        // Snapshot only: a protected target barrier would prevent the shared
        // primitive from creating/resuming its reserved bootstrap documents.
        let (_, targets) = self
            .page
            .targets
            .inventory()
            .map_err(|error| self.failure(error))?;
        if targets.iter().any(|target| {
            target.purpose == Some(TargetPurpose::Application)
                && (!target.configured || !target.resumed)
        }) {
            return Err(self.failure(ProtocolError::ScopeUnavailable));
        }
        Ok(())
    }
    fn check(&self, operation: &OperationLease) -> Result<(), StateDispatchFailure> {
        self.page
            .permit
            .check()
            .map_err(|error| self.failure(error))?;
        self.ui
            .check_exclusive(self.ui_gate)
            .map_err(|error| self.failure(error))?;
        self.check_inventory()?;
        check_operation(operation).map_err(|error| self.failure(error))
    }
}

/// Browser error and cleanup certainty are independent. Keep the shared
/// primitive's original cause when cleanup also loses containment integrity.
#[derive(Debug)]
pub struct StateDispatchFailure {
    pub error: ProtocolError,
    pub identity_scope: String,
    pub cleanup_integrity_lost: bool,
    /// An isolated context may need disposal after import or cleanup failure.
    /// Never grants disposal authority over a persistent borrowed host context;
    /// that owner retains exact bootstrap cleanup while honoring the error.
    pub discard_context: bool,
}
impl StateDispatchFailure {
    fn unchanged(scope: &str, error: ProtocolError) -> Self {
        Self {
            error,
            identity_scope: scope.into(),
            cleanup_integrity_lost: false,
            discard_context: false,
        }
    }
    fn outcome(scope: &str, outcome: StateFailure, importing: bool) -> Self {
        let mut failure = Self::state(scope, outcome.error, importing);
        failure.cleanup_integrity_lost |= outcome.cleanup_integrity_lost;
        failure.discard_context |= outcome.cleanup_integrity_lost;
        failure
    }
    fn state(scope: &str, error: StateError, importing: bool) -> Self {
        let cleanup_integrity_lost = error == StateError::CleanupIntegrityLost;
        Self {
            error: match error {
                StateError::InvalidInput => ProtocolError::InvalidArguments,
                StateError::IncompleteInventory => ProtocolError::ScopeUnavailable,
                StateError::UnsupportedValue => ProtocolError::UnsupportedCapability,
                StateError::Cancelled => ProtocolError::Cancelled,
                StateError::Deadline => ProtocolError::DeadlineExceeded,
                StateError::BrowserFailure => ProtocolError::BrowserFailure,
                StateError::CleanupIntegrityLost => ProtocolError::CleanupFailed,
            },
            identity_scope: scope.into(),
            cleanup_integrity_lost,
            discard_context: importing || cleanup_integrity_lost,
        }
    }
}
fn blob_error(error: BlobError) -> ProtocolError {
    match error {
        BlobError::QuotaExceeded => ProtocolError::CapacityExceeded,
        BlobError::StaleScope => ProtocolError::StaleScope,
        BlobError::Closed => ProtocolError::ScopeUnavailable,
        _ => ProtocolError::InvalidArguments,
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
fn check_scope(scope: &BlobScope, operation: &OperationLease) -> Result<(), ProtocolError> {
    if scope.generation == 0 || scope.generation != operation.generation {
        return Err(ProtocolError::StaleGeneration);
    }
    if scope.identity_scope.is_empty() {
        return Err(ProtocolError::StaleScope);
    }
    check_operation(operation)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StateCapture {
    pub identity_scope: String,
    pub format: &'static str,
    pub version: u32,
    #[serde(flatten)]
    pub blob: BlobInfo,
}

/// Reserve quota before invoking export, then publish only in the captured
/// scope. The shared export primitive is responsible for bounded collection;
/// this writer independently bounds serialization before blob publication.
pub async fn capture_state(
    context: &CapturedStateContext<'_>,
    blobs: &BlobStore,
    scope: &BlobScope,
    operation: &OperationLease,
) -> Result<StateCapture, StateDispatchFailure> {
    context.check(operation)?;
    check_scope(scope, operation).map_err(|error| context.failure(error))?;
    if scope.identity_scope != context.page.identity_scope {
        return Err(context.failure(ProtocolError::StaleScope));
    }
    // The primitive may collect up to its fixed logical state limit. A
    // smaller producer reservation cannot cover that collection, even if the
    // eventual snapshot would happen to fit. Refuse before the first CDP call.
    if blobs.producer_limit() < MAX_STATE_BYTES {
        return Err(context.failure(ProtocolError::CapacityExceeded));
    }
    let producer = blobs
        .reserve_producer(scope.clone())
        .map_err(|error| context.failure(blob_error(error)))?;
    let state = client_state::export_state(&context.context, operation)
        .await
        .map_err(|error| context.capture_failure(error))?;
    context.check(operation)?;
    let mut writer = BoundedWriter {
        bytes: Vec::new(),
        limit: MAX_STATE_BYTES,
    };
    serde_json::to_writer(&mut writer, &state)
        .map_err(|_| context.failure(ProtocolError::CapacityExceeded))?;
    context.check(operation)?;
    let blob = blobs
        .finish_producer(producer, writer.bytes)
        .map_err(|error| context.failure(blob_error(error)))?;
    if let Err(mut failure) = context.check(operation) {
        if let Err(error) = blobs.release(scope, &blob.handle) {
            // Scope retirement or another authorized release already removed it.
            if error != BlobError::Missing {
                failure.cleanup_integrity_lost = true;
            }
        }
        return Err(failure);
    }
    Ok(StateCapture {
        identity_scope: scope.identity_scope.clone(),
        format: "agent-browser-storage-state",
        version: 1,
        blob,
    })
}
struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("State size limit exceeded"));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| io::Error::other("State allocation failed"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Deserialize)]
enum StateFormat {
    #[serde(rename = "agent-browser-storage-state")]
    Native,
    #[serde(rename = "playwright-storage-state")]
    Playwright,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreRequest {
    identity_scope: String,
    format: StateFormat,
    version: u32,
    body_handle: String,
}

/// Preflight owns an immutable byte lease but does not reserve or consume the
/// caller's handle. Rejection or dropping this value leaves it releasable.
/// Fields intentionally do not implement Debug: storage payloads are private.
pub struct PreparedRestore<'a> {
    blobs: &'a BlobStore,
    scope: BlobScope,
    handle: String,
    operation_sequence: u64,
    body: BlobLease,
    state: NativeState,
}
/// Only lifecycle acceptance constructs this value. A failed or cancelled
/// import never transfers its upload back to the caller. The retained native
/// task owns cleanup and the body charge through actual browser settlement.
pub struct AcceptedRestore {
    generation: u64,
    operation_sequence: u64,
    source_identity_scope: String,
    _body: BlobLease,
    state: NativeState,
}

pub fn prepare_restore<'a>(
    blobs: &'a BlobStore,
    scope: &BlobScope,
    args: &Value,
    operation: &OperationLease,
) -> Result<PreparedRestore<'a>, StateDispatchFailure> {
    let failure = |error| StateDispatchFailure::unchanged(&scope.identity_scope, error);
    check_scope(scope, operation).map_err(failure)?;
    let request: RestoreRequest = serde_json::from_value(args.clone())
        .map_err(|_| failure(ProtocolError::InvalidArguments))?;
    if request.version != 1
        || request.body_handle.is_empty()
        || request.body_handle.len() > 1024
        || request.body_handle.chars().any(char::is_control)
    {
        return Err(failure(ProtocolError::InvalidArguments));
    }
    if request.identity_scope != scope.identity_scope {
        return Err(failure(ProtocolError::StaleScope));
    }
    let body = blobs
        .borrow_sealed(scope, &request.body_handle)
        .map_err(|error| failure(blob_error(error)))?;
    if body.bytes().len() > MAX_STATE_BYTES {
        return Err(failure(ProtocolError::CapacityExceeded));
    }
    let StrictValue(value) = serde_json::from_slice(body.bytes())
        .map_err(|_| failure(ProtocolError::InvalidArguments))?;
    let state = match request.format {
        StateFormat::Native => {
            let state: NativeState = serde_json::from_value(value)
                .map_err(|_| failure(ProtocolError::InvalidArguments))?;
            client_state::validate_state(&state).map_err(|error| {
                StateDispatchFailure::state(&scope.identity_scope, error, false)
            })?;
            state
        }
        StateFormat::Playwright => client_state::convert_playwright_state(value)
            .map_err(|error| StateDispatchFailure::state(&scope.identity_scope, error, false))?,
    };
    check_scope(scope, operation).map_err(failure)?;
    Ok(PreparedRestore {
        blobs,
        scope: scope.clone(),
        handle: request.body_handle,
        operation_sequence: operation.sequence,
        body,
        state,
    })
}
impl PreparedRestore<'_> {
    /// Call synchronously at lifecycle acceptance, before revoking the source
    /// blob scope or dispatching replacement writes. This method does not itself
    /// accept/replace a lifecycle scope. Revalidate the same opaque handle after
    /// releasing the immutable borrow; concurrent release/reservation rejects.
    pub fn accept(
        self,
        operation: &OperationLease,
    ) -> Result<AcceptedRestore, StateDispatchFailure> {
        let failure = |error| StateDispatchFailure::unchanged(&self.scope.identity_scope, error);
        check_scope(&self.scope, operation).map_err(failure)?;
        if self.operation_sequence != operation.sequence {
            return Err(failure(ProtocolError::InvalidSequence));
        }
        drop(self.body);
        let token = uuid::Uuid::new_v4().to_string();
        self.blobs
            .reserve(&self.scope, &self.handle, &token)
            .map_err(|error| failure(blob_error(error)))?;
        let body = match self.blobs.commit(&self.scope, &self.handle, &token) {
            Ok(body) => body,
            Err(error) => {
                let mut failure = failure(blob_error(error));
                failure.cleanup_integrity_lost = self.blobs.rollback(&token).is_err();
                return Err(failure);
            }
        };
        Ok(AcceptedRestore {
            generation: self.scope.generation,
            operation_sequence: self.operation_sequence,
            source_identity_scope: self.scope.identity_scope,
            _body: body,
            state: self.state,
        })
    }
}
impl AcceptedRestore {
    /// Seed these origins into the replacement's historical owner inventory at
    /// publication. Bootstrap documents intentionally bypass application events.
    pub fn origins(&self) -> impl Iterator<Item = &str> {
        self.state
            .origins
            .iter()
            .map(|origin| origin.origin.as_str())
    }
    pub async fn import(
        self,
        context: &CapturedStateContext<'_>,
        operation: &OperationLease,
    ) -> Result<(), StateDispatchFailure> {
        context.check(operation)?;
        if context.kind != StateContextKind::Isolated {
            return Err(context.failure(ProtocolError::UnsupportedCapability));
        }
        if self.generation != operation.generation {
            return Err(context.failure(ProtocolError::StaleGeneration));
        }
        if self.operation_sequence != operation.sequence {
            return Err(context.failure(ProtocolError::InvalidSequence));
        }
        if self.source_identity_scope == context.page.identity_scope {
            return Err(context.failure(ProtocolError::StaleScope));
        }
        // The shared primitive rejects a nonblank destination before writes.
        client_state::import_state(&context.context, &self.state, operation)
            .await
            .map_err(|error| {
                StateDispatchFailure::outcome(&context.page.identity_scope, error, true)
            })?;
        context.check(operation).map_err(|mut failure| {
            failure.discard_context = true;
            failure
        })
    }
}

/// serde_json::Value normally keeps the last duplicate object key. Reject
/// duplicates at every depth before format conversion, while retaining serde's
/// recursion/UTF-8/number limits and rejecting trailing JSON input.
struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("strict JSON value")
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|n| StrictValue(Value::Number(n)))
                    .ok_or_else(|| E::custom("Invalid JSON number"))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(StrictValue(value)) = input.next_element()? {
                    values.push(value);
                }
                Ok(StrictValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = input.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("Duplicate JSON key"));
                    }
                    let StrictValue(value) = input.next_value()?;
                    values.insert(key, value);
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::super::cdp::client::CdpClient;
    use super::super::client_blobs::BlobLimits;
    use super::super::client_browser::ExecutionGate;
    use super::super::client_targets::ClientTargets;
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use serde_json::json;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::sync::watch;

    fn operation() -> (watch::Sender<CancelSignal>, OperationLease) {
        let (sender, cancellation) = watch::channel(CancelSignal::None);
        (
            sender,
            OperationLease {
                is_callback: false,
                generation: 1,
                sequence: 1,
                deadline: Instant::now() + Duration::from_secs(5),
                cancellation,
            },
        )
    }
    fn scope() -> BlobScope {
        BlobScope {
            generation: 1,
            identity_scope: "scope".into(),
        }
    }
    fn store() -> BlobStore {
        let blobs = BlobStore::new(BlobLimits {
            max_blob_bytes: 4096,
            max_total_bytes: 4096,
            max_handles: 8,
        })
        .unwrap();
        blobs.activate_scope(scope()).unwrap();
        blobs
    }
    fn request(handle: &str, format: &str) -> Value {
        json!({"identityScope":"scope","format":format,"version":1,"bodyHandle":handle})
    }
    const NATIVE: &[u8] = br#"{"version":1,"cookies":[],"origins":[]}"#;
    const NATIVE_FORMAT: &str = "agent-browser-storage-state";
    const LEGACY_FORMAT: &str = "playwright-storage-state";

    #[test]
    fn strict_preflight_rejects_invalid_data_without_consuming_uploads() {
        let (_cancel, op) = operation();
        for bytes in [
            br#"{"version":1,"version":1,"cookies":[],"origins":[]}"#.as_slice(),
            br#"{"version":1,"cookies":[],"origins":[],"extra":true}"#,
            br#"{"version":2,"cookies":[],"origins":[]}"#,
            br#"{"version":1,"cookies":[{"name":"n","name":"other"}],"origins":[]}"#,
            br#"{"version":1,"cookies":[],"origins":[{"origin":"https://fixture.invalid/path","localStorage":[],"indexedDb":[]}]}"#,
            br#"{"version":1,"cookies":[],"origins":[{"origin":"https://fixture.invalid","localStorage":[{"name":"x","value":"one"},{"name":"x","value":"two"}],"indexedDb":[]}]}"#,
            br#"{"version":1,"cookies":[],"origins":[]} {}"#,
            &[0xff],
        ] {
            let blobs = store();
            let blob = blobs.insert_sealed(scope(), bytes).unwrap();
            assert!(prepare_restore(&blobs, &scope(), &request(&blob.handle, NATIVE_FORMAT), &op).is_err());
            blobs.release(&scope(), &blob.handle).unwrap();
        }
    }
    #[test]
    fn strict_wire_envelope_rejects_unknown_or_mixed_fields() {
        let blobs = store();
        let blob = blobs.insert_sealed(scope(), NATIVE).unwrap();
        let (_cancel, op) = operation();
        for args in [
            json!({"identityScope":"scope","format":NATIVE_FORMAT,"version":1,"bodyHandle":blob.handle,"data":{}}),
            json!({"identityScope":"scope","format":"unknown","version":1,"bodyHandle":blob.handle}),
            json!({"identityScope":"scope","format":NATIVE_FORMAT,"version":2,"bodyHandle":blob.handle}),
            json!({"identityScope":"scope","format":NATIVE_FORMAT,"version":1,"bodyHandle":""}),
            json!({"identityScope":"scope","format":NATIVE_FORMAT,"version":1,"bodyHandle":blob.handle,"isolated":true}),
        ] {
            let failure = prepare_restore(&blobs, &scope(), &args, &op).err().unwrap();
            assert_eq!(failure.error, ProtocolError::InvalidArguments);
            assert!(!failure.cleanup_integrity_lost);
        }
        blobs.release(&scope(), &blob.handle).unwrap();
    }
    #[test]
    fn native_and_legacy_uploads_transfer_only_at_acceptance_and_keep_quota() {
        for (format, bytes) in [
            (NATIVE_FORMAT, NATIVE),
            (LEGACY_FORMAT, br#"{"cookies":[],"origins":[]}"#.as_slice()),
        ] {
            let blobs = store();
            let blob = blobs.insert_sealed(scope(), bytes).unwrap();
            let (_cancel, op) = operation();
            let prepared =
                prepare_restore(&blobs, &scope(), &request(&blob.handle, format), &op).unwrap();
            assert_eq!(blobs.read(&scope(), &blob.handle, 0, 4096).unwrap(), bytes);
            let accepted = prepared.accept(&op).unwrap();
            assert_eq!(
                blobs.release(&scope(), &blob.handle),
                Err(BlobError::Missing)
            );
            assert_eq!(
                blobs.reserve_producer(scope()).err().unwrap(),
                BlobError::QuotaExceeded
            );
            drop(accepted);
            assert!(blobs.reserve_producer(scope()).is_ok());
        }
    }
    #[test]
    fn rejected_or_abandoned_preflight_preserves_caller_release() {
        let (_cancel, op) = operation();
        let blobs = store();
        let blob = blobs.insert_sealed(scope(), NATIVE).unwrap();
        drop(
            prepare_restore(&blobs, &scope(), &request(&blob.handle, NATIVE_FORMAT), &op).unwrap(),
        );
        blobs.release(&scope(), &blob.handle).unwrap();

        let blob = blobs.insert_sealed(scope(), NATIVE).unwrap();
        let prepared =
            prepare_restore(&blobs, &scope(), &request(&blob.handle, NATIVE_FORMAT), &op).unwrap();
        blobs.release(&scope(), &blob.handle).unwrap();
        assert_eq!(
            prepared.accept(&op).err().unwrap().error,
            ProtocolError::InvalidArguments
        );
        assert!(blobs.reserve_producer(scope()).is_ok());
    }
    #[test]
    fn acceptance_revalidates_live_generation_cancellation_and_same_handle() {
        let (cancel, mut op) = operation();
        let blobs = store();
        let blob = blobs.insert_sealed(scope(), NATIVE).unwrap();
        let prepared =
            prepare_restore(&blobs, &scope(), &request(&blob.handle, NATIVE_FORMAT), &op).unwrap();
        op.generation = 2;
        assert_eq!(
            prepared.accept(&op).err().unwrap().error,
            ProtocolError::StaleGeneration
        );
        op.generation = 1;
        let prepared =
            prepare_restore(&blobs, &scope(), &request(&blob.handle, NATIVE_FORMAT), &op).unwrap();
        op.sequence = 2;
        assert_eq!(
            prepared.accept(&op).err().unwrap().error,
            ProtocolError::InvalidSequence
        );
        op.sequence = 1;
        let prepared =
            prepare_restore(&blobs, &scope(), &request(&blob.handle, NATIVE_FORMAT), &op).unwrap();
        let other_borrow = blobs.borrow_sealed(&scope(), &blob.handle).unwrap();
        assert_eq!(
            prepared.accept(&op).err().unwrap().error,
            ProtocolError::InvalidArguments
        );
        drop(other_borrow);
        let prepared =
            prepare_restore(&blobs, &scope(), &request(&blob.handle, NATIVE_FORMAT), &op).unwrap();
        cancel.send(CancelSignal::Requested).unwrap();
        assert_eq!(
            prepared.accept(&op).err().unwrap().error,
            ProtocolError::Cancelled
        );
        blobs.release(&scope(), &blob.handle).unwrap();
    }
    #[test]
    fn capped_writer_does_not_partially_append_oversized_writes() {
        let mut writer = BoundedWriter {
            bytes: Vec::new(),
            limit: 3,
        };
        writer.write_all(b"ab").unwrap();
        assert!(writer.write_all(b"cd").is_err());
        assert_eq!(writer.bytes, b"ab");
        writer.write_all(b"c").unwrap();
        assert_eq!(writer.bytes, b"abc");
    }
    #[test]
    fn cleanup_integrity_is_distinct_from_original_error_and_import_disposal() {
        let original = StateDispatchFailure::state("scope", StateError::Cancelled, false);
        assert_eq!(original.error, ProtocolError::Cancelled);
        assert!(!original.cleanup_integrity_lost && !original.discard_context);
        let dirty = StateDispatchFailure::state("scope", StateError::CleanupIntegrityLost, false);
        assert_eq!(dirty.error, ProtocolError::CleanupFailed);
        assert!(dirty.cleanup_integrity_lost && dirty.discard_context);
        let combined = StateDispatchFailure::outcome(
            "scope",
            StateFailure {
                error: StateError::Cancelled,
                cleanup_integrity_lost: true,
            },
            false,
        );
        assert_eq!(combined.error, ProtocolError::Cancelled);
        assert!(combined.cleanup_integrity_lost && combined.discard_context);
        let import = StateDispatchFailure::state("replacement", StateError::BrowserFailure, true);
        assert_eq!(import.error, ProtocolError::BrowserFailure);
        assert!(!import.cleanup_integrity_lost && import.discard_context);
    }

    struct Harness {
        page: BrowserExecutionLease,
        ui: Arc<UiGate>,
        log: Arc<Mutex<Vec<String>>>,
        poison_on_capture: Arc<std::sync::atomic::AtomicBool>,
        reject_bootstrap_create: Arc<std::sync::atomic::AtomicBool>,
        server: tokio::task::JoinHandle<()>,
    }
    impl Drop for Harness {
        fn drop(&mut self) {
            self.server.abort();
        }
    }
    impl Harness {
        async fn new(fail_import: bool) -> Self {
            Self::named(fail_import, "scope").await
        }
        async fn named(fail_import: bool, identity_scope: &str) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let log = Arc::new(Mutex::new(Vec::new()));
            let commands = log.clone();
            let poison_on_capture = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let poison = poison_on_capture.clone();
            let reject_bootstrap_create = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let reject_create = reject_bootstrap_create.clone();
            let targets = ClientTargets::new("context".into(), identity_scope.into());
            let event_targets = targets.clone();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                while let Some(Ok(message)) = socket.next().await {
                    let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
                    let method = request["method"].as_str().unwrap();
                    commands.lock().unwrap().push(method.to_owned());
                    let response = if (method == "Storage.setCookies" && fail_import)
                        || (method == "Target.createTarget"
                            && reject_create.load(std::sync::atomic::Ordering::SeqCst))
                    {
                        json!({"id":request["id"],"error":{"code":-32000,"message":"synthetic failure"}})
                    } else {
                        let result = match method {
                            "Storage.getCookies" => {
                                if poison.load(std::sync::atomic::Ordering::SeqCst) {
                                    event_targets.seal();
                                }
                                json!({"cookies":[]})
                            }
                            "Storage.setCookies" => json!({}),
                            _ => panic!("Unexpected synthetic CDP method"),
                        };
                        json!({"id":request["id"],"result":result})
                    };
                    if socket
                        .send(tokio_tungstenite::tungstenite::Message::Text(
                            response.to_string(),
                        ))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            let client = Arc::new(CdpClient::connect(&url).await.unwrap());
            let gate = Arc::new(ExecutionGate::default());
            Self {
                page: BrowserExecutionLease {
                    client,
                    page_session_id: "session".into(),
                    target_id: "target".into(),
                    identity_scope: identity_scope.into(),
                    permit: gate.enter(false).unwrap(),
                    targets,
                },
                ui: Arc::new(UiGate::default()),
                log,
                poison_on_capture,
                reject_bootstrap_create,
                server,
            }
        }
        fn native<'a>(&'a self, origins: &'a [String], complete: bool) -> NativeStateContext<'a> {
            NativeStateContext {
                client: self.page.client.as_ref(),
                context_id: "context",
                targets: &self.page.targets,
                origins,
                origins_complete: complete,
            }
        }
        async fn exclusive(&self, op: &OperationLease) -> UiPermit {
            self.ui
                .enter(true, false, op.deadline, op.cancellation.clone())
                .await
                .unwrap()
        }
        fn captured<'a>(&'a self, permit: &'a UiPermit) -> CapturedStateContext<'a> {
            CapturedStateContext::new(
                &self.page,
                &self.ui,
                permit,
                self.native(&[], true),
                StateContextKind::Isolated,
            )
            .unwrap()
        }
    }
    #[tokio::test]
    async fn capture_reserves_before_export_and_emits_exact_blob_contract() {
        let harness = Harness::new(false).await;
        let (_cancel, op) = operation();
        let permit = harness.exclusive(&op).await;
        let context = harness.captured(&permit);
        let too_small = store();
        assert_eq!(
            capture_state(&context, &too_small, &scope(), &op)
                .await
                .err()
                .unwrap()
                .error,
            ProtocolError::CapacityExceeded
        );
        assert!(harness.log.lock().unwrap().is_empty());
        // Reservation accounting only: no 32 MiB buffer or payload allocated.
        let blobs = BlobStore::new(BlobLimits {
            max_blob_bytes: MAX_STATE_BYTES,
            max_total_bytes: MAX_STATE_BYTES,
            max_handles: 8,
        })
        .unwrap();
        blobs.activate_scope(scope()).unwrap();
        let occupied = blobs.insert_sealed(scope(), b"synthetic").unwrap();
        assert_eq!(
            capture_state(&context, &blobs, &scope(), &op)
                .await
                .err()
                .unwrap()
                .error,
            ProtocolError::CapacityExceeded
        );
        assert!(harness.log.lock().unwrap().is_empty());
        blobs.release(&scope(), &occupied.handle).unwrap();
        let captured = capture_state(&context, &blobs, &scope(), &op)
            .await
            .unwrap();
        assert_eq!(*harness.log.lock().unwrap(), ["Storage.getCookies"]);
        let envelope = serde_json::to_value(&captured).unwrap();
        assert_eq!(envelope["format"], NATIVE_FORMAT);
        assert_eq!(envelope["version"], 1);
        assert_eq!(envelope["identityScope"], "scope");
        assert_eq!(envelope["handle"], captured.blob.handle);
        assert!(envelope.get("bodyHandle").is_none());
        assert_eq!(envelope.as_object().unwrap().len(), 6);
        let bytes = blobs
            .read(&scope(), &captured.blob.handle, 0, 4096)
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            json!({"version":1,"cookies":[],"origins":[]})
        );
        blobs.release(&scope(), &captured.blob.handle).unwrap();
    }
    #[tokio::test]
    async fn capture_requires_exclusive_exact_gate_complete_context() {
        for kind in [StateContextKind::Isolated, StateContextKind::Persistent] {
            let harness = Harness::new(false).await;
            let (_cancel, op) = operation();
            let ordinary = harness
                .ui
                .enter(false, false, op.deadline, op.cancellation.clone())
                .await
                .unwrap();
            assert_eq!(
                CapturedStateContext::new(
                    &harness.page,
                    &harness.ui,
                    &ordinary,
                    harness.native(&[], true),
                    kind
                )
                .err()
                .unwrap()
                .error,
                ProtocolError::InvalidArguments
            );
            drop(ordinary);
            let permit = harness.exclusive(&op).await;
            let other_ui = Arc::new(UiGate::default());
            assert_eq!(
                CapturedStateContext::new(
                    &harness.page,
                    &other_ui,
                    &permit,
                    harness.native(&[], true),
                    kind
                )
                .err()
                .unwrap()
                .error,
                ProtocolError::InvalidArguments
            );
            assert_eq!(
                CapturedStateContext::new(
                    &harness.page,
                    &harness.ui,
                    &permit,
                    harness.native(&[], false),
                    kind
                )
                .err()
                .unwrap()
                .error,
                ProtocolError::ScopeUnavailable
            );
            let other_targets = ClientTargets::new("context".into(), "scope".into());
            let mut native = harness.native(&[], true);
            native.targets = &other_targets;
            assert_eq!(
                CapturedStateContext::new(&harness.page, &harness.ui, &permit, native, kind)
                    .err()
                    .unwrap()
                    .error,
                ProtocolError::StaleScope
            );
            harness.ui.seal();
            assert_eq!(
                CapturedStateContext::new(
                    &harness.page,
                    &harness.ui,
                    &permit,
                    harness.native(&[], true),
                    kind
                )
                .err()
                .unwrap()
                .error,
                ProtocolError::StaleScope
            );
            assert!(harness.log.lock().unwrap().is_empty());
        }
    }
    #[tokio::test]
    async fn persistent_capture_uses_shared_export_without_host_lifetime_commands() {
        let harness = Harness::new(false).await;
        let (_cancel, op) = operation();
        harness
            .page
            .targets
            .attached("context", "target".into(), "session".into(), "page".into())
            .unwrap();
        harness.page.targets.configured("target").unwrap();
        harness
            .page
            .targets
            .resume_permit("target")
            .await
            .unwrap()
            .complete()
            .unwrap();
        let permit = harness.exclusive(&op).await;
        let context = CapturedStateContext::new(
            &harness.page,
            &harness.ui,
            &permit,
            harness.native(&[], true),
            StateContextKind::Persistent,
        )
        .unwrap();
        // Even borrowed capture reserves the full shared logical-state budget
        // before any export RPC. This is accounting, not a large allocation.
        assert_eq!(
            capture_state(&context, &store(), &scope(), &op)
                .await
                .unwrap_err()
                .error,
            ProtocolError::CapacityExceeded
        );
        assert!(harness.log.lock().unwrap().is_empty());
        let blobs = BlobStore::new(BlobLimits {
            max_blob_bytes: MAX_STATE_BYTES,
            max_total_bytes: MAX_STATE_BYTES,
            max_handles: 8,
        })
        .unwrap();
        blobs.activate_scope(scope()).unwrap();
        let captured = capture_state(&context, &blobs, &scope(), &op)
            .await
            .unwrap();
        assert_eq!(captured.identity_scope, "scope");
        assert_eq!(captured.format, NATIVE_FORMAT);
        assert_eq!(captured.version, 1);
        assert_eq!(
            serde_json::from_slice::<Value>(
                &blobs
                    .read(&scope(), &captured.blob.handle, 0, 4096)
                    .unwrap()
            )
            .unwrap(),
            json!({"version":1,"cookies":[],"origins":[]})
        );
        assert_eq!(*harness.log.lock().unwrap(), ["Storage.getCookies"]);
        let host = harness.page.targets.owned_target("target").unwrap();
        assert_eq!(host.session_id, "session");
        assert_eq!(host.purpose, Some(TargetPurpose::Application));
        assert!(host.configured && host.resumed);
        blobs.release(&scope(), &captured.blob.handle).unwrap();
    }
    #[tokio::test]
    async fn persistent_capture_cleanup_uncertainty_never_grants_host_context_disposal() {
        for kind in [StateContextKind::Isolated, StateContextKind::Persistent] {
            let harness = Harness::new(false).await;
            let (_cancel, op) = operation();
            let permit = harness.exclusive(&op).await;
            let origins = ["https://observed.invalid".into()];
            let context = CapturedStateContext::new(
                &harness.page,
                &harness.ui,
                &permit,
                harness.native(&origins, true),
                kind,
            )
            .unwrap();
            harness
                .reject_bootstrap_create
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let blobs = BlobStore::new(BlobLimits {
                max_blob_bytes: MAX_STATE_BYTES,
                max_total_bytes: MAX_STATE_BYTES,
                max_handles: 8,
            })
            .unwrap();
            blobs.activate_scope(scope()).unwrap();
            let failure = capture_state(&context, &blobs, &scope(), &op)
                .await
                .unwrap_err();
            assert_eq!(failure.error, ProtocolError::BrowserFailure);
            assert_eq!(failure.identity_scope, "scope");
            assert!(failure.cleanup_integrity_lost);
            assert_eq!(failure.discard_context, kind == StateContextKind::Isolated);
            assert_eq!(
                *harness.log.lock().unwrap(),
                ["Storage.getCookies", "Target.createTarget"]
            );
            assert!(blobs.reserve_producer(scope()).is_ok());
        }
    }
    #[tokio::test]
    async fn accepted_restore_rejects_persistent_capture_authority_before_any_import_write() {
        let harness = Harness::named(false, "replacement").await;
        let (_cancel, op) = operation();
        let permit = harness.exclusive(&op).await;
        let context = CapturedStateContext::new(
            &harness.page,
            &harness.ui,
            &permit,
            harness.native(&[], true),
            StateContextKind::Persistent,
        )
        .unwrap();
        let blobs = store();
        let blob = blobs.insert_sealed(scope(), NATIVE).unwrap();
        let accepted =
            prepare_restore(&blobs, &scope(), &request(&blob.handle, NATIVE_FORMAT), &op)
                .unwrap()
                .accept(&op)
                .unwrap();
        let failure = accepted.import(&context, &op).await.unwrap_err();
        assert_eq!(failure.error, ProtocolError::UnsupportedCapability);
        assert!(!failure.cleanup_integrity_lost);
        assert!(!failure.discard_context);
        assert!(harness.log.lock().unwrap().is_empty());
        // The lifecycle owner must reject persistent restore before acceptance;
        // this defensive import refusal never resurrects an accepted upload.
        assert_eq!(
            blobs.release(&scope(), &blob.handle),
            Err(BlobError::Missing)
        );
        assert!(blobs.reserve_producer(scope()).is_ok());
    }
    #[tokio::test]
    async fn accepted_restore_delegates_import_and_never_restores_upload_on_failure() {
        for fail_import in [false, true] {
            let harness = Harness::named(fail_import, "replacement").await;
            let (_cancel, op) = operation();
            let permit = harness.exclusive(&op).await;
            let context = harness.captured(&permit);
            let blobs = store();
            let blob = blobs.insert_sealed(scope(), NATIVE).unwrap();
            let accepted =
                prepare_restore(&blobs, &scope(), &request(&blob.handle, NATIVE_FORMAT), &op)
                    .unwrap()
                    .accept(&op)
                    .unwrap();
            let result = accepted.import(&context, &op).await;
            if fail_import {
                let failure = result.err().unwrap();
                assert_eq!(failure.error, ProtocolError::BrowserFailure);
                assert!(failure.discard_context);
                assert!(!failure.cleanup_integrity_lost);
            } else {
                result.unwrap();
            }
            assert_eq!(*harness.log.lock().unwrap(), ["Storage.setCookies"]);
            assert_eq!(
                blobs.release(&scope(), &blob.handle),
                Err(BlobError::Missing)
            );
            assert!(blobs.reserve_producer(scope()).is_ok());
        }
    }
    #[tokio::test]
    async fn accepted_restore_rejects_nonblank_inventory_without_browser_write() {
        let harness = Harness::named(false, "replacement").await;
        let (_cancel, op) = operation();
        let permit = harness.exclusive(&op).await;
        let origins = ["https://fixture.invalid".to_owned()];
        let context = CapturedStateContext::new(
            &harness.page,
            &harness.ui,
            &permit,
            harness.native(&origins, true),
            StateContextKind::Isolated,
        )
        .unwrap();
        let blobs = store();
        let blob = blobs.insert_sealed(scope(), NATIVE).unwrap();
        let accepted =
            prepare_restore(&blobs, &scope(), &request(&blob.handle, NATIVE_FORMAT), &op)
                .unwrap()
                .accept(&op)
                .unwrap();
        let failure = accepted.import(&context, &op).await.err().unwrap();
        assert_eq!(failure.error, ProtocolError::InvalidArguments);
        assert!(failure.discard_context);
        assert!(harness.log.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn accepted_restore_never_writes_the_original_live_identity() {
        let harness = Harness::new(false).await;
        let (_cancel, op) = operation();
        let permit = harness.exclusive(&op).await;
        let context = harness.captured(&permit);
        let blobs = store();
        let blob = blobs.insert_sealed(scope(), NATIVE).unwrap();
        let accepted =
            prepare_restore(&blobs, &scope(), &request(&blob.handle, NATIVE_FORMAT), &op)
                .unwrap()
                .accept(&op)
                .unwrap();
        let failure = accepted.import(&context, &op).await.err().unwrap();
        assert_eq!(failure.error, ProtocolError::StaleScope);
        assert!(!failure.discard_context);
        assert!(harness.log.lock().unwrap().is_empty());
        assert_eq!(
            blobs.release(&scope(), &blob.handle),
            Err(BlobError::Missing)
        );
    }
    #[tokio::test]
    async fn capture_rejects_unresumed_application_and_late_inventory_poison() {
        let harness = Harness::new(false).await;
        let (_cancel, op) = operation();
        let permit = harness.exclusive(&op).await;
        harness
            .page
            .targets
            .attached(
                "context",
                "pending".into(),
                "pending-session".into(),
                "page".into(),
            )
            .unwrap();
        harness.page.targets.configured("pending").unwrap();
        assert_eq!(
            CapturedStateContext::new(
                &harness.page,
                &harness.ui,
                &permit,
                harness.native(&[], true),
                StateContextKind::Isolated
            )
            .err()
            .unwrap()
            .error,
            ProtocolError::ScopeUnavailable
        );
        harness
            .page
            .targets
            .resume_permit("pending")
            .await
            .unwrap()
            .complete()
            .unwrap();
        let context = harness.captured(&permit);
        harness
            .poison_on_capture
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let blobs = BlobStore::new(BlobLimits {
            max_blob_bytes: MAX_STATE_BYTES,
            max_total_bytes: MAX_STATE_BYTES,
            max_handles: 8,
        })
        .unwrap();
        blobs.activate_scope(scope()).unwrap();
        let failure = capture_state(&context, &blobs, &scope(), &op)
            .await
            .err()
            .unwrap();
        assert_eq!(failure.error, ProtocolError::ScopeUnavailable);
        assert_eq!(*harness.log.lock().unwrap(), ["Storage.getCookies"]);
        assert!(blobs.reserve_producer(scope()).is_ok());
    }
}
