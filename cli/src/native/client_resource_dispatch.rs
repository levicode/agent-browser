//! Typed, scope-captured resource commands. No browser discovery, filesystem
//! paths, callback execution, or lifecycle ownership belongs in this module.
use std::collections::HashSet;
use std::time::Instant;

use base64::Engine;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};

use super::client_blobs::{BlobError, BlobScope, BlobStore, MAX_CHUNK_BYTES};
use super::client_browser::ScopePermit;
use super::client_network::ClientNetwork;
use super::client_protocol::{Effects, ProtocolError};
use super::client_session::{CancelSignal, OperationLease};

pub struct ResourceContext<'a> {
    pub network: &'a ClientNetwork,
    pub blobs: &'a BlobStore,
    pub scope: &'a BlobScope,
    pub operation: &'a OperationLease,
    pub permit: &'a ScopePermit,
}
#[derive(Debug)]
pub struct ResourceFailure {
    pub error: ProtocolError,
    pub effects: Effects,
}
impl ResourceContext<'_> {
    fn check(&self) -> Result<(), ProtocolError> {
        self.permit.check()?;
        if self.operation.generation != self.scope.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if self.scope.identity_scope.is_empty() {
            return Err(ProtocolError::StaleScope);
        }
        self.network.validate_scope(self.scope)?;
        if *self.operation.cancellation.borrow() != CancelSignal::None {
            return Err(ProtocolError::Cancelled);
        }
        if Instant::now() >= self.operation.deadline {
            return Err(ProtocolError::DeadlineExceeded);
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Handle {
    handle: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Read {
    handle: String,
    offset: usize,
    max_bytes: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    size: usize,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Write {
    handle: String,
    offset: usize,
    base64: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Routes {
    version: u64,
    registration_ids: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Subscription {
    subscription_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Dialog {
    enabled: bool,
}
enum Command {
    BlobCreate(Create),
    BlobWrite(Write),
    BlobSeal(Handle),
    BlobRelease(Handle),
    BlobRead(Read),
    Routes(Routes),
    ResponsesSubscribe,
    ResponsesUnsubscribe(Subscription),
    BodyRead(Read),
    BodyRelease(Handle),
    Dialog(Dialog),
    DownloadsSubscribe,
    DownloadsUnsubscribe(Subscription),
    DownloadMetadata(Handle),
    DownloadRead(Read),
    DownloadRelease(Handle),
}
fn decode<T: DeserializeOwned>(args: &Value) -> Result<T, ProtocolError> {
    serde_json::from_value(args.clone()).map_err(|_| ProtocolError::InvalidArguments)
}
fn id(value: &str, limit: usize) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > limit || value.chars().any(char::is_control) {
        Err(ProtocolError::InvalidArguments)
    } else {
        Ok(())
    }
}
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
fn integer(value: usize) -> Result<(), ProtocolError> {
    if value as u128 > MAX_SAFE_INTEGER as u128 {
        Err(ProtocolError::InvalidArguments)
    } else {
        Ok(())
    }
}
fn handle(args: &Value) -> Result<Handle, ProtocolError> {
    let a: Handle = decode(args)?;
    id(&a.handle, 1024)?;
    Ok(a)
}
fn subscription(args: &Value) -> Result<Subscription, ProtocolError> {
    let a: Subscription = decode(args)?;
    id(&a.subscription_id, 1024)?;
    Ok(a)
}
fn read(args: &Value) -> Result<Read, ProtocolError> {
    let a: Read = decode(args)?;
    id(&a.handle, 1024)?;
    integer(a.offset)?;
    if a.max_bytes == 0 || a.max_bytes > MAX_CHUNK_BYTES {
        return Err(ProtocolError::InvalidArguments);
    }
    Ok(a)
}
fn parse(name: &str, args: &Value) -> Result<Command, ProtocolError> {
    Ok(match name {
        "blob.create" => {
            let a: Create = decode(args)?;
            integer(a.size)?;
            if a.sha256.len() != 64
                || !a
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(ProtocolError::InvalidArguments);
            }
            Command::BlobCreate(a)
        }
        "blob.write" => {
            let a: Write = decode(args)?;
            id(&a.handle, 1024)?;
            integer(a.offset)?;
            if a.base64.len() > MAX_CHUNK_BYTES.div_ceil(3) * 4 {
                return Err(ProtocolError::InvalidArguments);
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&a.base64)
                .map_err(|_| ProtocolError::InvalidArguments)?;
            if bytes.is_empty()
                || bytes.len() > MAX_CHUNK_BYTES
                || base64::engine::general_purpose::STANDARD.encode(&bytes) != a.base64
            {
                return Err(ProtocolError::InvalidArguments);
            }
            Command::BlobWrite(a)
        }
        "blob.seal" => Command::BlobSeal(handle(args)?),
        "blob.release" => Command::BlobRelease(handle(args)?),
        "blob.read" => Command::BlobRead(read(args)?),
        "network.routes.replace" => {
            let a: Routes = decode(args)?;
            if a.version == 0 || a.version > MAX_SAFE_INTEGER || a.registration_ids.len() > 1024 {
                return Err(ProtocolError::InvalidArguments);
            }
            let mut seen = HashSet::new();
            for registration in &a.registration_ids {
                id(registration, 128)?;
                if !seen.insert(registration) {
                    return Err(ProtocolError::InvalidArguments);
                }
            }
            Command::Routes(a)
        }
        "network.responses.subscribe" => {
            let _: Empty = decode(args)?;
            Command::ResponsesSubscribe
        }
        "network.responses.unsubscribe" => Command::ResponsesUnsubscribe(subscription(args)?),
        "network.body.read" => Command::BodyRead(read(args)?),
        "network.body.release" => Command::BodyRelease(handle(args)?),
        "dialog.register" => Command::Dialog(decode(args)?),
        "download.subscribe" => {
            let _: Empty = decode(args)?;
            Command::DownloadsSubscribe
        }
        "download.unsubscribe" => Command::DownloadsUnsubscribe(subscription(args)?),
        "download.metadata" => Command::DownloadMetadata(handle(args)?),
        "download.read" => Command::DownloadRead(read(args)?),
        "download.release" => Command::DownloadRelease(handle(args)?),
        _ => return Err(ProtocolError::UnsupportedCommand),
    })
}
fn blob_error(error: BlobError) -> ProtocolError {
    match error {
        BlobError::StaleScope => ProtocolError::StaleScope,
        BlobError::QuotaExceeded => ProtocolError::CapacityExceeded,
        BlobError::Closed => ProtocolError::ScopeUnavailable,
        BlobError::Reserved => ProtocolError::PolicyDenied,
        _ => ProtocolError::InvalidArguments,
    }
}
fn value<T: serde::Serialize>(data: T) -> Result<Value, ProtocolError> {
    serde_json::to_value(data).map_err(|_| ProtocolError::BrowserFailure)
}
/// The caller validates/strips the reserved wire identityScope before decoding.
/// Successful commands are Completed. Rejected store operations have no effect;
/// this dispatcher never sends a browser command or makes an uncertain retry.
pub async fn execute(
    context: ResourceContext<'_>,
    name: &str,
    args: &Value,
) -> Result<Value, ResourceFailure> {
    let mut completed = false;
    let result = async {
        context.check()?;
        let command = parse(name, args)?;
        context.check()?;
        let result = match command {
            Command::BlobCreate(a)=>{let handle=context.blobs.create(context.scope.clone(),a.size,a.sha256.clone()).map_err(blob_error)?;
                completed=true;json!({"handle":handle,"size":a.size,"sha256":a.sha256,"maxChunkBytes":MAX_CHUNK_BYTES})},
            Command::BlobWrite(a)=>{let next=context.blobs.write(context.scope,&a.handle,a.offset,&a.base64).map_err(blob_error)?;completed=true;json!({"nextOffset":next})},
            Command::BlobSeal(a)=>{let info=context.blobs.seal(context.scope,&a.handle).map_err(blob_error)?;completed=true;value(info)?},
            Command::BlobRelease(a)=>{context.blobs.release(context.scope,&a.handle).map_err(blob_error)?;completed=true;json!({"released":true})},
            Command::BlobRead(a)=>value(context.blobs.read_chunk(context.scope,&a.handle,a.offset,a.max_bytes).map_err(blob_error)?)?,
            Command::Routes(a)=>{context.network.replace_routes(a.version,a.registration_ids)?;completed=true;Value::Null},
            Command::ResponsesSubscribe=>{let id=context.network.subscribe_responses()?;completed=true;json!({"subscriptionId":id})},
            Command::ResponsesUnsubscribe(a)=>{context.network.unsubscribe_responses(&a.subscription_id)?;completed=true;Value::Null},
            Command::BodyRead(a)|Command::DownloadRead(a)=>{
                let chunk=context.network.read_resource(&a.handle,a.offset,a.max_bytes,context.operation).await;
                context.check()?;value(chunk?)?},
            Command::BodyRelease(a)|Command::DownloadRelease(a)=>{context.network.release_body(&a.handle)?;completed=true;Value::Null},
            Command::Dialog(a)=>{context.network.register_dialog(a.enabled)?;completed=true;Value::Null},
            Command::DownloadsSubscribe=>{let id=context.network.subscribe_downloads()?;completed=true;json!({"subscriptionId":id})},
            Command::DownloadsUnsubscribe(a)=>{context.network.unsubscribe_downloads(&a.subscription_id)?;completed=true;Value::Null},
            Command::DownloadMetadata(a)=>{let metadata=context.network.download_metadata(&a.handle,context.operation).await;context.check()?;metadata?},
        };
        context.check()?;
        Ok(result)
    }.await;
    result.map_err(|error| ResourceFailure {
        error,
        effects: if completed {
            Effects::Completed
        } else {
            Effects::NotDispatched
        },
    })
}

#[cfg(test)]
mod tests {
    use super::super::cdp::client::CdpClient;
    use super::super::client_blobs::BlobLimits;
    use super::super::client_browser::ExecutionGate;
    use super::super::client_network::NetworkPolicy;
    use super::super::client_session::ClientSession;
    use super::super::client_transport::ClientEventSink;
    use super::super::client_ui::UiGate;
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use std::time::Duration;
    struct Fixture {
        network: ClientNetwork,
        blobs: Arc<BlobStore>,
        scope: BlobScope,
        operation: OperationLease,
        permit: ScopePermit,
        cancellation: tokio::sync::watch::Sender<CancelSignal>,
        server: tokio::task::JoinHandle<()>,
        _events: tokio::sync::mpsc::Receiver<super::super::client_protocol::ServerMessage>,
    }
    impl Fixture {
        async fn new() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
                while let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) =
                    socket.next().await
                {
                    let request: Value = serde_json::from_str(&text).unwrap();
                    if socket
                        .send(tokio_tungstenite::tungstenite::Message::Text(
                            json!({"id":request["id"],"result":{}}).to_string(),
                        ))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            let client = Arc::new(
                CdpClient::connect(&format!("ws://{address}"))
                    .await
                    .unwrap(),
            );
            let broker = Arc::new(ClientSession::new());
            let (sink, events) = ClientEventSink::test_channel(broker.clone());
            let scope = BlobScope {
                generation: 1,
                identity_scope: "resource-scope".into(),
            };
            let blobs = Arc::new(
                BlobStore::new(BlobLimits {
                    max_blob_bytes: 1024,
                    max_total_bytes: 2048,
                    max_handles: 8,
                })
                .unwrap(),
            );
            blobs.activate_scope(scope.clone()).unwrap();
            let network = ClientNetwork::new(
                client,
                broker,
                sink,
                scope.clone(),
                blobs.clone(),
                Arc::new(UiGate::default()),
                NetworkPolicy::default(),
            );
            let gate = Arc::new(ExecutionGate::default());
            let (cancellation, receiver) = tokio::sync::watch::channel(CancelSignal::None);
            Self {
                network,
                blobs,
                scope,
                operation: OperationLease {
                    generation: 1,
                    sequence: 1,
                    is_callback: false,
                    deadline: Instant::now() + Duration::from_secs(5),
                    cancellation: receiver,
                },
                permit: gate.enter(false).unwrap(),
                cancellation,
                server,
                _events: events,
            }
        }
        fn context(&self) -> ResourceContext<'_> {
            ResourceContext {
                network: &self.network,
                blobs: &self.blobs,
                scope: &self.scope,
                operation: &self.operation,
                permit: &self.permit,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }
    #[test]
    fn strict_preflight_rejects_unknown_fields_noncanonical_bodies_and_bad_ranges() {
        for (name, args) in [
            ("dialog.register", json!({"enabled":true,"unexpected":1})),
            (
                "network.responses.subscribe",
                json!({"identityScope":"not-stripped"}),
            ),
            ("blob.read", json!({"handle":"h","offset":-1,"maxBytes":1})),
            ("blob.read", json!({"handle":"h","offset":0,"maxBytes":0})),
            (
                "download.read",
                json!({"handle":"h","offset":0,"maxBytes":MAX_CHUNK_BYTES+1}),
            ),
            ("blob.write", json!({"handle":"h","offset":0,"base64":"YQ"})),
            ("blob.write", json!({"handle":"h","offset":0,"base64":""})),
            (
                "network.routes.replace",
                json!({"version":1,"registrationIds":["same","same"]}),
            ),
            (
                "network.routes.replace",
                json!({"version":0,"registrationIds":[]}),
            ),
            (
                "download.metadata",
                json!({"handle":"h","path":"/private/file"}),
            ),
        ] {
            assert!(
                matches!(parse(name, &args), Err(ProtocolError::InvalidArguments)),
                "{name}"
            );
        }
        assert!(matches!(
            parse("not.a.command", &json!({})),
            Err(ProtocolError::UnsupportedCommand)
        ));
    }
    #[tokio::test]
    async fn staged_body_roundtrip_and_reserved_release_are_exact() {
        let f = Fixture::new().await;
        let hash = format!("{:x}", Sha256::digest(b"abc"));
        let created = execute(f.context(), "blob.create", &json!({"size":3,"sha256":hash}))
            .await
            .unwrap();
        let handle = created["handle"].as_str().unwrap();
        assert_eq!(created["maxChunkBytes"], MAX_CHUNK_BYTES);
        assert_eq!(
            execute(
                f.context(),
                "blob.write",
                &json!({"handle":handle,"offset":0,"base64":"YWJj"})
            )
            .await
            .unwrap(),
            json!({"nextOffset":3})
        );
        let sealed = execute(f.context(), "blob.seal", &json!({"handle":handle}))
            .await
            .unwrap();
        assert_eq!(sealed["sha256"], hash);
        assert_eq!(
            execute(
                f.context(),
                "blob.read",
                &json!({"handle":handle,"offset":1,"maxBytes":2})
            )
            .await
            .unwrap(),
            json!({"base64":"YmM=","nextOffset":3,"eof":true})
        );
        f.blobs.reserve(&f.scope, handle, "decision-token").unwrap();
        let error = execute(f.context(), "blob.release", &json!({"handle":handle}))
            .await
            .unwrap_err();
        assert_eq!(error.error, ProtocolError::PolicyDenied);
        assert_eq!(error.effects, Effects::NotDispatched);
        f.blobs.rollback("decision-token").unwrap();
        assert_eq!(
            execute(f.context(), "blob.release", &json!({"handle":handle}))
                .await
                .unwrap(),
            json!({"released":true})
        );
    }
    #[tokio::test]
    async fn rejected_blob_validation_preserves_bytes_and_effect_classification() {
        let f = Fixture::new().await;
        let blob = f.blobs.insert_sealed(f.scope.clone(), b"abc").unwrap();
        let error = execute(
            f.context(),
            "blob.write",
            &json!({"handle":blob.handle,"offset":0,"base64":"eA=="}),
        )
        .await
        .unwrap_err();
        assert_eq!(error.effects, Effects::NotDispatched);
        assert_eq!(f.blobs.read(&f.scope, &blob.handle, 0, 3).unwrap(), b"abc");
        let error = execute(
            f.context(),
            "blob.create",
            &json!({"size":2048,"sha256":"0".repeat(64)}),
        )
        .await
        .unwrap_err();
        assert_eq!(error.error, ProtocolError::CapacityExceeded);
        assert_eq!(error.effects, Effects::NotDispatched);
    }
    #[tokio::test]
    async fn captured_generation_scope_and_cancellation_reject_before_mutation() {
        let mut f = Fixture::new().await;
        f.operation.generation = 2;
        assert_eq!(
            execute(f.context(), "dialog.register", &json!({"enabled":true}))
                .await
                .unwrap_err()
                .error,
            ProtocolError::StaleGeneration
        );
        f.operation.generation = 1;
        f.scope.identity_scope = "replacement".into();
        assert_eq!(
            execute(f.context(), "network.responses.subscribe", &json!({}))
                .await
                .unwrap_err()
                .error,
            ProtocolError::StaleScope
        );
        f.scope.identity_scope = "resource-scope".into();
        f.cancellation.send(CancelSignal::Requested).unwrap();
        let error = execute(
            f.context(),
            "network.routes.replace",
            &json!({"version":1,"registrationIds":[]}),
        )
        .await
        .unwrap_err();
        assert_eq!(error.error, ProtocolError::Cancelled);
        assert_eq!(error.effects, Effects::NotDispatched);
    }
    #[tokio::test]
    async fn response_registry_and_dialog_commands_have_exact_wire_shapes() {
        let f = Fixture::new().await;
        assert_eq!(
            execute(
                f.context(),
                "network.routes.replace",
                &json!({"version":1,"registrationIds":["route"]})
            )
            .await
            .unwrap(),
            Value::Null
        );
        let subscription = execute(f.context(), "network.responses.subscribe", &json!({}))
            .await
            .unwrap();
        assert!(subscription["subscriptionId"].as_str().is_some());
        assert_eq!(
            execute(f.context(), "network.responses.unsubscribe", &subscription)
                .await
                .unwrap(),
            Value::Null
        );
        assert_eq!(
            execute(f.context(), "dialog.register", &json!({"enabled":true}))
                .await
                .unwrap(),
            Value::Null
        );
        let error = execute(f.context(), "download.subscribe", &json!({}))
            .await
            .unwrap_err();
        assert_eq!(error.error, ProtocolError::UnsupportedCapability);
        assert_eq!(error.effects, Effects::NotDispatched);
        assert_eq!(
            execute(
                f.context(),
                "network.body.release",
                &json!({"handle":"missing"})
            )
            .await
            .unwrap(),
            Value::Null
        );
        assert_eq!(
            execute(
                f.context(),
                "download.release",
                &json!({"handle":"missing"})
            )
            .await
            .unwrap(),
            Value::Null
        );
    }
}
