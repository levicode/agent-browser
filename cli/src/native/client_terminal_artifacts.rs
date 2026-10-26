//! Finalized attempt artifacts have no browser authority. This closed store is
//! moved into the terminal control loop before ordinary executor shutdown.
use std::collections::HashMap;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use super::client_blobs::{FrozenArtifact, MAX_CHUNK_BYTES};
use super::client_debt::OperationKey;
use super::client_protocol::ProtocolError;

pub(crate) struct FrozenRecordingBatch {
    key: OperationKey,
    scope: String,
    token: String,
    manifest: Value,
    // None is a released, exact-token tombstone, bounded by the fixed manifest.
    artifacts: HashMap<String, Option<FrozenArtifact>>,
}
impl FrozenRecordingBatch {
    pub(crate) fn new(
        key: OperationKey,
        scope: String,
        artifacts: Vec<(FrozenArtifact, String, u64)>,
    ) -> Self {
        let token = uuid::Uuid::new_v4().to_string();
        let segments: Vec<_> = artifacts
            .iter()
            .map(|(artifact, started_at, ordinal)| {
                json!({
                    "handle": artifact.info.handle, "size": artifact.info.size,
                    "sha256": artifact.info.sha256, "mediaType": "video/webm",
                    "startedAt": started_at, "ordinal": ordinal,
                })
            })
            .collect();
        let manifest = json!({"identityScope":scope,"failedOperationSeq":key.operation_seq,
            "token":token,"segments":segments});
        Self {
            key,
            scope,
            token,
            manifest,
            artifacts: artifacts
                .into_iter()
                .map(|(artifact, _, _)| (artifact.info.handle.clone(), Some(artifact)))
                .collect(),
        }
    }
    pub(crate) fn key(&self) -> OperationKey {
        self.key
    }
    fn identity(&self, generation: u64, scope: &str, failed: u64) -> Result<(), ProtocolError> {
        if generation != self.key.generation {
            return Err(ProtocolError::StaleGeneration);
        }
        if scope != self.scope || failed != self.key.operation_seq {
            return Err(ProtocolError::ScopeUnavailable);
        }
        Ok(())
    }
    fn token(&self, token: &str) -> Result<(), ProtocolError> {
        if token != self.token {
            Err(ProtocolError::ScopeUnavailable)
        } else {
            Ok(())
        }
    }
    pub(crate) fn command(
        &mut self,
        generation: u64,
        command: &str,
        args: Map<String, Value>,
    ) -> Result<Value, ProtocolError> {
        match command {
            "recording.finalized.collect" => {
                let request: Collect = decode(args)?;
                self.identity(
                    generation,
                    &request.identity_scope,
                    request.failed_operation_seq,
                )?;
                Ok(self.manifest.clone())
            }
            "recording.finalized.read" => {
                let request: Read = decode(args)?;
                self.identity(
                    generation,
                    &request.identity_scope,
                    request.failed_operation_seq,
                )?;
                self.token(&request.token)?;
                if request.max_bytes == 0 || request.max_bytes > MAX_CHUNK_BYTES {
                    return Err(ProtocolError::InvalidArguments);
                }
                let artifact = self
                    .artifacts
                    .get(&request.handle)
                    .and_then(Option::as_ref)
                    .ok_or(ProtocolError::ScopeUnavailable)?;
                let chunk = artifact
                    .read(request.offset, request.max_bytes)
                    .map_err(|_| ProtocolError::InvalidArguments)?;
                serde_json::to_value(chunk).map_err(|_| ProtocolError::BrowserFailure)
            }
            "recording.finalized.release" => {
                let request: Release = decode(args)?;
                self.identity(
                    generation,
                    &request.identity_scope,
                    request.failed_operation_seq,
                )?;
                self.token(&request.token)?;
                let artifact = self
                    .artifacts
                    .get_mut(&request.handle)
                    .ok_or(ProtocolError::ScopeUnavailable)?;
                artifact.take();
                Ok(json!({"released":true}))
            }
            _ => Err(ProtocolError::ScopeUnavailable),
        }
    }
}
fn decode<T: serde::de::DeserializeOwned>(args: Map<String, Value>) -> Result<T, ProtocolError> {
    serde_json::from_value(Value::Object(args)).map_err(|_| ProtocolError::InvalidArguments)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Collect {
    identity_scope: String,
    failed_operation_seq: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Read {
    identity_scope: String,
    failed_operation_seq: u64,
    token: String,
    handle: String,
    offset: usize,
    max_bytes: usize,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Release {
    identity_scope: String,
    failed_operation_seq: u64,
    token: String,
    handle: String,
}

#[cfg(test)]
mod tests {
    use super::super::client_blobs::{BlobLimits, BlobScope, BlobStore};
    use super::*;

    fn batch() -> (BlobStore, FrozenRecordingBatch) {
        let store = BlobStore::new(BlobLimits {
            max_blob_bytes: 16,
            max_total_bytes: 32,
            max_handles: 2,
        })
        .unwrap();
        let scope = BlobScope {
            generation: 1,
            identity_scope: "old-attempt".into(),
        };
        store.activate_scope(scope.clone()).unwrap();
        let authority = store.begin_artifact_attempt(&scope).unwrap();
        let mut reservation = store.reserve_artifact(&authority, &scope).unwrap();
        store.shrink_artifact(&mut reservation, 3).unwrap();
        store.revoke_scope(&scope).unwrap();
        let frozen = store
            .freeze_finalized_artifacts(&authority, 1, vec![(reservation, b"abc".to_vec())])
            .unwrap();
        assert!(store.reserve_artifact(&authority, &scope).is_err());
        let batch = FrozenRecordingBatch::new(
            OperationKey {
                generation: 1,
                operation_seq: 7,
            },
            scope.identity_scope,
            frozen
                .into_iter()
                .map(|blob| (blob, "2026-10-26T00:00:00.000Z".into(), 1))
                .collect(),
        );
        (store, batch)
    }
    fn args(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }
    #[test]
    fn terminal_batch_moves_quota_survives_store_close_and_releases_once() {
        let (store, mut batch) = batch();
        let collect = args(json!({"identityScope":"old-attempt","failedOperationSeq":7}));
        let manifest = batch
            .command(1, "recording.finalized.collect", collect.clone())
            .unwrap();
        assert_eq!(
            batch
                .command(1, "recording.finalized.collect", collect)
                .unwrap(),
            manifest
        );
        assert_eq!(store.charged_for_test(), (3, 1));
        store.close().unwrap();
        assert_eq!(store.charged_for_test(), (3, 1));
        let mut request = args(json!({"identityScope":"old-attempt","failedOperationSeq":7,
            "token":manifest["token"],"handle":manifest["segments"][0]["handle"],"offset":0,"maxBytes":3}));
        let chunk = batch
            .command(1, "recording.finalized.read", request.clone())
            .unwrap();
        assert_eq!(chunk, json!({"base64":"YWJj","nextOffset":3,"eof":true}));
        assert_eq!(
            batch
                .command(1, "recording.finalized.read", request.clone())
                .unwrap(),
            chunk
        );
        request.remove("offset");
        request.remove("maxBytes");
        assert_eq!(
            batch
                .command(1, "recording.finalized.release", request.clone())
                .unwrap(),
            json!({"released":true})
        );
        assert_eq!(store.charged_for_test(), (0, 0));
        assert!(batch
            .command(1, "recording.finalized.release", request)
            .is_ok());
        assert_eq!(store.charged_for_test(), (0, 0));
    }
    #[test]
    fn terminal_batch_rejects_foreign_identity_token_handle_and_unknown_fields() {
        let (store, mut batch) = batch();
        for (generation, value) in [
            (
                2,
                json!({"identityScope":"old-attempt","failedOperationSeq":7}),
            ),
            (
                1,
                json!({"identityScope":"other-attempt","failedOperationSeq":7}),
            ),
            (
                1,
                json!({"identityScope":"old-attempt","failedOperationSeq":8}),
            ),
            (
                1,
                json!({"identityScope":"old-attempt","failedOperationSeq":7,"command":"page.evaluate"}),
            ),
        ] {
            assert!(batch
                .command(generation, "recording.finalized.collect", args(value))
                .is_err());
        }
        let manifest = batch
            .command(
                1,
                "recording.finalized.collect",
                args(json!({"identityScope":"old-attempt","failedOperationSeq":7})),
            )
            .unwrap();
        for (token, handle) in [
            (json!("foreign"), manifest["segments"][0]["handle"].clone()),
            (manifest["token"].clone(), json!("foreign")),
        ] {
            let value = json!({"identityScope":"old-attempt","failedOperationSeq":7,"token":token,"handle":handle});
            assert!(batch
                .command(1, "recording.finalized.release", args(value))
                .is_err());
        }
        assert_eq!(store.charged_for_test(), (3, 1));
        assert!(batch.command(1, "recording.stop", Map::new()).is_err());
        drop(batch);
        assert_eq!(store.charged_for_test(), (0, 0));
    }
    #[test]
    fn terminal_batch_read_bounds_and_released_handle_never_recreate_bytes() {
        let (_, mut batch) = batch();
        let manifest = batch.manifest.clone();
        let base = json!({"identityScope":"old-attempt","failedOperationSeq":7,"token":manifest["token"],"handle":manifest["segments"][0]["handle"]});
        for (offset, max) in [(4, 1), (0, 0), (0, MAX_CHUNK_BYTES + 1)] {
            let mut value = base.clone();
            value["offset"] = json!(offset);
            value["maxBytes"] = json!(max);
            assert!(batch
                .command(1, "recording.finalized.read", args(value))
                .is_err());
        }
        batch
            .command(1, "recording.finalized.release", args(base.clone()))
            .unwrap();
        let mut value = base;
        value["offset"] = json!(0);
        value["maxBytes"] = json!(3);
        assert!(batch
            .command(1, "recording.finalized.read", args(value))
            .is_err());
    }
    #[test]
    fn frozen_quota_rejects_mixed_authority_retired_and_closed_stores() {
        for failure in ["mixed", "retired", "closed"] {
            let store = BlobStore::new(BlobLimits {
                max_blob_bytes: 16,
                max_total_bytes: 32,
                max_handles: 2,
            })
            .unwrap();
            let scope = BlobScope {
                generation: 1,
                identity_scope: "same-text".into(),
            };
            store.activate_scope(scope.clone()).unwrap();
            let authority = store.begin_artifact_attempt(&scope).unwrap();
            let other = store.begin_artifact_attempt(&scope).unwrap();
            let mut reservation = store
                .reserve_artifact(
                    if failure == "mixed" {
                        &other
                    } else {
                        &authority
                    },
                    &scope,
                )
                .unwrap();
            store.shrink_artifact(&mut reservation, 3).unwrap();
            if failure == "retired" {
                authority.retire().unwrap();
            }
            if failure == "closed" {
                store.close().unwrap();
            }
            assert!(store
                .freeze_finalized_artifacts(&authority, 1, vec![(reservation, b"abc".to_vec())])
                .is_err());
            assert_eq!(store.charged_for_test(), (0, 0));
        }
    }
}
