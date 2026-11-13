//! Bounded `page.evaluate` payload transport, negotiated by
//! `browser.evaluate-blobs/1`.
//!
//! A request that would not fit one protocol frame arrives as a sealed,
//! scope-bound blob whose bytes are the inline `{source, argument}` payload; a
//! result that would not fit one frame is published the same way and read back
//! with `blob.read`. Small results keep their inline single-frame shape, and
//! `MAX_FRAME_BYTES` is never raised: the frame budget is spent on a bounded
//! descriptor instead of on the payload.

use serde::Deserialize;
use serde_json::{json, Map, Value};

use super::client_blobs::{BlobError, BlobScope, BlobStore, MAX_CHUNK_BYTES};
use super::client_protocol::{ProtocolError, MAX_FRAME_BYTES};

/// A serialized result at or below this bound is returned inline. The reserve
/// matches the existing observation result bound: correlation and outcome
/// metadata must still fit beside it in the same frame.
pub(crate) const INLINE_RESULT_BUDGET: usize = MAX_FRAME_BYTES - 16 * 1024;

/// The blob form of the inline `page.evaluate` argument object. Unknown keys
/// are refused so a staged request cannot carry authority the inline form
/// cannot express.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StagedRequest {
    source: String,
    argument: Value,
}

/// Replace `requestHandle` with the sealed blob's `source` and `argument`.
/// Inline requests are left untouched. A handle and either inline field in the
/// same request is ambiguous and refused before any read.
pub(crate) fn resolve_request(
    args: &mut Map<String, Value>,
    blobs: &BlobStore,
    scope: &BlobScope,
) -> Result<(), ProtocolError> {
    let Some(handle) = args.remove("requestHandle") else {
        return Ok(());
    };
    if args.contains_key("source") || args.contains_key("argument") {
        return Err(ProtocolError::InvalidArguments);
    }
    let handle = handle
        .as_str()
        .filter(|value| valid_handle(value))
        .ok_or(ProtocolError::InvalidArguments)?;
    // The lease borrows the already-charged bytes; it transfers no handle
    // authority and survives only this decode.
    let lease = blobs.borrow_sealed(scope, handle).map_err(blob_failure)?;
    let staged: StagedRequest =
        serde_json::from_slice(lease.bytes()).map_err(|_| ProtocolError::InvalidArguments)?;
    args.insert("source".into(), Value::String(staged.source));
    args.insert("argument".into(), staged.argument);
    Ok(())
}

/// Return the inline result when it fits, otherwise publish it as a sealed blob
/// and return its bounded descriptor. Without negotiated blob transfer an
/// oversized result is a clean refusal; the writer must never tear the client
/// transport down for one result.
pub(crate) fn finish_result(
    result: Result<Value, ProtocolError>,
    blob_transfer: bool,
    blobs: &BlobStore,
    scope: &BlobScope,
) -> Result<Value, ProtocolError> {
    let value = result?;
    let bytes = serde_json::to_vec(&value).map_err(|_| ProtocolError::CapacityExceeded)?;
    if bytes.len() <= INLINE_RESULT_BUDGET {
        return Ok(value);
    }
    if !blob_transfer {
        return Err(ProtocolError::CapacityExceeded);
    }
    let info = blobs
        .insert_sealed(scope.clone(), &bytes)
        .map_err(blob_failure)?;
    Ok(json!({
        "resultHandle": info.handle,
        "size": info.size,
        "sha256": info.sha256,
        "maxChunkBytes": MAX_CHUNK_BYTES,
    }))
}

fn valid_handle(handle: &str) -> bool {
    !handle.is_empty()
        && handle.len() <= 1024
        && !handle.chars().any(char::is_control)
        && !handle.contains('/')
        && !handle.contains('\\')
}

fn blob_failure(error: BlobError) -> ProtocolError {
    match error {
        BlobError::QuotaExceeded => ProtocolError::CapacityExceeded,
        BlobError::Closed => ProtocolError::ScopeUnavailable,
        BlobError::StaleScope => ProtocolError::StaleScope,
        _ => ProtocolError::InvalidArguments,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn store() -> (BlobStore, BlobScope) {
        let store = BlobStore::new(Default::default()).unwrap();
        let scope = BlobScope {
            generation: 1,
            identity_scope: "transfer-scope".into(),
        };
        store.activate_scope(scope.clone()).unwrap();
        (store, scope)
    }

    fn sealed(store: &BlobStore, scope: &BlobScope, bytes: &[u8]) -> String {
        store.insert_sealed(scope.clone(), bytes).unwrap().handle
    }

    #[test]
    fn inline_arguments_are_untouched() {
        let (store, scope) = store();
        let mut args = Map::from_iter([
            ("source".to_string(), json!("()=>1")),
            ("argument".to_string(), json!(null)),
        ]);
        resolve_request(&mut args, &store, &scope).unwrap();
        assert_eq!(args["source"], json!("()=>1"));
        assert_eq!(args["argument"], json!(null));
        assert!(!args.contains_key("requestHandle"));
    }

    #[test]
    fn sealed_request_blob_replaces_its_handle_with_the_inline_payload() {
        let (store, scope) = store();
        let payload = serde_json::to_vec(&json!({
            "source": "()=>arguments",
            "argument": {"padding": "x".repeat(2048)},
        }))
        .unwrap();
        let handle = sealed(&store, &scope, &payload);
        let mut args = Map::from_iter([("requestHandle".to_string(), json!(handle))]);
        resolve_request(&mut args, &store, &scope).unwrap();
        assert_eq!(args["source"], json!("()=>arguments"));
        assert_eq!(args["argument"]["padding"].as_str().unwrap().len(), 2048);
        assert!(!args.contains_key("requestHandle"));
    }

    #[test]
    fn staged_requests_refuse_ambiguous_unsealed_missing_and_foreign_input() {
        let (store, scope) = store();
        let payload = br#"{"source":"()=>1","argument":null}"#;

        // A handle plus an inline field is ambiguous, not a precedence question.
        let handle = sealed(&store, &scope, payload);
        let mut ambiguous = Map::from_iter([
            ("requestHandle".to_string(), json!(handle.clone())),
            ("source".to_string(), json!("()=>1")),
        ]);
        assert_eq!(
            resolve_request(&mut ambiguous, &store, &scope),
            Err(ProtocolError::InvalidArguments)
        );

        // An unsealed handle has no admitted bytes.
        let unsealed = store
            .create(scope.clone(), payload.len(), {
                use sha2::{Digest, Sha256};
                format!("{:x}", Sha256::digest(payload))
            })
            .unwrap();
        store
            .write(&scope, &unsealed, 0, &{
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(payload)
            })
            .unwrap();
        let mut late = Map::from_iter([("requestHandle".to_string(), json!(unsealed))]);
        assert_eq!(
            resolve_request(&mut late, &store, &scope),
            Err(ProtocolError::InvalidArguments)
        );

        for handle in [
            json!("missing-handle"),
            json!(7),
            json!("bad/handle"),
            json!("line\nbreak"),
        ] {
            let mut args = Map::from_iter([("requestHandle".to_string(), handle)]);
            assert_eq!(
                resolve_request(&mut args, &store, &scope),
                Err(ProtocolError::InvalidArguments)
            );
        }

        // A handle that names bytes in no admitted scope is not transferable.
        let mut other = Map::from_iter([("requestHandle".to_string(), json!("foreign-handle"))]);
        assert_eq!(
            resolve_request(&mut other, &store, &scope),
            Err(ProtocolError::InvalidArguments)
        );

        // Malformed or extended payloads never reach the evaluator.
        for bytes in [
            b"not json".as_slice(),
            br#"[]"#.as_slice(),
            br#"{"source":"()=>1"}"#.as_slice(),
            br#"{"source":7,"argument":null}"#.as_slice(),
            br#"{"source":"()=>1","argument":null,"extra":true}"#.as_slice(),
            br#"{"source":"()=>1","argument":null} trailing"#.as_slice(),
        ] {
            let handle = sealed(&store, &scope, bytes);
            let mut args = Map::from_iter([("requestHandle".to_string(), json!(handle))]);
            assert_eq!(
                resolve_request(&mut args, &store, &scope),
                Err(ProtocolError::InvalidArguments)
            );
        }
    }

    #[test]
    fn small_results_stay_inline_and_large_negotiated_results_stay_bounded() {
        let (store, scope) = store();
        let small = json!({"value": {"ok": true, "value": "small"}});
        assert_eq!(
            finish_result(Ok(small.clone()), true, &store, &scope).unwrap(),
            small
        );
        assert_eq!(
            finish_result(Ok(small.clone()), false, &store, &scope).unwrap(),
            small
        );

        let large = json!({"value": {"ok": true, "value": "x".repeat(4 * 1024 * 1024)}});
        let inline_bytes = serde_json::to_vec(&large).unwrap();
        assert!(inline_bytes.len() > INLINE_RESULT_BUDGET);

        let transferred = finish_result(Ok(large.clone()), true, &store, &scope).unwrap();
        let handle = transferred["resultHandle"].as_str().unwrap();
        assert_eq!(transferred["size"], json!(inline_bytes.len()));
        assert_eq!(transferred["maxChunkBytes"], json!(MAX_CHUNK_BYTES));
        // The descriptor is what must fit the frame; one chunk of blob.read is
        // itself below the frame bound by construction.
        assert!(serde_json::to_vec(&transferred).unwrap().len() < 1024);
        // The published blob is sealed: the handle resolves through the same
        // bounded chunk read the client uses.
        assert!(!store
            .read_chunk(&scope, handle, 0, MAX_CHUNK_BYTES)
            .unwrap()
            .base64
            .is_empty());

        let mut chunk_offset = 0;
        let mut reassembled = Vec::new();
        loop {
            let chunk = store
                .read_chunk(&scope, handle, chunk_offset, MAX_CHUNK_BYTES)
                .unwrap();
            reassembled.extend({
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(&chunk.base64)
                    .unwrap()
            });
            chunk_offset = chunk.next_offset;
            if chunk.eof {
                break;
            }
        }
        assert_eq!(reassembled, inline_bytes);
        assert_eq!(
            serde_json::from_slice::<Value>(&reassembled).unwrap(),
            large
        );
        store.release(&scope, handle).unwrap();

        // Without negotiation the same result is a clean capacity refusal, not
        // an oversized frame that ends the client transport.
        assert_eq!(
            finish_result(Ok(large), false, &store, &scope),
            Err(ProtocolError::CapacityExceeded)
        );
    }

    #[test]
    fn result_descriptor_and_failures_keep_their_closed_wire_codes() {
        let (store, scope) = store();
        let large = json!({"value": "x".repeat(2 * 1024 * 1024)});
        let transferred = finish_result(Ok(large), true, &store, &scope).unwrap();
        let handle = transferred["resultHandle"].as_str().unwrap().to_owned();
        store.release(&scope, &handle).unwrap();
        // A released handle cannot be read after the descriptor was published.
        assert!(store
            .read_chunk(&scope, transferred["resultHandle"].as_str().unwrap(), 0, 16)
            .is_err());

        // The evaluator's own refusal is preserved verbatim.
        assert_eq!(
            finish_result(Err(ProtocolError::BrowserFailure), true, &store, &scope),
            Err(ProtocolError::BrowserFailure)
        );
    }
}
