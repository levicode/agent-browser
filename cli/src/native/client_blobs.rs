//! Bounded opaque byte storage shared by uploads, responses and native artifacts.
//! No caller-controlled filesystem path is accepted. Memory reservations remain
//! charged while a committed browser operation still holds its body lease.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const MAX_CHUNK_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlobScope {
    pub generation: u64,
    pub identity_scope: String,
}

#[derive(Debug, Clone, Copy)]
pub struct BlobLimits {
    pub max_blob_bytes: usize,
    pub max_total_bytes: usize,
    pub max_handles: usize,
}
impl Default for BlobLimits {
    fn default() -> Self {
        Self {
            max_blob_bytes: 64 * 1024 * 1024,
            max_total_bytes: 128 * 1024 * 1024,
            max_handles: 128,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobError {
    InvalidInput,
    Missing,
    StaleScope,
    OffsetMismatch,
    Unsealed,
    IntegrityMismatch,
    Reserved,
    QuotaExceeded,
    Closed,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BlobInfo {
    pub handle: String,
    pub size: usize,
    pub sha256: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BlobChunk {
    pub base64: String,
    pub next_offset: usize,
    pub eof: bool,
}

struct Budget {
    bytes: usize,
    handles: usize,
    producers: HashMap<BlobScope, usize>,
    changed: tokio::sync::watch::Sender<()>,
    corrupt: bool,
}
impl Budget {
    fn remove_producer(&mut self, scope: &BlobScope, size: usize) -> Result<(), BlobError> {
        let remaining = self
            .producers
            .get(scope)
            .copied()
            .and_then(|bytes| bytes.checked_sub(size))
            .ok_or(BlobError::Closed)?;
        if remaining == 0 {
            self.producers.remove(scope);
        } else {
            self.producers.insert(scope.clone(), remaining);
        }
        Ok(())
    }
}
struct Charge {
    size: usize,
    budget: Arc<Mutex<Budget>>,
    producer_scope: Option<BlobScope>,
}
impl Drop for Charge {
    fn drop(&mut self) {
        if let Ok(mut budget) = self.budget.lock() {
            if let Some(scope) = &self.producer_scope {
                if budget.remove_producer(scope, self.size).is_err() {
                    budget.corrupt = true;
                }
            }
            match (
                budget.bytes.checked_sub(self.size),
                budget.handles.checked_sub(1),
            ) {
                (Some(bytes), Some(handles)) => {
                    budget.bytes = bytes;
                    budget.handles = handles;
                }
                _ => budget.corrupt = true,
            }
            budget.changed.send_replace(());
        }
    }
}
struct Entry {
    scope: BlobScope,
    bytes: Arc<Vec<u8>>,
    expected_sha256: String,
    hasher: Sha256,
    sealed: bool,
    reserved_by: Option<String>,
    charge: Arc<Charge>,
}
struct Inner {
    closed: bool,
    active_scope: Option<BlobScope>,
    entries: HashMap<String, Entry>,
}

pub struct BlobStore {
    limits: BlobLimits,
    budget: Arc<Mutex<Budget>>,
    inner: Mutex<Inner>,
}

/// Owns immutable bytes until native dispatch completes. Not Clone: a single
/// accepted token commits one body lease, while its quota remains reserved.
pub struct BlobLease {
    bytes: Arc<Vec<u8>>,
    _charge: Arc<Charge>,
}
impl BlobLease {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Reserves the maximum producer payload before collection. The charge survives
/// the await and failed/stale producers release it on drop without publishing.
pub struct BlobProducer {
    scope: BlobScope,
    charge: Charge,
}

/// Native-only attempt authority. It carries no blob handle or wire authority.
/// The lifecycle owner retires it before ending the attempt; publication and
/// retirement share a lock so a late producer cannot pass a check then publish.
pub struct AttemptArtifacts {
    state: Arc<ArtifactAuthority>,
}
struct ArtifactAuthority {
    generation: u64,
    budget: Arc<Mutex<Budget>>,
    retired: Mutex<bool>,
}
impl AttemptArtifacts {
    pub fn retire(&self) -> Result<(), BlobError> {
        *self.state.retired.lock().map_err(|_| BlobError::Closed)? = true;
        Ok(())
    }
}
impl Drop for AttemptArtifacts {
    fn drop(&mut self) {
        if let Ok(mut retired) = self.state.retired.lock() {
            *retired = true;
        }
    }
}
/// Quota ownership may survive page scope rotation, never attempt retirement.
/// Only a currently admitted scope can turn it into a new immutable blob.
pub struct ArtifactReservation {
    authority: Arc<ArtifactAuthority>,
    charge: Charge,
}

impl BlobStore {
    pub fn new(limits: BlobLimits) -> Result<Self, BlobError> {
        if limits.max_blob_bytes == 0
            || limits.max_blob_bytes > 512 * 1024 * 1024
            || limits.max_total_bytes < limits.max_blob_bytes
            || limits.max_total_bytes > 1024 * 1024 * 1024
            || limits.max_handles == 0
            || limits.max_handles > 1024
        {
            return Err(BlobError::InvalidInput);
        }
        Ok(Self {
            limits,
            budget: Arc::new(Mutex::new(Budget {
                bytes: 0,
                handles: 0,
                producers: HashMap::new(),
                changed: tokio::sync::watch::channel(()).0,
                corrupt: false,
            })),
            inner: Mutex::new(Inner {
                closed: false,
                active_scope: None,
                entries: HashMap::new(),
            }),
        })
    }

    /// Lifecycle-only admission. Producers must never activate scopes: they
    /// only insert into the currently admitted owner. No retired-scope history
    /// grows unbounded, and revocation seals late producer insertion atomically.
    pub fn activate_scope(&self, scope: BlobScope) -> Result<(), BlobError> {
        if scope.generation == 0 || scope.identity_scope.is_empty() {
            return Err(BlobError::InvalidInput);
        }
        let mut inner = self.inner.lock().map_err(|_| BlobError::Closed)?;
        if inner.closed {
            return Err(BlobError::Closed);
        }
        if inner.active_scope.is_some() {
            return Err(BlobError::InvalidInput);
        }
        inner.active_scope = Some(scope);
        Ok(())
    }

    fn check_scope(entry: &Entry, scope: &BlobScope) -> Result<(), BlobError> {
        if &entry.scope == scope {
            Ok(())
        } else {
            Err(BlobError::StaleScope)
        }
    }
    fn valid_hash(hash: &str) -> bool {
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    pub fn create(
        &self,
        scope: BlobScope,
        size: usize,
        sha256: String,
    ) -> Result<String, BlobError> {
        if scope.generation == 0 || scope.identity_scope.is_empty() || !Self::valid_hash(&sha256) {
            return Err(BlobError::InvalidInput);
        }
        let mut inner = self.inner.lock().map_err(|_| BlobError::Closed)?;
        if inner.closed {
            return Err(BlobError::Closed);
        }
        if inner.active_scope.as_ref() != Some(&scope) {
            return Err(BlobError::StaleScope);
        }
        let mut budget = self.budget.lock().map_err(|_| BlobError::Closed)?;
        if budget.corrupt {
            return Err(BlobError::Closed);
        }
        if size > self.limits.max_blob_bytes
            || budget.handles >= self.limits.max_handles
            || size > self.limits.max_total_bytes.saturating_sub(budget.bytes)
        {
            return Err(BlobError::QuotaExceeded);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| BlobError::QuotaExceeded)?;
        budget.bytes += size;
        budget.handles += 1;
        drop(budget);
        let handle = Uuid::new_v4().to_string();
        inner.entries.insert(
            handle.clone(),
            Entry {
                scope,
                bytes: Arc::new(bytes),
                expected_sha256: sha256,
                hasher: Sha256::new(),
                sealed: false,
                reserved_by: None,
                charge: Arc::new(Charge {
                    size,
                    budget: self.budget.clone(),
                    producer_scope: None,
                }),
            },
        );
        Ok(handle)
    }

    pub fn write(
        &self,
        scope: &BlobScope,
        handle: &str,
        offset: usize,
        encoded: &str,
    ) -> Result<usize, BlobError> {
        if encoded.len() > MAX_CHUNK_BYTES.div_ceil(3) * 4 {
            return Err(BlobError::InvalidInput);
        }
        let chunk = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| BlobError::InvalidInput)?;
        if chunk.len() > MAX_CHUNK_BYTES || chunk.is_empty() {
            return Err(BlobError::InvalidInput);
        }
        let mut inner = self.inner.lock().map_err(|_| BlobError::Closed)?;
        if inner.closed {
            return Err(BlobError::Closed);
        }
        let entry = inner.entries.get_mut(handle).ok_or(BlobError::Missing)?;
        Self::check_scope(entry, scope)?;
        if entry.sealed || entry.reserved_by.is_some() {
            return Err(BlobError::Reserved);
        }
        if offset != entry.bytes.len() {
            return Err(BlobError::OffsetMismatch);
        }
        if chunk.len() > entry.charge.size.saturating_sub(offset) {
            return Err(BlobError::QuotaExceeded);
        }
        Arc::get_mut(&mut entry.bytes)
            .ok_or(BlobError::Reserved)?
            .extend_from_slice(&chunk);
        // Hash at bounded chunk admission, never scan a large body while the
        // resource mutex blocks the independently serviced control lane.
        entry.hasher.update(&chunk);
        Ok(entry.bytes.len())
    }

    pub fn seal(&self, scope: &BlobScope, handle: &str) -> Result<BlobInfo, BlobError> {
        let mut inner = self.inner.lock().map_err(|_| BlobError::Closed)?;
        if inner.closed {
            return Err(BlobError::Closed);
        }
        let entry = inner.entries.get_mut(handle).ok_or(BlobError::Missing)?;
        Self::check_scope(entry, scope)?;
        if entry.reserved_by.is_some() {
            return Err(BlobError::Reserved);
        }
        if entry.bytes.len() != entry.charge.size
            || format!("{:x}", entry.hasher.clone().finalize()) != entry.expected_sha256
        {
            return Err(BlobError::IntegrityMismatch);
        }
        entry.sealed = true;
        Ok(BlobInfo {
            handle: handle.into(),
            size: entry.charge.size,
            sha256: entry.expected_sha256.clone(),
        })
    }

    pub fn read(
        &self,
        scope: &BlobScope,
        handle: &str,
        offset: usize,
        length: usize,
    ) -> Result<Vec<u8>, BlobError> {
        if length == 0 || length > MAX_CHUNK_BYTES {
            return Err(BlobError::InvalidInput);
        }
        let inner = self.inner.lock().map_err(|_| BlobError::Closed)?;
        if inner.closed {
            return Err(BlobError::Closed);
        }
        let entry = inner.entries.get(handle).ok_or(BlobError::Missing)?;
        Self::check_scope(entry, scope)?;
        if !entry.sealed {
            return Err(BlobError::Unsealed);
        }
        if offset > entry.bytes.len() {
            return Err(BlobError::OffsetMismatch);
        }
        Ok(entry.bytes[offset..offset.saturating_add(length).min(entry.bytes.len())].to_vec())
    }

    pub fn read_chunk(
        &self,
        scope: &BlobScope,
        handle: &str,
        offset: usize,
        max_bytes: usize,
    ) -> Result<BlobChunk, BlobError> {
        if max_bytes == 0 || max_bytes > MAX_CHUNK_BYTES {
            return Err(BlobError::InvalidInput);
        }
        let inner = self.inner.lock().map_err(|_| BlobError::Closed)?;
        if inner.closed {
            return Err(BlobError::Closed);
        }
        let entry = inner.entries.get(handle).ok_or(BlobError::Missing)?;
        Self::check_scope(entry, scope)?;
        if !entry.sealed {
            return Err(BlobError::Unsealed);
        }
        if offset > entry.bytes.len() {
            return Err(BlobError::OffsetMismatch);
        }
        let next_offset = offset.saturating_add(max_bytes).min(entry.bytes.len());
        Ok(BlobChunk {
            base64: base64::engine::general_purpose::STANDARD
                .encode(&entry.bytes[offset..next_offset]),
            next_offset,
            eof: next_offset == entry.bytes.len(),
        })
    }

    pub fn reserve_producer(&self, scope: BlobScope) -> Result<BlobProducer, BlobError> {
        self.try_reserve_producer(scope)?
            .ok_or(BlobError::QuotaExceeded)
    }

    /// None means only same-scope in-flight byte reservations may shrink enough.
    /// It grants no capacity or authority; callers must retry after a notification.
    pub fn try_reserve_producer(
        &self,
        scope: BlobScope,
    ) -> Result<Option<BlobProducer>, BlobError> {
        self.try_reserve_bounded_producer(scope, self.limits.max_blob_bytes)
    }

    /// Reserve a producer's known encoded-output ceiling, never available headroom.
    /// The final payload must still fit this exact owned charge at publication.
    pub fn reserve_bounded_producer(
        &self,
        scope: BlobScope,
        size: usize,
    ) -> Result<BlobProducer, BlobError> {
        self.try_reserve_bounded_producer(scope, size)?
            .ok_or(BlobError::QuotaExceeded)
    }

    fn try_reserve_bounded_producer(
        &self,
        scope: BlobScope,
        size: usize,
    ) -> Result<Option<BlobProducer>, BlobError> {
        if size == 0 || size > self.limits.max_blob_bytes {
            return Err(BlobError::InvalidInput);
        }
        let inner = self.inner.lock().map_err(|_| BlobError::Closed)?;
        if inner.closed {
            return Err(BlobError::Closed);
        }
        if inner.active_scope.as_ref() != Some(&scope) {
            return Err(BlobError::StaleScope);
        }
        let mut budget = self.budget.lock().map_err(|_| BlobError::Closed)?;
        if budget.corrupt {
            return Err(BlobError::Closed);
        }
        if budget.handles >= self.limits.max_handles {
            return Err(BlobError::QuotaExceeded);
        }
        if size > self.limits.max_total_bytes.saturating_sub(budget.bytes) {
            let transient = budget.producers.get(&scope).copied().unwrap_or(0);
            let fixed = budget
                .bytes
                .checked_sub(transient)
                .ok_or(BlobError::Closed)?;
            if transient > 0 && fixed <= self.limits.max_total_bytes - size {
                return Ok(None);
            }
            return Err(BlobError::QuotaExceeded);
        }
        let reserved = budget
            .producers
            .get(&scope)
            .copied()
            .unwrap_or(0)
            .checked_add(size)
            .ok_or(BlobError::Closed)?;
        budget.bytes += size;
        budget.handles += 1;
        budget.producers.insert(scope.clone(), reserved);
        Ok(Some(BlobProducer {
            scope: scope.clone(),
            charge: Charge {
                size,
                budget: self.budget.clone(),
                producer_scope: Some(scope),
            },
        }))
    }

    /// Internal integrity proof, distinct from an ordinary closed/retired scope.
    pub fn check_budget_integrity(&self) -> Result<(), BlobError> {
        let budget = self.budget.lock().map_err(|_| BlobError::Closed)?;
        if budget.corrupt {
            return Err(BlobError::Closed);
        }
        Ok(())
    }

    pub fn budget_changes(&self) -> Result<tokio::sync::watch::Receiver<()>, BlobError> {
        let budget = self.budget.lock().map_err(|_| BlobError::Closed)?;
        if budget.corrupt {
            return Err(BlobError::Closed);
        }
        Ok(budget.changed.subscribe())
    }
    pub fn begin_artifact_attempt(&self, scope: &BlobScope) -> Result<AttemptArtifacts, BlobError> {
        let inner = self.inner.lock().map_err(|_| BlobError::Closed)?;
        if inner.closed {
            return Err(BlobError::Closed);
        }
        if inner.active_scope.as_ref() != Some(scope) {
            return Err(BlobError::StaleScope);
        }
        Ok(AttemptArtifacts {
            state: Arc::new(ArtifactAuthority {
                generation: scope.generation,
                budget: self.budget.clone(),
                retired: Mutex::new(false),
            }),
        })
    }
    pub fn reserve_artifact(
        &self,
        authority: &AttemptArtifacts,
        scope: &BlobScope,
    ) -> Result<ArtifactReservation, BlobError> {
        let retired = authority
            .state
            .retired
            .lock()
            .map_err(|_| BlobError::Closed)?;
        if *retired
            || authority.state.generation != scope.generation
            || !Arc::ptr_eq(&authority.state.budget, &self.budget)
        {
            return Err(BlobError::StaleScope);
        }
        let mut producer = self.reserve_producer(scope.clone())?;
        // Attempt artifacts can survive scope rotation and are not response-wait
        // progress authority. Convert their charge to fixed ownership immediately.
        {
            let mut budget = self.budget.lock().map_err(|_| BlobError::Closed)?;
            if budget.corrupt {
                return Err(BlobError::Closed);
            }
            budget.remove_producer(scope, producer.charge.size)?;
            producer.charge.producer_scope = None;
            budget.changed.send_replace(());
        }
        Ok(ArtifactReservation {
            authority: authority.state.clone(),
            charge: producer.charge,
        })
    }
    pub fn shrink_artifact(
        &self,
        reservation: &mut ArtifactReservation,
        size: usize,
    ) -> Result<(), BlobError> {
        let retired = reservation
            .authority
            .retired
            .lock()
            .map_err(|_| BlobError::Closed)?;
        if *retired || !Arc::ptr_eq(&reservation.authority.budget, &self.budget) {
            return Err(BlobError::StaleScope);
        }
        if size > reservation.charge.size {
            return Err(BlobError::QuotaExceeded);
        }
        let mut budget = self.budget.lock().map_err(|_| BlobError::Closed)?;
        if budget.corrupt {
            return Err(BlobError::Closed);
        }
        budget.bytes -= reservation.charge.size - size;
        reservation.charge.size = size;
        budget.changed.send_replace(());
        Ok(())
    }
    pub fn finish_artifact(
        &self,
        reservation: ArtifactReservation,
        scope: BlobScope,
        bytes: Vec<u8>,
    ) -> Result<BlobInfo, BlobError> {
        self.finish_artifact_batch(vec![(reservation, bytes)], scope)
            .map(|mut infos| infos.remove(0))
            .map_err(|(error, _)| error)
    }
    /// All-or-nothing publication: a failed scope/authority check returns every
    /// private reservation and byte buffer intact, with no visible handles.
    #[allow(clippy::type_complexity)]
    pub fn finish_artifact_batch(
        &self,
        items: Vec<(ArtifactReservation, Vec<u8>)>,
        scope: BlobScope,
    ) -> Result<Vec<BlobInfo>, (BlobError, Vec<(ArtifactReservation, Vec<u8>)>)> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let authority = items[0].0.authority.clone();
        if authority.generation != scope.generation
            || !Arc::ptr_eq(&authority.budget, &self.budget)
            || items
                .iter()
                .any(|(r, _)| !Arc::ptr_eq(&r.authority, &authority))
        {
            return Err((BlobError::StaleScope, items));
        }
        if items.iter().any(|(r, b)| b.len() > r.charge.size) {
            return Err((BlobError::QuotaExceeded, items));
        }
        let hashes: Vec<String> = items
            .iter()
            .map(|(_, bytes)| format!("{:x}", Sha256::digest(bytes)))
            .collect();
        let retired = match authority.retired.lock() {
            Ok(v) => v,
            Err(_) => return Err((BlobError::Closed, items)),
        };
        if *retired {
            return Err((BlobError::StaleScope, items));
        }
        let mut inner = match self.inner.lock() {
            Ok(v) => v,
            Err(_) => return Err((BlobError::Closed, items)),
        };
        if inner.closed {
            return Err((BlobError::Closed, items));
        }
        if inner.active_scope.as_ref() != Some(&scope) {
            return Err((BlobError::StaleScope, items));
        }
        let mut budget = match self.budget.lock() {
            Ok(v) => v,
            Err(_) => return Err((BlobError::Closed, items)),
        };
        if budget.corrupt {
            return Err((BlobError::Closed, items));
        }
        let mut infos = Vec::with_capacity(items.len());
        for ((mut reservation, bytes), sha256) in items.into_iter().zip(hashes) {
            budget.bytes -= reservation.charge.size - bytes.len();
            reservation.charge.size = bytes.len();
            let handle = Uuid::new_v4().to_string();
            infos.push(BlobInfo {
                handle: handle.clone(),
                size: bytes.len(),
                sha256: sha256.clone(),
            });
            inner.entries.insert(
                handle,
                Entry {
                    scope: scope.clone(),
                    bytes: Arc::new(bytes),
                    expected_sha256: sha256,
                    hasher: Sha256::new(),
                    sealed: true,
                    reserved_by: None,
                    charge: Arc::new(reservation.charge),
                },
            );
        }
        budget.changed.send_replace(());
        Ok(infos)
    }

    pub fn producer_limit(&self) -> usize {
        self.limits.max_blob_bytes
    }
    pub fn finish_producer(
        &self,
        mut producer: BlobProducer,
        bytes: Vec<u8>,
    ) -> Result<BlobInfo, BlobError> {
        if bytes.len() > producer.charge.size {
            return Err(BlobError::QuotaExceeded);
        }
        // Hash outside the store lock. Lifecycle is checked again at publication.
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        let mut inner = self.inner.lock().map_err(|_| BlobError::Closed)?;
        if inner.closed {
            return Err(BlobError::Closed);
        }
        if inner.active_scope.as_ref() != Some(&producer.scope) {
            return Err(BlobError::StaleScope);
        }
        {
            let mut budget = self.budget.lock().map_err(|_| BlobError::Closed)?;
            if budget.corrupt {
                return Err(BlobError::Closed);
            }
            budget.remove_producer(&producer.scope, producer.charge.size)?;
            producer.charge.producer_scope = None;
            budget.bytes -= producer.charge.size - bytes.len();
            producer.charge.size = bytes.len();
            budget.changed.send_replace(());
        }
        let handle = Uuid::new_v4().to_string();
        let info = BlobInfo {
            handle: handle.clone(),
            size: bytes.len(),
            sha256: sha256.clone(),
        };
        inner.entries.insert(
            handle,
            Entry {
                scope: producer.scope,
                bytes: Arc::new(bytes),
                expected_sha256: sha256,
                hasher: Sha256::new(),
                sealed: true,
                reserved_by: None,
                charge: Arc::new(producer.charge),
            },
        );
        Ok(info)
    }

    /// Native producers pass already-protected bytes, never unmasked pixels.
    /// Their pre-collected buffers are NOT charged here: callers must bound
    /// producer admission/collection separately before invoking this helper.
    pub fn insert_sealed(&self, scope: BlobScope, bytes: &[u8]) -> Result<BlobInfo, BlobError> {
        let sha256 = format!("{:x}", Sha256::digest(bytes));
        let handle = self.create(scope.clone(), bytes.len(), sha256)?;
        let result = (|| {
            for (index, chunk) in bytes.chunks(MAX_CHUNK_BYTES).enumerate() {
                self.write(
                    &scope,
                    &handle,
                    index * MAX_CHUNK_BYTES,
                    &base64::engine::general_purpose::STANDARD.encode(chunk),
                )?;
            }
            self.seal(&scope, &handle)
        })();
        if result.is_err() {
            let _ = self.release(&scope, &handle);
        }
        result
    }

    /// Reserve before selecting a one-use protocol token. Roll back if token
    /// validation/selection fails; never consume an invalid body after ack.
    pub fn reserve(&self, scope: &BlobScope, handle: &str, token: &str) -> Result<(), BlobError> {
        if token.is_empty() {
            return Err(BlobError::InvalidInput);
        }
        let mut inner = self.inner.lock().map_err(|_| BlobError::Closed)?;
        if inner.closed {
            return Err(BlobError::Closed);
        }
        // One reservation per token prevents a rejected replay using a second
        // handle from rolling back the first accepted decision's reservation.
        if inner
            .entries
            .values()
            .any(|entry| entry.reserved_by.as_deref() == Some(token))
        {
            return Err(BlobError::Reserved);
        }
        let entry = inner.entries.get_mut(handle).ok_or(BlobError::Missing)?;
        Self::check_scope(entry, scope)?;
        if !entry.sealed {
            return Err(BlobError::Unsealed);
        }
        if entry.reserved_by.is_some() || Arc::strong_count(&entry.bytes) > 1 {
            return Err(BlobError::Reserved);
        }
        entry.reserved_by = Some(token.into());
        Ok(())
    }

    /// Borrow immutable sealed bytes without transferring the handle. Both the
    /// owner entry and command lease retain one shared quota charge; no copy.
    pub fn borrow_sealed(&self, scope: &BlobScope, handle: &str) -> Result<BlobLease, BlobError> {
        let inner = self.inner.lock().map_err(|_| BlobError::Closed)?;
        if inner.closed {
            return Err(BlobError::Closed);
        }
        let entry = inner.entries.get(handle).ok_or(BlobError::Missing)?;
        Self::check_scope(entry, scope)?;
        if !entry.sealed {
            return Err(BlobError::Unsealed);
        }
        if entry.reserved_by.is_some() {
            return Err(BlobError::Reserved);
        }
        Ok(BlobLease {
            bytes: entry.bytes.clone(),
            _charge: entry.charge.clone(),
        })
    }

    pub fn commit(
        &self,
        scope: &BlobScope,
        handle: &str,
        token: &str,
    ) -> Result<BlobLease, BlobError> {
        let mut inner = self.inner.lock().map_err(|_| BlobError::Closed)?;
        if inner.closed {
            return Err(BlobError::Closed);
        }
        let entry = inner.entries.get(handle).ok_or(BlobError::Missing)?;
        Self::check_scope(entry, scope)?;
        if entry.reserved_by.as_deref() != Some(token) {
            return Err(BlobError::Reserved);
        }
        let entry = inner.entries.remove(handle).ok_or(BlobError::Missing)?;
        Ok(BlobLease {
            bytes: entry.bytes,
            _charge: entry.charge,
        })
    }

    pub fn rollback(&self, token: &str) -> Result<(), BlobError> {
        let mut inner = self.inner.lock().map_err(|_| BlobError::Closed)?;
        for entry in inner.entries.values_mut() {
            if entry.reserved_by.as_deref() == Some(token) {
                entry.reserved_by = None;
            }
        }
        Ok(())
    }

    /// After acceptance the upload belongs to native. Expiry/cancellation before
    /// a Selected outcome must discard it, not restore caller ownership.
    pub fn discard_reserved(&self, token: &str) -> Result<(), BlobError> {
        let mut inner = self.inner.lock().map_err(|_| BlobError::Closed)?;
        inner
            .entries
            .retain(|_, entry| entry.reserved_by.as_deref() != Some(token));
        Ok(())
    }

    pub fn release(&self, scope: &BlobScope, handle: &str) -> Result<(), BlobError> {
        let mut inner = self.inner.lock().map_err(|_| BlobError::Closed)?;
        let entry = inner.entries.get(handle).ok_or(BlobError::Missing)?;
        Self::check_scope(entry, scope)?;
        if entry.reserved_by.is_some() {
            return Err(BlobError::Reserved);
        }
        inner.entries.remove(handle);
        Ok(())
    }
    /// Discard only a native trace image receipt in its original blob scope.
    /// Scope rotation cannot transfer its charge or turn it into a new result.
    pub(crate) fn discard_trace_image(
        &self,
        generation: u64,
        value: &serde_json::Value,
    ) -> Result<(), BlobError> {
        let identity_scope = value
            .get("identityScope")
            .and_then(serde_json::Value::as_str)
            .ok_or(BlobError::InvalidInput)?;
        let handle = value
            .get("handle")
            .and_then(serde_json::Value::as_str)
            .ok_or(BlobError::InvalidInput)?;
        self.release(
            &BlobScope {
                generation,
                identity_scope: identity_scope.to_owned(),
            },
            handle,
        )
    }
    #[cfg(test)]
    pub(crate) fn charged_for_test(&self) -> (usize, usize) {
        let budget = self.budget.lock().unwrap();
        (budget.bytes, budget.handles)
    }
    pub fn revoke_scope(&self, scope: &BlobScope) -> Result<(), BlobError> {
        let mut inner = self.inner.lock().map_err(|_| BlobError::Closed)?;
        if inner.active_scope.as_ref() == Some(scope) {
            inner.active_scope = None;
        }
        inner.entries.retain(|_, entry| &entry.scope != scope);
        self.budget
            .lock()
            .map_err(|_| BlobError::Closed)?
            .changed
            .send_replace(());
        Ok(())
    }
    pub fn close(&self) -> Result<(), BlobError> {
        let mut inner = self.inner.lock().map_err(|_| BlobError::Closed)?;
        inner.closed = true;
        inner.active_scope = None;
        inner.entries.clear();
        self.budget
            .lock()
            .map_err(|_| BlobError::Closed)?
            .changed
            .send_replace(());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_producer_owns_exact_ceiling_and_oversize_releases_charge() {
        let store = BlobStore::new(BlobLimits {
            max_blob_bytes: 8,
            max_total_bytes: 16,
            max_handles: 8,
        })
        .unwrap();
        let scope = scope();
        store.activate_scope(scope.clone()).unwrap();
        for size in [0, 9] {
            assert!(matches!(
                store.reserve_bounded_producer(scope.clone(), size),
                Err(BlobError::InvalidInput)
            ));
        }
        let retained = store.insert_sealed(scope.clone(), b"12345").unwrap();
        let full = store.reserve_producer(scope.clone()).unwrap();
        let exact = store.reserve_bounded_producer(scope.clone(), 3).unwrap();
        assert!(matches!(
            store.reserve_bounded_producer(scope.clone(), 1),
            Err(BlobError::QuotaExceeded)
        ));
        assert!(matches!(
            store.finish_producer(exact, vec![0; 4]),
            Err(BlobError::QuotaExceeded)
        ));
        let exact = store.reserve_bounded_producer(scope.clone(), 3).unwrap();
        let info = store.finish_producer(exact, vec![0; 3]).unwrap();
        assert_eq!(info.size, 3);
        store.release(&scope, &info.handle).unwrap();
        drop(full);
        store.release(&scope, &retained.handle).unwrap();
        let budget = store.budget.lock().unwrap();
        assert_eq!(
            (
                budget.bytes,
                budget.handles,
                budget.producers.len(),
                budget.corrupt
            ),
            (0, 0, 0, false)
        );
    }

    #[test]
    fn bounded_producer_keeps_scope_and_handle_limits() {
        let store = BlobStore::new(BlobLimits {
            max_blob_bytes: 8,
            max_total_bytes: 16,
            max_handles: 1,
        })
        .unwrap();
        let old = scope();
        store.activate_scope(old.clone()).unwrap();
        let producer = store.reserve_bounded_producer(old.clone(), 4).unwrap();
        assert!(matches!(
            store.reserve_bounded_producer(old.clone(), 1),
            Err(BlobError::QuotaExceeded)
        ));
        store.revoke_scope(&old).unwrap();
        let next = BlobScope {
            generation: old.generation,
            identity_scope: "new".into(),
        };
        store.activate_scope(next.clone()).unwrap();
        assert!(matches!(
            store.finish_producer(producer, vec![0; 4]),
            Err(BlobError::StaleScope)
        ));
        assert!(matches!(
            store.reserve_bounded_producer(old, 4),
            Err(BlobError::StaleScope)
        ));
        drop(store.reserve_bounded_producer(next, 4).unwrap());
        let budget = store.budget.lock().unwrap();
        assert_eq!(
            (
                budget.bytes,
                budget.handles,
                budget.producers.len(),
                budget.corrupt
            ),
            (0, 0, 0, false)
        );
    }

    #[test]
    fn budget_integrity_is_not_ordinary_scope_closure() {
        let store = store();
        store.close().unwrap();
        assert!(store.check_budget_integrity().is_ok());
        store.budget.lock().unwrap().corrupt = true;
        assert_eq!(store.check_budget_integrity(), Err(BlobError::Closed));
    }

    #[test]
    fn transient_admission_wakes_without_lost_finish_and_competitors_recheck() {
        let store = BlobStore::new(BlobLimits {
            max_blob_bytes: 8,
            max_total_bytes: 16,
            max_handles: 8,
        })
        .unwrap();
        let scope = scope();
        store.activate_scope(scope.clone()).unwrap();
        let retained = store.insert_sealed(scope.clone(), b"x").unwrap();
        let producing = store.reserve_producer(scope.clone()).unwrap();
        let mut changes = store.budget_changes().unwrap();
        changes.borrow_and_update();
        assert!(store.try_reserve_producer(scope.clone()).unwrap().is_none());
        let finished = store.finish_producer(producing, b"y".to_vec()).unwrap();
        assert!(changes.has_changed().unwrap()); // Finish before changed().await is retained.
        let winner = store.try_reserve_producer(scope.clone()).unwrap().unwrap();
        assert!(store.try_reserve_producer(scope.clone()).unwrap().is_none());
        drop(winner);
        store.release(&scope, &retained.handle).unwrap();
        store.release(&scope, &finished.handle).unwrap();
        assert_eq!(store.budget.lock().unwrap().bytes, 0);
        assert!(store.budget.lock().unwrap().producers.is_empty());
    }

    #[test]
    fn fixed_and_handle_pressure_refuse_without_waiting() {
        let store = BlobStore::new(BlobLimits {
            max_blob_bytes: 8,
            max_total_bytes: 16,
            max_handles: 8,
        })
        .unwrap();
        let scope = scope();
        store.activate_scope(scope.clone()).unwrap();
        store.insert_sealed(scope.clone(), b"12345678").unwrap();
        store.insert_sealed(scope.clone(), b"x").unwrap();
        assert!(matches!(
            store.try_reserve_producer(scope.clone()),
            Err(BlobError::QuotaExceeded)
        ));
        let handles = BlobStore::new(BlobLimits {
            max_blob_bytes: 8,
            max_total_bytes: 16,
            max_handles: 1,
        })
        .unwrap();
        handles.activate_scope(scope.clone()).unwrap();
        let producer = handles.reserve_producer(scope.clone()).unwrap();
        assert!(matches!(
            handles.try_reserve_producer(scope),
            Err(BlobError::QuotaExceeded)
        ));
        drop(producer);
    }

    #[test]
    fn failed_finish_releases_once_and_retired_producers_are_not_progress_authority() {
        let store = BlobStore::new(BlobLimits {
            max_blob_bytes: 8,
            max_total_bytes: 16,
            max_handles: 8,
        })
        .unwrap();
        let old = scope();
        store.activate_scope(old.clone()).unwrap();
        let bad = store.reserve_producer(old.clone()).unwrap();
        assert_eq!(
            store.finish_producer(bad, vec![0; 9]),
            Err(BlobError::QuotaExceeded)
        );
        assert_eq!(store.budget.lock().unwrap().bytes, 0);
        assert!(store.budget.lock().unwrap().producers.is_empty());
        let first = store.reserve_producer(old.clone()).unwrap();
        let second = store.reserve_producer(old.clone()).unwrap();
        let mut changes = store.budget_changes().unwrap();
        changes.borrow_and_update();
        store.revoke_scope(&old).unwrap();
        assert!(changes.has_changed().unwrap());
        assert!(matches!(
            store.try_reserve_producer(old.clone()),
            Err(BlobError::StaleScope)
        ));
        let next = BlobScope {
            generation: old.generation,
            identity_scope: "replacement".into(),
        };
        store.activate_scope(next.clone()).unwrap();
        assert!(matches!(
            store.try_reserve_producer(next.clone()),
            Err(BlobError::QuotaExceeded)
        ));
        drop(first);
        let admitted = store.try_reserve_producer(next.clone()).unwrap().unwrap();
        store.revoke_scope(&next).unwrap(); // Successful reserve is not publication authority.
        assert_eq!(
            store.finish_producer(admitted, b"late".to_vec()),
            Err(BlobError::StaleScope)
        );
        drop(second);
        assert_eq!(store.budget.lock().unwrap().bytes, 0);
    }

    #[test]
    fn artifact_conversion_is_fixed_and_last_lease_release_wakes() {
        let store = BlobStore::new(BlobLimits {
            max_blob_bytes: 8,
            max_total_bytes: 16,
            max_handles: 8,
        })
        .unwrap();
        let scope = scope();
        store.activate_scope(scope.clone()).unwrap();
        let authority = store.begin_artifact_attempt(&scope).unwrap();
        let artifact = store.reserve_artifact(&authority, &scope).unwrap();
        assert!(store.budget.lock().unwrap().producers.is_empty());
        let sealed = store.insert_sealed(scope.clone(), b"x").unwrap();
        assert!(matches!(
            store.try_reserve_producer(scope.clone()),
            Err(BlobError::QuotaExceeded)
        ));
        let mut changes = store.budget_changes().unwrap();
        changes.borrow_and_update();
        drop(artifact);
        assert!(changes.has_changed().unwrap());
        let lease = store.borrow_sealed(&scope, &sealed.handle).unwrap();
        changes.borrow_and_update();
        store.release(&scope, &sealed.handle).unwrap();
        assert!(!changes.has_changed().unwrap()); // Borrowed bytes remain charged.
        drop(lease);
        assert!(changes.has_changed().unwrap());
        changes.borrow_and_update();
        store.close().unwrap();
        assert!(changes.has_changed().unwrap());
        assert!(matches!(
            store.try_reserve_producer(scope),
            Err(BlobError::Closed)
        ));
    }

    // These are deterministic accounting witnesses, not a reconstruction of the
    // CI18 after-reconnect refusal: that run did not retain its quota ledger.
    // Use the production defaults without allocating maximum-size byte buffers.
    fn recording_pressure_store() -> BlobStore {
        let limits = BlobLimits::default();
        assert_eq!(limits.max_blob_bytes, 64 * 1024 * 1024);
        assert_eq!(limits.max_total_bytes, 128 * 1024 * 1024);
        assert_eq!(limits.max_handles, 128);
        let store = BlobStore::new(limits).unwrap();
        store.activate_scope(scope()).unwrap();
        store
    }

    fn assert_recording_pressure_ledger(
        store: &BlobStore,
        bytes: usize,
        handles: usize,
        producers: &[(&BlobScope, usize)],
    ) {
        let budget = store.budget.lock().unwrap();
        assert_eq!(budget.bytes, bytes);
        assert_eq!(budget.handles, handles);
        assert_eq!(
            budget.producers,
            producers
                .iter()
                .map(|(scope, size)| ((**scope).clone(), *size))
                .collect::<HashMap<_, _>>()
        );
        assert!(!budget.corrupt);
    }

    #[test]
    fn recording_and_retained_response_refuse_capture_until_last_borrow_drops() {
        let store = recording_pressure_store();
        let scope = scope();
        let maximum = store.producer_limit();
        let authority = store.begin_artifact_attempt(&scope).unwrap();
        let recording = store.reserve_artifact(&authority, &scope).unwrap();
        assert_recording_pressure_ledger(&store, maximum, 1, &[]);

        let response = store.reserve_producer(scope.clone()).unwrap();
        assert_recording_pressure_ledger(&store, 2 * maximum, 2, &[(&scope, maximum)]);
        let response = store.finish_producer(response, b"x".to_vec()).unwrap();
        assert_recording_pressure_ledger(&store, maximum + 1, 2, &[]);
        let mut changes = store.budget_changes().unwrap();
        changes.borrow_and_update();

        // The recorder owns fixed capacity, not a response producer that can
        // finish and shrink. A capture must refuse instead of waiting on it.
        assert!(matches!(
            store.try_reserve_producer(scope.clone()),
            Err(BlobError::QuotaExceeded)
        ));
        assert_recording_pressure_ledger(&store, maximum + 1, 2, &[]);
        assert!(!changes.has_changed().unwrap());

        let first = store.borrow_sealed(&scope, &response.handle).unwrap();
        let last = store.borrow_sealed(&scope, &response.handle).unwrap();
        store.release(&scope, &response.handle).unwrap();
        assert_eq!(
            store.read(&scope, &response.handle, 0, 1),
            Err(BlobError::Missing)
        );
        assert_eq!(last.bytes(), b"x");
        drop(first);
        assert_recording_pressure_ledger(&store, maximum + 1, 2, &[]);
        assert!(!changes.has_changed().unwrap());
        assert!(matches!(
            store.try_reserve_producer(scope.clone()),
            Err(BlobError::QuotaExceeded)
        ));

        drop(last);
        assert!(changes.has_changed().unwrap());
        assert_recording_pressure_ledger(&store, maximum, 1, &[]);
        let capture = store.try_reserve_producer(scope.clone()).unwrap().unwrap();
        assert_recording_pressure_ledger(&store, 2 * maximum, 2, &[(&scope, maximum)]);
        drop(capture); // Cancellation before publication returns exactly its charge.
        assert_recording_pressure_ledger(&store, maximum, 1, &[]);
        drop(recording);
        assert_recording_pressure_ledger(&store, 0, 0, &[]);
    }

    #[test]
    fn response_producer_pressure_can_shrink_at_the_same_accounted_byte_count() {
        let store = recording_pressure_store();
        let scope = scope();
        let maximum = store.producer_limit();
        let retained = store.reserve_producer(scope.clone()).unwrap();
        let retained = store.finish_producer(retained, b"x".to_vec()).unwrap();
        let response = store.reserve_producer(scope.clone()).unwrap();
        assert_recording_pressure_ledger(&store, maximum + 1, 2, &[(&scope, maximum)]);
        let mut changes = store.budget_changes().unwrap();
        changes.borrow_and_update();

        // Same bytes and handles as the recording case, but this live response
        // producer is genuine same-scope progress authority.
        assert!(store.try_reserve_producer(scope.clone()).unwrap().is_none());
        assert!(!changes.has_changed().unwrap());
        assert_recording_pressure_ledger(&store, maximum + 1, 2, &[(&scope, maximum)]);
        let response = store.finish_producer(response, b"y".to_vec()).unwrap();
        assert!(changes.has_changed().unwrap());
        assert_recording_pressure_ledger(&store, 2, 2, &[]);

        let capture = store.try_reserve_producer(scope.clone()).unwrap().unwrap();
        assert_recording_pressure_ledger(&store, maximum + 2, 3, &[(&scope, maximum)]);
        drop(capture);
        store.release(&scope, &retained.handle).unwrap();
        store.release(&scope, &response.handle).unwrap();
        assert_recording_pressure_ledger(&store, 0, 0, &[]);
    }

    #[test]
    fn fixed_recording_pressure_survives_rotation_without_old_publication_authority() {
        let store = recording_pressure_store();
        let old = scope();
        let maximum = store.producer_limit();
        let authority = store.begin_artifact_attempt(&old).unwrap();
        let recording = store.reserve_artifact(&authority, &old).unwrap();
        let response = store.reserve_producer(old.clone()).unwrap();
        let response = store.finish_producer(response, b"x".to_vec()).unwrap();
        let lease = store.borrow_sealed(&old, &response.handle).unwrap();
        store.revoke_scope(&old).unwrap();
        let next = BlobScope {
            identity_scope: "recording-next".into(),
            ..old.clone()
        };
        store.activate_scope(next.clone()).unwrap();
        assert_recording_pressure_ledger(&store, maximum + 1, 2, &[]);
        assert_eq!(
            store.read(&next, &response.handle, 0, 1),
            Err(BlobError::Missing)
        );
        assert!(matches!(
            store.try_reserve_producer(old.clone()),
            Err(BlobError::StaleScope)
        ));
        assert!(matches!(
            store.try_reserve_producer(next.clone()),
            Err(BlobError::QuotaExceeded)
        ));

        drop(lease);
        assert_recording_pressure_ledger(&store, maximum, 1, &[]);
        let capture = store.reserve_producer(next.clone()).unwrap();
        store.revoke_scope(&next).unwrap();
        let current = BlobScope {
            identity_scope: "recording-current".into(),
            ..old.clone()
        };
        store.activate_scope(current.clone()).unwrap();
        assert_recording_pressure_ledger(&store, 2 * maximum, 2, &[(&next, maximum)]);
        // A producer from the retired scope is not progress authority either.
        assert!(matches!(
            store.try_reserve_producer(current.clone()),
            Err(BlobError::QuotaExceeded)
        ));
        assert_eq!(
            store.finish_producer(capture, b"late".to_vec()),
            Err(BlobError::StaleScope)
        );
        assert_recording_pressure_ledger(&store, maximum, 1, &[]);

        // Failure returns private artifact ownership intact, without rebinding
        // an old handle or granting its scope publication authority.
        let (error, returned) = store
            .finish_artifact_batch(vec![(recording, b"v".to_vec())], old.clone())
            .unwrap_err();
        assert_eq!(error, BlobError::StaleScope);
        assert_eq!(returned.len(), 1);
        assert!(store.inner.lock().unwrap().entries.is_empty());
        assert_recording_pressure_ledger(&store, maximum, 1, &[]);
        let published = store
            .finish_artifact_batch(returned, current.clone())
            .unwrap_or_else(|(error, _)| panic!("current artifact publication failed: {error:?}"));
        assert_eq!(published.len(), 1);
        assert_recording_pressure_ledger(&store, 1, 1, &[]);
        assert_eq!(
            store.read(&old, &published[0].handle, 0, 1),
            Err(BlobError::StaleScope)
        );
        assert_eq!(
            store.read(&current, &published[0].handle, 0, 1).unwrap(),
            b"v"
        );
        store.release(&current, &published[0].handle).unwrap();
        assert_recording_pressure_ledger(&store, 0, 0, &[]);
    }

    #[test]
    fn retired_recording_authority_keeps_ownership_but_cannot_publish_or_shrink() {
        for explicit_retirement in [false, true] {
            let store = recording_pressure_store();
            let scope = scope();
            let maximum = store.producer_limit();
            let mut authority = Some(store.begin_artifact_attempt(&scope).unwrap());
            let mut recording = store
                .reserve_artifact(authority.as_ref().unwrap(), &scope)
                .unwrap();
            if explicit_retirement {
                authority.as_ref().unwrap().retire().unwrap();
            } else {
                drop(authority.take());
            }
            assert_recording_pressure_ledger(&store, maximum, 1, &[]);
            assert_eq!(
                store.shrink_artifact(&mut recording, 1),
                Err(BlobError::StaleScope)
            );
            assert_recording_pressure_ledger(&store, maximum, 1, &[]);
            assert_eq!(
                store.finish_artifact(recording, scope.clone(), b"late".to_vec()),
                Err(BlobError::StaleScope)
            );
            assert_recording_pressure_ledger(&store, 0, 0, &[]);
            assert!(store.inner.lock().unwrap().entries.is_empty());
            if let Some(authority) = authority {
                assert!(matches!(
                    store.reserve_artifact(&authority, &scope),
                    Err(BlobError::StaleScope)
                ));
            }
            let capture = store.reserve_producer(scope).unwrap();
            drop(capture);
            assert_recording_pressure_ledger(&store, 0, 0, &[]);
        }
    }

    fn scope() -> BlobScope {
        BlobScope {
            generation: 1,
            identity_scope: "context-one".into(),
        }
    }
    fn digest(data: &[u8]) -> String {
        format!("{:x}", Sha256::digest(data))
    }
    fn store() -> BlobStore {
        let store = BlobStore::new(BlobLimits {
            max_blob_bytes: 8,
            max_total_bytes: 8,
            max_handles: 2,
        })
        .unwrap();
        store.activate_scope(scope()).unwrap();
        store
    }
    #[test]
    fn retired_scope_cannot_repopulate_after_late_completion() {
        let store = store();
        let old = scope();
        store.revoke_scope(&old).unwrap();
        assert_eq!(
            store.insert_sealed(old.clone(), b"late"),
            Err(BlobError::StaleScope)
        );
        let next = BlobScope {
            generation: 1,
            identity_scope: "next-context".into(),
        };
        store.activate_scope(next.clone()).unwrap();
        assert_eq!(
            store.insert_sealed(old.clone(), b"late"),
            Err(BlobError::StaleScope)
        );
        store.revoke_scope(&old).unwrap();
        assert!(store.insert_sealed(next, b"new").is_ok());
    }

    #[test]
    fn chunk_reads_have_exact_eof_and_reject_zero_length() {
        let store = store();
        let scope = scope();
        let info = store.insert_sealed(scope.clone(), b"abc").unwrap();
        assert_eq!(
            store.read_chunk(&scope, &info.handle, 0, 2).unwrap(),
            BlobChunk {
                base64: "YWI=".into(),
                next_offset: 2,
                eof: false
            }
        );
        assert_eq!(
            store.read_chunk(&scope, &info.handle, 2, 2).unwrap(),
            BlobChunk {
                base64: "Yw==".into(),
                next_offset: 3,
                eof: true
            }
        );
        assert_eq!(
            store.read_chunk(&scope, &info.handle, 3, 2).unwrap(),
            BlobChunk {
                base64: "".into(),
                next_offset: 3,
                eof: true
            }
        );
        assert_eq!(
            store.read_chunk(&scope, &info.handle, 0, 0),
            Err(BlobError::InvalidInput)
        );
        assert_eq!(
            store.read_chunk(&scope, &info.handle, 4, 1),
            Err(BlobError::OffsetMismatch)
        );
        store.release(&scope, &info.handle).unwrap();
        let empty = store.insert_sealed(scope.clone(), b"").unwrap();
        assert!(store.read_chunk(&scope, &empty.handle, 0, 1).unwrap().eof);
    }

    #[test]
    fn sequential_upload_requires_exact_size_hash_and_scope() {
        let store = store();
        let scope = scope();
        let handle = store.create(scope.clone(), 3, digest(b"abc")).unwrap();
        assert_eq!(
            store.write(&scope, &handle, 1, "YWJj"),
            Err(BlobError::OffsetMismatch)
        );
        assert_eq!(
            store.seal(&scope, &handle),
            Err(BlobError::IntegrityMismatch)
        );
        store.write(&scope, &handle, 0, "YWJj").unwrap();
        store.seal(&scope, &handle).unwrap();
        assert_eq!(store.read(&scope, &handle, 0, 3).unwrap(), b"abc");
        let other = BlobScope {
            generation: 2,
            ..scope.clone()
        };
        assert_eq!(
            store.read(&other, &handle, 0, 3),
            Err(BlobError::StaleScope)
        );
    }
    #[test]
    fn replay_cannot_reserve_another_handle_under_selected_token() {
        let store = store();
        let scope = scope();
        let first = store.insert_sealed(scope.clone(), b"one").unwrap();
        let second = store.insert_sealed(scope.clone(), b"two").unwrap();
        store.reserve(&scope, &first.handle, "selected").unwrap();
        assert_eq!(
            store.reserve(&scope, &second.handle, "selected"),
            Err(BlobError::Reserved)
        );
        assert!(store.release(&scope, &first.handle).is_err());
        assert_eq!(
            store
                .commit(&scope, &first.handle, "selected")
                .unwrap()
                .bytes(),
            b"one"
        );
        store.release(&scope, &second.handle).unwrap();
    }

    #[test]
    fn decision_reservation_is_one_use_and_lease_keeps_quota_charged() {
        let store = store();
        let scope = scope();
        let handle = store.create(scope.clone(), 8, digest(b"12345678")).unwrap();
        store.write(&scope, &handle, 0, "MTIzNDU2Nzg=").unwrap();
        store.seal(&scope, &handle).unwrap();
        store.reserve(&scope, &handle, "token").unwrap();
        assert_eq!(store.release(&scope, &handle), Err(BlobError::Reserved));
        let lease = store.commit(&scope, &handle, "token").unwrap();
        assert_eq!(lease.bytes(), b"12345678");
        assert!(store.commit(&scope, &handle, "token").is_err());
        assert_eq!(
            store.create(scope.clone(), 1, digest(b"x")),
            Err(BlobError::QuotaExceeded)
        );
        drop(lease);
        assert!(store.create(scope, 1, digest(b"x")).is_ok());
    }
    #[test]
    fn accepted_but_expired_decision_discards_upload_and_returns_quota() {
        let store = store();
        let scope = scope();
        let body = store.insert_sealed(scope.clone(), b"12345678").unwrap();
        store.reserve(&scope, &body.handle, "accepted").unwrap();
        store.discard_reserved("accepted").unwrap();
        assert!(store.commit(&scope, &body.handle, "accepted").is_err());
        assert!(store.insert_sealed(scope.clone(), b"12345678").is_ok());
        // Cleanup is idempotent even if a winning consumer already took bytes.
        store.discard_reserved("accepted").unwrap();
    }

    #[test]
    fn rejected_token_can_rollback_and_scope_revoke_clears_handles() {
        let store = store();
        let scope = scope();
        let handle = store.create(scope.clone(), 0, digest(b"")).unwrap();
        store.seal(&scope, &handle).unwrap();
        store.reserve(&scope, &handle, "bad-token").unwrap();
        store.rollback("bad-token").unwrap();
        store.reserve(&scope, &handle, "valid-token").unwrap();
        store.revoke_scope(&scope).unwrap();
        assert!(store.commit(&scope, &handle, "valid-token").is_err());
        store.close().unwrap();
        assert_eq!(store.create(scope, 0, digest(b"")), Err(BlobError::Closed));
    }
}

#[cfg(test)]
mod producer_tests {
    use super::*;
    #[test]
    fn borrowed_upload_retains_bytes_and_quota_after_handle_release() {
        let store = BlobStore::new(BlobLimits {
            max_blob_bytes: 8,
            max_total_bytes: 8,
            max_handles: 2,
        })
        .unwrap();
        let scope = BlobScope {
            generation: 1,
            identity_scope: "borrow".into(),
        };
        store.activate_scope(scope.clone()).unwrap();
        let info = store.insert_sealed(scope.clone(), b"12345678").unwrap();
        let lease = store.borrow_sealed(&scope, &info.handle).unwrap();
        assert_eq!(
            store.reserve(&scope, &info.handle, "decision"),
            Err(BlobError::Reserved)
        );
        store.release(&scope, &info.handle).unwrap();
        assert_eq!(lease.bytes(), b"12345678");
        assert!(matches!(
            store.reserve_producer(scope.clone()),
            Err(BlobError::QuotaExceeded)
        ));
        drop(lease);
        assert!(store.reserve_producer(scope).is_ok());
    }

    #[test]
    fn producer_reserves_before_collecting_and_rejects_late_scope() {
        let store = BlobStore::new(BlobLimits {
            max_blob_bytes: 8,
            max_total_bytes: 8,
            max_handles: 2,
        })
        .unwrap();
        let scope = BlobScope {
            generation: 1,
            identity_scope: "first".into(),
        };
        store.activate_scope(scope.clone()).unwrap();
        let producer = store.reserve_producer(scope.clone()).unwrap();
        assert!(matches!(
            store.reserve_producer(scope.clone()),
            Err(BlobError::QuotaExceeded)
        ));
        let info = store.finish_producer(producer, b"abc".to_vec()).unwrap();
        assert_eq!(info.size, 3);
        store.release(&scope, &info.handle).unwrap();
        let late = store.reserve_producer(scope.clone()).unwrap();
        store.revoke_scope(&scope).unwrap();
        assert_eq!(
            store.finish_producer(late, b"late".to_vec()),
            Err(BlobError::StaleScope)
        );
        store
            .activate_scope(BlobScope {
                generation: 1,
                identity_scope: "next".into(),
            })
            .unwrap();
    }
    #[test]
    fn attempt_artifact_rotates_scope_without_rebinding_old_handles() {
        let store = BlobStore::new(BlobLimits {
            max_blob_bytes: 8,
            max_total_bytes: 16,
            max_handles: 4,
        })
        .unwrap();
        let old = BlobScope {
            generation: 1,
            identity_scope: "old".into(),
        };
        let next = BlobScope {
            generation: 1,
            identity_scope: "next".into(),
        };
        store.activate_scope(old.clone()).unwrap();
        let authority = store.begin_artifact_attempt(&old).unwrap();
        let mut held = store.reserve_artifact(&authority, &old).unwrap();
        store.shrink_artifact(&mut held, 3).unwrap();
        assert_eq!(store.budget.lock().unwrap().bytes, 3);
        store.revoke_scope(&old).unwrap();
        store.activate_scope(next.clone()).unwrap();
        let result = store
            .finish_artifact(held, next.clone(), b"abc".to_vec())
            .unwrap();
        assert!(matches!(
            store.read(&old, &result.handle, 0, 3),
            Err(BlobError::StaleScope)
        ));
        assert_eq!(store.read(&next, &result.handle, 0, 3).unwrap(), b"abc");
        store.release(&next, &result.handle).unwrap();
        assert_eq!(store.budget.lock().unwrap().bytes, 0);
    }
    #[test]
    fn attempt_artifact_rejects_retirement_foreign_store_generation_and_growth() {
        let limits = BlobLimits {
            max_blob_bytes: 8,
            max_total_bytes: 16,
            max_handles: 4,
        };
        let store = BlobStore::new(limits).unwrap();
        let foreign = BlobStore::new(limits).unwrap();
        let scope = BlobScope {
            generation: 1,
            identity_scope: "scope".into(),
        };
        store.activate_scope(scope.clone()).unwrap();
        foreign.activate_scope(scope.clone()).unwrap();
        let authority = store.begin_artifact_attempt(&scope).unwrap();
        assert!(matches!(
            foreign.reserve_artifact(&authority, &scope),
            Err(BlobError::StaleScope)
        ));
        let mut held = store.reserve_artifact(&authority, &scope).unwrap();
        assert_eq!(
            store.shrink_artifact(&mut held, 9),
            Err(BlobError::QuotaExceeded)
        );
        authority.retire().unwrap();
        assert_eq!(
            store.finish_artifact(held, scope.clone(), vec![1]),
            Err(BlobError::StaleScope)
        );
        assert_eq!(store.budget.lock().unwrap().bytes, 0);
        assert!(matches!(
            store.reserve_artifact(&authority, &scope),
            Err(BlobError::StaleScope)
        ));
        let authority = store.begin_artifact_attempt(&scope).unwrap();
        let held = store.reserve_artifact(&authority, &scope).unwrap();
        store.revoke_scope(&scope).unwrap();
        let next = BlobScope {
            generation: 2,
            identity_scope: "next".into(),
        };
        store.activate_scope(next.clone()).unwrap();
        assert_eq!(
            store.finish_artifact(held, next, vec![1]),
            Err(BlobError::StaleScope)
        );
    }
    #[test]
    fn dropping_attempt_authority_seals_retained_artifact() {
        let store = BlobStore::new(BlobLimits::default()).unwrap();
        let scope = BlobScope {
            generation: 1,
            identity_scope: "scope".into(),
        };
        store.activate_scope(scope.clone()).unwrap();
        let authority = store.begin_artifact_attempt(&scope).unwrap();
        let held = store.reserve_artifact(&authority, &scope).unwrap();
        drop(authority);
        assert_eq!(
            store.finish_artifact(held, scope, vec![1]),
            Err(BlobError::StaleScope)
        );
        assert_eq!(store.budget.lock().unwrap().bytes, 0);
    }
}
#[test]
fn late_trace_discard_releases_only_the_original_scope_charge() {
    let store = BlobStore::new(Default::default()).unwrap();
    let scope = BlobScope {
        generation: 1,
        identity_scope: "original".into(),
    };
    store.activate_scope(scope.clone()).unwrap();
    let producer = store.reserve_producer(scope.clone()).unwrap();
    let image = store.finish_producer(producer, vec![1, 2, 3]).unwrap();
    let value = serde_json::json!({"identityScope":"original","handle":image.handle});
    assert_eq!(store.charged_for_test(), (3, 1));
    assert_eq!(
        store.discard_trace_image(2, &value),
        Err(BlobError::StaleScope)
    );
    let other = serde_json::json!({"identityScope":"replacement","handle":image.handle});
    assert_eq!(
        store.discard_trace_image(1, &other),
        Err(BlobError::StaleScope)
    );
    assert_eq!(store.charged_for_test(), (3, 1));
    store.discard_trace_image(1, &value).unwrap();
    assert_eq!(store.charged_for_test(), (0, 0));
    assert!(matches!(
        store.read(&scope, &image.handle, 0, 1),
        Err(BlobError::Missing)
    ));
    store.check_budget_integrity().unwrap();
}
