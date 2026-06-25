use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::sync::{Arc, LazyLock, Mutex};

use lru::LruCache;

use crate::api::{StorageBackend, StorageWriteBatch, Table};
use crate::error::Error;

use ethlambda_types::{
    attestation::{AggregationBits, AttestationData, HashedAttestationData, bits_is_subset},
    block::{
        Block, BlockBody, BlockHeader, MultiMessageAggregate, SignedBlock, TypeOneMultiSignature,
    },
    checkpoint::Checkpoint,
    primitives::{H256, HashTreeRoot as _},
    signature::ValidatorSignature,
    state::{ChainConfig, State, anchor_pair_is_consistent},
};
use libssz::{SszDecode, SszEncode};

use crate::state_diff::StateDiff;
use thiserror::Error;
use tracing::{info, warn};

/// Errors returned by [`Store::get_forkchoice_store`].
#[derive(Debug, Error)]
pub enum GetForkchoiceStoreError {
    #[error(
        "anchor block doesn't match anchor state: \
         state header = {anchor_state:?}, block = {anchor_block:?}"
    )]
    AnchorPairInconsistent {
        anchor_state: Box<State>,
        anchor_block: Box<Block>,
    },
}

/// The tree hash root of an empty block body.
///
/// Used to detect genesis/anchor blocks that have no attestations,
/// allowing us to skip storing empty bodies and reconstruct them on read.
static EMPTY_BODY_ROOT: LazyLock<H256> = LazyLock::new(|| BlockBody::default().hash_tree_root());

/// Checkpoints to update in the forkchoice store.
///
/// Used with `Store::update_checkpoints` to update head and optionally
/// update justified/finalized checkpoints (only if higher slot).
pub struct ForkCheckpoints {
    head: H256,
    justified: Option<Checkpoint>,
    finalized: Option<Checkpoint>,
}

impl ForkCheckpoints {
    /// Create checkpoints update with only the head.
    pub fn head_only(head: H256) -> Self {
        Self {
            head,
            justified: None,
            finalized: None,
        }
    }

    /// Create checkpoints update with optional justified and finalized.
    ///
    /// The head is passed through unchanged.
    pub fn new(head: H256, justified: Option<Checkpoint>, finalized: Option<Checkpoint>) -> Self {
        Self {
            head,
            justified,
            finalized,
        }
    }
}

// ============ Metadata Keys ============

/// Key for "time" field of the Store. Its value has type [`u64`] and it's SSZ-encoded.
const KEY_TIME: &[u8] = b"time";
/// Key for "config" field of the Store. Its value has type [`ChainConfig`] and it's SSZ-encoded.
const KEY_CONFIG: &[u8] = b"config";
/// Key for "head" field of the Store. Its value has type [`H256`] and it's SSZ-encoded.
const KEY_HEAD: &[u8] = b"head";
/// Key for "safe_target" field of the Store. Its value has type [`H256`] and it's SSZ-encoded.
const KEY_SAFE_TARGET: &[u8] = b"safe_target";
/// Key for "latest_justified" field of the Store. Its value has type [`Checkpoint`] and it's SSZ-encoded.
const KEY_LATEST_JUSTIFIED: &[u8] = b"latest_justified";
/// Key for "latest_finalized" field of the Store. Its value has type [`Checkpoint`] and it's SSZ-encoded.
const KEY_LATEST_FINALIZED: &[u8] = b"latest_finalized";

/// Persist a full-state snapshot whenever a block's slot crosses a multiple of
/// this value (relative to its parent's slot).
///
/// Snapshots are the only entries written to `States` (plus the bootstrap
/// anchor); they are never pruned and bound state-reconstruction diff walks to
/// at most this many steps. ~68 minutes at 4-second slots.
const SNAPSHOT_ANCHOR_INTERVAL: u64 = 1_024;

/// Number of reconstructed/imported states memoized in memory.
///
/// States are content-addressed by block root and immutable, so the cache never
/// needs invalidation; it only bounds how many recent states stay hot for reads
/// (e.g. a block's `parent_state` right after import). A miss falls back to a
/// snapshot read or a diff-chain reconstruction.
const STATE_CACHE_CAPACITY: usize = 32;

/// Keep block signatures for at least this many slots below the tip, even once
/// finalized. Signatures older than this window are pruned only when the window
/// lies entirely within finalized history; see [`Store::prune_old_block_signatures`].
/// ~1 day at 4-second slots.
const SIGNATURE_PRUNING_RANGE: u64 = 21_600;

/// ~30 minutes of resume window at 4-second slots (1800 / 4 = 450).
pub const MAX_RESUMABLE_DB_STATE_AGE: u64 = 450;

/// Hard cap for the known aggregated payload buffer (number of distinct attestation messages).
/// With 1 attestation/slot, this holds ~500 messages (~33 min at 4s/slot).
const AGGREGATED_PAYLOAD_CAP: usize = 512;

/// Hard cap for the new (pending) aggregated payload buffer.
/// Smaller than known since new payloads are drained every interval (~4s).
const NEW_PAYLOAD_CAP: usize = 64;

/// Hard cap for the gossip signature buffer (individual signatures, not distinct data_roots).
/// With 4 validators and 4-second slots, 2048 signatures covers ~512 slots (~34 min).
/// Each XMSS signature is ~3KB, so worst-case memory is ~6 MB.
const GOSSIP_SIGNATURE_CAP: usize = 2048;

/// An entry in the payload buffer: attestation data + set of proofs.
#[derive(Clone)]
struct PayloadEntry {
    data: AttestationData,
    proofs: Vec<TypeOneMultiSignature>,
}

/// Fixed-size circular buffer for aggregated payloads.
///
/// Groups proofs by attestation data (via data_root). Each distinct
/// attestation message stores the full `AttestationData` plus all
/// `TypeOneMultiSignature`s covering that message.
///
/// Entries are evicted FIFO (by insertion order of the data_root)
/// when the buffer reaches capacity.
#[derive(Clone)]
struct PayloadBuffer {
    data: HashMap<H256, PayloadEntry>,
    order: VecDeque<H256>,
    capacity: usize,
    total_proofs: usize,
}

impl PayloadBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            data: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
            total_proofs: 0,
        }
    }

    /// Insert a proof for an attestation, FIFO-evicting oldest data_roots
    /// when total proofs reach capacity. Also ensures the buffer doesn't
    /// include proofs which are a subset of other proofs for the same
    /// attestation data:
    ///
    /// - If the incoming proof's participants are a subset (incl. equal) of
    ///   any existing proof, the incoming proof is redundant and skipped.
    /// - Otherwise, any existing proof whose participants are a strict subset
    ///   of the incoming proof's is removed before inserting.
    fn push(&mut self, hashed: HashedAttestationData, proof: TypeOneMultiSignature) {
        let (data_root, att_data) = hashed.into_parts();

        if let Some(entry) = self.data.get_mut(&data_root) {
            let mut to_remove: Vec<usize> = Vec::new();
            for (i, p) in entry.proofs.iter().enumerate() {
                // Incoming is subsumed by an existing proof (incl. equal). Skip.
                if bits_is_subset(&proof.participants, &p.participants) {
                    return;
                }
                // Existing is a strict subset of incoming. Mark for removal.
                // (Non-strict equality was ruled out by the check above.)
                if bits_is_subset(&p.participants, &proof.participants) {
                    to_remove.push(i);
                }
            }

            // Remove subsumed proofs (reverse order so earlier indices stay valid).
            for i in to_remove.into_iter().rev() {
                entry.proofs.swap_remove(i);
                self.total_proofs -= 1;
            }

            entry.proofs.push(proof);
            self.total_proofs += 1;
        } else {
            self.data.insert(
                data_root,
                PayloadEntry {
                    data: att_data,
                    proofs: vec![proof],
                },
            );
            self.order.push_back(data_root);
            self.total_proofs += 1;
        }
        // Evict oldest data_roots until under capacity
        while self.total_proofs > self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                if let Some(removed) = self.data.remove(&evicted) {
                    self.total_proofs -= removed.proofs.len();
                }
            } else {
                break;
            }
        }
    }

    /// Insert a batch of (hashed_attestation_data, proof) entries.
    fn push_batch(&mut self, entries: Vec<(HashedAttestationData, TypeOneMultiSignature)>) {
        for (hashed, proof) in entries {
            self.push(hashed, proof);
        }
    }

    /// Take all entries, leaving the buffer empty.
    ///
    /// Drains in insertion order (via `self.order`) so downstream consumers
    /// like `promote_new_aggregated_payloads` re-insert into known_payloads
    /// deterministically. HashMap iteration would be RandomState-seeded and
    /// produce non-deterministic vote ordering for same-slot equivocation.
    fn drain(&mut self) -> Vec<(HashedAttestationData, TypeOneMultiSignature)> {
        self.total_proofs = 0;
        let mut result = Vec::with_capacity(self.data.values().map(|e| e.proofs.len()).sum());
        while let Some(data_root) = self.order.pop_front() {
            if let Some(entry) = self.data.remove(&data_root) {
                for proof in entry.proofs {
                    result.push((HashedAttestationData::new(entry.data.clone()), proof));
                }
            }
        }
        result
    }

    /// Return the number of distinct attestation messages in the buffer.
    fn len(&self) -> usize {
        self.data.len()
    }

    /// Return the number of proofs for a given data_root without cloning.
    fn proof_count_for_root(&self, data_root: &H256) -> usize {
        self.data.get(data_root).map_or(0, |e| e.proofs.len())
    }

    /// Return cloned proofs for a given data_root, or empty vec if none.
    fn proofs_for_root(&self, data_root: &H256) -> Vec<TypeOneMultiSignature> {
        self.data
            .get(data_root)
            .map_or_else(Vec::new, |e| e.proofs.clone())
    }

    /// Return attestation data entries keyed by data_root.
    fn attestation_data_keys(&self) -> Vec<(H256, AttestationData)> {
        self.data
            .iter()
            .map(|(&root, entry)| (root, entry.data.clone()))
            .collect()
    }

    /// Prune payload entries whose attestation target slot is at or below `finalized_slot`.
    ///
    /// Mirrors leanSpec's `prune_stale_attestation_data`: an entry is stale once its
    /// target checkpoint is finalized — it can no longer contribute to fork choice and
    /// keeping it around only pollutes `existing_proofs_for_data` lookups, occasionally
    /// forcing recursive aggregation when plain XMSS aggregation would suffice.
    ///
    /// Returns the number of data_root entries removed.
    fn prune(&mut self, finalized_slot: u64) -> usize {
        let before = self.data.len();
        let total_proofs = &mut self.total_proofs;
        self.data.retain(|_root, entry| {
            if entry.data.target.slot > finalized_slot {
                true
            } else {
                *total_proofs -= entry.proofs.len();
                false
            }
        });
        let pruned = before - self.data.len();
        if pruned > 0 {
            self.order.retain(|r| self.data.contains_key(r));
        }
        pruned
    }

    /// Extract per-validator latest attestations from proofs' participation bits.
    ///
    /// Iterates entries in insertion order (via `self.order`) so that, when two
    /// aggregations carry the same `slot` but disagree on the target (an
    /// equivocation by the shared validators), the first-observed aggregation
    /// wins. The ethrex spec relies on Python dict insertion-order semantics
    /// here; iterating `self.data.values()` would be RandomState-seeded and
    /// fail the equivocation fork-choice tests non-deterministically.
    fn extract_latest_attestations(&self) -> HashMap<u64, AttestationData> {
        let mut result: HashMap<u64, AttestationData> = HashMap::new();
        for data_root in &self.order {
            let Some(entry) = self.data.get(data_root) else {
                continue;
            };
            for proof in &entry.proofs {
                for vid in proof.participant_indices() {
                    let should_update = result
                        .get(&vid)
                        .is_none_or(|existing| existing.slot < entry.data.slot);
                    if should_update {
                        result.insert(vid, entry.data.clone());
                    }
                }
            }
        }
        result
    }
}

/// Gossip signatures grouped by attestation data.
///
/// Signatures are stored in a `BTreeMap` keyed by validator_id to guarantee
/// ascending iteration order. XMSS aggregate proofs are order-dependent:
/// verification reconstructs pubkeys from the participation bitfield (low-to-high),
/// so aggregation must produce them in the same ascending order.
struct GossipDataEntry {
    data: AttestationData,
    signatures: BTreeMap<u64, ValidatorSignature>,
}

/// Gossip signatures snapshot: (hashed_attestation_data, Vec<(validator_id, signature)>).
pub type GossipSignatureSnapshot = Vec<(HashedAttestationData, Vec<(u64, ValidatorSignature)>)>;

/// Bounded buffer for gossip signatures with FIFO eviction.
///
/// Groups signatures by attestation data (via data_root). Each distinct
/// attestation message stores the full `AttestationData` plus individual
/// validator signatures in ascending order (required for XMSS aggregation).
///
/// Entries are evicted FIFO (by insertion order of the data_root) when
/// total_signatures exceeds capacity, matching the `PayloadBuffer` pattern.
struct GossipSignatureBuffer {
    data: HashMap<H256, GossipDataEntry>,
    order: VecDeque<H256>,
    capacity: usize,
    total_signatures: usize,
}

impl GossipSignatureBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            data: HashMap::new(),
            order: VecDeque::new(),
            capacity,
            total_signatures: 0,
        }
    }

    /// Insert a gossip signature, FIFO-evicting oldest data_roots when over capacity.
    ///
    /// Last-write-wins: if (validator_id, data_root) already exists, the signature is overwritten.
    fn insert(
        &mut self,
        hashed: HashedAttestationData,
        validator_id: u64,
        signature: ValidatorSignature,
    ) {
        let (data_root, att_data) = hashed.into_parts();

        if let Some(entry) = self.data.get_mut(&data_root) {
            let is_new = entry.signatures.insert(validator_id, signature).is_none();
            if is_new {
                self.total_signatures += 1;
            }
        } else {
            let mut signatures = BTreeMap::new();
            signatures.insert(validator_id, signature);
            self.data.insert(
                data_root,
                GossipDataEntry {
                    data: att_data,
                    signatures,
                },
            );
            self.order.push_back(data_root);
            self.total_signatures += 1;
        }

        // Evict oldest data_roots until under capacity
        while self.total_signatures > self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                if let Some(removed) = self.data.remove(&evicted) {
                    self.total_signatures -= removed.signatures.len();
                }
            } else {
                break;
            }
        }
    }

    /// Delete gossip entries for the given (validator_id, data_root) pairs.
    ///
    /// When all signatures for a data_root are removed, the entry is cleaned up.
    /// Collects emptied roots and batch-cleans the VecDeque in one pass.
    fn delete(&mut self, keys: &[(u64, H256)]) {
        if keys.is_empty() {
            return;
        }
        let mut emptied_roots: HashSet<H256> = HashSet::new();
        for &(vid, data_root) in keys {
            if let Some(entry) = self.data.get_mut(&data_root) {
                if entry.signatures.remove(&vid).is_some() {
                    self.total_signatures -= 1;
                }
                if entry.signatures.is_empty() {
                    self.data.remove(&data_root);
                    emptied_roots.insert(data_root);
                }
            }
        }
        if !emptied_roots.is_empty() {
            self.order.retain(|r| !emptied_roots.contains(r));
        }
    }

    /// Prune gossip signatures for slots <= finalized_slot.
    ///
    /// Returns the number of data_root entries pruned.
    fn prune(&mut self, finalized_slot: u64) -> usize {
        let before = self.data.len();
        self.data.retain(|_root, entry| {
            if entry.data.slot > finalized_slot {
                true
            } else {
                self.total_signatures -= entry.signatures.len();
                false
            }
        });
        let pruned = before - self.data.len();
        if pruned > 0 {
            self.order.retain(|r| self.data.contains_key(r));
        }
        pruned
    }

    /// Returns a snapshot of all gossip signatures grouped by attestation data.
    fn snapshot(&self) -> GossipSignatureSnapshot {
        self.data
            .values()
            .map(|entry| {
                let sigs: Vec<_> = entry
                    .signatures
                    .iter()
                    .map(|(&vid, sig)| (vid, sig.clone()))
                    .collect();
                (HashedAttestationData::new(entry.data.clone()), sigs)
            })
            .collect()
    }

    /// Extract per-validator latest attestations from the raw signature pool.
    ///
    /// Mirrors `PayloadBuffer::extract_latest_attestations`: iterate data_roots
    /// in insertion order (via `self.order`) so that, when two votes share the
    /// same `slot`, the first-observed one wins for the validators present in
    /// both. This matches the leanSpec `location == "signatures"` checker, which
    /// folds `attestation_signatures` keeping each validator's highest-slot vote
    /// with first-seen-wins on slot ties.
    fn extract_latest_attestations(&self) -> HashMap<u64, AttestationData> {
        let mut result: HashMap<u64, AttestationData> = HashMap::new();
        for data_root in &self.order {
            let Some(entry) = self.data.get(data_root) else {
                continue;
            };
            for &vid in entry.signatures.keys() {
                let should_update = result
                    .get(&vid)
                    .is_none_or(|existing| existing.slot < entry.data.slot);
                if should_update {
                    result.insert(vid, entry.data.clone());
                }
            }
        }
        result
    }

    /// Returns the total number of individual signatures stored.
    fn total_signatures(&self) -> usize {
        self.total_signatures
    }

    /// Returns the number of distinct data_roots.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.data.len()
    }
}

/// Encode a LiveChain key (slot, root) to bytes.
/// Layout: slot (8 bytes big-endian) || root (32 bytes)
/// Big-endian ensures lexicographic ordering matches numeric ordering.
fn encode_slot_root_key(slot: u64, root: &H256) -> Vec<u8> {
    let mut result = slot.to_be_bytes().to_vec();
    result.extend_from_slice(&root.0);
    result
}

/// Decode a slot||root key (LiveChain / BlockSignatures) from bytes.
fn decode_slot_root_key(bytes: &[u8]) -> (u64, H256) {
    let slot = u64::from_be_bytes(bytes[..8].try_into().expect("valid slot bytes"));
    let root = H256::from_slice(&bytes[8..]);
    (slot, root)
}

/// Fork choice store backed by a pluggable storage backend.
///
/// The Store maintains all state required for fork choice and block processing:
///
/// - **Metadata**: time, config, head, safe_target, justified/finalized checkpoints
/// - **Blocks**: headers and bodies stored separately for efficient header-only queries
/// - **States**: beacon states indexed by block root
/// - **Attestations**: latest known and pending ("new") attestations per validator
/// - **Signatures**: gossip signatures and aggregated proofs for signature verification
/// - **LiveChain**: slot index for efficient fork choice traversal (pruned on finalization)
///
/// # Constructors
///
/// - [`from_anchor_state`](Self::from_anchor_state): Initialize from a checkpoint state (no block body)
/// - [`get_forkchoice_store`](Self::get_forkchoice_store): Initialize from state + block (stores body)
#[derive(Clone)]
pub struct Store {
    backend: Arc<dyn StorageBackend>,
    new_payloads: Arc<Mutex<PayloadBuffer>>,
    known_payloads: Arc<Mutex<PayloadBuffer>>,
    /// In-memory gossip signatures, consumed at interval 2 aggregation.
    gossip_signatures: Arc<Mutex<GossipSignatureBuffer>>,
    /// LRU memoization of states by block root, shared across `Store` clones.
    /// Avoids reconstructing recent states from diffs on every read.
    state_cache: Arc<Mutex<LruCache<H256, State>>>,
}

/// Build an empty state cache sized to [`STATE_CACHE_CAPACITY`].
fn new_state_cache() -> Arc<Mutex<LruCache<H256, State>>> {
    let capacity = NonZeroUsize::new(STATE_CACHE_CAPACITY).expect("cache capacity is non-zero");
    Arc::new(Mutex::new(LruCache::new(capacity)))
}

impl Store {
    /// Initialize a Store from an anchor state only.
    ///
    /// Uses the state's `latest_block_header` as the anchor block header.
    /// No block body is stored since it's not available.
    pub fn from_anchor_state(backend: Arc<dyn StorageBackend>, anchor_state: State) -> Self {
        Self::init_store(backend, anchor_state, None)
            .expect("store initialization should succeed in from_anchor_state")
    }

    /// Initialize a Store from an anchor state and block.
    ///
    /// The block must match the state's `latest_block_header`.
    /// Named to mirror the spec's `get_forkchoice_store` function.
    ///
    /// # Errors
    ///
    /// Returns [`GetForkchoiceStoreError::AnchorPairInconsistent`] if the block's header
    /// doesn't match the state's `latest_block_header` (comparing all fields
    /// except `state_root`, which is computed internally).
    pub fn get_forkchoice_store(
        backend: Arc<dyn StorageBackend>,
        mut anchor_state: State,
        anchor_block: Block,
    ) -> Result<Self, GetForkchoiceStoreError> {
        if !anchor_pair_is_consistent(&mut anchor_state, &anchor_block) {
            return Err(GetForkchoiceStoreError::AnchorPairInconsistent {
                anchor_state: Box::new(anchor_state),
                anchor_block: Box::new(anchor_block),
            });
        }

        Ok(
            Self::init_store(backend, anchor_state, Some(anchor_block.body))
                .expect("store initialization should succeed in get_forkchoice_store"),
        )
    }

    /// Build a Store from the state already persisted in the storage backend.
    ///
    /// Returns `None` if the backend is empty or its persisted `genesis_time`
    /// doesn't match `expected_genesis_time`.
    pub fn from_db_state(
        backend: Arc<dyn StorageBackend>,
        expected_genesis_time: u64,
    ) -> Option<Self> {
        let persisted_config = {
            let view = backend.begin_read().expect("read view");
            let bytes = view.get(Table::Metadata, KEY_CONFIG).expect("get config")?;
            // probe KEY_LATEST_FINALIZED
            view.get(Table::Metadata, KEY_LATEST_FINALIZED)
                .expect("get latest finalized")?;
            ChainConfig::from_ssz_bytes(&bytes).expect("valid config")
        };
        if persisted_config.genesis_time != expected_genesis_time {
            warn!(
                db_genesis_time = persisted_config.genesis_time,
                expected_genesis_time,
                "Persisted DB has a different genesis_time; treating as empty"
            );
            return None;
        }
        info!("Loaded store from persisted DB state");
        Some(Self {
            backend,
            new_payloads: Arc::new(Mutex::new(PayloadBuffer::new(NEW_PAYLOAD_CAP))),
            known_payloads: Arc::new(Mutex::new(PayloadBuffer::new(AGGREGATED_PAYLOAD_CAP))),
            gossip_signatures: Arc::new(Mutex::new(GossipSignatureBuffer::new(
                GOSSIP_SIGNATURE_CAP,
            ))),
            state_cache: new_state_cache(),
        })
    }

    /// Internal helper to initialize the store with anchor data.
    ///
    /// Header is taken from `anchor_state.latest_block_header`.
    fn init_store(
        backend: Arc<dyn StorageBackend>,
        mut anchor_state: State,
        anchor_body: Option<BlockBody>,
    ) -> Result<Self, Error> {
        // Save original state_root for validation
        let original_state_root = anchor_state.latest_block_header.state_root;

        // Zero out state_root before computing (state contains header, header contains state_root)
        anchor_state.latest_block_header.state_root = H256::ZERO;

        // Compute state root with zeroed header
        let anchor_state_root = anchor_state.hash_tree_root();

        // Validate: original must be zero (genesis) or match computed (checkpoint sync)
        assert!(
            original_state_root == H256::ZERO || original_state_root == anchor_state_root,
            "anchor header state_root mismatch: expected {anchor_state_root:?}, got {original_state_root:?}"
        );

        // Populate the correct state_root
        anchor_state.latest_block_header.state_root = anchor_state_root;

        let anchor_block_root = anchor_state.latest_block_header.hash_tree_root();

        let anchor_checkpoint = Checkpoint {
            root: anchor_block_root,
            slot: anchor_state.latest_block_header.slot,
        };

        // Insert initial data
        {
            let mut batch = backend.begin_write().expect("write batch");

            // Metadata
            let metadata_entries = vec![
                (KEY_TIME.to_vec(), 0u64.to_ssz()),
                (KEY_CONFIG.to_vec(), anchor_state.config.to_ssz()),
                (KEY_HEAD.to_vec(), anchor_block_root.to_ssz()),
                (KEY_SAFE_TARGET.to_vec(), anchor_block_root.to_ssz()),
                (KEY_LATEST_JUSTIFIED.to_vec(), anchor_checkpoint.to_ssz()),
                (KEY_LATEST_FINALIZED.to_vec(), anchor_checkpoint.to_ssz()),
            ];
            batch
                .put_batch(Table::Metadata, metadata_entries)
                .expect("put metadata");

            // Block header
            let header_entries = vec![(
                anchor_block_root.to_ssz(),
                anchor_state.latest_block_header.to_ssz(),
            )];
            batch
                .put_batch(Table::BlockHeaders, header_entries)
                .expect("put block header");

            // Block body (if provided)
            if let Some(body) = anchor_body {
                let body_entries = vec![(anchor_block_root.to_ssz(), body.to_ssz())];
                batch
                    .put_batch(Table::BlockBodies, body_entries)
                    .expect("put block body");
            }

            // State snapshot. The anchor has no parent in the store, so it is
            // the base of every diff chain: store it as a full snapshot in
            // `States` (never pruned) so reconstruction always terminates here.
            let state_entries = vec![(anchor_block_root.to_ssz(), anchor_state.to_ssz())];
            batch
                .put_batch(Table::States, state_entries)
                .expect("put state");

            // Live chain index
            let index_entries = vec![(
                encode_slot_root_key(anchor_state.latest_block_header.slot, &anchor_block_root),
                anchor_state.latest_block_header.parent_root.to_ssz(),
            )];
            batch
                .put_batch(Table::LiveChain, index_entries)
                .expect("put live chain index");

            batch.commit().expect("commit");
        }

        info!(%anchor_state_root, %anchor_block_root, "Initialized store");

        Ok(Self {
            backend,
            new_payloads: Arc::new(Mutex::new(PayloadBuffer::new(NEW_PAYLOAD_CAP))),
            known_payloads: Arc::new(Mutex::new(PayloadBuffer::new(AGGREGATED_PAYLOAD_CAP))),
            gossip_signatures: Arc::new(Mutex::new(GossipSignatureBuffer::new(
                GOSSIP_SIGNATURE_CAP,
            ))),
            state_cache: new_state_cache(),
        })
    }

    // ============ Metadata Helpers ============

    fn get_metadata<T: SszDecode>(&self, key: &[u8]) -> T {
        let view = self.backend.begin_read().expect("read view");
        let bytes = view
            .get(Table::Metadata, key)
            .expect("get")
            .expect("metadata key exists");
        T::from_ssz_bytes(&bytes).expect("valid encoding")
    }

    fn set_metadata<T: SszEncode>(&self, key: &[u8], value: &T) -> Result<(), Error> {
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .put_batch(Table::Metadata, vec![(key.to_vec(), value.to_ssz())])
            .expect("put metadata");
        batch.commit().expect("commit");
        Ok(())
    }

    // ============ Time ============

    /// Returns the current store time in interval counts since genesis.
    ///
    /// Each increment represents one 800ms interval. Derive slot/interval as:
    ///   slot     = time() / INTERVALS_PER_SLOT
    ///   interval = time() % INTERVALS_PER_SLOT
    pub fn time(&self) -> u64 {
        self.get_metadata(KEY_TIME)
    }

    /// Sets the current store time.
    pub fn set_time(&mut self, time: u64) -> Result<(), Error> {
        self.set_metadata(KEY_TIME, &time)
    }

    // ============ Config ============

    /// Returns the chain configuration.
    pub fn config(&self) -> ChainConfig {
        self.get_metadata(KEY_CONFIG)
    }

    // ============ Head ============

    /// Returns the current head block root.
    pub fn head(&self) -> H256 {
        self.get_metadata(KEY_HEAD)
    }

    // ============ Safe Target ============

    /// Returns the safe target block root for attestations.
    pub fn safe_target(&self) -> H256 {
        self.get_metadata(KEY_SAFE_TARGET)
    }

    /// Sets the safe target block root.
    pub fn set_safe_target(&mut self, safe_target: H256) -> Result<(), Error> {
        self.set_metadata(KEY_SAFE_TARGET, &safe_target)
    }

    // ============ Checkpoints ============

    /// Returns the latest justified checkpoint.
    pub fn latest_justified(&self) -> Checkpoint {
        self.get_metadata(KEY_LATEST_JUSTIFIED)
    }

    /// Returns the latest finalized checkpoint.
    pub fn latest_finalized(&self) -> Checkpoint {
        self.get_metadata(KEY_LATEST_FINALIZED)
    }

    // ============ Checkpoint Updates ============

    /// Updates head, justified, and finalized checkpoints.
    ///
    /// - Head is always updated to the new value.
    /// - Justified is updated if provided.
    /// - Finalized is updated if provided.
    ///
    /// When finalization advances, prunes the LiveChain index.
    pub fn update_checkpoints(&mut self, checkpoints: ForkCheckpoints) -> Result<(), Error> {
        // Read old finalized slot before updating metadata
        let old_finalized_slot = self.latest_finalized().slot;

        let mut entries = vec![(KEY_HEAD.to_vec(), checkpoints.head.to_ssz())];

        if let Some(justified) = checkpoints.justified {
            entries.push((KEY_LATEST_JUSTIFIED.to_vec(), justified.to_ssz()));
        }

        if let Some(finalized) = checkpoints.finalized {
            entries.push((KEY_LATEST_FINALIZED.to_vec(), finalized.to_ssz()));
        }

        let mut batch = self.backend.begin_write().expect("write batch");
        batch.put_batch(Table::Metadata, entries).expect("put");
        batch.commit().expect("commit");

        // Lightweight pruning that should happen immediately on finalization advance:
        // live chain index, signatures, and attestation data. These are cheap and
        // affect fork choice correctness (live chain) or attestation processing.
        // Heavy state/block pruning is deferred to prune_old_data().
        if let Some(finalized) = checkpoints.finalized
            && finalized.slot > old_finalized_slot
        {
            let pruned_chain = self
                .prune_live_chain(finalized.slot)
                .expect("prune live chain");
            let pruned_sigs = self.prune_gossip_signatures(finalized.slot);

            let pruned_payloads = self.prune_stale_aggregated_payloads(finalized.slot);

            if pruned_chain > 0 || pruned_sigs > 0 || pruned_payloads > 0 {
                info!(
                    finalized_slot = finalized.slot,
                    pruned_chain, pruned_sigs, pruned_payloads, "Pruned finalized data"
                );
            }
        }
        Ok(())
    }

    /// Prune finalized block signatures to keep signature storage bounded.
    ///
    /// State diffs, block headers, block bodies, and full-state snapshots are
    /// all retained for the full history and are never pruned. Only signatures
    /// of finalized blocks older than the pruning window are removed.
    ///
    /// This is separated from `update_checkpoints` so callers can defer heavy
    /// pruning until after a batch of blocks has been fully processed.
    pub fn prune_old_data(&mut self) {
        let finalized_slot = self.latest_finalized().slot;
        let tip_slot = self
            .get_block_header(&self.head())
            .map_or(finalized_slot, |header| header.slot);
        let pruned_signatures = self
            .prune_old_block_signatures(finalized_slot, tip_slot)
            .expect("prune old block signatures");
        if pruned_signatures > 0 {
            info!(pruned_signatures, "Pruned old finalized block signatures");
        }
    }

    // ============ Blocks ============

    /// Get block data for fork choice: root -> (slot, parent_root).
    ///
    /// Iterates only the LiveChain table, avoiding Block deserialization.
    /// Returns only non-finalized blocks, automatically pruned on finalization.
    pub fn get_live_chain(&self) -> HashMap<H256, (u64, H256)> {
        let view = self.backend.begin_read().expect("read view");
        view.prefix_iterator(Table::LiveChain, &[])
            .expect("iterator")
            .filter_map(|res| res.ok())
            .map(|(k, v)| {
                let (slot, root) = decode_slot_root_key(&k);
                let parent_root = H256::from_ssz_bytes(&v).expect("valid parent_root");
                (root, (slot, parent_root))
            })
            .collect()
    }

    /// Return the highest slot in the live chain.
    pub fn max_live_chain_slot(&self) -> Option<u64> {
        let view = self.backend.begin_read().expect("read view");
        view.prefix_iterator(Table::LiveChain, &[])
            .expect("iterator")
            .filter_map(Result::ok)
            .map(|(key, _)| decode_slot_root_key(&key).0)
            .max()
    }

    /// Get all known block roots as HashSet.
    ///
    /// Useful for checking block existence without deserializing.
    pub fn get_block_roots(&self) -> HashSet<H256> {
        let view = self.backend.begin_read().expect("read view");
        view.prefix_iterator(Table::LiveChain, &[])
            .expect("iterator")
            .filter_map(|res| res.ok())
            .map(|(k, _)| {
                let (_, root) = decode_slot_root_key(&k);
                root
            })
            .collect()
    }

    /// Prune slot index entries with slot < finalized_slot.
    ///
    /// Blocks/states are retained for historical queries, only the
    /// LiveChain index is pruned.
    ///
    /// Returns the number of entries pruned.
    pub fn prune_live_chain(&mut self, finalized_slot: u64) -> Result<usize, Error> {
        let view = self.backend.begin_read().expect("read view");

        // Collect keys to delete - stop once we hit finalized_slot
        // Keys are sorted by slot (big-endian encoding) so we can stop early
        let keys_to_delete: Vec<_> = view
            .prefix_iterator(Table::LiveChain, &[])
            .expect("iterator")
            .filter_map(|res| res.ok())
            .take_while(|(k, _)| {
                let (slot, _) = decode_slot_root_key(k);
                slot < finalized_slot
            })
            .map(|(k, _)| k.to_vec())
            .collect();
        drop(view);

        let count = keys_to_delete.len();
        if count == 0 {
            return Ok(0);
        }

        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .delete_batch(Table::LiveChain, keys_to_delete)
            .expect("delete non-finalized chain entries");
        batch.commit().expect("commit");
        Ok(count)
    }

    /// Prune gossip signatures for slots <= finalized_slot.
    ///
    /// Returns the number of entries pruned.
    pub fn prune_gossip_signatures(&mut self, finalized_slot: u64) -> usize {
        let mut gossip = self.gossip_signatures.lock().unwrap();
        gossip.prune(finalized_slot)
    }

    /// Prune aggregated payload buffers (new + known) whose target slot is at or below
    /// `finalized_slot`.
    ///
    /// Mirrors leanSpec's `prune_stale_attestation_data` for the two aggregated payload
    /// pools (gossip signatures are pruned separately by `prune_gossip_signatures`).
    /// Returns the total number of data_root entries removed across both buffers.
    pub fn prune_stale_aggregated_payloads(&mut self, finalized_slot: u64) -> usize {
        let pruned_new = self.new_payloads.lock().unwrap().prune(finalized_slot);
        let pruned_known = self.known_payloads.lock().unwrap().prune(finalized_slot);
        pruned_new + pruned_known
    }

    /// Prune signatures of old finalized blocks, keeping a recent window.
    ///
    /// Signatures within [`SIGNATURE_PRUNING_RANGE`] slots of `tip_slot` are
    /// always kept, as are all signatures of non-finalized blocks. Concretely,
    /// with `cutoff = tip_slot - SIGNATURE_PRUNING_RANGE`:
    ///
    /// - if `cutoff <= finalized_slot` (healthy finality): delete signatures for
    ///   `slot < cutoff` (entirely within finalized history);
    /// - otherwise (the non-finalized range exceeds the window): prune nothing,
    ///   since pruning up to `cutoff` would touch non-finalized blocks.
    ///
    /// Headers and bodies are always retained. Finalized blocks can never be
    /// reverted, so their signatures are not needed for fork choice, re-org
    /// safety, or re-aggregation once outside the window.
    ///
    /// Returns the number of signatures pruned.
    pub fn prune_old_block_signatures(
        &mut self,
        finalized_slot: u64,
        tip_slot: u64,
    ) -> Result<usize, Error> {
        let cutoff = tip_slot.saturating_sub(SIGNATURE_PRUNING_RANGE);
        // Only prune when the whole window is finalized; never touch
        // non-finalized signatures.
        if cutoff > finalized_slot {
            return Ok(0);
        }

        let view = self.backend.begin_read().expect("read view");

        // Keys are slot||root in big-endian slot order, so iteration ascends by
        // slot: take entries below the cutoff and stop at the first one past it.
        let keys_to_delete: Vec<Vec<u8>> = view
            .prefix_iterator(Table::BlockSignatures, &[])
            .expect("iterator")
            .filter_map(|res| res.ok())
            .map(|(key, _)| key.to_vec())
            .take_while(|key| decode_slot_root_key(key).0 < cutoff)
            .collect();
        drop(view);

        let count = keys_to_delete.len();
        if count > 0 {
            let mut batch = self.backend.begin_write().expect("write batch");
            batch
                .delete_batch(Table::BlockSignatures, keys_to_delete)
                .expect("delete finalized block signatures");
            batch.commit().expect("commit");
        }
        Ok(count)
    }

    /// Get the block header by root.
    pub fn get_block_header(&self, root: &H256) -> Option<BlockHeader> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::BlockHeaders, &root.to_ssz())
            .expect("get")
            .map(|bytes| BlockHeader::from_ssz_bytes(&bytes).expect("valid header"))
    }

    // ============ Signed Blocks ============

    /// Insert a block as pending (parent state not yet available).
    ///
    /// Stores block data in `BlockHeaders`/`BlockBodies`/`BlockSignatures`
    /// **without** writing to `LiveChain`. This persists the heavy signature
    /// data (~3KB+ per block) to disk while keeping the block invisible to
    /// fork choice.
    ///
    /// When the block is later processed via [`insert_signed_block`](Self::insert_signed_block),
    /// the same keys are overwritten (idempotent) and a `LiveChain` entry is added.
    pub fn insert_pending_block(
        &mut self,
        root: H256,
        signed_block: SignedBlock,
    ) -> Result<(), Error> {
        let mut batch = self.backend.begin_write().expect("write batch");
        write_signed_block(batch.as_mut(), &root, signed_block);
        batch.commit().expect("commit");
        Ok(())
    }

    /// Insert a signed block, storing the block and signatures separately.
    ///
    /// Blocks and signatures are stored in separate tables because the genesis
    /// block has no signatures. This allows uniform storage of all blocks while
    /// only storing signatures for non-genesis blocks.
    ///
    /// Takes ownership to avoid cloning large signature data.
    pub fn insert_signed_block(
        &mut self,
        root: H256,
        signed_block: SignedBlock,
    ) -> Result<(), Error> {
        let mut batch = self.backend.begin_write().expect("write batch");
        let block = write_signed_block(batch.as_mut(), &root, signed_block);

        let index_entries = vec![(
            encode_slot_root_key(block.slot, &root),
            block.parent_root.to_ssz(),
        )];
        batch
            .put_batch(Table::LiveChain, index_entries)
            .expect("put non-finalized chain index");

        batch.commit().expect("commit");
        Ok(())
    }

    /// Get a block (header + body, no signatures) by root.
    ///
    /// Unlike [`get_signed_block`](Self::get_signed_block), this works for the
    /// genesis block, which has no signature entry.
    pub fn get_block(&self, root: &H256) -> Option<Block> {
        let view = self.backend.begin_read().expect("read view");
        let key = root.to_ssz();

        let header_bytes = view.get(Table::BlockHeaders, &key).expect("get")?;
        let header = BlockHeader::from_ssz_bytes(&header_bytes).expect("valid header");

        let body = if header.body_root == *EMPTY_BODY_ROOT {
            BlockBody::default()
        } else {
            let body_bytes = view.get(Table::BlockBodies, &key).expect("get")?;
            BlockBody::from_ssz_bytes(&body_bytes).expect("valid body")
        };

        Some(Block::from_header_and_body(header, body))
    }

    /// Get a signed block by combining header, body, and the merged proof.
    ///
    /// Returns None if the header or body (for non-empty bodies) is missing,
    /// or if the signature row is missing for any block other than the
    /// slot-0 anchor.
    ///
    /// Signatures are absent in two cases: genesis-style anchor blocks (no
    /// proposer ever signed them), and finalized blocks whose signatures were
    /// pruned by [`prune_old_block_signatures`](Self::prune_old_block_signatures).
    /// To keep BlocksByRoot symmetric with the fork-choice view for peers,
    /// synthesize an empty proof for the slot-0 anchor only; for any other slot
    /// a missing signature surfaces as `None` (a pruned finalized block can no
    /// longer be served with its proof) rather than as a fabricated block.
    pub fn get_signed_block(&self, root: &H256) -> Option<SignedBlock> {
        let view = self.backend.begin_read().expect("read view");
        let key = root.to_ssz();

        let header_bytes = view.get(Table::BlockHeaders, &key).expect("get")?;
        let header = BlockHeader::from_ssz_bytes(&header_bytes).expect("valid header");

        // Use empty body if header indicates empty, otherwise fetch from DB
        let body = if header.body_root == *EMPTY_BODY_ROOT {
            BlockBody::default()
        } else {
            let body_bytes = view.get(Table::BlockBodies, &key).expect("get")?;
            BlockBody::from_ssz_bytes(&body_bytes).expect("valid body")
        };

        let sig_key = encode_slot_root_key(header.slot, root);
        let proof = match view.get(Table::BlockSignatures, &sig_key).expect("get") {
            Some(proof_bytes) => {
                MultiMessageAggregate::from_ssz_bytes(&proof_bytes).expect("valid block proof")
            }
            // Synthesis only covers the genesis-style anchor (slot 0). For any
            // other slot a missing proof (pruned finalized block, or genuine
            // corruption) surfaces as `None` rather than a fabricated block.
            None if header.slot == 0 => MultiMessageAggregate::default(),
            None => return None,
        };

        let block = Block::from_header_and_body(header, body);

        Some(SignedBlock {
            message: block,
            proof,
        })
    }

    // ============ States ============

    /// Returns the state for the given block root.
    ///
    /// Fast path: a full snapshot in `States`. Otherwise the state is
    /// reconstructed by walking parent-linked `StateDiffs` back to the nearest
    /// ancestor snapshot and replaying forward. Returns `None` if the diff chain
    /// is broken or the target block header is unavailable.
    pub fn get_state(&self, root: &H256) -> Option<State> {
        // Memoized hot states first (states are immutable per root).
        if let Some(state) = self.state_cache.lock().unwrap().get(root) {
            return Some(state.clone());
        }
        // Anchor snapshot in `States`, otherwise reconstruct from the diff chain.
        let snapshot = {
            let view = self.backend.begin_read().expect("read view");
            view.get(Table::States, &root.to_ssz())
                .expect("get")
                .map(|bytes| State::from_ssz_bytes(&bytes).expect("valid state"))
        };
        let state = snapshot.or_else(|| self.reconstruct_state(root))?;
        self.state_cache.lock().unwrap().put(*root, state.clone());
        Some(state)
    }

    /// Reconstruct a state from diffs and the nearest ancestor snapshot.
    ///
    /// Walks `base_root` pointers back until a snapshot is found, fetches the
    /// target's block header, and delegates the assembly to
    /// [`state_diff::reconstruct`](crate::state_diff::reconstruct).
    fn reconstruct_state(&self, root: &H256) -> Option<State> {
        // Walk back collecting diffs until we reach a snapshot.
        let view = self.backend.begin_read().expect("read view");
        let mut diffs: Vec<StateDiff> = Vec::new();
        let mut cursor = *root;
        let snapshot = loop {
            if let Some(bytes) = view.get(Table::States, &cursor.to_ssz()).expect("get") {
                break State::from_ssz_bytes(&bytes).expect("valid state");
            }
            let diff_bytes = view.get(Table::StateDiffs, &cursor.to_ssz()).expect("get")?;
            let diff = StateDiff::from_ssz_bytes(&diff_bytes).expect("valid state diff");
            cursor = diff.base_root;
            diffs.push(diff);
        };
        drop(view);

        // `diffs` runs target -> snapshot child; reverse to snapshot child -> target.
        diffs.reverse();

        // The latest block header lives in BlockHeaders; the stored state caches
        // the real state_root there, so it equals the header byte-for-byte.
        let latest_block_header = self.get_block_header(root)?;

        Some(crate::state_diff::reconstruct(
            snapshot,
            &diffs,
            latest_block_header,
        ))
    }

    /// Returns whether a state is available for the given block root.
    ///
    /// True if a snapshot exists or the state can be reconstructed from a diff.
    pub fn has_state(&self, root: &H256) -> bool {
        let view = self.backend.begin_read().expect("read view");
        let key = root.to_ssz();
        view.get(Table::States, &key).expect("get").is_some()
            || view.get(Table::StateDiffs, &key).expect("get").is_some()
    }

    /// Persist a post-block state as a parent-linked diff, snapshotting at anchors.
    ///
    /// Every non-genesis state gets a `StateDiffs` entry (never pruned, so the
    /// full state history is preserved). A full snapshot is written to `States`
    /// only when the block crosses a [`SNAPSHOT_ANCHOR_INTERVAL`] boundary; these
    /// anchors are never pruned and bound the reconstruction walk. The state is
    /// also inserted into the in-memory cache so the immediate next read (e.g. as
    /// a child block's parent state) is hot without reconstruction.
    ///
    /// The diff is built against the parent state, identified by the post-state's
    /// own `latest_block_header.parent_root` (the state transition sets it to the
    /// block's parent) and fetched via [`get_state`](Self::get_state). The parent
    /// was persisted when its own block was imported, so this read is normally a
    /// cache hit; a cold cache falls back to a snapshot read or a diff-chain
    /// reconstruction.
    ///
    /// # Panics
    ///
    /// Panics if no state exists for the parent root: a child state can only be
    /// inserted after its parent's state has been persisted.
    pub fn insert_state(&mut self, root: H256, state: State) -> Result<(), Error> {
        // The post-state's latest_block_header is the block's own header, so its
        // parent_root identifies the parent (base) state to diff against.
        let parent_root = state.latest_block_header.parent_root;
        let parent_state = self
            .get_state(&parent_root)
            .expect("parent state must exist to diff against");
        let is_anchor =
            state.slot / SNAPSHOT_ANCHOR_INTERVAL > parent_state.slot / SNAPSHOT_ANCHOR_INTERVAL;

        // Snapshot only at anchors; serialize before `state` is consumed.
        let snapshot_bytes = is_anchor.then(|| state.to_ssz());
        // Memoize the post-state for fast reads, then move it into the diff so
        // its multi-MB justification fields are not cloned again.
        self.state_cache.lock().unwrap().put(root, state.clone());
        let diff_bytes = StateDiff::from_states(&parent_state, state).to_ssz();

        let key = root.to_ssz();
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .put_batch(Table::StateDiffs, vec![(key.clone(), diff_bytes)])
            .expect("put state diff");
        if let Some(snapshot_bytes) = snapshot_bytes {
            batch
                .put_batch(Table::States, vec![(key, snapshot_bytes)])
                .expect("put state snapshot");
        }
        batch.commit().expect("commit");
        Ok(())
    }

    // ============ Attestation Extraction ============

    /// Extract per-validator latest attestations from known (fork-choice-active) payloads.
    pub fn extract_latest_known_attestations(&self) -> HashMap<u64, AttestationData> {
        self.known_payloads
            .lock()
            .unwrap()
            .extract_latest_attestations()
    }

    /// Extract per-validator latest attestations from new (pending) payloads.
    pub fn extract_latest_new_attestations(&self) -> HashMap<u64, AttestationData> {
        self.new_payloads
            .lock()
            .unwrap()
            .extract_latest_attestations()
    }

    /// Extract per-validator latest attestations from the raw gossip signature
    /// pool (the spec's `attestation_signatures`).
    ///
    /// Unlike the aggregated pools, this pool holds one entry per validator per
    /// vote, so it reflects raw per-validator signatures before aggregation.
    /// Each validator maps to its highest-slot vote (first-seen-wins on ties).
    pub fn extract_latest_signature_attestations(&self) -> HashMap<u64, AttestationData> {
        self.gossip_signatures
            .lock()
            .unwrap()
            .extract_latest_attestations()
    }

    // ============ Known Aggregated Payloads ============
    //
    // "Known" aggregated payloads are active in fork choice weight calculations.
    // Promoted from "new" payloads at specific intervals (0 with proposal, 4).

    /// Returns a snapshot of known payloads as (AttestationData, Vec<proof>) pairs.
    pub fn known_aggregated_payloads(
        &self,
    ) -> HashMap<H256, (AttestationData, Vec<TypeOneMultiSignature>)> {
        let buf = self.known_payloads.lock().unwrap();
        buf.data
            .iter()
            .map(|(root, entry)| (*root, (entry.data.clone(), entry.proofs.clone())))
            .collect()
    }

    /// Combined proof count for a data_root across new and known buffers.
    ///
    /// Cheap check (no cloning) to short-circuit before calling the more
    /// expensive `existing_proofs_for_data` which clones all proof bytes.
    pub fn proof_count_for_data(&self, data_root: &H256) -> usize {
        let new = self
            .new_payloads
            .lock()
            .unwrap()
            .proof_count_for_root(data_root);
        let known = self
            .known_payloads
            .lock()
            .unwrap()
            .proof_count_for_root(data_root);
        new + known
    }

    /// Look up existing proofs for a given data_root from both new and known buffers.
    ///
    /// Returns `(new_proofs, known_proofs)` in priority order: new payloads first
    /// (uncommitted work from the current round), then known payloads (already active
    /// in fork choice). This ordering is used by greedy proof selection to prefer
    /// reusing recent work.
    pub fn existing_proofs_for_data(
        &self,
        data_root: &H256,
    ) -> (Vec<TypeOneMultiSignature>, Vec<TypeOneMultiSignature>) {
        let new = self.new_payloads.lock().unwrap().proofs_for_root(data_root);
        let known = self
            .known_payloads
            .lock()
            .unwrap()
            .proofs_for_root(data_root);
        (new, known)
    }

    /// Return attestation data entries from the new (pending) payload buffer.
    ///
    /// Used to iterate over data that has pending proofs but may lack gossip
    /// signatures, matching the spec's `new.keys() | gossip_sigs.keys()` union.
    pub fn new_payload_keys(&self) -> Vec<(H256, AttestationData)> {
        self.new_payloads.lock().unwrap().attestation_data_keys()
    }

    /// Insert a single proof into the known (fork-choice-active) buffer.
    pub fn insert_known_aggregated_payload(
        &mut self,
        hashed: HashedAttestationData,
        proof: TypeOneMultiSignature,
    ) {
        self.known_payloads.lock().unwrap().push(hashed, proof);
    }

    /// Batch-insert proofs into the known buffer.
    pub fn insert_known_aggregated_payloads_batch(
        &mut self,
        entries: Vec<(HashedAttestationData, TypeOneMultiSignature)>,
    ) {
        self.known_payloads.lock().unwrap().push_batch(entries);
    }

    // ============ New Aggregated Payloads ============
    //
    // "New" aggregated payloads are pending — not yet counted in fork choice.
    // Promoted to "known" via `promote_new_aggregated_payloads`.

    /// Insert a single proof into the new (pending) buffer.
    pub fn insert_new_aggregated_payload(
        &mut self,
        hashed: HashedAttestationData,
        proof: TypeOneMultiSignature,
    ) {
        self.new_payloads.lock().unwrap().push(hashed, proof);
    }

    /// Batch-insert proofs into the new buffer.
    pub fn insert_new_aggregated_payloads_batch(
        &mut self,
        entries: Vec<(HashedAttestationData, TypeOneMultiSignature)>,
    ) {
        self.new_payloads.lock().unwrap().push_batch(entries);
    }

    // ============ Pruning Helpers ============

    /// Promotes all new aggregated payloads to known, making them active in fork choice.
    ///
    /// Drains the new buffer and pushes all entries into the known buffer.
    pub fn promote_new_aggregated_payloads(&mut self) {
        let drained = self.new_payloads.lock().unwrap().drain();
        self.known_payloads.lock().unwrap().push_batch(drained);
    }

    /// Returns the number of entries in the new (pending) aggregated payloads buffer.
    pub fn new_aggregated_payloads_count(&self) -> usize {
        self.new_payloads.lock().unwrap().len()
    }

    /// Returns the number of entries in the known (fork-choice-active) aggregated payloads buffer.
    pub fn known_aggregated_payloads_count(&self) -> usize {
        self.known_payloads.lock().unwrap().len()
    }

    /// Returns the participant bitfields of every pending (new) aggregated
    /// payload, one entry per proof, each tagged with its attestation
    /// `data.slot`.
    ///
    /// Used by the attestation aggregate coverage report, which needs only the
    /// bitfields. Clones just the `AggregationBits` — not the proofs — so it
    /// avoids deep-copying the multi-megabyte `proof_data` blobs that a full
    /// payload snapshot would carry.
    pub fn new_aggregated_payload_participants(&self) -> Vec<(u64, AggregationBits)> {
        let buf = self.new_payloads.lock().unwrap();
        buf.data
            .values()
            .flat_map(|entry| {
                let slot = entry.data.slot;
                entry
                    .proofs
                    .iter()
                    .map(move |proof| (slot, proof.participants.clone()))
            })
            .collect()
    }

    /// Returns the number of gossip signature entries stored.
    pub fn gossip_signatures_count(&self) -> usize {
        let gossip = self.gossip_signatures.lock().unwrap();
        gossip.total_signatures()
    }

    /// Estimated live data size in bytes for a table, as reported by the backend.
    pub fn estimate_table_bytes(&self, table: Table) -> u64 {
        self.backend.estimate_table_bytes(table)
    }

    // ============ Gossip Signatures ============
    //
    // Gossip signatures are individual validator signatures received via P2P.
    // They're transient (consumed at interval 2 aggregation) so stored in-memory.
    // Keyed by AttestationData (via data_root) matching the leanSpec structure:
    //   gossip_signatures: dict[AttestationData, set[GossipSignature]]

    /// Delete gossip entries for the given (validator_id, data_root) pairs.
    pub fn delete_gossip_signatures(&mut self, keys: &[(u64, H256)]) {
        let mut gossip = self.gossip_signatures.lock().unwrap();
        gossip.delete(keys);
    }

    /// Returns a snapshot of gossip signatures grouped by attestation data.
    pub fn iter_gossip_signatures(&self) -> GossipSignatureSnapshot {
        let gossip = self.gossip_signatures.lock().unwrap();
        gossip.snapshot()
    }

    /// Stores a gossip signature for later aggregation.
    pub fn insert_gossip_signature(
        &mut self,
        hashed: HashedAttestationData,
        validator_id: u64,
        signature: ValidatorSignature,
    ) {
        let mut gossip = self.gossip_signatures.lock().unwrap();
        gossip.insert(hashed, validator_id, signature);
    }

    // ============ Derived Accessors ============

    /// Returns the slot of the current head block.
    pub fn head_slot(&self) -> u64 {
        self.get_block_header(&self.head())
            .expect("head block exists")
            .slot
    }

    /// Returns the slot of the current safe target block.
    pub fn safe_target_slot(&self) -> u64 {
        self.get_block_header(&self.safe_target())
            .expect("safe target exists")
            .slot
    }

    /// Returns a clone of the head state.
    pub fn head_state(&self) -> State {
        self.get_state(&self.head())
            .expect("head state is always available")
    }
}

/// Write block header, body, and the merged proof blob onto an existing batch.
///
/// Returns the deserialized [`Block`] so callers can access fields like
/// `slot` and `parent_root` without re-deserializing.
fn write_signed_block(
    batch: &mut dyn StorageWriteBatch,
    root: &H256,
    signed_block: SignedBlock,
) -> Block {
    let SignedBlock {
        message: block,
        proof,
    } = signed_block;

    let header = block.header();
    let root_bytes = root.to_ssz();

    let header_entries = vec![(root_bytes.clone(), header.to_ssz())];
    batch
        .put_batch(Table::BlockHeaders, header_entries)
        .expect("put block header");

    // Skip storing empty bodies - they can be reconstructed from the header's body_root
    if header.body_root != *EMPTY_BODY_ROOT {
        let body_entries = vec![(root_bytes.clone(), block.body.to_ssz())];
        batch
            .put_batch(Table::BlockBodies, body_entries)
            .expect("put block body");
    }

    // Store the merged Type-2 proof blob, keyed by slot||root so signature
    // pruning can scan in slot order and stop early. Table name kept for the
    // column-family migration cost; renaming to `BlockProof` is a follow-up.
    let proof_entries = vec![(encode_slot_root_key(header.slot, root), proof.to_ssz())];
    batch
        .put_batch(Table::BlockSignatures, proof_entries)
        .expect("put block proof");

    block
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::InMemoryBackend;

    /// Insert a block header (and dummy body + signature) for a given root, slot,
    /// and parent. The stored header equals `header_at(slot, parent_root)`, so a
    /// state built from the same `(slot, parent_root)` reconstructs byte-identically.
    fn insert_header(backend: &dyn StorageBackend, root: H256, slot: u64, parent_root: H256) {
        let header = header_at(slot, parent_root);
        let mut batch = backend.begin_write().expect("write batch");
        let key = root.to_ssz();
        batch
            .put_batch(Table::BlockHeaders, vec![(key.clone(), header.to_ssz())])
            .expect("put header");
        batch
            .put_batch(Table::BlockBodies, vec![(key.clone(), vec![0u8; 4])])
            .expect("put body");
        batch
            .put_batch(
                Table::BlockSignatures,
                vec![(encode_slot_root_key(slot, &root), vec![0u8; 4])],
            )
            .expect("put sigs");
        batch.commit().expect("commit");
    }

    /// Insert a real full-state snapshot for a given root (seeds a diff-chain base).
    fn insert_snapshot(backend: &dyn StorageBackend, root: H256, state: &State) {
        let mut batch = backend.begin_write().expect("write batch");
        batch
            .put_batch(Table::States, vec![(root.to_ssz(), state.to_ssz())])
            .expect("put snapshot");
        batch.commit().expect("commit");
    }

    /// Count entries in a table.
    fn count_entries(backend: &dyn StorageBackend, table: Table) -> usize {
        let view = backend.begin_read().expect("read view");
        view.prefix_iterator(table, &[])
            .expect("iterator")
            .filter_map(|r| r.ok())
            .count()
    }

    /// Check if a key exists in a table.
    fn has_key(backend: &dyn StorageBackend, table: Table, root: &H256) -> bool {
        let view = backend.begin_read().expect("read view");
        view.get(table, &root.to_ssz()).expect("get").is_some()
    }

    /// Check whether a block signature exists for a (slot, root) pair.
    fn has_signature(backend: &dyn StorageBackend, slot: u64, root: &H256) -> bool {
        let view = backend.begin_read().expect("read view");
        view.get(Table::BlockSignatures, &encode_slot_root_key(slot, root))
            .expect("get")
            .is_some()
    }

    /// Generate a deterministic H256 root from an index.
    fn root(index: u64) -> H256 {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&index.to_be_bytes());
        H256::from(bytes)
    }

    impl Store {
        /// Create a Store with an in-memory backend for tests.
        fn test_store() -> Self {
            let backend = Arc::new(InMemoryBackend::new());
            Self {
                backend,
                new_payloads: Arc::new(Mutex::new(PayloadBuffer::new(NEW_PAYLOAD_CAP))),
                known_payloads: Arc::new(Mutex::new(PayloadBuffer::new(AGGREGATED_PAYLOAD_CAP))),
                gossip_signatures: Arc::new(Mutex::new(GossipSignatureBuffer::new(
                    GOSSIP_SIGNATURE_CAP,
                ))),
                state_cache: new_state_cache(),
            }
        }

        /// Create a Store with a shared in-memory backend for tests that need
        /// direct backend access.
        fn test_store_with_backend(backend: Arc<InMemoryBackend>) -> Self {
            Self {
                backend,
                new_payloads: Arc::new(Mutex::new(PayloadBuffer::new(NEW_PAYLOAD_CAP))),
                known_payloads: Arc::new(Mutex::new(PayloadBuffer::new(AGGREGATED_PAYLOAD_CAP))),
                gossip_signatures: Arc::new(Mutex::new(GossipSignatureBuffer::new(
                    GOSSIP_SIGNATURE_CAP,
                ))),
                state_cache: new_state_cache(),
            }
        }
    }

    // ============ Block Signature Pruning Tests ============

    #[test]
    fn prune_signatures_keeps_recent_window_when_finality_healthy() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::test_store_with_backend(backend.clone());

        // Blocks at slots 0..12, each with header + body + signature.
        for i in 0..13u64 {
            insert_header(backend.as_ref(), root(i), i, H256::ZERO);
        }

        // Healthy finality: non-finalized gap (5) < SIGNATURE_PRUNING_RANGE.
        // tip = range + 10, finalized = range + 5, so cutoff = tip - range = 10.
        let tip_slot = SIGNATURE_PRUNING_RANGE + 10;
        let finalized_slot = SIGNATURE_PRUNING_RANGE + 5;
        let pruned = store
            .prune_old_block_signatures(finalized_slot, tip_slot)
            .expect("prune");

        // cutoff = 10: slots 0..9 pruned, slots 10..12 kept (within the window).
        assert_eq!(pruned, 10);
        for i in 0..10u64 {
            assert!(!has_signature(backend.as_ref(), i, &root(i)));
        }
        for i in 10..13u64 {
            assert!(has_signature(backend.as_ref(), i, &root(i)));
        }

        // Headers and bodies are always retained for the whole history.
        assert_eq!(count_entries(backend.as_ref(), Table::BlockHeaders), 13);
        assert_eq!(count_entries(backend.as_ref(), Table::BlockBodies), 13);
    }

    #[test]
    fn prune_signatures_noop_when_non_finalized_range_exceeds_window() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::test_store_with_backend(backend.clone());

        for i in 0..10u64 {
            insert_header(backend.as_ref(), root(i), i, H256::ZERO);
        }

        // Deep non-finality: gap (tip - finalized) > SIGNATURE_PRUNING_RANGE, so
        // cutoff = tip - range > finalized → prune nothing.
        let tip_slot = SIGNATURE_PRUNING_RANGE + 100;
        let finalized_slot = 5;
        let pruned = store
            .prune_old_block_signatures(finalized_slot, tip_slot)
            .expect("prune");
        assert_eq!(pruned, 0);
        assert_eq!(count_entries(backend.as_ref(), Table::BlockSignatures), 10);
    }

    #[test]
    fn prune_signatures_noop_when_tip_within_window() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::test_store_with_backend(backend.clone());

        for i in 0..10u64 {
            insert_header(backend.as_ref(), root(i), i, H256::ZERO);
        }

        // Early chain: tip < SIGNATURE_PRUNING_RANGE → cutoff saturates to 0,
        // so nothing is old enough to prune even though slots are finalized.
        let pruned = store.prune_old_block_signatures(9, 9).expect("prune");
        assert_eq!(pruned, 0);
        assert_eq!(count_entries(backend.as_ref(), Table::BlockSignatures), 10);
    }

    // ============ State Diff Reconstruction Tests ============

    use ethlambda_types::state::Validator;

    /// The header `insert_header` writes for a given slot and parent.
    fn header_at(slot: u64, parent_root: H256) -> BlockHeader {
        BlockHeader {
            slot,
            proposer_index: 0,
            parent_root,
            state_root: H256::ZERO,
            body_root: H256::ZERO,
        }
    }

    /// A real `State` at `slot` whose `latest_block_header` matches what
    /// `insert_header` stores for `(slot, parent_root)`; `parent_root` is also the
    /// base the diff is built against (`insert_state` reads it back from the
    /// post-state's `latest_block_header`).
    fn sample_state(slot: u64, parent_root: H256, hbh: Vec<H256>) -> State {
        let validators = vec![Validator {
            attestation_pubkey: [7u8; 52],
            proposal_pubkey: [9u8; 52],
            index: 0,
        }];
        let mut state = State::from_genesis(1_000, validators);
        state.slot = slot;
        state.latest_block_header = header_at(slot, parent_root);
        state.historical_block_hashes = hbh.try_into().unwrap();
        state
    }

    #[test]
    fn get_state_reconstructs_from_diff() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::test_store_with_backend(backend.clone());

        // Genesis snapshot at slot 0; its block root is its header's hash.
        let s0 = sample_state(0, H256::ZERO, vec![]);
        let r0 = s0.latest_block_header.hash_tree_root();
        insert_header(backend.as_ref(), r0, 0, H256::ZERO);
        insert_snapshot(backend.as_ref(), r0, &s0);

        // Child at slot 1 (parent r0): appends r0 (slot 0's block root), sets a checkpoint.
        let mut s1 = sample_state(1, r0, vec![r0]);
        s1.latest_justified = Checkpoint {
            root: root(7),
            slot: 0,
        };
        let r1 = s1.latest_block_header.hash_tree_root();
        insert_header(backend.as_ref(), r1, 1, r0);
        store.insert_state(r1, s1.clone()).expect("insert state");

        // Not an anchor, so no snapshot was written; only the diff.
        assert!(!has_key(backend.as_ref(), Table::States, &r1));

        // Hot path: the just-imported state is memoized in the cache.
        assert_eq!(store.get_state(&r1).unwrap().to_ssz(), s1.to_ssz());

        // A cold store (empty cache, shared backend) reconstructs from the diff,
        // byte-identically.
        let cold = Store::test_store_with_backend(backend.clone());
        let reconstructed = cold.get_state(&r1).expect("reconstructs from diff");
        assert_eq!(reconstructed.to_ssz(), s1.to_ssz());
    }

    #[test]
    fn get_state_reconstructs_across_multiple_diffs() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::test_store_with_backend(backend.clone());

        // Snapshot s0, then two chained diffs s1 -> s2; each block root is the
        // hash of its header, as in production.
        let s0 = sample_state(0, H256::ZERO, vec![]);
        let r0 = s0.latest_block_header.hash_tree_root();
        insert_header(backend.as_ref(), r0, 0, H256::ZERO);
        insert_snapshot(backend.as_ref(), r0, &s0);

        let s1 = sample_state(1, r0, vec![r0]);
        let r1 = s1.latest_block_header.hash_tree_root();
        insert_header(backend.as_ref(), r1, 1, r0);
        store.insert_state(r1, s1.clone()).expect("insert state");

        let s2 = sample_state(2, r1, vec![r0, r1]);
        let r2 = s2.latest_block_header.hash_tree_root();
        insert_header(backend.as_ref(), r2, 2, r1);
        store.insert_state(r2, s2.clone()).expect("insert state");

        // Neither child is an anchor, so a cold store reconstructs s2 by walking
        // the diff chain back to the s0 snapshot.
        assert!(!has_key(backend.as_ref(), Table::States, &r1));
        assert!(!has_key(backend.as_ref(), Table::States, &r2));
        let cold = Store::test_store_with_backend(backend.clone());
        let reconstructed = cold.get_state(&r2).expect("reconstructs across diffs");
        assert_eq!(reconstructed.to_ssz(), s2.to_ssz());
    }

    #[test]
    fn insert_state_snapshots_only_on_boundary_crossing() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::test_store_with_backend(backend.clone());

        let s0 = sample_state(SNAPSHOT_ANCHOR_INTERVAL - 1, H256::ZERO, vec![]);
        let r0 = s0.latest_block_header.hash_tree_root();
        insert_header(backend.as_ref(), r0, s0.slot, H256::ZERO);
        insert_snapshot(backend.as_ref(), r0, &s0);

        // Crossing the interval boundary records an anchor.
        let s1 = sample_state(SNAPSHOT_ANCHOR_INTERVAL, r0, vec![r0]);
        let r1 = s1.latest_block_header.hash_tree_root();
        insert_header(backend.as_ref(), r1, s1.slot, r0);
        store.insert_state(r1, s1.clone()).expect("insert state");
        assert!(has_key(backend.as_ref(), Table::States, &r1));

        // A non-crossing child does not.
        let s2 = sample_state(SNAPSHOT_ANCHOR_INTERVAL + 1, r1, vec![r0, r1]);
        let r2 = s2.latest_block_header.hash_tree_root();
        insert_header(backend.as_ref(), r2, s2.slot, r1);
        store.insert_state(r2, s2.clone()).expect("insert state");
        assert!(!has_key(backend.as_ref(), Table::States, &r2));
    }

    // ============ PayloadBuffer Tests ============

    fn make_proof() -> TypeOneMultiSignature {
        use ethlambda_types::attestation::AggregationBits;
        TypeOneMultiSignature::empty(AggregationBits::new())
    }

    /// Create a proof with a specific validator bit set (distinct participants).
    fn make_proof_for_validator(vid: usize) -> TypeOneMultiSignature {
        use ethlambda_types::attestation::AggregationBits;
        let mut bits = AggregationBits::with_length(vid + 1).unwrap();
        bits.set(vid, true).unwrap();
        TypeOneMultiSignature::empty(bits)
    }

    /// Create a proof with bits set for every validator in `vids`.
    fn make_proof_for_validators(vids: &[u64]) -> TypeOneMultiSignature {
        use ethlambda_types::attestation::AggregationBits;
        let max = vids.iter().copied().max().unwrap_or(0) as usize;
        let mut bits = AggregationBits::with_length(max + 1).unwrap();
        for &v in vids {
            bits.set(v as usize, true).unwrap();
        }
        TypeOneMultiSignature::empty(bits)
    }

    fn make_att_data(slot: u64) -> AttestationData {
        AttestationData {
            slot,
            head: Checkpoint::default(),
            target: Checkpoint::default(),
            source: Checkpoint::default(),
        }
    }

    #[test]
    fn payload_buffer_fifo_eviction() {
        let mut buf = PayloadBuffer::new(3);

        // Insert 3 distinct attestation data entries (different slots → different roots)
        for slot in 1..=3u64 {
            let data = make_att_data(slot);
            buf.push(HashedAttestationData::new(data), make_proof());
        }
        assert_eq!(buf.len(), 3);

        // Pushing a 4th should evict the oldest (slot 1)
        let data = make_att_data(4);
        buf.push(HashedAttestationData::new(data), make_proof());
        assert_eq!(buf.len(), 3);

        // The oldest (slot 1) should be gone
        let att_data_1 = make_att_data(1);
        assert!(!buf.data.contains_key(&att_data_1.hash_tree_root()));
    }

    #[test]
    fn payload_buffer_multiple_proofs_per_data() {
        let mut buf = PayloadBuffer::new(10);
        let data = make_att_data(1);
        let data_root = data.hash_tree_root();

        // Insert 3 proofs with distinct participants for the same attestation data
        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validator(0),
        );
        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validator(1),
        );
        buf.push(
            HashedAttestationData::new(data),
            make_proof_for_validator(2),
        );

        // Should be 1 distinct data entry with 3 proofs
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.data[&data_root].proofs.len(), 3);
    }

    #[test]
    fn payload_buffer_drain_empties_buffer() {
        let mut buf = PayloadBuffer::new(10);
        let data = make_att_data(1);

        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validator(0),
        );
        buf.push(
            HashedAttestationData::new(data),
            make_proof_for_validator(1),
        );

        let drained = buf.drain();
        assert_eq!(drained.len(), 2); // 2 proofs flattened
        assert!(buf.data.is_empty());
        assert!(buf.order.is_empty());
    }

    #[test]
    fn promote_moves_new_to_known() {
        let mut store = Store::test_store();
        let data = make_att_data(1);
        let data_root = data.hash_tree_root();

        store.insert_new_aggregated_payload(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validator(0),
        );
        store.insert_new_aggregated_payload(
            HashedAttestationData::new(data),
            make_proof_for_validator(1),
        );

        assert_eq!(store.new_payloads.lock().unwrap().len(), 1);
        assert_eq!(store.known_payloads.lock().unwrap().len(), 0);

        store.promote_new_aggregated_payloads();

        assert_eq!(store.new_payloads.lock().unwrap().len(), 0);
        assert_eq!(store.known_payloads.lock().unwrap().len(), 1);
        // The known buffer should have 2 proofs for this data
        assert_eq!(
            store.known_payloads.lock().unwrap().data[&data_root]
                .proofs
                .len(),
            2
        );
    }

    #[test]
    fn cloned_store_shares_payload_buffers() {
        let mut store = Store::test_store();
        let cloned = store.clone();
        let data = make_att_data(1);

        store.insert_new_aggregated_payload(HashedAttestationData::new(data), make_proof());

        // Modification on original should be visible in clone
        assert_eq!(cloned.new_payloads.lock().unwrap().len(), 1);

        store.promote_new_aggregated_payloads();

        assert_eq!(cloned.new_payloads.lock().unwrap().len(), 0);
        assert_eq!(cloned.known_payloads.lock().unwrap().len(), 1);
    }

    #[test]
    fn payload_buffer_push_superset_removes_strict_subset() {
        let mut buf = PayloadBuffer::new(10);
        let data = make_att_data(1);
        let data_root = data.hash_tree_root();

        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[1, 2]),
        );
        buf.push(
            HashedAttestationData::new(data),
            make_proof_for_validators(&[1, 2, 3]),
        );

        assert_eq!(buf.total_proofs, 1);
        assert_eq!(buf.data[&data_root].proofs.len(), 1);
        let kept: HashSet<u64> = buf.data[&data_root].proofs[0]
            .participant_indices()
            .collect();
        assert_eq!(kept, HashSet::from([1, 2, 3]));
    }

    #[test]
    fn payload_buffer_push_subset_is_skipped() {
        let mut buf = PayloadBuffer::new(10);
        let data = make_att_data(1);
        let data_root = data.hash_tree_root();

        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[1, 2, 3]),
        );
        buf.push(
            HashedAttestationData::new(data),
            make_proof_for_validators(&[1, 2]),
        );

        assert_eq!(buf.total_proofs, 1);
        assert_eq!(buf.data[&data_root].proofs.len(), 1);
        let kept: HashSet<u64> = buf.data[&data_root].proofs[0]
            .participant_indices()
            .collect();
        assert_eq!(kept, HashSet::from([1, 2, 3]));
    }

    #[test]
    fn payload_buffer_push_equal_participants_is_skipped() {
        let mut buf = PayloadBuffer::new(10);
        let data = make_att_data(1);
        let data_root = data.hash_tree_root();

        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[1, 2]),
        );
        buf.push(
            HashedAttestationData::new(data),
            make_proof_for_validators(&[1, 2]),
        );

        assert_eq!(buf.total_proofs, 1);
        assert_eq!(buf.data[&data_root].proofs.len(), 1);
    }

    #[test]
    fn payload_buffer_push_incomparable_proofs_coexist() {
        let mut buf = PayloadBuffer::new(10);
        let data = make_att_data(1);
        let data_root = data.hash_tree_root();

        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[1, 2]),
        );
        buf.push(
            HashedAttestationData::new(data),
            make_proof_for_validators(&[3, 4]),
        );

        assert_eq!(buf.total_proofs, 2);
        assert_eq!(buf.data[&data_root].proofs.len(), 2);
    }

    #[test]
    fn payload_buffer_push_superset_absorbs_multiple_subsets() {
        let mut buf = PayloadBuffer::new(10);
        let data = make_att_data(1);
        let data_root = data.hash_tree_root();

        // Three pairwise-incomparable singletons: all retained.
        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[1]),
        );
        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[2]),
        );
        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[3]),
        );
        assert_eq!(buf.total_proofs, 3);

        // Superset push absorbs all three at once.
        buf.push(
            HashedAttestationData::new(data),
            make_proof_for_validators(&[1, 2, 3]),
        );

        assert_eq!(buf.total_proofs, 1);
        assert_eq!(buf.data[&data_root].proofs.len(), 1);
        // `order` still contains the single entry.
        assert_eq!(buf.order.len(), 1);
        assert_eq!(buf.order.front().copied(), Some(data_root));
    }

    #[test]
    fn payload_buffer_push_mixed_kept_and_removed() {
        let mut buf = PayloadBuffer::new(10);
        let data = make_att_data(1);
        let data_root = data.hash_tree_root();

        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[1, 2]),
        );
        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[5, 6]),
        );
        buf.push(
            HashedAttestationData::new(data),
            make_proof_for_validators(&[1, 2, 3]),
        );

        assert_eq!(buf.total_proofs, 2);

        let sets: HashSet<Vec<u64>> = buf.data[&data_root]
            .proofs
            .iter()
            .map(|p| {
                let mut v: Vec<u64> = p.participant_indices().collect();
                v.sort_unstable();
                v
            })
            .collect();
        assert!(sets.contains(&vec![5, 6]));
        assert!(sets.contains(&vec![1, 2, 3]));
    }

    #[test]
    fn payload_buffer_push_empty_participants_subsumed_by_anything() {
        let mut buf = PayloadBuffer::new(10);
        let data = make_att_data(1);
        let data_root = data.hash_tree_root();

        // Empty-participant proof inserted first: anything that follows absorbs it.
        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[]),
        );
        assert_eq!(buf.total_proofs, 1);
        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[1, 2]),
        );
        assert_eq!(buf.total_proofs, 1);
        assert_eq!(
            buf.data[&data_root].proofs[0]
                .participant_indices()
                .collect::<Vec<u64>>(),
            vec![1, 2]
        );

        // Empty-participant proof pushed against existing non-empty: incoming is subsumed, skipped.
        buf.push(
            HashedAttestationData::new(data),
            make_proof_for_validators(&[]),
        );
        assert_eq!(buf.total_proofs, 1);
    }

    #[test]
    fn payload_buffer_push_cross_data_root_independence() {
        let mut buf = PayloadBuffer::new(10);
        let data_a = make_att_data(1);
        let data_b = make_att_data(2);
        let root_a = data_a.hash_tree_root();
        let root_b = data_b.hash_tree_root();

        buf.push(
            HashedAttestationData::new(data_a),
            make_proof_for_validators(&[1, 2, 3]),
        );
        buf.push(
            HashedAttestationData::new(data_b),
            make_proof_for_validators(&[1, 2]),
        );

        // Different data_roots → no cross-entry subsumption.
        assert_eq!(buf.total_proofs, 2);
        assert_eq!(buf.data[&root_a].proofs.len(), 1);
        assert_eq!(buf.data[&root_b].proofs.len(), 1);
    }

    #[test]
    fn payload_buffer_push_fifo_eviction_uses_total_proofs() {
        let mut buf = PayloadBuffer::new(2);
        let data_a = make_att_data(1);
        let data_b = make_att_data(2);
        let data_c = make_att_data(3);
        let root_a = data_a.hash_tree_root();
        let root_c = data_c.hash_tree_root();

        buf.push(
            HashedAttestationData::new(data_a),
            make_proof_for_validators(&[1]),
        );
        buf.push(
            HashedAttestationData::new(data_b),
            make_proof_for_validators(&[2, 3]),
        );
        // total_proofs == 3, over capacity → evict oldest (root_a).
        // Pushing a third distinct data_root triggers eviction via capacity.
        buf.push(
            HashedAttestationData::new(data_c),
            make_proof_for_validators(&[4]),
        );

        assert!(!buf.data.contains_key(&root_a));
        assert!(buf.data.contains_key(&root_c));
        assert_eq!(buf.total_proofs, 2);
    }

    #[test]
    fn payload_buffer_prune_drops_entries_with_finalized_target() {
        let mut buf = PayloadBuffer::new(10);
        let target_a = H256([0xaa; 32]);
        let target_b = H256([0xbb; 32]);
        let target_c = H256([0xcc; 32]);

        // Three entries at different target slots: 3, 5, 7.
        let data_3 = make_att_data_for_target(3, target_a);
        let data_5 = make_att_data_for_target(5, target_b);
        let data_7 = make_att_data_for_target(7, target_c);
        let root_3 = data_3.hash_tree_root();
        let root_5 = data_5.hash_tree_root();
        let root_7 = data_7.hash_tree_root();

        buf.push(
            HashedAttestationData::new(data_3),
            make_proof_for_validators(&[0]),
        );
        buf.push(
            HashedAttestationData::new(data_5),
            make_proof_for_validators(&[1, 2]),
        );
        buf.push(
            HashedAttestationData::new(data_7),
            make_proof_for_validators(&[3]),
        );
        assert_eq!(buf.total_proofs, 3);

        // Finalized slot 5 prunes targets 3 and 5 (≤ 5), keeps target 7.
        let pruned = buf.prune(5);
        assert_eq!(pruned, 2);
        assert!(!buf.data.contains_key(&root_3));
        assert!(!buf.data.contains_key(&root_5));
        assert!(buf.data.contains_key(&root_7));
        assert_eq!(buf.total_proofs, 1);
        assert_eq!(buf.order.len(), 1);
        assert_eq!(buf.order.front(), Some(&root_7));
    }

    #[test]
    fn payload_buffer_prune_noop_when_nothing_stale() {
        let mut buf = PayloadBuffer::new(10);
        let data = make_att_data_for_target(10, H256([0xaa; 32]));
        buf.push(
            HashedAttestationData::new(data),
            make_proof_for_validators(&[0]),
        );

        let pruned = buf.prune(5);
        assert_eq!(pruned, 0);
        assert_eq!(buf.total_proofs, 1);
        assert_eq!(buf.order.len(), 1);
    }

    #[test]
    fn store_prune_stale_aggregated_payloads_clears_both_buffers() {
        let mut store = Store::test_store();

        let stale = make_att_data_for_target(2, H256([0xaa; 32]));
        let fresh = make_att_data_for_target(10, H256([0xbb; 32]));

        store.insert_new_aggregated_payload(
            HashedAttestationData::new(stale.clone()),
            make_proof_for_validators(&[0]),
        );
        store.insert_known_aggregated_payload(
            HashedAttestationData::new(stale),
            make_proof_for_validators(&[1]),
        );
        store.insert_new_aggregated_payload(
            HashedAttestationData::new(fresh.clone()),
            make_proof_for_validators(&[2]),
        );
        store.insert_known_aggregated_payload(
            HashedAttestationData::new(fresh),
            make_proof_for_validators(&[3]),
        );

        assert_eq!(store.new_aggregated_payloads_count(), 2);
        assert_eq!(store.known_aggregated_payloads_count(), 2);

        // Finalized slot 5: stale (target.slot == 2) is dropped from both buffers.
        let pruned = store.prune_stale_aggregated_payloads(5);
        assert_eq!(pruned, 2);
        assert_eq!(store.new_aggregated_payloads_count(), 1);
        assert_eq!(store.known_aggregated_payloads_count(), 1);
    }

    /// Build an attestation message at `slot` whose target points at `target_root`,
    /// distinct from the default zero target so two such datas have different roots.
    fn make_att_data_for_target(slot: u64, target_root: H256) -> AttestationData {
        AttestationData {
            slot,
            head: Checkpoint::default(),
            target: Checkpoint {
                root: target_root,
                slot,
            },
            source: Checkpoint::default(),
        }
    }

    /// When two aggregations share `slot` but disagree on the target
    /// (same-slot equivocation), the *first inserted* aggregation must win for
    /// the validators that participate in both. The fork-choice spec test
    /// `test_same_slot_equivocating_attesters_count_once` depends on this.
    /// HashMap iteration would make this RandomState-seeded and flaky.
    #[test]
    fn extract_latest_attestations_first_inserted_wins_on_slot_tie() {
        let target_a = H256([0xaa; 32]);
        let target_b = H256([0xbb; 32]);
        let data_a = make_att_data_for_target(3, target_a);
        let data_b = make_att_data_for_target(3, target_b);
        assert_ne!(data_a.hash_tree_root(), data_b.hash_tree_root());

        // Order 1: A then B → validators 0,1 (in both) must see A.
        let mut buf = PayloadBuffer::new(10);
        buf.push(
            HashedAttestationData::new(data_a.clone()),
            make_proof_for_validators(&[0, 1, 2]),
        );
        buf.push(
            HashedAttestationData::new(data_b.clone()),
            make_proof_for_validators(&[0, 1, 3, 4]),
        );
        let extracted = buf.extract_latest_attestations();
        assert_eq!(extracted[&0].target.root, target_a);
        assert_eq!(extracted[&1].target.root, target_a);
        assert_eq!(extracted[&2].target.root, target_a);
        assert_eq!(extracted[&3].target.root, target_b);
        assert_eq!(extracted[&4].target.root, target_b);

        // Order 2: B then A → validators 0,1 must now see B.
        let mut buf = PayloadBuffer::new(10);
        buf.push(
            HashedAttestationData::new(data_b),
            make_proof_for_validators(&[0, 1, 3, 4]),
        );
        buf.push(
            HashedAttestationData::new(data_a),
            make_proof_for_validators(&[0, 1, 2]),
        );
        let extracted = buf.extract_latest_attestations();
        assert_eq!(extracted[&0].target.root, target_b);
        assert_eq!(extracted[&1].target.root, target_b);
        assert_eq!(extracted[&2].target.root, target_a);
        assert_eq!(extracted[&3].target.root, target_b);
        assert_eq!(extracted[&4].target.root, target_b);
    }

    /// `drain` must hand back entries in insertion order so that
    /// `promote_new_aggregated_payloads` lands them in known_payloads in the
    /// same order, preserving same-slot equivocation semantics through the
    /// new → known migration.
    #[test]
    fn drain_preserves_insertion_order() {
        let target_a = H256([0xaa; 32]);
        let target_b = H256([0xbb; 32]);
        let target_c = H256([0xcc; 32]);
        let data_a = make_att_data_for_target(1, target_a);
        let data_b = make_att_data_for_target(2, target_b);
        let data_c = make_att_data_for_target(3, target_c);

        let mut buf = PayloadBuffer::new(10);
        buf.push(HashedAttestationData::new(data_a), make_proof());
        buf.push(HashedAttestationData::new(data_b), make_proof());
        buf.push(HashedAttestationData::new(data_c), make_proof());

        let drained = buf.drain();
        let slots: Vec<u64> = drained.iter().map(|(h, _)| h.data().slot).collect();
        assert_eq!(slots, vec![1, 2, 3]);
        assert!(buf.data.is_empty());
        assert!(buf.order.is_empty());
        assert_eq!(buf.total_proofs, 0);
    }

    // ============ GossipSignatureBuffer Tests ============

    fn make_dummy_sig() -> ValidatorSignature {
        use ethlambda_types::signature::LeanSignatureScheme;
        use leansig::{serialization::Serializable, signature::SignatureScheme};
        use rand::{SeedableRng, rngs::StdRng};

        static CACHED_SIG: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
            let mut rng = StdRng::seed_from_u64(42);
            let lifetime = 1 << 5; // small for speed
            let (_pk, sk) = LeanSignatureScheme::key_gen(&mut rng, 0, lifetime);
            let sig = LeanSignatureScheme::sign(&sk, 0, &[0u8; 32]).unwrap();
            sig.to_bytes()
        });

        ValidatorSignature::from_bytes(&CACHED_SIG).expect("cached test signature")
    }

    #[test]
    fn gossip_buffer_fifo_eviction() {
        // Capacity of 3 signatures total
        let mut buf = GossipSignatureBuffer::new(3);

        // Insert 3 sigs across 3 data_roots (1 sig each)
        for slot in 1..=3u64 {
            let data = make_att_data(slot);
            buf.insert(HashedAttestationData::new(data), 0, make_dummy_sig());
        }
        assert_eq!(buf.total_signatures(), 3);
        assert_eq!(buf.len(), 3);

        // Insert a 4th — should evict the oldest (slot 1)
        let data4 = make_att_data(4);
        buf.insert(HashedAttestationData::new(data4), 0, make_dummy_sig());
        assert_eq!(buf.total_signatures(), 3);
        assert_eq!(buf.len(), 3);

        // Slot 1 should be gone
        let slot1_root = HashedAttestationData::new(make_att_data(1)).root();
        assert!(!buf.data.contains_key(&slot1_root));

        // Slots 2, 3, 4 should remain
        let slot2_root = HashedAttestationData::new(make_att_data(2)).root();
        let slot4_root = HashedAttestationData::new(make_att_data(4)).root();
        assert!(buf.data.contains_key(&slot2_root));
        assert!(buf.data.contains_key(&slot4_root));
    }

    #[test]
    fn gossip_buffer_dedup_last_write_wins() {
        let mut buf = GossipSignatureBuffer::new(100);
        let data = make_att_data(1);
        let hashed = HashedAttestationData::new(data);

        buf.insert(hashed.clone(), 0, make_dummy_sig());
        buf.insert(hashed.clone(), 0, make_dummy_sig());

        // Last-write-wins: overwrites the signature but count stays at 1
        assert_eq!(buf.total_signatures(), 1);
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn gossip_buffer_multiple_validators_per_root() {
        let mut buf = GossipSignatureBuffer::new(100);
        let data = make_att_data(1);

        buf.insert(
            HashedAttestationData::new(data.clone()),
            0,
            make_dummy_sig(),
        );
        buf.insert(
            HashedAttestationData::new(data.clone()),
            1,
            make_dummy_sig(),
        );
        buf.insert(
            HashedAttestationData::new(data.clone()),
            2,
            make_dummy_sig(),
        );

        assert_eq!(buf.total_signatures(), 3);
        assert_eq!(buf.len(), 1); // One data_root
    }

    #[test]
    fn gossip_buffer_delete_cleans_up() {
        let mut buf = GossipSignatureBuffer::new(100);
        let data = make_att_data(1);
        let root = HashedAttestationData::new(data.clone()).root();

        buf.insert(
            HashedAttestationData::new(data.clone()),
            0,
            make_dummy_sig(),
        );
        buf.insert(
            HashedAttestationData::new(data.clone()),
            1,
            make_dummy_sig(),
        );
        assert_eq!(buf.total_signatures(), 2);

        // Delete one sig — root should remain
        buf.delete(&[(0, root)]);
        assert_eq!(buf.total_signatures(), 1);
        assert_eq!(buf.len(), 1);

        // Delete last sig — root should be fully removed
        buf.delete(&[(1, root)]);
        assert_eq!(buf.total_signatures(), 0);
        assert_eq!(buf.len(), 0);
        assert!(buf.order.is_empty());
    }

    #[test]
    fn gossip_buffer_prune_by_slot() {
        let mut buf = GossipSignatureBuffer::new(100);

        // Insert sigs at slots 1, 2, 3, 4, 5
        for slot in 1..=5u64 {
            buf.insert(
                HashedAttestationData::new(make_att_data(slot)),
                0,
                make_dummy_sig(),
            );
        }
        assert_eq!(buf.total_signatures(), 5);

        // Prune slots <= 3
        let pruned = buf.prune(3);
        assert_eq!(pruned, 3);
        assert_eq!(buf.total_signatures(), 2);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.order.len(), 2);
    }

    #[test]
    fn gossip_buffer_eviction_removes_whole_root() {
        // Capacity of 4 signatures
        let mut buf = GossipSignatureBuffer::new(4);

        // Slot 1: 3 validators
        let data1 = make_att_data(1);
        buf.insert(
            HashedAttestationData::new(data1.clone()),
            0,
            make_dummy_sig(),
        );
        buf.insert(
            HashedAttestationData::new(data1.clone()),
            1,
            make_dummy_sig(),
        );
        buf.insert(
            HashedAttestationData::new(data1.clone()),
            2,
            make_dummy_sig(),
        );

        // Slot 2: 1 validator
        let data2 = make_att_data(2);
        buf.insert(
            HashedAttestationData::new(data2.clone()),
            0,
            make_dummy_sig(),
        );
        assert_eq!(buf.total_signatures(), 4);

        // Insert slot 3 — should evict slot 1 (3 sigs), now total = 2
        let data3 = make_att_data(3);
        buf.insert(HashedAttestationData::new(data3), 0, make_dummy_sig());

        let slot1_root = HashedAttestationData::new(data1).root();
        assert!(!buf.data.contains_key(&slot1_root));
        assert_eq!(buf.total_signatures(), 2); // slot 2 (1) + slot 3 (1)
        assert_eq!(buf.len(), 2);
    }

    /// `Store::from_anchor_state` writes the header but no `BlockSignatures`
    /// row for the slot-0 anchor. `get_signed_block` must synthesize an empty
    /// proof so the genesis block can still be served on BlocksByRoot /
    /// `/lean/v0/blocks/finalized`.
    #[test]
    fn get_signed_block_synthesizes_blank_proof_for_genesis_anchor() {
        let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new());
        let store = Store::from_anchor_state(backend, State::from_genesis(0, vec![]));

        let head_root = store.head();
        let signed = store
            .get_signed_block(&head_root)
            .expect("genesis block must be retrievable with synthetic proof");

        assert_eq!(signed.message.slot, 0);
        assert_eq!(signed.proof, MultiMessageAggregate::default());
    }

    /// The synthesis branch must be confined to the slot-0 anchor: a
    /// non-genesis block whose `BlockSignatures` row is missing is treated
    /// as storage corruption and surfaces as `None`, not a fabricated block.
    #[test]
    fn get_signed_block_returns_none_for_non_genesis_with_missing_signatures() {
        let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new());

        // Hand-insert a slot-1 header (and empty body, via `EMPTY_BODY_ROOT`)
        // but skip the `BlockSignatures` row. This mimics the corruption case
        // the guard is meant to catch, without going through the normal
        // `insert_signed_block` write path which always writes all three rows.
        let header = BlockHeader {
            slot: 1,
            proposer_index: 0,
            parent_root: H256::ZERO,
            state_root: H256::ZERO,
            body_root: *EMPTY_BODY_ROOT,
        };
        let root = header.hash_tree_root();
        let mut batch = backend.begin_write().expect("write batch");
        batch
            .put_batch(Table::BlockHeaders, vec![(root.to_ssz(), header.to_ssz())])
            .expect("put header");
        batch.commit().expect("commit");

        let store = Store::from_anchor_state(backend, State::from_genesis(0, vec![]));
        assert!(store.get_signed_block(&root).is_none());
    }

    /// The bootstrap anchor is stored as a full snapshot in `States`, the base of
    /// every diff chain that reconstruction terminates at.
    #[test]
    fn from_anchor_state_stores_bootstrap_snapshot() {
        let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new());
        let store = Store::from_anchor_state(backend.clone(), State::from_genesis(0, vec![]));

        let anchor_root = store.head();
        assert!(has_key(backend.as_ref(), Table::States, &anchor_root));
    }

    // ============ from_db_state Tests ============

    #[test]
    fn from_db_state_returns_none_on_empty_backend() {
        let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new());
        assert!(Store::from_db_state(backend, 12345).is_none());
    }

    #[test]
    fn from_db_state_returns_some_on_matching_genesis_time() {
        let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new());
        // Write an initial state to the backend.
        let _ = Store::from_anchor_state(backend.clone(), State::from_genesis(12345, vec![]));
        assert!(Store::from_db_state(backend, 12345).is_some());
    }

    #[test]
    fn from_db_state_returns_none_on_genesis_time_mismatch() {
        let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new());
        // Write an initial state to the backend.
        let _ = Store::from_anchor_state(backend.clone(), State::from_genesis(12345, vec![]));
        assert!(Store::from_db_state(backend, 99999).is_none());
    }

    #[test]
    fn from_db_state_returns_none_when_latest_finalized_is_missing() {
        let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new());
        // Write only KEY_CONFIG, leaving KEY_LATEST_FINALIZED absent.
        let config = ChainConfig {
            genesis_time: 12345,
        };
        let mut batch = backend.begin_write().expect("write batch");
        batch
            .put_batch(
                Table::Metadata,
                vec![(KEY_CONFIG.to_vec(), config.to_ssz())],
            )
            .expect("put config");
        batch.commit().expect("commit");
        assert!(Store::from_db_state(backend, 12345).is_none());
    }
}
