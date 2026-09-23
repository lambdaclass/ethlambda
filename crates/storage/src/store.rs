use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::sync::{Arc, LazyLock, Mutex};

use lru::LruCache;

use crate::api::{StorageBackend, StorageReadView, StorageWriteBatch, Table};
use crate::error::Error;

use ethlambda_crypto::signature::ValidatorSignature;
use ethlambda_types::{
    attestation::{
        AggregatedAttestation, AggregationBits, AttestationData, HashedAttestationData,
        bits_is_subset, validator_indices,
    },
    beacon::{
        config::Config,
        containers::{BeaconState, Checkpoint as BeaconCheckpoint, SignedBeaconBlock},
        fork::ForkName,
        fork_choice::{LatestMessage, PayloadStatusV1, PowBlock},
        preset::{Preset, SLOTS_PER_EPOCH},
        primitives::ExecutionBlockHash,
    },
    block::{
        Block, BlockBody, BlockHeader, MultiMessageAggregate, SignedBlock, SingleMessageAggregate,
    },
    checkpoint::Checkpoint,
    primitives::{H256, HashTreeRoot as _},
    state::{State, anchor_pair_is_consistent},
};
use libssz::{SszDecode, SszEncode};

use crate::state_codec::encode_state_value;
use crate::state_writer::{
    CacheKey, PendingStates, STATE_WRITE_QUEUE_CAPACITY, StateCache, StateWriteRequest,
    StateWriterHandle, read_state,
};
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

/// Key for "time" field of the Store: a UNIX timestamp in **milliseconds**, on
/// both chains. Its value has type [`u64`] and it's SSZ-encoded.
///
/// The single clock. Milliseconds because it has to be fine enough for the
/// finest grid either chain schedules on, which is lean's interval: with
/// `INTERVALS_PER_SLOT` intervals to a slot, most interval boundaries fall
/// strictly between two whole seconds, and a second-resolution row could not
/// name them. Everything coarser is derived, exactly and in one direction:
/// [`Store::current_slot`] for either chain, [`Store::intervals_since_genesis`]
/// for lean's tick pipeline, and a plain division by a thousand for the beacon
/// specification's second-denominated `Store.time`.
///
/// Absolute rather than an offset from genesis, so that a reader holding no
/// configuration can still compare it against a wall clock.
const KEY_TIME: &[u8] = b"time";
/// Key for "config" field of the Store. Its value has type [`Config`] and it's SSZ-encoded.
const KEY_CONFIG: &[u8] = b"config";
/// Key for "head" field of the Store. Its value has type [`H256`] and it's SSZ-encoded.
const KEY_HEAD: &[u8] = b"head";
/// Key for "safe_target" field of the Store. Its value has type [`H256`] and it's SSZ-encoded.
const KEY_SAFE_TARGET: &[u8] = b"safe_target";
/// Key for "latest_justified" field of the Store. Its value has type [`Checkpoint`] and it's SSZ-encoded.
const KEY_LATEST_JUSTIFIED: &[u8] = b"latest_justified";
/// Key for "latest_finalized" field of the Store. Its value has type [`Checkpoint`] and it's SSZ-encoded.
const KEY_LATEST_FINALIZED: &[u8] = b"latest_finalized";
/// Key for the on-disk format version. Its value has type [`u64`] and it's SSZ-encoded.
const KEY_DB_VERSION: &[u8] = b"db_version";
/// Key for which chain this directory holds. Its value is a single
/// [`Chain::selector`] byte, not SSZ: it predates being able to decode
/// anything else in the directory.
const KEY_CHAIN: &[u8] = b"chain";
/// Key for which SSZ preset the build that wrote this directory used. Its
/// value is a single [`Preset::selector`] byte, raw for the same reason
/// [`KEY_CHAIN`] is, and more sharply: the preset is what *decides* the shape
/// of the containers in `States`, so it has to be readable before anything in
/// the directory is decoded, including by a build that would decode them into
/// the wrong shape.
///
/// Written beside [`KEY_CONFIG`] by both bootstrap paths and checked by
/// [`Store::from_db_state`]. Unlike [`KEY_DB_VERSION`], a mismatch here is not
/// something this build could fix by migrating: the other preset's states are
/// a different protocol's states (see this crate's `preset` module), so the
/// only answer is to refuse.
const KEY_PRESET: &[u8] = b"preset";
/// Key for the beacon store's unrealized justified checkpoint.
///
/// The *realized* pair has no beacon-specific key: both chains record theirs
/// under [`KEY_LATEST_JUSTIFIED`]/[`KEY_LATEST_FINALIZED`] as a slot-denominated
/// [`Checkpoint`], so one `update_checkpoints` advances either chain. A beacon
/// epoch converts to that shape losslessly, since an epoch names its own start
/// slot; see [`Store::beacon_justified_checkpoint`].
const KEY_BEACON_UNREALIZED_JUSTIFIED: &[u8] = b"beacon_unrealized_justified";
/// Key for the beacon store's unrealized finalized checkpoint.
const KEY_BEACON_UNREALIZED_FINALIZED: &[u8] = b"beacon_unrealized_finalized";
/// The slot this directory's chain begins at: the anchor block's own slot,
/// whether that anchor is genesis or a checkpoint. Its value has type [`u64`]
/// and it's SSZ-encoded.
///
/// Written once by each bootstrap path and never rewritten, like [`KEY_CONFIG`]
/// and [`KEY_CHAIN`]. It is the store's only record of where it started:
/// [`KEY_LATEST_FINALIZED`] is seeded to the anchor too, but moves with the
/// chain, so after the first finalization nothing else on disk can answer this.
const KEY_ANCHOR_SLOT: &[u8] = b"anchor_slot";
/// The on-disk format this build reads and writes.
///
/// Bumped whenever a table's key or value layout changes. `from_db_state`
/// refuses any other value rather than migrating: a lean devnet resyncs in
/// minutes, and a wrong guess about an old layout corrupts silently.
///
/// 2 added [`KEY_ANCHOR_SLOT`], which [`Store::from_db_state`] requires and a
/// version 1 directory does not carry.
///
/// 3 widened `Config` with the runtime keys a `config.yaml` carries: the struct
/// is SSZ-encoded under [`KEY_CONFIG`], so a directory written by the previous
/// version decodes into the wrong fields. There is no migration, by the same
/// policy every previous change followed.
pub const DB_VERSION: u64 = 3;

/// The consensus protocol a data directory holds.
///
/// Written once at bootstrap and never rewritten, like `Metadata["config"]`. A
/// directory is one chain or the other for its whole life: the two use
/// different state shapes, different checkpoint types and different clock
/// units, and nothing migrates between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Lean,
    Beacon,
}

impl Chain {
    /// The byte this chain is stored under. Spelled out rather than derived
    /// from the variant order, because it is a storage format and not a
    /// discriminant: reordering the variants must not reinterpret a directory.
    pub const fn selector(self) -> u8 {
        match self {
            Chain::Lean => 0,
            Chain::Beacon => 1,
        }
    }

    /// The inverse of [`Chain::selector`].
    pub const fn from_selector(byte: u8) -> Option<Chain> {
        match byte {
            0 => Some(Chain::Lean),
            1 => Some(Chain::Beacon),
            _ => None,
        }
    }
}

/// Number of reconstructed/imported states memoized in memory.
///
/// States are content-addressed by block root and immutable, so the cache never
/// needs invalidation; it only bounds how many recent states stay hot for reads
/// (e.g. a block's `parent_state` right after import). A miss falls back to a
/// snapshot read or a diff-chain reconstruction.
const STATE_CACHE_CAPACITY: usize = 32;

/// Keep block proofs for at least this many slots below the tip, even once
/// finalized. Proofs older than this window are pruned only when the window
/// lies entirely within finalized history; see [`Store::prune_old_block_proofs`].
/// ~1 day at the default 4-second slots, proportionally longer on a slower one.
const BLOCK_PROOF_PRUNING_RANGE: u64 = 21_600;

/// Resume window, in slots. A slot count rather than a wall-clock window: the
/// cost of resuming is replaying this many slots, whatever they last. ~30
/// minutes at the default 4-second slots (1800 / 4 = 450).
pub const MAX_RESUMABLE_DB_STATE_AGE: u64 = 450;

/// Hard cap for the known aggregated payload buffer (number of distinct attestation messages).
/// With 1 attestation/slot, this holds ~500 messages (~33 min at the default
/// 4s/slot).
const AGGREGATED_PAYLOAD_CAP: usize = 512;

/// Hard cap for the new (pending) aggregated payload buffer.
/// Smaller than known since new payloads are drained every interval.
/// Public so pool-seeding callers (the block-building benchmark) can reject
/// workloads that a single insertion batch would silently evict.
pub const NEW_PAYLOAD_CAP: usize = 64;

/// Hard cap for the gossip signature buffer (individual signatures, not distinct data_roots).
/// With 4 validators, 2048 signatures covers ~512 slots (~34 min at the
/// default 4-second slots).
/// Each XMSS signature is ~3KB, so worst-case memory is ~6 MB.
const GOSSIP_SIGNATURE_CAP: usize = 2048;

/// An entry in the payload buffer: attestation data + set of proofs.
#[derive(Clone)]
struct PayloadEntry {
    data: AttestationData,
    proofs: Vec<SingleMessageAggregate>,
}

/// Fixed-size circular buffer for aggregated payloads.
///
/// Groups proofs by attestation data (via data_root). Each distinct
/// attestation message stores the full `AttestationData` plus all
/// `SingleMessageAggregate`s covering that message.
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
    fn push(&mut self, hashed: HashedAttestationData, proof: SingleMessageAggregate) {
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
    fn push_batch(&mut self, entries: Vec<(HashedAttestationData, SingleMessageAggregate)>) {
        for (hashed, proof) in entries {
            self.push(hashed, proof);
        }
    }

    /// Take all entries, leaving the buffer empty.
    ///
    /// Drains in insertion order (via `self.order`) so downstream consumers
    /// like `promote_new_aggregated_payloads` re-insert into known_payloads
    /// deterministically; `self.data` iteration alone would be RandomState-seeded.
    /// (Fork-choice vote extraction no longer depends on this order: it resolves
    /// same-slot equivocation by canonical attestation-data root, see
    /// `extract_latest_attestations`.)
    fn drain(&mut self) -> Vec<(HashedAttestationData, SingleMessageAggregate)> {
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
    fn proofs_for_root(&self, data_root: &H256) -> Vec<SingleMessageAggregate> {
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

type StorageKey = Vec<u8>;
type StorageEntry = (StorageKey, Vec<u8>);
type BlockRootIndexChanges = (Vec<StorageKey>, Vec<StorageEntry>);

#[derive(Clone, Default)]
struct ForkChoiceState {
    known_votes: HashMap<u64, AttestationData>,
    new_votes: HashMap<u64, AttestationData>,
}

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

    /// Largest signature count among data groups whose attestation slot is `slot`.
    fn max_group_count_for_slot(&self, slot: u64) -> usize {
        self.data
            .values()
            .filter(|entry| entry.data.slot == slot)
            .map(|entry| entry.signatures.len())
            .max()
            .unwrap_or(0)
    }

    /// Extract per-validator latest attestations from the raw signature pool.
    ///
    /// Votes are processed newest-first with an equal-slot tie broken toward the
    /// larger canonical attestation-data root, so the extracted winner is
    /// independent of arrival or insertion order (leanSpec #1181). This matches the leanSpec
    /// `location == "signatures"` checker, which folds `attestation_signatures`
    /// keeping each validator's canonical-precedence winner.
    fn extract_latest_attestations(&self) -> HashMap<u64, AttestationData> {
        let mut ordered: Vec<(&H256, &GossipDataEntry)> = self.data.iter().collect();
        // Descending by (slot, data_root): the larger tuple is the canonical winner.
        ordered.sort_unstable_by(|a, b| (b.1.data.slot, b.0).cmp(&(a.1.data.slot, a.0)));

        let mut result: HashMap<u64, AttestationData> = HashMap::new();
        for (_data_root, entry) in ordered {
            for &vid in entry.signatures.keys() {
                // Descending order means the first vote seen for a validator wins.
                result.entry(vid).or_insert_with(|| entry.data.clone());
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

/// Beacon fork-choice state that is per-slot or per-epoch scratch rather than
/// chain history: nothing here survives a restart, and nothing here is worth
/// the write amplification of persisting.
///
/// `proposer_boost_root` resets every slot, `block_timeliness` is read only by
/// the same-slot reorg helpers, `equivocating_indices` is rebuilt by replaying
/// attester slashings on sync, `latest_messages` is rebuilt by the first epoch
/// of attestations, `pow_blocks` stands in for a call to an execution client
/// that a restarted node would simply make again, and
/// `unrealized_justifications` is recomputed by replaying epoch processing on a
/// copy of a block's post-state, which a node resuming from an anchor does
/// anyway as it re-imports the unfinalized window. `optimistic_roots` and
/// `payload_statuses` are likewise answers an execution client can be asked
/// for again, and `el_block_hashes` is a cache over data already decodable
/// from the block itself.
///
/// Most of this is uncapped: the per-validator maps are bounded by the
/// validator set, and the per-block ones (`block_timeliness`,
/// `unrealized_justifications`) grow with the blocks this process has
/// imported. Two are the exception, `el_block_hashes` and `optimistic_roots`,
/// each pruned to the unfinalized window by its own `prune_*` method. Both
/// fill on a path that runs for the whole life of the process and has no other
/// way of emptying them: `forkchoiceUpdated` reads the first once per head
/// move, and an execution client doing a long state sync answers
/// `NOT_VALIDATED` to every block, which writes the second once per import.
#[derive(Default)]
pub(crate) struct BeaconScratch {
    pub(crate) proposer_boost_root: H256,
    pub(crate) block_timeliness: HashMap<H256, bool>,
    pub(crate) equivocating_indices: HashSet<u64>,
    pub(crate) latest_messages: HashMap<u64, LatestMessage>,
    pub(crate) pow_blocks: HashMap<H256, PowBlock>,
    pub(crate) unrealized_justifications: HashMap<H256, BeaconCheckpoint>,
    /// Beacon roots imported on an execution client's `NOT_VALIDATED` answer,
    /// against the slot the unfinalized-window bound prunes them by.
    ///
    /// An entry leaves on a later `VALID` or `INVALIDATED` verdict, and, for
    /// the ones that get neither, on finality. Bounded like `el_block_hashes`
    /// and for the same kind of reason: an execution client stuck on `SYNCING`
    /// answers `NOT_VALIDATED` to every block, and without
    /// `prune_beacon_optimistic_roots` nothing would ever take those entries
    /// back out.
    ///
    /// Nothing outside `fork_choice::mark_validated`'s own ancestor walk reads
    /// [`Store::is_beacon_optimistic`] yet, so outside that walk this is
    /// write-only. The readers it is waiting for are the ones that need to
    /// answer "is my head optimistic?": the Beacon API's `execution_optimistic`
    /// response field, and a sync status that distinguishes a head this node
    /// has vouched for from one it has merely imported.
    pub(crate) optimistic_roots: HashMap<H256, u64>,
    /// Payload statuses keyed by execution block hash, standing in for a call
    /// to an execution client exactly as `pow_blocks` does. Written only by
    /// the `sync/optimistic` fixture runner's `on_payload_info` step; the
    /// production path carries its verdict as an `on_block` parameter instead.
    pub(crate) payload_statuses: HashMap<ExecutionBlockHash, PayloadStatusV1>,
    /// Beacon root to `(slot, execution block hash)`. A cache, not a source of
    /// truth: every entry is recoverable by decoding the block. Unlike its
    /// neighbours it *is* bounded, by `prune_beacon_el_block_hashes`, because
    /// forkchoiceUpdated reads it once per head move for the whole life of the
    /// process.
    pub(crate) el_block_hashes: HashMap<H256, (u64, ExecutionBlockHash)>,
}

/// Encode a LiveChain key (slot, root) to bytes.
/// Layout: slot (8 bytes big-endian) || root (32 bytes)
/// Big-endian ensures lexicographic ordering matches numeric ordering.
fn encode_slot_root_key(slot: u64, root: &H256) -> Vec<u8> {
    let mut result = slot.to_be_bytes().to_vec();
    result.extend_from_slice(&root.0);
    result
}

/// Decode a slot||root key (LiveChain / BlockProof) from bytes.
fn decode_slot_root_key(bytes: &[u8]) -> (u64, H256) {
    let slot = u64::from_be_bytes(bytes[..8].try_into().expect("valid slot bytes"));
    let root = H256::from_slice(&bytes[8..]);
    (slot, root)
}

fn encode_block_root_key(slot: u64) -> Vec<u8> {
    slot.to_be_bytes().to_vec()
}

/// The length of every [`data_column_key`]: slot, root, column index.
const DATA_COLUMN_KEY_LEN: usize = 8 + 32 + 8;

/// The key one sidecar is stored under: slot, then block root, then column.
///
/// Extends [`encode_slot_root_key`]'s slot||root pair with the column index,
/// so a block's sidecars share the same slot-major prefix `LiveChain` and
/// `BlockProof` already use, and a prefix scan over just that pair (see
/// [`data_column_block_prefix`]) recovers every column of one block.
fn data_column_key(slot: u64, block_root: &H256, column_index: u64) -> Vec<u8> {
    let mut key = encode_slot_root_key(slot, block_root);
    key.extend_from_slice(&column_index.to_be_bytes());
    key
}

/// The prefix every sidecar of one block shares: its slot||root pair.
fn data_column_block_prefix(slot: u64, block_root: &H256) -> Vec<u8> {
    encode_slot_root_key(slot, block_root)
}

/// Encodes a beacon `BlockHeaders` value: the block's fork selector, then the
/// variant's own SSZ.
///
/// The same tag-then-payload shape as [`encode_state_value`], and for the same
/// reason: a beacon block's shape varies by fork, and SSZ carries no type tag
/// of its own.
fn encode_beacon_block_value(block: &SignedBeaconBlock) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(block.fork_name().selector());
    bytes.extend_from_slice(&block.to_ssz());
    bytes
}

/// The inverse of [`encode_beacon_block_value`].
///
/// Panics on a value this build cannot tag-decode, matching every other read
/// in this file: `from_db_state` has already rejected a directory of the wrong
/// format version, so anything reaching here is corruption rather than an old
/// database.
fn decode_beacon_block_value(bytes: &[u8]) -> SignedBeaconBlock {
    let (tag, ssz) = bytes.split_first().expect("value is never empty");
    let fork = ForkName::from_selector(*tag).expect("value carries a known fork selector");
    SignedBeaconBlock::from_ssz(fork, ssz).expect("valid signed block")
}

/// `root`'s slot on a beacon chain, read without a `Store`, for the writer
/// thread's anchor decision.
///
/// `None` when no block is on record for `root`, which is how the store's
/// first-ever beacon state is recognised: it has no parent block, so there is
/// no base to diff against and it is always a snapshot.
///
/// Beacon directories only: it decodes the row as a tagged
/// [`SignedBeaconBlock`], which is the wrong shape for a lean directory's bare
/// [`BlockHeader`] (unlike [`block_fields`](Store::block_fields), which
/// dispatches on `self.chain`). Nothing does today: [`StateWriter::write`](crate::state_writer)'s
/// non-`Lean` match arm is this function's only caller, so that invariant is
/// enforced by having exactly one caller rather than by a runtime check.
pub(crate) fn beacon_block_slot(backend: &dyn StorageBackend, root: &H256) -> Option<u64> {
    let view = backend.begin_read().expect("read view");
    let bytes = view
        .get(Table::BlockHeaders, &root.to_ssz())
        .expect("get")?;
    drop(view);
    Some(decode_beacon_block_value(&bytes).slot())
}

/// Fork choice store backed by a pluggable storage backend.
///
/// The Store maintains all state required for fork choice and block processing:
///
/// - **Metadata**: time, config, head, safe_target, justified/finalized checkpoints
/// - **Blocks**: headers and bodies stored separately for efficient header-only queries
/// - **BlockRoots**: canonical block roots indexed by slot
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
    /// The node's runtime configuration: genesis time and slot duration for
    /// both chains, plus the beacon fork schedule when this is a beacon
    /// directory.
    ///
    /// Behind an `Arc` rather than a plain copy: every beacon fork-choice call
    /// takes `&mut Store` alongside the config, so a caller has to hold it
    /// across a mutable borrow of the store it came from. Cloning the `Arc` is
    /// one atomic increment, not a copy of the fork schedule.
    ///
    /// Written once at bootstrap and never rewritten, so a per-`Store` copy
    /// cannot go stale. It stays in `Table::Metadata` under `KEY_CONFIG`
    /// because `from_db_state` reads it back to reject a DB whose genesis time
    /// or slot duration disagrees with the config file; this field only spares
    /// every caller a backend round trip and a `Result` it could never act on.
    config: Arc<Config>,
    /// Which chain this directory holds. Cached for the same reason
    /// [`Store::config`] is: written once at bootstrap, so a per-`Store` copy
    /// cannot go stale.
    pub(crate) chain: Chain,
    /// The slot this store's chain begins at, from [`KEY_ANCHOR_SLOT`]. Cached
    /// for the same reason [`Store::chain`] is, and it is read on the
    /// `data_column_sidecars_by_range` path, where a backend round trip per
    /// request would buy nothing: the value cannot change while the process
    /// runs.
    ///
    /// A node that bootstrapped from genesis has zero here; one that
    /// checkpoint-synced has the checkpoint's slot. Nothing below it is
    /// servable, because nothing below it was ever written.
    anchor_slot: u64,
    new_payloads: Arc<Mutex<PayloadBuffer>>,
    known_payloads: Arc<Mutex<PayloadBuffer>>,
    /// Fork-choice votes, independent from bounded proof/signature buffers.
    fork_choice: Arc<Mutex<ForkChoiceState>>,
    /// In-memory gossip signatures, consumed at interval 2 aggregation.
    gossip_signatures: Arc<Mutex<GossipSignatureBuffer>>,
    /// LRU memoization of states by block root, shared across `Store` clones.
    ///
    /// Holds the same fork-ladder enum the `States` table stores, so a lean
    /// entry is a `BeaconState::Lean`. This is the only state cache: it is what
    /// bounds the beacon fork choice, which previously held whole states in
    /// unbounded maps.
    ///
    /// Behind an `Arc` because a hit must not copy: a mainnet `BeaconState` is
    /// large enough that returning an owned one would give back much of what
    /// the cache saves. Lean callers that need an owned `State` clone through
    /// the `Arc`, which is cheap at lean's sizes.
    ///
    /// A miss is never an error. Every caller derives the value by
    /// reconstructing from the nearest snapshot, which is what makes this a
    /// cache rather than the store's record of anything, and why the capacity
    /// is a pure speed and memory trade with no correctness stake. Nothing
    /// here may become a consensus input: a decision that changed with cache
    /// residency would be a bug, not a tuning choice.
    state_cache: Arc<StateCache>,
    /// States handed to the writer but not yet committed; see
    /// [`PendingStates`].
    pending_states: Arc<PendingStates>,
    /// Beacon fork-choice scratch. Empty and untouched on a lean chain.
    pub(crate) beacon: Arc<Mutex<BeaconScratch>>,
    /// The background writer, joined when the last clone of this `Store`
    /// drops. See [`StateWriterHandle`].
    state_writer: Arc<StateWriterHandle>,
}

/// Build an empty state cache sized to [`STATE_CACHE_CAPACITY`].
fn new_state_cache() -> Arc<StateCache> {
    let capacity = NonZeroUsize::new(STATE_CACHE_CAPACITY).expect("cache capacity is non-zero");
    Arc::new(Mutex::new(LruCache::new(capacity)))
}

impl Store {
    /// Initialize a Store from an anchor state only.
    ///
    /// Uses the state's `latest_block_header` as the anchor block header.
    /// No block body is stored since it's not available.
    ///
    /// `milliseconds_per_slot` comes from the network's config file: the anchor
    /// state carries the genesis time but not the cadence, which the spec's SSZ
    /// `Config` has no field for.
    pub fn from_anchor_state(
        backend: Arc<dyn StorageBackend>,
        anchor_state: State,
        milliseconds_per_slot: u64,
    ) -> Self {
        Self::init_store(backend, anchor_state, None, milliseconds_per_slot)
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
        milliseconds_per_slot: u64,
    ) -> Result<Self, GetForkchoiceStoreError> {
        if !anchor_pair_is_consistent(&mut anchor_state, &anchor_block) {
            return Err(GetForkchoiceStoreError::AnchorPairInconsistent {
                anchor_state: Box::new(anchor_state),
                anchor_block: Box::new(anchor_block),
            });
        }

        Ok(Self::init_store(
            backend,
            anchor_state,
            Some(anchor_block.body),
            milliseconds_per_slot,
        )
        .expect("store initialization should succeed in get_forkchoice_store"))
    }

    /// Load the chain a data directory holds, without judging whether it is
    /// ours.
    ///
    /// Returns `None` when the backend has never held a chain of either kind,
    /// leaving the caller to initialize one from genesis or a checkpoint.
    ///
    /// **The caller must check [`Store::chain`] and verify the finalized
    /// state's genesis against the network it was configured for before
    /// writing anything.** This returns a usable `Store` for a foreign chain
    /// as readily as for our own, and initializing a new anchor on top of a
    /// foreign one would leave that chain's rows in place, reachable through
    /// the slot-indexed reads that serve `BlocksByRange`, so peers would be
    /// served another network's blocks.
    ///
    /// Loading and judging are separate because the judgement needs the
    /// configured network and this crate does not know it. `main`'s
    /// `fetch_initial_state` is the caller, and it discharges the obligation
    /// immediately; the beacon path grows its own alongside it.
    ///
    /// **The caller must also call [`Store::repair_head`], after its own
    /// checks, before trusting this store for anything else.** This does not
    /// do it itself: repairing the head is a mutation, and this function's own
    /// contract (like every other read here) is to load without writing.
    /// `repair_head` also wants the caller's checks to have already run: it
    /// assumes justified and finalized both have persisted states (see
    /// [`Store::verify_anchor_states`]), which is what lets it bound its walk
    /// against finalized rather than potentially rewinding past it.
    ///
    /// # Errors
    ///
    /// [`Error::DbVersionMismatch`] when the directory was written by a build
    /// with a different on-disk format. There is no migration.
    pub fn from_db_state(backend: Arc<dyn StorageBackend>) -> Result<Option<Self>, Error> {
        let (config, chain, anchor_slot) = {
            // Written by both `init_store` and `init_beacon`, so a backend
            // missing this has never held a chain of either kind.
            let view = backend.begin_read().expect("read view");
            let Some(bytes) = view.get(Table::Metadata, KEY_CONFIG).expect("get config") else {
                return Ok(None);
            };

            let found = view
                .get(Table::Metadata, KEY_DB_VERSION)
                .expect("get db version")
                .map(|bytes| u64::from_ssz_bytes(&bytes).expect("valid db version"))
                .unwrap_or(0);
            if found != DB_VERSION {
                return Err(Error::DbVersionMismatch {
                    found,
                    expected: DB_VERSION,
                });
            }

            // Before the config decode below and well before any state read:
            // the preset fixes every SSZ container bound in the directory, so
            // a build holding the other one would not be reading the same
            // shapes back. The version check above cannot stand in for this,
            // since both presets write the same *layout* at the same version.
            let found_preset = view
                .get(Table::Metadata, KEY_PRESET)
                .expect("get preset")
                .and_then(|bytes| bytes.first().copied())
                .and_then(Preset::from_selector);
            if found_preset != Some(Preset::ACTIVE) {
                return Err(Error::PresetMismatch {
                    found: found_preset.map(Preset::name),
                    expected: Preset::ACTIVE.name(),
                });
            }

            let chain = view
                .get(Table::Metadata, KEY_CHAIN)
                .expect("get chain")
                .and_then(|bytes| bytes.first().copied())
                .and_then(Chain::from_selector)
                .expect("a versioned directory always carries a chain tag");

            // Both bootstrap paths write this, and the version check above
            // already turned away every directory written before they did, so
            // an absent key here is not an old directory but a corrupt one.
            let anchor_slot = view
                .get(Table::Metadata, KEY_ANCHOR_SLOT)
                .expect("get anchor slot")
                .map(|bytes| u64::from_ssz_bytes(&bytes).expect("valid anchor slot"))
                .expect("a versioned directory always carries an anchor slot");

            (
                Config::from_ssz_bytes(&bytes).expect("valid config"),
                chain,
                anchor_slot,
            )
        };

        info!(?chain, anchor_slot, "Loaded store from persisted DB state");
        Ok(Some(Self::from_parts(
            backend,
            Arc::new(config),
            chain,
            anchor_slot,
        )))
    }

    /// Checks that both the justified and finalized checkpoints have a
    /// persisted state, returning the finalized state (which a resuming
    /// caller needs anyway, to verify genesis) or [`Error::AnchorStateLost`]
    /// naming whichever checkpoint does not.
    ///
    /// Call this, and act on its error, before [`Store::repair_head`]:
    /// unlike the head, justified and finalized are consensus statements. A
    /// repair may roll the head back to a recent ancestor because fork choice
    /// reprocesses forward from there on its own (see `repair_head`'s doc),
    /// but there is no equivalent recovery for a checkpoint a repair cannot
    /// simply invent an earlier version of. So this reports the loss instead,
    /// for the caller's own retry logic to treat exactly like a stale
    /// directory: fall back to checkpoint sync if a URL is configured, or
    /// fail naming the remedy in [`Error::AnchorStateLost`] if not.
    ///
    /// This is also what lets `repair_head` bound its own walk against
    /// finalized: once this has passed, finalized's state is known good, so a
    /// walk that reaches it (rather than running past it) is a normal
    /// termination, not a case `repair_head` has to guard against on its own.
    pub fn verify_anchor_states(&self) -> Result<Arc<BeaconState>, Error> {
        let justified = self.latest_justified()?;
        if !self.has_state(&justified.root)? {
            return Err(Error::AnchorStateLost {
                checkpoint: justified,
            });
        }
        let finalized = self.latest_finalized()?;
        self.get_state(&finalized.root)?
            .ok_or(Error::AnchorStateLost {
                checkpoint: finalized,
            })
    }

    /// Rewinds the head to the newest ancestor with a persisted state, if the
    /// recorded head has none.
    ///
    /// A resuming caller (see [`Store::from_db_state`]'s doc) calls this
    /// after [`Store::verify_anchor_states`] has already confirmed justified
    /// and finalized both have one; this method assumes that and does not
    /// re-check it.
    ///
    /// # Why the head can outrun its own state
    ///
    /// The writer thread (see [`crate::state_writer::StateWriterHandle`])
    /// commits a block's post-state asynchronously; the caller that hands it
    /// off gets control back once the state is cached and buffered, not once
    /// it is on disk. The importer's `update_head` writes `KEY_HEAD` (and the
    /// canonical `BlockRoots` index) synchronously, right after that hand-off,
    /// so an unclean shutdown can catch the head pointer on disk before the
    /// state it names is. Before the writer thread existed the state write
    /// was synchronous and always preceded the head write, so a persisted
    /// head implied a persisted state; this restores that invariant on the
    /// way back up, once per resume, rather than requiring every future
    /// reader of the head to re-check it.
    ///
    /// Only the head pointer and the canonical `BlockRoots` index are
    /// rewritten (the latter by the same [`Store::update_checkpoints`] every
    /// head move already goes through). Justified and finalized are never
    /// touched here; see [`Store::verify_anchor_states`] for why.
    ///
    /// `KEY_SAFE_TARGET` is left exactly as stale as it already was: it can
    /// still name a hopped block whose `LiveChain` row this method just
    /// deleted. Harmless, deliberately not fixed up here: its only reader
    /// (the lean tick pipeline's block-building guard) takes the block's
    /// header, never its state, and the next interval-3 tick recomputes it
    /// from `get_live_chain()`, which already reflects the deletion.
    ///
    /// # This also removes the hopped blocks from fork choice
    ///
    /// Each block walked past keeps its `BlockHeaders`/`BlockBodies`/
    /// `BlockProof` rows; only its `LiveChain` row is deleted. That is
    /// already this codebase's encoding of "invisible to fork choice" (see
    /// [`Store::insert_pending_block`]'s doc), and it is what makes the
    /// rewind stick: leaving the row behind would keep the stateless tip
    /// visible to `compute_lmd_ghost_head`, which does not consult
    /// `has_state`, so the very next fork-choice run would walk right back to
    /// it. Deleting it composes with machinery that already exists to bring a
    /// stateless block back: `on_block_core` keys its duplicate check on
    /// `has_state`, not on the block being on record, so re-processing it is
    /// not treated as a no-op; range sync asks peers for blocks starting at
    /// `head_slot + 1`, which is now this block's slot again; and the
    /// pending-block walk that runs when a new block's parent has no state
    /// pulls a stateless ancestor back out of storage with
    /// [`Store::get_signed_block`] and re-imports it. Nothing here has to
    /// reach across into the blockchain crate to trigger any of that; it
    /// falls out of a block just being stateless again, which is the
    /// ordinary case those three already handle.
    ///
    /// # Termination
    ///
    /// On the lean arm, guaranteed: [`Store::init_store`] writes the anchor's
    /// snapshot synchronously, in the same atomic batch as the rest of the
    /// metadata, and a lean head always names a block (`init_store` writes it
    /// in that same batch), so the walk always reaches a persisted state
    /// before it could reach a root with no block entry at all.
    ///
    /// On the beacon arm this is not guaranteed the same way: the anchor
    /// insertion that follows [`Store::init_beacon`] now enqueues its state
    /// like any other (`insert_state` no longer writes synchronously on
    /// either arm), so the same unclean-shutdown window that motivates this
    /// method can also catch the anchor itself without a state. Two
    /// independent bounds cover this instead of trusting synchronous writes
    /// that no longer happen, checked together since
    /// [`Store::anchor_slot`] `<=` [`Store::latest_finalized`]'s slot always
    /// holds and the two therefore coincide on a fresh checkpoint-sync
    /// anchor with no finalization progress yet:
    ///
    /// - Below or at [`Store::latest_finalized`]'s slot,
    ///   [`Store::prune_live_chain`] has already deleted `LiveChain` rows for
    ///   every slot down there, so a head rewound that far would be invisible
    ///   to fork choice regardless — worse than the state it is missing.
    ///   Reported as [`Error::AnchorStateLost`], the same error
    ///   `verify_anchor_states` reports; reaching it here means that check's
    ///   invariant did not hold, which this treats as an error rather than
    ///   trusting. This is what the tie above resolves to, since it names the
    ///   checkpoint and a remedy.
    /// - Strictly below [`Store::anchor_slot`] *and* strictly below
    ///   finalized's slot (so distinguishable from the tie), this directory
    ///   could never have held a state to fall back to at all. Reported as
    ///   [`Error::UnexpectedMissingState`] naming the original head, not an
    ///   unfamiliar ancestor the operator never saw the walk step onto.
    ///
    /// Independently of both, at most [`STATE_WRITE_QUEUE_CAPACITY`] + 1
    /// blocks can have an unwritten state behind the head at once (the queue
    /// plus the one write the worker thread can be holding), so a walk
    /// longer than that means something other than this window caused it.
    /// That case is reported as [`Error::HeadRepairExceededWindow`] rather
    /// than walked past. A root with no block entry at all, reached partway
    /// through the walk (not at the start; see below), is a broken parent
    /// chain and is reported as [`Error::UnexpectedMissingBlockHeader`].
    ///
    /// # A head with no block at all
    ///
    /// On a lean directory this is corruption: `init_store` writes the head's
    /// own block in the same batch as `KEY_HEAD`, so nothing legitimate
    /// leaves that row pointing at an absent header. Reported as
    /// [`Error::UnexpectedMissingBlockHeader`].
    ///
    /// On a beacon directory this can be legitimate: [`Store::init_beacon`]
    /// alone seeds `KEY_HEAD` at the checkpoint root before the anchor block
    /// and state that pair with it have been inserted (a separate step,
    /// taken by the caller once checkpoint sync or the genesis path completes
    /// it), and `from_db_state`'s contract is to load that directory anyway.
    /// The writer-outran-the-head race this method repairs cannot produce
    /// that shape on its own: it requires the head's own block to already be
    /// on disk, only its state to be missing. So this bails out untouched,
    /// rather than reporting corruption for a directory `from_db_state` has
    /// always accepted.
    pub fn repair_head(&mut self) -> Result<(), Error> {
        let start = self.head()?;
        // `has_state` checks `pending_states` before the backend, but that
        // buffer is always empty here: this runs once per resume, right after
        // `from_parts` built a fresh one, before anything has been inserted.
        // So this is a pure backend check, not a reason to reach for a raw
        // table read instead. Checked before `block_entry` so the common,
        // already-healthy case pays for exactly one read, not two.
        if self.has_state(&start)? {
            return Ok(());
        }

        // See "A head with no block at all" above.
        let Some((mut slot, mut parent_root)) = self.block_entry(&start) else {
            return match self.chain {
                Chain::Lean => Err(Error::UnexpectedMissingBlockHeader(start)),
                Chain::Beacon => Ok(()),
            };
        };

        let finalized = self.latest_finalized()?;
        let mut cursor = start;
        let mut hops = 0usize;
        // `(slot, root)` pairs to delete from `LiveChain`; see "This also
        // removes the hopped blocks from fork choice" above.
        let mut hopped = Vec::new();

        loop {
            // `anchor_slot <= finalized.slot` always holds, so the two bounds
            // coincide on a fresh checkpoint-sync anchor with no finalization
            // progress yet. The tie, and everything at or below finalized in
            // general, is reported as `AnchorStateLost`: it names the
            // checkpoint and a remedy, which `UnexpectedMissingState` does
            // not. Only where the anchor sits strictly *above* finalized
            // does a stop at or below it get the more specific error: there,
            // "this directory never held that block" is the more accurate
            // statement than a reader would get from the checkpoint's own
            // (later) slot.
            if slot <= finalized.slot {
                return Err(
                    if slot <= self.anchor_slot && self.anchor_slot < finalized.slot {
                        Error::UnexpectedMissingState(start)
                    } else {
                        Error::AnchorStateLost {
                            checkpoint: finalized,
                        }
                    },
                );
            }

            hopped.push((slot, cursor));
            hops += 1;
            if hops > STATE_WRITE_QUEUE_CAPACITY + 1 {
                return Err(Error::HeadRepairExceededWindow {
                    start,
                    stalled_at: cursor,
                    hops,
                });
            }

            cursor = parent_root;
            if self.has_state(&cursor)? {
                break;
            }
            let Some(next) = self.block_entry(&cursor) else {
                return Err(Error::UnexpectedMissingBlockHeader(cursor));
            };
            slot = next.0;
            parent_root = next.1;
        }

        // Reaching here means the loop hopped at least once, so `cursor` is
        // strictly an ancestor of `start`: nothing below removes a row for a
        // head that was never touched.
        self.delete_live_chain_entries(&hopped);
        warn!(
            from = %start,
            to = %cursor,
            hops,
            "head outran the state writer; rewound to the newest ancestor with a persisted state"
        );
        self.update_checkpoints(ForkCheckpoints::head_only(cursor))?;
        Ok(())
    }

    /// Internal helper to initialize the store with anchor data.
    ///
    /// Header is taken from `anchor_state.latest_block_header`.
    fn init_store(
        backend: Arc<dyn StorageBackend>,
        mut anchor_state: State,
        anchor_body: Option<BlockBody>,
        milliseconds_per_slot: u64,
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

        let anchor_slot = anchor_state.latest_block_header.slot;
        let anchor_checkpoint = Checkpoint {
            root: anchor_block_root,
            slot: anchor_slot,
        };

        // The runtime config a lean directory bootstraps with: built once here
        // so the same value backs both the persisted row and the in-memory
        // `Store`, rather than reconstructing it twice.
        let runtime_config = Arc::new(Config::lean(
            anchor_state.config.genesis_time,
            milliseconds_per_slot,
        ));

        // Insert initial data
        {
            let mut batch = backend.begin_write().expect("write batch");

            // Metadata
            let metadata_entries = vec![
                (KEY_DB_VERSION.to_vec(), DB_VERSION.to_ssz()),
                (KEY_CHAIN.to_vec(), vec![Chain::Lean.selector()]),
                (KEY_PRESET.to_vec(), vec![Preset::ACTIVE.selector()]),
                // Genesis, not zero: `KEY_TIME` is an absolute UNIX
                // millisecond, so the value that means "the clock has not
                // advanced past genesis" is genesis itself.
                (KEY_TIME.to_vec(), runtime_config.genesis_time_ms().to_ssz()),
                (KEY_CONFIG.to_vec(), runtime_config.to_ssz()),
                (KEY_HEAD.to_vec(), anchor_block_root.to_ssz()),
                (KEY_SAFE_TARGET.to_vec(), anchor_block_root.to_ssz()),
                (KEY_LATEST_JUSTIFIED.to_vec(), anchor_checkpoint.to_ssz()),
                (KEY_LATEST_FINALIZED.to_vec(), anchor_checkpoint.to_ssz()),
                (KEY_ANCHOR_SLOT.to_vec(), anchor_slot.to_ssz()),
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

            batch
                .put_batch(
                    Table::BlockRoots,
                    vec![(
                        encode_block_root_key(anchor_state.latest_block_header.slot),
                        anchor_block_root.to_ssz(),
                    )],
                )
                .expect("put block root index");

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
            let state_entries = vec![(
                anchor_block_root.to_ssz(),
                encode_state_value(&BeaconState::Lean(anchor_state.clone())),
            )];
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

        info!(%anchor_state_root, %anchor_block_root, anchor_slot, "Initialized store");

        Ok(Self::from_parts(
            backend,
            runtime_config,
            Chain::Lean,
            anchor_slot,
        ))
    }

    /// Initialize an empty beacon-chain store.
    ///
    /// Writes only what every later read assumes exists: the format version,
    /// the chain tag, the config, a zero clock and zeroed checkpoints. The
    /// anchor block and state are written by the beacon fork choice's own
    /// `get_forkchoice_store`, which is where the specification's construction
    /// rules live and which needs beacon helpers this crate cannot call.
    ///
    /// `anchor_slot` is that caller's `anchor_state.slot()`, taken as its own
    /// argument rather than read off `anchor_checkpoint`: the stored checkpoint
    /// is epoch-denominated, so its slot is the epoch's *start*, which sits
    /// below the anchor's own slot whenever the anchor is not itself a boundary
    /// block.
    pub fn init_beacon(
        backend: Arc<dyn StorageBackend>,
        genesis_time: u64,
        config: Config,
        anchor_block_root: H256,
        anchor_checkpoint: Checkpoint,
        anchor_slot: u64,
    ) -> Self {
        let runtime_config = Arc::new(Config {
            genesis_time,
            ..config
        });

        let zero_checkpoint = BeaconCheckpoint::default();
        // `KEY_HEAD`, `KEY_LATEST_JUSTIFIED` and `KEY_LATEST_FINALIZED` are
        // seeded here for the same reason `init_store` seeds them on a lean
        // directory: `update_checkpoints` reads the head it is moving *from*
        // and the finalized slot it is advancing *past*, so both chains have
        // to start with those rows present rather than have that one writer
        // grow an absent-key branch.
        let metadata_entries = vec![
            (KEY_DB_VERSION.to_vec(), DB_VERSION.to_ssz()),
            (KEY_CHAIN.to_vec(), vec![Chain::Beacon.selector()]),
            (KEY_PRESET.to_vec(), vec![Preset::ACTIVE.selector()]),
            // Genesis rather than zero, for the reason `init_store` gives.
            // `get_forkchoice_store` overwrites this immediately with the
            // anchor's own time; the seed matters only for the window before
            // it does.
            (KEY_TIME.to_vec(), runtime_config.genesis_time_ms().to_ssz()),
            (KEY_CONFIG.to_vec(), runtime_config.to_ssz()),
            (KEY_HEAD.to_vec(), anchor_block_root.to_ssz()),
            (KEY_LATEST_JUSTIFIED.to_vec(), anchor_checkpoint.to_ssz()),
            (KEY_LATEST_FINALIZED.to_vec(), anchor_checkpoint.to_ssz()),
            (
                KEY_BEACON_UNREALIZED_JUSTIFIED.to_vec(),
                zero_checkpoint.to_ssz(),
            ),
            (
                KEY_BEACON_UNREALIZED_FINALIZED.to_vec(),
                zero_checkpoint.to_ssz(),
            ),
            (KEY_ANCHOR_SLOT.to_vec(), anchor_slot.to_ssz()),
        ];

        let mut batch = backend.begin_write().expect("write batch");
        batch
            .put_batch(Table::Metadata, metadata_entries)
            .expect("put metadata");
        batch.commit().expect("commit");

        info!(genesis_time, anchor_slot, "Initialized beacon store");

        Self::from_parts(backend, runtime_config, Chain::Beacon, anchor_slot)
    }

    /// Assembles a `Store` from the fields that vary across constructors,
    /// filling in the rest with fresh, empty buffers shared by every bootstrap
    /// path: [`Store::init_store`] (used by both [`Store::from_anchor_state`]
    /// and [`Store::get_forkchoice_store`]), [`Store::init_beacon`] and
    /// [`Store::from_db_state`].
    ///
    /// `anchor_slot` is the one field the resume path cannot derive, which is
    /// why the two `init_*` paths persist it under [`KEY_ANCHOR_SLOT`] for
    /// [`Store::from_db_state`] to read back.
    fn from_parts(
        backend: Arc<dyn StorageBackend>,
        config: Arc<Config>,
        chain: Chain,
        anchor_slot: u64,
    ) -> Self {
        let state_cache = new_state_cache();
        let pending_states = Arc::new(PendingStates::default());
        let state_writer = Arc::new(StateWriterHandle::spawn(
            backend.clone(),
            chain,
            state_cache.clone(),
            pending_states.clone(),
        ));
        Self {
            backend,
            config,
            chain,
            anchor_slot,
            new_payloads: Arc::new(Mutex::new(PayloadBuffer::new(NEW_PAYLOAD_CAP))),
            known_payloads: Arc::new(Mutex::new(PayloadBuffer::new(AGGREGATED_PAYLOAD_CAP))),
            fork_choice: Default::default(),
            gossip_signatures: Arc::new(Mutex::new(GossipSignatureBuffer::new(
                GOSSIP_SIGNATURE_CAP,
            ))),
            state_cache,
            pending_states,
            beacon: Default::default(),
            state_writer,
        }
    }

    // ============ Metadata Helpers ============

    /// Reads an SSZ metadata value that the store's bootstrap path guarantees
    /// exists.
    ///
    /// Names the key on the way out: the lean and beacon paths seed different
    /// key sets, so an absent key means the wrong chain's accessor was reached
    /// on this store, and the key is what says which one.
    pub(crate) fn get_metadata<T: SszDecode>(&self, key: &[u8]) -> T {
        let view = self.backend.begin_read().expect("read view");
        let bytes = view
            .get(Table::Metadata, key)
            .expect("get")
            .unwrap_or_else(|| {
                panic!(
                    "metadata key {:?} is absent on a {:?} store",
                    String::from_utf8_lossy(key),
                    self.chain
                )
            });
        T::from_ssz_bytes(&bytes).expect("valid encoding")
    }

    pub(crate) fn set_metadata<T: SszEncode>(&self, key: &[u8], value: &T) {
        self.set_metadata_batch(&[(key, value)]);
    }

    /// Writes several SSZ metadata values under one commit.
    ///
    /// [`Store::set_metadata`] opens and commits a batch per call, so a caller
    /// advancing a set of related keys through it would pay a commit each and
    /// leave a window in which only some of them had landed. An empty slice
    /// writes nothing rather than committing an empty batch, so a caller can
    /// pass only the values that actually changed.
    pub(crate) fn set_metadata_batch<T: SszEncode>(&self, values: &[(&[u8], &T)]) {
        if values.is_empty() {
            return;
        }
        let mut batch = self.backend.begin_write().expect("write batch");
        let entries = values
            .iter()
            .map(|(key, value)| (key.to_vec(), value.to_ssz()))
            .collect();
        batch
            .put_batch(Table::Metadata, entries)
            .expect("put metadata");
        batch.commit().expect("commit");
    }

    // ============ Time ============

    /// The store clock, as a UNIX timestamp in milliseconds. One row, one unit,
    /// both chains.
    ///
    /// Named for its unit because the beacon specification's `Store.time` is
    /// the same quantity in seconds, and the two would otherwise be one
    /// unmarked factor of a thousand apart at every call site. A caller that
    /// wants the specification's number divides; see
    /// [`Self::ms_since_genesis`] for the callers that want an offset instead.
    pub fn time_ms(&self) -> Result<u64, Error> {
        Ok(self.get_metadata(KEY_TIME))
    }

    /// Sets the store clock. See [`Self::time_ms`] for the unit.
    pub fn set_time_ms(&mut self, time_ms: u64) -> Result<(), Error> {
        self.set_metadata(KEY_TIME, &time_ms);
        Ok(())
    }

    /// How far past genesis the store clock reads, in milliseconds.
    ///
    /// The base of both derived clocks below, and the one place the genesis
    /// subtraction and its saturation are written. Saturates rather than
    /// wrapping: a store seeded at genesis never reads earlier, but an
    /// externally supplied anchor time can.
    ///
    /// Public because it is also what a caller placing a moment *within* the
    /// current slot wants: `ms_since_genesis() % slot_duration_ms` is how far
    /// into its slot the clock reads, which the beacon reorg and
    /// block-timeliness rules compare against their basis-point deadlines.
    pub fn ms_since_genesis(&self) -> u64 {
        self.time_ms()
            .expect("store time exists")
            .saturating_sub(self.config.genesis_time_ms())
    }

    /// How many intervals have elapsed since genesis, each a fifth of the
    /// configured slot.
    ///
    /// Derived from [`Self::time_ms`], not stored: it is the same clock read on
    /// a finer grid, and a second row would be a second thing to keep in step.
    /// This is the grid lean's `on_tick` steps through, running a duty per
    /// step, and the one lean's fork-choice fixtures report.
    ///
    /// The slot is `intervals_since_genesis() / INTERVALS_PER_SLOT` and the
    /// interval within it is the remainder; the former agrees with
    /// [`Self::current_slot`] by construction, since both divide the same
    /// millisecond offset.
    ///
    /// Meaningful on lean only, but not gated: a beacon directory shares the
    /// row this reads, so the answer is well-defined there and simply names a
    /// grid that chain does not schedule on.
    pub fn intervals_since_genesis(&self) -> u64 {
        self.ms_since_genesis() / self.config.milliseconds_per_interval()
    }

    /// The slot the store clock falls in, on either chain.
    ///
    /// Divides by [`Config::slot_duration_ms`] rather than
    /// [`Config::seconds_per_slot`] so a cadence that is not a whole number of
    /// seconds still lands on the right slot: `Config::lean` derives
    /// `seconds_per_slot` by truncating the millisecond value, so for lean the
    /// millisecond field is the authoritative one. The two agree wherever
    /// `slot_duration_ms == seconds_per_slot * 1000`, which every beacon
    /// configuration holds to.
    pub fn current_slot(&self) -> u64 {
        self.ms_since_genesis() / self.config.slot_duration_ms
    }

    // ============ Config ============

    /// The node's runtime configuration.
    ///
    /// Returns an owned handle rather than a reference so the caller can hold
    /// it across the `&mut Store` that every beacon fork-choice entry point
    /// takes alongside it; cloning the `Arc` is one atomic increment, not a
    /// copy of the fork schedule.
    ///
    /// Infallible: fixed at bootstrap and cached, so this never reads the
    /// backend.
    pub fn config(&self) -> Arc<Config> {
        Arc::clone(&self.config)
    }

    /// Which consensus protocol this data directory holds.
    ///
    /// Infallible for the same reason [`Store::config`] is: fixed at bootstrap
    /// and cached, so this never reads the backend.
    pub fn chain(&self) -> Chain {
        self.chain
    }

    /// Refuse a lean-only accessor on a beacon store, naming the accessor.
    ///
    /// `Table::BlockHeaders` holds a different shape per chain: a lean
    /// directory a [`BlockHeader`], a beacon one the whole signed block. An
    /// accessor that decodes lean's own types out of it therefore answers
    /// nothing on a beacon directory, and left unchecked it fails inside SSZ
    /// with a length mismatch that names neither the accessor nor the caller.
    ///
    /// A P2P handler reached one through a peer's request on 2026-09-11 and
    /// took the whole swarm actor down with exactly that error, so the check
    /// is here rather than left to every call site to remember. Callers that
    /// need these fields on either chain have
    /// [`block_entry`](Self::block_entry) and
    /// [`block_slot_and_state_root`](Self::block_slot_and_state_root), which
    /// decode per chain.
    #[cold]
    #[track_caller]
    fn lean_only(accessor: &str) -> ! {
        panic!("{accessor} is lean-only and was called on a beacon store");
    }

    // ============ Head ============

    /// Returns the current head block root.
    pub fn head(&self) -> Result<H256, Error> {
        Ok(self.get_metadata(KEY_HEAD))
    }

    // ============ Safe Target ============

    /// Returns the safe target block root for attestations.
    pub fn safe_target(&self) -> Result<H256, Error> {
        Ok(self.get_metadata(KEY_SAFE_TARGET))
    }

    /// Sets the safe target block root.
    pub fn set_safe_target(&mut self, safe_target: H256) -> Result<(), Error> {
        self.set_metadata(KEY_SAFE_TARGET, &safe_target);
        Ok(())
    }

    // ============ Checkpoints ============

    /// Returns the latest justified checkpoint.
    pub fn latest_justified(&self) -> Result<Checkpoint, Error> {
        Ok(self.get_metadata(KEY_LATEST_JUSTIFIED))
    }

    /// Returns the latest finalized checkpoint.
    pub fn latest_finalized(&self) -> Result<Checkpoint, Error> {
        Ok(self.get_metadata(KEY_LATEST_FINALIZED))
    }

    /// The root of the finalized state, whichever chain this store holds.
    ///
    /// Reads [`KEY_LATEST_FINALIZED`] without asking which chain it is on:
    /// both keep their finalized checkpoint there, and the epoch-to-slot
    /// conversion the beacon accessors apply
    /// ([`Store::beacon_finalized_checkpoint`]) touches only the slot, never
    /// the root. So a caller that wants just the anchor, such as a resume
    /// path's genesis check, needs no chain-specific branch at all.
    ///
    /// Every initialized directory has one: `init_store` anchors at the
    /// genesis or checkpoint block, and `init_beacon` takes its anchor as an
    /// argument and writes it in the same atomic batch as the rest of the
    /// metadata. A zero root is therefore not a state either bootstrap path
    /// can produce; see [`Error::UnanchoredDirectory`] for what it takes to
    /// reach one.
    pub fn finalized_state_root(&self) -> Result<H256, Error> {
        let root = self.latest_finalized()?.root;
        if root.is_zero() {
            return Err(Error::UnanchoredDirectory);
        }
        Ok(root)
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
        let old_finalized_slot = self.latest_finalized()?.slot;
        let old_head = self.head()?;
        let (block_root_deletes, block_root_entries) =
            self.block_root_index_changes(old_head, checkpoints.head)?;

        let mut entries = vec![(KEY_HEAD.to_vec(), checkpoints.head.to_ssz())];

        if let Some(justified) = checkpoints.justified {
            entries.push((KEY_LATEST_JUSTIFIED.to_vec(), justified.to_ssz()));
        }

        if let Some(finalized) = checkpoints.finalized {
            entries.push((KEY_LATEST_FINALIZED.to_vec(), finalized.to_ssz()));
        }

        let mut batch = self.backend.begin_write().expect("write batch");
        batch.put_batch(Table::Metadata, entries).expect("put");
        batch
            .delete_batch(Table::BlockRoots, block_root_deletes)
            .expect("delete old canonical block roots");
        batch
            .put_batch(Table::BlockRoots, block_root_entries)
            .expect("put canonical block roots");
        batch.commit().expect("commit");

        // Lightweight pruning that should happen immediately on finalization advance:
        // live chain index, signatures, and attestation data. These are cheap and
        // affect fork choice correctness (live chain) or attestation processing.
        // Heavy state/block pruning is deferred to prune_old_data().
        //
        // Lean only, and deliberately so. The gossip-signature and aggregated
        // payload buffers hold lean attestations, which a beacon directory
        // never has, so those two would be no-ops. `prune_live_chain` would
        // not be: it drops every row below the finalized slot, but the beacon
        // fork choice walks *past* that boundary. `filter_block_tree` asks
        // `get_checkpoint_block` for the ancestor at the finalized epoch's
        // start slot, and `get_ancestor` keeps walking parents while their
        // slot exceeds the one asked for, so an empty start slot sends it to a
        // block strictly below the horizon. A missing row there is a hard
        // `SpecAssert`, not a degraded read, so beacon needs its own horizon
        // before it can prune at all.
        if self.chain == Chain::Lean
            && let Some(finalized) = checkpoints.finalized
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

    /// Prune finalized block proofs to keep proof storage bounded.
    ///
    /// State diffs, block headers, block bodies, and full-state snapshots are
    /// all retained for the full history and are never pruned. Only proofs
    /// of finalized blocks older than the pruning window are removed.
    ///
    /// This is separated from `update_checkpoints` so callers can defer heavy
    /// pruning until after a batch of blocks has been fully processed.
    pub fn prune_old_data(&mut self) -> Result<(), Error> {
        let finalized_slot = self
            .latest_finalized()
            .expect("Failed to get latest finalized checkpoint")
            .slot;
        let tip_slot = self
            .get_block_header(&self.head().expect("Failed to get head block root"))
            .map_or(finalized_slot, |header| {
                header.expect("Failed to get block header").slot
            });
        let pruned_below_slot = self
            .prune_old_block_proofs(finalized_slot, tip_slot)
            .expect("prune old block proofs");
        if pruned_below_slot > 0 {
            info!(pruned_below_slot, "Pruned old finalized block proofs");
        }
        Ok(())
    }

    // ============ Blocks ============

    /// `BlockRoots` index diff between the branch ending at `old_root` and the one
    /// ending at `new_root`: slot keys to delete (canonical only on the old branch)
    /// and slot -> root entries to write (canonical on the new branch).
    ///
    /// Both branches must be walkable down to their common ancestor. A root with no
    /// header, genesis' zero parent included, means they have none in common, and
    /// yields [`Error::UnexpectedMissingBlockHeader`] instead of a partial diff.
    fn block_root_index_changes(
        &self,
        mut old_root: H256,
        mut new_root: H256,
    ) -> Result<BlockRootIndexChanges, Error> {
        let mut deletes = Vec::new();
        let mut entries = Vec::new();

        // The head did not move, so the canonical index cannot have changed.
        // Answered before the two reads below because a checkpoint-only
        // advance passes the head through unchanged, and on the beacon arm
        // that is the common case rather than an edge one.
        if old_root == new_root {
            return Ok((deletes, entries));
        }

        // Through `block_entry` rather than `get_block_header`: the walk wants
        // only a slot and a parent root, which both chains' header rows carry,
        // so this diff is the same computation on either.
        let mut old_entry = self
            .block_entry(&old_root)
            .ok_or(Error::UnexpectedMissingBlockHeader(old_root))?;
        let mut new_entry = self
            .block_entry(&new_root)
            .ok_or(Error::UnexpectedMissingBlockHeader(new_root))?;

        // Walk both branches back toward their common ancestor, until we find the common ancestor.
        while old_root != new_root {
            let (old_slot, old_parent) = old_entry;
            let (new_slot, new_parent) = new_entry;
            if old_slot < new_slot {
                entries.push((encode_block_root_key(new_slot), new_root.to_ssz()));
                new_root = new_parent;
                new_entry = self
                    .block_entry(&new_root)
                    .ok_or(Error::UnexpectedMissingBlockHeader(new_root))?;
            } else {
                deletes.push(encode_block_root_key(old_slot));
                old_root = old_parent;
                old_entry = self
                    .block_entry(&old_root)
                    .ok_or(Error::UnexpectedMissingBlockHeader(old_root))?;
            }
        }

        Ok((deletes, entries))
    }

    /// Get block data for fork choice: root -> (slot, parent_root).
    ///
    /// Iterates only the LiveChain table, avoiding Block deserialization.
    /// Returns only non-finalized blocks, automatically pruned on finalization.
    pub fn get_live_chain(&self) -> Result<HashMap<H256, (u64, H256)>, Error> {
        let view = self.backend.begin_read().expect("read view");
        Ok(view
            .prefix_iterator(Table::LiveChain, &[])
            .expect("iterator")
            .filter_map(|res| res.ok())
            .map(|(k, v)| {
                let (slot, root) = decode_slot_root_key(&k);
                let parent_root = H256::from_ssz_bytes(&v).expect("valid parent_root");
                (root, (slot, parent_root))
            })
            .collect())
    }

    /// Return the highest slot in the live chain.
    pub fn max_live_chain_slot(&self) -> Result<Option<u64>, Error> {
        let view = self.backend.begin_read().expect("read view");
        Ok(view
            .prefix_iterator(Table::LiveChain, &[])
            .expect("iterator")
            .filter_map(Result::ok)
            .map(|(key, _)| decode_slot_root_key(&key).0)
            .max())
    }

    /// Get all known block roots as HashSet.
    ///
    /// Useful for checking block existence without deserializing.
    pub fn get_block_roots(&self) -> Result<HashSet<H256>, Error> {
        let view = self.backend.begin_read().expect("read view");
        Ok(view
            .prefix_iterator(Table::LiveChain, &[])
            .expect("iterator")
            .filter_map(|res| res.ok())
            .map(|(k, _)| {
                let (_, root) = decode_slot_root_key(&k);
                root
            })
            .collect())
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

    /// Writes one live-chain index row.
    ///
    /// `insert_signed_block` writes these as part of a block's own batch; this
    /// is the standalone form, for tests and for any caller that needs to put a
    /// row back.
    pub fn insert_live_chain_entry(&mut self, slot: u64, root: H256, parent_root: H256) {
        let entries = vec![(encode_slot_root_key(slot, &root), parent_root.to_ssz())];
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .put_batch(Table::LiveChain, entries)
            .expect("put live chain entry");
        batch.commit().expect("commit");
    }

    /// Deletes the named live-chain index rows.
    ///
    /// Unlike [`prune_live_chain`](Self::prune_live_chain), which drops a whole
    /// slot range below a horizon and is lean-only, this removes exactly the
    /// `(slot, root)` pairs given. That is what invalidating an execution
    /// payload needs: the roots to drop are a subtree, not a slot window, and
    /// the blocks either side of them at the same slots must survive.
    ///
    /// Dropping the row is the whole of "remove this block from fork choice":
    /// [`block_index`](Self::block_index) is the only source
    /// `filter_block_tree`, `compute_weights` and `get_head` read, so a root
    /// with no row contributes no weight to any ancestor and can never be
    /// walked to.
    ///
    /// The block and its state stay in their own tables. Nothing reads them
    /// once the index row is gone, and keeping them means an operator can still
    /// inspect what was rejected.
    pub fn delete_live_chain_entries(&mut self, entries: &[(u64, H256)]) {
        if entries.is_empty() {
            return;
        }
        let keys: Vec<Vec<u8>> = entries
            .iter()
            .map(|(slot, root)| encode_slot_root_key(*slot, root))
            .collect();
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .delete_batch(Table::LiveChain, keys)
            .expect("delete live chain entries");
        batch.commit().expect("commit");
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

    /// Prune proofs of old finalized blocks, keeping a recent window.
    ///
    /// Proofs within [`BLOCK_PROOF_PRUNING_RANGE`] slots of `tip_slot` are
    /// always kept, as are all proofs of non-finalized blocks. Concretely,
    /// with `cutoff = tip_slot - BLOCK_PROOF_PRUNING_RANGE`:
    ///
    /// - if `cutoff <= finalized_slot` (healthy finality): delete proofs for
    ///   `slot < cutoff` (entirely within finalized history);
    /// - otherwise (the non-finalized range exceeds the window): prune nothing,
    ///   since pruning up to `cutoff` would touch non-finalized blocks.
    ///
    /// Headers and bodies are always retained. Finalized blocks can never be
    /// reverted, so their proofs are not needed for fork choice, re-org
    /// safety, or re-aggregation once outside the window.
    ///
    /// Returns the exclusive slot below which proofs were dropped, or 0 when
    /// nothing was pruned. This is a range delete, so the count of removed keys
    /// is not known without reading the table back.
    pub fn prune_old_block_proofs(
        &mut self,
        finalized_slot: u64,
        tip_slot: u64,
    ) -> Result<u64, Error> {
        let cutoff = tip_slot.saturating_sub(BLOCK_PROOF_PRUNING_RANGE);
        // Only prune when the whole window is finalized; never touch
        // non-finalized proofs. A zero cutoff covers nothing.
        if cutoff > finalized_slot || cutoff == 0 {
            return Ok(0);
        }

        // Keys are slot||root in big-endian slot order, so the cutoff's bare
        // slot prefix is an exact upper bound: keys below the cutoff sort
        // before it, and keys at the cutoff sort after it (they extend it with
        // a root). A single range delete drops them all without reading the
        // table (and without walking the tombstones left by earlier prunes).
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .delete_range(
                Table::BlockProof,
                &0u64.to_be_bytes(),
                &cutoff.to_be_bytes(),
            )
            .expect("delete finalized block proofs");
        batch.commit().expect("commit");

        Ok(cutoff)
    }

    /// Get the block header by root.
    pub fn get_block_header(&self, root: &H256) -> Result<Option<BlockHeader>, Error> {
        if self.chain != Chain::Lean {
            Self::lean_only("Store::get_block_header");
        }
        let view = self.backend.begin_read().expect("read view");
        Ok(view
            .get(Table::BlockHeaders, &root.to_ssz())
            .expect("get")
            .map(|bytes| BlockHeader::from_ssz_bytes(&bytes).expect("valid header")))
    }

    // ============ Signed Blocks ============

    /// Insert a block as pending (parent state not yet available).
    ///
    /// One method for both chains, mirroring [`insert_signed_block`](Self::insert_signed_block):
    /// the lean arm stores block data in `BlockHeaders`/`BlockBodies`/`BlockProof`,
    /// the beacon arm stores the whole signed block in a single `BlockHeaders`
    /// row. Neither arm writes to `LiveChain`, which is the one and only
    /// difference from `insert_signed_block`: that omission is exactly what
    /// keeps a pending block invisible to fork choice until its parent
    /// arrives and it is re-inserted as admitted. Lean's proof data
    /// (~3KB+ per block) is persisted to disk in the meantime rather than
    /// held in memory.
    ///
    /// When the block is later processed via [`insert_signed_block`](Self::insert_signed_block),
    /// the same keys are overwritten (idempotent) and a `LiveChain` entry is added.
    ///
    /// Unlike `insert_signed_block`, this never calls
    /// `record_known_attestation_votes`: that call records votes carried by
    /// blocks fork choice has actually admitted, and a pending block is not
    /// admitted.
    pub fn insert_pending_block(
        &mut self,
        root: H256,
        block: SignedBeaconBlock,
    ) -> Result<(), Error> {
        let mut batch = self.backend.begin_write().expect("write batch");

        match block {
            SignedBeaconBlock::Lean(signed_block) => {
                write_signed_block(batch.as_mut(), &root, signed_block);
            }
            beacon_block => {
                // The whole signed block, in one row, through the same
                // `write_beacon_block` `insert_signed_block`'s beacon arm
                // uses: no `BlockBodies` row (a beacon block has no
                // header/body split) and no `BlockProof` row (its signature
                // lives inside the block, not in a separate proof blob).
                write_beacon_block(batch.as_mut(), &root, &beacon_block);
            }
        }

        // One commit for both arms, so the write stays atomic.
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
    ///
    /// One method for both chains, split inline rather than behind a per-chain
    /// helper: the two arms write different tables, and that difference is
    /// exactly what a reader of this function needs to see. Because a beacon
    /// [`Root`](ethlambda_types::beacon::primitives::Root) is already [`H256`],
    /// there is one key type shared by both arms and nothing to bridge.
    pub fn insert_signed_block(
        &mut self,
        root: H256,
        block: SignedBeaconBlock,
    ) -> Result<(), Error> {
        let mut batch = self.backend.begin_write().expect("write batch");

        // The lean arm's post-commit attestation-vote recording has nothing to
        // do for a beacon block, which carries no lean attestations, so the
        // decision is handed back out of the match rather than run
        // unconditionally after the commit.
        let lean_block = match block {
            SignedBeaconBlock::Lean(signed_block) => {
                let block = write_signed_block(batch.as_mut(), &root, signed_block);

                let index_entries = vec![(
                    encode_slot_root_key(block.slot, &root),
                    block.parent_root.to_ssz(),
                )];
                batch
                    .put_batch(Table::LiveChain, index_entries)
                    .expect("put non-finalized chain index");

                Some(block)
            }
            beacon_block => {
                let slot = beacon_block.slot();
                let parent_root = beacon_block.parent_root();

                // The whole signed block, in one row. `BlockHeaders` holds a
                // full lean `BlockHeader` on a lean directory and a whole
                // beacon block here; the two shapes never coexist in one
                // table, since a data directory holds one chain for its whole
                // life (see `Chain`).
                //
                // `BlockBodies` is not written at all on this arm. Lean splits
                // header from body so a header-only query need not pay for the
                // body, and so an empty body can be left out entirely; a
                // beacon block has no such empty case and nothing reads a
                // beacon header without its block, so a second row would only
                // add a write and a way for the two to disagree.
                write_beacon_block(batch.as_mut(), &root, &beacon_block);

                // `BlockRoots` is not written here, on either chain: it
                // indexes the canonical branch, which import order does not
                // determine, so `update_checkpoints` maintains it as the head
                // moves. `BlockProof` is lean's alone, since a beacon block
                // carries its signature inside the block rather than in a
                // separate proof blob.
                let index_entries = vec![(encode_slot_root_key(slot, &root), parent_root.to_ssz())];
                batch
                    .put_batch(Table::LiveChain, index_entries)
                    .expect("put non-finalized chain index");

                None
            }
        };

        // One commit for both arms, so the write stays atomic: a half-written
        // block would be visible to the LiveChain scan without being
        // decodable from BlockHeaders/BlockBodies.
        batch.commit().expect("commit");

        if let Some(block) = lean_block {
            self.record_known_attestation_votes(&block.body.attestations);
        }
        Ok(())
    }

    // ============ Beacon Checkpoints ============

    /// Returns the beacon store's justified checkpoint.
    ///
    /// Reads the same slot-denominated [`KEY_LATEST_JUSTIFIED`] row lean uses
    /// and converts back. The conversion is exact in both directions: a
    /// checkpoint's epoch is stored as that epoch's own start slot, so
    /// dividing recovers it, and this pair of helpers is the only place either
    /// chain's checkpoint changes units.
    pub fn beacon_justified_checkpoint(&self) -> BeaconCheckpoint {
        Self::as_beacon_checkpoint(
            self.latest_justified()
                .expect("justified checkpoint exists"),
        )
    }

    /// Returns the beacon store's finalized checkpoint. See
    /// [`Store::beacon_justified_checkpoint`] for the unit conversion.
    pub fn beacon_finalized_checkpoint(&self) -> BeaconCheckpoint {
        Self::as_beacon_checkpoint(
            self.latest_finalized()
                .expect("finalized checkpoint exists"),
        )
    }

    /// A stored, slot-denominated [`Checkpoint`] read as a beacon one.
    fn as_beacon_checkpoint(checkpoint: Checkpoint) -> BeaconCheckpoint {
        BeaconCheckpoint {
            epoch: checkpoint.slot / SLOTS_PER_EPOCH,
            root: checkpoint.root,
        }
    }

    /// A beacon checkpoint in the slot-denominated form both chains store.
    ///
    /// An epoch is stored as its own start slot, which is what makes
    /// [`Store::as_beacon_checkpoint`] recover it exactly, and what lets the
    /// shared finalization-advance comparison read a beacon checkpoint
    /// without a second rule for it.
    pub fn beacon_checkpoint_as_stored(checkpoint: BeaconCheckpoint) -> Checkpoint {
        Checkpoint {
            root: checkpoint.root,
            slot: checkpoint.epoch * SLOTS_PER_EPOCH,
        }
    }

    /// Returns the beacon store's unrealized justified checkpoint.
    pub fn beacon_unrealized_justified_checkpoint(&self) -> BeaconCheckpoint {
        self.get_metadata(KEY_BEACON_UNREALIZED_JUSTIFIED)
    }

    /// Sets the beacon store's unrealized justified checkpoint.
    ///
    /// No monotonicity check: the specification's own
    /// `update_unrealized_checkpoints` owns that rule, and this is a plain
    /// write underneath it.
    pub fn set_beacon_unrealized_justified_checkpoint(&mut self, checkpoint: BeaconCheckpoint) {
        self.set_metadata(KEY_BEACON_UNREALIZED_JUSTIFIED, &checkpoint);
    }

    /// Returns the beacon store's unrealized finalized checkpoint.
    pub fn beacon_unrealized_finalized_checkpoint(&self) -> BeaconCheckpoint {
        self.get_metadata(KEY_BEACON_UNREALIZED_FINALIZED)
    }

    /// Sets the beacon store's unrealized finalized checkpoint. See
    /// [`Store::set_beacon_unrealized_justified_checkpoint`] for why there is
    /// no monotonicity check here either.
    pub fn set_beacon_unrealized_finalized_checkpoint(&mut self, checkpoint: BeaconCheckpoint) {
        self.set_metadata(KEY_BEACON_UNREALIZED_FINALIZED, &checkpoint);
    }

    /// Advances whichever of the unrealized justified and finalized
    /// checkpoints is `Some`, under one commit.
    ///
    /// The fork choice moves the two as a pair, so they are written as one:
    /// separate commits leave a window in which one has advanced and the
    /// other has not. Passing `None` for one leaves that key alone, and
    /// `None` for both writes nothing at all.
    ///
    /// The *realized* pair has no counterpart here: it goes through
    /// [`Store::update_checkpoints`], the writer both chains share.
    pub fn set_beacon_unrealized_checkpoints(
        &mut self,
        justified: Option<BeaconCheckpoint>,
        finalized: Option<BeaconCheckpoint>,
    ) {
        let mut values: Vec<(&[u8], &BeaconCheckpoint)> = Vec::with_capacity(2);
        if let Some(justified) = justified.as_ref() {
            values.push((KEY_BEACON_UNREALIZED_JUSTIFIED, justified));
        }
        if let Some(finalized) = finalized.as_ref() {
            values.push((KEY_BEACON_UNREALIZED_FINALIZED, finalized));
        }
        self.set_metadata_batch(&values);
    }

    // ============ Beacon Head ============

    /// The beacon fork-choice head as `(slot, root)`, or `None` if the head
    /// row names a block this store has no header for.
    ///
    /// Derived rather than stored: the head itself is [`KEY_HEAD`], the row
    /// both chains keep and [`Store::update_checkpoints`] is the single writer
    /// of, and the slot comes from the head's own
    /// [`block_entry`](Self::block_entry). A second head row denominated in
    /// `slot || root` would be a value that could drift from the first.
    pub fn beacon_head(&self) -> Option<(u64, H256)> {
        let root = self.head().expect("head block exists");
        let (slot, _) = self.block_entry(&root)?;
        Some((slot, root))
    }

    /// `root`'s slot and parent root, without decoding its body.
    ///
    /// The two chains keep different shapes in `Table::BlockHeaders`: a lean
    /// directory a full [`BlockHeader`], a beacon one the whole signed block.
    /// Both answer this question, so the decode is what varies and the caller
    /// does not have to care which chain it is on. That is what lets the
    /// fork-choice tree walk and the `BlockRoots` index diff be written once
    /// for both.
    ///
    /// On the beacon arm this decodes the whole block to reach two fields.
    /// Callers walking a chain of them should build [`Store::block_index`]
    /// once instead, which reads the same links out of `LiveChain`.
    pub fn block_entry(&self, root: &H256) -> Option<(u64, H256)> {
        self.block_fields(root)
            .map(|(slot, parent_root, _)| (slot, parent_root))
    }

    /// `root`'s slot and state root, without decoding its body on lean.
    ///
    /// The sibling of [`block_entry`](Self::block_entry), which answers the
    /// parent-root question instead, and chain-generic for the same reason:
    /// a lean directory keeps a [`BlockHeader`] in `Table::BlockHeaders` and a
    /// beacon one the whole signed block, so the decode is what varies and the
    /// caller does not have to know which chain it is on. On the beacon arm
    /// this decodes the whole block to reach two fields.
    ///
    /// Both fields come out of one read, so a caller emitting them together
    /// cannot pair a slot with a state root from a different block. That is
    /// what the chain-event emission needs, and why it does not read them
    /// through two accessors.
    pub fn block_slot_and_state_root(&self, root: &H256) -> Option<(u64, H256)> {
        self.block_fields(root)
            .map(|(slot, _, state_root)| (slot, state_root))
    }

    /// `root`'s slot, parent root and state root: the one read and the one
    /// per-chain decode that [`block_entry`](Self::block_entry) and
    /// [`block_slot_and_state_root`](Self::block_slot_and_state_root) project
    /// out of.
    ///
    /// One decode rather than one per accessor, so the `Table::BlockHeaders`
    /// row shape is stated once and the two public accessors cannot disagree
    /// about which block a row is. Returning all three costs nothing: every
    /// field is already in hand once the row is decoded.
    fn block_fields(&self, root: &H256) -> Option<(u64, H256, H256)> {
        let view = self.backend.begin_read().expect("read view");
        let bytes = view
            .get(Table::BlockHeaders, &root.to_ssz())
            .expect("get")?;
        Some(match self.chain {
            Chain::Lean => {
                let header = BlockHeader::from_ssz_bytes(&bytes).expect("valid header");
                (header.slot, header.parent_root, header.state_root)
            }
            Chain::Beacon => {
                let block = decode_beacon_block_value(&bytes);
                (block.slot(), block.parent_root(), block.state_root())
            }
        })
    }

    /// Whether a block is stored under `root`.
    pub fn has_block(&self, root: &H256) -> bool {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::BlockHeaders, &root.to_ssz())
            .expect("get")
            .is_some()
    }

    /// Every stored beacon block as `root -> (slot, parent_root)`.
    ///
    /// Built once per tree walk and passed down rather than re-read per hop:
    /// `get_weight` calls `get_ancestor` once per active validator, so a point
    /// lookup per hop would multiply a scan the specification already writes
    /// as naive by a backend round trip.
    ///
    /// The same `LiveChain` scan lean's fork choice reads through
    /// [`Store::get_live_chain`], under the name the beacon specification uses
    /// and without the `Result`: the beacon fork choice's error type lives in
    /// `ethlambda-types` and cannot name a storage error, like the rest of the
    /// scratch accessors below.
    pub fn block_index(&self) -> HashMap<H256, (u64, H256)> {
        self.get_live_chain().expect("live chain scan")
    }

    /// Get a block (header + body, no signatures) by root.
    ///
    /// Unlike [`get_signed_block`](Self::get_signed_block), this works for the
    /// genesis block, which has no signature entry.
    pub fn get_block(&self, root: &H256) -> Result<Option<Block>, Error> {
        if self.chain != Chain::Lean {
            Self::lean_only("Store::get_block");
        }
        let view = self.backend.begin_read().expect("read view");
        let key = root.to_ssz();

        let Some(header_bytes) = view.get(Table::BlockHeaders, &key).expect("get") else {
            return Ok(None);
        };
        let header = BlockHeader::from_ssz_bytes(&header_bytes).expect("valid header");

        let body = if header.body_root == *EMPTY_BODY_ROOT {
            BlockBody::default()
        } else {
            let Some(body_bytes) = view.get(Table::BlockBodies, &key).expect("get") else {
                return Ok(None);
            };
            BlockBody::from_ssz_bytes(&body_bytes).expect("valid body")
        };

        Ok(Some(Block::from_header_and_body(header, body)))
    }

    /// Get a signed block by root, as the fork it was written under.
    ///
    /// One method for both chains, split inline the same way
    /// [`insert_signed_block`](Self::insert_signed_block) is: dispatched on
    /// `self.chain` rather than by trial-decoding, since a data directory
    /// holds one chain for its whole life and the tag is authoritative.
    ///
    /// The lean arm returns None if the header or body (for non-empty
    /// bodies) is missing, or if the proof row is missing for any block
    /// other than the slot-0 anchor.
    ///
    /// Proofs are absent in two cases: genesis-style anchor blocks (no
    /// proposer ever signed them), and finalized blocks whose proofs were
    /// pruned by [`prune_old_block_proofs`](Self::prune_old_block_proofs).
    /// To keep BlocksByRoot symmetric with the fork-choice view for peers,
    /// synthesize an empty proof for the slot-0 anchor only; for any other slot
    /// a missing proof surfaces as `None` (a pruned finalized block can no
    /// longer be served with its proof) rather than as a fabricated block.
    pub fn get_signed_block(&self, root: &H256) -> Result<Option<SignedBeaconBlock>, Error> {
        let view = self.backend.begin_read().expect("read view");

        match self.chain {
            Chain::Lean => {
                Ok(Self::signed_block_from_view(view.as_ref(), root).map(SignedBeaconBlock::Lean))
            }
            Chain::Beacon => {
                let Some(bytes) = view.get(Table::BlockHeaders, &root.to_ssz()).expect("get")
                else {
                    return Ok(None);
                };

                let block = decode_beacon_block_value(&bytes);

                Ok(Some(block))
            }
        }
    }

    fn signed_block_from_view(view: &dyn StorageReadView, root: &H256) -> Option<SignedBlock> {
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
        let proof = match view.get(Table::BlockProof, &sig_key).expect("get") {
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

    /// Return the canonical block root at `slot`, or `None` when the canonical
    /// chain has no block there.
    ///
    /// The index is maintained atomically with the head in
    /// [`update_checkpoints`](Self::update_checkpoints), so it always describes
    /// the branch ending at the stored head. It can lag a freshly imported block
    /// that fork choice has not selected yet, but it never runs ahead of the head.
    ///
    /// A `None` covers two cases the index cannot tell apart: a slot the
    /// canonical chain skipped, and a slot below the anchor this store was
    /// bootstrapped from. Callers that use this to *reject* something must treat
    /// `None` as "unknown" rather than "not canonical".
    pub fn canonical_root_at_slot(&self, slot: u64) -> Result<Option<H256>, Error> {
        let view = self.backend.begin_read().expect("read view");
        Ok(view
            .get(Table::BlockRoots, &encode_block_root_key(slot))
            .expect("get block root")
            .map(|bytes| H256::from_ssz_bytes(&bytes).expect("valid block root")))
    }

    /// Return canonical signed blocks for the slot range `[start_slot, end_slot]`.
    ///
    /// Missing slots or blocks are skipped, which is what both chains'
    /// `BlocksByRange` wants: "In cases where a slot is empty for a given slot
    /// number, no block is returned."
    ///
    /// Canonical by construction rather than by filtering: `BlockRoots` holds
    /// one root per slot on the branch ending at the current head, maintained by
    /// [`update_checkpoints`](Self::update_checkpoints), so a sibling block at a
    /// slot the head does not descend from is never read. Blocks come back in
    /// ascending slot order because the loop walks the range in it.
    ///
    /// One method for both chains, split inline the same way
    /// [`get_signed_block`](Self::get_signed_block) is. The index walk above the
    /// split is identical: `BlockRoots` is written for either chain and keyed by
    /// slot alone, so only the read of the row it points at differs.
    pub fn get_signed_blocks_by_slot_range(
        &self,
        start_slot: u64,
        end_slot: u64,
    ) -> Result<Vec<SignedBeaconBlock>, Error> {
        let view = self.backend.begin_read().expect("read view");
        let mut blocks = Vec::new();
        for slot in start_slot..=end_slot {
            // Read the index through this range's own view rather than via
            // `canonical_root_at_slot`, which opens a fresh one per call: a
            // range must be served from a single snapshot so a head change
            // partway through cannot splice two branches into one response.
            let Some(root_bytes) = view
                .get(Table::BlockRoots, &encode_block_root_key(slot))
                .expect("get block root")
            else {
                continue;
            };
            let root = H256::from_ssz_bytes(&root_bytes).expect("valid block root");
            match self.chain {
                Chain::Lean => {
                    if let Some(block) = Self::signed_block_from_view(view.as_ref(), &root) {
                        blocks.push(SignedBeaconBlock::Lean(block));
                    }
                }
                // A beacon block is one row, so there is no equivalent of the
                // lean arm's "header found but proof pruned" `None`: the row is
                // there or the slot is skipped.
                Chain::Beacon => {
                    if let Some(bytes) = view.get(Table::BlockHeaders, &root.to_ssz()).expect("get")
                    {
                        blocks.push(decode_beacon_block_value(&bytes));
                    }
                }
            }
        }
        Ok(blocks)
    }

    // ============ States ============

    /// Returns the state for the given block root.
    ///
    /// One method for both chains, split inline the same way
    /// [`get_signed_block`](Self::get_signed_block) is: dispatched on
    /// `self.chain` rather than on the returned value's own shape, since a
    /// data directory holds one chain for its whole life and the tag is
    /// authoritative.
    ///
    /// The lookup order (cache, then the `pending_states` write-buffer, then
    /// the backend) and the per-chain reconstruction live on
    /// [`read_state`](crate::state_writer::read_state), which this calls
    /// directly rather than restating: one copy of the algorithm is one copy
    /// that can go stale.
    pub fn get_state(&self, root: &H256) -> Result<Option<Arc<BeaconState>>, Error> {
        read_state(
            self.backend.as_ref(),
            self.chain,
            &self.state_cache,
            &self.pending_states,
            root,
        )
    }

    /// The memoized state for `key`, if it is still resident.
    pub fn cached_state(&self, key: CacheKey) -> Option<Arc<BeaconState>> {
        self.state_cache.lock().unwrap().get(&key).cloned()
    }

    /// Memoizes `state` under `key`.
    ///
    /// Takes `&self`, not `&mut self`: the read-only fork-choice helpers derive
    /// on a miss and must be able to record the result. The interior mutex is
    /// what makes that sound, and it is why `checkpoint_state` and the helpers
    /// that reach it can stay `&Store`.
    pub fn cache_state(&self, key: CacheKey, state: Arc<BeaconState>) {
        self.state_cache.lock().unwrap().put(key, state);
    }

    /// Returns whether a state is available for the given block root.
    ///
    /// True if `pending_states` holds the state, a snapshot exists, or the
    /// state can be reconstructed from a diff.
    pub fn has_state(&self, root: &H256) -> Result<bool, Error> {
        // Same pending-before-backend order as `read_state`; see its doc for
        // why the backend never has to consult `pending_states` on its own.
        if self.pending_states.get(root).is_some() {
            return Ok(true);
        }
        let view = self.backend.begin_read().expect("read view");
        let key = root.to_ssz();
        let states = view.get(Table::States, &key).expect("get");
        let diffs = view.get(Table::StateDiffs, &key).expect("get");
        Ok(states.is_some() || diffs.is_some())
    }

    /// Persist a post-block state.
    ///
    /// One method for both chains, split inline: dispatched on `state`'s own
    /// variant rather than on `self.chain`, since the write already has a
    /// concrete value in hand (mirrors [`insert_signed_block`](Self::insert_signed_block),
    /// which dispatches its write the same way while its `get_signed_block`
    /// counterpart dispatches reads on `self.chain`).
    ///
    /// The byte-producing half of each arm, and the backend reads, the
    /// commit and the parent-bytes memo, all live on the background writer in
    /// [`crate::state_writer`]; this method only builds the request and hands
    /// it off.
    ///
    /// Lean: a parent-linked diff, snapshotting at anchors. Every non-genesis
    /// state gets a `StateDiffs` entry (never pruned, so the full state
    /// history is preserved). A full snapshot is written to `States` only
    /// when the block crosses a [`ForkName::snapshot_interval`] boundary;
    /// these anchors are never pruned and bound the reconstruction walk. The
    /// state is also inserted into the in-memory cache so the immediate next
    /// read (e.g. as a child block's parent state) is hot without
    /// reconstruction. The diff is built against the parent state, identified
    /// by the post-state's own `latest_block_header.parent_root` (the state
    /// transition sets it to the block's parent) and fetched via
    /// [`get_state`](Self::get_state). The parent was persisted when its own
    /// block was imported, so this read is normally a cache hit; a cold cache
    /// falls back to a snapshot read or a diff-chain reconstruction.
    ///
    /// Beacon: a byte-domain [`beacon_state_delta`](crate::beacon_state_delta)
    /// diff, snapshotting at anchors, the same shape as lean's but working in
    /// the SSZ byte domain rather than the field domain: a beacon validator
    /// registry breaks lean's [`StateDiff`](crate::state_diff::StateDiff)'s "`validators` never changes"
    /// assumption every epoch, so lean's diff cannot be reused as-is. The
    /// parent is identified the same way lean's is, off the post-state's own
    /// `latest_block_header.parent_root`, but its *encoded* bytes are what the
    /// delta is computed against; the writer thread's parent-bytes lookup
    /// (`StateWriter::encoded_parent_bytes`) explains how those are obtained
    /// without an extra encode round trip. The store's first-ever beacon
    /// state (a bootstrap or checkpoint-sync anchor) has no parent block on
    /// record, so it is always a snapshot regardless of the interval math:
    /// there is no base to diff against.
    ///
    /// The work itself happens on the writer thread; this call returns once
    /// the state is in the cache and the handoff buffer, which is what makes
    /// it readable before it is written. A full queue blocks here.
    ///
    /// # Panics
    ///
    /// If the writer thread has already died from a previous write's panic;
    /// see [`StateWriterHandle::send`](crate::state_writer::StateWriterHandle::send).
    /// The invariant that a child state's parent must already be persisted is
    /// still enforced, and still panics on violation, but on the writer
    /// thread now rather than in this call.
    pub fn insert_state(&mut self, root: H256, state: BeaconState) -> Result<(), Error> {
        let state = Arc::new(state);
        // Both the cache and the buffer take a handle to the same state. The
        // cache is the hot path for the immediate next read; the buffer is
        // what keeps the state readable if the cache evicts it before the
        // writer has committed. See `PendingStates`.
        self.cache_state(CacheKey::BlockState(root), state.clone());
        self.pending_states.insert(root, state.clone());
        crate::metrics::inc_state_write_queue_depth();
        self.state_writer.send(StateWriteRequest { root, state });
        Ok(())
    }

    // ============ Attestation Extraction ============

    fn should_replace_vote(existing: &AttestationData, candidate: &AttestationData) -> bool {
        candidate.slot > existing.slot
            || (candidate.slot == existing.slot
                && candidate.hash_tree_root() > existing.hash_tree_root())
    }

    fn record_vote(
        votes: &mut HashMap<u64, AttestationData>,
        validator_id: u64,
        data: &AttestationData,
    ) {
        let should_replace = votes
            .get(&validator_id)
            .is_none_or(|existing| Self::should_replace_vote(existing, data));
        if should_replace {
            votes.insert(validator_id, data.clone());
        }
    }

    fn record_known_attestation_votes(&self, attestations: &[AggregatedAttestation]) {
        let mut fork_choice = self.fork_choice.lock().unwrap();
        for attestation in attestations {
            for validator_id in validator_indices(&attestation.aggregation_bits) {
                Self::record_vote(
                    &mut fork_choice.known_votes,
                    validator_id,
                    &attestation.data,
                );
            }
        }
    }

    /// Extract per-validator latest attestations from known fork-choice votes.
    pub fn extract_latest_known_attestations(&self) -> HashMap<u64, AttestationData> {
        self.fork_choice.lock().unwrap().known_votes.clone()
    }

    /// Extract per-validator latest attestations from new (pending) payloads.
    pub fn extract_latest_new_attestations(&self) -> HashMap<u64, AttestationData> {
        self.fork_choice.lock().unwrap().new_votes.clone()
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
    ) -> HashMap<H256, (AttestationData, Vec<SingleMessageAggregate>)> {
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
    ) -> (Vec<SingleMessageAggregate>, Vec<SingleMessageAggregate>) {
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

    /// Batch-insert proofs into the known buffer.
    pub fn insert_known_aggregated_payloads_batch(
        &mut self,
        entries: Vec<(HashedAttestationData, SingleMessageAggregate)>,
    ) {
        let mut fork_choice = self.fork_choice.lock().unwrap();
        for (hashed, proof) in &entries {
            for validator_id in proof.participant_indices() {
                Self::record_vote(&mut fork_choice.known_votes, validator_id, hashed.data());
            }
        }
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
        proof: SingleMessageAggregate,
    ) {
        {
            let mut fork_choice = self.fork_choice.lock().unwrap();
            for validator_id in proof.participant_indices() {
                Self::record_vote(&mut fork_choice.new_votes, validator_id, hashed.data());
            }
        }
        self.new_payloads.lock().unwrap().push(hashed, proof);
    }

    /// Batch-insert proofs into the new buffer.
    pub fn insert_new_aggregated_payloads_batch(
        &mut self,
        entries: Vec<(HashedAttestationData, SingleMessageAggregate)>,
    ) {
        let mut fork_choice = self.fork_choice.lock().unwrap();
        for (hashed, proof) in &entries {
            for validator_id in proof.participant_indices() {
                Self::record_vote(&mut fork_choice.new_votes, validator_id, hashed.data());
            }
        }
        self.new_payloads.lock().unwrap().push_batch(entries);
    }

    // ============ Pruning Helpers ============

    /// Promotes all new aggregated payloads to known, making them active in fork choice.
    ///
    /// Drains the new buffer and pushes all entries into the known buffer.
    pub fn promote_new_aggregated_payloads(&mut self) {
        let drained = self.new_payloads.lock().unwrap().drain();
        {
            let mut fork_choice = self.fork_choice.lock().unwrap();
            let mut new_votes = std::mem::take(&mut fork_choice.new_votes);
            for (validator_id, data) in new_votes.drain() {
                Self::record_vote(&mut fork_choice.known_votes, validator_id, &data);
            }
            // Reuse the underlying buffer to keep memory constant
            fork_choice.new_votes = new_votes;
        }
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

    /// Largest per-group signature count among gossip groups voting for `slot`.
    ///
    /// One lock, no signature clones — cheap enough to call per gossip insert.
    /// Drives the early-aggregation threshold check.
    pub fn max_gossip_group_count_for_slot(&self, slot: u64) -> usize {
        let gossip = self.gossip_signatures.lock().unwrap();
        gossip.max_group_count_for_slot(slot)
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
        if self.chain != Chain::Lean {
            Self::lean_only("Store::head_slot");
        }
        self.get_block_header(&self.head().expect("head block exists"))
            .expect("head block exists")
            .unwrap()
            .slot
    }

    /// Returns the slot of the current safe target block.
    pub fn safe_target_slot(&self) -> u64 {
        if self.chain != Chain::Lean {
            Self::lean_only("Store::safe_target_slot");
        }
        self.get_block_header(&self.safe_target().expect("safe target exists"))
            .expect("safe target exists")
            .unwrap()
            .slot
    }

    /// Returns a clone of the head state.
    ///
    /// Lean-only: every caller of this accessor wants the concrete lean
    /// `State`, so the `BeaconState::Lean` wrapper is peeled off here rather
    /// than at each call site.
    pub fn head_state(&self) -> State {
        let state = self
            .get_state(&self.head().expect("head block exists"))
            .expect("head state is always available")
            .unwrap();
        state.expect_lean().clone()
    }

    // ============ Beacon Fork-Choice Scratch ============
    //
    // None of these carry a `Result`: the beacon fork choice's error type
    // lives in `ethlambda-types` and cannot name a storage error, so these
    // accessors take and return plain values like the rest of this scratch.

    /// The block root proposer boost currently applies to. Resets every slot.
    pub fn proposer_boost_root(&self) -> H256 {
        self.beacon.lock().unwrap().proposer_boost_root
    }

    /// Sets the block root proposer boost currently applies to.
    pub fn set_proposer_boost_root(&mut self, root: H256) {
        self.beacon.lock().unwrap().proposer_boost_root = root;
    }

    /// Whether `root` arrived within the same-slot reorg window. `None` when
    /// no timeliness has been recorded for the block yet.
    pub fn block_timeliness(&self, root: &H256) -> Option<bool> {
        self.beacon
            .lock()
            .unwrap()
            .block_timeliness
            .get(root)
            .copied()
    }

    /// Records whether `root` arrived within the same-slot reorg window.
    pub fn set_block_timeliness(&mut self, root: H256, timely: bool) {
        self.beacon
            .lock()
            .unwrap()
            .block_timeliness
            .insert(root, timely);
    }

    /// Whether `index` has been observed equivocating (via a processed
    /// attester slashing).
    pub fn is_equivocating(&self, index: u64) -> bool {
        self.beacon
            .lock()
            .unwrap()
            .equivocating_indices
            .contains(&index)
    }

    /// Marks `index` as equivocating.
    pub fn insert_equivocating_index(&mut self, index: u64) {
        self.beacon
            .lock()
            .unwrap()
            .equivocating_indices
            .insert(index);
    }

    /// The latest attestation recorded for validator `index`, if any.
    pub fn latest_message(&self, index: u64) -> Option<LatestMessage> {
        self.beacon
            .lock()
            .unwrap()
            .latest_messages
            .get(&index)
            .copied()
    }

    /// Records the latest attestation for validator `index`.
    pub fn set_latest_message(&mut self, index: u64, message: LatestMessage) {
        self.beacon
            .lock()
            .unwrap()
            .latest_messages
            .insert(index, message);
    }

    /// Calls `f` with `(validator_index, latest_message)` for every latest
    /// message whose validator has not been observed equivocating.
    ///
    /// Takes a closure rather than returning an iterator or a cloned map:
    /// the data lives behind a mutex, so a borrow of it cannot escape the
    /// lock. The equivocator filter lives here, at the read, because
    /// `get_weight` must exclude an equivocator's vote entirely rather than
    /// let it count for either side of the fork it created.
    pub fn for_each_non_equivocating_latest_message(&self, mut f: impl FnMut(u64, LatestMessage)) {
        let beacon = self.beacon.lock().unwrap();
        for (&index, &message) in &beacon.latest_messages {
            if !beacon.equivocating_indices.contains(&index) {
                f(index, message);
            }
        }
    }

    /// Looks up a PoW block by its own hash, standing in for the
    /// specification's `get_pow_block(hash)`.
    pub fn beacon_pow_block(&self, hash: H256) -> Option<PowBlock> {
        self.beacon.lock().unwrap().pow_blocks.get(&hash).copied()
    }

    /// Records a PoW block, keyed by its own `block_hash` rather than a
    /// caller-supplied key, matching the specification's lookup by that same
    /// hash.
    pub fn insert_beacon_pow_block(&mut self, block: PowBlock) {
        self.beacon
            .lock()
            .unwrap()
            .pow_blocks
            .insert(block.block_hash, block);
    }

    /// Looks up an execution client's answer for a payload, by that payload's
    /// own execution block hash.
    pub fn beacon_payload_status(&self, block_hash: ExecutionBlockHash) -> Option<PayloadStatusV1> {
        self.beacon
            .lock()
            .unwrap()
            .payload_statuses
            .get(&block_hash)
            .cloned()
    }

    /// Records an execution client's answer for a payload. The fixture format
    /// allows the same payload's status to be updated several times over a
    /// case, so this overwrites rather than preserving a first answer.
    pub fn insert_beacon_payload_status(
        &mut self,
        block_hash: ExecutionBlockHash,
        status: PayloadStatusV1,
    ) {
        self.beacon
            .lock()
            .unwrap()
            .payload_statuses
            .insert(block_hash, status);
    }

    /// Whether `root` was imported on a `NOT_VALIDATED` answer and has not
    /// since been resolved.
    pub fn is_beacon_optimistic(&self, root: H256) -> bool {
        self.beacon
            .lock()
            .unwrap()
            .optimistic_roots
            .contains_key(&root)
    }

    /// Whether this store holds any optimistic root at all.
    ///
    /// The cheap half of [`Store::is_beacon_optimistic`], for callers that
    /// would otherwise pay for a `block_index` scan only to walk a set that is
    /// empty. With a healthy execution client it always is.
    pub fn has_beacon_optimistic_roots(&self) -> bool {
        !self.beacon.lock().unwrap().optimistic_roots.is_empty()
    }

    /// Marks `root` as imported on a payload the execution layer has not
    /// vouched for yet, against the slot the unfinalized-window bound prunes
    /// it by.
    pub fn insert_beacon_optimistic_root(&mut self, root: H256, slot: u64) {
        self.beacon
            .lock()
            .unwrap()
            .optimistic_roots
            .insert(root, slot);
    }

    /// Clears `root`'s optimistic marker, once its payload has been resolved
    /// either way.
    pub fn remove_beacon_optimistic_root(&mut self, root: H256) {
        self.beacon.lock().unwrap().optimistic_roots.remove(&root);
    }

    /// Drops optimistic roots strictly below `finalized_slot`.
    ///
    /// A root below finality can no longer be validated or invalidated in any
    /// way this node acts on, so holding it only costs memory. Unlike
    /// `el_block_hashes` this needs no exemption for the finalized checkpoint's
    /// own root: nothing reads a finalized block's optimistic status, and
    /// `mark_validated`'s walk stopping one block earlier is the same answer.
    pub fn prune_beacon_optimistic_roots(&mut self, finalized_slot: u64) {
        self.beacon
            .lock()
            .unwrap()
            .optimistic_roots
            .retain(|_root, slot| *slot >= finalized_slot);
    }

    /// The execution block hash cached for a beacon root at import.
    pub fn beacon_el_block_hash(&self, root: H256) -> Option<ExecutionBlockHash> {
        self.beacon
            .lock()
            .unwrap()
            .el_block_hashes
            .get(&root)
            .map(|(_slot, hash)| *hash)
    }

    /// Caches the execution block hash a beacon block carries, against the slot
    /// the unfinalized-window bound prunes it by.
    pub fn insert_beacon_el_block_hash(
        &mut self,
        root: H256,
        slot: u64,
        block_hash: ExecutionBlockHash,
    ) {
        self.beacon
            .lock()
            .unwrap()
            .el_block_hashes
            .insert(root, (slot, block_hash));
    }

    /// Drops cached hashes strictly below `finalized_slot`, always keeping
    /// `keep`.
    ///
    /// Strictly below, not at or below: the justified and head blocks
    /// `forkchoiceUpdated` reads are at or above that slot, so this bound keeps
    /// every root the call reads but one.
    ///
    /// That one is `keep`, the finalized checkpoint's own root, whose hash the
    /// same call sends as `finalized_block_hash`. The slot bound alone does not
    /// reach it: `finalized_slot` comes from a checkpoint, and
    /// [`Store::beacon_checkpoint_as_stored`] stores an epoch as its own start
    /// slot, while the checkpoint root is the last block at *or before* that
    /// boundary. A missed proposal at an epoch boundary therefore leaves the
    /// finalized block below the bound, and dropping its hash makes every later
    /// `forkchoiceUpdated` carry `finalized_block_hash = 0x00..0`, which stops
    /// the execution client advancing its own finalized block for as long as
    /// the process runs.
    pub fn prune_beacon_el_block_hashes(&mut self, finalized_slot: u64, keep: H256) {
        self.beacon
            .lock()
            .unwrap()
            .el_block_hashes
            .retain(|root, (slot, _hash)| *slot >= finalized_slot || *root == keep);
    }

    /// Returns `root`'s unrealized justification, if this store has computed
    /// one.
    ///
    /// `get_voting_source` reads this for every block from a prior epoch, so
    /// it is the hottest map in the scratch; recomputing a missing entry means
    /// replaying epoch processing on a copy of that block's post-state. That
    /// still does not make it chain history: a restarted node re-imports the
    /// unfinalized window from its anchor and refills the map as it goes.
    pub fn unrealized_justification(&self, root: &H256) -> Option<BeaconCheckpoint> {
        self.beacon
            .lock()
            .unwrap()
            .unrealized_justifications
            .get(root)
            .copied()
    }

    /// Records `root`'s unrealized justification.
    pub fn set_unrealized_justification(&mut self, root: H256, checkpoint: BeaconCheckpoint) {
        self.beacon
            .lock()
            .unwrap()
            .unrealized_justifications
            .insert(root, checkpoint);
    }

    // ============ Data Columns ============
    //
    // Written on arrival (after verification), not at block import: the
    // availability check needs a block's columns before that block imports,
    // and a restart should keep what this node already paid to verify. See
    // `Table::DataColumns`.

    /// Store one verified sidecar.
    ///
    /// Takes the encoded bytes rather than the container: the caller has just
    /// decoded them off the wire, and re-encoding a sidecar to store it would
    /// pay a second SSZ pass on the hot gossip path for nothing.
    ///
    /// No earliest-slot bookkeeping rides along. The floor the by-range handler
    /// refuses below is [`Store::anchor_slot`], which is where this directory's
    /// chain begins and so is where custody could have begun; deriving it from
    /// the sidecars actually written would make a hot-path read-decide-write
    /// span out of a value that is fixed for the life of the directory.
    ///
    /// `&self` rather than `&mut self`, unlike most other writers in this
    /// file, matching `set_metadata`: nothing here mutates a `Store` field
    /// itself, only the shared backend behind it, so a shared reference
    /// suffices no matter how many read-only clones exist elsewhere.
    pub fn put_data_column_sidecar(
        &self,
        slot: u64,
        block_root: &H256,
        column_index: u64,
        encoded: Vec<u8>,
    ) -> Result<(), Error> {
        self.put_column_row(Table::DataColumns, slot, block_root, column_index, encoded)
    }

    /// Park a sidecar whose parent block has no post-state to check it against.
    ///
    /// The same key and the same encoded bytes as
    /// [`Self::put_data_column_sidecar`], in `Table::PendingDataColumns`
    /// instead. Nothing that decides data availability reads that table, which
    /// is the whole point: this row has passed only the cheap structural
    /// checks, and the expensive ones run when
    /// [`Self::take_pending_data_column_sidecar`] hands it back.
    pub fn put_pending_data_column_sidecar(
        &self,
        slot: u64,
        block_root: &H256,
        column_index: u64,
        encoded: Vec<u8>,
    ) -> Result<(), Error> {
        self.put_column_row(
            Table::PendingDataColumns,
            slot,
            block_root,
            column_index,
            encoded,
        )
    }

    /// Commit one sidecar row, under the same key in whichever of the two
    /// column tables the caller named.
    ///
    /// Which table a sidecar belongs in is what separates the two writers
    /// above; how a row is committed is not, and the availability gate's whole
    /// safety rests on a parked row and a verified one being the same bytes
    /// under the same key in different tables.
    fn put_column_row(
        &self,
        table: Table,
        slot: u64,
        block_root: &H256,
        column_index: u64,
        encoded: Vec<u8>,
    ) -> Result<(), Error> {
        let mut batch = self.backend.begin_write().expect("write batch");
        let entries = vec![(data_column_key(slot, block_root, column_index), encoded)];
        batch
            .put_batch(table, entries)
            .expect("put data column sidecar");
        batch.commit().expect("commit");
        Ok(())
    }

    /// Drop every parked row this directory holds.
    ///
    /// Called once at startup. The only index into `PendingDataColumns` is the
    /// chain actor's in-memory `sidecars_awaiting_parent`, which does not
    /// survive a restart, so every row written before one is unreachable by
    /// construction — kept, unverified, and never read again. Nothing is lost
    /// by dropping them: a parked sidecar had passed no check worth
    /// preserving, and the block it belongs to will ask for its columns again.
    pub fn clear_pending_data_column_sidecars(&self) -> Result<(), Error> {
        // `delete_range` is half-open, and every key here is 48 bytes, so the
        // upper bound is one byte longer and all ones: a shorter key sorts
        // before its own extension, which is what makes this a strict bound on
        // even an all-ones key rather than one that spares it.
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .delete_range(
                Table::PendingDataColumns,
                &[0u8; DATA_COLUMN_KEY_LEN],
                &[u8::MAX; DATA_COLUMN_KEY_LEN + 1],
            )
            .expect("clear parked data column sidecars");
        batch.commit().expect("commit");
        Ok(())
    }

    /// Read a parked sidecar back and drop its row in one step.
    ///
    /// Take rather than get: every caller is either about to verify the
    /// sidecar, after which it belongs in `DataColumns` and not here, or about
    /// to give up on it. Leaving the row behind for the caller to delete is
    /// the shape that leaks one on every path that returns early.
    pub fn take_pending_data_column_sidecar(
        &self,
        slot: u64,
        block_root: &H256,
        column_index: u64,
    ) -> Result<Option<Vec<u8>>, Error> {
        let key = data_column_key(slot, block_root, column_index);
        let view = self.backend.begin_read().expect("read view");
        let encoded = view.get(Table::PendingDataColumns, &key).expect("get");
        drop(view);
        if encoded.is_some() {
            let mut batch = self.backend.begin_write().expect("write batch");
            batch
                .delete_batch(Table::PendingDataColumns, vec![key])
                .expect("delete pending data column sidecar");
            batch.commit().expect("commit");
        }
        Ok(encoded)
    }

    /// Drop parked rows without reading them, for sidecars being given up on.
    pub fn delete_pending_data_column_sidecars(
        &self,
        keys: impl IntoIterator<Item = (u64, H256, u64)>,
    ) -> Result<(), Error> {
        let keys: Vec<Vec<u8>> = keys
            .into_iter()
            .map(|(slot, block_root, column_index)| {
                data_column_key(slot, &block_root, column_index)
            })
            .collect();
        if keys.is_empty() {
            return Ok(());
        }
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .delete_batch(Table::PendingDataColumns, keys)
            .expect("delete pending data column sidecars");
        batch.commit().expect("commit");
        Ok(())
    }

    /// One sidecar, or `None` if this node never custodied it.
    pub fn get_data_column_sidecar(
        &self,
        slot: u64,
        block_root: &H256,
        column_index: u64,
    ) -> Result<Option<Vec<u8>>, Error> {
        let view = self.backend.begin_read().expect("read view");
        Ok(view
            .get(
                Table::DataColumns,
                &data_column_key(slot, block_root, column_index),
            )
            .expect("get"))
    }

    /// Which columns of one block this node holds, ascending.
    ///
    /// What the availability check asks: it compares this against the columns
    /// the node owes rather than fetching the sidecars themselves, so a block
    /// missing one column costs no decoding at all.
    ///
    /// Sorted explicitly rather than trusted from the backend: both current
    /// backends already return a prefix scan in lexicographic key order (see
    /// `InMemoryBackend::prefix_iterator`), which for a fixed slot||root
    /// prefix and a big-endian index is already ascending, but a future
    /// backend need not repeat that guarantee.
    pub fn data_column_indices_for(&self, slot: u64, block_root: &H256) -> Result<Vec<u64>, Error> {
        let view = self.backend.begin_read().expect("read view");
        let prefix = data_column_block_prefix(slot, block_root);
        let mut indices: Vec<u64> = view
            .prefix_iterator(Table::DataColumns, &prefix)
            .expect("iterator")
            .filter_map(|res| res.ok())
            .map(|(key, _)| {
                let index_bytes: [u8; 8] = key[key.len() - 8..]
                    .try_into()
                    .expect("a column key ends in an eight-byte index");
                u64::from_be_bytes(index_bytes)
            })
            .collect();
        indices.sort_unstable();
        Ok(indices)
    }

    /// Every sidecar in `[start_slot, end_slot)` whose column is in `columns`,
    /// restricted to each slot's canonical block, in slot then column order.
    ///
    /// What the by-range handler serves from. The specification asks a
    /// response to be "consistent from a single chain within the context of
    /// the request", but gossip import only requires a sidecar's block to
    /// name a known, finalized-descendant parent, not a canonical one: a live
    /// fork can leave both siblings' columns stored at one slot, and
    /// `Table::DataColumns` is never pruned, so an orphaned sidecar would
    /// otherwise sit there forever and leak into every future range answer
    /// covering that slot. `Table::BlockRoots` is the canonical slot-to-root
    /// index [`Self::get_signed_blocks_by_slot_range`] and the block-range
    /// handler already key off, kept current by
    /// [`Self::update_checkpoints`] on both chains; a slot with no entry
    /// there has no canonical block; per the same "no block is returned for
    /// an empty slot" rule the block-range handler applies, it contributes no
    /// sidecars either.
    ///
    /// One [`StorageReadView::prefix_iterator`] call per slot rather than a
    /// single range read, because [`StorageReadView`] offers only
    /// exact-prefix iteration, with no range-iterator counterpart to
    /// [`StorageWriteBatch::delete_range`]; a per-slot prefix is the closest
    /// match this interface can express. The per-slot shape is right on its
    /// own terms regardless, and should not change even if a range iterator
    /// existed: this table is never pruned, so a whole-table scan would
    /// degrade forever, while these indexed per-slot seeks stay bounded by
    /// the requested range.
    pub fn data_column_sidecars_in_range(
        &self,
        start_slot: u64,
        end_slot: u64,
        columns: &[u64],
    ) -> Result<Vec<Vec<u8>>, Error> {
        let view = self.backend.begin_read().expect("read view");
        let mut found = Vec::new();
        for slot in start_slot..end_slot {
            let Some(root_bytes) = view
                .get(Table::BlockRoots, &encode_block_root_key(slot))
                .expect("get block root")
            else {
                continue;
            };
            let root = H256::from_ssz_bytes(&root_bytes).expect("valid block root");
            let prefix = data_column_block_prefix(slot, &root);
            let entries = view
                .prefix_iterator(Table::DataColumns, &prefix)
                .expect("iterator")
                .filter_map(|res| res.ok());
            for (key, value) in entries {
                let index_bytes: [u8; 8] = key[key.len() - 8..]
                    .try_into()
                    .expect("a column key ends in an eight-byte index");
                if columns.contains(&u64::from_be_bytes(index_bytes)) {
                    found.push(value.to_vec());
                }
            }
        }
        Ok(found)
    }

    /// The slot this store's chain begins at.
    ///
    /// Zero for a directory bootstrapped from genesis, the checkpoint's slot
    /// for one bootstrapped from a checkpoint. Fixed for the life of the
    /// directory, which is what lets this be a field read rather than a
    /// backend round trip; see [`KEY_ANCHOR_SLOT`].
    ///
    /// This is the honest floor for both the `Status` message's
    /// `earliest_available_slot` and the `by_range` handlers: nothing below it
    /// was ever written, so nothing below it can be served.
    pub fn anchor_slot(&self) -> u64 {
        self.anchor_slot
    }
}

/// Write a whole beacon signed block onto an existing batch, as one
/// `BlockHeaders` row.
///
/// The beacon counterpart of [`write_signed_block`], and a function for the
/// same reason: both `insert_signed_block` and `insert_pending_block` write
/// this row, so the key encoding, the value encoding and the table are stated
/// once. No `BlockBodies` row (a beacon block has no header/body split) and no
/// `BlockProof` row (its signature lives inside the block).
fn write_beacon_block(batch: &mut dyn StorageWriteBatch, root: &H256, block: &SignedBeaconBlock) {
    let header_entries = vec![(root.to_ssz(), encode_beacon_block_value(block))];
    batch
        .put_batch(Table::BlockHeaders, header_entries)
        .expect("put beacon block");
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

    // Store the merged multi-message aggregate proof blob, keyed by slot||root
    // so proof pruning can scan in slot order and stop early.
    let proof_entries = vec![(encode_slot_root_key(header.slot, root), proof.to_ssz())];
    batch
        .put_batch(Table::BlockProof, proof_entries)
        .expect("put block proof");

    block
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::InMemoryBackend;
    use ethlambda_types::beacon::containers::Checkpoint as BeaconCheckpoint;
    // Only the tests name a status variant: the store itself stores and hands
    // back whole `PayloadStatusV1` values without ever reading the tag.
    use ethlambda_types::beacon::fork_choice::PayloadStatusEnum;
    use ethlambda_types::beacon::primitives::Uint256;
    use ethlambda_types::constants::{DEFAULT_MILLISECONDS_PER_SLOT, INTERVALS_PER_SLOT};

    /// Insert a block header (and dummy body + proof) for a given root, slot,
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
                Table::BlockProof,
                vec![(encode_slot_root_key(slot, &root), vec![0u8; 4])],
            )
            .expect("put proof");
        batch
            .put_batch(
                Table::BlockRoots,
                vec![(encode_block_root_key(slot), root.to_ssz())],
            )
            .expect("put block root");
        batch.commit().expect("commit");
    }

    /// Insert a real full-state snapshot for a given root (seeds a diff-chain base).
    fn insert_snapshot(backend: &dyn StorageBackend, root: H256, state: &State) {
        let mut batch = backend.begin_write().expect("write batch");
        batch
            .put_batch(
                Table::States,
                vec![(
                    root.to_ssz(),
                    encode_state_value(&BeaconState::Lean(state.clone())),
                )],
            )
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

    /// Check whether a block proof exists for a (slot, root) pair.
    fn has_block_proof(backend: &dyn StorageBackend, slot: u64, root: &H256) -> bool {
        let view = backend.begin_read().expect("read view");
        view.get(Table::BlockProof, &encode_slot_root_key(slot, root))
            .expect("get")
            .is_some()
    }

    /// Canonical block root at `slot`, for storage-index assertions.
    fn canonical_root(store: &Store, slot: u64) -> Option<H256> {
        store
            .canonical_root_at_slot(slot)
            .expect("canonical block root")
    }

    /// Generate a deterministic H256 root from an index.
    fn root(index: u64) -> H256 {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&index.to_be_bytes());
        H256::from(bytes)
    }

    fn signed_block(slot: u64, parent_root: H256) -> SignedBlock {
        SignedBlock {
            message: Block {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: H256::ZERO,
                body: BlockBody::default(),
            },
            proof: MultiMessageAggregate::default(),
        }
    }

    fn signed_block_with_attestations(
        slot: u64,
        parent_root: H256,
        attestations: Vec<AggregatedAttestation>,
    ) -> SignedBlock {
        SignedBlock {
            message: Block {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: H256::ZERO,
                body: BlockBody {
                    attestations: attestations.try_into().unwrap(),
                },
            },
            proof: MultiMessageAggregate::default(),
        }
    }

    /// A signed beacon block with an empty body and a zero signature, for
    /// tests that only care about `slot` and `parent_root`. Phase0-shaped
    /// since nothing under test here reads anything fork-specific, mirroring
    /// the `block` helper in `state_transition`'s beacon fork-choice tests.
    fn beacon_test_block(slot: u64, parent_root: H256) -> SignedBeaconBlock {
        use ethlambda_types::beacon::containers::phase0;

        SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: H256::ZERO,
                body: phase0::BeaconBlockBody {
                    randao_reveal: Default::default(),
                    eth1_data: Default::default(),
                    graffiti: H256::ZERO,
                    proposer_slashings: Default::default(),
                    attester_slashings: Default::default(),
                    attestations: Default::default(),
                    deposits: Default::default(),
                    voluntary_exits: Default::default(),
                },
            },
            signature: Default::default(),
        })
    }

    #[test]
    fn a_beacon_block_round_trips_through_the_store() {
        // A beacon directory, not the lean `test_store`: `block_entry` decodes
        // the header row through the store's own chain tag, so a beacon row
        // read from a lean-tagged store is the one thing that cannot work.
        let mut store = beacon_test_store(Arc::new(InMemoryBackend::new()));
        let block = beacon_test_block(5, H256::from([1u8; 32]));
        let root = block.message_hash_tree_root();

        store
            .insert_signed_block(root, block.clone())
            .expect("insert beacon block");

        assert_eq!(store.block_entry(&root), Some((5, H256::from([1u8; 32]))));
        assert!(store.has_block(&root));
    }

    #[test]
    fn a_lean_block_still_records_its_attestation_votes() {
        // The lean arm's post-commit side effect must survive the split: a
        // beacon block has no lean attestations, so the decision has to be
        // made per arm rather than unconditionally.
        let mut store = Store::test_store();
        let data = make_att_data_for_target(8, root(8));
        let signed = signed_block_with_attestations(
            1,
            H256::ZERO,
            vec![AggregatedAttestation {
                aggregation_bits: make_proof_for_validators(&[1, 3]).participants,
                data: data.clone(),
            }],
        );
        let block_root = signed.message.hash_tree_root();

        store
            .insert_signed_block(block_root, SignedBeaconBlock::Lean(signed))
            .expect("insert lean block");

        let votes = store.extract_latest_known_attestations();
        assert_eq!(votes[&1], data);
        assert_eq!(votes[&3], data);
    }

    #[test]
    fn an_unknown_root_has_no_block() {
        let store = Store::test_store();
        assert!(!store.has_block(&H256::from([9u8; 32])));
        assert_eq!(store.block_entry(&H256::from([9u8; 32])), None);
    }

    /// A beacon store anchored at the zero root, for the tests that only need
    /// the chain tag rather than a real anchor block.
    fn beacon_test_store(backend: Arc<dyn StorageBackend>) -> Store {
        Store::init_beacon(
            backend,
            0,
            Config::mainnet(),
            H256::ZERO,
            Checkpoint::default(),
            0,
        )
    }

    #[test]
    fn a_beacon_block_reads_back_as_the_fork_it_was_written_as() {
        // `get_signed_block` dispatches on the store's own chain tag, so this
        // needs a real beacon store rather than the lean `test_store` helper:
        // on a lean store the tag would send a beacon-shaped body row through
        // the lean decode path.
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = beacon_test_store(backend);
        let block = beacon_test_block(5, H256::from([1u8; 32]));
        let root = block.message_hash_tree_root();

        store
            .insert_signed_block(root, block.clone())
            .expect("insert beacon block");

        // The body row carries a fork selector, so the reader recovers the
        // shape without the caller having to know which chain it opened.
        let read = store
            .get_signed_block(&root)
            .expect("get")
            .expect("present");
        assert_eq!(read.fork_name(), block.fork_name());
        assert_eq!(read.slot(), 5);
        assert_eq!(read.parent_root(), H256::from([1u8; 32]));
    }

    #[test]
    fn a_lean_block_still_reads_back_through_the_same_method() {
        let mut store = Store::test_store();
        let signed = signed_block_with_attestations(1, H256::ZERO, Vec::new());
        let root = signed.message.hash_tree_root();

        store
            .insert_signed_block(root, SignedBeaconBlock::Lean(signed.clone()))
            .expect("insert lean block");

        let read = store
            .get_signed_block(&root)
            .expect("get")
            .expect("present");
        match read {
            SignedBeaconBlock::Lean(lean) => assert_eq!(lean.message.slot, signed.message.slot),
            other => panic!("expected a lean block, got {}", other.fork_name()),
        }
    }

    #[test]
    fn block_slot_and_state_root_returns_a_lean_blocks_own_slot_and_state_root() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::from_anchor_state(
            backend,
            State::from_genesis(0, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );
        let anchor_root = store.head().expect("head root");

        let block = signed_block(1, anchor_root);
        let state_root = block.message.state_root;
        let block_root = block.message.hash_tree_root();
        store
            .insert_signed_block(block_root, SignedBeaconBlock::Lean(block))
            .expect("insert lean block");

        assert_eq!(
            store.block_slot_and_state_root(&block_root),
            Some((1, state_root))
        );
    }

    #[test]
    fn block_slot_and_state_root_returns_a_beacon_blocks_own_slot_and_state_root() {
        // Distinctive slot and state_root (not the zeroed defaults
        // `beacon_test_block` uses), so a decode that silently returned the
        // wrong field, or the wrong block, would not pass by coincidence.
        use ethlambda_types::beacon::containers::phase0;

        let mut store = beacon_test_store(Arc::new(InMemoryBackend::new()));
        let state_root = H256::from([7u8; 32]);
        let block = SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot: 42,
                proposer_index: 0,
                parent_root: H256::from([1u8; 32]),
                state_root,
                body: phase0::BeaconBlockBody {
                    randao_reveal: Default::default(),
                    eth1_data: Default::default(),
                    graffiti: H256::ZERO,
                    proposer_slashings: Default::default(),
                    attester_slashings: Default::default(),
                    attestations: Default::default(),
                    deposits: Default::default(),
                    voluntary_exits: Default::default(),
                },
            },
            signature: Default::default(),
        });
        let block_root = block.message_hash_tree_root();

        store
            .insert_signed_block(block_root, block)
            .expect("insert beacon block");

        assert_eq!(
            store.block_slot_and_state_root(&block_root),
            Some((42, state_root))
        );
    }

    #[test]
    fn block_slot_and_state_root_returns_none_for_an_absent_root() {
        let store = Store::test_store();
        assert_eq!(
            store.block_slot_and_state_root(&H256::from([9u8; 32])),
            None
        );
    }

    #[test]
    fn block_slot_and_state_root_agrees_with_block_entry_on_slot_for_a_lean_block() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::from_anchor_state(
            backend,
            State::from_genesis(0, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );
        let anchor_root = store.head().expect("head root");

        let block = signed_block(1, anchor_root);
        let block_root = block.message.hash_tree_root();
        store
            .insert_signed_block(block_root, SignedBeaconBlock::Lean(block))
            .expect("insert lean block");

        let (entry_slot, _) = store.block_entry(&block_root).expect("block entry");
        let (read_slot, _) = store
            .block_slot_and_state_root(&block_root)
            .expect("block slot and state root");
        // Both accessors read the same BlockHeaders row, so they must not
        // disagree about which block it is.
        assert_eq!(entry_slot, read_slot);
    }

    #[test]
    fn block_slot_and_state_root_agrees_with_block_entry_on_slot_for_a_beacon_block() {
        let mut store = beacon_test_store(Arc::new(InMemoryBackend::new()));
        let block = beacon_test_block(5, H256::from([1u8; 32]));
        let block_root = block.message_hash_tree_root();
        store
            .insert_signed_block(block_root, block)
            .expect("insert beacon block");

        let (entry_slot, _) = store.block_entry(&block_root).expect("block entry");
        let (read_slot, _) = store
            .block_slot_and_state_root(&block_root)
            .expect("block slot and state root");
        assert_eq!(entry_slot, read_slot);
    }

    impl Store {
        /// Create a Store with an in-memory backend for tests.
        fn test_store() -> Self {
            let backend = Arc::new(InMemoryBackend::new());
            Self::from_parts(
                backend,
                Arc::new(Config::lean(0, DEFAULT_MILLISECONDS_PER_SLOT)),
                Chain::Lean,
                0,
            )
        }

        /// Create a Store with a shared in-memory backend for tests that need
        /// direct backend access.
        fn test_store_with_backend(backend: Arc<InMemoryBackend>) -> Self {
            Self::from_parts(
                backend,
                Arc::new(Config::lean(0, DEFAULT_MILLISECONDS_PER_SLOT)),
                Chain::Lean,
                0,
            )
        }
    }

    // ============ Chain / DB Version Tests ============

    #[test]
    fn a_fresh_lean_store_records_its_chain_and_db_version() {
        let backend = Arc::new(InMemoryBackend::new());
        let store = Store::from_anchor_state(
            backend.clone(),
            State::from_genesis(7, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );
        assert_eq!(store.chain(), Chain::Lean);

        let view = backend.begin_read().expect("read view");
        let version = view
            .get(Table::Metadata, KEY_DB_VERSION)
            .expect("get")
            .expect("db version written at bootstrap");
        assert_eq!(
            u64::from_ssz_bytes(&version).expect("valid version"),
            DB_VERSION
        );
    }

    #[test]
    fn a_fresh_lean_store_records_the_preset_it_was_built_against() {
        let backend = Arc::new(InMemoryBackend::new());
        let _ = Store::from_anchor_state(
            backend.clone(),
            State::from_genesis(7, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );

        let view = backend.begin_read().expect("read view");
        let preset = view
            .get(Table::Metadata, KEY_PRESET)
            .expect("get")
            .expect("preset written at bootstrap");
        assert_eq!(
            preset.first().copied().and_then(Preset::from_selector),
            Some(Preset::ACTIVE)
        );
    }

    #[test]
    fn from_db_state_refuses_a_directory_written_against_another_preset() {
        let backend = Arc::new(InMemoryBackend::new());
        let _ = Store::from_anchor_state(
            backend.clone(),
            State::from_genesis(7, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );

        // Rewrite only the preset byte, to whichever this build is not. Which
        // one that is depends on the feature this crate was compiled with, and
        // the check must hold either way round, so the value is derived rather
        // than written as a literal.
        let other = match Preset::ACTIVE {
            Preset::Mainnet => Preset::Minimal,
            Preset::Minimal => Preset::Mainnet,
        };
        let mut batch = backend.begin_write().expect("write batch");
        let entries = vec![(KEY_PRESET.to_vec(), vec![other.selector()])];
        batch
            .put_batch(Table::Metadata, entries)
            .expect("put preset");
        batch.commit().expect("commit");

        let Err(err) = Store::from_db_state(backend) else {
            panic!("a directory built against another preset must not be reused");
        };
        let Error::PresetMismatch { found, expected } = err else {
            panic!("expected a preset mismatch, got {err}");
        };
        assert_eq!(found, Some(other.name()));
        assert_eq!(expected, Preset::ACTIVE.name());
    }

    #[test]
    fn from_db_state_refuses_a_directory_with_no_preset_recorded() {
        let backend = Arc::new(InMemoryBackend::new());
        let _ = Store::from_anchor_state(
            backend.clone(),
            State::from_genesis(7, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );

        // A directory from before the preset was recorded. It cannot be
        // assumed to be this build's: the whole point of the row is that
        // nothing else in the directory says which shapes it holds.
        let mut batch = backend.begin_write().expect("write batch");
        batch
            .delete_batch(Table::Metadata, vec![KEY_PRESET.to_vec()])
            .expect("delete preset");
        batch.commit().expect("commit");

        let Err(err) = Store::from_db_state(backend) else {
            panic!("a directory with no preset recorded must not be reused");
        };
        assert!(matches!(err, Error::PresetMismatch { found: None, .. }));
    }

    #[test]
    fn a_fresh_lean_store_starts_its_clock_at_genesis() {
        const GENESIS_TIME: u64 = 1_770_407_233;
        let backend = Arc::new(InMemoryBackend::new());
        let store = Store::from_anchor_state(
            backend,
            State::from_genesis(GENESIS_TIME, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );

        // The row is an absolute Unix millisecond, so "not moved yet" is
        // genesis itself; both derived clocks read zero off it.
        assert_eq!(store.time_ms().expect("time"), GENESIS_TIME * 1_000);
        assert_eq!(store.ms_since_genesis(), 0);
        assert_eq!(store.intervals_since_genesis(), 0);
        assert_eq!(store.current_slot(), 0);
    }

    #[test]
    fn the_derived_clocks_agree_at_every_interval_boundary() {
        // One row, three readings. The interval grid is the finest, so it is
        // the one that can disagree with the slot: it must not.
        const GENESIS_TIME: u64 = 1_770_407_233;
        const MILLISECONDS_PER_SLOT: u64 = 4_000;
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::from_anchor_state(
            backend,
            State::from_genesis(GENESIS_TIME, vec![]),
            MILLISECONDS_PER_SLOT,
        );
        let genesis_ms = GENESIS_TIME * 1_000;
        let ms_per_interval = MILLISECONDS_PER_SLOT / INTERVALS_PER_SLOT;

        for intervals in 0..4 * INTERVALS_PER_SLOT {
            store
                .set_time_ms(genesis_ms + intervals * ms_per_interval)
                .expect("set time");
            assert_eq!(store.intervals_since_genesis(), intervals);
            assert_eq!(
                store.current_slot(),
                intervals / INTERVALS_PER_SLOT,
                "interval {intervals}"
            );
        }

        // And a reading between two boundaries names the interval it is inside,
        // which is the whole reason the row is finer than a second: four of
        // every five of these boundaries are not on a whole second.
        store
            .set_time_ms(genesis_ms + ms_per_interval + 1)
            .expect("set time");
        assert_eq!(store.intervals_since_genesis(), 1);
    }

    #[test]
    fn current_slot_follows_the_slot_duration_not_the_truncated_second() {
        // A cadence that is not a whole number of seconds: `Config::lean`
        // truncates `seconds_per_slot`, so dividing by that would put this
        // store a slot ahead of itself within a few slots. `current_slot`
        // divides by the millisecond duration instead.
        const GENESIS_TIME: u64 = 1_000;
        const MILLISECONDS_PER_SLOT: u64 = 6_500;
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::from_anchor_state(
            backend,
            State::from_genesis(GENESIS_TIME, vec![]),
            MILLISECONDS_PER_SLOT,
        );
        let genesis_ms = GENESIS_TIME * 1_000;

        for (elapsed_ms, expected_slot) in
            [(0, 0), (6_499, 0), (6_500, 1), (13_000, 2), (26_000, 4)]
        {
            store
                .set_time_ms(genesis_ms + elapsed_ms)
                .expect("set time");
            assert_eq!(
                store.current_slot(),
                expected_slot,
                "{elapsed_ms}ms after genesis at a {MILLISECONDS_PER_SLOT}ms cadence"
            );
        }
    }

    #[test]
    fn the_store_clock_never_reads_before_genesis() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::from_anchor_state(
            backend,
            State::from_genesis(1_770_407_233, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );

        // An externally supplied anchor time is the one way this row lands
        // below genesis; saturating is what keeps every derived clock at the
        // first slot of the chain rather than the last of a u64.
        store.set_time_ms(1).expect("set time");
        assert_eq!(store.ms_since_genesis(), 0);
        assert_eq!(store.intervals_since_genesis(), 0);
        assert_eq!(store.current_slot(), 0);
    }

    #[test]
    fn from_db_state_rejects_an_unversioned_database() {
        let backend = Arc::new(InMemoryBackend::new());
        let _ = Store::from_anchor_state(
            backend.clone(),
            State::from_genesis(7, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );

        // A pre-versioning database is exactly one with no version key, so
        // deleting it reproduces the format this build must refuse.
        let mut batch = backend.begin_write().expect("write batch");
        batch
            .delete_batch(Table::Metadata, vec![KEY_DB_VERSION.to_vec()])
            .expect("delete db version");
        batch.commit().expect("commit");

        // Matched rather than `expect_err`: that would need `Store: Debug`, and
        // the store holds a `dyn StorageBackend` and buffers with no `Debug`.
        let Err(err) = Store::from_db_state(backend) else {
            panic!("an unversioned database must not be reused");
        };
        assert!(matches!(
            err,
            Error::DbVersionMismatch {
                found: 0,
                expected: DB_VERSION
            }
        ));
    }

    #[test]
    fn a_directory_written_by_the_previous_format_is_refused() {
        let backend = Arc::new(InMemoryBackend::new());

        // A directory from the format one version back: only `KEY_CONFIG` and
        // `KEY_DB_VERSION` need to be present to reach the check, since it
        // runs before the preset and chain reads.
        let mut batch = backend.begin_write().expect("write batch");
        let entries = vec![
            (KEY_CONFIG.to_vec(), Config::mainnet().to_ssz()),
            (KEY_DB_VERSION.to_vec(), (DB_VERSION - 1).to_ssz()),
        ];
        batch
            .put_batch(Table::Metadata, entries)
            .expect("put metadata");
        batch.commit().expect("commit");

        // Matched rather than `expect_err`: that would need `Store: Debug`, and
        // the store holds a `dyn StorageBackend` and buffers with no `Debug`.
        let Err(err) = Store::from_db_state(backend) else {
            panic!("a directory written by the previous format must not be reused");
        };
        assert!(
            matches!(
                err,
                Error::DbVersionMismatch { found, expected }
                if found == DB_VERSION - 1 && expected == DB_VERSION
            ),
            "got {err:?}"
        );
    }

    // ============ Block Signature Pruning Tests ============

    #[test]
    fn block_root_index_tracks_canonical_chain_across_reorgs() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::from_anchor_state(
            backend,
            State::from_genesis(0, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );
        let anchor_root = store.head().expect("head root");

        let block_1 = signed_block(1, anchor_root);
        let root_1 = block_1.message.hash_tree_root();
        store
            .insert_signed_block(root_1, SignedBeaconBlock::Lean(block_1))
            .expect("insert block 1");

        let block_3 = signed_block(3, root_1);
        let root_3 = block_3.message.hash_tree_root();
        store
            .insert_signed_block(root_3, SignedBeaconBlock::Lean(block_3))
            .expect("insert block 3");
        store
            .update_checkpoints(ForkCheckpoints::head_only(root_3))
            .expect("update head to block 3");

        assert_eq!(canonical_root(&store, 0), Some(anchor_root));
        assert_eq!(canonical_root(&store, 1), Some(root_1));
        assert_eq!(canonical_root(&store, 2), None);
        assert_eq!(canonical_root(&store, 3), Some(root_3));

        let side_block_2 = signed_block(2, anchor_root);
        let side_root_2 = side_block_2.message.hash_tree_root();
        store
            .insert_signed_block(side_root_2, SignedBeaconBlock::Lean(side_block_2))
            .expect("insert side block 2");

        let side_block_4 = signed_block(4, side_root_2);
        let side_root_4 = side_block_4.message.hash_tree_root();
        store
            .insert_signed_block(side_root_4, SignedBeaconBlock::Lean(side_block_4))
            .expect("insert side block 4");
        store
            .update_checkpoints(ForkCheckpoints::head_only(side_root_4))
            .expect("update head to side block 4");

        assert_eq!(canonical_root(&store, 0), Some(anchor_root));
        assert_eq!(canonical_root(&store, 1), None);
        assert_eq!(canonical_root(&store, 2), Some(side_root_2));
        assert_eq!(canonical_root(&store, 3), None);
        assert_eq!(canonical_root(&store, 4), Some(side_root_4));
    }

    #[test]
    fn from_db_state_preserves_block_root_index() {
        // No state is ever inserted for the block below, and none needs to
        // be: `from_db_state` only loads (see its doc); `repair_head` is a
        // separate, explicit step a resuming caller takes afterward (see
        // `main.rs`'s `fetch_initial_state`), so nothing here mutates the
        // head this test is checking the index survives around.
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::from_anchor_state(
            backend.clone(),
            State::from_genesis(12345, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );

        let block = signed_block(1, store.head().expect("head root"));
        let block_root = block.message.hash_tree_root();
        store
            .insert_signed_block(block_root, SignedBeaconBlock::Lean(block))
            .expect("insert block");
        store
            .update_checkpoints(ForkCheckpoints::head_only(block_root))
            .expect("update head");

        let restored = Store::from_db_state(backend)
            .expect("restore store")
            .expect("store exists");
        let blocks = restored
            .get_signed_blocks_by_slot_range(1, 1)
            .expect("get blocks by slot range");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].message_hash_tree_root(), block_root);
    }

    /// A lean chain rooted at a real anchor, up to `head_slot`. Every block
    /// gets a real `insert_signed_block` (so it carries a `LiveChain` row,
    /// like production data would), and every state is a [`child_of`] the
    /// anchor, so the diff chain reconstructs against real, consistent
    /// `config`/`validators` rather than an unrelated fixture's.
    ///
    /// `stateless_from` marks the first slot whose state is never inserted
    /// (standing in for the writer never having gotten to it); every slot
    /// from there to `head_slot` is left stateless the same way. Returns the
    /// roots in slot order, `r0` (the anchor) included, and does not move
    /// `KEY_HEAD` itself: callers do that with `set_metadata`, the same way a
    /// crash would leave it pointing further than the writer had reached.
    fn lean_chain_with_stateless_tail(
        store: &mut Store,
        head_slot: u64,
        stateless_from: u64,
    ) -> Vec<H256> {
        let r0 = store.head().expect("head root");
        let anchor_state = store
            .get_state(&r0)
            .expect("get anchor state")
            .expect("anchor state exists")
            .expect_lean()
            .clone();

        let mut roots = vec![r0];
        let mut parent_root = r0;
        let mut hbh = Vec::new();
        for slot in 1..=head_slot {
            hbh.push(parent_root);
            let root = signed_block(slot, parent_root).message.hash_tree_root();
            store
                .insert_signed_block(
                    root,
                    SignedBeaconBlock::Lean(signed_block(slot, parent_root)),
                )
                .expect("insert block");
            if slot < stateless_from {
                let state = child_of(&anchor_state, slot, parent_root, hbh.clone());
                store
                    .insert_state(root, BeaconState::Lean(state))
                    .expect("insert state");
            }
            roots.push(root);
            parent_root = root;
        }
        roots
    }

    /// The regression this whole repair exists for, walking back more than
    /// one hop: three blocks in a row whose states the writer never got to
    /// (standing in for an unclean shutdown inside the writer's queue
    /// window) are rewound past. Each of their `LiveChain` rows -- fork
    /// choice's only record of them -- goes with the rewind, which is what
    /// makes it stick rather than have the very next fork-choice run walk
    /// right back to the stateless tip.
    #[test]
    fn repair_head_rewinds_three_hops_and_drops_them_from_fork_choice() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::from_anchor_state(
            backend.clone(),
            State::from_genesis(1_000, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );
        let roots = lean_chain_with_stateless_tail(&mut store, 4, 2);
        let (r1, r2, r3, r4) = (roots[1], roots[2], roots[3], roots[4]);
        store.set_metadata(KEY_HEAD, &r4);

        // Settle every write before resuming; r2, r3 and r4 never get one.
        drop(store);

        let mut resumed = Store::from_db_state(backend.clone())
            .expect("restore store")
            .expect("store exists");
        resumed.repair_head().expect("repair head");
        assert_eq!(
            resumed.head().expect("head"),
            r1,
            "rewound three hops to the newest ancestor with a persisted state"
        );

        let live_chain = resumed.get_live_chain().expect("get live chain");
        for hopped in [r2, r3, r4] {
            assert!(
                !live_chain.contains_key(&hopped),
                "a hopped block's LiveChain row must be gone"
            );
        }
        assert!(
            live_chain.contains_key(&r1),
            "the repaired head's own LiveChain row must survive"
        );

        // Persisted, not just an in-memory correction: a second Store over
        // the same backend reads back the repaired head.
        drop(resumed);
        let reread = Store::from_db_state(backend)
            .expect("restore store")
            .expect("store exists");
        assert_eq!(reread.head().expect("head"), r1);
    }

    /// The walk's own bound: exactly `STATE_WRITE_QUEUE_CAPACITY + 1` missing
    /// states behind the head is still within what the writer's queue can
    /// explain, and repairs cleanly.
    #[test]
    fn repair_head_accepts_a_rewind_exactly_at_the_writer_queue_bound() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::from_anchor_state(
            backend.clone(),
            State::from_genesis(1_000, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );
        // r1 has a state; r2, r3 and r4 (three hops) do not.
        let roots = lean_chain_with_stateless_tail(&mut store, 4, 2);
        let (r1, r4) = (roots[1], roots[4]);
        store.set_metadata(KEY_HEAD, &r4);

        drop(store);
        let mut resumed = Store::from_db_state(backend)
            .expect("restore store")
            .expect("store exists");
        resumed
            .repair_head()
            .expect("three hops is within the bound");
        assert_eq!(resumed.head().expect("head"), r1);
    }

    /// One hop past that bound is no longer explained by the writer's queue,
    /// and is reported rather than walked past.
    #[test]
    fn repair_head_rejects_a_rewind_one_hop_past_the_writer_queue_bound() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::from_anchor_state(
            backend.clone(),
            State::from_genesis(1_000, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );
        // r1 has a state; r2 through r5 (four hops) do not.
        let roots = lean_chain_with_stateless_tail(&mut store, 5, 2);
        let r5 = roots[5];
        store.set_metadata(KEY_HEAD, &r5);

        drop(store);
        let mut resumed = Store::from_db_state(backend)
            .expect("restore store")
            .expect("store exists");
        let err = resumed
            .repair_head()
            .expect_err("four missing states is past the bound");
        assert!(
            matches!(err, Error::HeadRepairExceededWindow { hops: 4, .. }),
            "unexpected error: {err:?}"
        );
    }

    /// A broken parent chain reached partway through the walk is corruption,
    /// not this race: the race requires the head's own block, and every
    /// block it walks through, to already be on disk, only their states
    /// missing.
    #[test]
    fn repair_head_reports_a_broken_parent_chain_mid_walk() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::from_anchor_state(
            backend.clone(),
            State::from_genesis(1_000, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );

        // r1 has a block on record and no state, but its own parent root
        // names nothing this directory ever held.
        let ghost = H256::repeat_byte(0xee);
        let r1 = signed_block(1, ghost).message.hash_tree_root();
        store
            .insert_signed_block(r1, SignedBeaconBlock::Lean(signed_block(1, ghost)))
            .expect("insert block");
        store.set_metadata(KEY_HEAD, &r1);

        drop(store);
        let mut resumed = Store::from_db_state(backend)
            .expect("restore store")
            .expect("store exists");
        let err = resumed
            .repair_head()
            .expect_err("a broken parent chain is corruption");
        assert!(
            matches!(err, Error::UnexpectedMissingBlockHeader(root) if root == ghost),
            "unexpected error: {err:?}"
        );
    }

    /// `anchor_slot` and finalized's slot are both zero on a freshly
    /// bootstrapped store (`init_store` seeds finalized at the anchor
    /// itself), so a walk that bottoms out there hits the tie between the
    /// two bounds. It must resolve to `AnchorStateLost`, which names the
    /// checkpoint and a remedy, not `UnexpectedMissingState`, which names
    /// neither.
    #[test]
    fn repair_head_resolves_the_anchor_finalized_tie_to_anchor_state_lost() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::from_anchor_state(
            backend.clone(),
            State::from_genesis(1_000, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );
        assert_eq!(
            store.latest_finalized().expect("finalized").slot,
            0,
            "the tie this test needs: nothing has finalized past the anchor yet"
        );

        // A block on record at slot 0 itself, with no state and a parent
        // this directory never held: not a descendant of the real anchor,
        // just something at the same slot the walk's bound checks compare
        // against.
        let unknown_parent = H256::repeat_byte(0xcc);
        let stale = signed_block(0, unknown_parent);
        let r_stale = stale.message.hash_tree_root();
        store
            .insert_signed_block(r_stale, SignedBeaconBlock::Lean(stale))
            .expect("insert block");
        store.set_metadata(KEY_HEAD, &r_stale);

        drop(store);
        let mut resumed = Store::from_db_state(backend)
            .expect("restore store")
            .expect("store exists");
        let err = resumed
            .repair_head()
            .expect_err("nothing to rewind to below the tie");
        assert!(
            matches!(err, Error::AnchorStateLost { .. }),
            "unexpected error: {err:?}"
        );
    }

    /// `repair_head` works the same way on a beacon directory with a real
    /// chain behind it, not just at `init_beacon`'s bare bootstrap (see
    /// `from_db_state_loads_a_beacon_directory_as_beacon` for that case).
    #[test]
    fn repair_head_rewinds_a_beacon_head_past_bootstrap() {
        let backend = Arc::new(InMemoryBackend::new());
        let anchor_root = H256::repeat_byte(0xaa);
        // Never given its own block, which is what makes the anchor state a
        // snapshot rather than a diff (see `is_anchor`): a real checkpoint
        // sync anchor's parent is exactly as unknown to this directory.
        let unknown_parent = H256::repeat_byte(0xbb);
        let mut store = Store::init_beacon(
            backend.clone(),
            0,
            Config::mainnet(),
            anchor_root,
            Checkpoint {
                root: anchor_root,
                slot: 0,
            },
            0,
        );
        store
            .insert_signed_block(anchor_root, beacon_test_block(0, unknown_parent))
            .expect("insert anchor block");
        store
            .insert_state(
                anchor_root,
                beacon_test_state_with_parent(0, unknown_parent),
            )
            .expect("insert anchor state");

        // r1: a real, committed state.
        let block1 = beacon_test_block(1, anchor_root);
        let r1 = block1.message_hash_tree_root();
        store.insert_signed_block(r1, block1).expect("insert block");
        store
            .insert_state(r1, beacon_test_state_with_parent(1, anchor_root))
            .expect("insert state");

        // r2: a block on record, but the writer never got to its state.
        let block2 = beacon_test_block(2, r1);
        let r2 = block2.message_hash_tree_root();
        store.insert_signed_block(r2, block2).expect("insert block");
        store.set_metadata(KEY_HEAD, &r2);

        drop(store);
        let mut resumed = Store::from_db_state(backend)
            .expect("restore store")
            .expect("store exists");
        resumed.repair_head().expect("repair head");
        assert_eq!(resumed.head().expect("head"), r1);
    }

    /// The common case: nothing for `repair_head` to do when the recorded
    /// head already has a persisted state. Same head back, and the slot-1
    /// `BlockRoots` entry survives untouched, which is what proves no rewind
    /// through `update_checkpoints` ran to produce that answer.
    #[test]
    fn repair_head_leaves_an_already_settled_head_alone() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::from_anchor_state(
            backend.clone(),
            State::from_genesis(1_000, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );
        let roots = lean_chain_with_stateless_tail(&mut store, 1, 2);
        let r1 = roots[1];
        store
            .update_checkpoints(ForkCheckpoints::head_only(r1))
            .expect("update head");

        drop(store);

        let mut resumed = Store::from_db_state(backend)
            .expect("restore store")
            .expect("store exists");
        resumed.repair_head().expect("repair head");
        assert_eq!(
            resumed.head().expect("head"),
            r1,
            "a head whose state is already settled is left exactly where it was"
        );
        assert_eq!(
            canonical_root(&resumed, 1),
            Some(r1),
            "no rewind ran: the slot-1 canonical entry update_checkpoints would \
             otherwise have touched is untouched"
        );
    }

    #[test]
    fn insert_signed_block_records_block_attestation_votes() {
        let mut store = Store::test_store();
        let data = make_att_data_for_target(8, root(8));
        let block = signed_block_with_attestations(
            1,
            H256::ZERO,
            vec![AggregatedAttestation {
                aggregation_bits: make_proof_for_validators(&[1, 3]).participants,
                data: data.clone(),
            }],
        );
        let block_root = block.message.hash_tree_root();

        store
            .insert_signed_block(block_root, SignedBeaconBlock::Lean(block))
            .expect("insert signed block");

        let votes = store.extract_latest_known_attestations();
        assert_eq!(votes[&1], data);
        assert_eq!(votes[&3], data);
    }

    #[test]
    fn prune_old_block_proofs_within_retention() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::test_store_with_backend(backend.clone());

        // Blocks at slots 0..12, each with header + body + proof.
        for i in 0..13u64 {
            insert_header(backend.as_ref(), root(i), i, H256::ZERO);
        }

        // Healthy finality: non-finalized gap (5) < BLOCK_PROOF_PRUNING_RANGE.
        // tip = range + 10, finalized = range + 5, so cutoff = tip - range = 10.
        let tip_slot = BLOCK_PROOF_PRUNING_RANGE + 10;
        let finalized_slot = BLOCK_PROOF_PRUNING_RANGE + 5;
        let pruned_below_slot = store
            .prune_old_block_proofs(finalized_slot, tip_slot)
            .expect("prune");

        // cutoff = 10: slots 0..9 pruned, slots 10..12 kept (within the window).
        assert_eq!(pruned_below_slot, 10);
        assert_eq!(count_entries(backend.as_ref(), Table::BlockProof), 3);

        // Oldest proofs are gone, but headers, bodies, and roots stay queryable.
        for i in 0..10u64 {
            assert!(!has_block_proof(backend.as_ref(), i, &root(i)));
        }
        for i in 10..13u64 {
            assert!(has_block_proof(backend.as_ref(), i, &root(i)));
        }

        // Headers and bodies are always retained for the whole history.
        assert_eq!(count_entries(backend.as_ref(), Table::BlockHeaders), 13);
        assert_eq!(count_entries(backend.as_ref(), Table::BlockBodies), 13);
        assert_eq!(count_entries(backend.as_ref(), Table::BlockRoots), 13);
    }

    #[test]
    fn prune_block_proofs_noop_when_non_finalized_range_exceeds_window() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::test_store_with_backend(backend.clone());

        for i in 0..10u64 {
            insert_header(backend.as_ref(), root(i), i, H256::ZERO);
        }

        // Deep non-finality: gap (tip - finalized) > BLOCK_PROOF_PRUNING_RANGE, so
        // cutoff = tip - range > finalized → prune nothing.
        let tip_slot = BLOCK_PROOF_PRUNING_RANGE + 100;
        let finalized_slot = 5;
        let pruned_below_slot = store
            .prune_old_block_proofs(finalized_slot, tip_slot)
            .expect("prune");
        assert_eq!(pruned_below_slot, 0);
        assert_eq!(count_entries(backend.as_ref(), Table::BlockProof), 10);
    }

    #[test]
    fn prune_block_proofs_noop_when_tip_within_window() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::test_store_with_backend(backend.clone());

        for i in 0..10u64 {
            insert_header(backend.as_ref(), root(i), i, H256::ZERO);
        }

        // Early chain: tip < BLOCK_PROOF_PRUNING_RANGE → cutoff saturates to 0,
        // so nothing is old enough to prune even though slots are finalized.
        let pruned_below_slot = store.prune_old_block_proofs(9, 9).expect("prune");
        assert_eq!(pruned_below_slot, 0);
        assert_eq!(count_entries(backend.as_ref(), Table::BlockProof), 10);
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

    /// A child of `anchor` at `slot`, inheriting its `config` and
    /// `validators` rather than starting a fresh, unrelated
    /// `State::from_genesis`.
    ///
    /// `StateDiff` omits both fields, trusting they never change from parent
    /// to child, so a diff chain built on a child from an unrelated fixture
    /// would still reconstruct using the *real* anchor's values: a test that
    /// compared against the fixture's own (different) values would be
    /// checking a premise the store never held, whether or not that
    /// happened to matter for what it asserted.
    fn child_of(anchor: &State, slot: u64, parent_root: H256, hbh: Vec<H256>) -> State {
        let mut child = anchor.clone();
        child.slot = slot;
        child.latest_block_header = header_at(slot, parent_root);
        child.historical_block_hashes = hbh.try_into().unwrap();
        child
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
        store
            .insert_state(r1, BeaconState::Lean(s1.clone()))
            .expect("insert state");

        // Hot path: the just-imported state is memoized in the cache, readable
        // immediately regardless of whether the writer thread has committed
        // it yet.
        assert_eq!(
            store
                .get_state(&r1)
                .expect("get state")
                .expect("state exists")
                .to_ssz(),
            s1.to_ssz()
        );

        // A cold store (empty cache, shared backend) reconstructs from the
        // diff, byte-identically. Dropping the writing store first joins its
        // writer thread, which is what settles the backend.
        drop(store);
        let cold = Store::test_store_with_backend(backend.clone());
        let reconstructed = cold
            .get_state(&r1)
            .expect("reconstructs from diff")
            .expect("state exists");
        assert_eq!(reconstructed.to_ssz(), s1.to_ssz());
    }

    /// A state that only the handoff buffer holds is still readable. The LRU
    /// is cleared first, so a pass here cannot come from the cache, and the
    /// backend was never written for this root, so it cannot come from disk.
    #[test]
    fn a_pending_state_is_readable_without_the_cache_or_the_backend() {
        let backend = Arc::new(InMemoryBackend::new());
        let store = Store::test_store_with_backend(backend.clone());

        let s = sample_state(1, H256::ZERO, vec![]);
        let r = s.latest_block_header.hash_tree_root();
        store
            .pending_states
            .insert(r, Arc::new(BeaconState::Lean(s.clone())));
        store.state_cache.lock().unwrap().clear();

        assert!(store.has_state(&r).expect("has_state"));
        assert_eq!(
            store
                .get_state(&r)
                .expect("get state")
                .expect("pending state is readable")
                .to_ssz(),
            s.to_ssz()
        );
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
        store
            .insert_state(r1, BeaconState::Lean(s1.clone()))
            .expect("insert state");

        let s2 = sample_state(2, r1, vec![r0, r1]);
        let r2 = s2.latest_block_header.hash_tree_root();
        insert_header(backend.as_ref(), r2, 2, r1);
        store
            .insert_state(r2, BeaconState::Lean(s2.clone()))
            .expect("insert state");

        // Neither child is an anchor, so a cold store reconstructs s2 by walking
        // the diff chain back to the s0 snapshot. Dropping the writing store
        // first joins its writer thread, which is what settles the backend.
        drop(store);
        let cold = Store::test_store_with_backend(backend.clone());
        let reconstructed = cold
            .get_state(&r2)
            .expect("reconstructs across diffs")
            .expect("state exists");
        assert_eq!(reconstructed.to_ssz(), s2.to_ssz());
    }

    /// Dropping the store joins the writer, so every state inserted through
    /// it is on the backend afterwards and a fresh store reads them all back.
    ///
    /// The chain is longer than the writer's queue capacity, but that does not
    /// make this a test of the blocking send path or of commit ordering: these
    /// are small in-memory lean states the worker drains faster than the loop
    /// can fill the queue, and the lean parent lookup goes through the shared
    /// LRU rather than the backend, so an out-of-order commit would still
    /// pass here. What this actually proves is narrower and still the point
    /// of the task: drop joins the writer, and every write made it to the
    /// backend by the time a fresh store reads it back.
    #[test]
    fn dropping_the_store_settles_every_queued_write() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::test_store_with_backend(backend.clone());

        let s0 = sample_state(0, H256::ZERO, vec![]);
        let r0 = s0.latest_block_header.hash_tree_root();
        insert_header(backend.as_ref(), r0, 0, H256::ZERO);
        insert_snapshot(backend.as_ref(), r0, &s0);

        let mut parent = s0;
        let mut parent_root = r0;
        let mut expected = Vec::new();
        for slot in 1..=6u64 {
            let mut hbh = parent.historical_block_hashes.to_vec();
            hbh.push(parent_root);
            let state = sample_state(slot, parent_root, hbh);
            let root = state.latest_block_header.hash_tree_root();
            insert_header(backend.as_ref(), root, slot, parent_root);
            store
                .insert_state(root, BeaconState::Lean(state.clone()))
                .expect("insert state");
            expected.push((root, state.clone()));
            parent = state;
            parent_root = root;
        }

        drop(store);

        let cold = Store::test_store_with_backend(backend.clone());
        for (root, state) in expected {
            assert_eq!(
                cold.get_state(&root)
                    .expect("reconstructs from the settled backend")
                    .expect("state exists")
                    .to_ssz(),
                state.to_ssz(),
            );
        }
    }

    // ============ State Value Fork Tagging Tests ============

    #[test]
    fn states_values_carry_a_fork_selector() {
        let backend = Arc::new(InMemoryBackend::new());
        let store = Store::from_anchor_state(
            backend.clone(),
            State::from_genesis(7, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );
        let anchor = store.head().expect("head root");

        let view = backend.begin_read().expect("read view");
        let value = view
            .get(Table::States, &anchor.to_ssz())
            .expect("get")
            .expect("anchor snapshot written at bootstrap");
        assert_eq!(value[0], ForkName::Lean.selector());
    }

    // ============ Beacon State Persistence Tests ============

    /// A minimal phase0 beacon state at `slot`, with an empty validator
    /// registry. Nothing under test here reads validators or history, so
    /// every fixed-length vector is filled with zeroes rather than built out
    /// with real content, mirroring `beacon_test_block`'s "phase0-shaped,
    /// nothing fork-specific" approach.
    fn beacon_test_state(slot: u64) -> BeaconState {
        use ethlambda_types::beacon::containers::phase0;
        use ethlambda_types::beacon::preset;

        BeaconState::Phase0(phase0::BeaconState {
            genesis_time: 0,
            genesis_validators_root: H256::ZERO,
            slot,
            fork: Default::default(),
            latest_block_header: Default::default(),
            block_roots: vec![H256::ZERO; preset::SLOTS_PER_HISTORICAL_ROOT]
                .try_into()
                .expect("the vector is built at its exact length"),
            state_roots: vec![H256::ZERO; preset::SLOTS_PER_HISTORICAL_ROOT]
                .try_into()
                .expect("the vector is built at its exact length"),
            historical_roots: Default::default(),
            eth1_data: Default::default(),
            eth1_data_votes: Default::default(),
            eth1_deposit_index: 0,
            validators: Default::default(),
            balances: Default::default(),
            randao_mixes: vec![H256::ZERO; preset::EPOCHS_PER_HISTORICAL_VECTOR]
                .try_into()
                .expect("the vector is built at its exact length"),
            slashings: vec![0; preset::EPOCHS_PER_SLASHINGS_VECTOR]
                .try_into()
                .expect("the vector is built at its exact length"),
            previous_epoch_attestations: Default::default(),
            current_epoch_attestations: Default::default(),
            justification_bits: Default::default(),
            previous_justified_checkpoint: Default::default(),
            current_justified_checkpoint: Default::default(),
            finalized_checkpoint: Default::default(),
        })
    }

    #[test]
    fn a_beacon_state_round_trips_through_the_states_table() {
        let mut store = beacon_test_store(Arc::new(InMemoryBackend::new()));
        let root = H256::from([1u8; 32]);
        let state = beacon_test_state(7);

        store
            .insert_state(root, state.clone())
            .expect("insert beacon state");

        let read = store.get_state(&root).expect("get").expect("state present");
        assert_eq!(read.fork_name(), state.fork_name());
        assert_eq!(read.slot(), 7);
    }

    #[test]
    fn a_beacon_state_with_no_known_parent_block_is_its_own_snapshot() {
        // A bootstrap or checkpoint-sync anchor is the store's first-ever
        // beacon state: its parent block was never imported here, so there is
        // no base to diff against and `insert_state` must fall back to an
        // unconditional snapshot rather than panicking on a missing parent.
        let mut store = beacon_test_store(Arc::new(InMemoryBackend::new()));
        let orphan_root = H256::from([9u8; 32]);

        store
            .insert_state(orphan_root, beacon_test_state(42))
            .expect("insert");

        // Nothing else was inserted, so this can only succeed if the value is
        // self-contained.
        assert_eq!(
            store
                .get_state(&orphan_root)
                .expect("get")
                .expect("present")
                .slot(),
            42
        );
    }

    #[test]
    fn a_beacon_state_read_misses_cleanly_for_an_unknown_root() {
        let store = beacon_test_store(Arc::new(InMemoryBackend::new()));
        assert!(
            store
                .get_state(&H256::from([5u8; 32]))
                .expect("get")
                .is_none()
        );
    }

    #[test]
    fn the_state_cache_is_shared_across_store_clones() {
        let store = beacon_test_store(Arc::new(InMemoryBackend::new()));
        let clone = store.clone();
        let key = CacheKey::BlockState(H256::from([1u8; 32]));

        clone.cache_state(key, Arc::new(beacon_test_state(7)));
        assert!(store.cached_state(key).is_some());
    }

    #[test]
    fn the_state_cache_is_bounded() {
        let store = beacon_test_store(Arc::new(InMemoryBackend::new()));
        for i in 0..(STATE_CACHE_CAPACITY + 4) {
            let mut bytes = [0u8; 32];
            bytes[0] = i as u8;
            let key = CacheKey::BlockState(H256::from(bytes));
            store.cache_state(key, Arc::new(beacon_test_state(i as u64)));
        }
        // The bound is the whole point: the beacon fork choice previously held
        // whole states in maps with no cap at all.
        let oldest = CacheKey::BlockState(H256::from([0u8; 32]));
        assert!(store.cached_state(oldest).is_none());
    }

    #[test]
    fn block_and_checkpoint_states_share_one_bound() {
        // Two kinds in one cache, so a single capacity bounds the total. Keyed
        // distinctly, so a checkpoint state never masquerades as a block state.
        let store = beacon_test_store(Arc::new(InMemoryBackend::new()));
        let root = H256::from([2u8; 32]);

        store.cache_state(CacheKey::BlockState(root), Arc::new(beacon_test_state(1)));
        store.cache_state(
            CacheKey::CheckpointState { epoch: 5, root },
            Arc::new(beacon_test_state(2)),
        );

        assert_eq!(
            store
                .cached_state(CacheKey::BlockState(root))
                .expect("block state")
                .slot(),
            1
        );
        assert_eq!(
            store
                .cached_state(CacheKey::CheckpointState { epoch: 5, root })
                .expect("checkpoint state")
                .slot(),
            2
        );
        // The same root at a different epoch is a different entry, since a
        // checkpoint's root is the last block at or before its boundary slot.
        assert!(
            store
                .cached_state(CacheKey::CheckpointState { epoch: 6, root })
                .is_none()
        );
    }

    #[test]
    fn a_beacon_state_read_is_served_from_the_cache_the_second_time() {
        let mut store = beacon_test_store(Arc::new(InMemoryBackend::new()));
        let root = H256::from([3u8; 32]);
        store
            .insert_state(root, beacon_test_state(9))
            .expect("insert");

        // Both reads must agree; the second one is the cached path.
        let first = store.get_state(&root).expect("get").expect("present");
        let second = store.get_state(&root).expect("get").expect("present");
        assert_eq!(first.slot(), 9);
        assert_eq!(second.slot(), 9);
        assert!(store.cached_state(CacheKey::BlockState(root)).is_some());
    }

    /// `beacon_test_state` with its parent linked in, the way `insert_state`'s
    /// beacon arm expects: it reads the base to diff against off the
    /// post-state's own `latest_block_header.parent_root`, mirroring how the
    /// lean arm already recovers its base.
    fn beacon_test_state_with_parent(slot: u64, parent_root: H256) -> BeaconState {
        let mut state = beacon_test_state(slot);
        state.latest_block_header_mut().parent_root = parent_root;
        state
    }

    #[test]
    fn a_beacon_state_reconstructs_across_a_whole_snapshot_interval() {
        let mut store = beacon_test_store(Arc::new(InMemoryBackend::new()));
        let interval = ForkName::Electra.snapshot_interval();

        // A chain one slot longer than the interval, so the walk crosses a
        // snapshot boundary and the fold has real work to do.
        let mut roots = Vec::new();
        let mut parent = H256::ZERO;
        for slot in 0..=interval {
            let root = H256::from([(slot + 1) as u8; 32]);
            let block = beacon_test_block(slot, parent);
            store
                .insert_signed_block(root, block)
                .expect("insert block");
            store
                .insert_state(root, beacon_test_state_with_parent(slot, parent))
                .expect("insert state");
            roots.push((root, slot));
            parent = root;
        }

        for (root, slot) in roots {
            let state = store.get_state(&root).expect("get").expect("present");
            assert_eq!(state.slot(), slot, "wrong state for root at slot {slot}");
        }
    }

    #[test]
    fn a_beacon_delta_chain_writes_snapshots_only_at_the_interval() {
        // The point of the delta layer: one snapshot per interval, not one per
        // block. A full mainnet snapshot per block is what this replaces.
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = beacon_test_store(backend.clone());
        let interval = ForkName::Electra.snapshot_interval();

        let mut parent = H256::ZERO;
        for slot in 0..interval {
            let root = H256::from([(slot + 1) as u8; 32]);
            store
                .insert_signed_block(root, beacon_test_block(slot, parent))
                .expect("insert block");
            store
                .insert_state(root, beacon_test_state_with_parent(slot, parent))
                .expect("insert state");
            parent = root;
        }

        // Dropping the store joins the writer, which is what settles the
        // backend; counting rows against an unsettled writer would only make
        // this one-sided assertion easier to pass, not harder.
        drop(store);
        let view = backend.begin_read().expect("read view");
        let snapshots = view
            .prefix_iterator(Table::States, &[])
            .expect("iterator")
            .filter_map(Result::ok)
            .count();
        assert!(
            snapshots < interval as usize,
            "expected fewer snapshots than blocks, got {snapshots} for {interval} blocks"
        );
    }

    // ============ PayloadBuffer Tests ============

    fn make_proof() -> SingleMessageAggregate {
        use ethlambda_types::attestation::AggregationBits;
        SingleMessageAggregate::empty(AggregationBits::new())
    }

    /// Create a proof with a specific validator bit set (distinct participants).
    fn make_proof_for_validator(vid: usize) -> SingleMessageAggregate {
        use ethlambda_types::attestation::AggregationBits;
        let mut bits = AggregationBits::with_length(vid + 1).unwrap();
        bits.set(vid, true).unwrap();
        SingleMessageAggregate::empty(bits)
    }

    /// Create a proof with bits set for every validator in `vids`.
    fn make_proof_for_validators(vids: &[u64]) -> SingleMessageAggregate {
        use ethlambda_types::attestation::AggregationBits;
        let max = vids.iter().copied().max().unwrap_or(0) as usize;
        let mut bits = AggregationBits::with_length(max + 1).unwrap();
        for &v in vids {
            bits.set(v as usize, true).unwrap();
        }
        SingleMessageAggregate::empty(bits)
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
            HashedAttestationData::new(data.clone()),
            make_proof_for_validator(1),
        );

        assert_eq!(store.new_payloads.lock().unwrap().len(), 1);
        assert_eq!(store.known_payloads.lock().unwrap().len(), 0);
        assert_eq!(store.extract_latest_new_attestations()[&0], data);
        assert_eq!(store.extract_latest_new_attestations()[&1], data);
        assert!(store.extract_latest_known_attestations().is_empty());

        store.promote_new_aggregated_payloads();

        assert_eq!(store.new_payloads.lock().unwrap().len(), 0);
        assert_eq!(store.known_payloads.lock().unwrap().len(), 1);
        assert!(store.extract_latest_new_attestations().is_empty());
        assert_eq!(store.extract_latest_known_attestations()[&0], data);
        assert_eq!(store.extract_latest_known_attestations()[&1], data);
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
        store.insert_known_aggregated_payloads_batch(vec![(
            HashedAttestationData::new(stale),
            make_proof_for_validators(&[1]),
        )]);
        store.insert_new_aggregated_payload(
            HashedAttestationData::new(fresh.clone()),
            make_proof_for_validators(&[2]),
        );
        store.insert_known_aggregated_payloads_batch(vec![(
            HashedAttestationData::new(fresh),
            make_proof_for_validators(&[3]),
        )]);

        assert_eq!(store.new_aggregated_payloads_count(), 2);
        assert_eq!(store.known_aggregated_payloads_count(), 2);

        // Finalized slot 5: stale (target.slot == 2) is dropped from both buffers.
        let pruned = store.prune_stale_aggregated_payloads(5);
        assert_eq!(pruned, 2);
        assert_eq!(store.new_aggregated_payloads_count(), 1);
        assert_eq!(store.known_aggregated_payloads_count(), 1);
    }

    #[test]
    fn known_votes_survive_payload_fifo_eviction() {
        let mut store = Store::test_store();
        let vote = make_att_data_for_target(100, root(100));
        let vote_root = vote.hash_tree_root();

        store.insert_known_aggregated_payloads_batch(vec![(
            HashedAttestationData::new(vote.clone()),
            make_proof_for_validator(0),
        )]);

        for i in 0..=AGGREGATED_PAYLOAD_CAP {
            let slot = i as u64 + 1;
            let data = make_att_data_for_target(slot, root(1_000 + slot));
            store.insert_known_aggregated_payloads_batch(vec![(
                HashedAttestationData::new(data),
                make_proof_for_validator(1),
            )]);
        }

        assert!(
            !store
                .known_payloads
                .lock()
                .unwrap()
                .data
                .contains_key(&vote_root)
        );
        assert_eq!(store.extract_latest_known_attestations()[&0], vote);
    }

    #[test]
    fn known_votes_survive_finalized_payload_pruning() {
        let mut store = Store::test_store();
        let stale = make_att_data_for_target(2, root(2));
        let fresh = make_att_data_for_target(10, root(10));

        store.insert_known_aggregated_payloads_batch(vec![(
            HashedAttestationData::new(stale.clone()),
            make_proof_for_validator(0),
        )]);
        store.insert_known_aggregated_payloads_batch(vec![(
            HashedAttestationData::new(fresh.clone()),
            make_proof_for_validator(1),
        )]);

        assert_eq!(store.prune_stale_aggregated_payloads(5), 1);
        let votes = store.extract_latest_known_attestations();
        assert_eq!(votes[&0], stale);
        assert_eq!(votes[&1], fresh);
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
        use ethlambda_crypto::signature::LeanSignatureScheme;
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

    /// `Store::from_anchor_state` writes the header but no `BlockProof`
    /// row for the slot-0 anchor. `get_signed_block` must synthesize an empty
    /// proof so the genesis block can still be served on BlocksByRoot /
    /// `/lean/v0/blocks/finalized`.
    #[test]
    fn get_signed_block_synthesizes_blank_proof_for_genesis_anchor() {
        let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new());
        let store = Store::from_anchor_state(
            backend,
            State::from_genesis(0, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );

        let head_root = store.head().expect("head root must exist");
        let signed = store
            .get_signed_block(&head_root)
            .expect("genesis block must be retrievable with synthetic proof")
            .expect("genesis block must be retrievable with synthetic proof");
        let SignedBeaconBlock::Lean(signed) = signed else {
            panic!("a lean store must read back a lean block");
        };

        assert_eq!(signed.message.slot, 0);
        assert_eq!(signed.proof, MultiMessageAggregate::default());
    }

    /// The synthesis branch must be confined to the slot-0 anchor: a
    /// non-genesis block whose `BlockProof` row is missing is treated
    /// as storage corruption and surfaces as `None`, not a fabricated block.
    #[test]
    fn get_signed_block_returns_none_for_non_genesis_with_missing_proof() {
        let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new());

        // Hand-insert a slot-1 header (and empty body, via `EMPTY_BODY_ROOT`)
        // but skip the `BlockProof` row. This mimics the corruption case
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

        let store = Store::from_anchor_state(
            backend,
            State::from_genesis(0, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );
        assert!(
            store
                .get_signed_block(&root)
                .expect("Failed to get signed block")
                .is_none()
        );
    }

    /// The bootstrap anchor is stored as a full snapshot in `States`, the base of
    /// every diff chain that reconstruction terminates at.
    #[test]
    fn from_anchor_state_stores_bootstrap_snapshot() {
        let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new());
        let store = Store::from_anchor_state(
            backend.clone(),
            State::from_genesis(0, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );

        let anchor_root = store.head().expect("Failed to get head block root");
        assert!(has_key(backend.as_ref(), Table::States, &anchor_root));
    }

    // ============ from_db_state Tests ============

    #[test]
    fn from_db_state_is_none_on_an_untouched_backend() {
        let backend = Arc::new(InMemoryBackend::new());

        assert!(Store::from_db_state(backend).unwrap().is_none());
    }

    #[test]
    fn from_db_state_loads_a_lean_directory_as_lean() {
        let backend = Arc::new(InMemoryBackend::new());
        Store::from_anchor_state(
            backend.clone(),
            State::from_genesis(0, Vec::new()),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );

        let store = Store::from_db_state(backend).unwrap().unwrap();

        assert_eq!(store.chain(), Chain::Lean);
    }

    /// A beacon directory loads rather than erroring: judging whether it is
    /// the chain the caller wanted is the caller's job now.
    #[test]
    fn from_db_state_loads_a_beacon_directory_as_beacon() {
        let backend = Arc::new(InMemoryBackend::new());
        let anchor = BeaconCheckpoint {
            epoch: 0,
            root: H256::from([1u8; 32]),
        };
        Store::init_beacon(
            backend.clone(),
            1_606_824_023,
            Config::mainnet(),
            anchor.root,
            Store::beacon_checkpoint_as_stored(anchor),
            0,
        );

        let mut store = Store::from_db_state(backend).unwrap().unwrap();

        assert_eq!(store.chain(), Chain::Beacon);
        assert_eq!(store.config().genesis_time, 1_606_824_023);

        // `init_beacon` alone seeds the head at the checkpoint root before
        // the anchor block/state pair that follows it is ever inserted, so
        // `repair_head` must leave a directory shaped exactly like this one
        // alone rather than reporting corruption; see its doc. Pinned here,
        // on purpose, rather than left to be covered incidentally by
        // whichever other test happens to build this shape.
        store.repair_head().expect("repair head leaves this alone");
        assert_eq!(store.head().expect("head"), anchor.root);
    }

    #[test]
    fn a_store_hands_back_the_runtime_config_it_persisted() {
        let backend = Arc::new(InMemoryBackend::new());
        let store = Store::from_anchor_state(
            backend.clone(),
            State::from_genesis(7, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );

        // Returned by value behind an Arc, so a caller can hold it across the
        // &mut Store that every beacon fork-choice entry point takes.
        let config = store.config();
        assert_eq!(config.genesis_time, 7);

        // A lean store's config is the lean preset: no beacon fork ever reads
        // as activated, which is what stops a beacon-shaped gate firing here.
        assert_eq!(
            config.altair_fork_epoch,
            ethlambda_types::beacon::constants::FAR_FUTURE_EPOCH
        );

        // And it survives a reopen through Metadata["config"].
        let reopened = Store::from_db_state(backend)
            .expect("reopen")
            .expect("populated directory");
        assert_eq!(reopened.config().genesis_time, 7);
    }

    // ============ Beacon Fork-Choice Scratch Tests ============

    #[test]
    fn fork_choice_scratch_is_shared_across_store_clones() {
        let store = Store::test_store();
        let mut clone = store.clone();

        // Shared behind a mutex like the payload buffers, so a handler holding
        // one clone sees what another wrote.
        clone.set_proposer_boost_root(H256::from([9u8; 32]));
        assert_eq!(store.proposer_boost_root(), H256::from([9u8; 32]));

        clone.insert_equivocating_index(42);
        assert!(store.is_equivocating(42));
        assert!(!store.is_equivocating(43));

        clone.set_block_timeliness(H256::from([1u8; 32]), true);
        assert_eq!(store.block_timeliness(&H256::from([1u8; 32])), Some(true));
        assert_eq!(store.block_timeliness(&H256::from([2u8; 32])), None);
    }

    #[test]
    fn latest_messages_skip_equivocators() {
        let mut store = Store::test_store();
        let message = LatestMessage {
            epoch: 3,
            root: H256::from([7u8; 32]),
        };

        store.set_latest_message(1, message);
        store.set_latest_message(2, message);
        store.insert_equivocating_index(2);

        // get_weight excludes an equivocator's vote entirely rather than
        // letting it count for either side of the fork it created, so the
        // filter belongs with the read.
        let mut seen = Vec::new();
        store.for_each_non_equivocating_latest_message(|index, _| seen.push(index));
        assert_eq!(seen, vec![1]);
    }

    #[test]
    fn a_pow_block_is_looked_up_by_its_own_hash() {
        let mut store = Store::test_store();
        let block = PowBlock {
            block_hash: H256::from([4u8; 32]),
            parent_hash: H256::from([3u8; 32]),
            total_difficulty: Uint256::from(99u64),
        };
        store.insert_beacon_pow_block(block);

        assert_eq!(
            store
                .beacon_pow_block(H256::from([4u8; 32]))
                .map(|b| b.parent_hash),
            Some(H256::from([3u8; 32]))
        );
        assert!(store.beacon_pow_block(H256::from([5u8; 32])).is_none());
    }

    #[test]
    fn a_payload_status_is_looked_up_by_the_execution_block_hash() {
        let mut store = Store::test_store();
        let status = PayloadStatusV1 {
            status: PayloadStatusEnum::Syncing,
            latest_valid_hash: None,
            validation_error: None,
        };

        store.insert_beacon_payload_status(ExecutionBlockHash::repeat_byte(4), status.clone());

        assert_eq!(
            store.beacon_payload_status(ExecutionBlockHash::repeat_byte(4)),
            Some(status)
        );
        assert_eq!(
            store.beacon_payload_status(ExecutionBlockHash::repeat_byte(5)),
            None
        );
    }

    #[test]
    fn optimistic_roots_round_trip_and_clear() {
        let mut store = Store::test_store();
        assert!(!store.is_beacon_optimistic(H256::repeat_byte(1)));
        assert!(!store.has_beacon_optimistic_roots());

        store.insert_beacon_optimistic_root(H256::repeat_byte(1), 7);
        assert!(store.is_beacon_optimistic(H256::repeat_byte(1)));
        assert!(store.has_beacon_optimistic_roots());

        store.remove_beacon_optimistic_root(H256::repeat_byte(1));
        assert!(!store.is_beacon_optimistic(H256::repeat_byte(1)));
        assert!(!store.has_beacon_optimistic_roots());
    }

    /// The set fills once per import while an execution client is state
    /// syncing, and neither `mark_validated` nor `invalidate_subtree` ever
    /// sees those roots, so finality is the only thing that empties it.
    #[test]
    fn optimistic_roots_prune_strictly_below_the_finalized_slot() {
        let mut store = Store::test_store();
        let below = H256::repeat_byte(1);
        let at = H256::repeat_byte(2);
        let above = H256::repeat_byte(3);
        store.insert_beacon_optimistic_root(below, 4);
        store.insert_beacon_optimistic_root(at, 5);
        store.insert_beacon_optimistic_root(above, 6);

        store.prune_beacon_optimistic_roots(5);

        assert!(!store.is_beacon_optimistic(below));
        assert!(store.is_beacon_optimistic(at));
        assert!(store.is_beacon_optimistic(above));
    }

    #[test]
    fn el_block_hashes_prune_strictly_below_the_finalized_slot() {
        let mut store = Store::test_store();
        let below = H256::repeat_byte(1);
        let at = H256::repeat_byte(2);
        let above = H256::repeat_byte(3);
        store.insert_beacon_el_block_hash(below, 4, ExecutionBlockHash::repeat_byte(0xa1));
        store.insert_beacon_el_block_hash(at, 5, ExecutionBlockHash::repeat_byte(0xa2));
        store.insert_beacon_el_block_hash(above, 6, ExecutionBlockHash::repeat_byte(0xa3));

        store.prune_beacon_el_block_hashes(5, at);

        // Slot 4 is gone; the finalized block itself (slot 5) is kept, because
        // forkchoiceUpdated needs its hash for `finalized_block_hash`.
        assert_eq!(store.beacon_el_block_hash(below), None);
        assert_eq!(
            store.beacon_el_block_hash(at),
            Some(ExecutionBlockHash::repeat_byte(0xa2))
        );
        assert_eq!(
            store.beacon_el_block_hash(above),
            Some(ExecutionBlockHash::repeat_byte(0xa3))
        );
    }

    /// A checkpoint names the last block at *or before* its epoch boundary, so
    /// a missed proposal there puts the finalized block below the slot the
    /// checkpoint is stored as. The slot bound alone would drop exactly the
    /// hash `forkchoiceUpdated` sends as `finalized_block_hash`.
    #[test]
    fn el_block_hashes_keep_the_finalized_root_below_a_skipped_epoch_boundary() {
        let mut store = Store::test_store();
        let finalized = H256::repeat_byte(1);
        let stale = H256::repeat_byte(2);
        let head = H256::repeat_byte(3);
        // Slot 30 proposed, 31 skipped: the epoch that starts at 32 finalizes
        // with its checkpoint root still sitting at slot 30.
        store.insert_beacon_el_block_hash(finalized, 30, ExecutionBlockHash::repeat_byte(0xb1));
        store.insert_beacon_el_block_hash(stale, 29, ExecutionBlockHash::repeat_byte(0xb2));
        store.insert_beacon_el_block_hash(head, 33, ExecutionBlockHash::repeat_byte(0xb3));

        store.prune_beacon_el_block_hashes(32, finalized);

        assert_eq!(
            store.beacon_el_block_hash(finalized),
            Some(ExecutionBlockHash::repeat_byte(0xb1)),
            "the finalized checkpoint's own hash must survive its epoch's prune"
        );
        assert_eq!(store.beacon_el_block_hash(stale), None);
        assert_eq!(
            store.beacon_el_block_hash(head),
            Some(ExecutionBlockHash::repeat_byte(0xb3))
        );
    }

    #[test]
    fn a_fresh_beacon_store_seeds_every_key_its_accessors_read() {
        let backend = Arc::new(InMemoryBackend::new());
        let config = Config::mainnet();
        let store = Store::init_beacon(
            backend,
            1_606_824_023,
            config,
            H256::ZERO,
            Checkpoint::default(),
            0,
        );

        assert_eq!(store.chain(), Chain::Beacon);
        assert_eq!(store.config().genesis_time, 1_606_824_023);

        // Every beacon key an accessor reads must be seeded, or the first read
        // panics. This is the test that makes get_metadata's panic honest.
        // Seeded at genesis rather than at zero: `KEY_TIME` is an absolute Unix
        // millisecond on both chains, so genesis is the value that means "the
        // clock has not moved yet".
        assert_eq!(store.time_ms().expect("time"), 1_606_824_023 * 1_000);
        assert_eq!(store.current_slot(), 0);
        assert_eq!(
            store.beacon_justified_checkpoint(),
            BeaconCheckpoint::default()
        );
        assert_eq!(
            store.beacon_finalized_checkpoint(),
            BeaconCheckpoint::default()
        );
        assert_eq!(
            store.beacon_unrealized_justified_checkpoint(),
            BeaconCheckpoint::default()
        );
        assert_eq!(
            store.beacon_unrealized_finalized_checkpoint(),
            BeaconCheckpoint::default()
        );
        // Seeded, unlike every other beacon key: the anchor is the store's
        // first head. `beacon_head` still answers `None` here, because it
        // pairs that root with the slot from its own header row and this
        // store has no block under the zero root yet.
        assert_eq!(store.head().expect("head"), H256::ZERO);
        assert_eq!(store.beacon_head(), None);
    }

    #[test]
    fn finalized_state_root_answers_on_a_lean_directory() {
        let backend = Arc::new(InMemoryBackend::new());
        let state = State::from_genesis(0, Vec::new());
        let store = Store::from_anchor_state(backend, state, DEFAULT_MILLISECONDS_PER_SLOT);

        let root = store.finalized_state_root().unwrap();

        assert_eq!(root, store.latest_finalized().unwrap().root);
    }

    #[test]
    fn finalized_state_root_answers_on_a_beacon_directory() {
        let anchor = BeaconCheckpoint {
            epoch: 4,
            root: H256::from([5u8; 32]),
        };
        let store = Store::init_beacon(
            Arc::new(InMemoryBackend::new()),
            0,
            Config::mainnet(),
            anchor.root,
            Store::beacon_checkpoint_as_stored(anchor),
            0,
        );

        assert_eq!(store.finalized_state_root().unwrap(), anchor.root);
    }

    /// A directory whose checkpoint names no root was written and never
    /// anchored. There is nothing to resume from, and it is not an empty
    /// directory either.
    #[test]
    fn finalized_state_root_rejects_a_directory_with_no_anchor() {
        let store = Store::init_beacon(
            Arc::new(InMemoryBackend::new()),
            0,
            Config::mainnet(),
            H256::ZERO,
            Store::beacon_checkpoint_as_stored(BeaconCheckpoint::default()),
            0,
        );

        assert!(matches!(
            store.finalized_state_root(),
            Err(Error::UnanchoredDirectory)
        ));
    }

    #[test]
    fn the_beacon_clock_head_and_checkpoints_round_trip() {
        // Anchored at a block the store then holds, mirroring
        // `get_forkchoice_store`: the head row names the anchor from
        // bootstrap on, and moving off it diffs the canonical index across
        // both branches, so the anchor's own header has to be there.
        let anchor = beacon_test_block(0, H256::ZERO);
        let anchor_root = anchor.message_hash_tree_root();
        let mut store = Store::init_beacon(
            Arc::new(InMemoryBackend::new()),
            0,
            Config::mainnet(),
            anchor_root,
            Checkpoint::default(),
            0,
        );
        store
            .insert_signed_block(anchor_root, anchor)
            .expect("insert anchor");

        // Metadata["time"] is one Unix-millisecond row for both chains, so it
        // means the same thing here as on a lean directory, and the beacon
        // handlers convert to the specification's seconds at their own edges
        // rather than the store keeping a second unit for them.
        store.set_time_ms(1_606_824_023_000).expect("set time");
        assert_eq!(store.time_ms().expect("time"), 1_606_824_023_000);

        // The realized pair lives in lean's own rows, slot-denominated: an
        // epoch is stored as its start slot and divides back out exactly. The
        // head is passed through unchanged here, which is what a
        // checkpoint-only advance looks like on the beacon arm.
        let cp = BeaconCheckpoint {
            epoch: 3,
            root: H256::from([7u8; 32]),
        };
        let stored = Store::beacon_checkpoint_as_stored(cp);
        assert_eq!(stored.slot, 3 * SLOTS_PER_EPOCH);
        store
            .update_checkpoints(ForkCheckpoints::new(anchor_root, Some(stored), None))
            .expect("advance justified");
        assert_eq!(store.beacon_justified_checkpoint(), cp);
        assert_eq!(store.beacon_head(), Some((0, anchor_root)));

        // A real head move: derived from `KEY_HEAD` plus that block's own
        // header row, so the slot comes back with it.
        let child = beacon_test_block(9, anchor_root);
        let child_root = child.message_hash_tree_root();
        store
            .insert_signed_block(child_root, child)
            .expect("insert child");
        store
            .update_checkpoints(ForkCheckpoints::head_only(child_root))
            .expect("record head");
        assert_eq!(store.beacon_head(), Some((9, child_root)));
        assert_eq!(store.head().expect("head"), child_root);
    }

    #[test]
    fn an_unrealized_justification_is_scratch_not_chain_history() {
        // Shared across clones of one `Store`, since the scratch sits behind
        // an `Arc`, but gone once the process reopens the directory: a
        // restarted node refills the map as it re-imports the unfinalized
        // window.
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = beacon_test_store(backend.clone());
        let root = H256::from([1u8; 32]);
        let cp = BeaconCheckpoint {
            epoch: 5,
            root: H256::from([2u8; 32]),
        };

        store.set_unrealized_justification(root, cp);
        assert_eq!(store.unrealized_justification(&root), Some(cp));
        assert_eq!(store.unrealized_justification(&H256::from([3u8; 32])), None);
        assert_eq!(store.clone().unrealized_justification(&root), Some(cp));

        let reopened = beacon_test_store(backend);
        assert_eq!(reopened.unrealized_justification(&root), None);
    }

    // ============ Data Column Tests ============

    fn sidecar_bytes(marker: u8) -> Vec<u8> {
        vec![marker; 16]
    }

    #[test]
    fn a_sidecar_round_trips_by_slot_root_and_index() {
        let store = beacon_test_store(Arc::new(InMemoryBackend::new()));
        let root = H256::repeat_byte(1);
        store
            .put_data_column_sidecar(7, &root, 3, sidecar_bytes(0xab))
            .unwrap();
        assert_eq!(
            store.get_data_column_sidecar(7, &root, 3).unwrap(),
            Some(sidecar_bytes(0xab))
        );
        assert_eq!(store.get_data_column_sidecar(7, &root, 4).unwrap(), None);
    }

    #[test]
    fn a_parked_sidecar_is_invisible_to_the_verified_table() {
        // The separation the availability gate rests on: `PendingDataColumns`
        // holds rows nothing has verified, and `data_column_indices_for` is
        // what decides whether a held block's custody set is complete.
        let store = beacon_test_store(Arc::new(InMemoryBackend::new()));
        let root = H256::repeat_byte(1);
        store
            .put_pending_data_column_sidecar(7, &root, 3, sidecar_bytes(0xab))
            .unwrap();

        assert_eq!(
            store.data_column_indices_for(7, &root).unwrap(),
            Vec::<u64>::new()
        );
        assert_eq!(store.get_data_column_sidecar(7, &root, 3).unwrap(), None);
    }

    #[test]
    fn taking_a_parked_sidecar_hands_it_back_once() {
        let store = beacon_test_store(Arc::new(InMemoryBackend::new()));
        let root = H256::repeat_byte(1);
        store
            .put_pending_data_column_sidecar(7, &root, 3, sidecar_bytes(0xab))
            .unwrap();

        assert_eq!(
            store.take_pending_data_column_sidecar(7, &root, 3).unwrap(),
            Some(sidecar_bytes(0xab))
        );
        assert_eq!(
            store.take_pending_data_column_sidecar(7, &root, 3).unwrap(),
            None,
            "the row goes with the read, so a replayed key cannot be replayed twice"
        );
    }

    #[test]
    fn clearing_the_parked_table_spares_nothing_and_touches_no_other_table() {
        // Run at startup, when the in-memory index into this table is gone.
        // The bound has to cover an all-ones key too, which a `u64::MAX` slot
        // prefix would sort before rather than delete.
        let store = beacon_test_store(Arc::new(InMemoryBackend::new()));
        let root = H256::repeat_byte(1);
        let extreme = H256::repeat_byte(0xff);
        store
            .put_pending_data_column_sidecar(0, &root, 0, sidecar_bytes(1))
            .unwrap();
        store
            .put_pending_data_column_sidecar(u64::MAX, &extreme, u64::MAX, sidecar_bytes(2))
            .unwrap();
        store
            .put_data_column_sidecar(7, &root, 3, sidecar_bytes(3))
            .unwrap();

        store.clear_pending_data_column_sidecars().unwrap();

        assert_eq!(
            store.take_pending_data_column_sidecar(0, &root, 0).unwrap(),
            None
        );
        assert_eq!(
            store
                .take_pending_data_column_sidecar(u64::MAX, &extreme, u64::MAX)
                .unwrap(),
            None
        );
        assert_eq!(
            store.get_data_column_sidecar(7, &root, 3).unwrap(),
            Some(sidecar_bytes(3)),
            "the verified table is not what a restart throws away"
        );
    }

    #[test]
    fn the_indices_of_one_block_are_listed_in_order() {
        let store = beacon_test_store(Arc::new(InMemoryBackend::new()));
        let root = H256::repeat_byte(2);
        for index in [9, 1, 4] {
            store
                .put_data_column_sidecar(11, &root, index, sidecar_bytes(index as u8))
                .unwrap();
        }
        // A sibling block at the same slot must not leak into the answer.
        store
            .put_data_column_sidecar(11, &H256::repeat_byte(3), 7, sidecar_bytes(7))
            .unwrap();

        assert_eq!(
            store.data_column_indices_for(11, &root).unwrap(),
            vec![1, 4, 9]
        );
    }

    #[test]
    fn the_anchor_slot_survives_a_resume_and_no_write_moves_it() {
        // The whole reason this is persisted rather than derived: by the time a
        // resumed store reads it back, `latest_finalized` has moved off the
        // anchor, and storing sidecars must not be able to move it either.
        let backend = Arc::new(InMemoryBackend::new());
        let store = Store::init_beacon(
            backend.clone(),
            0,
            Config::mainnet(),
            H256::ZERO,
            Checkpoint::default(),
            4_096,
        );
        assert_eq!(store.anchor_slot(), 4_096);

        let root = H256::repeat_byte(4);
        for slot in [4_200, 4_100, 9_000] {
            store
                .put_data_column_sidecar(slot, &root, 0, sidecar_bytes(1))
                .unwrap();
        }
        assert_eq!(store.anchor_slot(), 4_096);

        let resumed = Store::from_db_state(backend).unwrap().unwrap();
        assert_eq!(resumed.anchor_slot(), 4_096);
    }

    #[test]
    fn a_genesis_bootstrapped_lean_store_anchors_at_zero() {
        let store = Store::from_anchor_state(
            Arc::new(InMemoryBackend::new()),
            State::from_genesis(0, Vec::new()),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );
        assert_eq!(store.anchor_slot(), 0);
    }

    /// A beacon store with a real anchor block behind its head, unlike
    /// `beacon_test_store`'s bare zero-root stub: `update_checkpoints` walks
    /// back from the old head to find the common ancestor with the new one,
    /// and that walk needs a block entry for whatever root it starts from.
    /// The data-column range tests below need to move the head, since
    /// `data_column_sidecars_in_range` now reads `Table::BlockRoots` to learn
    /// each slot's canonical root.
    fn beacon_test_store_with_anchor() -> Store {
        let mut store = beacon_test_store(Arc::new(InMemoryBackend::new()));
        store
            .insert_signed_block(H256::ZERO, beacon_test_block(0, H256::ZERO))
            .expect("insert anchor block");
        store
    }

    /// Inserts `block` and advances the store's head to its root, so the
    /// slot it names reads back as canonical from `Table::BlockRoots`: what
    /// `update_checkpoints` maintains on every head move, on both chains.
    fn make_canonical(store: &mut Store, block: SignedBeaconBlock) -> H256 {
        let root = block.message_hash_tree_root();
        store.insert_signed_block(root, block).expect("insert");
        store
            .update_checkpoints(ForkCheckpoints::head_only(root))
            .expect("advance head");
        root
    }

    #[test]
    fn sidecars_are_scanned_in_slot_order_across_a_range() {
        // A real linear chain, not three siblings of the anchor: advancing
        // the head to `root_3` in one move is what makes slots 1, 2 and 3 all
        // canonical at once, since `update_checkpoints` walks every
        // intermediate ancestor on its way back to the common ancestor with
        // the old head.
        let mut store = beacon_test_store_with_anchor();
        let block_1 = beacon_test_block(1, H256::ZERO);
        let root_1 = block_1.message_hash_tree_root();
        store.insert_signed_block(root_1, block_1).expect("insert");
        let block_2 = beacon_test_block(2, root_1);
        let root_2 = block_2.message_hash_tree_root();
        store.insert_signed_block(root_2, block_2).expect("insert");
        let root_3 = make_canonical(&mut store, beacon_test_block(3, root_2));

        for (slot, root) in [(1, root_1), (2, root_2), (3, root_3)] {
            store
                .put_data_column_sidecar(slot, &root, 0, sidecar_bytes(slot as u8))
                .unwrap();
        }
        let found = store.data_column_sidecars_in_range(1, 3, &[0]).unwrap();
        assert_eq!(found.len(), 2, "the range is half open: [1, 3)");
        assert_eq!(found[0], sidecar_bytes(1));
        assert_eq!(found[1], sidecar_bytes(2));
    }

    #[test]
    fn the_range_query_returns_exactly_the_requested_columns() {
        // Every existing test before this one wrote and queried only column
        // index 0, so an inverted or dropped column filter would have passed
        // the whole suite regardless.
        let mut store = beacon_test_store_with_anchor();
        let root = make_canonical(&mut store, beacon_test_block(9, H256::ZERO));
        for index in [0, 1, 2, 3] {
            store
                .put_data_column_sidecar(9, &root, index, sidecar_bytes(0x10 + index as u8))
                .unwrap();
        }

        let found = store.data_column_sidecars_in_range(9, 10, &[1, 2]).unwrap();

        // Columns 0 and 3 must not appear at all.
        assert_eq!(found, vec![sidecar_bytes(0x11), sidecar_bytes(0x12)]);
    }

    #[test]
    fn a_sibling_roots_columns_never_leak_into_a_range_answer() {
        // Gossip import only requires a sidecar's block to name a known,
        // finalized-descendant parent, not a canonical one, so a live fork
        // can leave both siblings' columns stored at one slot. The
        // specification asks a range response to be "consistent from a
        // single chain within the context of the request": only the
        // canonical root's columns may come back, even though this node
        // holds both.
        let mut store = beacon_test_store_with_anchor();
        let canonical_root = make_canonical(&mut store, beacon_test_block(9, H256::ZERO));

        let mut sibling = match beacon_test_block(9, H256::ZERO) {
            SignedBeaconBlock::Phase0(block) => block,
            other => panic!("expected phase0, got {}", other.fork_name()),
        };
        sibling.message.body.graffiti = H256::repeat_byte(0xee);
        let sibling = SignedBeaconBlock::Phase0(sibling);
        let sibling_root = sibling.message_hash_tree_root();
        assert_ne!(
            sibling_root, canonical_root,
            "the fixture's premise changed"
        );
        store
            .insert_signed_block(sibling_root, sibling)
            .expect("insert sibling, never made canonical");

        store
            .put_data_column_sidecar(9, &canonical_root, 1, sidecar_bytes(0xaa))
            .unwrap();
        store
            .put_data_column_sidecar(9, &sibling_root, 1, sidecar_bytes(0xbb))
            .unwrap();

        let found = store.data_column_sidecars_in_range(9, 10, &[1]).unwrap();
        assert_eq!(found, vec![sidecar_bytes(0xaa)]);
    }

    #[test]
    fn deleting_live_chain_entries_removes_exactly_those_roots() {
        let mut store = Store::test_store();
        let kept = H256::repeat_byte(1);
        let removed = H256::repeat_byte(2);

        store.insert_live_chain_entry(9, kept, H256::ZERO);
        store.insert_live_chain_entry(9, removed, H256::ZERO);
        assert_eq!(store.block_index().len(), 2);

        store.delete_live_chain_entries(&[(9, removed)]);

        let index = store.block_index();
        assert!(index.contains_key(&kept));
        assert!(!index.contains_key(&removed));
    }
}
