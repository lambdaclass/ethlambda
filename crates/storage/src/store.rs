use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, LazyLock, Mutex};

/// The tree hash root of an empty block body.
///
/// Used to detect genesis/anchor blocks that have no attestations,
/// allowing us to skip storing empty bodies and reconstruct them on read.
static EMPTY_BODY_ROOT: LazyLock<H256> = LazyLock::new(|| BlockBody::default().tree_hash_root());

use crate::api::{StorageBackend, StorageWriteBatch, Table};
use crate::types::{StoredAggregatedPayload, StoredSignature};

use ethlambda_types::{
    attestation::AttestationData,
    block::{
        Block, BlockBody, BlockHeader, BlockSignaturesWithAttestation, BlockWithAttestation,
        SignedBlockWithAttestation,
    },
    checkpoint::Checkpoint,
    primitives::{
        H256,
        ssz::{Decode, Encode, TreeHash},
    },
    signature::ValidatorSignature,
    state::{ChainConfig, State},
};
use tracing::info;

/// Key for looking up individual validator signatures.
/// Used to index signature caches by (validator, message) pairs.
///
/// Values are (validator_index, attestation_data_root).
pub type SignatureKey = (u64, H256);

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

/// ~1 day of block history at 4-second slots (86400 / 4 = 21600).
const BLOCKS_TO_KEEP: usize = 21_600;

/// ~1 hour of state history at 4-second slots (3600 / 4 = 900).
const STATES_TO_KEEP: usize = 900;

const _: () = assert!(
    BLOCKS_TO_KEEP >= STATES_TO_KEEP,
    "BLOCKS_TO_KEEP must be >= STATES_TO_KEEP"
);

/// Hard cap for the known aggregated payload buffer.
/// Matches Lantern's approach. With 9 validators, this holds
/// ~455 unique attestation messages (~30 min at 1/slot).
const AGGREGATED_PAYLOAD_CAP: usize = 4096;

/// Hard cap for the new (pending) aggregated payload buffer.
/// Smaller than known since new payloads are drained every interval (~4s).
/// With 9 validators at 1 attestation/slot, one interval holds ~9 entries.
const NEW_PAYLOAD_CAP: usize = 512;

/// Fixed-size circular buffer for aggregated payloads.
///
/// Entries are evicted FIFO when the buffer reaches capacity.
/// This prevents unbounded memory growth when finalization stalls.
#[derive(Clone)]
struct PayloadBuffer {
    entries: VecDeque<(SignatureKey, StoredAggregatedPayload)>,
    capacity: usize,
}

impl PayloadBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Insert one entry, FIFO-evicting the oldest if at capacity.
    fn push(&mut self, key: SignatureKey, payload: StoredAggregatedPayload) {
        if self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back((key, payload));
    }

    /// Insert multiple entries, FIFO-evicting as needed.
    fn push_batch(&mut self, entries: Vec<(SignatureKey, StoredAggregatedPayload)>) {
        for (key, payload) in entries {
            self.push(key, payload);
        }
    }

    /// Take all entries, leaving the buffer empty.
    fn drain(&mut self) -> Vec<(SignatureKey, StoredAggregatedPayload)> {
        self.entries.drain(..).collect()
    }

    /// Group entries by key, preserving insertion order within each group.
    fn grouped(&self) -> HashMap<SignatureKey, Vec<StoredAggregatedPayload>> {
        let mut map: HashMap<SignatureKey, Vec<StoredAggregatedPayload>> = HashMap::new();
        for (key, payload) in &self.entries {
            map.entry(*key).or_default().push(payload.clone());
        }
        map
    }

    /// Return deduplicated keys.
    fn unique_keys(&self) -> HashSet<SignatureKey> {
        self.entries.iter().map(|(key, _)| *key).collect()
    }
}

// ============ Key Encoding Helpers ============

/// Encode a SignatureKey (validator_id, root) to bytes.
/// Layout: validator_id (8 bytes SSZ) || root (32 bytes SSZ)
fn encode_signature_key(key: &SignatureKey) -> Vec<u8> {
    let mut result = key.0.as_ssz_bytes();
    result.extend(key.1.as_ssz_bytes());
    result
}

/// Decode a SignatureKey from bytes.
fn decode_signature_key(bytes: &[u8]) -> SignatureKey {
    let validator_id = u64::from_ssz_bytes(&bytes[..8]).expect("valid validator_id");
    let root = H256::from_ssz_bytes(&bytes[8..]).expect("valid root");
    (validator_id, root)
}

/// Encode a LiveChain key (slot, root) to bytes.
/// Layout: slot (8 bytes big-endian) || root (32 bytes)
/// Big-endian ensures lexicographic ordering matches numeric ordering.
fn encode_live_chain_key(slot: u64, root: &H256) -> Vec<u8> {
    let mut result = slot.to_be_bytes().to_vec();
    result.extend_from_slice(&root.0);
    result
}

/// Decode a LiveChain key from bytes.
fn decode_live_chain_key(bytes: &[u8]) -> (u64, H256) {
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
}

impl Store {
    /// Initialize a Store from an anchor state only.
    ///
    /// Uses the state's `latest_block_header` as the anchor block header.
    /// No block body is stored since it's not available.
    pub fn from_anchor_state(backend: Arc<dyn StorageBackend>, anchor_state: State) -> Self {
        Self::init_store(backend, anchor_state, None)
    }

    /// Initialize a Store from an anchor state and block.
    ///
    /// The block must match the state's `latest_block_header`.
    /// Named to mirror the spec's `get_forkchoice_store` function.
    ///
    /// # Panics
    ///
    /// Panics if the block's header doesn't match the state's `latest_block_header`
    /// (comparing all fields except `state_root`, which is computed internally).
    pub fn get_forkchoice_store(
        backend: Arc<dyn StorageBackend>,
        anchor_state: State,
        anchor_block: Block,
    ) -> Self {
        // Compare headers with state_root zeroed (init_store handles state_root separately)
        let mut state_header = anchor_state.latest_block_header.clone();
        let mut block_header = anchor_block.header();
        state_header.state_root = H256::ZERO;
        block_header.state_root = H256::ZERO;

        assert_eq!(
            state_header, block_header,
            "block header doesn't match state's latest_block_header"
        );

        Self::init_store(backend, anchor_state, Some(anchor_block.body))
    }

    /// Internal helper to initialize the store with anchor data.
    ///
    /// Header is taken from `anchor_state.latest_block_header`.
    fn init_store(
        backend: Arc<dyn StorageBackend>,
        mut anchor_state: State,
        anchor_body: Option<BlockBody>,
    ) -> Self {
        // Save original state_root for validation
        let original_state_root = anchor_state.latest_block_header.state_root;

        // Zero out state_root before computing (state contains header, header contains state_root)
        anchor_state.latest_block_header.state_root = H256::ZERO;

        // Compute state root with zeroed header
        let anchor_state_root = anchor_state.tree_hash_root();

        // Validate: original must be zero (genesis) or match computed (checkpoint sync)
        assert!(
            original_state_root == H256::ZERO || original_state_root == anchor_state_root,
            "anchor header state_root mismatch: expected {anchor_state_root:?}, got {original_state_root:?}"
        );

        // Populate the correct state_root
        anchor_state.latest_block_header.state_root = anchor_state_root;

        let anchor_block_root = anchor_state.latest_block_header.tree_hash_root();

        let anchor_checkpoint = Checkpoint {
            root: anchor_block_root,
            slot: anchor_state.latest_block_header.slot,
        };

        // Insert initial data
        {
            let mut batch = backend.begin_write().expect("write batch");

            // Metadata
            let metadata_entries = vec![
                (KEY_TIME.to_vec(), 0u64.as_ssz_bytes()),
                (KEY_CONFIG.to_vec(), anchor_state.config.as_ssz_bytes()),
                (KEY_HEAD.to_vec(), anchor_block_root.as_ssz_bytes()),
                (KEY_SAFE_TARGET.to_vec(), anchor_block_root.as_ssz_bytes()),
                (
                    KEY_LATEST_JUSTIFIED.to_vec(),
                    anchor_checkpoint.as_ssz_bytes(),
                ),
                (
                    KEY_LATEST_FINALIZED.to_vec(),
                    anchor_checkpoint.as_ssz_bytes(),
                ),
            ];
            batch
                .put_batch(Table::Metadata, metadata_entries)
                .expect("put metadata");

            // Block header
            let header_entries = vec![(
                anchor_block_root.as_ssz_bytes(),
                anchor_state.latest_block_header.as_ssz_bytes(),
            )];
            batch
                .put_batch(Table::BlockHeaders, header_entries)
                .expect("put block header");

            // Block body (if provided)
            if let Some(body) = anchor_body {
                let body_entries = vec![(anchor_block_root.as_ssz_bytes(), body.as_ssz_bytes())];
                batch
                    .put_batch(Table::BlockBodies, body_entries)
                    .expect("put block body");
            }

            // State
            let state_entries = vec![(
                anchor_block_root.as_ssz_bytes(),
                anchor_state.as_ssz_bytes(),
            )];
            batch
                .put_batch(Table::States, state_entries)
                .expect("put state");

            // Live chain index
            let index_entries = vec![(
                encode_live_chain_key(anchor_state.latest_block_header.slot, &anchor_block_root),
                anchor_state.latest_block_header.parent_root.as_ssz_bytes(),
            )];
            batch
                .put_batch(Table::LiveChain, index_entries)
                .expect("put live chain index");

            batch.commit().expect("commit");
        }

        info!(%anchor_state_root, %anchor_block_root, "Initialized store");

        Self {
            backend,
            new_payloads: Arc::new(Mutex::new(PayloadBuffer::new(NEW_PAYLOAD_CAP))),
            known_payloads: Arc::new(Mutex::new(PayloadBuffer::new(AGGREGATED_PAYLOAD_CAP))),
        }
    }

    // ============ Metadata Helpers ============

    fn get_metadata<T: Decode>(&self, key: &[u8]) -> T {
        let view = self.backend.begin_read().expect("read view");
        let bytes = view
            .get(Table::Metadata, key)
            .expect("get")
            .expect("metadata key exists");
        T::from_ssz_bytes(&bytes).expect("valid encoding")
    }

    fn set_metadata<T: Encode>(&self, key: &[u8], value: &T) {
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .put_batch(Table::Metadata, vec![(key.to_vec(), value.as_ssz_bytes())])
            .expect("put metadata");
        batch.commit().expect("commit");
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
    pub fn set_time(&mut self, time: u64) {
        self.set_metadata(KEY_TIME, &time);
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
    pub fn set_safe_target(&mut self, safe_target: H256) {
        self.set_metadata(KEY_SAFE_TARGET, &safe_target);
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
    pub fn update_checkpoints(&mut self, checkpoints: ForkCheckpoints) {
        // Read old finalized slot before updating metadata
        let old_finalized_slot = self.latest_finalized().slot;

        let mut entries = vec![(KEY_HEAD.to_vec(), checkpoints.head.as_ssz_bytes())];

        if let Some(justified) = checkpoints.justified {
            entries.push((KEY_LATEST_JUSTIFIED.to_vec(), justified.as_ssz_bytes()));
        }

        if let Some(finalized) = checkpoints.finalized {
            entries.push((KEY_LATEST_FINALIZED.to_vec(), finalized.as_ssz_bytes()));
        }

        let mut batch = self.backend.begin_write().expect("write batch");
        batch.put_batch(Table::Metadata, entries).expect("put");
        batch.commit().expect("commit");

        // Prune after successful checkpoint update
        if let Some(finalized) = checkpoints.finalized
            && finalized.slot > old_finalized_slot
        {
            let pruned_chain = self.prune_live_chain(finalized.slot);

            // Prune signatures and attestation data for finalized slots
            let pruned_sigs = self.prune_gossip_signatures(finalized.slot);
            let pruned_att_data = self.prune_attestation_data_by_root(finalized.slot);
            // Prune old states before blocks: state pruning uses headers for slot lookup
            let protected_roots = [finalized.root, self.latest_justified().root];
            let pruned_states = self.prune_old_states(&protected_roots);
            let pruned_blocks = self.prune_old_blocks(&protected_roots);

            if pruned_chain > 0
                || pruned_sigs > 0
                || pruned_att_data > 0
                || pruned_states > 0
                || pruned_blocks > 0
            {
                info!(
                    finalized_slot = finalized.slot,
                    pruned_chain,
                    pruned_sigs,
                    pruned_att_data,
                    pruned_states,
                    pruned_blocks,
                    "Pruned finalized data"
                );
            }
        } else {
            // Fallback pruning when finalization is stalled.
            // When finalization doesn't advance, the normal pruning path above never
            // triggers. Prune old states and blocks on every head update to keep
            // storage bounded. The prune methods are no-ops when within retention limits.
            let protected_roots = [self.latest_finalized().root, self.latest_justified().root];
            let pruned_states = self.prune_old_states(&protected_roots);
            let pruned_blocks = self.prune_old_blocks(&protected_roots);
            if pruned_states > 0 || pruned_blocks > 0 {
                info!(
                    pruned_states,
                    pruned_blocks, "Fallback pruning (finalization stalled)"
                );
            }
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
                let (slot, root) = decode_live_chain_key(&k);
                let parent_root = H256::from_ssz_bytes(&v).expect("valid parent_root");
                (root, (slot, parent_root))
            })
            .collect()
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
                let (_, root) = decode_live_chain_key(&k);
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
    pub fn prune_live_chain(&mut self, finalized_slot: u64) -> usize {
        let view = self.backend.begin_read().expect("read view");

        // Collect keys to delete - stop once we hit finalized_slot
        // Keys are sorted by slot (big-endian encoding) so we can stop early
        let keys_to_delete: Vec<_> = view
            .prefix_iterator(Table::LiveChain, &[])
            .expect("iterator")
            .filter_map(|res| res.ok())
            .take_while(|(k, _)| {
                let (slot, _) = decode_live_chain_key(k);
                slot < finalized_slot
            })
            .map(|(k, _)| k.to_vec())
            .collect();
        drop(view);

        let count = keys_to_delete.len();
        if count == 0 {
            return 0;
        }

        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .delete_batch(Table::LiveChain, keys_to_delete)
            .expect("delete non-finalized chain entries");
        batch.commit().expect("commit");
        count
    }

    /// Prune gossip signatures for slots <= finalized_slot.
    ///
    /// Returns the number of signatures pruned.
    pub fn prune_gossip_signatures(&mut self, finalized_slot: u64) -> usize {
        self.prune_by_slot(Table::GossipSignatures, finalized_slot, |bytes| {
            StoredSignature::from_ssz_bytes(bytes).ok().map(|s| s.slot)
        })
    }

    /// Prune attestation data by root for slots <= finalized_slot.
    ///
    /// Returns the number of entries pruned.
    pub fn prune_attestation_data_by_root(&mut self, finalized_slot: u64) -> usize {
        self.prune_by_slot(Table::AttestationDataByRoot, finalized_slot, |bytes| {
            AttestationData::from_ssz_bytes(bytes).ok().map(|d| d.slot)
        })
    }

    /// Prune old states beyond the retention window.
    ///
    /// Keeps the most recent `STATES_TO_KEEP` states (by slot), plus any
    /// states whose roots appear in `protected_roots` (finalized, justified).
    ///
    /// Returns the number of states pruned.
    pub fn prune_old_states(&mut self, protected_roots: &[H256]) -> usize {
        let view = self.backend.begin_read().expect("read view");

        // Collect (root_bytes, slot) from BlockHeaders to determine state age.
        let mut entries: Vec<(Vec<u8>, u64)> = view
            .prefix_iterator(Table::BlockHeaders, &[])
            .expect("iterator")
            .filter_map(|res| res.ok())
            .map(|(key, value)| {
                let header = BlockHeader::from_ssz_bytes(&value).expect("valid header");
                (key.to_vec(), header.slot)
            })
            .collect();
        drop(view);

        if entries.len() <= STATES_TO_KEEP {
            return 0;
        }

        // Sort by slot descending (newest first)
        entries.sort_unstable_by(|a, b| b.1.cmp(&a.1));

        let protected: HashSet<Vec<u8>> =
            protected_roots.iter().map(|r| r.as_ssz_bytes()).collect();

        // Skip the retention window, collect remaining keys for deletion
        let keys_to_delete: Vec<Vec<u8>> = entries
            .into_iter()
            .skip(STATES_TO_KEEP)
            .filter(|(key, _)| !protected.contains(key))
            .map(|(key, _)| key)
            .collect();

        let count = keys_to_delete.len();
        if count > 0 {
            let mut batch = self.backend.begin_write().expect("write batch");
            batch
                .delete_batch(Table::States, keys_to_delete)
                .expect("delete old states");
            batch.commit().expect("commit");
        }
        count
    }

    /// Prune old blocks beyond the retention window.
    ///
    /// Keeps the most recent `BLOCKS_TO_KEEP` blocks (by slot), plus any
    /// blocks whose roots appear in `protected_roots` (finalized, justified).
    /// Deletes from `BlockHeaders`, `BlockBodies`, and `BlockSignatures`.
    ///
    /// Returns the number of blocks pruned.
    pub fn prune_old_blocks(&mut self, protected_roots: &[H256]) -> usize {
        let view = self.backend.begin_read().expect("read view");

        let mut entries: Vec<(Vec<u8>, u64)> = view
            .prefix_iterator(Table::BlockHeaders, &[])
            .expect("iterator")
            .filter_map(|res| res.ok())
            .map(|(key, value)| {
                let header = BlockHeader::from_ssz_bytes(&value).expect("valid header");
                (key.to_vec(), header.slot)
            })
            .collect();
        drop(view);

        if entries.len() <= BLOCKS_TO_KEEP {
            return 0;
        }

        // Sort by slot descending (newest first)
        entries.sort_unstable_by(|a, b| b.1.cmp(&a.1));

        let protected: HashSet<Vec<u8>> =
            protected_roots.iter().map(|r| r.as_ssz_bytes()).collect();

        let keys_to_delete: Vec<Vec<u8>> = entries
            .into_iter()
            .skip(BLOCKS_TO_KEEP)
            .filter(|(key, _)| !protected.contains(key))
            .map(|(key, _)| key)
            .collect();

        let count = keys_to_delete.len();
        if count > 0 {
            let mut batch = self.backend.begin_write().expect("write batch");
            batch
                .delete_batch(Table::BlockHeaders, keys_to_delete.clone())
                .expect("delete old block headers");
            batch
                .delete_batch(Table::BlockBodies, keys_to_delete.clone())
                .expect("delete old block bodies");
            batch
                .delete_batch(Table::BlockSignatures, keys_to_delete)
                .expect("delete old block signatures");
            batch.commit().expect("commit");
        }
        count
    }

    /// Get the block header by root.
    pub fn get_block_header(&self, root: &H256) -> Option<BlockHeader> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::BlockHeaders, &root.as_ssz_bytes())
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
    pub fn insert_pending_block(&mut self, root: H256, signed_block: SignedBlockWithAttestation) {
        let mut batch = self.backend.begin_write().expect("write batch");
        write_signed_block(batch.as_mut(), &root, signed_block);
        batch.commit().expect("commit");
    }

    /// Insert a signed block, storing the block and signatures separately.
    ///
    /// Blocks and signatures are stored in separate tables because the genesis
    /// block has no signatures. This allows uniform storage of all blocks while
    /// only storing signatures for non-genesis blocks.
    ///
    /// Takes ownership to avoid cloning large signature data.
    pub fn insert_signed_block(&mut self, root: H256, signed_block: SignedBlockWithAttestation) {
        let mut batch = self.backend.begin_write().expect("write batch");
        let block = write_signed_block(batch.as_mut(), &root, signed_block);

        let index_entries = vec![(
            encode_live_chain_key(block.slot, &root),
            block.parent_root.as_ssz_bytes(),
        )];
        batch
            .put_batch(Table::LiveChain, index_entries)
            .expect("put non-finalized chain index");

        batch.commit().expect("commit");
    }

    /// Get a signed block by combining header, body, and signatures.
    ///
    /// Returns None if any of the components are not found.
    /// Note: Genesis block has no entry in BlockSignatures table.
    pub fn get_signed_block(&self, root: &H256) -> Option<SignedBlockWithAttestation> {
        let view = self.backend.begin_read().expect("read view");
        let key = root.as_ssz_bytes();

        let header_bytes = view.get(Table::BlockHeaders, &key).expect("get")?;
        let sig_bytes = view.get(Table::BlockSignatures, &key).expect("get")?;

        let header = BlockHeader::from_ssz_bytes(&header_bytes).expect("valid header");

        // Use empty body if header indicates empty, otherwise fetch from DB
        let body = if header.body_root == *EMPTY_BODY_ROOT {
            BlockBody::default()
        } else {
            let body_bytes = view.get(Table::BlockBodies, &key).expect("get")?;
            BlockBody::from_ssz_bytes(&body_bytes).expect("valid body")
        };

        let block = Block::from_header_and_body(header, body);
        let signatures =
            BlockSignaturesWithAttestation::from_ssz_bytes(&sig_bytes).expect("valid signatures");

        Some(signatures.to_signed_block(block))
    }

    // ============ States ============

    /// Returns the state for the given block root.
    pub fn get_state(&self, root: &H256) -> Option<State> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::States, &root.as_ssz_bytes())
            .expect("get")
            .map(|bytes| State::from_ssz_bytes(&bytes).expect("valid state"))
    }

    /// Returns whether a state exists for the given block root.
    pub fn has_state(&self, root: &H256) -> bool {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::States, &root.as_ssz_bytes())
            .expect("get")
            .is_some()
    }

    /// Stores a state indexed by block root.
    pub fn insert_state(&mut self, root: H256, state: State) {
        let mut batch = self.backend.begin_write().expect("write batch");
        let entries = vec![(root.as_ssz_bytes(), state.as_ssz_bytes())];
        batch.put_batch(Table::States, entries).expect("put state");
        batch.commit().expect("commit");
    }

    // ============ Attestation Data By Root ============
    //
    // Content-addressed attestation data storage. Used to reconstruct
    // per-validator attestation maps from aggregated payloads.

    /// Stores attestation data indexed by its tree hash root.
    pub fn insert_attestation_data_by_root(&mut self, root: H256, data: AttestationData) {
        let mut batch = self.backend.begin_write().expect("write batch");
        let entries = vec![(root.as_ssz_bytes(), data.as_ssz_bytes())];
        batch
            .put_batch(Table::AttestationDataByRoot, entries)
            .expect("put attestation data");
        batch.commit().expect("commit");
    }

    /// Batch-insert multiple attestation data entries in a single commit.
    pub fn insert_attestation_data_by_root_batch(&mut self, entries: Vec<(H256, AttestationData)>) {
        if entries.is_empty() {
            return;
        }
        let mut batch = self.backend.begin_write().expect("write batch");
        let ssz_entries = entries
            .into_iter()
            .map(|(root, data)| (root.as_ssz_bytes(), data.as_ssz_bytes()))
            .collect();
        batch
            .put_batch(Table::AttestationDataByRoot, ssz_entries)
            .expect("put attestation data batch");
        batch.commit().expect("commit");
    }

    /// Returns attestation data for the given root hash.
    pub fn get_attestation_data_by_root(&self, root: &H256) -> Option<AttestationData> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::AttestationDataByRoot, &root.as_ssz_bytes())
            .expect("get")
            .map(|bytes| AttestationData::from_ssz_bytes(&bytes).expect("valid attestation data"))
    }

    /// Reconstruct per-validator attestation data from aggregated payloads.
    ///
    /// For each (validator_id, data_root) key in the payloads, looks up the
    /// attestation data by root. Returns the latest attestation per validator
    /// (by slot).
    pub fn extract_latest_attestations(
        &self,
        keys: impl Iterator<Item = SignatureKey>,
    ) -> HashMap<u64, AttestationData> {
        let mut result: HashMap<u64, AttestationData> = HashMap::new();
        let mut data_cache: HashMap<H256, Option<AttestationData>> = HashMap::new();

        for (validator_id, data_root) in keys {
            let data = data_cache
                .entry(data_root)
                .or_insert_with(|| self.get_attestation_data_by_root(&data_root));

            let Some(data) = data else {
                continue;
            };

            let should_update = result
                .get(&validator_id)
                .is_none_or(|existing| existing.slot < data.slot);

            if should_update {
                result.insert(validator_id, data.clone());
            }
        }

        result
    }

    /// Convenience: extract latest attestation per validator from known
    /// (fork-choice-active) aggregated payloads only.
    pub fn extract_latest_known_attestations(&self) -> HashMap<u64, AttestationData> {
        let keys = self.known_payloads.lock().unwrap().unique_keys();
        self.extract_latest_attestations(keys.into_iter())
    }

    // ============ Known Aggregated Payloads ============
    //
    // "Known" aggregated payloads are active in fork choice weight calculations.
    // Promoted from "new" payloads at specific intervals (0 with proposal, 4).

    /// Iterates over all known aggregated payloads, grouped by key.
    pub fn iter_known_aggregated_payloads(
        &self,
    ) -> impl Iterator<Item = (SignatureKey, Vec<StoredAggregatedPayload>)> {
        self.known_payloads.lock().unwrap().grouped().into_iter()
    }

    /// Iterates over deduplicated keys from the known aggregated payloads.
    pub fn iter_known_aggregated_payload_keys(&self) -> impl Iterator<Item = SignatureKey> {
        self.known_payloads
            .lock()
            .unwrap()
            .unique_keys()
            .into_iter()
    }

    /// Insert an aggregated payload into the known (fork-choice-active) buffer.
    pub fn insert_known_aggregated_payload(
        &mut self,
        key: SignatureKey,
        payload: StoredAggregatedPayload,
    ) {
        self.known_payloads.lock().unwrap().push(key, payload);
    }

    /// Batch-insert multiple aggregated payloads into the known buffer.
    pub fn insert_known_aggregated_payloads_batch(
        &mut self,
        entries: Vec<(SignatureKey, StoredAggregatedPayload)>,
    ) {
        self.known_payloads.lock().unwrap().push_batch(entries);
    }

    // ============ New Aggregated Payloads ============
    //
    // "New" aggregated payloads are pending — not yet counted in fork choice.
    // Promoted to "known" via `promote_new_aggregated_payloads`.

    /// Iterates over all new (pending) aggregated payloads, grouped by key.
    pub fn iter_new_aggregated_payloads(
        &self,
    ) -> impl Iterator<Item = (SignatureKey, Vec<StoredAggregatedPayload>)> {
        self.new_payloads.lock().unwrap().grouped().into_iter()
    }

    /// Iterates over deduplicated keys from the new aggregated payloads.
    pub fn iter_new_aggregated_payload_keys(&self) -> impl Iterator<Item = SignatureKey> {
        self.new_payloads.lock().unwrap().unique_keys().into_iter()
    }

    /// Insert an aggregated payload into the new (pending) buffer.
    pub fn insert_new_aggregated_payload(
        &mut self,
        key: SignatureKey,
        payload: StoredAggregatedPayload,
    ) {
        self.new_payloads.lock().unwrap().push(key, payload);
    }

    /// Batch-insert multiple aggregated payloads into the new buffer.
    pub fn insert_new_aggregated_payloads_batch(
        &mut self,
        entries: Vec<(SignatureKey, StoredAggregatedPayload)>,
    ) {
        self.new_payloads.lock().unwrap().push_batch(entries);
    }

    // ============ Pruning Helpers ============

    /// Prune entries from a table where the slot (extracted via `get_slot`) is <= `finalized_slot`.
    /// Returns the number of entries pruned.
    fn prune_by_slot(
        &mut self,
        table: Table,
        finalized_slot: u64,
        get_slot: impl Fn(&[u8]) -> Option<u64>,
    ) -> usize {
        let view = self.backend.begin_read().expect("read view");
        let mut to_delete = vec![];

        for (key_bytes, value_bytes) in view
            .prefix_iterator(table, &[])
            .expect("iter")
            .filter_map(|r| r.ok())
        {
            if let Some(slot) = get_slot(&value_bytes)
                && slot <= finalized_slot
            {
                to_delete.push(key_bytes.to_vec());
            }
        }
        drop(view);

        let count = to_delete.len();
        if !to_delete.is_empty() {
            let mut batch = self.backend.begin_write().expect("write batch");
            batch.delete_batch(table, to_delete).expect("delete");
            batch.commit().expect("commit");
        }
        count
    }

    /// Promotes all new aggregated payloads to known, making them active in fork choice.
    ///
    /// Drains the new buffer and pushes all entries into the known buffer.
    pub fn promote_new_aggregated_payloads(&mut self) {
        let drained = self.new_payloads.lock().unwrap().drain();
        self.known_payloads.lock().unwrap().push_batch(drained);
    }

    /// Delete specific gossip signatures by key.
    pub fn delete_gossip_signatures(&mut self, keys: &[SignatureKey]) {
        if keys.is_empty() {
            return;
        }
        let encoded_keys: Vec<_> = keys.iter().map(encode_signature_key).collect();
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .delete_batch(Table::GossipSignatures, encoded_keys)
            .expect("delete gossip signatures");
        batch.commit().expect("commit");
    }

    // ============ Gossip Signatures ============
    //
    // Gossip signatures are individual validator signatures received via P2P.
    // They're aggregated into proofs for block signature verification.

    /// Iterates over all gossip signatures.
    pub fn iter_gossip_signatures(
        &self,
    ) -> impl Iterator<Item = (SignatureKey, StoredSignature)> + '_ {
        let view = self.backend.begin_read().expect("read view");
        let entries: Vec<_> = view
            .prefix_iterator(Table::GossipSignatures, &[])
            .expect("iterator")
            .filter_map(|res| res.ok())
            .filter_map(|(k, v)| {
                let key = decode_signature_key(&k);
                StoredSignature::from_ssz_bytes(&v)
                    .ok()
                    .map(|stored| (key, stored))
            })
            .collect();
        entries.into_iter()
    }

    /// Stores a gossip signature for later aggregation.
    pub fn insert_gossip_signature(
        &mut self,
        data_root: H256,
        slot: u64,
        validator_id: u64,
        signature: ValidatorSignature,
    ) {
        let key = (validator_id, data_root);

        let stored = StoredSignature::new(slot, signature);
        let mut batch = self.backend.begin_write().expect("write batch");
        let entries = vec![(encode_signature_key(&key), stored.as_ssz_bytes())];
        batch
            .put_batch(Table::GossipSignatures, entries)
            .expect("put signature");
        batch.commit().expect("commit");
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

/// Write block header, body, and signatures onto an existing batch.
///
/// Returns the deserialized [`Block`] so callers can access fields like
/// `slot` and `parent_root` without re-deserializing.
fn write_signed_block(
    batch: &mut dyn StorageWriteBatch,
    root: &H256,
    signed_block: SignedBlockWithAttestation,
) -> Block {
    let SignedBlockWithAttestation {
        message:
            BlockWithAttestation {
                block,
                proposer_attestation,
            },
        signature,
    } = signed_block;

    let signatures = BlockSignaturesWithAttestation {
        proposer_attestation,
        signatures: signature,
    };

    let header = block.header();
    let root_bytes = root.as_ssz_bytes();

    let header_entries = vec![(root_bytes.clone(), header.as_ssz_bytes())];
    batch
        .put_batch(Table::BlockHeaders, header_entries)
        .expect("put block header");

    // Skip storing empty bodies - they can be reconstructed from the header's body_root
    if header.body_root != *EMPTY_BODY_ROOT {
        let body_entries = vec![(root_bytes.clone(), block.body.as_ssz_bytes())];
        batch
            .put_batch(Table::BlockBodies, body_entries)
            .expect("put block body");
    }

    let sig_entries = vec![(root_bytes, signatures.as_ssz_bytes())];
    batch
        .put_batch(Table::BlockSignatures, sig_entries)
        .expect("put block signatures");

    block
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::InMemoryBackend;

    /// Insert a block header (and dummy body + signature) for a given root and slot.
    fn insert_header(backend: &dyn StorageBackend, root: H256, slot: u64) {
        let header = BlockHeader {
            slot,
            proposer_index: 0,
            parent_root: H256::ZERO,
            state_root: H256::ZERO,
            body_root: H256::ZERO,
        };
        let mut batch = backend.begin_write().expect("write batch");
        let key = root.as_ssz_bytes();
        batch
            .put_batch(
                Table::BlockHeaders,
                vec![(key.clone(), header.as_ssz_bytes())],
            )
            .expect("put header");
        batch
            .put_batch(Table::BlockBodies, vec![(key.clone(), vec![0u8; 4])])
            .expect("put body");
        batch
            .put_batch(Table::BlockSignatures, vec![(key, vec![0u8; 4])])
            .expect("put sigs");
        batch.commit().expect("commit");
    }

    /// Insert a dummy state for a given root.
    fn insert_state(backend: &dyn StorageBackend, root: H256) {
        let mut batch = backend.begin_write().expect("write batch");
        let key = root.as_ssz_bytes();
        batch
            .put_batch(Table::States, vec![(key, vec![0u8; 4])])
            .expect("put state");
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
        view.get(table, &root.as_ssz_bytes())
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
            }
        }

        /// Create a Store with a shared in-memory backend for tests that need
        /// direct backend access.
        fn test_store_with_backend(backend: Arc<InMemoryBackend>) -> Self {
            Self {
                backend,
                new_payloads: Arc::new(Mutex::new(PayloadBuffer::new(NEW_PAYLOAD_CAP))),
                known_payloads: Arc::new(Mutex::new(PayloadBuffer::new(AGGREGATED_PAYLOAD_CAP))),
            }
        }
    }

    // ============ Block Pruning Tests ============

    #[test]
    fn prune_old_blocks_within_retention() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::test_store_with_backend(backend.clone());

        // Insert exactly BLOCKS_TO_KEEP blocks
        for i in 0..BLOCKS_TO_KEEP as u64 {
            insert_header(backend.as_ref(), root(i), i);
        }
        assert_eq!(
            count_entries(backend.as_ref(), Table::BlockHeaders),
            BLOCKS_TO_KEEP
        );

        let pruned = store.prune_old_blocks(&[]);
        assert_eq!(pruned, 0);
        assert_eq!(
            count_entries(backend.as_ref(), Table::BlockHeaders),
            BLOCKS_TO_KEEP
        );
    }

    #[test]
    fn prune_old_blocks_exceeding_retention() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::test_store_with_backend(backend.clone());

        let total = BLOCKS_TO_KEEP + 10;
        for i in 0..total as u64 {
            insert_header(backend.as_ref(), root(i), i);
        }
        assert_eq!(count_entries(backend.as_ref(), Table::BlockHeaders), total);

        let pruned = store.prune_old_blocks(&[]);
        assert_eq!(pruned, 10);
        assert_eq!(
            count_entries(backend.as_ref(), Table::BlockHeaders),
            BLOCKS_TO_KEEP
        );
        assert_eq!(
            count_entries(backend.as_ref(), Table::BlockBodies),
            BLOCKS_TO_KEEP
        );
        assert_eq!(
            count_entries(backend.as_ref(), Table::BlockSignatures),
            BLOCKS_TO_KEEP
        );

        // Oldest blocks (slots 0..10) should be gone
        for i in 0..10u64 {
            assert!(!has_key(backend.as_ref(), Table::BlockHeaders, &root(i)));
        }
        // Newest blocks should still exist
        for i in 10..total as u64 {
            assert!(has_key(backend.as_ref(), Table::BlockHeaders, &root(i)));
        }
    }

    #[test]
    fn prune_old_blocks_preserves_protected() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::test_store_with_backend(backend.clone());

        let total = BLOCKS_TO_KEEP + 10;
        for i in 0..total as u64 {
            insert_header(backend.as_ref(), root(i), i);
        }

        // Protect the two oldest blocks (slots 0 and 1)
        let finalized_root = root(0);
        let justified_root = root(1);
        let pruned = store.prune_old_blocks(&[finalized_root, justified_root]);

        // 10 would be pruned, but 2 are protected
        assert_eq!(pruned, 8);
        assert!(has_key(
            backend.as_ref(),
            Table::BlockHeaders,
            &finalized_root
        ));
        assert!(has_key(
            backend.as_ref(),
            Table::BlockHeaders,
            &justified_root
        ));
        assert!(has_key(
            backend.as_ref(),
            Table::BlockBodies,
            &finalized_root
        ));
        assert!(has_key(
            backend.as_ref(),
            Table::BlockSignatures,
            &finalized_root
        ));
    }

    // ============ State Pruning Tests ============

    #[test]
    fn prune_old_states_within_retention() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::test_store_with_backend(backend.clone());

        // Insert STATES_TO_KEEP headers + states
        for i in 0..STATES_TO_KEEP as u64 {
            insert_header(backend.as_ref(), root(i), i);
            insert_state(backend.as_ref(), root(i));
        }
        assert_eq!(
            count_entries(backend.as_ref(), Table::States),
            STATES_TO_KEEP
        );

        let pruned = store.prune_old_states(&[]);
        assert_eq!(pruned, 0);
    }

    #[test]
    fn prune_old_states_exceeding_retention() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::test_store_with_backend(backend.clone());

        let total = STATES_TO_KEEP + 5;
        for i in 0..total as u64 {
            insert_header(backend.as_ref(), root(i), i);
            insert_state(backend.as_ref(), root(i));
        }
        assert_eq!(count_entries(backend.as_ref(), Table::States), total);

        let pruned = store.prune_old_states(&[]);
        assert_eq!(pruned, 5);
        assert_eq!(
            count_entries(backend.as_ref(), Table::States),
            STATES_TO_KEEP
        );

        // Oldest states should be gone
        for i in 0..5u64 {
            assert!(!has_key(backend.as_ref(), Table::States, &root(i)));
        }
        // Newest states should remain
        for i in 5..total as u64 {
            assert!(has_key(backend.as_ref(), Table::States, &root(i)));
        }
    }

    #[test]
    fn prune_old_states_preserves_protected() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::test_store_with_backend(backend.clone());

        let total = STATES_TO_KEEP + 5;
        for i in 0..total as u64 {
            insert_header(backend.as_ref(), root(i), i);
            insert_state(backend.as_ref(), root(i));
        }

        let finalized_root = root(0);
        let justified_root = root(2);
        let pruned = store.prune_old_states(&[finalized_root, justified_root]);

        // 5 would be pruned, but 2 are protected
        assert_eq!(pruned, 3);
        assert!(has_key(backend.as_ref(), Table::States, &finalized_root));
        assert!(has_key(backend.as_ref(), Table::States, &justified_root));
    }

    // ============ Periodic Pruning Tests ============

    /// Set up finalized and justified checkpoints in metadata.
    fn set_checkpoints(backend: &dyn StorageBackend, finalized: Checkpoint, justified: Checkpoint) {
        let mut batch = backend.begin_write().expect("write batch");
        batch
            .put_batch(
                Table::Metadata,
                vec![
                    (KEY_LATEST_FINALIZED.to_vec(), finalized.as_ssz_bytes()),
                    (KEY_LATEST_JUSTIFIED.to_vec(), justified.as_ssz_bytes()),
                ],
            )
            .expect("put checkpoints");
        batch.commit().expect("commit");
    }

    #[test]
    fn fallback_pruning_removes_old_states_and_blocks() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::test_store_with_backend(backend.clone());

        // Use roots that are within the retention window as finalized/justified
        let finalized_root = root(0);
        let justified_root = root(1);
        set_checkpoints(
            backend.as_ref(),
            Checkpoint {
                slot: 0,
                root: finalized_root,
            },
            Checkpoint {
                slot: 1,
                root: justified_root,
            },
        );

        // Insert more than STATES_TO_KEEP headers + states, but fewer than BLOCKS_TO_KEEP
        let total_states = STATES_TO_KEEP + 5;
        for i in 0..total_states as u64 {
            insert_header(backend.as_ref(), root(i), i);
            insert_state(backend.as_ref(), root(i));
        }

        assert_eq!(count_entries(backend.as_ref(), Table::States), total_states);
        assert_eq!(
            count_entries(backend.as_ref(), Table::BlockHeaders),
            total_states
        );

        // Use the last inserted root as head. Calling update_checkpoints with
        // head_only triggers the fallback path (finalization doesn't advance).
        let head_root = root(total_states as u64 - 1);
        store.update_checkpoints(ForkCheckpoints::head_only(head_root));

        // 905 headers total. Top 900 by slot are kept in the retention window,
        // leaving 5 candidates. 2 are protected (finalized + justified),
        // so 3 are pruned → 905 - 3 = 902 states remaining.
        assert_eq!(
            count_entries(backend.as_ref(), Table::States),
            STATES_TO_KEEP + 2
        );
        // Finalized and justified states must survive
        assert!(has_key(backend.as_ref(), Table::States, &finalized_root));
        assert!(has_key(backend.as_ref(), Table::States, &justified_root));

        // Blocks: total_states < BLOCKS_TO_KEEP, so no blocks should be pruned
        assert_eq!(
            count_entries(backend.as_ref(), Table::BlockHeaders),
            total_states
        );
    }

    #[test]
    fn fallback_pruning_no_op_within_retention() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::test_store_with_backend(backend.clone());

        set_checkpoints(
            backend.as_ref(),
            Checkpoint {
                slot: 0,
                root: root(0),
            },
            Checkpoint {
                slot: 0,
                root: root(0),
            },
        );

        // Insert exactly STATES_TO_KEEP entries (no excess)
        for i in 0..STATES_TO_KEEP as u64 {
            insert_header(backend.as_ref(), root(i), i);
            insert_state(backend.as_ref(), root(i));
        }

        // Use the last inserted root as head
        let head_root = root(STATES_TO_KEEP as u64 - 1);
        store.update_checkpoints(ForkCheckpoints::head_only(head_root));

        // Nothing should be pruned (within retention window)
        assert_eq!(
            count_entries(backend.as_ref(), Table::States),
            STATES_TO_KEEP
        );
        assert_eq!(
            count_entries(backend.as_ref(), Table::BlockHeaders),
            STATES_TO_KEEP
        );
    }

    // ============ PayloadBuffer Tests ============

    fn make_payload(slot: u64) -> StoredAggregatedPayload {
        use ethlambda_types::attestation::AggregationBits;
        use ethlambda_types::block::AggregatedSignatureProof;

        StoredAggregatedPayload {
            slot,
            proof: AggregatedSignatureProof::empty(AggregationBits::with_capacity(0).unwrap()),
        }
    }

    #[test]
    fn payload_buffer_fifo_eviction() {
        let mut buf = PayloadBuffer::new(3);
        let key = (0u64, H256::ZERO);

        buf.push(key, make_payload(1));
        buf.push(key, make_payload(2));
        buf.push(key, make_payload(3));
        assert_eq!(buf.entries.len(), 3);

        // Pushing a 4th entry should evict the oldest (slot 1)
        buf.push(key, make_payload(4));
        assert_eq!(buf.entries.len(), 3);
        let slots: Vec<u64> = buf.entries.iter().map(|(_, p)| p.slot).collect();
        assert_eq!(slots, vec![2, 3, 4]);
    }

    #[test]
    fn payload_buffer_grouped_returns_correct_groups() {
        let mut buf = PayloadBuffer::new(10);
        let key_a = (0u64, H256::ZERO);
        let key_b = (1u64, H256::ZERO);

        buf.push(key_a, make_payload(1));
        buf.push(key_b, make_payload(2));
        buf.push(key_a, make_payload(3));

        let grouped = buf.grouped();
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[&key_a].len(), 2);
        assert_eq!(grouped[&key_a][0].slot, 1);
        assert_eq!(grouped[&key_a][1].slot, 3);
        assert_eq!(grouped[&key_b].len(), 1);
        assert_eq!(grouped[&key_b][0].slot, 2);
    }

    #[test]
    fn payload_buffer_drain_empties_buffer() {
        let mut buf = PayloadBuffer::new(10);
        let key = (0u64, H256::ZERO);

        buf.push(key, make_payload(1));
        buf.push(key, make_payload(2));

        let drained = buf.drain();
        assert_eq!(drained.len(), 2);
        assert!(buf.entries.is_empty());
    }

    #[test]
    fn promote_moves_new_to_known() {
        let mut store = Store::test_store();

        let key = (0u64, H256::ZERO);
        store.insert_new_aggregated_payload(key, make_payload(1));
        store.insert_new_aggregated_payload(key, make_payload(2));

        assert_eq!(store.new_payloads.lock().unwrap().entries.len(), 2);
        assert_eq!(store.known_payloads.lock().unwrap().entries.len(), 0);

        store.promote_new_aggregated_payloads();

        assert_eq!(store.new_payloads.lock().unwrap().entries.len(), 0);
        assert_eq!(store.known_payloads.lock().unwrap().entries.len(), 2);
    }

    #[test]
    fn cloned_store_shares_payload_buffers() {
        let mut store = Store::test_store();
        let cloned = store.clone();

        let key = (0u64, H256::ZERO);
        store.insert_new_aggregated_payload(key, make_payload(1));

        // Modification on original should be visible in clone
        assert_eq!(cloned.new_payloads.lock().unwrap().entries.len(), 1);

        store.promote_new_aggregated_payloads();

        assert_eq!(cloned.new_payloads.lock().unwrap().entries.len(), 0);
        assert_eq!(cloned.known_payloads.lock().unwrap().entries.len(), 1);
    }
}
