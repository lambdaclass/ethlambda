use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};

/// The tree hash root of an empty block body.
///
/// Used to detect genesis/anchor blocks that have no attestations,
/// allowing us to skip storing empty bodies and reconstruct them on read.
static EMPTY_BODY_ROOT: LazyLock<H256> = LazyLock::new(|| BlockBody::default().tree_hash_root());

use crate::api::{StorageBackend, Table};
use crate::types::{StoredAggregatedPayload, StoredSignature};

use ethlambda_types::{
    attestation::AttestationData,
    block::{
        Block, BlockBody, BlockHeader, BlockSignaturesWithAttestation, BlockWithAttestation,
        SignedBlockWithAttestation,
    },
    primitives::{
        H256,
        ssz::{Decode, Encode, TreeHash},
    },
    signature::ValidatorSignature,
    state::{ChainConfig, Checkpoint, State},
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

        Self { backend }
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
            self.prune_live_chain(finalized.slot);

            // Prune signatures, payloads, and attestation data for finalized slots
            let pruned_sigs = self.prune_gossip_signatures(finalized.slot);
            let pruned_att_data = self.prune_attestation_data_by_root(finalized.slot);
            self.prune_aggregated_payload_table(Table::LatestNewAggregatedPayloads, finalized.slot);
            self.prune_aggregated_payload_table(
                Table::LatestKnownAggregatedPayloads,
                finalized.slot,
            );
            if pruned_sigs > 0 || pruned_att_data > 0 {
                info!(
                    finalized_slot = finalized.slot,
                    pruned_sigs, pruned_att_data, "Pruned finalized signatures"
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
    pub fn prune_live_chain(&mut self, finalized_slot: u64) {
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

        if keys_to_delete.is_empty() {
            return;
        }

        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .delete_batch(Table::LiveChain, keys_to_delete)
            .expect("delete non-finalized chain entries");
        batch.commit().expect("commit");
    }

    /// Prune gossip signatures for slots <= finalized_slot.
    ///
    /// Returns the number of signatures pruned.
    pub fn prune_gossip_signatures(&mut self, finalized_slot: u64) -> usize {
        let view = self.backend.begin_read().expect("read view");
        let mut to_delete = vec![];

        for (key_bytes, value_bytes) in view
            .prefix_iterator(Table::GossipSignatures, &[])
            .expect("iter")
            .filter_map(|r| r.ok())
        {
            if let Ok(stored) = StoredSignature::from_ssz_bytes(&value_bytes)
                && stored.slot <= finalized_slot
            {
                to_delete.push(key_bytes.to_vec());
            }
        }
        drop(view);

        let count = to_delete.len();
        if !to_delete.is_empty() {
            let mut batch = self.backend.begin_write().expect("write batch");
            batch
                .delete_batch(Table::GossipSignatures, to_delete)
                .expect("delete");
            batch.commit().expect("commit");
        }
        count
    }

    /// Prune attestation data by root for slots <= finalized_slot.
    ///
    /// Returns the number of entries pruned.
    pub fn prune_attestation_data_by_root(&mut self, finalized_slot: u64) -> usize {
        let view = self.backend.begin_read().expect("read view");
        let mut to_delete = vec![];

        for (key_bytes, value_bytes) in view
            .prefix_iterator(Table::AttestationDataByRoot, &[])
            .expect("iter")
            .filter_map(|r| r.ok())
        {
            if let Ok(data) = AttestationData::from_ssz_bytes(&value_bytes)
                && data.slot <= finalized_slot
            {
                to_delete.push(key_bytes.to_vec());
            }
        }
        drop(view);

        let count = to_delete.len();
        if !to_delete.is_empty() {
            let mut batch = self.backend.begin_write().expect("write batch");
            batch
                .delete_batch(Table::AttestationDataByRoot, to_delete)
                .expect("delete");
            batch.commit().expect("commit");
        }
        count
    }

    /// Prune an aggregated payload table (new or known) for slots <= finalized_slot.
    fn prune_aggregated_payload_table(&mut self, table: Table, finalized_slot: u64) {
        let view = self.backend.begin_read().expect("read view");
        let mut updates = vec![];
        let mut deletes = vec![];

        for (key_bytes, value_bytes) in view
            .prefix_iterator(table, &[])
            .expect("iter")
            .filter_map(|r| r.ok())
        {
            if let Ok(mut payloads) = Vec::<StoredAggregatedPayload>::from_ssz_bytes(&value_bytes) {
                let original_len = payloads.len();
                payloads.retain(|p| p.slot > finalized_slot);

                if payloads.is_empty() {
                    deletes.push(key_bytes.to_vec());
                } else if payloads.len() < original_len {
                    updates.push((key_bytes.to_vec(), payloads.as_ssz_bytes()));
                }
            }
        }
        drop(view);

        if !updates.is_empty() || !deletes.is_empty() {
            let mut batch = self.backend.begin_write().expect("write batch");
            if !updates.is_empty() {
                batch.put_batch(table, updates).expect("put");
            }
            if !deletes.is_empty() {
                batch.delete_batch(table, deletes).expect("delete");
            }
            batch.commit().expect("commit");
        }
    }

    /// Get the block header by root.
    pub fn get_block_header(&self, root: &H256) -> Option<BlockHeader> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::BlockHeaders, &root.as_ssz_bytes())
            .expect("get")
            .map(|bytes| BlockHeader::from_ssz_bytes(&bytes).expect("valid header"))
    }

    // ============ Signed Blocks ============

    /// Insert a signed block, storing the block and signatures separately.
    ///
    /// Blocks and signatures are stored in separate tables because the genesis
    /// block has no signatures. This allows uniform storage of all blocks while
    /// only storing signatures for non-genesis blocks.
    ///
    /// Takes ownership to avoid cloning large signature data.
    pub fn insert_signed_block(&mut self, root: H256, signed_block: SignedBlockWithAttestation) {
        // Destructure to extract all components without cloning
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

        let mut batch = self.backend.begin_write().expect("write batch");

        let header = block.header();
        let header_entries = vec![(root.as_ssz_bytes(), header.as_ssz_bytes())];
        batch
            .put_batch(Table::BlockHeaders, header_entries)
            .expect("put block header");

        // Skip storing empty bodies - they can be reconstructed from the header's body_root
        if header.body_root != *EMPTY_BODY_ROOT {
            let body_entries = vec![(root.as_ssz_bytes(), block.body.as_ssz_bytes())];
            batch
                .put_batch(Table::BlockBodies, body_entries)
                .expect("put block body");
        }

        let sig_entries = vec![(root.as_ssz_bytes(), signatures.as_ssz_bytes())];
        batch
            .put_batch(Table::BlockSignatures, sig_entries)
            .expect("put block signatures");

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

    /// Returns attestation data for the given root hash.
    pub fn get_attestation_data_by_root(&self, root: &H256) -> Option<AttestationData> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::AttestationDataByRoot, &root.as_ssz_bytes())
            .expect("get")
            .map(|bytes| AttestationData::from_ssz_bytes(&bytes).expect("valid attestation data"))
    }

    // ============ Known Aggregated Payloads ============
    //
    // "Known" aggregated payloads are active in fork choice weight calculations.
    // Promoted from "new" payloads at specific intervals (0 with proposal, 4).

    /// Iterates over all known aggregated payloads.
    pub fn iter_known_aggregated_payloads(
        &self,
    ) -> impl Iterator<Item = (SignatureKey, Vec<StoredAggregatedPayload>)> + '_ {
        let view = self.backend.begin_read().expect("read view");
        let entries: Vec<_> = view
            .prefix_iterator(Table::LatestKnownAggregatedPayloads, &[])
            .expect("iterator")
            .filter_map(|res| res.ok())
            .map(|(k, v)| {
                let key = decode_signature_key(&k);
                let payloads =
                    Vec::<StoredAggregatedPayload>::from_ssz_bytes(&v).expect("valid payloads");
                (key, payloads)
            })
            .collect();
        entries.into_iter()
    }

    /// Insert an aggregated payload into the known (fork-choice-active) table.
    pub fn insert_known_aggregated_payload(
        &mut self,
        key: SignatureKey,
        payload: StoredAggregatedPayload,
    ) {
        let encoded_key = encode_signature_key(&key);
        let view = self.backend.begin_read().expect("read view");
        let mut payloads: Vec<StoredAggregatedPayload> = view
            .get(Table::LatestKnownAggregatedPayloads, &encoded_key)
            .expect("get")
            .map(|bytes| Vec::<StoredAggregatedPayload>::from_ssz_bytes(&bytes).expect("valid"))
            .unwrap_or_default();
        drop(view);

        payloads.push(payload);

        let mut batch = self.backend.begin_write().expect("write batch");
        let entries = vec![(encoded_key, payloads.as_ssz_bytes())];
        batch
            .put_batch(Table::LatestKnownAggregatedPayloads, entries)
            .expect("put known aggregated payload");
        batch.commit().expect("commit");
    }

    // ============ New Aggregated Payloads ============
    //
    // "New" aggregated payloads are pending — not yet counted in fork choice.
    // Promoted to "known" via `promote_new_aggregated_payloads`.

    /// Iterates over all new (pending) aggregated payloads.
    pub fn iter_new_aggregated_payloads(
        &self,
    ) -> impl Iterator<Item = (SignatureKey, Vec<StoredAggregatedPayload>)> + '_ {
        let view = self.backend.begin_read().expect("read view");
        let entries: Vec<_> = view
            .prefix_iterator(Table::LatestNewAggregatedPayloads, &[])
            .expect("iterator")
            .filter_map(|res| res.ok())
            .map(|(k, v)| {
                let key = decode_signature_key(&k);
                let payloads =
                    Vec::<StoredAggregatedPayload>::from_ssz_bytes(&v).expect("valid payloads");
                (key, payloads)
            })
            .collect();
        entries.into_iter()
    }

    /// Insert an aggregated payload into the new (pending) table.
    pub fn insert_new_aggregated_payload(
        &mut self,
        key: SignatureKey,
        payload: StoredAggregatedPayload,
    ) {
        let encoded_key = encode_signature_key(&key);
        let view = self.backend.begin_read().expect("read view");
        let mut payloads: Vec<StoredAggregatedPayload> = view
            .get(Table::LatestNewAggregatedPayloads, &encoded_key)
            .expect("get")
            .map(|bytes| Vec::<StoredAggregatedPayload>::from_ssz_bytes(&bytes).expect("valid"))
            .unwrap_or_default();
        drop(view);

        payloads.push(payload);

        let mut batch = self.backend.begin_write().expect("write batch");
        let entries = vec![(encoded_key, payloads.as_ssz_bytes())];
        batch
            .put_batch(Table::LatestNewAggregatedPayloads, entries)
            .expect("put new aggregated payload");
        batch.commit().expect("commit");
    }

    /// Promotes all new aggregated payloads to known, making them active in fork choice.
    ///
    /// Merges entries from `LatestNewAggregatedPayloads` into `LatestKnownAggregatedPayloads`,
    /// appending to existing payload lists rather than overwriting them.
    pub fn promote_new_aggregated_payloads(&mut self) {
        let view = self.backend.begin_read().expect("read view");
        let new_entries: Vec<(Vec<u8>, Vec<u8>)> = view
            .prefix_iterator(Table::LatestNewAggregatedPayloads, &[])
            .expect("iterator")
            .filter_map(|res| res.ok())
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();

        if new_entries.is_empty() {
            drop(view);
            return;
        }

        // Merge new payloads with existing known payloads
        let merged: Vec<(Vec<u8>, Vec<u8>)> = new_entries
            .iter()
            .map(|(key, new_bytes)| {
                let new_payloads =
                    Vec::<StoredAggregatedPayload>::from_ssz_bytes(new_bytes).expect("valid");
                let mut known_payloads: Vec<StoredAggregatedPayload> = view
                    .get(Table::LatestKnownAggregatedPayloads, key)
                    .expect("get")
                    .map(|bytes| {
                        Vec::<StoredAggregatedPayload>::from_ssz_bytes(&bytes).expect("valid")
                    })
                    .unwrap_or_default();
                known_payloads.extend(new_payloads);
                (key.clone(), known_payloads.as_ssz_bytes())
            })
            .collect();
        drop(view);

        let keys_to_delete: Vec<_> = new_entries.into_iter().map(|(k, _)| k).collect();
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .delete_batch(Table::LatestNewAggregatedPayloads, keys_to_delete)
            .expect("delete new aggregated payloads");
        batch
            .put_batch(Table::LatestKnownAggregatedPayloads, merged)
            .expect("put known aggregated payloads");
        batch.commit().expect("commit");
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
        attestation_data: &AttestationData,
        validator_id: u64,
        signature: ValidatorSignature,
    ) {
        let slot = attestation_data.slot;
        let data_root = attestation_data.tree_hash_root();
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
