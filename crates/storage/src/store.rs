use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::api::{StorageBackend, Table};

use ethlambda_types::{
    attestation::AttestationData,
    block::{
        AggregatedSignatureProof, Block, BlockBody, BlockSignaturesWithAttestation,
        BlockWithAttestation, SignedBlockWithAttestation,
    },
    primitives::{Decode, Encode, H256, TreeHash},
    signature::{StoredAggregatedPayload, StoredSignature, ValidatorSignature},
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

/// Underlying storage of the node.
/// Similar to the spec's `Store`, but backed by a pluggable storage backend.
///
/// All data is stored in the backend. Metadata fields (time, config, head, etc.)
/// are stored in the Metadata table with their field name as the key.
#[derive(Clone)]
pub struct Store {
    /// Storage backend for all store data.
    backend: Arc<dyn StorageBackend>,
}

impl Store {
    /// Initialize a Store from a genesis state.
    pub fn from_genesis(backend: Arc<dyn StorageBackend>, mut genesis_state: State) -> Self {
        // Ensure the header state root is zero before computing the state root
        genesis_state.latest_block_header.state_root = H256::ZERO;

        let genesis_state_root = genesis_state.tree_hash_root();
        let genesis_block = Block {
            slot: 0,
            proposer_index: 0,
            parent_root: H256::ZERO,
            state_root: genesis_state_root,
            body: BlockBody::default(),
        };
        Self::get_forkchoice_store(backend, genesis_state, genesis_block)
    }

    /// Initialize a Store from an anchor state and block.
    pub fn get_forkchoice_store(
        backend: Arc<dyn StorageBackend>,
        anchor_state: State,
        anchor_block: Block,
    ) -> Self {
        let anchor_state_root = anchor_state.tree_hash_root();
        let anchor_block_root = anchor_block.tree_hash_root();

        let anchor_checkpoint = Checkpoint {
            root: anchor_block_root,
            slot: anchor_block.slot,
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

            // Block and state
            let block_entries = vec![(
                anchor_block_root.as_ssz_bytes(),
                anchor_block.as_ssz_bytes(),
            )];
            batch
                .put_batch(Table::Blocks, block_entries)
                .expect("put block");

            let state_entries = vec![(
                anchor_block_root.as_ssz_bytes(),
                anchor_state.as_ssz_bytes(),
            )];
            batch
                .put_batch(Table::States, state_entries)
                .expect("put state");

            // Non-finalized chain index
            let index_entries = vec![(
                encode_live_chain_key(anchor_block.slot, &anchor_block_root),
                anchor_block.parent_root.as_ssz_bytes(),
            )];
            batch
                .put_batch(Table::LiveChain, index_entries)
                .expect("put non-finalized chain index");

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

    pub fn time(&self) -> u64 {
        self.get_metadata(KEY_TIME)
    }

    pub fn set_time(&mut self, time: u64) {
        self.set_metadata(KEY_TIME, &time);
    }

    // ============ Config ============

    pub fn config(&self) -> ChainConfig {
        self.get_metadata(KEY_CONFIG)
    }

    // ============ Head ============

    pub fn head(&self) -> H256 {
        self.get_metadata(KEY_HEAD)
    }

    // ============ Safe Target ============

    pub fn safe_target(&self) -> H256 {
        self.get_metadata(KEY_SAFE_TARGET)
    }

    pub fn set_safe_target(&mut self, safe_target: H256) {
        self.set_metadata(KEY_SAFE_TARGET, &safe_target);
    }

    // ============ Latest Justified ============

    pub fn latest_justified(&self) -> Checkpoint {
        self.get_metadata(KEY_LATEST_JUSTIFIED)
    }

    // ============ Latest Finalized ============

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

            // Prune signatures and payloads for finalized slots
            let pruned_sigs = self.prune_gossip_signatures(finalized.slot);
            let pruned_payloads = self.prune_aggregated_payloads(finalized.slot);
            if pruned_sigs > 0 || pruned_payloads > 0 {
                info!(
                    finalized_slot = finalized.slot,
                    pruned_sigs, pruned_payloads, "Pruned finalized signatures"
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

    /// Prune aggregated payloads for slots <= finalized_slot.
    ///
    /// Returns the number of payloads pruned.
    pub fn prune_aggregated_payloads(&mut self, finalized_slot: u64) -> usize {
        let view = self.backend.begin_read().expect("read view");
        let mut updates = vec![];
        let mut deletes = vec![];
        let mut removed_count = 0;

        for (key_bytes, value_bytes) in view
            .prefix_iterator(Table::AggregatedPayloads, &[])
            .expect("iter")
            .filter_map(|r| r.ok())
        {
            if let Ok(mut payloads) = Vec::<StoredAggregatedPayload>::from_ssz_bytes(&value_bytes) {
                let original_len = payloads.len();
                payloads.retain(|p| p.slot > finalized_slot);
                removed_count += original_len - payloads.len();

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
                batch
                    .put_batch(Table::AggregatedPayloads, updates)
                    .expect("put");
            }
            if !deletes.is_empty() {
                batch
                    .delete_batch(Table::AggregatedPayloads, deletes)
                    .expect("delete");
            }
            batch.commit().expect("commit");
        }
        removed_count
    }

    pub fn get_block(&self, root: &H256) -> Option<Block> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::Blocks, &root.as_ssz_bytes())
            .expect("get")
            .map(|bytes| Block::from_ssz_bytes(&bytes).expect("valid block"))
    }

    pub fn contains_block(&self, root: &H256) -> bool {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::Blocks, &root.as_ssz_bytes())
            .expect("get")
            .is_some()
    }

    pub fn insert_block(&mut self, root: H256, block: Block) {
        let mut batch = self.backend.begin_write().expect("write batch");
        let block_entries = vec![(root.as_ssz_bytes(), block.as_ssz_bytes())];
        batch
            .put_batch(Table::Blocks, block_entries)
            .expect("put block");

        let index_entries = vec![(
            encode_live_chain_key(block.slot, &root),
            block.parent_root.as_ssz_bytes(),
        )];
        batch
            .put_batch(Table::LiveChain, index_entries)
            .expect("put non-finalized chain index");

        batch.commit().expect("commit");
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

        let block_entries = vec![(root.as_ssz_bytes(), block.as_ssz_bytes())];
        batch
            .put_batch(Table::Blocks, block_entries)
            .expect("put block");

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

    /// Get a signed block by combining block and signatures.
    ///
    /// Returns None if either the block or signatures are not found.
    /// Note: Genesis block has no entry in BlockSignatures table.
    pub fn get_signed_block(&self, root: &H256) -> Option<SignedBlockWithAttestation> {
        let view = self.backend.begin_read().expect("read view");
        let key = root.as_ssz_bytes();

        let block_bytes = view.get(Table::Blocks, &key).expect("get")?;
        let sig_bytes = view.get(Table::BlockSignatures, &key).expect("get")?;

        let block = Block::from_ssz_bytes(&block_bytes).expect("valid block");
        let signatures =
            BlockSignaturesWithAttestation::from_ssz_bytes(&sig_bytes).expect("valid signatures");

        Some(signatures.to_signed_block(block))
    }

    // ============ States ============

    /// Iterate over all (root, state) pairs.
    pub fn iter_states(&self) -> impl Iterator<Item = (H256, State)> + '_ {
        let view = self.backend.begin_read().expect("read view");
        let entries: Vec<_> = view
            .prefix_iterator(Table::States, &[])
            .expect("iterator")
            .filter_map(|res| res.ok())
            .map(|(k, v)| {
                let root = H256::from_ssz_bytes(&k).expect("valid root");
                let state = State::from_ssz_bytes(&v).expect("valid state");
                (root, state)
            })
            .collect();
        entries.into_iter()
    }

    pub fn get_state(&self, root: &H256) -> Option<State> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::States, &root.as_ssz_bytes())
            .expect("get")
            .map(|bytes| State::from_ssz_bytes(&bytes).expect("valid state"))
    }

    pub fn insert_state(&mut self, root: H256, state: State) {
        let mut batch = self.backend.begin_write().expect("write batch");
        let entries = vec![(root.as_ssz_bytes(), state.as_ssz_bytes())];
        batch.put_batch(Table::States, entries).expect("put state");
        batch.commit().expect("commit");
    }

    // ============ Latest Known Attestations ============

    /// Iterate over all (validator_id, attestation_data) pairs for known attestations.
    pub fn iter_known_attestations(&self) -> impl Iterator<Item = (u64, AttestationData)> + '_ {
        let view = self.backend.begin_read().expect("read view");
        let entries: Vec<_> = view
            .prefix_iterator(Table::LatestKnownAttestations, &[])
            .expect("iterator")
            .filter_map(|res| res.ok())
            .map(|(k, v)| {
                let validator_id = u64::from_ssz_bytes(&k).expect("valid validator_id");
                let data = AttestationData::from_ssz_bytes(&v).expect("valid attestation data");
                (validator_id, data)
            })
            .collect();
        entries.into_iter()
    }

    pub fn get_known_attestation(&self, validator_id: &u64) -> Option<AttestationData> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::LatestKnownAttestations, &validator_id.as_ssz_bytes())
            .expect("get")
            .map(|bytes| AttestationData::from_ssz_bytes(&bytes).expect("valid attestation data"))
    }

    pub fn insert_known_attestation(&mut self, validator_id: u64, data: AttestationData) {
        let mut batch = self.backend.begin_write().expect("write batch");
        let entries = vec![(validator_id.as_ssz_bytes(), data.as_ssz_bytes())];
        batch
            .put_batch(Table::LatestKnownAttestations, entries)
            .expect("put attestation");
        batch.commit().expect("commit");
    }

    // ============ Latest New Attestations ============

    /// Iterate over all (validator_id, attestation_data) pairs for new attestations.
    pub fn iter_new_attestations(&self) -> impl Iterator<Item = (u64, AttestationData)> + '_ {
        let view = self.backend.begin_read().expect("read view");
        let entries: Vec<_> = view
            .prefix_iterator(Table::LatestNewAttestations, &[])
            .expect("iterator")
            .filter_map(|res| res.ok())
            .map(|(k, v)| {
                let validator_id = u64::from_ssz_bytes(&k).expect("valid validator_id");
                let data = AttestationData::from_ssz_bytes(&v).expect("valid attestation data");
                (validator_id, data)
            })
            .collect();
        entries.into_iter()
    }

    pub fn get_new_attestation(&self, validator_id: &u64) -> Option<AttestationData> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::LatestNewAttestations, &validator_id.as_ssz_bytes())
            .expect("get")
            .map(|bytes| AttestationData::from_ssz_bytes(&bytes).expect("valid attestation data"))
    }

    pub fn insert_new_attestation(&mut self, validator_id: u64, data: AttestationData) {
        let mut batch = self.backend.begin_write().expect("write batch");
        let entries = vec![(validator_id.as_ssz_bytes(), data.as_ssz_bytes())];
        batch
            .put_batch(Table::LatestNewAttestations, entries)
            .expect("put attestation");
        batch.commit().expect("commit");
    }

    pub fn remove_new_attestation(&mut self, validator_id: &u64) {
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .delete_batch(
                Table::LatestNewAttestations,
                vec![validator_id.as_ssz_bytes()],
            )
            .expect("delete attestation");
        batch.commit().expect("commit");
    }

    /// Promotes all new attestations to known attestations.
    ///
    /// Takes all attestations from `latest_new_attestations` and moves them
    /// to `latest_known_attestations`, making them count for fork choice.
    pub fn promote_new_attestations(&mut self) {
        // Read all new attestations
        let view = self.backend.begin_read().expect("read view");
        let new_attestations: Vec<(Vec<u8>, Vec<u8>)> = view
            .prefix_iterator(Table::LatestNewAttestations, &[])
            .expect("iterator")
            .filter_map(|res| res.ok())
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        drop(view);

        if new_attestations.is_empty() {
            return;
        }

        // Delete from new and insert to known in a single batch
        let mut batch = self.backend.begin_write().expect("write batch");
        let keys_to_delete: Vec<_> = new_attestations.iter().map(|(k, _)| k.clone()).collect();
        batch
            .delete_batch(Table::LatestNewAttestations, keys_to_delete)
            .expect("delete new attestations");
        batch
            .put_batch(Table::LatestKnownAttestations, new_attestations)
            .expect("put known attestations");
        batch.commit().expect("commit");
    }

    // ============ Gossip Signatures ============

    /// Iterate over all (signature_key, stored_signature) pairs.
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

    pub fn get_gossip_signature(&self, key: &SignatureKey) -> Option<StoredSignature> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::GossipSignatures, &encode_signature_key(key))
            .expect("get")
            .and_then(|bytes| StoredSignature::from_ssz_bytes(&bytes).ok())
    }

    pub fn contains_gossip_signature(&self, key: &SignatureKey) -> bool {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::GossipSignatures, &encode_signature_key(key))
            .expect("get")
            .is_some()
    }

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

    // ============ Aggregated Payloads ============

    /// Iterate over all (signature_key, stored_payloads) pairs.
    pub fn iter_aggregated_payloads(
        &self,
    ) -> impl Iterator<Item = (SignatureKey, Vec<StoredAggregatedPayload>)> + '_ {
        let view = self.backend.begin_read().expect("read view");
        let entries: Vec<_> = view
            .prefix_iterator(Table::AggregatedPayloads, &[])
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

    pub fn get_aggregated_payloads(
        &self,
        key: &SignatureKey,
    ) -> Option<Vec<StoredAggregatedPayload>> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::AggregatedPayloads, &encode_signature_key(key))
            .expect("get")
            .map(|bytes| {
                Vec::<StoredAggregatedPayload>::from_ssz_bytes(&bytes).expect("valid payloads")
            })
    }

    /// Insert an aggregated signature proof for a validator's attestation.
    ///
    /// Multiple proofs can be stored for the same (validator, attestation_data) pair,
    /// each with its own slot metadata for pruning.
    ///
    /// # Thread Safety
    ///
    /// This method uses a read-modify-write pattern that is NOT atomic:
    /// 1. Read existing payloads
    /// 2. Append new payload
    /// 3. Write back
    ///
    /// Concurrent calls could result in lost updates. This method MUST be called
    /// from a single thread. In our case, that thread is the `BlockChain` `GenServer`
    pub fn insert_aggregated_payload(
        &mut self,
        attestation_data: &AttestationData,
        validator_id: u64,
        proof: AggregatedSignatureProof,
    ) {
        let slot = attestation_data.slot;
        let data_root = attestation_data.tree_hash_root();
        let key = (validator_id, data_root);

        // Read existing, add new, write back (NOT atomic - requires single-threaded access)
        let mut payloads = self.get_aggregated_payloads(&key).unwrap_or_default();
        payloads.push(StoredAggregatedPayload { slot, proof });

        let mut batch = self.backend.begin_write().expect("write batch");
        let entries = vec![(encode_signature_key(&key), payloads.as_ssz_bytes())];
        batch
            .put_batch(Table::AggregatedPayloads, entries)
            .expect("put proofs");
        batch.commit().expect("commit");
    }

    // ============ Derived Accessors ============

    /// Returns the slot of the current safe target block.
    pub fn safe_target_slot(&self) -> u64 {
        self.get_block(&self.safe_target())
            .expect("safe target exists")
            .slot
    }

    /// Returns a clone of the head state.
    pub fn head_state(&self) -> State {
        self.get_state(&self.head())
            .expect("head state is always available")
    }
}
