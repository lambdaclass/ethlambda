use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::api::{StorageBackend, Table};
use crate::config::{
    AGGREGATED_PAYLOAD_CAP, BLOCKS_TO_KEEP, EMPTY_BODY_ROOT, GOSSIP_SIGNATURE_CAP, KEY_CONFIG,
    KEY_HEAD, KEY_LATEST_FINALIZED, KEY_LATEST_JUSTIFIED, KEY_SAFE_TARGET, KEY_TIME,
    NEW_PAYLOAD_CAP, STATES_TO_KEEP,
};
use crate::types::{
    ForkCheckpoints, GossipSignatureBuffer, GossipSignatureSnapshot, PayloadBuffer,
};
use crate::utils::{decode_live_chain_key, encode_live_chain_key, write_signed_block};

use ethlambda_types::{
    attestation::{AttestationData, HashedAttestationData},
    block::{
        AggregatedSignatureProof, Block, BlockBody, BlockHeader, BlockSignatures, SignedBlock,
    },
    checkpoint::Checkpoint,
    primitives::{H256, HashTreeRoot as _},
    signature::ValidatorSignature,
    state::{ChainConfig, State, anchor_pair_is_consistent},
};
use libssz::{SszDecode, SszEncode};
use thiserror::Error;
use tracing::info;

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

/// Fork choice store backed by a pluggable storage backend.
///
/// Maintains metadata, blocks, states, and attestation/signature buffers
/// required for fork choice and block processing.
#[derive(Clone)]
pub struct Store {
    backend: Arc<dyn StorageBackend>,
    new_payloads: Arc<Mutex<PayloadBuffer>>,
    known_payloads: Arc<Mutex<PayloadBuffer>>,
    /// In-memory gossip signatures, consumed at interval 2 aggregation.
    gossip_signatures: Arc<Mutex<GossipSignatureBuffer>>,
}

impl Store {
    /// Initialize from a checkpoint state. Anchor header is taken from
    /// `state.latest_block_header`. No body is stored.
    pub fn from_anchor_state(backend: Arc<dyn StorageBackend>, anchor_state: State) -> Self {
        Self::init_store(backend, anchor_state, None)
    }

    /// Initialize from an anchor state and block.
    ///
    /// The block must match the state's `latest_block_header`.
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

        Ok(Self::init_store(
            backend,
            anchor_state,
            Some(anchor_block.body),
        ))
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

            // State
            let state_entries = vec![(anchor_block_root.to_ssz(), anchor_state.to_ssz())];
            batch
                .put_batch(Table::States, state_entries)
                .expect("put state");

            // Live chain index
            let index_entries = vec![(
                encode_live_chain_key(anchor_state.latest_block_header.slot, &anchor_block_root),
                anchor_state.latest_block_header.parent_root.to_ssz(),
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
            gossip_signatures: Arc::new(Mutex::new(GossipSignatureBuffer::new(
                GOSSIP_SIGNATURE_CAP,
            ))),
        }
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

    fn set_metadata<T: SszEncode>(&self, key: &[u8], value: &T) {
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .put_batch(Table::Metadata, vec![(key.to_vec(), value.to_ssz())])
            .expect("put metadata");
        batch.commit().expect("commit");
    }

    /// Current store time in intervals since genesis.
    ///
    /// slot     = time() / INTERVALS_PER_SLOT
    /// interval = time() % INTERVALS_PER_SLOT
    pub fn time(&self) -> u64 {
        self.get_metadata(KEY_TIME)
    }

    pub fn set_time(&mut self, time: u64) {
        self.set_metadata(KEY_TIME, &time);
    }

    pub fn config(&self) -> ChainConfig {
        self.get_metadata(KEY_CONFIG)
    }

    pub fn head(&self) -> H256 {
        self.get_metadata(KEY_HEAD)
    }

    pub fn safe_target(&self) -> H256 {
        self.get_metadata(KEY_SAFE_TARGET)
    }

    pub fn set_safe_target(&mut self, safe_target: H256) {
        self.set_metadata(KEY_SAFE_TARGET, &safe_target);
    }

    pub fn latest_justified(&self) -> Checkpoint {
        self.get_metadata(KEY_LATEST_JUSTIFIED)
    }

    pub fn latest_finalized(&self) -> Checkpoint {
        self.get_metadata(KEY_LATEST_FINALIZED)
    }

    /// Updates head, justified, and finalized checkpoints.
    ///
    /// When finalization advances, prunes the LiveChain index.
    pub fn update_checkpoints(&mut self, checkpoints: ForkCheckpoints) {
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

        // Immediately prune cheap finalized data (index, signatures, attestations).
        // Heavy state/block pruning is deferred to prune_old_data().
        if let Some(finalized) = checkpoints.finalized
            && finalized.slot > old_finalized_slot
        {
            let pruned_chain = self.prune_live_chain(finalized.slot);
            let pruned_sigs = self.prune_gossip_signatures(finalized.slot);

            if pruned_chain > 0 || pruned_sigs > 0 {
                info!(
                    finalized_slot = finalized.slot,
                    pruned_chain, pruned_sigs, "Pruned finalized data"
                );
            }
        }
    }

    /// Prune old states and blocks to keep storage bounded.
    pub fn prune_old_data(&mut self) {
        let protected_roots = [self.latest_finalized().root, self.latest_justified().root];
        let pruned_states = self.prune_old_states(&protected_roots);
        let pruned_blocks = self.prune_old_blocks(&protected_roots);
        if pruned_states > 0 || pruned_blocks > 0 {
            info!(pruned_states, pruned_blocks, "Pruned old states and blocks");
        }
    }

    /// Root -> (slot, parent_root) for non-finalized blocks.
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

    /// Prune LiveChain index entries with slot < finalized_slot.
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

    pub fn prune_gossip_signatures(&mut self, finalized_slot: u64) -> usize {
        let mut gossip = self.gossip_signatures.lock().unwrap();
        gossip.prune(finalized_slot)
    }

    /// Keeps the most recent `STATES_TO_KEEP` states (by slot) plus protected roots.
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

        entries.sort_unstable_by(|a, b| b.1.cmp(&a.1));

        let protected: HashSet<Vec<u8>> = protected_roots.iter().map(|r| r.to_ssz()).collect();

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

    /// Keeps the most recent `BLOCKS_TO_KEEP` blocks (by slot) plus protected roots.
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

        entries.sort_unstable_by(|a, b| b.1.cmp(&a.1));

        let protected: HashSet<Vec<u8>> = protected_roots.iter().map(|r| r.to_ssz()).collect();

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

    pub fn get_block_header(&self, root: &H256) -> Option<BlockHeader> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::BlockHeaders, &root.to_ssz())
            .expect("get")
            .map(|bytes| BlockHeader::from_ssz_bytes(&bytes).expect("valid header"))
    }

    /// Insert a block as pending (parent state not yet available).
    ///
    /// Persists heavy signature data to disk while keeping the block invisible to fork choice.
    pub fn insert_pending_block(&mut self, root: H256, signed_block: SignedBlock) {
        let mut batch = self.backend.begin_write().expect("write batch");
        write_signed_block(batch.as_mut(), &root, signed_block);
        batch.commit().expect("commit");
    }

    /// Insert a signed block and its signatures.
    pub fn insert_signed_block(&mut self, root: H256, signed_block: SignedBlock) {
        let mut batch = self.backend.begin_write().expect("write batch");
        let block = write_signed_block(batch.as_mut(), &root, signed_block);

        let index_entries = vec![(
            encode_live_chain_key(block.slot, &root),
            block.parent_root.to_ssz(),
        )];
        batch
            .put_batch(Table::LiveChain, index_entries)
            .expect("put non-finalized chain index");

        batch.commit().expect("commit");
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

    /// Get a signed block by combining header, body, and signatures.
    ///
    /// Note: Genesis block has no entry in BlockSignatures table.
    pub fn get_signed_block(&self, root: &H256) -> Option<SignedBlock> {
        let view = self.backend.begin_read().expect("read view");
        let key = root.to_ssz();

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
        let signature = BlockSignatures::from_ssz_bytes(&sig_bytes).expect("valid signatures");

        Some(SignedBlock {
            message: block,
            signature,
        })
    }

    pub fn get_state(&self, root: &H256) -> Option<State> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::States, &root.to_ssz())
            .expect("get")
            .map(|bytes| State::from_ssz_bytes(&bytes).expect("valid state"))
    }

    pub fn has_state(&self, root: &H256) -> bool {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::States, &root.to_ssz())
            .expect("get")
            .is_some()
    }

    pub fn insert_state(&mut self, root: H256, state: State) {
        let mut batch = self.backend.begin_write().expect("write batch");
        let entries = vec![(root.to_ssz(), state.to_ssz())];
        batch.put_batch(Table::States, entries).expect("put state");
        batch.commit().expect("commit");
    }

    pub fn extract_latest_known_attestations(&self) -> HashMap<u64, AttestationData> {
        self.known_payloads
            .lock()
            .unwrap()
            .extract_latest_attestations()
    }

    pub fn extract_latest_new_attestations(&self) -> HashMap<u64, AttestationData> {
        self.new_payloads
            .lock()
            .unwrap()
            .extract_latest_attestations()
    }

    pub fn extract_latest_all_attestations(&self) -> HashMap<u64, AttestationData> {
        let mut result = self
            .known_payloads
            .lock()
            .unwrap()
            .extract_latest_attestations();
        for (vid, data) in self
            .new_payloads
            .lock()
            .unwrap()
            .extract_latest_attestations()
        {
            let should_update = result
                .get(&vid)
                .is_none_or(|existing| existing.slot < data.slot);
            if should_update {
                result.insert(vid, data);
            }
        }
        result
    }

    /// Snapshot of known payloads active in fork choice.
    pub fn known_aggregated_payloads(
        &self,
    ) -> HashMap<H256, (AttestationData, Vec<AggregatedSignatureProof>)> {
        let buf = self.known_payloads.lock().unwrap();
        buf.data
            .iter()
            .map(|(root, entry)| (*root, (entry.data.clone(), entry.proofs.clone())))
            .collect()
    }

    /// Combined proof count for a data_root across new and known buffers.
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

    /// Existing proofs for a data_root from both buffers.
    ///
    /// Returns `(new_proofs, known_proofs)` in priority order (new first).
    pub fn existing_proofs_for_data(
        &self,
        data_root: &H256,
    ) -> (Vec<AggregatedSignatureProof>, Vec<AggregatedSignatureProof>) {
        let new = self.new_payloads.lock().unwrap().proofs_for_root(data_root);
        let known = self
            .known_payloads
            .lock()
            .unwrap()
            .proofs_for_root(data_root);
        (new, known)
    }

    pub fn new_payload_keys(&self) -> Vec<(H256, AttestationData)> {
        self.new_payloads.lock().unwrap().attestation_data_keys()
    }

    pub fn insert_known_aggregated_payload(
        &mut self,
        hashed: HashedAttestationData,
        proof: AggregatedSignatureProof,
    ) {
        self.known_payloads.lock().unwrap().push(hashed, proof);
    }

    pub fn insert_known_aggregated_payloads_batch(
        &mut self,
        entries: Vec<(HashedAttestationData, AggregatedSignatureProof)>,
    ) {
        self.known_payloads.lock().unwrap().push_batch(entries);
    }

    pub fn insert_new_aggregated_payload(
        &mut self,
        hashed: HashedAttestationData,
        proof: AggregatedSignatureProof,
    ) {
        self.new_payloads.lock().unwrap().push(hashed, proof);
    }

    pub fn insert_new_aggregated_payloads_batch(
        &mut self,
        entries: Vec<(HashedAttestationData, AggregatedSignatureProof)>,
    ) {
        self.new_payloads.lock().unwrap().push_batch(entries);
    }

    /// Promotes all new aggregated payloads to known (active in fork choice).
    pub fn promote_new_aggregated_payloads(&mut self) {
        let drained = self.new_payloads.lock().unwrap().drain();
        self.known_payloads.lock().unwrap().push_batch(drained);
    }

    pub fn new_aggregated_payloads_count(&self) -> usize {
        self.new_payloads.lock().unwrap().len()
    }

    pub fn known_aggregated_payloads_count(&self) -> usize {
        self.known_payloads.lock().unwrap().len()
    }

    pub fn gossip_signatures_count(&self) -> usize {
        let gossip = self.gossip_signatures.lock().unwrap();
        gossip.total_signatures()
    }

    pub fn estimate_table_bytes(&self, table: Table) -> u64 {
        self.backend.estimate_table_bytes(table)
    }

    pub fn delete_gossip_signatures(&mut self, keys: &[(u64, H256)]) {
        let mut gossip = self.gossip_signatures.lock().unwrap();
        gossip.delete(keys);
    }

    pub fn iter_gossip_signatures(&self) -> GossipSignatureSnapshot {
        let gossip = self.gossip_signatures.lock().unwrap();
        gossip.snapshot()
    }

    pub fn insert_gossip_signature(
        &mut self,
        hashed: HashedAttestationData,
        validator_id: u64,
        signature: ValidatorSignature,
    ) {
        let mut gossip = self.gossip_signatures.lock().unwrap();
        gossip.insert(hashed, validator_id, signature);
    }

    pub fn head_slot(&self) -> u64 {
        self.get_block_header(&self.head())
            .expect("head block exists")
            .slot
    }

    pub fn safe_target_slot(&self) -> u64 {
        self.get_block_header(&self.safe_target())
            .expect("safe target exists")
            .slot
    }

    pub fn head_state(&self) -> State {
        self.get_state(&self.head())
            .expect("head state is always available")
    }
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
        let key = root.to_ssz();
        batch
            .put_batch(Table::BlockHeaders, vec![(key.clone(), header.to_ssz())])
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
        let key = root.to_ssz();
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
        view.get(table, &root.to_ssz()).expect("get").is_some()
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
                    (KEY_LATEST_FINALIZED.to_vec(), finalized.to_ssz()),
                    (KEY_LATEST_JUSTIFIED.to_vec(), justified.to_ssz()),
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

        // update_checkpoints no longer prunes states/blocks inline — the caller
        // must invoke prune_old_data() separately (after a block cascade completes).
        assert_eq!(count_entries(backend.as_ref(), Table::States), total_states);

        store.prune_old_data();

        // 3005 headers total. Top 3000 by slot are kept in the retention window,
        // leaving 5 candidates. 2 are protected (finalized + justified),
        // so 3 are pruned → 3005 - 3 = 3002 states remaining.
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
        store.prune_old_data();

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

    // ============ Store Buffer Tests ============

    fn make_proof() -> AggregatedSignatureProof {
        use ethlambda_types::attestation::AggregationBits;
        AggregatedSignatureProof::empty(AggregationBits::new())
    }

    fn make_proof_for_validator(vid: usize) -> AggregatedSignatureProof {
        use ethlambda_types::attestation::AggregationBits;
        let mut bits = AggregationBits::with_length(vid + 1).unwrap();
        bits.set(vid, true).unwrap();
        AggregatedSignatureProof::empty(bits)
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
}
