use crate::api::{StorageBackend, Table};
use crate::backend::InMemoryBackend;

use ethlambda_types::{
    attestation::AttestationData,
    block::{AggregatedSignatureProof, Block, BlockBody},
    primitives::{Decode, Encode, H256, TreeHash},
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

/// Forkchoice store tracking chain state and validator attestations.
///
/// This is the "local view" that a node uses to run LMD GHOST. It contains:
///
/// - which blocks and states are known,
/// - which checkpoints are justified and finalized,
/// - which block is currently considered the head,
/// - and, for each validator, their latest attestation that should influence fork choice.
///
/// The `Store` is updated whenever:
/// - a new block is processed,
/// - an attestation is received (via a block or gossip),
/// - an interval tick occurs (activating new attestations),
/// - or when the head is recomputed.
#[derive(Clone)]
pub struct Store {
    /// Current time in intervals since genesis.
    time: u64,

    /// Chain configuration parameters.
    config: ChainConfig,

    /// Root of the current canonical chain head block.
    ///
    /// This is the result of running the fork choice algorithm on the current contents of the `Store`.
    head: H256,

    /// Root of the current safe target for attestation.
    ///
    /// This can be used by higher-level logic to restrict which blocks are
    /// considered safe to attest to, based on additional safety conditions.
    ///
    safe_target: H256,

    /// Highest slot justified checkpoint known to the store.
    ///
    /// LMD GHOST starts from this checkpoint when computing the head.
    ///
    /// Only descendants of this checkpoint are considered viable.
    latest_justified: Checkpoint,

    /// Highest slot finalized checkpoint known to the store.
    ///
    /// Everything strictly before this checkpoint can be considered immutable.
    ///
    /// Fork choice will never revert finalized history.
    latest_finalized: Checkpoint,

    /// Storage backend for blocks, states, attestations, and signatures.
    backend: InMemoryBackend,
}

impl Store {
    /// Initialize a Store from a genesis state.
    pub fn from_genesis(mut genesis_state: State) -> Self {
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
        Self::get_forkchoice_store(genesis_state, genesis_block)
    }

    /// Initialize a Store from an anchor state and block.
    pub fn get_forkchoice_store(anchor_state: State, anchor_block: Block) -> Self {
        let anchor_state_root = anchor_state.tree_hash_root();
        let anchor_block_root = anchor_block.tree_hash_root();

        let backend = InMemoryBackend::new();

        // Insert initial block and state
        {
            let mut batch = backend.begin_write().expect("write batch");
            batch
                .put_batch(
                    Table::Blocks,
                    vec![(
                        anchor_block_root.as_ssz_bytes(),
                        anchor_block.as_ssz_bytes(),
                    )],
                )
                .expect("put block");
            batch
                .put_batch(
                    Table::States,
                    vec![(
                        anchor_block_root.as_ssz_bytes(),
                        anchor_state.as_ssz_bytes(),
                    )],
                )
                .expect("put state");
            batch.commit().expect("commit");
        }

        let anchor_checkpoint = Checkpoint {
            root: anchor_block_root,
            slot: 0,
        };

        info!(%anchor_state_root, %anchor_block_root, "Initialized store");

        Self {
            time: 0,
            config: anchor_state.config.clone(),
            head: anchor_block_root,
            safe_target: anchor_block_root,
            latest_justified: anchor_checkpoint,
            latest_finalized: anchor_checkpoint,
            backend,
        }
    }

    /// Creates a new Store with the given initial values.
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        time: u64,
        config: ChainConfig,
        head: H256,
        safe_target: H256,
        latest_justified: Checkpoint,
        latest_finalized: Checkpoint,
        blocks: impl IntoIterator<Item = (H256, Block)>,
        states: impl IntoIterator<Item = (H256, State)>,
    ) -> Self {
        let backend = InMemoryBackend::new();

        // Insert blocks and states
        {
            let mut batch = backend.begin_write().expect("write batch");
            let block_entries: Vec<_> = blocks
                .into_iter()
                .map(|(k, v)| (k.as_ssz_bytes(), v.as_ssz_bytes()))
                .collect();
            if !block_entries.is_empty() {
                batch
                    .put_batch(Table::Blocks, block_entries)
                    .expect("put blocks");
            }
            let state_entries: Vec<_> = states
                .into_iter()
                .map(|(k, v)| (k.as_ssz_bytes(), v.as_ssz_bytes()))
                .collect();
            if !state_entries.is_empty() {
                batch
                    .put_batch(Table::States, state_entries)
                    .expect("put states");
            }
            batch.commit().expect("commit");
        }

        Self {
            time,
            config,
            head,
            safe_target,
            latest_justified,
            latest_finalized,
            backend,
        }
    }

    // ============ Time ============

    pub fn time(&self) -> u64 {
        self.time
    }

    pub fn set_time(&mut self, time: u64) {
        self.time = time;
    }

    // ============ Config ============

    pub fn config(&self) -> &ChainConfig {
        &self.config
    }

    // ============ Head ============

    pub fn head(&self) -> H256 {
        self.head
    }

    // ============ Safe Target ============

    pub fn safe_target(&self) -> H256 {
        self.safe_target
    }

    pub fn set_safe_target(&mut self, safe_target: H256) {
        self.safe_target = safe_target;
    }

    // ============ Latest Justified ============

    pub fn latest_justified(&self) -> &Checkpoint {
        &self.latest_justified
    }

    // ============ Latest Finalized ============

    pub fn latest_finalized(&self) -> &Checkpoint {
        &self.latest_finalized
    }

    // ============ Checkpoint Updates ============

    /// Updates head, justified, and finalized checkpoints.
    ///
    /// - Head is always updated to the new value.
    /// - Justified is updated if provided.
    /// - Finalized is updated if provided.
    pub fn update_checkpoints(&mut self, checkpoints: ForkCheckpoints) {
        self.head = checkpoints.head;

        if let Some(justified) = checkpoints.justified {
            self.latest_justified = justified;
        }

        if let Some(finalized) = checkpoints.finalized {
            self.latest_finalized = finalized;
        }
    }

    // ============ Blocks ============

    /// Iterate over all (root, block) pairs.
    pub fn iter_blocks(&self) -> impl Iterator<Item = (H256, Block)> + '_ {
        let view = self.backend.begin_read().expect("read view");
        let entries: Vec<_> = view
            .prefix_iterator(Table::Blocks, &[])
            .expect("iterator")
            .filter_map(|res| res.ok())
            .map(|(k, v)| {
                let root = H256::from_ssz_bytes(&k).expect("valid root");
                let block = Block::from_ssz_bytes(&v).expect("valid block");
                (root, block)
            })
            .collect();
        entries.into_iter()
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
        batch
            .put_batch(
                Table::Blocks,
                vec![(root.as_ssz_bytes(), block.as_ssz_bytes())],
            )
            .expect("put block");
        batch.commit().expect("commit");
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
        batch
            .put_batch(
                Table::States,
                vec![(root.as_ssz_bytes(), state.as_ssz_bytes())],
            )
            .expect("put state");
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
        batch
            .put_batch(
                Table::LatestKnownAttestations,
                vec![(validator_id.as_ssz_bytes(), data.as_ssz_bytes())],
            )
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
        batch
            .put_batch(
                Table::LatestNewAttestations,
                vec![(validator_id.as_ssz_bytes(), data.as_ssz_bytes())],
            )
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

    /// Iterate over all (signature_key, signature) pairs.
    pub fn iter_gossip_signatures(
        &self,
    ) -> impl Iterator<Item = (SignatureKey, ValidatorSignature)> + '_ {
        let view = self.backend.begin_read().expect("read view");
        let entries: Vec<_> = view
            .prefix_iterator(Table::GossipSignatures, &[])
            .expect("iterator")
            .filter_map(|res| res.ok())
            .filter_map(|(k, v)| {
                let key = decode_signature_key(&k);
                ValidatorSignature::from_bytes(&v)
                    .ok()
                    .map(|sig| (key, sig))
            })
            .collect();
        entries.into_iter()
    }

    pub fn get_gossip_signature(&self, key: &SignatureKey) -> Option<ValidatorSignature> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::GossipSignatures, &encode_signature_key(key))
            .expect("get")
            .and_then(|bytes| ValidatorSignature::from_bytes(&bytes).ok())
    }

    pub fn contains_gossip_signature(&self, key: &SignatureKey) -> bool {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::GossipSignatures, &encode_signature_key(key))
            .expect("get")
            .is_some()
    }

    pub fn insert_gossip_signature(&mut self, key: SignatureKey, signature: ValidatorSignature) {
        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .put_batch(
                Table::GossipSignatures,
                vec![(encode_signature_key(&key), signature.to_bytes())],
            )
            .expect("put signature");
        batch.commit().expect("commit");
    }

    // ============ Aggregated Payloads ============

    /// Iterate over all (signature_key, proofs) pairs.
    pub fn iter_aggregated_payloads(
        &self,
    ) -> impl Iterator<Item = (SignatureKey, Vec<AggregatedSignatureProof>)> + '_ {
        let view = self.backend.begin_read().expect("read view");
        let entries: Vec<_> = view
            .prefix_iterator(Table::AggregatedPayloads, &[])
            .expect("iterator")
            .filter_map(|res| res.ok())
            .map(|(k, v)| {
                let key = decode_signature_key(&k);
                let proofs =
                    Vec::<AggregatedSignatureProof>::from_ssz_bytes(&v).expect("valid proofs");
                (key, proofs)
            })
            .collect();
        entries.into_iter()
    }

    pub fn get_aggregated_payloads(
        &self,
        key: &SignatureKey,
    ) -> Option<Vec<AggregatedSignatureProof>> {
        let view = self.backend.begin_read().expect("read view");
        view.get(Table::AggregatedPayloads, &encode_signature_key(key))
            .expect("get")
            .map(|bytes| {
                Vec::<AggregatedSignatureProof>::from_ssz_bytes(&bytes).expect("valid proofs")
            })
    }

    pub fn push_aggregated_payload(&mut self, key: SignatureKey, proof: AggregatedSignatureProof) {
        // Read existing, add new, write back
        let mut proofs = self.get_aggregated_payloads(&key).unwrap_or_default();
        proofs.push(proof);

        let mut batch = self.backend.begin_write().expect("write batch");
        batch
            .put_batch(
                Table::AggregatedPayloads,
                vec![(encode_signature_key(&key), proofs.as_ssz_bytes())],
            )
            .expect("put proofs");
        batch.commit().expect("commit");
    }

    // ============ Derived Accessors ============

    /// Returns the slot of the current safe target block.
    pub fn safe_target_slot(&self) -> u64 {
        self.get_block(&self.safe_target)
            .expect("safe target exists")
            .slot
    }

    /// Returns a clone of the head state.
    pub fn head_state(&self) -> State {
        self.get_state(&self.head)
            .expect("head state is always available")
    }
}
