use std::collections::HashMap;

use ethlambda_types::{
    attestation::AttestationData,
    block::{AggregatedSignatureProof, Block, BlockBody},
    primitives::{H256, TreeHash},
    signature::ValidatorSignature,
    state::{ChainConfig, Checkpoint, State},
};
use tracing::info;

/// Key for looking up individual validator signatures.
/// Used to index signature caches by (validator, message) pairs.
///
/// Values are (validator_index, attestation_data_root).
pub type SignatureKey = (u64, H256);

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

    /// Mapping from block root to Block objects.
    ///
    /// This is the set of blocks that the node currently knows about.
    ///
    /// Every block that might participate in fork choice must appear here.
    blocks: HashMap<H256, Block>,

    /// Mapping from block root to State objects.
    ///
    /// For each known block, we keep its post-state.
    ///
    /// These states carry justified and finalized checkpoints that we use to update the
    /// `Store`'s latest justified and latest finalized checkpoints.
    states: HashMap<H256, State>,

    /// Latest signed attestations by validator that have been processed.
    ///
    /// - These attestations are "known" and contribute to fork choice weights.
    /// - Keyed by validator index to enforce one attestation per validator.
    latest_known_attestations: HashMap<u64, AttestationData>,

    /// Latest signed attestations by validator that are pending processing.
    ///
    /// - These attestations are "new" and do not yet contribute to fork choice.
    /// - They migrate to `latest_known_attestations` via interval ticks.
    /// - Keyed by validator index to enforce one attestation per validator.
    latest_new_attestations: HashMap<u64, AttestationData>,

    /// Per-validator XMSS signatures learned from gossip.
    ///
    /// Keyed by SignatureKey(validator_id, attestation_data_root).
    gossip_signatures: HashMap<SignatureKey, ValidatorSignature>,

    /// Aggregated signature proofs learned from blocks.
    /// - Keyed by SignatureKey(validator_id, attestation_data_root).
    /// - Values are lists of AggregatedSignatureProof, each containing the participants
    ///   bitfield indicating which validators signed.
    /// - Used for recursive signature aggregation when building blocks.
    /// - Populated by on_block.
    aggregated_payloads: HashMap<SignatureKey, Vec<AggregatedSignatureProof>>,
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

        let mut blocks = HashMap::new();
        blocks.insert(anchor_block_root, anchor_block);

        let mut states = HashMap::new();
        states.insert(anchor_block_root, anchor_state.clone());

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
            blocks,
            states,
            latest_known_attestations: HashMap::new(),
            latest_new_attestations: HashMap::new(),
            gossip_signatures: HashMap::new(),
            aggregated_payloads: HashMap::new(),
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
        blocks: HashMap<H256, Block>,
        states: HashMap<H256, State>,
    ) -> Self {
        Self {
            time,
            config,
            head,
            safe_target,
            latest_justified,
            latest_finalized,
            blocks,
            states,
            latest_known_attestations: HashMap::new(),
            latest_new_attestations: HashMap::new(),
            gossip_signatures: HashMap::new(),
            aggregated_payloads: HashMap::new(),
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

    pub fn set_head(&mut self, head: H256) {
        self.head = head;
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

    pub fn set_latest_justified(&mut self, checkpoint: Checkpoint) {
        self.latest_justified = checkpoint;
    }

    // ============ Latest Finalized ============

    pub fn latest_finalized(&self) -> &Checkpoint {
        &self.latest_finalized
    }

    pub fn set_latest_finalized(&mut self, checkpoint: Checkpoint) {
        self.latest_finalized = checkpoint;
    }

    // ============ Blocks ============

    pub fn blocks(&self) -> &HashMap<H256, Block> {
        &self.blocks
    }

    pub fn get_block(&self, root: &H256) -> Option<&Block> {
        self.blocks.get(root)
    }

    pub fn contains_block(&self, root: &H256) -> bool {
        self.blocks.contains_key(root)
    }

    pub fn insert_block(&mut self, root: H256, block: Block) {
        self.blocks.insert(root, block);
    }

    // ============ States ============

    pub fn states(&self) -> &HashMap<H256, State> {
        &self.states
    }

    pub fn get_state(&self, root: &H256) -> Option<&State> {
        self.states.get(root)
    }

    pub fn insert_state(&mut self, root: H256, state: State) {
        self.states.insert(root, state);
    }

    // ============ Latest Known Attestations ============

    pub fn latest_known_attestations(&self) -> &HashMap<u64, AttestationData> {
        &self.latest_known_attestations
    }

    pub fn get_known_attestation(&self, validator_id: &u64) -> Option<&AttestationData> {
        self.latest_known_attestations.get(validator_id)
    }

    pub fn insert_known_attestation(&mut self, validator_id: u64, data: AttestationData) {
        self.latest_known_attestations.insert(validator_id, data);
    }

    // ============ Latest New Attestations ============

    pub fn latest_new_attestations(&self) -> &HashMap<u64, AttestationData> {
        &self.latest_new_attestations
    }

    pub fn get_new_attestation(&self, validator_id: &u64) -> Option<&AttestationData> {
        self.latest_new_attestations.get(validator_id)
    }

    pub fn insert_new_attestation(&mut self, validator_id: u64, data: AttestationData) {
        self.latest_new_attestations.insert(validator_id, data);
    }

    pub fn remove_new_attestation(&mut self, validator_id: &u64) {
        self.latest_new_attestations.remove(validator_id);
    }

    /// Promotes all new attestations to known attestations.
    ///
    /// Takes all attestations from `latest_new_attestations` and moves them
    /// to `latest_known_attestations`, making them count for fork choice.
    pub fn promote_new_attestations(&mut self) {
        let mut new_attestations = std::mem::take(&mut self.latest_new_attestations);
        self.latest_known_attestations
            .extend(new_attestations.drain());
        self.latest_new_attestations = new_attestations;
    }

    // ============ Gossip Signatures ============

    pub fn gossip_signatures(&self) -> &HashMap<SignatureKey, ValidatorSignature> {
        &self.gossip_signatures
    }

    pub fn get_gossip_signature(&self, key: &SignatureKey) -> Option<&ValidatorSignature> {
        self.gossip_signatures.get(key)
    }

    pub fn contains_gossip_signature(&self, key: &SignatureKey) -> bool {
        self.gossip_signatures.contains_key(key)
    }

    pub fn insert_gossip_signature(&mut self, key: SignatureKey, signature: ValidatorSignature) {
        self.gossip_signatures.insert(key, signature);
    }

    // ============ Aggregated Payloads ============

    pub fn aggregated_payloads(&self) -> &HashMap<SignatureKey, Vec<AggregatedSignatureProof>> {
        &self.aggregated_payloads
    }

    pub fn get_aggregated_payloads(
        &self,
        key: &SignatureKey,
    ) -> Option<&Vec<AggregatedSignatureProof>> {
        self.aggregated_payloads.get(key)
    }

    pub fn push_aggregated_payload(&mut self, key: SignatureKey, proof: AggregatedSignatureProof) {
        self.aggregated_payloads.entry(key).or_default().push(proof);
    }
}
