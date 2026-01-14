use std::collections::HashMap;

use ethlambda_types::{
    attestation::{AttestationData, XmssSignature},
    block::{AggregatedSignatureProof, Block, SignedBlockWithAttestation},
    primitives::{H256, TreeHash},
    state::{ChainConfig, Checkpoint, State},
};
use tracing::{info, warn};

/// Key for looking up individual validator signatures.
/// Used to index signature caches by (validator, message) pairs.
///
/// Values are (validator_index, attestation_data_root).
type SignatureKey = (u64, H256);

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
    gossip_signatures: HashMap<SignatureKey, XmssSignature>,

    /// Aggregated signature proofs learned from blocks.
    /// - Keyed by SignatureKey(validator_id, attestation_data_root).
    /// - Values are lists of AggregatedSignatureProof, each containing the participants
    ///   bitfield indicating which validators signed.
    /// - Used for recursive signature aggregation when building blocks.
    /// - Populated by on_block.
    aggregated_payloads: HashMap<SignatureKey, Vec<AggregatedSignatureProof>>,
}

impl Store {
    pub fn from_genesis(mut genesis_state: State) -> Self {
        // Ensure the header state root is zero before computing the state root
        genesis_state.latest_block_header.state_root = H256::ZERO;

        let genesis_state_root = genesis_state.tree_hash_root();
        let genesis_block = Block {
            slot: 0,
            proposer_index: 0,
            parent_root: H256::ZERO,
            state_root: genesis_state_root,
            body: Default::default(),
        };
        Self::get_forkchoice_store(genesis_state, genesis_block)
    }

    pub fn get_forkchoice_store(anchor_state: State, anchor_block: Block) -> Self {
        let anchor_state_root = anchor_state.tree_hash_root();
        let anchor_block_root = anchor_block.tree_hash_root();

        let mut blocks = HashMap::new();
        blocks.insert(anchor_block_root, anchor_block.clone());

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
        }
    }

    pub fn accept_new_attestations(&mut self) {
        let mut latest_new_attestations = std::mem::take(&mut self.latest_new_attestations);
        self.latest_known_attestations
            .extend(latest_new_attestations.drain());
        self.latest_new_attestations = latest_new_attestations;

        self.update_head();
    }

    pub fn update_head(&mut self) {
        let head = ethlambda_fork_choice::compute_lmd_ghost_head(
            self.latest_finalized.root,
            &self.blocks,
            &self.latest_known_attestations,
            0,
        );
        self.head = head;
    }

    pub fn update_safe_target(&mut self) {
        let head_state = &self.states[&self.head];
        let num_validators = head_state.validators.len() as u64;

        let min_target_score = (num_validators * 2).div_ceil(3);

        let safe_target = ethlambda_fork_choice::compute_lmd_ghost_head(
            self.latest_finalized.root,
            &self.blocks,
            &self.latest_known_attestations,
            min_target_score,
        );
        self.safe_target = safe_target;
    }

    pub fn on_block(&mut self, signed_block: SignedBlockWithAttestation) {
        let slot = signed_block.message.block.slot;

        let block = &signed_block.message.block;
        let proposer_attestation = &signed_block.message.proposer_attestation;
        let signatures = &signed_block.signature;

        let block_root = block.tree_hash_root();

        if self.blocks.contains_key(&block_root) {
            return;
        }

        let Some(pre_state) = self.states.get(&block.parent_root) else {
            // TODO: backfill missing blocks
            warn!(%slot, %block_root, parent=%block.parent_root, "Missing pre-state for new block");
            return;
        };

        if let Err(err) = verify_signatures(pre_state, &signed_block) {
            warn!(%slot, %block_root, %err, "Block has invalid signatures");
            return;
        }
        let mut post_state = pre_state.clone();

        if let Err(err) = ethlambda_state_transition::state_transition(&mut post_state, &block) {
            warn!(%slot, %block_root, %err, "State transition failed for new block");
            return;
        }
        // Cache the state root in the latest block header
        let state_root = block.state_root;
        post_state.latest_block_header.state_root = state_root;

        self.blocks
            .insert(block_root, signed_block.message.block.clone());
        self.states.insert(block_root, post_state);

        let attestations = &block.body.attestations;
        for (attestation, proof) in attestations.iter().zip(&signatures.attestation_signatures) {
            // Add attestation
        }

        self.latest_justified = post_state.latest_justified;
        self.latest_finalized = post_state.latest_finalized;

        self.update_head();

        info!(%slot, %block_root, %state_root, "Processed new block");
    }
}

fn verify_signatures(
    state: &State,
    signed_block: &SignedBlockWithAttestation,
) -> Result<(), String> {
    // TODO: validate signatures
    Ok(())
}
