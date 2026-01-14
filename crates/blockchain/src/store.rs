use std::collections::HashMap;

use ethlambda_types::{
    attestation::{Attestation, AttestationData, XmssSignature},
    block::{AggregationBits, Block, NaiveAggregatedSignature, SignedBlockWithAttestation},
    primitives::{Decode, H256, TreeHash},
    signature::Signature,
    state::{ChainConfig, Checkpoint, State},
};
use tracing::{info, warn};

use crate::SECONDS_PER_SLOT;

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
    // TODO: change back to AggregatedSignatureProof when implemented
    // aggregated_payloads: HashMap<SignatureKey, Vec<AggregatedSignatureProof>>,
    aggregated_payloads: HashMap<SignatureKey, Vec<NaiveAggregatedSignature>>,
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
            gossip_signatures: HashMap::new(),
            aggregated_payloads: HashMap::new(),
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

    /// Validate incoming attestation before processing.
    ///
    /// Ensures the vote respects the basic laws of time and topology:
    ///     1. The blocks voted for must exist in our store.
    ///     2. A vote cannot span backwards in time (source > target).
    ///     3. A vote cannot be for a future slot.
    pub fn validate_attestation(&self, attestation: &Attestation) -> Result<(), StoreError> {
        let data = &attestation.data;

        // Availability Check - We cannot count a vote if we haven't seen the blocks involved.
        if !self.blocks.contains_key(&data.source.root) {
            return Err(StoreError::UnknownSourceBlock(data.source.root));
        }
        if !self.blocks.contains_key(&data.target.root) {
            return Err(StoreError::UnknownTargetBlock(data.target.root));
        }
        if !self.blocks.contains_key(&data.head.root) {
            return Err(StoreError::UnknownHeadBlock(data.head.root));
        }

        // Topology Check - Source must be older than Target.
        if data.source.slot > data.target.slot {
            return Err(StoreError::SourceExceedsTarget);
        }

        // TODO: Consistency Check - Validate checkpoint slots match block slots

        // TODO: Time Check - Validate attestation is not too far in the future

        Ok(())
    }

    /// Process a new attestation and place it into the correct attestation stage.
    ///
    /// Attestations can come from:
    /// - a block body (on-chain, `is_from_block=true`), or
    /// - the gossip network (off-chain, `is_from_block=false`).
    ///
    /// The Attestation Pipeline:
    /// - Stage 1 (latest_new_attestations): Pending attestations not yet counted in fork choice.
    /// - Stage 2 (latest_known_attestations): Active attestations used by LMD-GHOST.
    pub fn on_attestation(
        &mut self,
        attestation: Attestation,
        is_from_block: bool,
    ) -> Result<(), StoreError> {
        // First, ensure the attestation is structurally and temporally valid.
        self.validate_attestation(&attestation)?;

        let validator_id = attestation.validator_id;
        let attestation_data = attestation.data;
        let attestation_slot = attestation_data.slot;

        if is_from_block {
            // On-chain attestation processing
            // These are historical attestations from other validators included by the proposer.
            // They are processed immediately as "known" attestations.

            let should_update = self
                .latest_known_attestations
                .get(&validator_id)
                .map_or(true, |latest| latest.slot < attestation_slot);

            if should_update {
                self.latest_known_attestations
                    .insert(validator_id, attestation_data.clone());
            }

            // Remove pending attestation if superseded by on-chain attestation
            if let Some(existing_new) = self.latest_new_attestations.get(&validator_id) {
                if existing_new.slot <= attestation_slot {
                    self.latest_new_attestations.remove(&validator_id);
                }
            }
        } else {
            // Network gossip attestation processing
            // These enter the "new" stage and must wait for interval tick acceptance.

            // Reject attestations from future slots
            let time_slots = self.time / SECONDS_PER_SLOT;
            if attestation_slot > time_slots {
                return Err(StoreError::FutureAttestation);
            }

            let should_update = self
                .latest_new_attestations
                .get(&validator_id)
                .map_or(true, |latest| latest.slot < attestation_slot);

            if should_update {
                self.latest_new_attestations
                    .insert(validator_id, attestation_data);
            }
        }

        Ok(())
    }

    /// Process a new block and update the forkchoice state.
    ///
    /// This method integrates a block into the forkchoice store by:
    /// 1. Validating the block's parent exists
    /// 2. Computing the post-state via the state transition function
    /// 3. Processing attestations included in the block body (on-chain)
    /// 4. Updating the forkchoice head
    /// 5. Processing the proposer's attestation (as if gossiped)
    pub fn on_block(&mut self, signed_block: SignedBlockWithAttestation) -> Result<(), StoreError> {
        // Unpack block components
        let block = signed_block.message.block.clone();
        let proposer_attestation = signed_block.message.proposer_attestation.clone();
        let block_root = block.tree_hash_root();
        let slot = block.slot;

        // Skip duplicate blocks (idempotent operation)
        if self.blocks.contains_key(&block_root) {
            return Ok(());
        }

        // Verify parent chain is available
        // TODO: sync parent chain if parent is missing
        let parent_state =
            self.states
                .get(&block.parent_root)
                .ok_or(StoreError::MissingParentState {
                    parent_root: block.parent_root,
                    slot,
                })?;

        // Validate cryptographic signatures
        // TODO: change error
        verify_signatures(parent_state, &signed_block)?;

        // Execute state transition function to compute post-block state
        let mut post_state = parent_state.clone();
        ethlambda_state_transition::state_transition(&mut post_state, &block)?;

        // Cache the state root in the latest block header
        let state_root = block.state_root;
        post_state.latest_block_header.state_root = state_root;

        // If post-state has a higher justified checkpoint, update the store
        if post_state.latest_justified.slot > self.latest_justified.slot {
            self.latest_justified = post_state.latest_justified;
        }

        // If post-state has a higher finalized checkpoint, update the store
        if post_state.latest_finalized.slot > self.latest_finalized.slot {
            self.latest_finalized = post_state.latest_finalized;
        }

        // Store block and state
        self.blocks.insert(block_root, block.clone());
        self.states.insert(block_root, post_state);

        // Process block body attestations and their signatures
        let aggregated_attestations = &block.body.attestations;
        let attestation_signatures = &signed_block.signature.attestation_signatures;

        // Process block body attestations.
        // TODO: fail the block if an attestation is invalid. Right now we
        // just log a warning.
        for (att, proof) in aggregated_attestations
            .iter()
            .zip(attestation_signatures.iter())
        {
            let validator_ids = aggregation_bits_to_validator_indices(&att.aggregation_bits);
            let data_root = att.data.tree_hash_root();

            for validator_id in validator_ids {
                // Update Proof Map - Store the proof so future block builders can reuse this aggregation
                let key: SignatureKey = (validator_id, data_root);
                self.aggregated_payloads
                    .entry(key)
                    .or_default()
                    .push(proof.clone());

                // Update Fork Choice - Register the vote immediately (historical/on-chain)
                let attestation = Attestation {
                    validator_id,
                    data: att.data.clone(),
                };
                // TODO: validate attestations before processing
                if let Err(err) = self.on_attestation(attestation, true) {
                    warn!(%slot, %validator_id, %err, "Invalid attestation in block");
                }
            }
        }

        // Update forkchoice head based on new block and attestations
        // IMPORTANT: This must happen BEFORE processing proposer attestation
        // to prevent the proposer from gaining circular weight advantage.
        self.update_head();

        // Process proposer attestation as if received via gossip
        // The proposer's attestation should NOT affect this block's fork choice position.
        // It is treated as pending until interval 3 (end of slot).

        // Store the proposer's signature for potential future block building
        let proposer_sig_key: SignatureKey = (
            proposer_attestation.validator_id,
            proposer_attestation.data.tree_hash_root(),
        );
        self.gossip_signatures.insert(
            proposer_sig_key,
            signed_block.signature.proposer_signature.clone(),
        );

        // Process proposer attestation (enters "new" stage, not "known")
        // TODO: validate attestations before processing
        if let Err(err) = self.on_attestation(proposer_attestation, false) {
            warn!(%slot, %err, "Invalid proposer attestation in block");
        }

        info!(%slot, %block_root, %state_root, "Processed new block");
        Ok(())
    }
}

/// Errors that can occur during Store operations.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("Parent state not found for slot {slot}. Missing block: {parent_root}")]
    MissingParentState { parent_root: H256, slot: u64 },

    #[error("Validator index out of range")]
    InvalidValidatorIndex,

    #[error("State transition failed: {0}")]
    StateTransitionFailed(#[from] ethlambda_state_transition::Error),

    #[error("Unknown source block: {0}")]
    UnknownSourceBlock(H256),

    #[error("Unknown target block: {0}")]
    UnknownTargetBlock(H256),

    #[error("Unknown head block: {0}")]
    UnknownHeadBlock(H256),

    #[error("Source checkpoint slot exceeds target")]
    SourceExceedsTarget,

    #[error("Attestation is for future slot")]
    FutureAttestation,

    #[error(
        "Attestations and signatures don't match in length: got {signatures} signatures and {attestations} attestations"
    )]
    AttestationSignatureMismatch {
        signatures: usize,
        attestations: usize,
    },
}

/// Extract validator indices from aggregation bits.
fn aggregation_bits_to_validator_indices(bits: &AggregationBits) -> Vec<u64> {
    bits.iter()
        .enumerate()
        .filter_map(|(i, bit)| if bit { Some(i as u64) } else { None })
        .collect()
}

fn verify_signatures(
    state: &State,
    signed_block: &SignedBlockWithAttestation,
) -> Result<(), StoreError> {
    let block = &signed_block.message.block;
    let attestations = &block.body.attestations;
    let attestation_signatures = &signed_block.signature.attestation_signatures;

    if attestations.len() != attestation_signatures.len() {
        return Err(StoreError::AttestationSignatureMismatch {
            signatures: attestation_signatures.len(),
            attestations: attestations.len(),
        });
    }
    let validators = &state.validators;
    let num_validators = validators.len() as u64;

    for (attestation, _aggregated_signature) in attestations.iter().zip(attestation_signatures) {
        let validator_ids = aggregation_bits_to_validator_indices(&attestation.aggregation_bits);
        if validator_ids.iter().any(|vid| *vid >= num_validators) {
            return Err(StoreError::InvalidValidatorIndex);
        }
        // TODO: verify signatures
    }
    let proposer_attestation = &signed_block.message.proposer_attestation;
    let proposer_signature = &signed_block.signature.proposer_signature;
    let proposer = validators
        .get(block.proposer_index as usize)
        .expect("we already checked the proposer index is valid");

    // TODO: verify proposer signature
    Ok(())
}
