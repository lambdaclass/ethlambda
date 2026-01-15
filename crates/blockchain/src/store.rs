use std::collections::{HashMap, HashSet};

use ethlambda_state_transition::{process_block, process_slots, slot_is_justifiable_after};
use ethlambda_types::{
    attestation::{
        AggregatedAttestation, Attestation, AttestationData, SignedAttestation, XmssSignature,
    },
    block::{
        AggregatedAttestations, AggregationBits, Block, BlockBody, NaiveAggregatedSignature,
        SignedBlockWithAttestation,
    },
    primitives::{H256, TreeHash},
    state::{ChainConfig, Checkpoint, State},
};
use tracing::{info, trace, warn};

use crate::SECONDS_PER_SLOT;

const JUSTIFICATION_LOOKBACK_SLOTS: u64 = 3;

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
            self.latest_justified.root,
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
            self.latest_justified.root,
            &self.blocks,
            &self.latest_new_attestations,
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

    pub fn on_tick(&mut self, timestamp: u64, has_proposal: bool) {
        let time = timestamp - self.config.genesis_time;

        // If we're more than a slot behind, fast-forward to a slot before.
        // Operations are idempotent, so this should be fine.
        if time.saturating_sub(self.time) > SECONDS_PER_SLOT {
            self.time = time - SECONDS_PER_SLOT;
        }

        while self.time < time {
            self.time += 1;

            let slot = self.time / SECONDS_PER_SLOT;
            let interval = self.time % SECONDS_PER_SLOT;

            trace!(%slot, %interval, "processing tick");

            // has_proposal is only signaled for the final tick (matching Python spec behavior)
            let is_final_tick = self.time == time;
            let should_signal_proposal = has_proposal && is_final_tick;

            // NOTE: here we assume on_tick never skips intervals
            match interval {
                0 => {
                    // Start of slot - process attestations if proposal exists
                    if should_signal_proposal {
                        self.accept_new_attestations();
                    }
                }
                1 => {
                    // Second interval - no action
                }
                2 => {
                    // Mid-slot - update safe target for validators
                    self.update_safe_target();
                }
                3 => {
                    // End of slot - accept accumulated attestations
                    self.accept_new_attestations();
                }
                _ => unreachable!("slots only have 4 intervals"),
            }
        }
    }

    pub fn on_gossip_attestation(
        &mut self,
        signed_attestation: SignedAttestation,
    ) -> Result<(), StoreError> {
        let validator_id = signed_attestation.validator_id;
        let attestation = Attestation {
            validator_id,
            data: signed_attestation.message,
        };
        self.validate_attestation(&attestation)?;
        let target = attestation.data.target;
        let target_state = self
            .states
            .get(&target.root)
            .ok_or(StoreError::MissingTargetState(target.root))?;
        if validator_id >= target_state.validators.len() as u64 {
            return Err(StoreError::InvalidValidatorIndex);
        }
        let validator_pubkey = target_state.validators[validator_id as usize]
            .get_pubkey()
            .map_err(|_| StoreError::PubkeyDecodingFailed(validator_id))?;
        let message = attestation.data.tree_hash_root();
        #[cfg(not(feature = "skip-signature-verification"))]
        {
            use ethlambda_types::signature::ValidatorSignature;
            let epoch = target.slot.try_into().expect("slot exceeds u32");
            let signature = ValidatorSignature::from_bytes(&signed_attestation.signature)
                .map_err(|_| StoreError::SignatureDecodingFailed)?;
            if !validator_pubkey.is_valid(epoch, &message, &signature) {
                return Err(StoreError::SignatureVerificationFailed);
            }
        }
        #[cfg(feature = "skip-signature-verification")]
        let _ = validator_pubkey;
        self.on_attestation(attestation, false)?;

        // Store signature for later lookup during block building
        let signature_key = (validator_id, message);
        self.gossip_signatures
            .insert(signature_key, signed_attestation.signature);
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
    fn on_attestation(
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
                .is_none_or(|latest| latest.slot < attestation_slot);

            if should_update {
                self.latest_known_attestations
                    .insert(validator_id, attestation_data.clone());
            }

            // Remove pending attestation if superseded by on-chain attestation
            if let Some(existing_new) = self.latest_new_attestations.get(&validator_id)
                && existing_new.slot <= attestation_slot
            {
                self.latest_new_attestations.remove(&validator_id);
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
                .is_none_or(|latest| latest.slot < attestation_slot);

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
        // TODO: extract signature verification to a pre-checks function
        // to avoid the need for this
        #[cfg(not(feature = "skip-signature-verification"))]
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

    /// Calculate target checkpoint for validator attestations.
    ///
    /// NOTE: this assumes that we have all the blocks from the head back to the latest finalized.
    pub fn get_attestation_target(&self) -> Checkpoint {
        // Start from current head
        let mut target_block_root = self.head;
        let mut target_block = &self.blocks[&target_block_root];

        let safe_target_block_slot = self.blocks[&self.safe_target].slot;

        // Walk back toward safe target (up to `JUSTIFICATION_LOOKBACK_SLOTS` steps)
        //
        // This ensures the target doesn't advance too far ahead of safe target,
        // providing a balance between liveness and safety.
        for _ in 0..JUSTIFICATION_LOOKBACK_SLOTS {
            if target_block.slot > safe_target_block_slot {
                target_block_root = target_block.parent_root;
                target_block = &self.blocks[&target_block_root];
            } else {
                break;
            }
        }

        // Ensure target is in justifiable slot range
        //
        // Walk back until we find a slot that satisfies justifiability rules
        // relative to the latest finalized checkpoint.
        while !slot_is_justifiable_after(target_block.slot, self.latest_finalized.slot) {
            target_block_root = target_block.parent_root;
            target_block = &self.blocks[&target_block_root];
        }
        Checkpoint {
            root: target_block_root,
            slot: target_block.slot,
        }
    }

    /// Produce attestation data for the given slot.
    pub fn produce_attestation_data(&self, slot: u64) -> AttestationData {
        // Get the head block the validator sees for this slot
        let head_checkpoint = Checkpoint {
            root: self.head,
            slot: self.blocks[&self.head].slot,
        };

        // Calculate the target checkpoint for this attestation
        let target_checkpoint = self.get_attestation_target();

        // Construct attestation data
        AttestationData {
            slot,
            head: head_checkpoint,
            target: target_checkpoint,
            source: self.latest_justified,
        }
    }

    /// Get the head for block proposal at the given slot.
    ///
    /// Ensures store is up-to-date and processes any pending attestations
    /// before returning the canonical head.
    pub fn get_proposal_head(&mut self, slot: u64) -> H256 {
        // Calculate time corresponding to this slot
        let slot_time = self.config.genesis_time + slot * SECONDS_PER_SLOT;

        // Advance time to current slot (ticking intervals)
        self.on_tick(slot_time, true);

        // Process any pending attestations before proposal
        self.accept_new_attestations();

        self.head
    }

    /// Produce a block and per-aggregated-attestation signature payloads for the target slot.
    ///
    /// Returns the finalized block and attestation signature payloads aligned
    /// with `block.body.attestations`.
    pub fn produce_block_with_signatures(
        &mut self,
        slot: u64,
        validator_index: u64,
    ) -> Result<(Block, Vec<NaiveAggregatedSignature>), StoreError> {
        // Get parent block and state to build upon
        let head_root = self.get_proposal_head(slot);
        let head_state = self
            .states
            .get(&head_root)
            .ok_or(StoreError::MissingParentState {
                parent_root: head_root,
                slot,
            })?
            .clone();

        // Validate proposer authorization for this slot
        let num_validators = head_state.validators.len() as u64;
        if !is_proposer(validator_index, slot, num_validators) {
            return Err(StoreError::NotProposer {
                validator_index,
                slot,
            });
        }

        // Convert AttestationData to Attestation objects for build_block
        let available_attestations: Vec<Attestation> = self
            .latest_known_attestations
            .iter()
            .map(|(&validator_id, data)| Attestation {
                validator_id,
                data: data.clone(),
            })
            .collect();

        // Get known block roots for attestation validation
        let known_block_roots: HashSet<H256> = self.blocks.keys().copied().collect();

        // Build the block using fixed-point attestation collection
        let (block, _post_state, signatures) = build_block(
            &head_state,
            slot,
            validator_index,
            head_root,
            &available_attestations,
            &known_block_roots,
            &self.gossip_signatures,
            &self.aggregated_payloads,
        )?;

        Ok((block, signatures))
    }

    /// Returns the root of the current canonical chain head block.
    pub fn head(&self) -> H256 {
        self.head
    }

    /// Returns a reference to all known blocks.
    pub fn blocks(&self) -> &HashMap<H256, Block> {
        &self.blocks
    }

    /// Returns a reference to the latest known attestations by validator.
    pub fn latest_known_attestations(&self) -> &HashMap<u64, AttestationData> {
        &self.latest_known_attestations
    }

    /// Returns a reference to the latest new (pending) attestations by validator.
    pub fn latest_new_attestations(&self) -> &HashMap<u64, AttestationData> {
        &self.latest_new_attestations
    }

    /// Returns a reference to the latest justified checkpoint.
    pub fn latest_justified(&self) -> &Checkpoint {
        &self.latest_justified
    }

    /// Returns a reference to the latest finalized checkpoint.
    pub fn latest_finalized(&self) -> &Checkpoint {
        &self.latest_finalized
    }
}

/// Errors that can occur during Store operations.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("Parent state not found for slot {slot}. Missing block: {parent_root}")]
    MissingParentState { parent_root: H256, slot: u64 },

    #[error("Validator index out of range")]
    InvalidValidatorIndex,

    #[error("Failed to decode validator {0}'s public key")]
    PubkeyDecodingFailed(u64),

    #[error("Validator signature could not be decoded")]
    SignatureDecodingFailed,

    #[error("Validator signature verification failed")]
    SignatureVerificationFailed,

    #[error("Proposer signature could not be decoded")]
    ProposerSignatureDecodingFailed,

    #[error("Proposer signature verification failed")]
    ProposerSignatureVerificationFailed,

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

    #[error("Missing target state for block: {0}")]
    MissingTargetState(H256),

    #[error("Validator {validator_index} is not the proposer for slot {slot}")]
    NotProposer { validator_index: u64, slot: u64 },
}

/// Check if a validator is the proposer for a given slot.
///
/// Proposer selection uses simple round-robin: `slot % num_validators`.
fn is_proposer(validator_index: u64, slot: u64, num_validators: u64) -> bool {
    if num_validators == 0 {
        return false;
    }
    slot % num_validators == validator_index
}

/// Extract validator indices from aggregation bits.
fn aggregation_bits_to_validator_indices(bits: &AggregationBits) -> Vec<u64> {
    bits.iter()
        .enumerate()
        .filter_map(|(i, bit)| if bit { Some(i as u64) } else { None })
        .collect()
}

/// Group individual attestations by their data and create aggregated attestations.
///
/// Attestations with identical `AttestationData` are combined into a single
/// `AggregatedAttestation` with a bitfield indicating participating validators.
fn aggregate_attestations_by_data(attestations: &[Attestation]) -> Vec<AggregatedAttestation> {
    // Group attestations by their data root
    let mut groups: HashMap<H256, (AttestationData, Vec<u64>)> = HashMap::new();

    for attestation in attestations {
        let data_root = attestation.data.tree_hash_root();
        groups
            .entry(data_root)
            .or_insert_with(|| (attestation.data.clone(), Vec::new()))
            .1
            .push(attestation.validator_id);
    }

    // Convert groups into aggregated attestations
    groups
        .into_values()
        .map(|(data, validator_ids)| {
            // Find max validator id to determine bitlist capacity
            let max_id = validator_ids.iter().copied().max().unwrap_or(0) as usize;
            let mut bits =
                AggregationBits::with_capacity(max_id + 1).expect("validator count exceeds limit");

            for vid in validator_ids {
                bits.set(vid as usize, true)
                    .expect("validator id exceeds capacity");
            }

            AggregatedAttestation {
                aggregation_bits: bits,
                data,
            }
        })
        .collect()
}

/// Build a valid block on top of this state.
fn build_block(
    head_state: &State,
    slot: u64,
    proposer_index: u64,
    parent_root: H256,
    available_attestations: &[Attestation],
    known_block_roots: &HashSet<H256>,
    gossip_signatures: &HashMap<SignatureKey, XmssSignature>,
    aggregated_payloads: &HashMap<SignatureKey, Vec<NaiveAggregatedSignature>>,
) -> Result<(Block, State, Vec<NaiveAggregatedSignature>), StoreError> {
    // Start with empty attestation set
    let mut attestations: Vec<Attestation> = Vec::new();

    // Track which attestations we've already considered (by validator_id, data_root)
    let mut included_keys: HashSet<SignatureKey> = HashSet::new();

    // Fixed-point loop: collect attestations until no new ones can be added
    let (post_state, aggregated_attestations) = loop {
        // Aggregate attestations by data for the candidate block
        let aggregated = aggregate_attestations_by_data(&attestations);
        let aggregated_attestations: AggregatedAttestations = aggregated
            .clone()
            .try_into()
            .expect("attestation count exceeds limit");

        // Create candidate block with current attestations (state_root is placeholder)
        let candidate_block = Block {
            slot,
            proposer_index,
            parent_root,
            state_root: H256::ZERO,
            body: BlockBody {
                attestations: aggregated_attestations,
            },
        };

        // Apply state transition: process_slots + process_block
        let mut post_state = head_state.clone();
        process_slots(&mut post_state, slot)?;
        process_block(&mut post_state, &candidate_block)?;

        // Find new valid attestations matching post-state requirements
        let mut new_attestations: Vec<Attestation> = Vec::new();

        for attestation in available_attestations {
            let data_root = attestation.data.tree_hash_root();
            let sig_key: SignatureKey = (attestation.validator_id, data_root);

            // Skip if already included
            if included_keys.contains(&sig_key) {
                continue;
            }

            // Skip if target block is unknown
            if !known_block_roots.contains(&attestation.data.head.root) {
                continue;
            }

            // Skip if attestation source does not match post-state's latest justified
            if attestation.data.source != post_state.latest_justified {
                continue;
            }

            // Only include if we have a signature for this attestation
            let has_gossip_sig = gossip_signatures.contains_key(&sig_key);
            let has_block_proof = aggregated_payloads.contains_key(&sig_key);
            if has_gossip_sig || has_block_proof {
                new_attestations.push(attestation.clone());
                included_keys.insert(sig_key);
            }
        }

        // Fixed point reached: no new attestations found
        if new_attestations.is_empty() {
            break (post_state, aggregated);
        }

        // Add new attestations and continue iteration
        attestations.extend(new_attestations);
    };

    // Compute signatures for each aggregated attestation
    let signatures: Vec<NaiveAggregatedSignature> = aggregated_attestations
        .iter()
        .map(|agg_att| {
            let data_root = agg_att.data.tree_hash_root();
            let validator_ids = aggregation_bits_to_validator_indices(&agg_att.aggregation_bits);

            // Collect signatures for participating validators
            let sigs: Vec<XmssSignature> = validator_ids
                .iter()
                .filter_map(|&vid| gossip_signatures.get(&(vid, data_root)).cloned())
                .collect();

            sigs.try_into().expect("signature count exceeds limit")
        })
        .collect();

    // Build final block with correct state root
    let final_aggregated: AggregatedAttestations = aggregated_attestations
        .try_into()
        .expect("attestation count exceeds limit");

    let final_block = Block {
        slot,
        proposer_index,
        parent_root,
        state_root: post_state.tree_hash_root(),
        body: BlockBody {
            attestations: final_aggregated,
        },
    };

    Ok((final_block, post_state, signatures))
}

#[cfg(not(feature = "skip-signature-verification"))]
fn verify_signatures(
    state: &State,
    signed_block: &SignedBlockWithAttestation,
) -> Result<(), StoreError> {
    use ethlambda_types::signature::ValidatorSignature;

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

    for (attestation, aggregated_signature) in attestations.iter().zip(attestation_signatures) {
        let validator_ids = aggregation_bits_to_validator_indices(&attestation.aggregation_bits);
        if validator_ids.iter().any(|vid| *vid >= num_validators) {
            return Err(StoreError::InvalidValidatorIndex);
        }
        let epoch = attestation.data.slot.try_into().expect("slot exceeds u32");
        let message = attestation.data.tree_hash_root();

        // TODO: move to aggregated verification
        for (validator, signature) in validator_ids.into_iter().zip(aggregated_signature) {
            let validator = validators
                .get(validator as usize)
                .ok_or(StoreError::InvalidValidatorIndex)?;
            let pubkey = validator
                .get_pubkey()
                .map_err(|_| StoreError::PubkeyDecodingFailed(validator.index))?;

            let validator_signature = ValidatorSignature::from_bytes(signature)
                .map_err(|_| StoreError::SignatureDecodingFailed)?;

            if !pubkey.is_valid(epoch, &message, &validator_signature) {
                return Err(StoreError::SignatureVerificationFailed);
            }
        }
    }

    let proposer_attestation = &signed_block.message.proposer_attestation;
    let proposer_signature =
        ValidatorSignature::from_bytes(&signed_block.signature.proposer_signature)
            .map_err(|_| StoreError::ProposerSignatureDecodingFailed)?;
    let proposer = validators
        .get(block.proposer_index as usize)
        .ok_or(StoreError::InvalidValidatorIndex)?;

    let proposer_pubkey = proposer
        .get_pubkey()
        .map_err(|_| StoreError::PubkeyDecodingFailed(proposer.index))?;
    let epoch = proposer_attestation
        .data
        .slot
        .try_into()
        .expect("slot exceeds u32");
    let message = proposer_attestation.data.tree_hash_root();
    if !proposer_pubkey.is_valid(epoch, &message, &proposer_signature) {
        return Err(StoreError::ProposerSignatureVerificationFailed);
    }
    Ok(())
}
