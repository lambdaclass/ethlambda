use std::collections::HashMap;

use ethlambda_types::{
    block::{AggregatedAttestations, Block, BlockHeader},
    primitives::{H256, TreeHash},
    state::{Checkpoint, JustificationValidators, JustifiedSlots, State},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("target slot {target_slot} is in the past (current is {current_slot})")]
    StateSlotIsNewer { target_slot: u64, current_slot: u64 },
    #[error("advanced state slot {state_slot} is different from block slot {block_slot}")]
    SlotMismatch { state_slot: u64, block_slot: u64 },
    #[error("parent slot {parent_slot} is newer than block slot {block_slot}")]
    ParentSlotIsNewer { parent_slot: u64, block_slot: u64 },
    #[error("invalid proposer: expected {expected}, found {found}")]
    InvalidProposer { expected: u64, found: u64 },
    #[error("parent root mismatch: expected {expected}, found {found}")]
    InvalidParent { expected: H256, found: H256 },
    #[error("state root mismatch: expected {expected}, computed {computed}")]
    StateRootMismatch { expected: H256, computed: H256 },
}

/// Transition the given pre-state to the block's post-state.
///
/// Similar to the spec's `State.state_transition`: https://github.com/leanEthereum/leanSpec/blob/bf0f606a75095cf1853529bc770516b1464d9716/src/lean_spec/subspecs/containers/state/state.py#L569
pub fn state_transition(state: &mut State, block: &Block) -> Result<(), Error> {
    process_slots(state, block.slot)?;
    process_block(state, block)?;

    let computed_state_root = state.tree_hash_root();
    if block.state_root != computed_state_root {
        return Err(Error::StateRootMismatch {
            expected: block.state_root,
            computed: computed_state_root,
        });
    }

    // Cache the latest state root
    state.latest_block_header.state_root = computed_state_root;
    Ok(())
}

/// Advance the state through empty slots up to, but not including, target_slot.
fn process_slots(state: &mut State, target_slot: u64) -> Result<(), Error> {
    if state.slot >= target_slot {
        return Err(Error::StateSlotIsNewer {
            target_slot,
            current_slot: state.slot,
        });
    }
    // NOTE: we cache the state root at the end of the state_transition
    // function instead of here.
    state.slot = target_slot;
    Ok(())
}

/// Apply full block processing including header and body.
fn process_block(state: &mut State, block: &Block) -> Result<(), Error> {
    process_block_header(state, block)?;
    process_attestations(state, &block.body.attestations)?;
    Ok(())
}

/// Validate the block header and update header-linked state.
fn process_block_header(state: &mut State, block: &Block) -> Result<(), Error> {
    let parent_header = &state.latest_block_header;

    // Validation

    // TODO: this is redundant if we assume process_slots has been called
    if block.slot != state.slot {
        return Err(Error::SlotMismatch {
            state_slot: state.slot,
            block_slot: block.slot,
        });
    }
    if block.slot <= parent_header.slot {
        return Err(Error::ParentSlotIsNewer {
            parent_slot: parent_header.slot,
            block_slot: block.slot,
        });
    }
    let expected_proposer = current_proposer(block.slot, state.validators.len() as u64);
    if block.proposer_index != expected_proposer {
        return Err(Error::InvalidProposer {
            expected: expected_proposer,
            found: block.proposer_index,
        });
    }
    // TODO: this is redundant in normal operation
    let parent_root = parent_header.tree_hash_root();
    if block.parent_root != parent_root {
        return Err(Error::InvalidParent {
            expected: parent_root,
            found: block.parent_root,
        });
    }

    // State Updates

    // Special case: first block after genesis.
    // TODO: this could be moved to genesis state initialization
    let is_genesis_parent = parent_header.slot == 0;
    if is_genesis_parent {
        state.latest_justified.root = parent_root;
        state.latest_finalized.root = parent_root;
    }

    let num_empty_slots = (block.slot - parent_header.slot - 1) as usize;

    let mut historical_block_hashes: Vec<_> =
        std::mem::take(&mut state.historical_block_hashes).into();
    historical_block_hashes.push(parent_root);
    historical_block_hashes.extend(std::iter::repeat_n(H256::ZERO, num_empty_slots));

    state.historical_block_hashes = historical_block_hashes
        .try_into()
        .expect("maximum slots reached");

    // Extend justified_slots with [is_genesis_parent] + [false] * num_empty_slots
    // We do this by creating a new bitlist with enough capacity, which sets all bits to 0.
    // Then we compute the AND/union of both bitlists.
    // TODO: replace with a better API once we roll our own SSZ lib
    let mut justified_slots =
        JustifiedSlots::with_capacity(state.justified_slots.len() + 1 + num_empty_slots)
            .expect("maximum justified slots reached");

    justified_slots
        .set(state.justified_slots.len(), is_genesis_parent)
        .expect("we just created this with enough capacity");

    state.justified_slots = state.justified_slots.union(&justified_slots);

    let new_header = BlockHeader {
        slot: block.slot,
        proposer_index: block.proposer_index,
        parent_root: block.parent_root,
        body_root: block.body.tree_hash_root(),
        // Zeroed out until local state root computation.
        // This is later filled with the state root after all processing is done.
        state_root: H256::ZERO,
    };
    state.latest_block_header = new_header;
    Ok(())
}

/// Determine if a validator is the proposer for a given slot.
///
/// Uses round-robin proposer selection based on slot number and total
/// validator count, following the lean protocol specification.
fn current_proposer(slot: u64, num_validators: u64) -> u64 {
    slot % num_validators
}

/// Apply attestations and update justification/finalization
/// according to the Lean Consensus 3SF-mini rules.
fn process_attestations(state: &mut State, attestations: &AggregatedAttestations) -> Result<(), Error> {
    let validator_count = state.validators.len();
    let mut justifications: HashMap<H256, Vec<bool>> = state
        .justifications_roots
        .iter()
        .enumerate()
        .map(|(i, root)| {
            let votes = state
                .justifications_validators
                .iter()
                .skip(i * validator_count)
                .take(validator_count)
                .collect();
            (*root, votes)
        })
        .collect();

    for attestation in attestations {
        let attestation_data = &attestation.data;
        let source = attestation_data.source;
        let target = attestation_data.target;

        // Check that the source is already justified
        if !state
            .justified_slots
            .get(source.slot as usize)
            .unwrap_or(false)
        {
            // TODO: why doesn't this make the block invalid?
            continue;
        }

        // Ignore votes for targets that have already reached consensus
        if state
            .justified_slots
            .get(target.slot as usize)
            .unwrap_or(false)
        {
            continue;
        }

        // Ensure the vote refers to blocks that actually exist on our chain
        if !checkpoint_exists(state, source) || !checkpoint_exists(state, target) {
            continue;
        }

        // Ensure time flows forward
        if target.slot <= source.slot {
            continue;
        }

        // Ensure the target falls on a slot that can be justified after the finalized one.
        if !slot_is_justifiable_after(target.slot, state.latest_finalized.slot) {
            continue;
        }

        // Record the vote
        let votes = justifications.entry(target.root).or_insert_with(|| std::iter::repeat_n(false, validator_count).collect());
        // Mark that each validator in this aggregation has voted for the target.
        for (validator_id, _) in attestation.aggregation_bits.iter().enumerate().filter(|(_, voted)| *voted) {
            votes[validator_id] = true;
        }

        // Check whether the vote count crosses the supermajority threshold
        let vote_count = votes.iter().filter(|voted| **voted).count();
        if 3 *vote_count >= 2 * validator_count {
            // The block becomes justified
            state.latest_justified = target;
            state.justified_slots.set(target.slot as usize, true).expect("we already resized in process_block_header");

            justifications.remove(&target.root);

            // Consider whether finalization can advance
            if !((source.slot + 1)..target.slot).any(|slot| slot_is_justifiable_after(slot, state.latest_finalized.slot)) {
                state.latest_finalized = source;
            }
        }
    }

    // Convert the vote structure back into SSZ format

    // Sorting ensures that every node produces identical state representation.
    let justification_roots = {
        let mut roots: Vec<H256> = justifications.keys().cloned().collect();
        roots.sort();
        roots
    };
    let mut justifications_validators = JustificationValidators::with_capacity(justification_roots.len() * validator_count).expect("maximum validator justifications reached");
    justification_roots.iter().flat_map(|root| justifications[root].iter()).enumerate().filter(|(_, voted)| **voted).for_each(|(i, _)| justifications_validators.set(i, true).expect("we just updated the capacity"));
    Ok(())
}

fn checkpoint_exists(state: &State, checkpoint: Checkpoint) -> bool {
    state
        .historical_block_hashes
        .get(checkpoint.slot as usize)
        .map(|root| root == &checkpoint.root)
        .unwrap_or(false)
}

/// Checks if the slot is a valid candidate for justification after a given finalized slot.
///
/// According to the 3SF-mini specification, a slot is justifiable if its
/// distance (`delta`) from the last finalized slot is:
///     1. Less than or equal to 5.
///     2. A perfect square (e.g., 9, 16, 25...).
///     3. A pronic number (of the form x^2 + x, e.g., 6, 12, 20...).
fn slot_is_justifiable_after(slot: u64, finalized_slot: u64) -> bool {
    let Some(delta) = slot.checked_sub(finalized_slot) else {
        // Candidate slot must not be before finalized slot
        return false;
    };
    return 
        // Rule 1: The first 5 slots after finalization are always justifiable.
        //
        // Examples: delta = 0, 1, 2, 3, 4, 5
        delta <= 5
        // Rule 2: Slots at perfect square distances are justifiable.
        //
        // Examples: delta = 1, 4, 9, 16, 25, 36, 49, 64, ...
        // Check: integer square root squared equals delta
        || delta.isqrt().pow(2) == delta
        // Rule 3: Slots at pronic number distances are justifiable.
        //
        // Pronic numbers have the form n(n+1): 2, 6, 12, 20, 30, 42, 56, ...
        // Mathematical insight: For pronic delta = n(n+1), we have:
        //   4*delta + 1 = 4n(n+1) + 1 = (2n+1)^2
        // Check: 4*delta+1 is an odd perfect square
        || (4*delta + 1).isqrt().pow(2) == 4*delta + 1 && (4*delta + 1) % 2 == 1;
}
