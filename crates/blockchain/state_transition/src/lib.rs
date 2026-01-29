use std::collections::HashMap;

use ethlambda_types::{
    block::{AggregatedAttestations, Block, BlockHeader},
    primitives::{H256, TreeHash},
    state::{Checkpoint, JustificationValidators, State},
    ShortRoot,
};
use tracing::info;

mod justified_slots_ops;
pub mod metrics;

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
    let _timing = metrics::time_state_transition();

    process_slots(state, block.slot)?;
    process_block(state, block)?;

    // Uncomment for debugging state transitions
    // std::fs::write(
    //     &format!("block_slot_{}.ssz", state.slot),
    //     block.as_ssz_bytes(),
    // )
    // .unwrap();
    // std::fs::write(
    //     &format!("post_state_slot_{}.ssz", state.slot),
    //     state.as_ssz_bytes(),
    // )
    // .unwrap();

    let computed_state_root = state.tree_hash_root();
    if block.state_root != computed_state_root {
        return Err(Error::StateRootMismatch {
            expected: block.state_root,
            computed: computed_state_root,
        });
    }
    Ok(())
}

/// Advance the state through empty slots up to, but not including, target_slot.
pub fn process_slots(state: &mut State, target_slot: u64) -> Result<(), Error> {
    let _timing = metrics::time_slots_processing();

    if state.slot >= target_slot {
        return Err(Error::StateSlotIsNewer {
            target_slot,
            current_slot: state.slot,
        });
    }
    if state.latest_block_header.state_root == H256::ZERO {
        // Special case: cache the state root if not already set.
        state.latest_block_header.state_root = state.tree_hash_root();
    }
    let slots_processed = target_slot - state.slot;
    state.slot = target_slot;
    metrics::inc_slots_processed(slots_processed);
    Ok(())
}

/// Apply full block processing including header and body.
pub fn process_block(state: &mut State, block: &Block) -> Result<(), Error> {
    let _timing = metrics::time_block_processing();

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

    // Extend justified_slots to cover slots up to (block.slot - 1)
    //
    // The storage is relative to the finalized boundary.
    // The current block's slot is not materialized until processing completes,
    // so we only extend up to the last materialized slot.
    let last_materialized_slot = block.slot - 1;
    justified_slots_ops::extend_to_slot(
        &mut state.justified_slots,
        state.latest_finalized.slot,
        last_materialized_slot,
    );

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

/// Check if a validator is the proposer for a given slot.
///
/// Proposer selection uses simple round-robin: `slot % num_validators`.
pub fn is_proposer(validator_index: u64, slot: u64, num_validators: u64) -> bool {
    if num_validators == 0 {
        return false;
    }
    current_proposer(slot, num_validators) == validator_index
}

/// Apply attestations and update justification/finalization
/// according to the Lean Consensus 3SF-mini rules.
fn process_attestations(
    state: &mut State,
    attestations: &AggregatedAttestations,
) -> Result<(), Error> {
    let _timing = metrics::time_attestations_processing();
    let validator_count = state.validators.len();
    let mut attestations_processed: u64 = 0;
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

    // For is_justifiable_after checks (must use original value, not updated during iteration)
    let original_finalized_slot = state.latest_finalized.slot;

    // Map roots to their latest slot for pruning.
    //
    // Votes for zero hash are ignored, so we only need the most recent slot
    // where a root appears to decide whether it is still unfinalized.
    let mut root_to_slot: HashMap<H256, u64> = HashMap::new();
    for slot in (state.latest_finalized.slot + 1)..state.historical_block_hashes.len() as u64 {
        if let Some(root) = state.historical_block_hashes.get(slot as usize) {
            root_to_slot
                .entry(*root)
                .and_modify(|x| *x = (*x).max(slot))
                .or_insert(slot);
        }
    }

    for attestation in attestations {
        let attestation_data = &attestation.data;
        let source = attestation_data.source;
        let target = attestation_data.target;

        // Check that the source is already justified
        if !justified_slots_ops::is_slot_justified(
            &state.justified_slots,
            state.latest_finalized.slot,
            source.slot,
        ) {
            // TODO: why doesn't this make the block invalid?
            continue;
        }

        // Ignore votes for targets that have already reached consensus
        if justified_slots_ops::is_slot_justified(
            &state.justified_slots,
            state.latest_finalized.slot,
            target.slot,
        ) {
            continue;
        }

        // Ignore votes that reference zero-hash slots.
        if source.root == H256::ZERO || target.root == H256::ZERO {
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
        if !slot_is_justifiable_after(target.slot, original_finalized_slot) {
            continue;
        }

        // Record the vote
        attestations_processed += 1;
        let votes = justifications
            .entry(target.root)
            .or_insert_with(|| std::iter::repeat_n(false, validator_count).collect());
        // Mark that each validator in this aggregation has voted for the target.
        for (validator_id, _) in attestation
            .aggregation_bits
            .iter()
            .enumerate()
            .filter(|(_, voted)| *voted)
        {
            votes[validator_id] = true;
        }

        // Check whether the vote count crosses the supermajority threshold
        let vote_count = votes.iter().filter(|voted| **voted).count();
        if 3 * vote_count >= 2 * validator_count {
            // The block becomes justified
            state.latest_justified = target;
            justified_slots_ops::set_justified(
                &mut state.justified_slots,
                state.latest_finalized.slot,
                target.slot,
            );

            info!(
                justified_slot = target.slot,
                justified_root = %ShortRoot(&target.root.0),
                vote_count = vote_count,
                threshold = (2 * validator_count).div_ceil(3),
                "Checkpoint justified"
            );

            justifications.remove(&target.root);

            // Consider whether finalization can advance.
            // Use ORIGINAL finalized slot for is_justifiable_after check.
            if !((source.slot + 1)..target.slot)
                .any(|slot| slot_is_justifiable_after(slot, original_finalized_slot))
            {
                let old_finalized_slot = state.latest_finalized.slot;
                state.latest_finalized = source;
                metrics::inc_finalizations("success");

                info!(
                    finalized_slot = source.slot,
                    finalized_root = %ShortRoot(&source.root.0),
                    previous_finalized = old_finalized_slot,
                    justified_slot = state.latest_justified.slot,
                    "Checkpoint finalized"
                );

                // Shift window to drop finalized slots from the front
                let delta = (state.latest_finalized.slot - old_finalized_slot) as usize;
                justified_slots_ops::shift_window(&mut state.justified_slots, delta);

                // Prune justifications whose roots only appear at now-finalized slots
                justifications.retain(|root, _| {
                    let slot = root_to_slot[root];
                    slot > state.latest_finalized.slot
                });
            } else {
                metrics::inc_finalizations("error");
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
    let mut justifications_validators =
        JustificationValidators::with_capacity(justification_roots.len() * validator_count)
            .expect("maximum validator justifications reached");
    justification_roots
        .iter()
        .flat_map(|root| justifications[root].iter())
        .enumerate()
        .filter(|(_, voted)| **voted)
        .for_each(|(i, _)| {
            justifications_validators
                .set(i, true)
                .expect("we just updated the capacity")
        });
    state.justifications_roots = justification_roots
        .try_into()
        .expect("justifications_roots limit exceeded");
    state.justifications_validators = justifications_validators;
    metrics::inc_attestations_processed(attestations_processed);
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
///
/// See https://github.com/ethereum/research/blob/c003fe1c1a785797e7b53e3cbf9569b989be6e93/3sf-mini/consensus.py#L52-L54
/// for the 3SF-mini reference.
///
/// For why we have unjustifiable slots, consider that in high-latency
/// scenarios, validators may vote for many different slots, making none of them
/// reach the supermajority threshold. By having unjustifiable slots, we can
/// funnel votes towards only some slots, increasing finalization chances.
pub fn slot_is_justifiable_after(slot: u64, finalized_slot: u64) -> bool {
    let Some(delta) = slot.checked_sub(finalized_slot) else {
        // Candidate slot must not be before finalized slot
        return false;
    };
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
        || (4*delta + 1).isqrt().pow(2) == 4*delta + 1 && (4*delta + 1) % 2 == 1
}
