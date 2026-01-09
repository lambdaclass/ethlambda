use ethlambda_types::{
    attestation::Attestations,
    block::{Block, BlockHeader},
    primitives::{H256, TreeHash},
    state::{JustifiedSlots, State},
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
    #[error("parent root doesn't match: expected {expected}, found {found}")]
    InvalidParent { expected: H256, found: H256 },
}

pub fn state_transition(state: &mut State, block: &Block) -> Result<(), Error> {
    process_slots(state, block.slot)?;
    process_block(state, block)?;
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
    // TODO: cache the pre-block state root?
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

fn process_attestations(state: &mut State, attestations: &Attestations) -> Result<(), Error> {
    Ok(())
}
