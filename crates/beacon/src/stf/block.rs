//! Block processing: the header, RANDAO, and eth1-vote steps that run before a
//! block's operations.
//!
//! Corresponds to the specification's "Block processing" section (`##
//! Beacon chain state transition function` > `### Block processing`), which is
//! `process_block` and the three steps it runs before handing off to
//! [`crate::stf::operations::process_operations`].

use crate::bls;
use crate::config::Config;
use crate::constants;
use crate::containers::{BeaconBlockHeader, BeaconState, phase0};
use crate::error::{Result, verify};
use crate::hash::hash;
use crate::helpers::accessors::{
    get_beacon_proposer_index, get_current_epoch, get_domain, get_randao_mix,
};
use crate::helpers::math::xor;
use crate::helpers::misc::compute_signing_root;
use crate::preset;
use crate::primitives::{HashTreeRoot as _, Root};

/// Applies a block's header, RANDAO reveal, eth1 vote, and operations to the
/// state, in the specification's order.
///
/// Called after [`super::process_slots`] has already advanced the state to the
/// block's slot, so everything here validates and mutates a state that is
/// already positioned at `block.slot`.
pub fn process_block(
    state: &mut BeaconState,
    block: &phase0::BeaconBlock,
    config: &Config,
) -> Result<()> {
    process_block_header(state, block)?;
    process_randao(state, &block.body)?;
    process_eth1_data(state, &block.body)?;
    crate::stf::operations::process_operations(state, &block.body, config)?;
    Ok(())
}

/// Validates the block's header against the state and records it as the
/// state's `latest_block_header`.
///
/// Checks, in order: the slot matches the state's current slot, the slot is
/// strictly after the previous header's, the proposer index is the one the
/// shuffling computes for this slot, the parent root matches the previous
/// header's own root, and the proposer has not been slashed. The slashed check
/// runs last because the specification itself runs it after the header has
/// already been overwritten, which is one more reason an invalid block cannot
/// be retried against the same state: by the time this returns an error, the
/// header it rejected the block for is already gone.
pub fn process_block_header(state: &mut BeaconState, block: &phase0::BeaconBlock) -> Result<()> {
    verify(block.slot == state.slot(), "block.slot == state.slot")?;
    verify(
        block.slot > state.latest_block_header().slot,
        "block.slot > state.latest_block_header.slot",
    )?;
    verify(
        block.proposer_index == get_beacon_proposer_index(state)?,
        "block.proposer_index == get_beacon_proposer_index(state)",
    )?;
    verify(
        block.parent_root == state.latest_block_header().hash_tree_root(),
        "block.parent_root == hash_tree_root(state.latest_block_header)",
    )?;

    *state.latest_block_header_mut() = BeaconBlockHeader {
        slot: block.slot,
        proposer_index: block.proposer_index,
        parent_root: block.parent_root,
        // Left zero for the reason given on `super::process_slot`'s doc
        // comment: a block cannot commit to the root of the state it produces.
        state_root: Root::zero(),
        body_root: block.body.hash_tree_root(),
    };

    verify(
        !state.validator(block.proposer_index)?.slashed,
        "proposer is not slashed",
    )?;
    Ok(())
}

/// Verifies the proposer's RANDAO reveal and mixes it into the current epoch's
/// randao mix.
///
/// The reveal signs the epoch rather than the slot, so the same signature would
/// verify for every slot of the epoch: the mix it feeds is per-epoch, not
/// per-slot, and a skipped slot leaves nothing for the next proposer to reveal
/// differently.
pub fn process_randao(state: &mut BeaconState, body: &phase0::BeaconBlockBody) -> Result<()> {
    let epoch = get_current_epoch(state);
    let proposer_index = get_beacon_proposer_index(state)?;
    let domain = get_domain(state, constants::DOMAIN_RANDAO, None);
    let signing_root = compute_signing_root(epoch.hash_tree_root(), domain);

    let proposer = state.validator(proposer_index)?;
    verify(
        bls::verify(&proposer.pubkey, signing_root, &body.randao_reveal),
        "RANDAO reveal signature",
    )?;

    let mix = xor(get_randao_mix(state, epoch), hash(&body.randao_reveal.0));
    let position = epoch as usize % preset::EPOCHS_PER_HISTORICAL_VECTOR;
    state.randao_mixes_mut()[position] = mix;
    Ok(())
}

/// Records the block's eth1 vote, adopting it once it holds a majority within
/// the voting period.
///
/// The voting period is `EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH`, the
/// specification's own expression for it. Both are preset values rather than
/// per-chain configuration, which is why this function needs no `Config`. The
/// count used for the majority check includes the vote just appended, so a
/// single block can supply the deciding vote.
pub fn process_eth1_data(state: &mut BeaconState, body: &phase0::BeaconBlockBody) -> Result<()> {
    state.eth1_data_votes_mut().push(body.eth1_data.clone())?;

    let matching_votes = state
        .eth1_data_votes()
        .iter()
        .filter(|vote| **vote == body.eth1_data)
        .count() as u64;
    let voting_period_slots = preset::EPOCHS_PER_ETH1_VOTING_PERIOD * preset::SLOTS_PER_EPOCH;
    if matching_votes * 2 > voting_period_slots {
        *state.eth1_data_mut() = body.eth1_data.clone();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containers::Eth1Data;
    use crate::primitives::{BlsSignature, Bytes32};

    /// An otherwise-empty block body, since the header, RANDAO, and eth1 checks
    /// below never look past its `hash_tree_root`.
    fn empty_body() -> phase0::BeaconBlockBody {
        phase0::BeaconBlockBody {
            randao_reveal: BlsSignature::default(),
            eth1_data: Eth1Data::default(),
            graffiti: Bytes32::zero(),
            proposer_slashings: Default::default(),
            attester_slashings: Default::default(),
            attestations: Default::default(),
            deposits: Default::default(),
            voluntary_exits: Default::default(),
        }
    }

    #[test]
    fn a_mismatched_parent_root_is_rejected() {
        let mut state = crate::helpers::test_state::with_validators(8);
        let proposer_index = get_beacon_proposer_index(&state).unwrap();

        let block = phase0::BeaconBlock {
            slot: state.slot(),
            proposer_index,
            // Deliberately wrong: the real parent root is
            // `state.latest_block_header().hash_tree_root()`.
            parent_root: Root::repeat_byte(0xab),
            state_root: Root::zero(),
            body: empty_body(),
        };

        assert!(process_block_header(&mut state, &block).is_err());
    }

    #[test]
    fn a_slashed_proposer_is_rejected() {
        let mut state = crate::helpers::test_state::with_validators(8);
        let proposer_index = get_beacon_proposer_index(&state).unwrap();
        state.validator_mut(proposer_index).unwrap().slashed = true;

        let block = phase0::BeaconBlock {
            slot: state.slot(),
            proposer_index,
            parent_root: state.latest_block_header().hash_tree_root(),
            state_root: Root::zero(),
            body: empty_body(),
        };

        assert!(process_block_header(&mut state, &block).is_err());
    }
}
