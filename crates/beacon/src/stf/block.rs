//! Block processing: the header, RANDAO, and eth1-vote steps every fork shares,
//! plus the per-fork drivers that run them (and each fork's own operations) in
//! the specification's order.
//!
//! Corresponds to the specification's "Block processing" section (`##
//! Beacon chain state transition function` > `### Block processing`), redefined
//! once per fork here the same way the specification itself redefines
//! `process_block` per fork rather than parameterising a single definition.
//! [`process_block`] is the dispatcher [`super::state_transition`] calls, and
//! [`process_block_phase0`] and [`process_block_altair`] are the two drivers it
//! dispatches to that are actually implemented; see [`super::bellatrix`] and its
//! siblings for the rest, and [`super`]'s module documentation for why none of
//! this needs a shared body type to do it.
//!
//! [`process_block_header`], [`process_randao`], and [`process_eth1_data`] take
//! the fields they read directly rather than a whole body, which is what lets
//! every driver, present and future, call the identical function regardless of
//! what else that fork's body carries.

use crate::bls;
use crate::config::Config;
use crate::constants;
use crate::containers::{self, BeaconBlockHeader, BeaconState, Eth1Data, altair, phase0};
use crate::error::{Result, verify};
use crate::hash::hash;
use crate::helpers::accessors::{
    get_beacon_proposer_index, get_current_epoch, get_domain, get_randao_mix,
};
use crate::helpers::math::xor;
use crate::helpers::misc::compute_signing_root;
use crate::preset;
use crate::primitives::{BlsSignature, HashTreeRoot as _, Root, Slot, ValidatorIndex};

use super::{ExecutionEngine, bellatrix, capella, deneb, electra, fulu};

/// Dispatches on the block's fork and runs that fork's own block processing.
///
/// Matches [`containers::SignedBeaconBlock`]'s variant once, then hands the
/// unwrapped, fork-specific `BeaconBlock` to the function written for it. Called
/// after [`super::process_slots`] has already advanced the state to the block's
/// slot, so every arm validates and mutates a state already positioned at
/// `signed_block`'s slot.
pub fn process_block(
    state: &mut BeaconState,
    signed_block: &containers::SignedBeaconBlock,
    config: &Config,
    engine: &ExecutionEngine,
) -> Result<()> {
    match signed_block {
        containers::SignedBeaconBlock::Phase0(signed) => {
            process_block_phase0(state, &signed.message, config)
        }
        containers::SignedBeaconBlock::Altair(signed) => {
            process_block_altair(state, &signed.message, config)
        }
        containers::SignedBeaconBlock::Bellatrix(signed) => {
            bellatrix::process_block(state, &signed.message, config, engine)
        }
        containers::SignedBeaconBlock::Capella(signed) => {
            capella::process_block(state, &signed.message, config, engine)
        }
        containers::SignedBeaconBlock::Deneb(signed) => {
            deneb::process_block(state, &signed.message, config, engine)
        }
        containers::SignedBeaconBlock::Electra(signed) => {
            electra::process_block(state, &signed.message, config, engine)
        }
        containers::SignedBeaconBlock::Fulu(signed) => {
            fulu::process_block(state, &signed.message, config, engine)
        }
    }
}

/// Phase0's block processing: the header, the RANDAO reveal, the eth1 vote,
/// then every operation, in the specification's order.
pub fn process_block_phase0(
    state: &mut BeaconState,
    block: &phase0::BeaconBlock,
    config: &Config,
) -> Result<()> {
    process_block_header(
        state,
        block.slot,
        block.proposer_index,
        block.parent_root,
        block.body.hash_tree_root(),
    )?;
    process_randao(state, &block.body.randao_reveal)?;
    process_eth1_data(state, &block.body.eth1_data)?;
    crate::stf::operations::process_operations(
        state,
        &block.body.proposer_slashings,
        &block.body.attester_slashings,
        &block.body.attestations,
        &block.body.deposits,
        &block.body.voluntary_exits,
        config,
    )?;
    Ok(())
}

/// Altair's block processing: phase0's steps, plus the sync aggregate.
///
/// The sync aggregate runs last, after every operation, matching the
/// specification's own `process_block`, which appends
/// `process_sync_aggregate(state, block.body.sync_aggregate)` to phase0's list
/// rather than interleaving it earlier.
pub fn process_block_altair(
    state: &mut BeaconState,
    block: &altair::BeaconBlock,
    config: &Config,
) -> Result<()> {
    process_block_header(
        state,
        block.slot,
        block.proposer_index,
        block.parent_root,
        block.body.hash_tree_root(),
    )?;
    process_randao(state, &block.body.randao_reveal)?;
    process_eth1_data(state, &block.body.eth1_data)?;
    crate::stf::operations::process_operations(
        state,
        &block.body.proposer_slashings,
        &block.body.attester_slashings,
        &block.body.attestations,
        &block.body.deposits,
        &block.body.voluntary_exits,
        config,
    )?;
    super::altair::process_sync_aggregate(state, &block.body.sync_aggregate)?;
    Ok(())
}

/// Validates a block's header against the state and records it as the state's
/// `latest_block_header`.
///
/// Checks, in order: the slot matches the state's current slot, the slot is
/// strictly after the previous header's, the proposer index is the one the
/// shuffling computes for this slot, the parent root matches the previous
/// header's own root, and the proposer has not been slashed. The slashed check
/// runs last because the specification itself runs it after the header has
/// already been overwritten, which is one more reason an invalid block cannot
/// be retried against the same state: by the time this returns an error, the
/// header it rejected the block for is already gone.
///
/// Takes `body_root` rather than a body to hash itself, unlike every other
/// piece a driver hands this module's shared steps: a body's shape is
/// fork-specific, so only the caller, which already knows which fork it is
/// calling from, can compute `hash_tree_root()` on it. This function makes no
/// assertion about `body_root` beyond using it verbatim as the header's own
/// field; the caller must pass `block.body.hash_tree_root()`, and a wrong value
/// here would corrupt the header exactly as a wrong value from the
/// specification's own `hash_tree_root(block.body)` would.
pub fn process_block_header(
    state: &mut BeaconState,
    slot: Slot,
    proposer_index: ValidatorIndex,
    parent_root: Root,
    body_root: Root,
) -> Result<()> {
    verify(slot == state.slot(), "block.slot == state.slot")?;
    verify(
        slot > state.latest_block_header().slot,
        "block.slot > state.latest_block_header.slot",
    )?;
    verify(
        proposer_index == get_beacon_proposer_index(state)?,
        "block.proposer_index == get_beacon_proposer_index(state)",
    )?;
    verify(
        parent_root == state.latest_block_header().hash_tree_root(),
        "block.parent_root == hash_tree_root(state.latest_block_header)",
    )?;

    *state.latest_block_header_mut() = BeaconBlockHeader {
        slot,
        proposer_index,
        parent_root,
        // Left zero for the reason given on `super::process_slot`'s doc
        // comment: a block cannot commit to the root of the state it produces.
        state_root: Root::zero(),
        body_root,
    };

    verify(
        !state.validator(proposer_index)?.slashed,
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
pub fn process_randao(state: &mut BeaconState, randao_reveal: &BlsSignature) -> Result<()> {
    let epoch = get_current_epoch(state);
    let proposer_index = get_beacon_proposer_index(state)?;
    let domain = get_domain(state, constants::DOMAIN_RANDAO, None);
    let signing_root = compute_signing_root(epoch.hash_tree_root(), domain);

    let proposer = state.validator(proposer_index)?;
    verify(
        bls::verify(&proposer.pubkey, signing_root, randao_reveal),
        "RANDAO reveal signature",
    )?;

    let mix = xor(get_randao_mix(state, epoch), hash(&randao_reveal.0));
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
pub fn process_eth1_data(state: &mut BeaconState, eth1_data: &Eth1Data) -> Result<()> {
    state.eth1_data_votes_mut().push(eth1_data.clone())?;

    let matching_votes = state
        .eth1_data_votes()
        .iter()
        .filter(|vote| *vote == eth1_data)
        .count() as u64;
    let voting_period_slots = preset::EPOCHS_PER_ETH1_VOTING_PERIOD * preset::SLOTS_PER_EPOCH;
    if matching_votes * 2 > voting_period_slots {
        *state.eth1_data_mut() = eth1_data.clone();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::Bytes32;

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

        assert!(
            process_block_header(
                &mut state,
                block.slot,
                block.proposer_index,
                block.parent_root,
                block.body.hash_tree_root(),
            )
            .is_err()
        );
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

        assert!(
            process_block_header(
                &mut state,
                block.slot,
                block.proposer_index,
                block.parent_root,
                block.body.hash_tree_root(),
            )
            .is_err()
        );
    }
}
