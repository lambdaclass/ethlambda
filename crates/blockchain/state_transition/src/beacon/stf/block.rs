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

use crate::beacon::bls::{IndexedPubkey, SignatureSet};
use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::{self, BeaconBlockHeader, BeaconState, Eth1Data, altair, phase0};
use crate::beacon::error::{Result, verify};
use crate::beacon::hash::hash;
use crate::beacon::helpers::accessors::{
    ActiveBalanceCache, CommitteeCache, get_beacon_proposer_index, get_current_epoch, get_domain,
    get_randao_mix,
};
use crate::beacon::helpers::math::xor;
use crate::beacon::helpers::misc::compute_signing_root;
use crate::beacon::preset;
use crate::beacon::primitives::{BlsSignature, HashTreeRoot as _, Root, Slot, ValidatorIndex};
use crate::beacon::stf::signatures::SignatureBatch;

use super::{ExecutionEngine, bellatrix, capella, deneb, electra, fulu, gloas};

/// Dispatches on the block's fork and runs that fork's own block processing,
/// then verifies every signature the processing deferred.
///
/// Matches [`containers::SignedBeaconBlock`]'s variant once, then hands the
/// unwrapped, fork-specific `BeaconBlock` to the function written for it. Called
/// after [`super::process_slots`] has already advanced the state to the block's
/// slot, so every arm validates and mutates a state already positioned at
/// `signed_block`'s slot.
///
/// Means what it always did, that the block is valid: it builds the
/// [`SignatureBatch`] the drivers push into and checks it before returning
/// `Ok`, so a caller that has nothing to add to the batch (block production
/// re-running its own block) needs no knowledge of it. A caller with a
/// signature of its own to check alongside, such as the proposer's, calls
/// [`process_block_with_signatures`] and verifies the batch itself.
///
/// An `Err` leaves `state` partly mutated, as it always could: an operation
/// whose signature is deferred has already written when a bad signature is
/// found at the end. Every caller discards the state after an error.
pub fn process_block(
    state: &mut BeaconState,
    signed_block: &containers::SignedBeaconBlock,
    config: &Config,
    engine: &ExecutionEngine,
    committees: &CommitteeCache,
    active_balances: &ActiveBalanceCache,
    options: BlockProcessingOptions,
) -> Result<()> {
    let mut signatures = SignatureBatch::new();
    process_block_with_signatures(
        state,
        signed_block,
        config,
        engine,
        committees,
        active_balances,
        options,
        &mut signatures,
    )?;
    signatures.verify()
}

/// [`process_block`] without the final signature check: every signature the
/// block's processing needs is pushed into `signatures`, and the caller
/// verifies them.
///
/// For [`super::apply_block`], which adds the proposer's block signature to the
/// same batch so the whole block costs one pairing check. The block is only
/// valid once `signatures.verify()` has returned `Ok`.
#[allow(clippy::too_many_arguments)]
pub fn process_block_with_signatures(
    state: &mut BeaconState,
    signed_block: &containers::SignedBeaconBlock,
    config: &Config,
    engine: &ExecutionEngine,
    committees: &CommitteeCache,
    active_balances: &ActiveBalanceCache,
    options: BlockProcessingOptions,
    signatures: &mut SignatureBatch,
) -> Result<()> {
    match signed_block {
        containers::SignedBeaconBlock::Phase0(signed) => process_block_phase0(
            state,
            &signed.message,
            config,
            committees,
            active_balances,
            options,
            signatures,
        ),
        containers::SignedBeaconBlock::Altair(signed) => process_block_altair(
            state,
            &signed.message,
            config,
            committees,
            active_balances,
            options,
            signatures,
        ),
        containers::SignedBeaconBlock::Bellatrix(signed) => bellatrix::process_block(
            state,
            &signed.message,
            config,
            engine,
            committees,
            active_balances,
            options,
            signatures,
        ),
        containers::SignedBeaconBlock::Capella(signed) => capella::process_block(
            state,
            &signed.message,
            config,
            engine,
            committees,
            active_balances,
            options,
            signatures,
        ),
        containers::SignedBeaconBlock::Deneb(signed) => deneb::process_block(
            state,
            &signed.message,
            config,
            engine,
            committees,
            active_balances,
            options,
            signatures,
        ),
        containers::SignedBeaconBlock::Electra(signed) => electra::process_block(
            state,
            &signed.message,
            config,
            engine,
            committees,
            active_balances,
            options,
            signatures,
        ),
        containers::SignedBeaconBlock::Fulu(signed) => fulu::process_block(
            state,
            &signed.message,
            config,
            engine,
            committees,
            active_balances,
            options,
            signatures,
        ),
        // ePBS (EIP-7732) restructures block processing around a builder's
        // bid rather than an embedded payload: a gloas block carries no
        // payload for `engine` to answer for, so this arm never reaches it.
        containers::SignedBeaconBlock::Gloas(signed) => gloas::process_block(
            state,
            &signed.message,
            config,
            committees,
            active_balances,
            options,
            signatures,
        ),
        containers::SignedBeaconBlock::Lean(_) => {
            crate::beacon::lean_block_unreachable("process_block")
        }
    }
}

/// Phase0's block processing: the header, the RANDAO reveal, the eth1 vote,
/// then every operation, in the specification's order.
pub fn process_block_phase0(
    state: &mut BeaconState,
    block: &phase0::BeaconBlock,
    config: &Config,
    committees: &CommitteeCache,
    active_balances: &ActiveBalanceCache,
    options: BlockProcessingOptions,
    signatures: &mut SignatureBatch,
) -> Result<()> {
    process_block_header(
        state,
        block.slot,
        block.proposer_index,
        block.parent_root,
        block.body.hash_tree_root(),
    )?;
    process_randao(state, &block.body.randao_reveal, options.randao, signatures)?;
    process_eth1_data(state, &block.body.eth1_data)?;
    crate::beacon::stf::operations::process_operations(
        state,
        &block.body.proposer_slashings,
        &block.body.attester_slashings,
        &block.body.attestations,
        &block.body.deposits,
        &block.body.voluntary_exits,
        config,
        committees,
        active_balances,
        signatures,
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
    committees: &CommitteeCache,
    active_balances: &ActiveBalanceCache,
    options: BlockProcessingOptions,
    signatures: &mut SignatureBatch,
) -> Result<()> {
    process_block_header(
        state,
        block.slot,
        block.proposer_index,
        block.parent_root,
        block.body.hash_tree_root(),
    )?;
    process_randao(state, &block.body.randao_reveal, options.randao, signatures)?;
    process_eth1_data(state, &block.body.eth1_data)?;
    crate::beacon::stf::operations::process_operations(
        state,
        &block.body.proposer_slashings,
        &block.body.attester_slashings,
        &block.body.attestations,
        &block.body.deposits,
        &block.body.voluntary_exits,
        config,
        committees,
        active_balances,
        signatures,
    )?;
    super::altair::process_sync_aggregate(
        state,
        &block.body.sync_aggregate,
        active_balances,
        signatures,
    )?;
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
        state_root: Root::ZERO,
        body_root,
    };

    verify(
        !state.validator(proposer_index)?.slashed,
        "proposer is not slashed",
    )?;
    Ok(())
}

/// What `process_block` may leave unchecked. The default checks everything the
/// specification does, and is the only value block import uses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlockProcessingOptions {
    pub randao: RandaoVerification,
}

/// Whether `process_randao` verifies the proposer's reveal before mixing it in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RandaoVerification {
    #[default]
    Verify,
    /// Block production for a caller that set `skip_randao_verification`: the
    /// reveal is the point at infinity, which verifies against no key, so the
    /// state root can only be computed by mixing it in unchecked.
    Skip,
}

/// Defers the check of the proposer's RANDAO reveal (unless `verification`
/// skips it) to `signatures`, and mixes the reveal into the current epoch's
/// randao mix.
///
/// The reveal signs the epoch rather than the slot, so the same signature would
/// verify for every slot of the epoch: the mix it feeds is per-epoch, not
/// per-slot, and a skipped slot leaves nothing for the next proposer to reveal
/// differently.
pub fn process_randao(
    state: &mut BeaconState,
    randao_reveal: &BlsSignature,
    verification: RandaoVerification,
    signatures: &mut SignatureBatch,
) -> Result<()> {
    let epoch = get_current_epoch(state);
    let proposer_index = get_beacon_proposer_index(state)?;
    let domain = get_domain(state, constants::DOMAIN_RANDAO, None);
    let signing_root = compute_signing_root(epoch.hash_tree_root(), domain);

    let proposer = state.validator(proposer_index)?;
    if verification == RandaoVerification::Verify {
        signatures.push(
            SignatureSet::single(
                &IndexedPubkey {
                    index: proposer_index,
                    pubkey: proposer.pubkey,
                },
                signing_root,
                randao_reveal,
            ),
            "RANDAO reveal signature",
        )?;
    }

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
    use crate::beacon::bls;
    use crate::beacon::primitives::Bytes32;
    use crate::beacon::stf::signatures::checked;

    /// An otherwise-empty block body, since the header, RANDAO, and eth1 checks
    /// below never look past its `hash_tree_root`.
    fn empty_body() -> phase0::BeaconBlockBody {
        phase0::BeaconBlockBody {
            randao_reveal: BlsSignature::default(),
            eth1_data: Eth1Data::default(),
            graffiti: Bytes32::ZERO,
            proposer_slashings: Default::default(),
            attester_slashings: Default::default(),
            attestations: Default::default(),
            deposits: Default::default(),
            voluntary_exits: Default::default(),
        }
    }

    #[test]
    fn a_mismatched_parent_root_is_rejected() {
        let mut state = crate::beacon::helpers::test_state::with_validators(8);
        let proposer_index = get_beacon_proposer_index(&state).unwrap();

        let block = phase0::BeaconBlock {
            slot: state.slot(),
            proposer_index,
            // Deliberately wrong: the real parent root is
            // `state.latest_block_header().hash_tree_root()`.
            parent_root: Root::repeat_byte(0xab),
            state_root: Root::ZERO,
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
        let mut state = crate::beacon::helpers::test_state::with_validators(8);
        let proposer_index = get_beacon_proposer_index(&state).unwrap();
        state.validator_mut(proposer_index).unwrap().slashed = true;

        let block = phase0::BeaconBlock {
            slot: state.slot(),
            proposer_index,
            parent_root: state.latest_block_header().hash_tree_root(),
            state_root: Root::ZERO,
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
    fn skipping_randao_verification_mixes_in_the_infinity_reveal() {
        let mut state = crate::beacon::helpers::test_state::with_validators(8);
        let epoch = get_current_epoch(&state);
        let reveal = BlsSignature(bls::G2_POINT_AT_INFINITY);
        let expected = xor(get_randao_mix(&state, epoch), hash(&reveal.0));

        checked(|s| process_randao(&mut state, &reveal, RandaoVerification::Skip, s)).unwrap();

        assert_eq!(get_randao_mix(&state, epoch), expected);
    }

    /// A reveal signed by the right proposer over the wrong message.
    fn reveal_over(state: &BeaconState, signed: Root) -> BlsSignature {
        let proposer = get_beacon_proposer_index(state).unwrap();
        crate::beacon::helpers::test_state::sign_for(proposer as usize, signed)
    }

    #[test]
    fn a_bad_randao_reveal_is_deferred_and_rejected_by_the_batch() {
        let mut state = crate::beacon::helpers::test_state::with_validators(8);
        let reveal = reveal_over(&state, Root::repeat_byte(7));
        let mut signatures = SignatureBatch::new();

        // Nothing is checked while processing; the batch is what rejects.
        process_randao(
            &mut state,
            &reveal,
            RandaoVerification::Verify,
            &mut signatures,
        )
        .unwrap();
        let err = signatures.verify().unwrap_err();
        assert!(
            format!("{err:?}").contains("RANDAO reveal signature"),
            "{err:?}"
        );
    }

    #[test]
    fn a_valid_randao_reveal_passes_the_batch() {
        let mut state = crate::beacon::helpers::test_state::with_validators(8);
        let epoch = get_current_epoch(&state);
        let domain = get_domain(&state, constants::DOMAIN_RANDAO, None);
        let signing_root = compute_signing_root(epoch.hash_tree_root(), domain);
        let reveal = reveal_over(&state, signing_root);

        checked(|s| process_randao(&mut state, &reveal, RandaoVerification::Verify, s)).unwrap();
    }

    #[test]
    fn skipping_randao_verification_pushes_nothing() {
        let mut state = crate::beacon::helpers::test_state::with_validators(8);
        let reveal = BlsSignature(bls::G2_POINT_AT_INFINITY);
        let mut signatures = SignatureBatch::immediate();

        process_randao(
            &mut state,
            &reveal,
            RandaoVerification::Skip,
            &mut signatures,
        )
        .unwrap();
        signatures.verify().unwrap();
    }

    #[test]
    fn verifying_randao_rejects_the_infinity_reveal() {
        let mut state = crate::beacon::helpers::test_state::with_validators(8);
        let reveal = BlsSignature(bls::G2_POINT_AT_INFINITY);

        assert!(
            checked(|s| process_randao(&mut state, &reveal, RandaoVerification::Verify, s))
                .is_err()
        );
    }
}
