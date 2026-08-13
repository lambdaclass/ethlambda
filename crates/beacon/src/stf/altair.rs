//! Altair's two block-processing changes.
//!
//! Phase0 cannot score an attestation the moment it arrives: whether an
//! attester's vote turns out to matter depends on facts that are not settled
//! until the epoch boundary (whether the target became the epoch's canonical
//! block, whether the chain finalized at all), so phase0 defers scoring by
//! appending a whole `PendingAttestation` to the state and replaying the
//! backlog in [`crate::stf::epoch`]. Altair restructures the state instead of
//! the schedule: [`crate::helpers::altair::get_attestation_participation_flag_indices`]
//! already knows, the moment an attestation is processed, exactly which of the
//! three timeliness conditions it satisfies, so this module's
//! [`process_attestation`] scores it right there, flips the matching
//! participation bits, and pays the including proposer immediately rather than
//! waiting for an epoch boundary to replay anything. That is both cheaper (one
//! bit per validator per epoch instead of a growing list of whole
//! attestations) and bounded (the participation record can never grow past the
//! size of the validator registry, unlike phase0's attestation lists).
//!
//! [`process_sync_aggregate`] is new in altair, with no phase0 analogue: it
//! pays the rotating sync committee (see [`crate::helpers::altair`] for how
//! that committee is drawn) for having signed the previous slot's block root.
//! The reward split between the committee and the proposer, and between reward
//! and penalty, is fixed entirely by [`crate::constants`]'s weight constants
//! rather than anything computed here, so a non-participating member is
//! charged precisely the `participant_reward` a participating one earns: the
//! two are the same number applied with opposite sign, not two independently
//! derived quantities that happen to match.

use std::collections::HashMap;

use crate::bls;
use crate::constants;
use crate::containers::{BeaconState, altair, phase0};
use crate::error::{Error, Result, verify};
use crate::helpers::accessors::{
    get_beacon_committee, get_beacon_proposer_index, get_block_root_at_slot,
    get_committee_count_per_slot, get_current_epoch, get_domain, get_previous_epoch,
    get_total_active_balance,
};
use crate::helpers::altair::{
    add_flag, get_attestation_participation_flag_indices, get_base_reward_per_increment, has_flag,
};
use crate::helpers::attestation::{
    get_attesting_indices, get_indexed_attestation, is_valid_indexed_attestation,
};
use crate::helpers::misc::{compute_epoch_at_slot, compute_signing_root};
use crate::helpers::mutators::{decrease_balance, increase_balance};
use crate::preset;
use crate::primitives::{BlsPubkey, Gwei, ParticipationFlags, ValidatorIndex};

// ---------------------------------------------------------------------------
// Attestations
// ---------------------------------------------------------------------------

/// Scores an attestation against the three timeliness conditions and pays the
/// including proposer for whichever of them it newly satisfies.
///
/// Shares its entire validation prologue with phase0's
/// [`crate::stf::operations::process_attestation`] (target epoch, inclusion
/// window, committee shape, then the signature): none of that changed in
/// altair. What changed is what happens to a *valid* attestation. Phase0
/// appends it, whole, to one of two epoch-scoped lists and leaves every reward
/// decision for the epoch boundary. Altair instead asks
/// [`get_attestation_participation_flag_indices`] which of the three
/// timeliness flags this attestation satisfies, sets exactly the ones each
/// attester does not already have (a repeat vote earns nothing twice), and
/// converts each newly-set flag directly into a share of the proposer's
/// reward, paid before this function returns rather than at the next epoch
/// boundary.
///
/// Reading which flags are already set and computing the reward for newly-set
/// ones (`get_base_reward`) only ever needs `&state`, while flipping the bits
/// needs `&mut state`; those two cannot be interleaved in one pass the way the
/// specification's single loop does, since holding the mutable participation
/// borrow across a call that needs to read the rest of `state` does not
/// borrow-check (see `process_effective_balance_updates` in
/// `crate::stf::epoch` for the same trade-off spelled out in more depth). This
/// runs as two passes instead: a read phase that decides which flags each
/// attester newly earns and totals the proposer's reward for them, then a
/// write phase that only ever applies what the first phase already decided.
///
/// Takes no [`crate::config::Config`]: every quantity this needs is either a
/// [`crate::constants`] weight or a [`preset`] value, and the specification
/// lists none of them under a network's "Configuration" table.
pub fn process_attestation(
    state: &mut BeaconState,
    attestation: &phase0::Attestation,
) -> Result<()> {
    let data = attestation.data;
    let current_epoch = get_current_epoch(state);
    let previous_epoch = get_previous_epoch(state);

    verify(
        data.target.epoch == previous_epoch || data.target.epoch == current_epoch,
        "data.target.epoch in (get_previous_epoch(state), get_current_epoch(state))",
    )?;
    verify(
        data.target.epoch == compute_epoch_at_slot(data.slot),
        "data.target.epoch == compute_epoch_at_slot(data.slot)",
    )?;

    // Both bounds are driven directly by `data.slot`, which comes straight off
    // the wire, so a hostile value close to `u64::MAX` must not be allowed to
    // wrap either bound into something that vacuously accepts the attestation.
    let min_slot = data
        .slot
        .checked_add(preset::MIN_ATTESTATION_INCLUSION_DELAY)
        .ok_or(Error::ArithmeticOverflow(
            "data.slot + MIN_ATTESTATION_INCLUSION_DELAY",
        ))?;
    let max_slot = data
        .slot
        .checked_add(preset::SLOTS_PER_EPOCH)
        .ok_or(Error::ArithmeticOverflow("data.slot + SLOTS_PER_EPOCH"))?;
    verify(
        min_slot <= state.slot() && state.slot() <= max_slot,
        "data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= state.slot <= data.slot + SLOTS_PER_EPOCH",
    )?;
    verify(
        data.index < get_committee_count_per_slot(state, data.target.epoch),
        "data.index < get_committee_count_per_slot(state, data.target.epoch)",
    )?;

    let committee = get_beacon_committee(state, data.slot, data.index)?;
    verify(
        attestation.aggregation_bits.len() == committee.len(),
        "len(attestation.aggregation_bits) == len(committee)",
    )?;

    // Safe: `min_slot <= state.slot()` above and `min_slot >= data.slot` (the
    // inclusion delay is non-negative), so `data.slot <= state.slot()`.
    let inclusion_delay = state.slot() - data.slot;
    let participation_flag_indices =
        get_attestation_participation_flag_indices(state, &data, inclusion_delay)?;

    let indexed_attestation = get_indexed_attestation(state, attestation)?;
    verify(
        is_valid_indexed_attestation(state, &indexed_attestation),
        "is_valid_indexed_attestation(state, get_indexed_attestation(state, attestation))",
    )?;

    // Read phase: for every attester, decide which flags this attestation
    // newly satisfies and add up the proposer's reward for granting them.
    // Everything here only ever reads `state`, so it can run to completion
    // before the write phase below needs a mutable borrow of the same
    // participation list.
    let attesting_indices = get_attesting_indices(state, attestation)?;
    let current_epoch_target = data.target.epoch == current_epoch;
    let (previous_epoch_participation, current_epoch_participation, _) =
        state.altair_validator_lists()?;
    let epoch_participation = if current_epoch_target {
        current_epoch_participation
    } else {
        previous_epoch_participation
    };

    // Hoisted: see the comment on the same line in `electra::process_attestation`.
    let base_reward_per_increment = get_base_reward_per_increment(state)?;

    let mut proposer_reward_numerator: Gwei = 0;
    let mut updates: Vec<(ValidatorIndex, ParticipationFlags)> = Vec::new();
    for index in attesting_indices {
        let current_flags =
            epoch_participation
                .get(index as usize)
                .copied()
                .ok_or(Error::IndexOutOfBounds {
                    index: index as usize,
                    len: epoch_participation.len(),
                })?;

        let mut new_flags: ParticipationFlags = 0;
        for &flag_index in &participation_flag_indices {
            if has_flag(current_flags, flag_index) {
                continue;
            }
            new_flags = add_flag(new_flags, flag_index);
            let weight = constants::PARTICIPATION_FLAG_WEIGHTS[flag_index];
            // `get_base_reward(state, index)` inlined against the hoisted
            // per-increment value, in the helper's own order of operations so
            // the result is bit-identical. See `electra::process_attestation`
            // for why the hoist is not an optimisation but the difference
            // between importing a block at mainnet scale and not.
            let increments =
                state.validator(index)?.effective_balance / preset::EFFECTIVE_BALANCE_INCREMENT;
            let reward = (increments * base_reward_per_increment)
                .checked_mul(weight)
                .ok_or(Error::ArithmeticOverflow(
                    "get_base_reward(state, index) * weight",
                ))?;
            proposer_reward_numerator = proposer_reward_numerator
                .checked_add(reward)
                .ok_or(Error::ArithmeticOverflow("proposer_reward_numerator"))?;
        }
        if new_flags != 0 {
            updates.push((index, new_flags));
        }
    }

    // Write phase: apply exactly the flags the read phase decided on. Nothing
    // from here on reads `state` any further, so this is free to take the
    // mutable borrow the read phase could not.
    let (previous_epoch_participation, current_epoch_participation, _) =
        state.altair_validator_lists_mut()?;
    let epoch_participation = if current_epoch_target {
        current_epoch_participation
    } else {
        previous_epoch_participation
    };
    let epoch_participation_len = epoch_participation.len();
    for (index, new_flags) in updates {
        let flags = epoch_participation
            .get_mut(index as usize)
            .ok_or(Error::IndexOutOfBounds {
                index: index as usize,
                len: epoch_participation_len,
            })?;
        *flags |= new_flags;
    }

    // The weights partition `WEIGHT_DENOMINATOR` between the three flags, the
    // sync committee, and the proposer (see `crate::constants`'s module
    // documentation), so taking the proposer's share out of the denominator
    // and multiplying back up by the full denominator is what turns "the
    // proposer's flat share of a reward" into the multiplier that inflates a
    // validator's own reward for a flag into what the proposer earns for
    // having included the vote that granted it.
    const NON_PROPOSER_WEIGHT: u64 = constants::WEIGHT_DENOMINATOR - constants::PROPOSER_WEIGHT;
    const PROPOSER_REWARD_DENOMINATOR: u64 =
        NON_PROPOSER_WEIGHT * constants::WEIGHT_DENOMINATOR / constants::PROPOSER_WEIGHT;
    let proposer_reward = proposer_reward_numerator / PROPOSER_REWARD_DENOMINATOR;
    let proposer_index = get_beacon_proposer_index(state)?;
    increase_balance(state, proposer_index, proposer_reward)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Sync aggregate
// ---------------------------------------------------------------------------

/// Verifies the sync committee's aggregate signature over the previous slot's
/// block root, then pays each participating committee member (and the
/// proposer, once per participant) and penalizes each one that did not.
///
/// The specification chooses which pubkeys to aggregate by a three-way branch:
/// reuse the committee's precomputed `aggregate_pubkey` when everyone signed,
/// subtract the non-participants from it via elliptic-curve point negation
/// when more than half did, or aggregate the participants directly otherwise.
/// All three branches assert the identical claim, that the signature verifies
/// against the aggregate of exactly the participating members, so the branch
/// is a `blst`-level performance optimization rather than a difference in what
/// is checked. [`crate::bls`] has no point-subtraction primitive (nothing else
/// in this crate needs one) and its own aggregation already batches every
/// point in a single pass, so this collapses the three cases into one direct
/// aggregation of the participating members' pubkeys.
/// [`bls::eth_fast_aggregate_verify`]'s own convention for an empty list
/// (accept only when the signature is the point at infinity) covers the case
/// nobody participated exactly the way the specification's own "less than
/// half" branch does when zero bits are set.
///
/// Every reward and penalty here is the same `participant_reward`, applied
/// with opposite sign: [`crate::constants::SYNC_REWARD_WEIGHT`] and
/// [`crate::constants::PROPOSER_WEIGHT`] fix the whole split ahead of time, so
/// there is no independently-derived penalty formula that could drift out of
/// sync with the reward one.
///
/// Resolving each committee seat's validator index needs a linear scan of
/// `state.validators` (sync committee membership is recorded as pubkeys, not
/// indices), and the specification does that scan inside the very loop that
/// also calls `get_beacon_proposer_index` and adjusts balances. Doing the scan
/// there would need `state` borrowed immutably (to search) and mutably (to
/// pay or penalize) at the same time, which does not borrow-check; this
/// resolves every seat's index, and the proposer's index, into owned values
/// first, then runs the payment loop against those, the same shape
/// `process_effective_balance_updates` (`crate::stf::epoch`) uses for the
/// identical reason.
///
/// Takes no [`crate::config::Config`]: [`constants::DOMAIN_SYNC_COMMITTEE`]
/// and the weight constants are fixed, and [`preset::SYNC_COMMITTEE_SIZE`],
/// [`preset::EFFECTIVE_BALANCE_INCREMENT`], and [`preset::SLOTS_PER_EPOCH`]
/// are preset values; the specification lists none of them under a network's
/// "Configuration" table.
pub fn process_sync_aggregate(
    state: &mut BeaconState,
    sync_aggregate: &altair::SyncAggregate,
) -> Result<()> {
    let committee_bits = &sync_aggregate.sync_committee_bits;

    let (current_sync_committee, _) = state.sync_committees()?;
    let committee_pubkeys = &current_sync_committee.pubkeys;

    let mut participant_pubkeys = Vec::new();
    for (position, pubkey) in committee_pubkeys.iter().enumerate() {
        if committee_bits.get(position).unwrap_or(false) {
            participant_pubkeys.push(*pubkey);
        }
    }

    // `max(state.slot, 1) - 1`, rewritten as a saturating subtraction: the two
    // are equal for every `Slot`, including genesis, and this way there is no
    // intermediate `max` to explain.
    let previous_slot = state.slot().saturating_sub(1);
    let domain = get_domain(
        state,
        constants::DOMAIN_SYNC_COMMITTEE,
        Some(compute_epoch_at_slot(previous_slot)),
    );
    let signing_root = compute_signing_root(get_block_root_at_slot(state, previous_slot)?, domain);
    verify(
        bls::eth_fast_aggregate_verify(
            &participant_pubkeys,
            signing_root,
            &sync_aggregate.sync_committee_signature,
        ),
        "eth_fast_aggregate_verify(participant_pubkeys, signing_root, sync_aggregate.sync_committee_signature)",
    )?;

    // Resolve every committee seat's validator index up front; see this
    // function's documentation for why the mutation loop below cannot do its
    // own scan of `state.validators` the way the specification's single loop
    // does.
    //
    // One pass over the registry, not one per seat. The specification writes
    // this as a search per committee member, which is `SYNC_COMMITTEE_SIZE`
    // scans of the whole validator set: at mainnet's ~1M validators that is
    // hundreds of millions of 48-byte pubkey comparisons per block, and it was
    // measured as the single largest cost in a live import, dwarfing the
    // signature verification above it. Inverting the loop makes it one scan
    // against a committee-sized map.
    //
    // A pubkey may hold more than one seat, since sync-committee selection
    // samples with replacement, so each key maps to every seat it occupies
    // rather than to one.
    let mut seats_by_pubkey: HashMap<&BlsPubkey, Vec<usize>> = HashMap::new();
    for (seat, pubkey) in committee_pubkeys.iter().enumerate() {
        seats_by_pubkey.entry(pubkey).or_default().push(seat);
    }
    let mut resolved: Vec<Option<ValidatorIndex>> = vec![None; committee_pubkeys.len()];
    for (index, validator) in state.validators().iter().enumerate() {
        if let Some(seats) = seats_by_pubkey.get(&validator.pubkey) {
            for &seat in seats {
                resolved[seat] = Some(index as ValidatorIndex);
            }
        }
    }
    let committee_indices: Vec<ValidatorIndex> = resolved
        .into_iter()
        .map(|index| {
            index.ok_or(Error::SpecAssert(
                "state.current_sync_committee.pubkeys[i] in [v.pubkey for v in state.validators]",
            ))
        })
        .collect::<Result<Vec<_>>>()?;

    let total_active_increments =
        get_total_active_balance(state)? / preset::EFFECTIVE_BALANCE_INCREMENT;
    let total_base_rewards = get_base_reward_per_increment(state)?
        .checked_mul(total_active_increments)
        .ok_or(Error::ArithmeticOverflow(
            "get_base_reward_per_increment(state) * total_active_increments",
        ))?;
    let max_participant_rewards = total_base_rewards
        .checked_mul(constants::SYNC_REWARD_WEIGHT)
        .ok_or(Error::ArithmeticOverflow(
            "total_base_rewards * SYNC_REWARD_WEIGHT",
        ))?
        / constants::WEIGHT_DENOMINATOR
        / preset::SLOTS_PER_EPOCH;
    let participant_reward = max_participant_rewards / preset::SYNC_COMMITTEE_SIZE as u64;

    const NON_PROPOSER_WEIGHT: u64 = constants::WEIGHT_DENOMINATOR - constants::PROPOSER_WEIGHT;
    let proposer_reward = participant_reward
        .checked_mul(constants::PROPOSER_WEIGHT)
        .ok_or(Error::ArithmeticOverflow(
            "participant_reward * PROPOSER_WEIGHT",
        ))?
        / NON_PROPOSER_WEIGHT;

    // Stable across every iteration below: nothing in this loop changes the
    // slot or the seed a proposer is drawn from, so resolving it once here
    // (rather than once per seat, as the specification's own pseudocode does)
    // is a straightforward optimization, not a behavior change.
    let proposer_index = get_beacon_proposer_index(state)?;

    for (position, participant_index) in committee_indices.into_iter().enumerate() {
        if committee_bits.get(position).unwrap_or(false) {
            increase_balance(state, participant_index, participant_reward)?;
            increase_balance(state, proposer_index, proposer_reward)?;
        } else {
            decrease_balance(state, participant_index, participant_reward)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use blst::min_pk::SecretKey;

    use super::*;
    use crate::containers::altair::SyncCommittee;
    use crate::containers::shared::{AttestationData, Checkpoint, Validator};
    use crate::primitives::{
        BLS_SIGNATURE_SIZE, BlsPubkey, BlsSignature, Bytes32, HashTreeRoot as _, Root,
    };

    /// An altair state with `count` fully active, full-balance validators, each
    /// with a real (signable) BLS keypair, positioned one epoch in so the
    /// previous epoch and the block-root history window both have entries.
    ///
    /// A near-duplicate of `crate::helpers::altair::tests::altair_state_with_validators`,
    /// which builds the same shape of state but with placeholder (unsigned,
    /// invalid) keys; that builder cannot be reused here since it is private to
    /// its module and returns no secret keys, and this crate has no shared
    /// altair test-state builder yet. The two should probably be merged into
    /// one the next time either needs a change.
    fn altair_state_with_keypairs(count: usize) -> (BeaconState, Vec<SecretKey>) {
        let secret_keys: Vec<SecretKey> = (0..count)
            .map(|index| {
                let mut ikm = [0u8; 32];
                ikm[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
                SecretKey::key_gen(&ikm, &[])
                    .expect("32 bytes of input material is enough for key generation")
            })
            .collect();

        let validators: Vec<Validator> = secret_keys
            .iter()
            .map(|secret_key| Validator {
                pubkey: BlsPubkey(secret_key.sk_to_pk().to_bytes()),
                effective_balance: preset::MAX_EFFECTIVE_BALANCE,
                activation_eligibility_epoch: 0,
                activation_epoch: 0,
                exit_epoch: constants::FAR_FUTURE_EPOCH,
                withdrawable_epoch: constants::FAR_FUTURE_EPOCH,
                ..Default::default()
            })
            .collect();

        let empty_sync_committee = || SyncCommittee {
            pubkeys: vec![BlsPubkey::default(); preset::SYNC_COMMITTEE_SIZE]
                .try_into()
                .expect("built at exactly SYNC_COMMITTEE_SIZE"),
            aggregate_pubkey: BlsPubkey::default(),
        };

        let state = BeaconState::Altair(altair::BeaconState {
            genesis_time: 0,
            genesis_validators_root: Root::zero(),
            slot: preset::SLOTS_PER_EPOCH,
            fork: Default::default(),
            latest_block_header: Default::default(),
            block_roots: vec![Root::zero(); preset::SLOTS_PER_HISTORICAL_ROOT]
                .try_into()
                .expect("the vector is built at its exact length"),
            state_roots: vec![Root::zero(); preset::SLOTS_PER_HISTORICAL_ROOT]
                .try_into()
                .expect("the vector is built at its exact length"),
            historical_roots: Default::default(),
            eth1_data: Default::default(),
            eth1_data_votes: Default::default(),
            eth1_deposit_index: 0,
            validators: validators
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            balances: vec![preset::MAX_EFFECTIVE_BALANCE; count]
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            randao_mixes: vec![Bytes32::zero(); preset::EPOCHS_PER_HISTORICAL_VECTOR]
                .try_into()
                .expect("the vector is built at its exact length"),
            slashings: vec![0; preset::EPOCHS_PER_SLASHINGS_VECTOR]
                .try_into()
                .expect("the vector is built at its exact length"),
            previous_epoch_participation: vec![0; count]
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            current_epoch_participation: vec![0; count]
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            justification_bits: Default::default(),
            previous_justified_checkpoint: Default::default(),
            current_justified_checkpoint: Default::default(),
            finalized_checkpoint: Default::default(),
            inactivity_scores: vec![0; count]
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            current_sync_committee: empty_sync_committee(),
            next_sync_committee: empty_sync_committee(),
        });

        (state, secret_keys)
    }

    /// `specs/altair/bls.md`'s `G2_POINT_AT_INFINITY`: the compressed encoding
    /// of the identity element of G2, and the only signature
    /// `eth_fast_aggregate_verify` accepts for an empty participant list.
    fn g2_point_at_infinity() -> BlsSignature {
        let mut bytes = [0u8; BLS_SIGNATURE_SIZE];
        bytes[0] = 0b1100_0000;
        BlsSignature(bytes)
    }

    #[test]
    fn process_attestation_sets_new_flags_once_and_pays_the_proposer_only_for_them() {
        let (mut state, secret_keys) = altair_state_with_keypairs(64);

        // The last slot of the previous epoch: `state.slot()` sits at
        // `SLOTS_PER_EPOCH` (one epoch in, matching `altair_state_with_keypairs`),
        // so an attestation for this slot has an inclusion delay of exactly
        // `MIN_ATTESTATION_INCLUSION_DELAY`, which is what makes it eligible
        // for all three timeliness flags rather than just source and target.
        let data_slot = preset::SLOTS_PER_EPOCH - 1;
        let target_epoch = compute_epoch_at_slot(data_slot);
        assert_eq!(target_epoch, 0, "the previous epoch, by construction");

        let committee = get_beacon_committee(&state, data_slot, 0).expect("committee exists");
        assert!(
            !committee.is_empty(),
            "64 validators spread finely enough across the shuffle that every \
             slot's first committee has at least one member, under either preset"
        );

        let data = AttestationData {
            slot: data_slot,
            index: 0,
            // Matches the all-zero synthetic block-root history exactly, which
            // is what makes both the target and the head vote "matching".
            beacon_block_root: Root::zero(),
            source: Checkpoint::default(),
            target: Checkpoint {
                epoch: target_epoch,
                root: Root::zero(),
            },
        };

        let mut aggregation_bits =
            crate::containers::phase0::AggregationBits::with_length(committee.len())
                .expect("committee.len() is far below MAX_VALIDATORS_PER_COMMITTEE");
        for position in 0..committee.len() {
            aggregation_bits.set(position, true).unwrap();
        }

        let domain = get_domain(
            &state,
            constants::DOMAIN_BEACON_ATTESTER,
            Some(target_epoch),
        );
        let signing_root = compute_signing_root(data.hash_tree_root(), domain);
        const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
        let signatures: Vec<BlsSignature> = committee
            .iter()
            .map(|&index| {
                BlsSignature(
                    secret_keys[index as usize]
                        .sign(signing_root.as_bytes(), DST, &[])
                        .to_bytes(),
                )
            })
            .collect();
        let signature = bls::aggregate(&signatures).unwrap();

        let attestation = phase0::Attestation {
            aggregation_bits,
            data,
            signature,
        };

        let proposer_index = get_beacon_proposer_index(&state).unwrap();
        let balance_before = state.balance(proposer_index).unwrap();

        process_attestation(&mut state, &attestation).unwrap();

        let (previous_epoch_participation, _, _) = state.altair_validator_lists().unwrap();
        for &index in &committee {
            let flags = previous_epoch_participation[index as usize];
            assert!(
                has_flag(flags, constants::TIMELY_SOURCE_FLAG_INDEX),
                "validator {index} should have earned the timely-source flag"
            );
            assert!(
                has_flag(flags, constants::TIMELY_TARGET_FLAG_INDEX),
                "validator {index} should have earned the timely-target flag"
            );
            assert!(
                has_flag(flags, constants::TIMELY_HEAD_FLAG_INDEX),
                "validator {index} should have earned the timely-head flag, since \
                 the inclusion delay is exactly MIN_ATTESTATION_INCLUSION_DELAY"
            );
        }

        let balance_after = state.balance(proposer_index).unwrap();
        assert!(
            balance_after > balance_before,
            "the proposer must be paid for newly granting three flags to every attester"
        );

        // Idempotency: every flag this attestation could grant is already set,
        // so reprocessing the identical attestation must grant nothing new, and
        // the proposer's balance must not move.
        let balance_before_replay = state.balance(proposer_index).unwrap();
        process_attestation(&mut state, &attestation).unwrap();
        let balance_after_replay = state.balance(proposer_index).unwrap();
        assert_eq!(
            balance_before_replay, balance_after_replay,
            "a repeat vote must earn nothing, since every flag it could set is already set"
        );
    }

    #[test]
    fn process_sync_aggregate_rewards_participants_and_penalizes_a_repeated_non_participant() {
        // Five validators: the first four hold one participating seat each,
        // and the fifth's key fills every one of the remaining committee
        // seats, all marked non-participating. That exercises the same
        // validator index being resolved, and paid or penalized, more than
        // once per call, which is exactly what the borrow-checker fix (resolve
        // every seat's index before the mutation loop) has to get right.
        let (mut state, secret_keys) = altair_state_with_keypairs(5);

        let participant_pubkeys: Vec<BlsPubkey> = secret_keys[0..4]
            .iter()
            .map(|secret_key| BlsPubkey(secret_key.sk_to_pk().to_bytes()))
            .collect();
        let filler_pubkey = BlsPubkey(secret_keys[4].sk_to_pk().to_bytes());

        let mut pubkeys_vec = participant_pubkeys.clone();
        pubkeys_vec.resize(preset::SYNC_COMMITTEE_SIZE, filler_pubkey);
        let aggregate_pubkey = bls::eth_aggregate_pubkeys(&pubkeys_vec).unwrap();
        let pubkeys = pubkeys_vec
            .try_into()
            .expect("built at exactly SYNC_COMMITTEE_SIZE");

        let mut sync_committee_bits = altair::SyncCommitteeBits::default();
        for position in 0..participant_pubkeys.len() {
            sync_committee_bits.set(position, true).unwrap();
        }

        {
            let (current_sync_committee, _) = state.sync_committees_mut().unwrap();
            *current_sync_committee = SyncCommittee {
                pubkeys,
                aggregate_pubkey,
            };
        }

        let previous_slot = state.slot() - 1;
        let domain = get_domain(
            &state,
            constants::DOMAIN_SYNC_COMMITTEE,
            Some(compute_epoch_at_slot(previous_slot)),
        );
        // Matches the all-zero synthetic block-root history.
        let signing_root = compute_signing_root(Root::zero(), domain);

        const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
        let signatures: Vec<BlsSignature> = secret_keys[0..4]
            .iter()
            .map(|secret_key| {
                BlsSignature(
                    secret_key
                        .sign(signing_root.as_bytes(), DST, &[])
                        .to_bytes(),
                )
            })
            .collect();
        let sync_committee_signature = bls::aggregate(&signatures).unwrap();

        let sync_aggregate = altair::SyncAggregate {
            sync_committee_bits,
            sync_committee_signature,
        };

        let proposer_index = get_beacon_proposer_index(&state).unwrap();
        let balances_before: Vec<Gwei> = (0..5u64)
            .map(|index| state.balance(index).unwrap())
            .collect();

        process_sync_aggregate(&mut state, &sync_aggregate).unwrap();

        // Independently derived expected rewards, sharing only the
        // already-tested building blocks (`get_total_active_balance`,
        // `get_base_reward_per_increment`) with `process_sync_aggregate`
        // itself, not the arithmetic under test.
        let total_active_increments =
            get_total_active_balance(&state).unwrap() / preset::EFFECTIVE_BALANCE_INCREMENT;
        let total_base_rewards =
            get_base_reward_per_increment(&state).unwrap() * total_active_increments;
        let max_participant_rewards = total_base_rewards * constants::SYNC_REWARD_WEIGHT
            / constants::WEIGHT_DENOMINATOR
            / preset::SLOTS_PER_EPOCH;
        let participant_reward = max_participant_rewards / preset::SYNC_COMMITTEE_SIZE as u64;
        let proposer_reward = participant_reward * constants::PROPOSER_WEIGHT
            / (constants::WEIGHT_DENOMINATOR - constants::PROPOSER_WEIGHT);

        let filler_seats = (preset::SYNC_COMMITTEE_SIZE - 4) as u64;
        for index in 0..5u64 {
            let mut expected = balances_before[index as usize] as i128;
            if index < 4 {
                expected += participant_reward as i128;
            } else {
                expected -= (participant_reward * filler_seats) as i128;
            }
            if index == proposer_index {
                expected += (proposer_reward * 4) as i128;
            }
            assert_eq!(
                state.balance(index).unwrap() as i128,
                expected,
                "validator {index}'s balance did not match its expected reward or penalty"
            );
        }
    }

    #[test]
    fn process_sync_aggregate_rejects_a_non_infinity_signature_for_zero_participants() {
        let (mut state, secret_keys) = altair_state_with_keypairs(1);
        let filler_pubkey = BlsPubkey(secret_keys[0].sk_to_pk().to_bytes());
        let pubkeys_vec = vec![filler_pubkey; preset::SYNC_COMMITTEE_SIZE];
        let aggregate_pubkey = bls::eth_aggregate_pubkeys(&pubkeys_vec).unwrap();
        let pubkeys = pubkeys_vec
            .try_into()
            .expect("built at exactly SYNC_COMMITTEE_SIZE");

        {
            let (current_sync_committee, _) = state.sync_committees_mut().unwrap();
            *current_sync_committee = SyncCommittee {
                pubkeys,
                aggregate_pubkey,
            };
        }

        // Every bit left at zero: nobody participated, so
        // `eth_fast_aggregate_verify` demands the point-at-infinity signature
        // and nothing else, matching the specification's convention for an
        // aggregate over an empty key set.
        let sync_committee_bits = altair::SyncCommitteeBits::default();

        let wrong = altair::SyncAggregate {
            sync_committee_bits: sync_committee_bits.clone(),
            sync_committee_signature: BlsSignature::default(),
        };
        assert!(
            process_sync_aggregate(&mut state.clone(), &wrong).is_err(),
            "the all-zero signature is not the point at infinity, so this must be rejected"
        );

        let correct = altair::SyncAggregate {
            sync_committee_bits,
            sync_committee_signature: g2_point_at_infinity(),
        };
        let balance_before = state.balance(0).unwrap();
        process_sync_aggregate(&mut state, &correct).unwrap();

        // The sole validator holds every seat and none of them participated,
        // so it is penalized once per seat and the proposer (itself, the only
        // validator in this registry) earns nothing extra.
        let total_active_increments =
            get_total_active_balance(&state).unwrap() / preset::EFFECTIVE_BALANCE_INCREMENT;
        let total_base_rewards =
            get_base_reward_per_increment(&state).unwrap() * total_active_increments;
        let max_participant_rewards = total_base_rewards * constants::SYNC_REWARD_WEIGHT
            / constants::WEIGHT_DENOMINATOR
            / preset::SLOTS_PER_EPOCH;
        let participant_reward = max_participant_rewards / preset::SYNC_COMMITTEE_SIZE as u64;
        let expected_penalty = participant_reward * preset::SYNC_COMMITTEE_SIZE as u64;

        assert_eq!(
            state.balance(0).unwrap(),
            balance_before.saturating_sub(expected_penalty)
        );
    }
}
