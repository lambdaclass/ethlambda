//! Tests for the EIP-8453 helpers, one or more per specification function.
//! There are no published EIP-8453 fixtures, so each test checks a rule of
//! the function it names against values worked out from the specification.

use std::collections::BTreeSet;

use super::*;
use crate::beacon::containers::shared::Checkpoint;
use crate::beacon::fork::ForkName;
use crate::beacon::helpers::shuffling::compute_shuffled_index;
use crate::beacon::helpers::test_state;

/// An EIP-8453 state with `count` active validators, one epoch in, straight
/// out of `upgrade_to_eip8453`.
fn state(count: usize) -> BeaconState {
    test_state::with_validators_at(ForkName::Eip8453, count)
}

fn signing_state(count: usize) -> BeaconState {
    test_state::with_signing_validators_at(ForkName::Eip8453, count)
}

fn inner(state: &BeaconState) -> &eip8453::BeaconState {
    eip8453_state(state, "test").unwrap()
}

fn inner_mut(state: &mut BeaconState) -> &mut eip8453::BeaconState {
    eip8453_state_mut(state, "test").unwrap()
}

fn checkpoint(height: u64, byte: u8) -> eip8453::HeightCheckpoint {
    eip8453::HeightCheckpoint {
        height,
        root: Root::repeat_byte(byte),
    }
}

fn data(
    target: eip8453::HeightCheckpoint,
    timeout: bool,
    finality: eip8453::HeightCheckpoint,
) -> eip8453::AttestationData {
    eip8453::AttestationData {
        target,
        timeout,
        finality,
    }
}

fn pending(checkpoint: eip8453::HeightCheckpoint, count: usize) -> eip8453::PendingFinality {
    eip8453::PendingFinality {
        checkpoint,
        slot: 0,
        participation: vec![false; count].into(),
    }
}

// ---------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------

#[test]
fn is_well_formed_attestation_data_checks_both_pairs() {
    let empty = eip8453::HeightCheckpoint::empty();
    // The height pair needs a height and a root.
    assert!(!is_well_formed_attestation_data(&data(
        checkpoint(0, 1),
        false,
        empty
    )));
    assert!(!is_well_formed_attestation_data(&data(
        eip8453::HeightCheckpoint {
            height: 2,
            root: Root::ZERO
        },
        false,
        empty
    )));
    // An absent finality pair is fine.
    assert!(is_well_formed_attestation_data(&data(
        checkpoint(2, 1),
        true,
        empty
    )));
    // A present one needs a root and a lower height.
    assert!(is_well_formed_attestation_data(&data(
        checkpoint(2, 1),
        false,
        checkpoint(1, 2)
    )));
    assert!(!is_well_formed_attestation_data(&data(
        checkpoint(2, 1),
        false,
        checkpoint(2, 2)
    )));
    assert!(!is_well_formed_attestation_data(&data(
        checkpoint(2, 1),
        false,
        eip8453::HeightCheckpoint {
            height: 1,
            root: Root::ZERO
        }
    )));
}

#[test]
fn is_valid_attestation_data_takes_the_target_or_a_pending_finality_pair_below_it() {
    let mut state = state(4);
    let inner = inner_mut(&mut state);
    inner.target_checkpoint = checkpoint(5, 9);
    inner.pending_finality = vec![pending(checkpoint(3, 7), 4)].try_into().unwrap();
    let inner = &*inner;

    // The current target, whatever the finality pair.
    assert!(is_valid_attestation_data(
        inner,
        &data(checkpoint(5, 9), false, eip8453::HeightCheckpoint::empty())
    ));
    // A vote below the current height whose finality pair is pending.
    assert!(is_valid_attestation_data(
        inner,
        &data(checkpoint(4, 1), false, checkpoint(3, 7))
    ));
    // ... but not at or above the current height.
    assert!(!is_valid_attestation_data(
        inner,
        &data(checkpoint(5, 1), false, checkpoint(3, 7))
    ));
    // ... nor with a finality pair that is not pending, or at the target's
    // own height.
    assert!(!is_valid_attestation_data(
        inner,
        &data(checkpoint(4, 1), false, checkpoint(3, 8))
    ));
    assert!(!is_valid_attestation_data(
        inner,
        &data(checkpoint(3, 1), false, checkpoint(3, 7))
    ));
}

/// Signs `data` for `indices` under the finality gadget's domain at `epoch`.
fn signed_indexed(
    state: &BeaconState,
    indices: &[ValidatorIndex],
    data: eip8453::AttestationData,
    epoch: Epoch,
    domain_type: crate::beacon::primitives::DomainType,
) -> eip8453::IndexedAttestation {
    let domain = get_domain(state, domain_type, Some(epoch));
    let signing_root = compute_signing_root(data.hash_tree_root(), domain);
    let signatures: Vec<_> = indices
        .iter()
        .map(|index| test_state::sign_for(*index as usize, signing_root))
        .collect();
    eip8453::IndexedAttestation {
        attesting_indices: indices.to_vec().into(),
        data,
        signature: bls::aggregate(&signatures).unwrap(),
        epoch,
    }
}

#[test]
fn is_valid_indexed_attestation_checks_indices_and_the_finality_attester_signature() {
    let state = signing_state(8);
    let vote = data(checkpoint(1, 1), false, eip8453::HeightCheckpoint::empty());
    let epoch = get_current_epoch(&state);

    let valid = signed_indexed(
        &state,
        &[1, 3, 4],
        vote,
        epoch,
        constants::DOMAIN_FINALITY_ATTESTER,
    );
    assert!(is_valid_indexed_attestation(&state, &valid));

    // Casper FFG's domain does not verify.
    let wrong_domain = signed_indexed(
        &state,
        &[1, 3, 4],
        vote,
        epoch,
        constants::DOMAIN_BEACON_ATTESTER,
    );
    assert!(!is_valid_indexed_attestation(&state, &wrong_domain));

    // The epoch is part of the domain: signed for one epoch, claimed for
    // another under a different fork version, it fails.
    let mut other_epoch = valid.clone();
    other_epoch.epoch = 0;
    assert!(!is_valid_indexed_attestation(&state, &other_epoch));

    let mut empty = valid.clone();
    empty.attesting_indices = Vec::new().into();
    assert!(!is_valid_indexed_attestation(&state, &empty));

    let mut unsorted = valid.clone();
    unsorted.attesting_indices = vec![3, 1, 4].into();
    assert!(!is_valid_indexed_attestation(&state, &unsorted));

    let mut duplicate = valid.clone();
    duplicate.attesting_indices = vec![1, 1, 4].into();
    assert!(!is_valid_indexed_attestation(&state, &duplicate));

    let mut too_many = valid;
    too_many.attesting_indices = (0..=preset::MAX_VALIDATORS_PER_AGGREGATE)
        .collect::<Vec<_>>()
        .into();
    assert!(!is_valid_indexed_attestation(&state, &too_many));
}

#[test]
fn is_double_target_vote_needs_two_target_votes_for_different_roots_at_one_height() {
    let empty = eip8453::HeightCheckpoint::empty();
    let a = data(checkpoint(3, 1), false, empty);
    let b = data(checkpoint(3, 2), false, empty);
    assert!(is_double_target_vote(&a, &b));
    // Same root, different height, or a timeout on either side: not double.
    assert!(!is_double_target_vote(&a, &a));
    assert!(!is_double_target_vote(
        &a,
        &data(checkpoint(4, 2), false, empty)
    ));
    assert!(!is_double_target_vote(
        &a,
        &data(checkpoint(3, 2), true, empty)
    ));
    assert!(!is_double_target_vote(
        &data(checkpoint(3, 1), true, empty),
        &b
    ));
}

#[test]
fn is_conflicting_with_finality_pair_catches_a_timeout_or_another_root_at_its_height() {
    let empty = eip8453::HeightCheckpoint::empty();
    let finality = checkpoint(3, 7);
    // An absent pair conflicts with nothing.
    assert!(!is_conflicting_with_finality_pair(
        &data(checkpoint(3, 1), true, empty),
        &empty
    ));
    // Another height: no conflict.
    assert!(!is_conflicting_with_finality_pair(
        &data(checkpoint(4, 1), true, empty),
        &finality
    ));
    // A timeout, or a target vote for another root, at that height conflicts.
    assert!(is_conflicting_with_finality_pair(
        &data(checkpoint(3, 7), true, empty),
        &finality
    ));
    assert!(is_conflicting_with_finality_pair(
        &data(checkpoint(3, 1), false, empty),
        &finality
    ));
    // A target vote for its root does not.
    assert!(!is_conflicting_with_finality_pair(
        &data(checkpoint(3, 7), false, empty),
        &finality
    ));
}

#[test]
fn is_slashable_attestation_data_is_a_double_vote_or_a_finality_conflict_either_way() {
    let empty = eip8453::HeightCheckpoint::empty();
    let double_1 = data(checkpoint(3, 1), false, empty);
    let double_2 = data(checkpoint(3, 2), false, empty);
    assert!(is_slashable_attestation_data(&double_1, &double_2));

    // data_2's finality pair (height 3, root 7) against data_1's timeout at 3.
    let timeout = data(checkpoint(3, 7), true, empty);
    let with_finality = data(checkpoint(5, 1), false, checkpoint(3, 7));
    assert!(is_slashable_attestation_data(&timeout, &with_finality));
    // And the other way round.
    assert!(is_slashable_attestation_data(&with_finality, &timeout));

    // Consistent votes are not slashable.
    let consistent = data(checkpoint(3, 7), false, empty);
    assert!(!is_slashable_attestation_data(&consistent, &with_finality));
    assert!(!is_slashable_attestation_data(&consistent, &consistent));
}

#[test]
fn is_slashable_legacy_attestation_data_keeps_casper_ffgs_rules() {
    use crate::beacon::containers::shared::AttestationData;
    let at = |source: u64, target: u64, root: u8| AttestationData {
        source: Checkpoint {
            epoch: source,
            root: Root::ZERO,
        },
        target: Checkpoint {
            epoch: target,
            root: Root::repeat_byte(root),
        },
        ..Default::default()
    };
    // Double vote.
    assert!(is_slashable_legacy_attestation_data(
        &at(1, 3, 1),
        &at(1, 3, 2)
    ));
    // Surround vote.
    assert!(is_slashable_legacy_attestation_data(
        &at(1, 5, 1),
        &at(2, 4, 1)
    ));
    // Neither.
    assert!(!is_slashable_legacy_attestation_data(
        &at(1, 3, 1),
        &at(1, 3, 1)
    ));
    assert!(!is_slashable_legacy_attestation_data(
        &at(1, 3, 1),
        &at(3, 4, 1)
    ));
}

#[test]
fn is_valid_legacy_indexed_attestation_checks_under_the_beacon_attester_domain() {
    use crate::beacon::containers::shared::AttestationData;
    let state = signing_state(4);
    let legacy = AttestationData {
        slot: 3,
        target: Checkpoint {
            epoch: 0,
            root: Root::repeat_byte(5),
        },
        ..Default::default()
    };
    let domain = get_domain(&state, constants::DOMAIN_BEACON_ATTESTER, Some(0));
    let signing_root = compute_signing_root(legacy.hash_tree_root(), domain);
    let signatures: Vec<_> = [0usize, 2]
        .iter()
        .map(|index| test_state::sign_for(*index, signing_root))
        .collect();
    let indexed = gloas::IndexedAttestation {
        attesting_indices: vec![0, 2].into(),
        data: legacy,
        signature: bls::aggregate(&signatures).unwrap(),
    };
    assert!(is_valid_legacy_indexed_attestation(&state, &indexed));
    let mut unsorted = indexed;
    unsorted.attesting_indices = vec![2, 0].into();
    assert!(!is_valid_legacy_indexed_attestation(&state, &unsorted));
}

#[test]
fn is_eligible_for_activation_reads_the_finalized_slots_epoch() {
    let mut state = state(1);
    let validator = Validator {
        activation_eligibility_epoch: 2,
        activation_epoch: constants::FAR_FUTURE_EPOCH,
        ..Default::default()
    };
    inner_mut(&mut state).finalized_slot = 2 * preset::SLOTS_PER_EPOCH - 1;
    assert!(!is_eligible_for_activation(inner(&state), &validator));
    inner_mut(&mut state).finalized_slot = 2 * preset::SLOTS_PER_EPOCH;
    assert!(is_eligible_for_activation(inner(&state), &validator));
    let active = Validator {
        activation_epoch: 0,
        ..validator
    };
    assert!(!is_eligible_for_activation(inner(&state), &active));
}

#[test]
fn is_active_builder_reads_the_finalized_slots_epoch() {
    let mut state = state(1);
    inner_mut(&mut state).builders.push(gloas::Builder {
        deposit_epoch: 1,
        withdrawable_epoch: constants::FAR_FUTURE_EPOCH,
        ..Default::default()
    });
    inner_mut(&mut state).finalized_slot = 2 * preset::SLOTS_PER_EPOCH - 1;
    assert!(!is_active_builder(inner(&state), 0).unwrap());
    // Through gloas's own entry point, which dispatches on the fork.
    assert!(!super::super::gloas::is_active_builder(&state, 0).unwrap());
    inner_mut(&mut state).finalized_slot = 2 * preset::SLOTS_PER_EPOCH;
    assert!(is_active_builder(inner(&state), 0).unwrap());
    assert!(super::super::gloas::is_active_builder(&state, 0).unwrap());
    assert!(is_active_builder(inner(&state), 1).is_err());
}

#[test]
fn is_head_vote_same_slot_needs_the_slots_own_block() {
    let mut state = state(1);
    let slot = state.slot();
    *state.slot_mut() = slot + 2;
    state.block_roots_mut()[(slot as usize) % preset::SLOTS_PER_HISTORICAL_ROOT] =
        Root::repeat_byte(1);
    state.block_roots_mut()[(slot as usize + 1) % preset::SLOTS_PER_HISTORICAL_ROOT] =
        Root::repeat_byte(1);
    let vote = |slot: Slot, byte: u8| eip8453::HeadVoteData {
        slot,
        beacon_block_root: Root::repeat_byte(byte),
        payload_status: constants::PAYLOAD_STATUS_PENDING,
    };
    // The genesis slot always counts.
    assert!(is_head_vote_same_slot(&state, &vote(0, 9)).unwrap());
    // The block of `slot` (whose predecessor's root differs).
    assert!(is_head_vote_same_slot(&state, &vote(slot, 1)).unwrap());
    // Another root.
    assert!(!is_head_vote_same_slot(&state, &vote(slot, 2)).unwrap());
    // `slot + 1` was skipped: its root is `slot`'s.
    assert!(!is_head_vote_same_slot(&state, &vote(slot + 1, 1)).unwrap());
    // `get_block_root_at_slot` asserts the slot is in the past.
    assert!(is_head_vote_same_slot(&state, &vote(slot + 2, 1)).is_err());
}

#[test]
fn has_builder_payment_quorum_needs_sixty_percent_of_the_seats() {
    let size = preset::HEAD_VOTE_COMMITTEE_SIZE as u64;
    // Smallest seat count with `seats * 10 >= size * 6`.
    let needed = (size * 6).div_ceil(10) as usize;
    let mut bits = eip8453::HeadVoteCommitteeBits::new();
    for seat in 0..needed - 1 {
        bits.set(seat, true).unwrap();
    }
    assert!(!has_builder_payment_quorum(&bits));
    bits.set(needed - 1, true).unwrap();
    assert!(has_builder_payment_quorum(&bits));
}

#[test]
fn has_quorum_needs_two_thirds_of_the_active_weight() {
    let mut state = state(6);
    // Four of six equal weights is exactly two thirds.
    let four = [true, true, true, true, false, false];
    assert!(has_quorum(&state, &four).unwrap());
    let three = [true, true, true, false, false, false];
    assert!(!has_quorum(&state, &three).unwrap());
    // Nothing participating is never a quorum.
    assert!(!has_quorum(&state, &[false; 6]).unwrap());
    // A slashed participant counts toward the total but not the quorum.
    state.validator_mut(0).unwrap().slashed = true;
    assert!(!has_quorum(&state, &four).unwrap());
    // An inactive validator counts toward neither.
    state.validator_mut(5).unwrap().activation_epoch = constants::FAR_FUTURE_EPOCH;
    state.validator_mut(4).unwrap().activation_epoch = constants::FAR_FUTURE_EPOCH;
    // Active: 0..4, weight 4 parts; participating unslashed 1, 2, 3: 3 >= 8/3.
    assert!(has_quorum(&state, &four).unwrap());
    // A participation list shorter than the registry fails, as indexing does.
    assert!(has_quorum(&state, &[true]).is_err());
}

#[test]
fn get_validator_weight_falls_with_the_square_of_the_score() {
    let mut state = state(3);
    let increments = preset::MAX_EFFECTIVE_BALANCE / preset::EFFECTIVE_BALANCE_INCREMENT;
    let ejection = preset::EJECTION_INACTIVITY_SCORE as u128;
    assert_eq!(
        get_validator_weight(&state, 0).unwrap(),
        increments as u128 * ejection * ejection
    );
    *state.inactivity_score_mut(1).unwrap() = 4_096;
    assert_eq!(
        get_validator_weight(&state, 1).unwrap(),
        increments as u128 * (ejection - 4_096) * (ejection + 4_096)
    );
    // The table's 99.61% row: score 4096 of 65536.
    let ratio = get_validator_weight(&state, 1).unwrap() * 10_000
        / get_validator_weight(&state, 0).unwrap();
    assert_eq!(ratio, 9_960);
    // At or past the ejection score the weight is zero.
    *state.inactivity_score_mut(2).unwrap() = preset::EJECTION_INACTIVITY_SCORE + 5;
    assert_eq!(get_validator_weight(&state, 2).unwrap(), 0);
    assert!(get_validator_weight(&state, 3).is_err());
}

#[test]
fn get_total_and_participating_weight_sum_their_validators() {
    let mut state = state(4);
    *state.inactivity_score_mut(2).unwrap() = 100;
    let all: BTreeSet<ValidatorIndex> = (0..4).collect();
    let expected: Weight = (0..4)
        .map(|i| get_validator_weight(&state, i).unwrap())
        .sum();
    assert_eq!(get_total_weight(&state, &all).unwrap(), expected);

    state.validator_mut(3).unwrap().slashed = true;
    let participation = [false, true, true, true];
    assert_eq!(
        get_participating_weight(&state, &participation).unwrap(),
        get_validator_weight(&state, 1).unwrap() + get_validator_weight(&state, 2).unwrap()
    );
}

#[test]
fn get_finality_delay_counts_rounds_and_stops_at_zero() {
    let mut state = state(1);
    // Slot 4 rounds into the epoch past round 0's slots.
    *state.slot_mut() = 5 * preset::SLOTS_PER_ROUND;
    inner_mut(&mut state).finalized_slot = 0;
    // Previous round 4, finalized round 0.
    assert_eq!(get_finality_delay(&state).unwrap(), 4);
    inner_mut(&mut state).finalized_slot = 5 * preset::SLOTS_PER_ROUND;
    // The finalized round is the current one, past the previous round.
    assert_eq!(get_finality_delay(&state).unwrap(), 0);
}

#[test]
fn is_in_inactivity_leak_is_a_delay_past_the_threshold() {
    let mut state = state(1);
    inner_mut(&mut state).finalized_slot = 0;
    let rounds = preset::MIN_ROUNDS_TO_INACTIVITY_LEAK;
    // Previous round = MIN_ROUNDS_TO_INACTIVITY_LEAK: delay equal, no leak.
    *state.slot_mut() = (rounds + 1) * preset::SLOTS_PER_ROUND;
    assert!(!is_in_inactivity_leak(&state).unwrap());
    *state.slot_mut() = (rounds + 2) * preset::SLOTS_PER_ROUND;
    assert!(is_in_inactivity_leak(&state).unwrap());
}

/// An aggregate over the given committees of `epoch`, every member's bit set.
fn aggregate_over(
    state: &BeaconState,
    epoch: Epoch,
    committees: &[u64],
) -> (eip8453::Attestation, Vec<ValidatorIndex>) {
    let mut committee_bits = eip8453::AttestationCommitteeBits::new();
    let mut members = Vec::new();
    for &index in committees {
        committee_bits.set(index as usize, true).unwrap();
        members.extend(
            get_attestation_committee(state, epoch, index)
                .unwrap()
                .iter(),
        );
    }
    let mut aggregation_bits = eip8453::AggregationBits::with_length(members.len());
    for position in 0..members.len() {
        aggregation_bits.set(position, true).unwrap();
    }
    let attestation = eip8453::Attestation {
        aggregation_bits,
        data: data(checkpoint(1, 1), false, eip8453::HeightCheckpoint::empty()),
        signature: Default::default(),
        committee_bits,
        epoch,
    };
    (attestation, members)
}

/// Committee indices of `epoch` that have members, ascending.
fn non_empty_committees(state: &BeaconState, epoch: Epoch) -> Vec<u64> {
    (0..preset::ATTESTATION_COMMITTEES_PER_ROUND as u64)
        .filter(|&index| {
            !get_attestation_committee(state, epoch, index)
                .unwrap()
                .is_empty()
        })
        .collect()
}

#[test]
fn is_valid_aggregation_bits_needs_one_bit_per_committee_member() {
    let state = state(40);
    let epoch = get_current_epoch(&state);
    let committees = non_empty_committees(&state, epoch);
    let (mut aggregate, members) = aggregate_over(&state, epoch, &committees[..2]);
    assert!(is_valid_aggregation_bits(&state, epoch, &aggregate).unwrap());
    aggregate.aggregation_bits = eip8453::AggregationBits::with_length(members.len() + 1);
    assert!(!is_valid_aggregation_bits(&state, epoch, &aggregate).unwrap());
    aggregate.aggregation_bits = eip8453::AggregationBits::with_length(members.len() - 1);
    assert!(!is_valid_aggregation_bits(&state, epoch, &aggregate).unwrap());
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

#[test]
fn rounds_are_slots_per_round_long() {
    let per_round = preset::SLOTS_PER_ROUND;
    assert_eq!(compute_round_at_slot(0), 0);
    assert_eq!(compute_round_at_slot(per_round - 1), 0);
    assert_eq!(compute_round_at_slot(per_round), 1);
    assert_eq!(compute_start_slot_at_round(3).unwrap(), 3 * per_round);
    assert!(compute_start_slot_at_round(u64::MAX).is_err());
    // A round divides an epoch on both presets, so the round boundary falls
    // on every epoch boundary.
    assert_eq!(preset::SLOTS_PER_EPOCH % per_round, 0);
    assert_eq!(
        preset::ATTESTATION_COMMITTEES_PER_ROUND as u64 % per_round,
        0
    );
    assert_eq!(preset::TIMEOUT_DELAY_SLOTS, per_round);
}

#[test]
fn compute_attestation_committee_slot_spreads_committees_over_the_round() {
    let per_slot = preset::ATTESTATION_COMMITTEES_PER_ROUND as u64 / preset::SLOTS_PER_ROUND;
    let start = compute_start_slot_at_round(2).unwrap();
    assert_eq!(compute_attestation_committee_slot(2, 0).unwrap(), start);
    assert_eq!(
        compute_attestation_committee_slot(2, per_slot - 1).unwrap(),
        start
    );
    assert_eq!(
        compute_attestation_committee_slot(2, per_slot).unwrap(),
        start + 1
    );
    let last = preset::ATTESTATION_COMMITTEES_PER_ROUND as u64 - 1;
    assert_eq!(
        compute_attestation_committee_slot(2, last).unwrap(),
        start + preset::SLOTS_PER_ROUND - 1
    );
}

/// The per-draw definitions both shuffled selections replace: draw `i` is
/// `indices[compute_shuffled_index(i % total, total, seed)]`.
#[test]
fn shuffled_selections_match_the_per_draw_definition() {
    let state = state(23);
    let indices: Vec<ValidatorIndex> = (0..23).rev().collect();
    let seed = Bytes32::repeat_byte(0x5a);

    let uniform = compute_uniform_selection(&indices, seed, 50).unwrap();
    let total = indices.len() as u64;
    let expected: Vec<ValidatorIndex> = (0..50u64)
        .map(|i| indices[compute_shuffled_index(i % total, total, seed).unwrap() as usize])
        .collect();
    assert_eq!(uniform, expected);

    let weighted = compute_shuffled_balance_weighted_selection(&state, &indices, seed, 40).unwrap();
    let reference =
        super::super::gloas::compute_balance_weighted_selection(&state, &indices, seed, 40, true)
            .unwrap();
    assert_eq!(weighted, reference);
}

#[test]
fn compute_uniform_selection_repeats_only_past_the_candidate_count() {
    let indices: Vec<ValidatorIndex> = (10..20).collect();
    let seed = Bytes32::repeat_byte(3);
    let all = compute_uniform_selection(&indices, seed, 10).unwrap();
    let distinct: BTreeSet<_> = all.iter().copied().collect();
    assert_eq!(distinct, indices.iter().copied().collect());
    let more = compute_uniform_selection(&indices, seed, 25).unwrap();
    assert_eq!(more.len(), 25);
    assert_eq!(&more[..10], &all[..]);
    assert!(compute_uniform_selection(&[], seed, 1).is_err());
}

/// `compute_ptc` and `compute_head_vote_committee` are the same draw under
/// two domains and sizes, over the epoch's whole active set.
#[test]
fn per_slot_committees_draw_from_the_whole_active_set() {
    let mut state = state(12);
    // At the electra ceiling every draw is accepted, which keeps the
    // per-draw reference (one shuffle per draw) quick at mainnet's sizes.
    for index in 0..12 {
        state.validator_mut(index).unwrap().effective_balance =
            preset::MAX_EFFECTIVE_BALANCE_ELECTRA;
    }
    let slot = state.slot() + 3;
    let active = get_active_validator_indices(&state, compute_epoch_at_slot(slot));

    let ptc = compute_ptc(&state, slot).unwrap();
    let ptc_seed = slot_seed(&state, slot, constants::DOMAIN_PTC_ATTESTER);
    let expected = super::super::gloas::compute_balance_weighted_selection(
        &state,
        &active,
        ptc_seed,
        preset::PTC_SIZE as u64,
        true,
    )
    .unwrap();
    assert_eq!(ptc.to_vec(), expected);

    let committee = compute_head_vote_committee(&state, slot).unwrap();
    let seed = slot_seed(&state, slot, constants::DOMAIN_HEAD_VOTE_COMMITTEE);
    let expected = super::super::gloas::compute_balance_weighted_selection(
        &state,
        &active,
        seed,
        preset::HEAD_VOTE_COMMITTEE_SIZE as u64,
        true,
    )
    .unwrap();
    assert_eq!(committee.to_vec(), expected);
    assert_ne!(seed, ptc_seed);
}

#[test]
fn initialize_head_vote_committee_window_leaves_the_previous_epoch_empty() {
    let state = state(5);
    let window = initialize_head_vote_committee_window(&state).unwrap();
    let per_epoch = preset::SLOTS_PER_EPOCH as usize;
    assert!(
        window[..per_epoch]
            .iter()
            .all(|committee| *committee == eip8453::empty_head_vote_committee())
    );
    let start = compute_start_slot_at_epoch(get_current_epoch(&state));
    for (offset, committee) in window[per_epoch..].iter().enumerate() {
        assert_eq!(
            *committee,
            compute_head_vote_committee(&state, start + offset as u64).unwrap(),
            "slot {}",
            start + offset as u64
        );
    }
    // The upgrade filled the state's own window the same way.
    assert_eq!(inner(&state).head_vote_committee_window, window);
}

// ---------------------------------------------------------------------------
// Beacon state accessors
// ---------------------------------------------------------------------------

#[test]
fn the_previous_round_stops_at_genesis() {
    let mut state = state(1);
    *state.slot_mut() = 0;
    assert_eq!(get_current_round(&state), 0);
    assert_eq!(get_previous_round(&state), constants::GENESIS_ROUND);
    *state.slot_mut() = 3 * preset::SLOTS_PER_ROUND + 1;
    assert_eq!(get_current_round(&state), 3);
    assert_eq!(get_previous_round(&state), 2);
}

#[test]
fn attestation_committees_partition_the_active_set_in_rotated_index_order() {
    let count = 2 * preset::ATTESTATION_COMMITTEES_PER_ROUND + 3;
    let mut state = state(count);
    // An inactive validator sits on no committee.
    state.validator_mut(4).unwrap().activation_epoch = constants::FAR_FUTURE_EPOCH;
    for epoch in [1, 2] {
        let active = get_active_validator_indices(&state, epoch);
        let mut seen: Vec<ValidatorIndex> = Vec::new();
        for index in 0..preset::ATTESTATION_COMMITTEES_PER_ROUND as u64 {
            seen.extend(
                get_attestation_committee(&state, epoch, index)
                    .unwrap()
                    .iter(),
            );
        }
        // Every active validator exactly once, in index order rotated by
        // `epoch`.
        let rotated: Vec<_> = (0..active.len())
            .map(|position| active[(position + epoch as usize) % active.len()])
            .collect();
        assert_eq!(seen, rotated, "epoch {epoch}");
    }
    // Empty registry: no committee has members.
    let empty = test_state::with_validators_at(ForkName::Eip8453, 1);
    let mut empty = empty;
    empty.validator_mut(0).unwrap().activation_epoch = constants::FAR_FUTURE_EPOCH;
    assert!(get_attestation_committee(&empty, 1, 0).unwrap().is_empty());
}

#[test]
fn committee_assignments_name_each_wanted_validators_one_committee() {
    let count = 2 * preset::ATTESTATION_COMMITTEES_PER_ROUND + 3;
    let mut state = state(count);
    state.validator_mut(4).unwrap().activation_epoch = constants::FAR_FUTURE_EPOCH;
    let wanted = [0u64, 4, 7, count as u64 + 5];
    for epoch in [1, 2] {
        let assignments =
            get_attestation_committee_assignments(&state, epoch, |v| wanted.contains(&v)).unwrap();
        // Inactive and absent validators have none.
        assert_eq!(assignments.keys().copied().collect::<Vec<_>>(), vec![0, 7]);
        for (&validator, assignment) in &assignments {
            let committee =
                get_attestation_committee(&state, epoch, assignment.committee_index).unwrap();
            assert_eq!(assignment.committee_length, committee.len() as u64);
            assert_eq!(committee[assignment.position as usize], validator);
        }
    }
}

#[test]
fn a_committee_attests_once_per_round_of_the_epoch() {
    let rounds_per_epoch = preset::SLOTS_PER_EPOCH / preset::SLOTS_PER_ROUND;
    let per_slot = preset::ATTESTATION_COMMITTEES_PER_ROUND as u64 / preset::SLOTS_PER_ROUND;
    for epoch in [0, 3] {
        let last = preset::ATTESTATION_COMMITTEES_PER_ROUND as u64 - 1;
        for committee_index in [0, per_slot - 1, per_slot, last] {
            let slots = attestation_committee_slots(epoch, committee_index).unwrap();
            assert_eq!(slots.len() as u64, rounds_per_epoch);
            for &slot in &slots {
                assert_eq!(compute_epoch_at_slot(slot), epoch);
                let round = compute_round_at_slot(slot);
                assert_eq!(
                    compute_attestation_committee_slot(round, committee_index).unwrap(),
                    slot
                );
            }
        }
    }
}

#[test]
fn aggregate_participants_follow_the_concatenated_committees() {
    let state = state(40);
    let epoch = get_current_epoch(&state);
    let committees = non_empty_committees(&state, epoch);
    let chosen = [committees[0], committees[2]];
    let (mut aggregate, members) = aggregate_over(&state, epoch, &chosen);
    // Clear the first committee's first member.
    aggregate.aggregation_bits.set(0, false).unwrap();
    let participants = get_aggregate_participants(&state, epoch, &aggregate).unwrap();
    let expected: BTreeSet<_> = members[1..].iter().copied().collect();
    assert_eq!(participants, expected);
    assert_eq!(get_attesting_indices(&state, &aggregate).unwrap(), expected);

    let indexed = get_indexed_attestation(&state, &aggregate).unwrap();
    assert_eq!(indexed.epoch, epoch);
    assert_eq!(
        indexed.attesting_indices.to_vec(),
        expected.iter().copied().collect::<Vec<_>>()
    );
    assert_eq!(indexed.data, aggregate.data);

    // Bits shorter than the committees are an error.
    aggregate.aggregation_bits = eip8453::AggregationBits::with_length(1);
    assert!(get_aggregate_participants(&state, epoch, &aggregate).is_err());
}

#[test]
fn get_head_vote_committee_reads_the_window_for_the_previous_current_and_lookahead_epochs() {
    let mut state = state(6);
    let config = Config::active().with_fork_epoch(ForkName::Eip8453, 0);
    let per_epoch = preset::SLOTS_PER_EPOCH;
    // Mark every window entry so each read can be traced to its position.
    for (position, committee) in inner_mut(&mut state)
        .head_vote_committee_window
        .iter_mut()
        .enumerate()
    {
        committee[0] = position as u64;
    }
    let epoch = get_current_epoch(&state);
    let start = compute_start_slot_at_epoch(epoch);
    // Current epoch: offset one epoch.
    assert_eq!(
        get_head_vote_committee(&state, start + 2, &config).unwrap()[0],
        per_epoch + 2
    );
    // Previous epoch: the window's first epoch.
    assert_eq!(
        get_head_vote_committee(&state, start - per_epoch + 1, &config).unwrap()[0],
        1
    );
    // Lookahead.
    let lookahead = start + preset::MIN_SEED_LOOKAHEAD * per_epoch;
    assert_eq!(
        get_head_vote_committee(&state, lookahead, &config).unwrap()[0],
        (preset::MIN_SEED_LOOKAHEAD + 1) * per_epoch
    );
    // Beyond the lookahead, two epochs back, or before the fork: refused.
    assert!(get_head_vote_committee(&state, lookahead + per_epoch, &config).is_err());
    *state.slot_mut() += 2 * per_epoch;
    assert!(get_head_vote_committee(&state, start, &config).is_err());
    let late_fork = Config::active().with_fork_epoch(ForkName::Eip8453, epoch + 3);
    assert!(get_head_vote_committee(&state, state.slot(), &late_fork).is_err());
}

#[test]
fn get_inclusion_list_committee_is_a_uniform_draw_from_the_active_set() {
    let state = state(9);
    let slot = state.slot() + 1;
    let committee = get_inclusion_list_committee(&state, slot).unwrap();
    let active = get_active_validator_indices(&state, compute_epoch_at_slot(slot));
    let seed = slot_seed(&state, slot, constants::DOMAIN_INCLUSION_LIST_COMMITTEE);
    assert_eq!(
        committee.to_vec(),
        compute_uniform_selection(&active, seed, preset::INCLUSION_LIST_COMMITTEE_SIZE as u64)
            .unwrap()
    );
    // Heze's entry point dispatches to this one for an EIP-8453 slot.
    let config = Config::active().with_fork_epoch(ForkName::Eip8453, get_current_epoch(&state));
    let via_heze = crate::beacon::inclusion_list::get_inclusion_list_committee(
        &config,
        &state,
        slot,
        &crate::beacon::helpers::accessors::CommitteeCache::default(),
    )
    .unwrap();
    assert_eq!(via_heze, committee.to_vec());
}

#[test]
fn get_unslashed_participating_indices_reads_round_participation() {
    let mut state = state(5);
    add_participation_flag(inner_mut(&mut state), 1, constants::PROGRESS_FLAG_INDEX).unwrap();
    add_participation_flag(inner_mut(&mut state), 2, constants::PROGRESS_FLAG_INDEX).unwrap();
    add_participation_flag(inner_mut(&mut state), 3, constants::PROGRESS_FLAG_INDEX).unwrap();
    add_participation_flag(inner_mut(&mut state), 3, constants::FINALITY_FLAG_INDEX).unwrap();
    state.validator_mut(2).unwrap().slashed = true;
    state.validator_mut(1).unwrap().activation_epoch = constants::FAR_FUTURE_EPOCH;
    assert_eq!(
        get_unslashed_participating_indices(&state, constants::PROGRESS_FLAG_INDEX).unwrap(),
        vec![3]
    );
    assert_eq!(
        get_unslashed_participating_indices(&state, constants::FINALITY_FLAG_INDEX).unwrap(),
        vec![3]
    );
}

#[test]
fn get_round_base_reward_scales_with_the_root_of_the_total_balance() {
    let state = state(16);
    let total = get_total_active_balance(&state).unwrap();
    let per_increment = preset::EFFECTIVE_BALANCE_INCREMENT * preset::ROUND_REWARD_FACTOR
        / integer_squareroot(total);
    let increments = preset::MAX_EFFECTIVE_BALANCE / preset::EFFECTIVE_BALANCE_INCREMENT;
    assert_eq!(
        get_round_base_reward(&state, 0).unwrap(),
        increments * per_increment
    );
}

#[test]
fn get_flag_index_rewards_pays_participants_only_and_nothing_during_a_leak() {
    let mut state = state(8);
    for index in [0, 1, 2, 3, 4] {
        add_participation_flag(inner_mut(&mut state), index, constants::PROGRESS_FLAG_INDEX)
            .unwrap();
    }
    let rewards = get_flag_index_rewards(&state, constants::PROGRESS_FLAG_INDEX).unwrap();
    let total = get_total_active_balance(&state).unwrap();
    let base = get_round_base_reward(&state, 0).unwrap();
    let participating_increments =
        5 * preset::MAX_EFFECTIVE_BALANCE / preset::EFFECTIVE_BALANCE_INCREMENT;
    let active_increments = total / preset::EFFECTIVE_BALANCE_INCREMENT;
    let expected = base * constants::PROGRESS_WEIGHT * participating_increments
        / (active_increments * constants::WEIGHT_DENOMINATOR);
    assert!(expected > 0);
    assert_eq!(&rewards[..5], &[expected; 5]);
    // No flag, no reward, and no penalty either.
    assert_eq!(&rewards[5..], &[0; 3]);
    assert_eq!(
        get_flag_index_rewards(&state, constants::FINALITY_FLAG_INDEX).unwrap(),
        vec![0; 8]
    );

    // In an inactivity leak nobody is paid.
    *state.slot_mut() = (preset::MIN_ROUNDS_TO_INACTIVITY_LEAK + 2) * preset::SLOTS_PER_ROUND;
    inner_mut(&mut state).finalized_slot = 0;
    assert_eq!(
        get_flag_index_rewards(&state, constants::PROGRESS_FLAG_INDEX).unwrap(),
        vec![0; 8]
    );
}

// ---------------------------------------------------------------------------
// Mutators
// ---------------------------------------------------------------------------

#[test]
fn add_participation_flag_sets_one_bit_of_the_current_round() {
    let mut state = state(2);
    add_participation_flag(inner_mut(&mut state), 1, constants::FINALITY_FLAG_INDEX).unwrap();
    assert_eq!(
        inner(&state).round_participation[1],
        1 << constants::FINALITY_FLAG_INDEX
    );
    add_participation_flag(inner_mut(&mut state), 1, constants::PROGRESS_FLAG_INDEX).unwrap();
    add_participation_flag(inner_mut(&mut state), 1, constants::PROGRESS_FLAG_INDEX).unwrap();
    assert_eq!(inner(&state).round_participation[1], 0b11);
    assert_eq!(inner(&state).round_participation[0], 0);
    assert!(add_participation_flag(inner_mut(&mut state), 2, 0).is_err());
}
