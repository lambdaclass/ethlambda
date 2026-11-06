//! Tests for EIP-8453's round and epoch processing.

use super::*;
use crate::beacon::containers::electra::PendingDeposit;
use crate::beacon::fork::ForkName;
use crate::beacon::helpers::eip8453::{compute_head_vote_committee, get_validator_weight};
use crate::beacon::helpers::test_state;
use crate::beacon::primitives::{BlsSignature, Bytes32, Root};

fn state(count: usize) -> BeaconState {
    test_state::with_validators_at(ForkName::Eip8453, count)
}

fn inner(state: &BeaconState) -> &eip8453::BeaconState {
    eip8453_state(state, "test").unwrap()
}

fn inner_mut(state: &mut BeaconState) -> &mut eip8453::BeaconState {
    eip8453_state_mut(state, "test").unwrap()
}

fn config() -> Config {
    Config::active().with_fork_epoch(ForkName::Eip8453, 1)
}

// ---------------------------------------------------------------------------
// Round processing
// ---------------------------------------------------------------------------

#[test]
fn process_inactivity_updates_recovers_participants_and_charges_the_rest() {
    let config = config();
    let mut state = state(4);
    *state.inactivity_score_mut(0).unwrap() = 20;
    *state.inactivity_score_mut(1).unwrap() = 20;
    add_participation_flag(inner_mut(&mut state), 0, constants::PROGRESS_FLAG_INDEX).unwrap();
    // A slashed validator's flag does not count.
    add_participation_flag(inner_mut(&mut state), 2, constants::PROGRESS_FLAG_INDEX).unwrap();
    state.validator_mut(2).unwrap().slashed = true;
    // An inactive validator is left alone.
    state.validator_mut(3).unwrap().activation_epoch = constants::FAR_FUTURE_EPOCH;

    process_inactivity_updates(&mut state, &config).unwrap();

    let scores = &inner(&state).inactivity_scores;
    assert_eq!(scores[0], 20 - config.inactivity_score_recovery_rate);
    assert_eq!(scores[1], 20 + config.inactivity_score_bias);
    assert_eq!(scores[2], config.inactivity_score_bias);
    assert_eq!(scores[3], 0);
    // Recovery saturates at zero.
    process_inactivity_updates(&mut state, &config).unwrap();
    process_inactivity_updates(&mut state, &config).unwrap();
    assert_eq!(inner(&state).inactivity_scores[0], 0);
}

#[test]
fn process_inactivity_updates_exits_a_validator_at_the_ejection_score() {
    let config = config();
    let mut state = state(3);
    *state.inactivity_score_mut(1).unwrap() =
        preset::EJECTION_INACTIVITY_SCORE - config.inactivity_score_bias;
    process_inactivity_updates(&mut state, &config).unwrap();
    assert_eq!(
        inner(&state).inactivity_scores[1],
        preset::EJECTION_INACTIVITY_SCORE
    );
    assert_ne!(
        state.validator(1).unwrap().exit_epoch,
        constants::FAR_FUTURE_EPOCH
    );
    // The exit costs weight, not balance.
    assert_eq!(state.balance(1).unwrap(), preset::MAX_EFFECTIVE_BALANCE);
    assert_eq!(get_validator_weight(&state, 1).unwrap(), 0);
    assert_eq!(
        state.validator(0).unwrap().exit_epoch,
        constants::FAR_FUTURE_EPOCH
    );
}

#[test]
fn process_rewards_credits_each_flag_and_penalizes_nobody() {
    let mut state = state(8);
    for index in 0..6 {
        add_participation_flag(inner_mut(&mut state), index, constants::PROGRESS_FLAG_INDEX)
            .unwrap();
    }
    add_participation_flag(inner_mut(&mut state), 0, constants::FINALITY_FLAG_INDEX).unwrap();
    let progress = get_flag_index_rewards(&state, constants::PROGRESS_FLAG_INDEX).unwrap();
    let finality = get_flag_index_rewards(&state, constants::FINALITY_FLAG_INDEX).unwrap();

    process_rewards(&mut state).unwrap();

    for index in 0..8 {
        assert_eq!(
            state.balance(index as u64).unwrap(),
            preset::MAX_EFFECTIVE_BALANCE + progress[index] + finality[index],
            "validator {index}"
        );
    }
    assert!(progress[0] > 0 && finality[0] > 0);
    assert_eq!(state.balance(7).unwrap(), preset::MAX_EFFECTIVE_BALANCE);
}

#[test]
fn process_participation_flag_updates_carries_progress_made_at_the_height() {
    let mut state = state(4);
    let fields = inner_mut(&mut state);
    fields.round_participation[0] = 0b11;
    fields.round_participation[1] = 0b01;
    fields.progress_participation[1] = true;
    fields.progress_participation[3] = true;

    process_participation_flag_updates(&mut state).unwrap();

    let flags = &inner(&state).round_participation;
    assert_eq!(flags.len(), 4);
    assert_eq!(flags[0], 0);
    assert_eq!(flags[1], 1 << constants::PROGRESS_FLAG_INDEX);
    assert_eq!(flags[2], 0);
    assert_eq!(flags[3], 1 << constants::PROGRESS_FLAG_INDEX);
}

#[test]
fn process_round_runs_inactivity_then_rewards_then_the_reset() {
    let config = config();
    let mut state = state(4);
    for index in 0..3 {
        add_participation_flag(inner_mut(&mut state), index, constants::PROGRESS_FLAG_INDEX)
            .unwrap();
    }
    let rewards = get_flag_index_rewards(&state, constants::PROGRESS_FLAG_INDEX).unwrap();

    process_round(&mut state, &config).unwrap();

    // Validator 3 had no flag: charged, unpaid.
    assert_eq!(
        inner(&state).inactivity_scores[3],
        config.inactivity_score_bias
    );
    assert_eq!(state.balance(3).unwrap(), preset::MAX_EFFECTIVE_BALANCE);
    // The others: paid the reward computed before the reset.
    assert_eq!(
        state.balance(0).unwrap(),
        preset::MAX_EFFECTIVE_BALANCE + rewards[0]
    );
    // And the round's flags start over (no progress recorded at the height).
    assert!(inner(&state).round_participation.iter().all(|&f| f == 0));
}

// ---------------------------------------------------------------------------
// Epoch processing
// ---------------------------------------------------------------------------

#[test]
fn process_epoch_runs_every_step_on_a_fresh_state() {
    let config = config();
    let mut state = state(16);
    let window_before = inner(&state).head_vote_committee_window.clone();
    process_epoch(&mut state, &config).unwrap();
    // The window moved up an epoch.
    let per_epoch = preset::SLOTS_PER_EPOCH as usize;
    assert_eq!(
        inner(&state).head_vote_committee_window[..2 * per_epoch],
        window_before[per_epoch..]
    );
    // Through the dispatcher too.
    super::super::process_epoch(&mut state, &config).unwrap();
    // Casper FFG justification is refused rather than run.
    assert!(super::super::process_justification_and_finalization(&mut state, &config).is_err());
}

#[test]
fn process_builder_pending_payments_pays_on_a_head_vote_quorum_and_shifts_both_windows() {
    let mut state = state(4);
    let per_epoch = preset::SLOTS_PER_EPOCH as usize;
    let needed = (preset::HEAD_VOTE_COMMITTEE_SIZE as u64 * 6).div_ceil(10) as usize;
    let payment = |amount: u64, builder_index: u64| gloas::BuilderPendingPayment {
        weight: 0,
        withdrawal: gloas::BuilderPendingWithdrawal {
            fee_recipient: Default::default(),
            amount,
            builder_index,
        },
        proposer_index: 0,
    };
    let inner = inner_mut(&mut state);
    // Slot 0: quorum, paid. Slot 1: one seat short, dropped. Slot 2: zero
    // amount with a quorum, skipped.
    inner.builder_pending_payments[0] = payment(10, 1);
    inner.builder_pending_payments[1] = payment(20, 2);
    inner.builder_pending_payments[2] = payment(0, 3);
    for seat in 0..needed {
        inner.head_vote_participation[0].set(seat, true).unwrap();
        inner.head_vote_participation[2].set(seat, true).unwrap();
    }
    for seat in 0..needed - 1 {
        inner.head_vote_participation[1].set(seat, true).unwrap();
    }
    // The current epoch's entries move down.
    inner.builder_pending_payments[per_epoch] = payment(30, 4);
    inner.head_vote_participation[per_epoch]
        .set(5, true)
        .unwrap();

    process_builder_pending_payments(&mut state).unwrap();

    let inner = inner_mut(&mut state);
    assert_eq!(inner.builder_pending_withdrawals.len(), 1);
    assert_eq!(inner.builder_pending_withdrawals[0].builder_index, 1);
    assert_eq!(inner.builder_pending_payments[0], payment(30, 4));
    assert_eq!(
        inner.builder_pending_payments[per_epoch],
        gloas::BuilderPendingPayment::default()
    );
    assert_eq!(inner.head_vote_participation[0].count_ones(), 1);
    assert_eq!(inner.head_vote_participation[0].get(5), Some(true));
    assert!(
        inner.head_vote_participation[per_epoch..]
            .iter()
            .all(|bits| bits.count_ones() == 0)
    );
}

#[test]
fn process_pending_deposits_waits_for_the_finalized_slot() {
    let config = config();
    let mut state = test_state::with_signing_validators_at(ForkName::Eip8453, 4);
    // A top-up for validator 0, queued at slot 5.
    let pubkey = state.validator(0).unwrap().pubkey;
    let deposit = PendingDeposit {
        pubkey,
        withdrawal_credentials: Bytes32::ZERO,
        amount: 1_000_000_000,
        signature: BlsSignature::default(),
        slot: 5,
    };
    inner_mut(&mut state).pending_deposits.push(deposit.clone());
    inner_mut(&mut state).finalized_slot = 4;
    process_pending_deposits(&mut state, &config).unwrap();
    assert_eq!(inner(&state).pending_deposits.len(), 1);
    assert_eq!(state.balance(0).unwrap(), preset::MAX_EFFECTIVE_BALANCE);

    inner_mut(&mut state).finalized_slot = 5;
    process_pending_deposits(&mut state, &config).unwrap();
    assert!(inner(&state).pending_deposits.is_empty());
    assert_eq!(
        state.balance(0).unwrap(),
        preset::MAX_EFFECTIVE_BALANCE + deposit.amount
    );
}

/// `add_validator_to_registry` (modified): a new validator grows every
/// per-validator list the finality gadget keeps, pending justifications'
/// participation included.
#[test]
fn a_new_validator_grows_every_finality_gadget_list() {
    let config = config();
    let mut state = state(3);
    let pending = eip8453::PendingFinality {
        checkpoint: eip8453::HeightCheckpoint {
            height: 1,
            root: Root::repeat_byte(1),
        },
        slot: 1,
        participation: vec![true; 3].into(),
    };
    inner_mut(&mut state).pending_finality = vec![pending].try_into().unwrap();
    inner_mut(&mut state).finalized_slot = 100;

    // A properly signed deposit for a new key with execution credentials.
    let secret = test_state::secret_key_for(42);
    let pubkey = crate::beacon::primitives::BlsPubkey(secret.sk_to_pk().to_bytes());
    let mut credentials = [0u8; 32];
    credentials[0] = constants::ETH1_ADDRESS_WITHDRAWAL_PREFIX;
    let withdrawal_credentials = Bytes32::from(credentials);
    let amount = preset::MIN_ACTIVATION_BALANCE;
    let message = crate::beacon::containers::shared::DepositMessage {
        pubkey,
        withdrawal_credentials,
        amount,
    };
    let domain = crate::beacon::helpers::misc::compute_deposit_domain(config.genesis_fork_version);
    let signing_root = crate::beacon::helpers::misc::compute_signing_root(
        crate::beacon::primitives::HashTreeRoot::hash_tree_root(&message),
        domain,
    );
    let signature = BlsSignature(
        secret
            .sign(signing_root.as_slice(), crate::beacon::bls::DST, &[])
            .to_bytes(),
    );
    inner_mut(&mut state).pending_deposits.push(PendingDeposit {
        pubkey,
        withdrawal_credentials,
        amount,
        signature,
        slot: 1,
    });

    process_pending_deposits(&mut state, &config).unwrap();

    assert_eq!(state.validator_count(), 4);
    let inner = inner(&state);
    assert_eq!(inner.inactivity_scores.len(), 4);
    assert_eq!(inner.round_participation.len(), 4);
    assert_eq!(inner.target_participation.to_vec(), vec![false; 4]);
    assert_eq!(inner.progress_participation.to_vec(), vec![false; 4]);
    assert_eq!(
        inner.pending_finality[0].participation.to_vec(),
        vec![true, true, true, false]
    );
}

#[test]
fn registry_updates_activate_once_the_finalized_slot_passes_eligibility() {
    let config = config();
    let mut state = state(3);
    state.validator_mut(2).unwrap().activation_epoch = constants::FAR_FUTURE_EPOCH;
    state.validator_mut(2).unwrap().activation_eligibility_epoch = 1;
    // Finalized slot in epoch 0: not yet.
    inner_mut(&mut state).finalized_slot = preset::SLOTS_PER_EPOCH - 1;
    super::super::electra::process_registry_updates(&mut state, &config).unwrap();
    assert_eq!(
        state.validator(2).unwrap().activation_epoch,
        constants::FAR_FUTURE_EPOCH
    );
    inner_mut(&mut state).finalized_slot = preset::SLOTS_PER_EPOCH;
    super::super::electra::process_registry_updates(&mut state, &config).unwrap();
    assert_ne!(
        state.validator(2).unwrap().activation_epoch,
        constants::FAR_FUTURE_EPOCH
    );
}

#[test]
fn process_head_vote_committee_window_appends_the_new_lookahead_epoch() {
    let mut state = state(5);
    let before = inner(&state).head_vote_committee_window.clone();
    process_head_vote_committee_window(&mut state).unwrap();
    let after = &inner(&state).head_vote_committee_window;
    let per_epoch = preset::SLOTS_PER_EPOCH as usize;
    assert_eq!(after[..after.len() - per_epoch], before[per_epoch..]);
    let start = crate::beacon::helpers::misc::compute_start_slot_at_epoch(
        get_current_epoch(&state) + preset::MIN_SEED_LOOKAHEAD + 1,
    );
    for (offset, committee) in after[after.len() - per_epoch..].iter().enumerate() {
        assert_eq!(
            *committee,
            compute_head_vote_committee(&state, start + offset as u64).unwrap()
        );
    }
}

#[test]
fn process_ptc_window_draws_with_the_eip8453_compute_ptc() {
    let mut state = state(5);
    super::super::gloas::process_ptc_window(&mut state).unwrap();
    let window = state.ptc_window().unwrap();
    let per_epoch = preset::SLOTS_PER_EPOCH as usize;
    let start = crate::beacon::helpers::misc::compute_start_slot_at_epoch(
        get_current_epoch(&state) + preset::MIN_SEED_LOOKAHEAD + 1,
    );
    let last = window.len() - per_epoch;
    assert_eq!(
        window[last],
        crate::beacon::helpers::eip8453::compute_ptc(&state, start).unwrap()
    );
}
