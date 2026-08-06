//! Altair-specific epoch processing.
//!
//! Altair keeps every phase0 step that does not touch attestation accounting
//! unchanged (registry updates, slashings, the four resets, the historical
//! roots roll-up) and replaces the rest: justification now reads participation
//! flags instead of `PendingAttestation`s, rewards score those same flags
//! instead of replaying attestations, and three steps are new outright:
//! [`process_inactivity_updates`] (the running per-validator score the leak
//! penalty scales from), [`process_participation_flag_updates`] (the rotation
//! that gives the reward accounting its two-epoch window), and
//! [`process_sync_committee_updates`] (rotating in the next sync committee at
//! each period boundary). [`process_epoch`] below is the driver, transcribed
//! from the specification's own list in the order it gives them; that order is
//! load-bearing in the same two places [`super`]'s phase0 driver documents,
//! plus one more altair adds: [`process_inactivity_updates`] must run before
//! [`process_rewards_and_penalties`], since the inactivity penalty scales by
//! the score the former just updated, not by whatever it held a step earlier.

use crate::config::Config;
use crate::constants;
use crate::containers::BeaconState;
use crate::error::{Error, Result};
use crate::helpers::accessors::{
    get_current_epoch, get_previous_epoch, get_total_active_balance, get_total_balance,
};
use crate::helpers::altair::{
    get_flag_index_deltas, get_inactivity_penalty_deltas, get_next_sync_committee,
    get_unslashed_participating_indices,
};
use crate::helpers::finality::{get_eligible_validator_indices, is_in_inactivity_leak};
use crate::helpers::math::saturating_sub;
use crate::helpers::mutators::{decrease_balance, increase_balance};
use crate::preset;
use crate::primitives::ValidatorIndex;

use super::justification::weigh_justification_and_finalization;

/// Runs every altair epoch-boundary step, in the specification's order.
///
/// Delegates every step the specification does not modify in altair
/// (registry updates, slashings, the four resets, the historical roots
/// update) to the fork-shared functions in [`super`], and substitutes
/// altair's own version of the rest.
pub fn process_epoch(state: &mut BeaconState, config: &Config) -> Result<()> {
    process_justification_and_finalization(state)?;
    process_inactivity_updates(state, config)?;
    process_rewards_and_penalties(state, config)?;
    super::registry::process_registry_updates(state, config)?;
    super::registry::process_slashings(state, config)?;
    super::process_eth1_data_reset(state)?;
    super::process_effective_balance_updates(state)?;
    super::process_slashings_reset(state)?;
    super::process_randao_mixes_reset(state)?;
    super::process_historical_roots_update(state)?;
    process_participation_flag_updates(state)?;
    process_sync_committee_updates(state)?;
    Ok(())
}

/// Updates justification and finality from how much active balance cast a
/// timely, correct target vote for the previous and current epoch.
///
/// The only difference from phase0's version: the two target balances come
/// from [`get_unslashed_participating_indices`] over the epoch's participation
/// flags rather than from matching stored `PendingAttestation`s against the
/// block root history. Once those two balances are in hand, the actual
/// bitfield and finality bookkeeping is identical, so this hands off to
/// [`weigh_justification_and_finalization`], the same function phase0 calls.
pub fn process_justification_and_finalization(state: &mut BeaconState) -> Result<()> {
    // Initial FFG checkpoint values have a `0x00` stub for `root`. Skip FFG
    // updates in the first two epochs to avoid corner cases that might result
    // in modifying this stub.
    if get_current_epoch(state) <= constants::GENESIS_EPOCH + 1 {
        return Ok(());
    }

    let previous_indices = get_unslashed_participating_indices(
        state,
        constants::TIMELY_TARGET_FLAG_INDEX,
        get_previous_epoch(state),
    )?;
    let current_indices = get_unslashed_participating_indices(
        state,
        constants::TIMELY_TARGET_FLAG_INDEX,
        get_current_epoch(state),
    )?;
    let total_active_balance = get_total_active_balance(state)?;
    let previous_target_balance = get_total_balance(state, &previous_indices)?;
    let current_target_balance = get_total_balance(state, &current_indices)?;
    weigh_justification_and_finalization(
        state,
        total_active_balance,
        previous_target_balance,
        current_target_balance,
    )
}

/// Updates every eligible validator's inactivity score from its previous
/// epoch's timely-target participation.
///
/// The score is a validator's own running memory of missed target votes: it
/// rises by [`Config::inactivity_score_bias`] for an epoch it misses, and
/// falls back down (by one for participating, and by
/// [`Config::inactivity_score_recovery_rate`] more whenever the chain is not
/// leaking) the moment it returns. That per-validator memory is what makes
/// [`crate::helpers::altair::get_inactivity_penalty_deltas`]'s leak penalty
/// proportional to an individual's own record of absence rather than to a
/// single chain-wide severity shared by everyone: two validators who have been
/// offline for different lengths of time pay different penalties even if the
/// leak itself is the same age for both.
///
/// Skipped at the genesis epoch, since the score update reads the previous
/// epoch's participation and genesis has none.
pub fn process_inactivity_updates(state: &mut BeaconState, config: &Config) -> Result<()> {
    if get_current_epoch(state) == constants::GENESIS_EPOCH {
        return Ok(());
    }

    // Every read below needs `&BeaconState`, so they all run before this takes
    // the mutable borrow `inactivity_scores` requires: `altair_validator_lists_mut`
    // borrows the whole state, and there is no way to hold that mutably while
    // also calling `get_eligible_validator_indices`, `get_unslashed_participating_indices`,
    // or `is_in_inactivity_leak`, each of which needs its own `&BeaconState`.
    // `process_effective_balance_updates` in the parent module resolves the
    // identical conflict the same way: decide everything in one pass over
    // immutable state, then apply it in a second pass over a mutable borrow.
    let eligible_indices = get_eligible_validator_indices(state);
    let previous_epoch = get_previous_epoch(state);
    let participating_indices = get_unslashed_participating_indices(
        state,
        constants::TIMELY_TARGET_FLAG_INDEX,
        previous_epoch,
    )?;
    let leaking = is_in_inactivity_leak(state);

    let (_, _, inactivity_scores) = state.altair_validator_lists_mut()?;
    let score_count = inactivity_scores.len();
    for index in eligible_indices {
        let score = inactivity_scores
            .get_mut(index as usize)
            .ok_or(Error::IndexOutOfBounds {
                index: index as usize,
                len: score_count,
            })?;

        // `participating_indices` is ascending and duplicate-free (see
        // `get_unslashed_participating_indices`), so membership is a binary
        // search rather than a linear scan.
        if participating_indices.binary_search(&index).is_ok() {
            // `x -= min(1, x)`, written with `saturating_sub` so a
            // already-zero score cannot underflow.
            *score = saturating_sub(*score, 1);
        } else {
            // The specification treats a `uint64` overflow here as an invalid
            // state rather than a wrapped one, so this is checked rather than
            // left to release-mode wrapping.
            *score = score.checked_add(config.inactivity_score_bias).ok_or(
                Error::ArithmeticOverflow("inactivity_scores[index] + INACTIVITY_SCORE_BIAS"),
            )?;
        }

        if !leaking {
            *score = saturating_sub(*score, config.inactivity_score_recovery_rate);
        }
    }

    Ok(())
}

/// Applies the epoch's flag-index and inactivity deltas to every validator's
/// balance.
///
/// Altair's version of this step: phase0 sums four attestation-shaped delta
/// functions (source, target, head, inclusion delay) plus one inactivity
/// penalty; altair instead sums one delta per participation flag (weighted by
/// [`constants::PARTICIPATION_FLAG_WEIGHTS`]) plus the same kind of inactivity
/// penalty, computed from [`crate::helpers::altair::get_inactivity_penalty_deltas`]
/// against the scores [`process_inactivity_updates`] just brought up to date.
/// Applying rewards and penalties as two separate passes (through
/// [`increase_balance`] and [`decrease_balance`], not one netted delta) is
/// unchanged from phase0, and for the same reason: [`decrease_balance`] floors
/// at zero, so netting first would let a reward mask a penalty that should
/// have driven a low balance all the way down.
///
/// Skipped entirely at the genesis epoch: rewards pay for participation
/// recorded during the previous epoch, and genesis has none.
pub fn process_rewards_and_penalties(state: &mut BeaconState, config: &Config) -> Result<()> {
    if get_current_epoch(state) == constants::GENESIS_EPOCH {
        return Ok(());
    }

    let mut deltas = Vec::with_capacity(constants::PARTICIPATION_FLAG_WEIGHTS.len() + 1);
    for flag_index in 0..constants::PARTICIPATION_FLAG_WEIGHTS.len() {
        deltas.push(get_flag_index_deltas(state, flag_index)?);
    }
    deltas.push(get_inactivity_penalty_deltas(state, config)?);

    let validator_count = state.validators().len() as ValidatorIndex;
    for (rewards, penalties) in deltas {
        for index in 0..validator_count {
            increase_balance(state, index, rewards[index as usize])?;
            decrease_balance(state, index, penalties[index as usize])?;
        }
    }
    Ok(())
}

/// Rotates the current epoch's participation flags into the previous slot and
/// installs a fresh, all-zero current list.
///
/// This is what gives the reward accounting a two-epoch window without
/// storing whole attestations the way phase0 does: a flag set at processing
/// time survives exactly one more epoch boundary (as
/// `previous_epoch_participation`, read by the next epoch's rewards and
/// justification) and then this drops it, so the state never holds more than
/// two epochs of participation regardless of how long the chain runs.
///
/// The fresh current list is sized to the validator registry, not left empty:
/// every validator (including one that just activated) needs a flag slot from
/// the moment it can be attested for, and `process_attestation` (not
/// implemented in this file) indexes into it directly rather than appending.
pub fn process_participation_flag_updates(state: &mut BeaconState) -> Result<()> {
    let validator_count = state.validators().len();
    let (previous_epoch_participation, current_epoch_participation, _) =
        state.altair_validator_lists_mut()?;

    *previous_epoch_participation = core::mem::take(current_epoch_participation);
    *current_epoch_participation = vec![0; validator_count].try_into()?;

    Ok(())
}

/// Rotates in the next sync committee at each sync committee period boundary.
///
/// Only fires once every [`preset::EPOCHS_PER_SYNC_COMMITTEE_PERIOD`] epochs;
/// every other epoch this is a no-op, since `current_sync_committee` and
/// `next_sync_committee` are otherwise left exactly as they were. Computing
/// the new `next_sync_committee` before touching either field (rather than
/// computing it after `current_sync_committee` has already been overwritten)
/// matters because [`get_next_sync_committee`] reads the validator registry,
/// not either committee field, so the order is safe either way for
/// correctness; it is still done first here so the fallible call happens
/// before any mutation, leaving the state untouched if it errors.
pub fn process_sync_committee_updates(state: &mut BeaconState) -> Result<()> {
    let next_epoch = get_current_epoch(state) + 1;
    if next_epoch.is_multiple_of(preset::EPOCHS_PER_SYNC_COMMITTEE_PERIOD) {
        let next_committee = get_next_sync_committee(state)?;
        let (current_sync_committee, next_sync_committee) = state.sync_committees_mut()?;
        *current_sync_committee = core::mem::replace(next_sync_committee, next_committee);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containers::altair;
    use crate::containers::altair::SyncCommittee;
    use crate::containers::shared::Validator;
    use crate::helpers::altair::add_flag;
    use crate::primitives::{BlsPubkey, Bytes32, Root};

    /// A deterministic but genuinely valid BLS public key for validator
    /// `index`.
    ///
    /// [`process_sync_committee_updates`] aggregates every validator's pubkey
    /// through [`get_next_sync_committee`], and a zero pubkey is not a curve
    /// point, so an all-default validator would make that aggregation fail
    /// rather than exercise the rotation this module is testing.
    fn pubkey_for(index: usize) -> BlsPubkey {
        let mut ikm = [0u8; 32];
        ikm[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
        let secret = blst::min_pk::SecretKey::key_gen(&ikm, &[])
            .expect("32 bytes of input material is enough for key generation");
        BlsPubkey(secret.sk_to_pk().to_bytes())
    }

    /// An altair state with `count` fully active, full-balance validators,
    /// positioned one epoch in, the same way
    /// `crate::helpers::test_state::with_validators` positions its phase0
    /// state.
    ///
    /// Not shared with `crate::helpers::altair`'s own private
    /// `altair_state_with_validators`: that builder predates this file and
    /// lives in a test module of its own, so this is a second copy of the same
    /// shape. The two should probably be lifted into one place either party
    /// can import, rather than kept as two independent sources of truth that
    /// happen to agree.
    fn altair_state_with_validators(count: usize) -> BeaconState {
        let validators: Vec<Validator> = (0..count)
            .map(|index| Validator {
                pubkey: pubkey_for(index),
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

        BeaconState::Altair(altair::BeaconState {
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
        })
    }

    // -----------------------------------------------------------------------
    // process_justification_and_finalization
    // -----------------------------------------------------------------------

    #[test]
    fn justification_near_genesis_is_a_no_op() {
        // Positioned at current epoch 1, still within the `GENESIS_EPOCH + 1`
        // guard.
        let mut state = altair_state_with_validators(4);
        let before = state.clone();

        process_justification_and_finalization(&mut state).unwrap();

        assert_eq!(state.justification_bits(), before.justification_bits());
        assert_eq!(
            state.current_justified_checkpoint(),
            before.current_justified_checkpoint()
        );
    }

    #[test]
    fn justification_reads_target_balance_from_participation_flags() {
        let mut state = altair_state_with_validators(4);
        *state.slot_mut() = preset::SLOTS_PER_EPOCH * 2; // current epoch 2, previous epoch 1

        // Every validator cast a timely, correct target vote last epoch, but
        // none has yet this epoch: only the previous epoch should justify.
        {
            let (previous_epoch_participation, _, _) = state.altair_validator_lists_mut().unwrap();
            for flags in previous_epoch_participation.iter_mut() {
                *flags = add_flag(*flags, constants::TIMELY_TARGET_FLAG_INDEX);
            }
        }

        process_justification_and_finalization(&mut state).unwrap();

        let bits = state.justification_bits();
        assert_eq!(bits.get(0), Some(false), "current epoch did not justify");
        assert_eq!(bits.get(1), Some(true), "previous epoch justified");
        assert_eq!(state.current_justified_checkpoint().epoch, 1);
    }

    // -----------------------------------------------------------------------
    // process_inactivity_updates
    // -----------------------------------------------------------------------

    #[test]
    fn inactivity_updates_are_a_no_op_at_genesis() {
        let mut state = altair_state_with_validators(4);
        *state.slot_mut() = 0;
        let (_, _, scores) = state.altair_validator_lists().unwrap();
        let before = scores.clone();

        process_inactivity_updates(&mut state, &Config::mainnet()).unwrap();

        let (_, _, scores) = state.altair_validator_lists().unwrap();
        assert_eq!(*scores, before);
    }

    #[test]
    fn inactivity_updates_diverge_by_participation_during_a_leak() {
        let config = Config::mainnet();
        let mut state = altair_state_with_validators(4);
        // Push the previous epoch far enough past the (still-genesis)
        // finalized checkpoint to be a leak, matching how
        // `rewards.rs`'s `finality_stalled_past_the_threshold_is_a_leak` test
        // forces the same condition.
        *state.slot_mut() =
            preset::SLOTS_PER_EPOCH * (preset::MIN_EPOCHS_TO_INACTIVITY_PENALTY + 10);

        {
            let (previous_epoch_participation, _, inactivity_scores) =
                state.altair_validator_lists_mut().unwrap();
            inactivity_scores[0] = 10;
            inactivity_scores[1] = 10;
            // Validator 0 participated last epoch; validator 1 did not.
            previous_epoch_participation[0] = add_flag(0, constants::TIMELY_TARGET_FLAG_INDEX);
        }

        process_inactivity_updates(&mut state, &config).unwrap();

        let (_, _, scores) = state.altair_validator_lists().unwrap();
        // Participating: score falls by one; during a leak nothing recovers
        // it further.
        assert_eq!(scores[0], 9);
        // Not participating: score rises by the configured bias.
        assert_eq!(scores[1], 10 + config.inactivity_score_bias);
    }

    #[test]
    fn inactivity_updates_recover_fully_outside_a_leak() {
        let config = Config::mainnet();
        let mut state = altair_state_with_validators(4);
        // The default position (current epoch 1, finalized checkpoint at
        // epoch 0) is not a leak: `get_finality_delay` is zero.

        {
            let (previous_epoch_participation, _, inactivity_scores) =
                state.altair_validator_lists_mut().unwrap();
            inactivity_scores[0] = 5;
            previous_epoch_participation[0] = add_flag(0, constants::TIMELY_TARGET_FLAG_INDEX);
        }

        process_inactivity_updates(&mut state, &config).unwrap();

        // One point off for participating, then the whole remainder recovers
        // because the recovery rate outpaces a score this small.
        let (_, _, scores) = state.altair_validator_lists().unwrap();
        assert_eq!(scores[0], 0);
    }

    // -----------------------------------------------------------------------
    // process_rewards_and_penalties
    // -----------------------------------------------------------------------

    #[test]
    fn rewards_and_penalties_are_a_no_op_at_genesis() {
        let config = Config::mainnet();
        let mut state = altair_state_with_validators(4);
        *state.slot_mut() = 0;
        let balances_before = state.balances().clone();

        process_rewards_and_penalties(&mut state, &config).unwrap();

        assert_eq!(
            state.balances(),
            &balances_before,
            "the genesis epoch has no previous epoch to reward"
        );
    }

    // -----------------------------------------------------------------------
    // process_participation_flag_updates
    // -----------------------------------------------------------------------

    #[test]
    fn participation_flag_updates_rotate_current_into_previous_and_reset_current() {
        let mut state = altair_state_with_validators(4);
        let current_before = {
            let (_, current_epoch_participation, _) = state.altair_validator_lists_mut().unwrap();
            current_epoch_participation[0] = add_flag(0, constants::TIMELY_SOURCE_FLAG_INDEX);
            current_epoch_participation[1] = add_flag(0, constants::TIMELY_HEAD_FLAG_INDEX);
            current_epoch_participation.to_vec()
        };

        process_participation_flag_updates(&mut state).unwrap();

        let (previous_epoch_participation, current_epoch_participation, _) =
            state.altair_validator_lists().unwrap();
        assert_eq!(previous_epoch_participation.to_vec(), current_before);
        assert_eq!(current_epoch_participation.len(), 4);
        assert!(
            current_epoch_participation.iter().all(|&flags| flags == 0),
            "the fresh current list must start all-zero"
        );
    }

    // -----------------------------------------------------------------------
    // process_sync_committee_updates
    // -----------------------------------------------------------------------

    #[test]
    fn sync_committee_updates_are_a_no_op_off_the_period_boundary() {
        // Current epoch 1: `next_epoch` (2) is not a multiple of
        // `EPOCHS_PER_SYNC_COMMITTEE_PERIOD` on either preset.
        let mut state = altair_state_with_validators(4);
        let (before_current, before_next) = {
            let (current, next) = state.sync_committees().unwrap();
            (current.clone(), next.clone())
        };

        process_sync_committee_updates(&mut state).unwrap();

        let (current, next) = state.sync_committees().unwrap();
        assert_eq!(*current, before_current);
        assert_eq!(*next, before_next);
    }

    #[test]
    fn sync_committee_updates_rotate_at_the_period_boundary() {
        let mut state = altair_state_with_validators(4);
        // One epoch before a period boundary, so `next_epoch` lands exactly on
        // it.
        *state.slot_mut() =
            preset::SLOTS_PER_EPOCH * (preset::EPOCHS_PER_SYNC_COMMITTEE_PERIOD - 1);

        let old_next = state.sync_committees().unwrap().1.clone();
        let expected_next = get_next_sync_committee(&state).unwrap();

        process_sync_committee_updates(&mut state).unwrap();

        let (current, next) = state.sync_committees().unwrap();
        assert_eq!(
            *current, old_next,
            "the old next committee takes over as current"
        );
        assert_eq!(
            *next, expected_next,
            "a freshly drawn committee takes the next slot"
        );
    }
}
