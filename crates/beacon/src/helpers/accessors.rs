//! Beacon state accessors.
//!
//! The specification reads its constants from global scope. Here the preset
//! values are compile-time constants, but the configuration values are not, so
//! any accessor needing one takes a [`Config`]. That is the only systematic
//! difference between these signatures and the spec's.

use crate::config::Config;
use crate::constants;
use crate::containers::BeaconState;
use crate::error::Result;
use crate::hash::hash;
use crate::preset;
use crate::primitives::{
    Bytes32, CommitteeIndex, Domain, DomainType, Epoch, Gwei, Root, Slot, ValidatorIndex,
};

use super::misc::{
    compute_domain, compute_epoch_at_slot, compute_start_slot_at_epoch, fork_version_at_epoch,
};
use super::predicates::is_active_validator;
use super::shuffling::{compute_committee, compute_proposer_index};

/// The epoch the state is currently in.
pub fn get_current_epoch(state: &BeaconState) -> Epoch {
    compute_epoch_at_slot(state.slot())
}

/// The epoch before the current one, clamped at genesis.
///
/// Clamped rather than allowed to underflow, since the genesis epoch has no
/// predecessor but the reward and justification logic still asks for one.
pub fn get_previous_epoch(state: &BeaconState) -> Epoch {
    let current = get_current_epoch(state);
    if current == constants::GENESIS_EPOCH {
        constants::GENESIS_EPOCH
    } else {
        current - 1
    }
}

/// The block root at a recent slot.
///
/// Fails outside the retained window: the state keeps only
/// `SLOTS_PER_HISTORICAL_ROOT` roots, so asking for an older slot is a fault
/// rather than a miss.
pub fn get_block_root_at_slot(state: &BeaconState, slot: Slot) -> Result<Root> {
    crate::verify(
        slot < state.slot() && state.slot() <= slot + preset::SLOTS_PER_HISTORICAL_ROOT as u64,
        "slot < state.slot <= slot + SLOTS_PER_HISTORICAL_ROOT",
    )?;
    Ok(state.block_roots()[slot as usize % preset::SLOTS_PER_HISTORICAL_ROOT])
}

/// The block root at the start of a recent epoch, which is what a checkpoint
/// names.
pub fn get_block_root(state: &BeaconState, epoch: Epoch) -> Result<Root> {
    get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch))
}

/// The randao mix at a recent epoch.
pub fn get_randao_mix(state: &BeaconState, epoch: Epoch) -> Bytes32 {
    state.randao_mix(epoch)
}

/// The validators active at `epoch`.
pub fn get_active_validator_indices(state: &BeaconState, epoch: Epoch) -> Vec<ValidatorIndex> {
    state
        .validators()
        .iter()
        .enumerate()
        .filter(|(_, validator)| is_active_validator(validator, epoch))
        .map(|(index, _)| index as ValidatorIndex)
        .collect()
}

/// How many validators may enter or leave per epoch.
///
/// Proportional to the active set, with a floor, so that a small chain still
/// makes progress and a large one cannot be turned over quickly enough to
/// threaten finality.
pub fn get_validator_churn_limit(state: &BeaconState, config: &Config) -> u64 {
    let active = get_active_validator_indices(state, get_current_epoch(state)).len() as u64;
    config
        .min_per_epoch_churn_limit
        .max(active / config.churn_limit_quotient)
}

/// The seed for `epoch` and `domain_type`.
///
/// The mix is read from far enough back that the seed for an epoch is fixed
/// before that epoch's committees matter, which is what makes shuffling
/// unpredictable but not manipulable. The specification adds
/// `EPOCHS_PER_HISTORICAL_VECTOR` before subtracting to avoid underflowing near
/// genesis, and this keeps that form.
pub fn get_seed(state: &BeaconState, epoch: Epoch, domain_type: DomainType) -> Bytes32 {
    let lookback =
        epoch + preset::EPOCHS_PER_HISTORICAL_VECTOR as u64 - preset::MIN_SEED_LOOKAHEAD - 1;
    let mix = get_randao_mix(state, lookback);

    let mut input = Vec::with_capacity(4 + 8 + 32);
    input.extend_from_slice(&domain_type);
    input.extend_from_slice(&epoch.to_le_bytes());
    input.extend_from_slice(&mix.0);
    hash(&input)
}

/// How many committees each slot of `epoch` has.
///
/// At least one, so a small chain still produces committees, and at most
/// `MAX_COMMITTEES_PER_SLOT`.
pub fn get_committee_count_per_slot(state: &BeaconState, epoch: Epoch) -> u64 {
    let active = get_active_validator_indices(state, epoch).len() as u64;
    let ideal = active / preset::SLOTS_PER_EPOCH / preset::TARGET_COMMITTEE_SIZE;
    ideal.clamp(1, preset::MAX_COMMITTEES_PER_SLOT as u64)
}

/// The committee at `slot` with index `index`.
///
/// One epoch's active set is shuffled once and then split across every slot and
/// committee of that epoch, so the committee index is a position within that
/// single split rather than an independent draw.
pub fn get_beacon_committee(
    state: &BeaconState,
    slot: Slot,
    index: CommitteeIndex,
) -> Result<Vec<ValidatorIndex>> {
    let epoch = compute_epoch_at_slot(slot);
    let committees_per_slot = get_committee_count_per_slot(state, epoch);
    let indices = get_active_validator_indices(state, epoch);
    let seed = get_seed(state, epoch, constants::DOMAIN_BEACON_ATTESTER);

    compute_committee(
        &indices,
        seed,
        (slot % preset::SLOTS_PER_EPOCH) * committees_per_slot + index,
        committees_per_slot * preset::SLOTS_PER_EPOCH,
    )
}

/// The proposer for the state's current slot.
pub fn get_beacon_proposer_index(state: &BeaconState) -> Result<ValidatorIndex> {
    let epoch = get_current_epoch(state);

    let seed_base = get_seed(state, epoch, constants::DOMAIN_BEACON_PROPOSER);
    let mut input = Vec::with_capacity(40);
    input.extend_from_slice(&seed_base.0);
    input.extend_from_slice(&state.slot().to_le_bytes());
    let seed = hash(&input);

    let indices = get_active_validator_indices(state, epoch);
    compute_proposer_index(&indices, seed, preset::MAX_EFFECTIVE_BALANCE, |index| {
        Ok(state.validator(index)?.effective_balance)
    })
}

/// The combined effective balance of `indices`.
///
/// Floored at one increment so that callers dividing by it cannot divide by zero,
/// which is why the specification defines it this way rather than as a plain sum.
pub fn get_total_balance(state: &BeaconState, indices: &[ValidatorIndex]) -> Result<Gwei> {
    let mut total: Gwei = 0;
    for index in indices {
        total = total.saturating_add(state.validator(*index)?.effective_balance);
    }
    Ok(total.max(preset::EFFECTIVE_BALANCE_INCREMENT))
}

/// The combined effective balance of the currently active validators.
pub fn get_total_active_balance(state: &BeaconState) -> Result<Gwei> {
    let indices = get_active_validator_indices(state, get_current_epoch(state));
    get_total_balance(state, &indices)
}

/// The signing domain for `domain_type` at `epoch`, or at the current epoch when
/// none is given.
pub fn get_domain(state: &BeaconState, domain_type: DomainType, epoch: Option<Epoch>) -> Domain {
    let epoch = epoch.unwrap_or_else(|| get_current_epoch(state));
    let fork_version = fork_version_at_epoch(state.fork(), epoch);
    compute_domain(domain_type, fork_version, state.genesis_validators_root())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn previous_epoch_is_clamped_at_genesis() {
        let mut state = crate::helpers::test_state::with_validators(4);
        *state.slot_mut() = 0;
        assert_eq!(get_previous_epoch(&state), constants::GENESIS_EPOCH);

        *state.slot_mut() = preset::SLOTS_PER_EPOCH * 3;
        assert_eq!(get_previous_epoch(&state), 2);
    }

    #[test]
    fn block_root_outside_the_window_is_an_error() {
        let state = crate::helpers::test_state::with_validators(4);
        // The current slot itself is not retained: the window is strictly past.
        assert!(get_block_root_at_slot(&state, state.slot()).is_err());
        assert!(get_block_root_at_slot(&state, state.slot() - 1).is_ok());
    }

    #[test]
    fn committees_cover_every_active_validator_once_per_epoch() {
        // Across a whole epoch, every active validator must be assigned exactly
        // one committee slot, since the epoch's committees are one permutation
        // split up.
        let count = 64;
        let state = crate::helpers::test_state::with_validators(count);
        let epoch = get_current_epoch(&state);
        let per_slot = get_committee_count_per_slot(&state, epoch);

        let mut all = Vec::new();
        for slot_offset in 0..preset::SLOTS_PER_EPOCH {
            let slot = compute_start_slot_at_epoch(epoch) + slot_offset;
            for index in 0..per_slot {
                all.extend(get_beacon_committee(&state, slot, index).unwrap());
            }
        }
        all.sort_unstable();
        assert_eq!(all, (0..count as u64).collect::<Vec<_>>());
    }

    #[test]
    fn total_balance_is_floored_at_one_increment() {
        // An empty set must not yield zero, since callers divide by this.
        let state = crate::helpers::test_state::with_validators(4);
        assert_eq!(
            get_total_balance(&state, &[]).unwrap(),
            preset::EFFECTIVE_BALANCE_INCREMENT
        );
    }

    #[test]
    fn proposer_is_drawn_from_the_active_set() {
        let state = crate::helpers::test_state::with_validators(32);
        let proposer = get_beacon_proposer_index(&state).unwrap();
        assert!(proposer < 32);
    }

    #[test]
    fn churn_limit_respects_its_floor() {
        let config = Config::mainnet();
        // A tiny validator set falls below the proportional limit, so the floor
        // is what applies.
        let state = crate::helpers::test_state::with_validators(4);
        assert_eq!(
            get_validator_churn_limit(&state, &config),
            config.min_per_epoch_churn_limit
        );
    }
}
