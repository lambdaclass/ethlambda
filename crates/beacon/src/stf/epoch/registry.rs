//! Registry updates and slashings.
//!
//! Both functions walk the whole validator registry once per epoch: the first
//! moves validators between activation and exit states, the second applies the
//! deferred part of a slashing penalty.

use crate::config::Config;
use crate::containers::BeaconState;
use crate::error::{Error, Result};
use crate::fork::ForkName;
use crate::helpers::accessors::{
    get_current_epoch, get_total_active_balance, get_validator_churn_limit,
};
use crate::helpers::misc::compute_activation_exit_epoch;
use crate::helpers::mutators::{decrease_balance, initiate_validator_exit};
use crate::helpers::predicates::{
    is_active_validator, is_eligible_for_activation, is_eligible_for_activation_queue,
};
use crate::preset;
use crate::primitives::{Epoch, Gwei, ValidatorIndex};

/// The cap on how many validators may newly activate this epoch.
///
/// Phase0 through capella cap activations only indirectly, as part of the
/// combined activation/exit churn limit ([`get_validator_churn_limit`]).
/// Deneb adds a second, independent ceiling on activations specifically
/// (EIP-7514, `MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT` in [`Config`]), so that a
/// single epoch's whole churn budget cannot be spent activating new
/// validators and leave none of it for the exits already in flight.
///
/// Electra replaces [`process_registry_updates`] wholesale with a
/// balance-denominated version (`get_balance_churn_limit`), which belongs to
/// whichever module implements electra rather than here, and the
/// specification never revives a validator-count churn limit for fulu after
/// that. Calling this for electra or fulu would silently apply deneb's rule
/// where the specification no longer has one at all, so both are refused
/// outright rather than guessed at; see [`process_registry_updates`]'s own
/// documentation for exactly which forks that leaves this serving.
fn activation_churn_limit(state: &BeaconState, config: &Config) -> Result<u64> {
    let churn_limit = get_validator_churn_limit(state, config);
    match state.fork_name() {
        ForkName::Phase0 | ForkName::Altair | ForkName::Bellatrix | ForkName::Capella => {
            Ok(churn_limit)
        }
        ForkName::Deneb => Ok(config.max_per_epoch_activation_churn_limit.min(churn_limit)),
        fork @ (ForkName::Electra | ForkName::Fulu) => Err(Error::UnsupportedForFork {
            function: "process_registry_updates",
            fork,
        }),
        ForkName::Lean => unreachable!(
            "lean state reached a beacon accessor (activation_churn_limit); \
             BlockChainServer must dispatch on fork_name() before this point"
        ),
    }
}

/// Moves validators between activation and exit states.
///
/// Three passes, and the order between them matters. The first marks
/// validators newly eligible for the activation queue and starts exiting
/// anyone whose balance has fallen to the ejection floor; both checks read the
/// registry as it stood at the start of the epoch, before either pass changes
/// anything. The second builds the activation queue from eligibility as it
/// stands after that pass, so a validator ejected and a validator freshly
/// eligible in the same epoch are both accounted for before anyone activates.
///
/// One copy of this function serves phase0 through deneb. Deneb's own change
/// (EIP-7514) is confined to which cap the third pass dequeues against, so it
/// is selected by fork through [`activation_churn_limit`] rather than
/// duplicating the three passes around it, the same reuse-by-value pattern
/// [`super::process_slashings`] already uses for its own per-fork multiplier.
/// Electra redefines every pass, not just the cap, so it is a wholly separate
/// function the crate's electra module owns, and fulu never revives a
/// validator-count rule after that; [`activation_churn_limit`] refuses to run
/// for either, so this function does too, rather than letting an electra or
/// fulu state silently activate validators under deneb's superseded rule.
pub fn process_registry_updates(state: &mut BeaconState, config: &Config) -> Result<()> {
    let current_epoch = get_current_epoch(state);
    let validator_count = state.validators().len() as ValidatorIndex;

    // `initiate_validator_exit` itself scans every validator's exit epoch to
    // find the queue's current tail, which needs `state` uncommitted to any
    // other borrow. Collecting the indices first, rather than calling it from
    // inside a loop that also holds a reference into the registry, is what
    // keeps that scan free to run.
    let mut to_eject = Vec::new();
    for index in 0..validator_count {
        if is_eligible_for_activation_queue(state.validator(index)?) {
            state.validator_mut(index)?.activation_eligibility_epoch = current_epoch + 1;
        }

        let validator = state.validator(index)?;
        if is_active_validator(validator, current_epoch)
            && validator.effective_balance <= config.ejection_balance
        {
            to_eject.push(index);
        }
    }
    for index in to_eject {
        initiate_validator_exit(state, index, config)?;
    }

    // Queue validators eligible for activation and not yet dequeued. The sort
    // key pairs the eligibility epoch with the validator index so that two
    // validators becoming eligible in the same epoch still activate in the
    // same order on every client, rather than in whatever order the registry
    // happens to store them.
    let finalized_epoch = state.finalized_checkpoint().epoch;
    let mut activation_queue: Vec<ValidatorIndex> = (0..validator_count)
        .filter(|&index| {
            is_eligible_for_activation(
                state
                    .validator(index)
                    .expect("index is within the registry"),
                finalized_epoch,
            )
        })
        .collect();
    activation_queue.sort_by_key(|&index| {
        let validator = state
            .validator(index)
            .expect("index is within the registry");
        (validator.activation_eligibility_epoch, index)
    });

    // Dequeue validators for activation up to the churn limit.
    let churn_limit = activation_churn_limit(state, config)? as usize;
    let activation_epoch = compute_activation_exit_epoch(current_epoch);
    for &index in activation_queue.iter().take(churn_limit) {
        state.validator_mut(index)?.activation_epoch = activation_epoch;
    }

    Ok(())
}

/// Applies the deferred part of every slashing whose penalty falls due this
/// epoch.
///
/// `slash_validator` only takes an immediate cut of the slashed validator's
/// balance; the rest is scaled by how much of the whole active balance was
/// slashed in the surrounding window and applied here, `EPOCHS_PER_SLASHINGS_VECTOR`
/// divided by two after the offence. Scaling by the fraction of the registry
/// slashed together is what makes a coordinated attack cost far more per
/// validator than an isolated slashable mistake.
///
/// Takes `config` only to match the signature every other step of
/// [`super::process_epoch`]'s pipeline is called with; the specification's
/// version of this function takes no configuration, since the multiplier and
/// the slashings window are both presets, not chain configuration.
///
/// One copy of this function serves phase0 through deneb. Altair and
/// bellatrix each raise the proportional multiplier and nothing else, which
/// the specification expresses by redefining the whole function around a new
/// constant; here the value is selected by fork through [`preset::retuned`]
/// instead, the same reuse-by-value pattern [`process_registry_updates`] uses
/// for its own deneb-only change.
///
/// Electra (EIP-7251) is not another multiplier swap: it restructures the
/// division itself, so this copy stops being correct there. Where this
/// function divides `effective_balance_increments * adjusted_total_slashing_balance`
/// by the raw `total_balance` and multiplies the result back up by
/// `increment` at the end, electra's version divides
/// `adjusted_total_slashing_balance` by `total_balance / increment` once, up
/// front, and multiplies that shared quotient by each validator's own
/// `effective_balance_increments` instead. The two orders are not equivalent
/// under integer division, and electra's own copy in
/// [`super::electra::process_slashings`] is where that difference is worked
/// through with a concrete example; fulu never mentions this function again,
/// so it reuses electra's copy the same way it reuses everything else electra
/// last redefined.
pub fn process_slashings(state: &mut BeaconState, _config: &Config) -> Result<()> {
    let epoch = get_current_epoch(state);
    let total_balance = get_total_active_balance(state)?;

    let mut slashed_sum: Gwei = 0;
    for &slashing in state.slashings().iter() {
        slashed_sum = slashed_sum
            .checked_add(slashing)
            .ok_or(Error::ArithmeticOverflow("summing the slashings vector"))?;
    }
    let multiplier = preset::retuned::proportional_slashing_multiplier(state.fork_name());
    let scaled_slashings = slashed_sum
        .checked_mul(multiplier)
        .ok_or(Error::ArithmeticOverflow(
            "scaling the summed slashings by the proportional multiplier",
        ))?;
    let adjusted_total_slashing_balance = scaled_slashings.min(total_balance);

    let withdrawable_offset = (preset::EPOCHS_PER_SLASHINGS_VECTOR / 2) as Epoch;

    // Collecting the penalties before applying any of them keeps this pass
    // reading a stable registry: `decrease_balance` only touches the balances
    // vector, not the validator being read here, but every other mutator in
    // this module needs the same shape, so this one follows suit.
    let mut penalties = Vec::new();
    for (index, validator) in state.validators().iter().enumerate() {
        if validator.slashed && epoch + withdrawable_offset == validator.withdrawable_epoch {
            // Factored out from the penalty numerator to avoid a `uint64`
            // overflow, exactly as the specification does; multiplying before
            // dividing (rather than the algebraically equivalent other order)
            // is what reproduces the specification's integer rounding.
            let increment = preset::EFFECTIVE_BALANCE_INCREMENT;
            let penalty_numerator = (validator.effective_balance / increment)
                .checked_mul(adjusted_total_slashing_balance)
                .ok_or(Error::ArithmeticOverflow(
                    "computing a validator's slashing penalty numerator",
                ))?;
            let penalty = penalty_numerator / total_balance * increment;
            penalties.push((index as ValidatorIndex, penalty));
        }
    }

    for (index, penalty) in penalties {
        decrease_balance(state, index, penalty)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::FAR_FUTURE_EPOCH;

    /// A deneb state with `count` fully active, full-balance validators,
    /// positioned one epoch in, the same shape
    /// [`crate::helpers::test_state::with_validators`] builds for phase0.
    ///
    /// A thin wrapper around the shared fork-parameterised builder: see
    /// [`crate::helpers::test_state::with_validators_at`] for the construction
    /// this and every other fork's test module used to duplicate.
    fn deneb_state_with_validators(count: usize) -> BeaconState {
        crate::helpers::test_state::with_validators_at(ForkName::Deneb, count)
    }

    /// Deneb's EIP-7514 cap must bind even when the plain validator-count
    /// churn limit alone would let more validators through: enough of these
    /// validators are already active that [`get_validator_churn_limit`]
    /// exceeds [`Config::max_per_epoch_activation_churn_limit`], so a state
    /// still running phase0's rule would activate more of the queued
    /// validators below than deneb's is allowed to.
    #[test]
    fn deneb_caps_activation_churn_below_the_validator_count_limit() {
        let config = Config::minimal();
        let active_count = 200;
        let queued_count = 10;
        let mut state = deneb_state_with_validators(active_count + queued_count);

        // Everyone from `active_count` on is eligible for activation but not
        // yet active; everyone before them already is, active from genesis
        // by `deneb_state_with_validators`'s own construction.
        for index in active_count..(active_count + queued_count) {
            let validator = state.validator_mut(index as ValidatorIndex).unwrap();
            validator.activation_epoch = FAR_FUTURE_EPOCH;
            validator.activation_eligibility_epoch = 0;
        }

        let churn_limit = get_validator_churn_limit(&state, &config);
        assert!(
            churn_limit > config.max_per_epoch_activation_churn_limit,
            "the active set must be large enough that the plain churn limit \
             alone exceeds deneb's cap, or this test is not exercising it"
        );
        assert_eq!(
            activation_churn_limit(&state, &config).unwrap(),
            config.max_per_epoch_activation_churn_limit,
            "the smaller of the two limits must win"
        );

        process_registry_updates(&mut state, &config).unwrap();

        let activated = (active_count..(active_count + queued_count))
            .filter(|&index| {
                state
                    .validator(index as ValidatorIndex)
                    .unwrap()
                    .activation_epoch
                    != FAR_FUTURE_EPOCH
            })
            .count();
        assert_eq!(
            activated, config.max_per_epoch_activation_churn_limit as usize,
            "only the deneb cap's worth of queued validators should have activated this epoch"
        );
    }

    /// Validators becoming eligible for activation in the same epoch must
    /// dequeue in index order, since every client has to agree on which ones
    /// take the churn limit's few slots.
    #[test]
    fn activation_ordering_breaks_ties_by_validator_index() {
        let config = Config::mainnet();
        // None of these validators are active yet, so the churn limit is the
        // configured floor rather than a share of the active set. A few more
        // candidates than that floor leaves some outside the queue.
        let count = config.min_per_epoch_churn_limit as usize + 2;
        let mut state = crate::helpers::test_state::with_validators(count);

        // Every validator becomes eligible for activation in the same epoch,
        // but the churn limit does not admit all of them.
        for index in 0..count as ValidatorIndex {
            let validator = state.validator_mut(index).unwrap();
            validator.activation_eligibility_epoch = 0;
            validator.activation_epoch = FAR_FUTURE_EPOCH;
        }
        let churn_limit = get_validator_churn_limit(&state, &config);
        assert_eq!(churn_limit, config.min_per_epoch_churn_limit);
        assert!((churn_limit as usize) < count);

        process_registry_updates(&mut state, &config).unwrap();

        for index in 0..churn_limit {
            assert_ne!(
                state.validator(index).unwrap().activation_epoch,
                FAR_FUTURE_EPOCH,
                "validator {index} is within the churn limit and should have activated",
            );
        }
        for index in churn_limit..count as ValidatorIndex {
            assert_eq!(
                state.validator(index).unwrap().activation_epoch,
                FAR_FUTURE_EPOCH,
                "validator {index} is past the churn limit and should still be queued",
            );
        }
    }

    /// A validator whose effective balance has fallen to the ejection floor
    /// must be moved into the exit queue, even though nothing else about it
    /// changed.
    #[test]
    fn a_validator_at_the_ejection_balance_is_queued_to_exit() {
        let config = Config::mainnet();
        let mut state = crate::helpers::test_state::with_validators(4);
        state.validator_mut(2).unwrap().effective_balance = config.ejection_balance;

        process_registry_updates(&mut state, &config).unwrap();

        assert_ne!(state.validator(2).unwrap().exit_epoch, FAR_FUTURE_EPOCH);
    }

    /// A validator just above the ejection floor is untouched.
    #[test]
    fn a_validator_above_the_ejection_balance_stays_active() {
        let config = Config::mainnet();
        let mut state = crate::helpers::test_state::with_validators(4);
        state.validator_mut(2).unwrap().effective_balance = config.ejection_balance + 1;

        process_registry_updates(&mut state, &config).unwrap();

        assert_eq!(state.validator(2).unwrap().exit_epoch, FAR_FUTURE_EPOCH);
    }

    /// A freshly slashed validator is not due a deferred penalty yet: the
    /// window has not elapsed, so this epoch must leave its balance alone.
    #[test]
    fn slashings_outside_the_withdrawable_window_are_untouched() {
        let config = Config::mainnet();
        let mut state = crate::helpers::test_state::with_validators(4);
        let balance_before = state.balance(1).unwrap();

        state.validator_mut(1).unwrap().slashed = true;
        state.slashings_mut()[0] = preset::MAX_EFFECTIVE_BALANCE;

        process_slashings(&mut state, &config).unwrap();

        assert_eq!(state.balance(1).unwrap(), balance_before);
    }

    /// Once the withdrawable epoch arrives, the deferred penalty is applied,
    /// scaled up by the whole slashed balance recorded in the window.
    #[test]
    fn a_slashing_due_this_epoch_reduces_the_balance() {
        let config = Config::mainnet();
        let mut state = crate::helpers::test_state::with_validators(4);
        let epoch = get_current_epoch(&state);
        let balance_before = state.balance(1).unwrap();

        let validator = state.validator_mut(1).unwrap();
        validator.slashed = true;
        validator.withdrawable_epoch = epoch + (preset::EPOCHS_PER_SLASHINGS_VECTOR / 2) as Epoch;
        state.slashings_mut()[0] = preset::MAX_EFFECTIVE_BALANCE;

        process_slashings(&mut state, &config).unwrap();

        assert!(state.balance(1).unwrap() < balance_before);
    }
}
