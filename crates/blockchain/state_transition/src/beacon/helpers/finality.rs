//! Epoch-boundary accessors that every fork shares.
//!
//! The specification introduces these under phase0's epoch processing, and no
//! later fork changes them, so both phase0's and altair's reward accounting call
//! the same three functions. They live in `helpers` rather than in either fork's
//! reward module so that neither has to depend on the other: altair's helpers
//! previously reached into phase0's `stf::epoch::rewards` for them, which made
//! `helpers` depend on `stf` where the dependency otherwise runs the other way.

use crate::beacon::containers::BeaconState;
use crate::beacon::error::{Error, Result};
use crate::beacon::preset;
use crate::beacon::primitives::{Epoch, ValidatorIndex};

use super::accessors::get_previous_epoch;
use super::predicates::is_active_validator;

/// How many epochs finality has lagged behind the previous epoch.
///
/// Zero whenever finality is keeping pace with attestation processing; grows
/// by one every further epoch the chain fails to finalize, which is what lets
/// [`is_in_inactivity_leak`] and the inactivity penalty scale with how long the
/// stall has lasted rather than firing at a fixed severity.
///
/// A finalized checkpoint past the previous epoch makes this a `uint64`
/// underflow, which the specification treats as an invalid state transition,
/// so it returns [`Error::ArithmeticOverflow`] rather than wrapping. No chain
/// reaches that state: justification only ever finalizes an epoch already
/// behind the current one.
pub fn get_finality_delay(state: &BeaconState) -> Result<Epoch> {
    get_previous_epoch(state)
        .checked_sub(state.finalized_checkpoint().epoch)
        .ok_or(Error::ArithmeticOverflow(
            "get_previous_epoch(state) - finalized_checkpoint.epoch",
        ))
}

/// Whether the chain has gone long enough without finalizing that inactive
/// validators' balances should start leaking away.
///
/// The leak exists so a large inactive or adversarial minority cannot stall
/// finality forever while keeping its stake intact: the longer finality
/// stalls, the faster an inactive validator's share of the active set shrinks,
/// until the honest, active minority eventually clears the two-thirds
/// threshold on its own.
///
/// Fails wherever [`get_finality_delay`] does.
pub fn is_in_inactivity_leak(state: &BeaconState) -> Result<bool> {
    Ok(get_finality_delay(state)? > preset::MIN_EPOCHS_TO_INACTIVITY_PENALTY)
}

/// Validators whose participation this epoch's rewards and penalties account
/// for: every currently active validator, plus one already exited but not yet
/// past its withdrawable epoch, so a validator that leaves the active set
/// still pays (or earns) whatever this epoch's accounting owes it up to that
/// point.
pub fn get_eligible_validator_indices(state: &BeaconState) -> Vec<ValidatorIndex> {
    let previous_epoch = get_previous_epoch(state);
    state
        .iter_validators()
        .enumerate()
        .filter(|(_, validator)| {
            is_active_validator(validator, previous_epoch)
                || (validator.slashed && previous_epoch + 1 < validator.withdrawable_epoch)
        })
        .map(|(index, _)| index as ValidatorIndex)
        .collect()
}
