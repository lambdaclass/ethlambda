//! Justification and finalization.
//!
//! Every epoch, the state re-weighs how much of the active balance attested to
//! the previous and current epoch's checkpoint and folds the result into
//! `justification_bits`, a four-epoch sliding window recording which of the
//! last four epochs reached the two-thirds threshold. Finalization then checks
//! that window for one of two shapes: two consecutively-justified epochs, or
//! three, with the extra epoch of slack existing so a single epoch that narrowly
//! misses justification does not also cost the chain finality for the epoch
//! before it. Each shape is checked from both the previous and the current
//! epoch's justified checkpoint, which is why there are four rules rather than
//! two.

use crate::config::Config;
use crate::constants;
use crate::containers::{BeaconState, Checkpoint};
use crate::error::{Error, Result};
use crate::helpers::accessors::{
    get_block_root, get_current_epoch, get_previous_epoch, get_total_active_balance,
};
use crate::primitives::Gwei;

use super::{JUSTIFICATION_BITS, get_attesting_balance, get_matching_target_attestations};

/// Updates justification and finality from the attestations the previous and
/// current epoch collected.
///
/// `config` is unused: this step needs no configuration value, but takes one
/// anyway so every step in [`super::process_epoch`]'s pipeline shares a call
/// shape.
pub fn process_justification_and_finalization(
    state: &mut BeaconState,
    _config: &Config,
) -> Result<()> {
    // Initial FFG checkpoint values have a `0x00` stub for `root`.
    // Skip FFG updates in the first two epochs to avoid corner cases that might
    // result in modifying this stub.
    if get_current_epoch(state) <= constants::GENESIS_EPOCH + 1 {
        return Ok(());
    }

    let previous_attestations = get_matching_target_attestations(state, get_previous_epoch(state))?;
    let current_attestations = get_matching_target_attestations(state, get_current_epoch(state))?;
    let total_active_balance = get_total_active_balance(state)?;
    let previous_target_balance = get_attesting_balance(state, &previous_attestations)?;
    let current_target_balance = get_attesting_balance(state, &current_attestations)?;
    weigh_justification_and_finalization(
        state,
        total_active_balance,
        previous_target_balance,
        current_target_balance,
    )
}

/// Advances the justification bitfield and applies the four finalization rules
/// against it.
///
/// The target balances are passed in rather than recomputed here so this can be
/// exercised (and reasoned about) independently of attestation matching, which
/// is what [`process_justification_and_finalization`] uses it for.
pub fn weigh_justification_and_finalization(
    state: &mut BeaconState,
    total_active_balance: Gwei,
    previous_epoch_target_balance: Gwei,
    current_epoch_target_balance: Gwei,
) -> Result<()> {
    let previous_epoch = get_previous_epoch(state);
    let current_epoch = get_current_epoch(state);
    let old_previous_justified_checkpoint = state.previous_justified_checkpoint();
    let old_current_justified_checkpoint = state.current_justified_checkpoint();

    // Process justifications
    *state.previous_justified_checkpoint_mut() = state.current_justified_checkpoint();

    // Age the bitfield by one epoch before folding in this epoch's result. Index
    // 0 always names the epoch just processed, so ageing moves every bit toward
    // a HIGHER index (older epochs); the oldest bit falls off the top and is
    // lost. Reading index `i - 1` before writing index `i`, from the top down,
    // reproduces the spec's simultaneous slice assignment without a temporary
    // copy.
    for i in (1..JUSTIFICATION_BITS).rev() {
        let older = state
            .justification_bits()
            .get(i - 1)
            .expect("index is within JUSTIFICATION_BITS_LENGTH");
        state
            .justification_bits_mut()
            .set(i, older)
            .expect("index is within JUSTIFICATION_BITS_LENGTH");
    }
    state
        .justification_bits_mut()
        .set(0, false)
        .expect("index is within JUSTIFICATION_BITS_LENGTH");

    if meets_justification_threshold(previous_epoch_target_balance, total_active_balance)? {
        *state.current_justified_checkpoint_mut() = Checkpoint {
            epoch: previous_epoch,
            root: get_block_root(state, previous_epoch)?,
        };
        state
            .justification_bits_mut()
            .set(1, true)
            .expect("index is within JUSTIFICATION_BITS_LENGTH");
    }
    if meets_justification_threshold(current_epoch_target_balance, total_active_balance)? {
        *state.current_justified_checkpoint_mut() = Checkpoint {
            epoch: current_epoch,
            root: get_block_root(state, current_epoch)?,
        };
        state
            .justification_bits_mut()
            .set(0, true)
            .expect("index is within JUSTIFICATION_BITS_LENGTH");
    }

    // Process finalizations
    //
    // Read every bit the four rules need before touching `finalized_checkpoint`,
    // since holding a `&JustificationBits` borrow across those writes would
    // conflict with the `&mut BeaconState` each rule needs.
    let (justifies_1_2_3, justifies_1_2, justifies_0_1_2, justifies_0_1) = {
        let bits = state.justification_bits();
        let bit = |i: usize| {
            bits.get(i)
                .expect("index is within JUSTIFICATION_BITS_LENGTH")
        };
        (
            bit(1) && bit(2) && bit(3),
            bit(1) && bit(2),
            bit(0) && bit(1) && bit(2),
            bit(0) && bit(1),
        )
    };

    // The 2nd/3rd/4th most recent epochs are justified, the 2nd using the 4th as source
    if justifies_1_2_3 && old_previous_justified_checkpoint.epoch + 3 == current_epoch {
        *state.finalized_checkpoint_mut() = old_previous_justified_checkpoint;
    }
    // The 2nd/3rd most recent epochs are justified, the 2nd using the 3rd as source
    if justifies_1_2 && old_previous_justified_checkpoint.epoch + 2 == current_epoch {
        *state.finalized_checkpoint_mut() = old_previous_justified_checkpoint;
    }
    // The 1st/2nd/3rd most recent epochs are justified, the 1st using the 3rd as source
    if justifies_0_1_2 && old_current_justified_checkpoint.epoch + 2 == current_epoch {
        *state.finalized_checkpoint_mut() = old_current_justified_checkpoint;
    }
    // The 1st/2nd most recent epochs are justified, the 1st using the 2nd as source
    if justifies_0_1 && old_current_justified_checkpoint.epoch + 1 == current_epoch {
        *state.finalized_checkpoint_mut() = old_current_justified_checkpoint;
    }

    Ok(())
}

/// Whether `balance` covers at least two-thirds of `total_active_balance`.
///
/// Written as `balance * 3 >= total_active_balance * 2` to avoid a division,
/// matching the specification exactly. `total_active_balance` sums the whole
/// validator registry, so its product is checked rather than left to wrap: a
/// wrapped comparison could manufacture or hide a justification that the real
/// balances never earned.
fn meets_justification_threshold(balance: Gwei, total_active_balance: Gwei) -> Result<bool> {
    let weighed_balance = balance.checked_mul(3).ok_or(Error::ArithmeticOverflow(
        "weigh_justification_and_finalization",
    ))?;
    let weighed_total = total_active_balance
        .checked_mul(2)
        .ok_or(Error::ArithmeticOverflow(
            "weigh_justification_and_finalization",
        ))?;
    Ok(weighed_balance >= weighed_total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn near_genesis_process_is_a_no_op() {
        // `with_validators` positions the state at slot `SLOTS_PER_EPOCH`, i.e.
        // current epoch 1, which is still within the `GENESIS_EPOCH + 1` guard.
        let mut state = crate::helpers::test_state::with_validators(4);
        let before = state.clone();
        let config = Config::mainnet();

        process_justification_and_finalization(&mut state, &config).unwrap();

        assert_eq!(
            state.justification_bits(),
            before.justification_bits(),
            "the bitfield must be untouched this close to genesis"
        );
        assert_eq!(
            state.current_justified_checkpoint(),
            before.current_justified_checkpoint()
        );
        assert_eq!(state.finalized_checkpoint(), before.finalized_checkpoint());
    }

    #[test]
    fn only_the_previous_epoch_bit_is_set_when_only_it_justifies() {
        // `with_validators` positions the state at current epoch 1, previous
        // epoch 0, which is enough to exercise `weigh_justification_and_finalization`
        // directly without needing to build real attestations: it takes the
        // target balances as arguments.
        let mut state = crate::helpers::test_state::with_validators(4);
        let total_active_balance: Gwei = 300;
        let previous_epoch_target_balance: Gwei = 200; // exactly two-thirds: justifies
        let current_epoch_target_balance: Gwei = 0; // nowhere near: does not justify

        weigh_justification_and_finalization(
            &mut state,
            total_active_balance,
            previous_epoch_target_balance,
            current_epoch_target_balance,
        )
        .unwrap();

        let bits = state.justification_bits();
        assert_eq!(bits.get(0), Some(false), "current epoch did not justify");
        assert_eq!(bits.get(1), Some(true), "previous epoch justified");
        assert_eq!(bits.get(2), Some(false));
        assert_eq!(bits.get(3), Some(false));

        assert_eq!(state.current_justified_checkpoint().epoch, 0);
        // Only one epoch justified this round, so none of the four finalization
        // rules (each needing two or three consecutive justified epochs) fire.
        assert_eq!(state.finalized_checkpoint().epoch, constants::GENESIS_EPOCH);
    }

    #[test]
    fn a_below_threshold_balance_justifies_neither_epoch() {
        let mut state = crate::helpers::test_state::with_validators(4);
        let total_active_balance: Gwei = 300;

        weigh_justification_and_finalization(&mut state, total_active_balance, 199, 199).unwrap();

        let bits = state.justification_bits();
        assert_eq!(bits.get(0), Some(false));
        assert_eq!(bits.get(1), Some(false));
    }

    #[test]
    fn an_overflowing_balance_is_reported_rather_than_wrapped() {
        let mut state = crate::helpers::test_state::with_validators(4);

        let result = weigh_justification_and_finalization(&mut state, Gwei::MAX, Gwei::MAX, 0);

        assert!(matches!(result, Err(Error::ArithmeticOverflow(_))));
    }
}
