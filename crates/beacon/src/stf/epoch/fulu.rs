//! Fulu-specific epoch processing.
//!
//! Electra's whole step list carries over unchanged: fulu's "Epoch processing"
//! section (`beacon-chain.md`) redefines `process_epoch` only to append one new
//! step, [`process_proposer_lookahead`] (EIP-7917), after electra's last one.
//! Nothing about how any existing step behaves changes; the state simply grows
//! one more piece of bookkeeping for [`process_proposer_lookahead`] to
//! maintain.
//!
//! [`process_proposer_lookahead`] keeps `BeaconState::proposer_lookahead`
//! (`crate::containers::fulu::BeaconState`) a fixed-length rolling window: it
//! drops the epoch that just ended (the window's oldest slice) and appends the
//! one epoch further out than the window already reached, so the window keeps
//! covering exactly the current epoch through `MIN_SEED_LOOKAHEAD` epochs
//! beyond it, the same span
//! [`crate::helpers::fulu::initialize_proposer_lookahead`] fills from scratch
//! at genesis and at the fulu upgrade. See that function's module docs for why
//! a seed, and therefore a proposer, is only ever knowable that far ahead and
//! no further.
//!
//! # Why this step runs last
//!
//! The newly-visible epoch's proposers come from
//! [`crate::helpers::fulu::get_beacon_proposer_indices`], which weighs
//! [`crate::helpers::accessors::get_active_validator_indices`] and each
//! validator's `effective_balance`, both of which earlier steps in this same
//! epoch's processing change: [`super::registry::process_registry_updates`]
//! moves validators into or out of the active set, and
//! [`super::process_effective_balance_updates`] moves balances toward their
//! post-epoch values. Running [`process_proposer_lookahead`] after every such
//! step, rather than before, is what lets the newly-appended epoch's proposers
//! reflect this epoch's final registry state rather than a stale one; the
//! specification gets that simply by placing the step last, and this driver
//! does the same.
//!
//! The randao mix the new epoch's seed reads is not why the step sits where it
//! does. [`crate::helpers::accessors::get_seed`]'s lookback means the
//! newly-visible epoch's seed is drawn from the *current*, outgoing epoch's
//! mix, and that mix was already fixed by the last block processed in this
//! epoch, well before epoch processing starts. [`super::process_randao_mixes_reset`]
//! only ever writes the *next* epoch's slot, so running this step before or
//! after that reset would not change which mix the new epoch's seed reads;
//! only the registry and balance state matters for the ordering here.

use crate::config::Config;
use crate::containers::BeaconState;
use crate::error::Result;
use crate::helpers::accessors::get_current_epoch;
use crate::helpers::fulu::{fulu_state, get_beacon_proposer_indices};
use crate::preset;

use super::electra;

/// Fulu's epoch-boundary driver: electra's, unchanged, with
/// [`process_proposer_lookahead`] appended at the end.
pub fn process_epoch(state: &mut BeaconState, config: &Config) -> Result<()> {
    electra::process_epoch(state, config)?;
    process_proposer_lookahead(state)
}

/// Shifts `proposer_lookahead` forward by one epoch.
///
/// Drops the window's first `SLOTS_PER_EPOCH` entries (the epoch that just
/// ended) and appends `SLOTS_PER_EPOCH` more for the epoch that becomes
/// computable now that this epoch's registry and balance updates have run: see
/// the module docs for why appending happens last rather than first.
///
/// The specification writes this as two in-place slice assignments on
/// `state.proposer_lookahead`. This instead builds the whole new window as a
/// plain `Vec` and assigns it back in one piece, since `SszVector` has no
/// `Default` to grow into and its `IndexMut` only ever addresses a window that
/// already exists at its full length; building the replacement value
/// explicitly, at exactly [`preset::PROPOSER_LOOKAHEAD_LENGTH`], sidesteps
/// needing one.
pub fn process_proposer_lookahead(state: &mut BeaconState) -> Result<()> {
    // The seed for this epoch is only just now fixed, per the module docs, so
    // this is the earliest moment its proposers could have been computed.
    let new_epoch = get_current_epoch(state) + preset::MIN_SEED_LOOKAHEAD + 1;
    let new_epoch_proposers = get_beacon_proposer_indices(state, new_epoch)?;

    let fulu_state = fulu_state(state, "process_proposer_lookahead")?;
    let slots_per_epoch = preset::SLOTS_PER_EPOCH as usize;

    let mut window = Vec::with_capacity(preset::PROPOSER_LOOKAHEAD_LENGTH);
    window.extend_from_slice(&fulu_state.proposer_lookahead[slots_per_epoch..]);
    window.extend(new_epoch_proposers);

    fulu_state.proposer_lookahead = window.try_into().expect(
        "dropping SLOTS_PER_EPOCH entries and appending SLOTS_PER_EPOCH more preserves \
         PROPOSER_LOOKAHEAD_LENGTH",
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fork::ForkName;
    use crate::helpers::fulu::initialize_proposer_lookahead;

    /// A fulu state with `count` fully active, full-balance validators and a
    /// `proposer_lookahead` filled by
    /// [`crate::helpers::fulu::initialize_proposer_lookahead`], one epoch past
    /// genesis.
    ///
    /// The shared builder leaves `proposer_lookahead` zeroed, since that
    /// field is fulu-specific and most of this crate's per-fork test states
    /// never touch it; this module's own tests are exactly the ones that do,
    /// so this runs the real computation on top before handing the state
    /// back, the same override
    /// `crate::helpers::fulu::tests::fulu_state_with_validators` applies.
    fn fulu_state_with_validators(count: usize) -> BeaconState {
        let mut state = crate::helpers::test_state::with_validators_at(ForkName::Fulu, count);
        let lookahead = initialize_proposer_lookahead(&state).unwrap();
        if let BeaconState::Fulu(fulu_state) = &mut state {
            fulu_state.proposer_lookahead = lookahead.try_into().expect(
                "initialize_proposer_lookahead returns exactly PROPOSER_LOOKAHEAD_LENGTH indices",
            );
        }
        state
    }

    /// Reads out `proposer_lookahead` for assertions, without exposing the
    /// fork-specific projection to every test.
    fn lookahead_of(state: &BeaconState) -> Vec<crate::primitives::ValidatorIndex> {
        match state {
            BeaconState::Fulu(state) => state.proposer_lookahead.to_vec(),
            _ => unreachable!("test states here are always fulu"),
        }
    }

    #[test]
    fn process_proposer_lookahead_preserves_the_carried_over_slice() {
        let mut state = fulu_state_with_validators(32);
        let before = lookahead_of(&state);

        process_proposer_lookahead(&mut state).unwrap();

        let after = lookahead_of(&state);
        let slots_per_epoch = preset::SLOTS_PER_EPOCH as usize;
        // Everything but the oldest and newest epoch's worth of entries must
        // carry over unchanged, just shifted down by one epoch's length.
        assert_eq!(
            after[..after.len() - slots_per_epoch],
            before[slots_per_epoch..]
        );
    }

    #[test]
    fn process_proposer_lookahead_appends_the_newly_computable_epoch() {
        let state = fulu_state_with_validators(32);
        let current_epoch = get_current_epoch(&state);
        let new_epoch = current_epoch + preset::MIN_SEED_LOOKAHEAD + 1;
        let expected = get_beacon_proposer_indices(&state, new_epoch).unwrap();

        let mut state = state;
        process_proposer_lookahead(&mut state).unwrap();

        let after = lookahead_of(&state);
        let slots_per_epoch = preset::SLOTS_PER_EPOCH as usize;
        assert_eq!(after[after.len() - slots_per_epoch..], expected[..]);
    }

    #[test]
    fn process_proposer_lookahead_keeps_the_window_at_its_fixed_length() {
        let mut state = fulu_state_with_validators(32);
        process_proposer_lookahead(&mut state).unwrap();
        assert_eq!(
            lookahead_of(&state).len(),
            preset::PROPOSER_LOOKAHEAD_LENGTH
        );
    }

    #[test]
    fn process_proposer_lookahead_rejects_a_state_older_than_fulu() {
        let mut phase0_state = crate::helpers::test_state::with_validators(4);
        assert!(process_proposer_lookahead(&mut phase0_state).is_err());
    }
}
