//! Incremental unslashed TIMELY_TARGET balances.
//!
//! `compute_pulled_up_tip` weighs justification for every imported block, and
//! the weighing needs the balance that cast a timely target vote in the
//! previous and current epoch. Summing it is a pass over the whole registry
//! ([`ParticipationTotals::compute_raw_target`]); this module makes the common
//! case O(block) instead, the way Lighthouse's `ProgressiveBalancesCache`
//! does, with the totals held by block root in
//! [`ethlambda_storage::TargetBalanceCache`].
//!
//! # Why a parent's totals plus the block's delta is exact
//!
//! Within one epoch a validator's contribution to either total can only change
//! three ways:
//!
//! 1. Its TIMELY_TARGET flag goes from unset to set. Only `process_attestation`
//!    writes participation flags during block processing (the sync aggregate,
//!    withdrawals, deposits, the execution requests and gloas's builder and
//!    payload operations touch balances, queues and exit epochs, never a
//!    flag), and [`TargetBalanceDelta::record_new_target`] is called from every
//!    fork's copy of it.
//! 2. Its effective balance changes. Only `process_effective_balance_updates`
//!    writes one, at an epoch boundary, plus `upgrade_to_electra` zeroing
//!    never-activated validators, also at a boundary. Deposits append
//!    validators that are not active in the previous or current epoch (an
//!    activation epoch is always assigned in the future), so a new entry never
//!    contributes.
//! 3. It is slashed, which removes it from the unslashed total.
//!    `slash_validator` is reachable only through a block's proposer and
//!    attester slashings, so [`block_has_slashings`] sends such a block to the
//!    full scan instead of threading a second accumulator through them. Rare
//!    enough that the scan costs nothing on average.
//!
//! Which validators are counted cannot change either: membership needs
//! "active in the epoch", and exits only assign future exit epochs.
//!
//! So a block whose parent's post-state shares its epoch (no `process_slots`
//! epoch boundary crossed) has exactly the parent's totals plus the delta. At a
//! boundary, on a cache miss, after a restart, or for a block with slashings,
//! the totals are computed in full once and cached.
//!
//! The first two epochs are skipped entirely: justification does not run
//! there, and the previous and current epoch coincide at genesis, where the
//! scan reads the current list for both.

use std::sync::atomic::{AtomicU64, Ordering};

use ethlambda_storage::{TargetBalanceCache, TargetBalances};

use crate::beacon::containers::BeaconState;
use crate::beacon::containers::SignedBeaconBlock;
use crate::beacon::error::Result;
use crate::beacon::primitives::{Epoch, Gwei, Root};

use super::accessors::get_current_epoch;
use super::participation::ParticipationTotals;

/// What one block's attestations added to the previous and current epoch's
/// unslashed TIMELY_TARGET balance.
///
/// Written by `process_attestation` through a shared reference (hence the
/// atomics, relaxed since one thread writes), so it can ride in
/// [`BlockProcessingOptions`](crate::beacon::stf::block::BlockProcessingOptions),
/// which is `Copy`, and keep that type `Send` for the async block producers.
#[derive(Debug, Default)]
pub struct TargetBalanceDelta {
    previous: AtomicU64,
    current: AtomicU64,
}

impl PartialEq for TargetBalanceDelta {
    fn eq(&self, other: &Self) -> bool {
        self.previous() == other.previous() && self.current() == other.current()
    }
}

impl Eq for TargetBalanceDelta {}

impl TargetBalanceDelta {
    /// Records that a validator with `effective_balance` just earned
    /// TIMELY_TARGET in the current or previous epoch's participation. A
    /// `slashed` validator is not counted, as the specification's unslashed
    /// participating set excludes it.
    ///
    /// Takes the two fields rather than the validator, so the caller, which
    /// has already read the validator for the reward, does not descend the
    /// registry a second time.
    pub fn record_new_target(
        &self,
        current_epoch_target: bool,
        effective_balance: Gwei,
        slashed: bool,
    ) {
        if slashed {
            return;
        }
        let side = if current_epoch_target {
            &self.current
        } else {
            &self.previous
        };
        let total = side
            .load(Ordering::Relaxed)
            .saturating_add(effective_balance);
        side.store(total, Ordering::Relaxed);
    }

    /// The balance added to the previous epoch's total.
    pub fn previous(&self) -> Gwei {
        self.previous.load(Ordering::Relaxed)
    }

    /// The balance added to the current epoch's total.
    pub fn current(&self) -> Gwei {
        self.current.load(Ordering::Relaxed)
    }

    /// `parent` plus this delta, for the block's own epoch.
    fn applied_to(&self, parent: TargetBalances) -> TargetBalances {
        TargetBalances {
            epoch: parent.epoch,
            previous: parent.previous.saturating_add(self.previous()),
            current: parent.current.saturating_add(self.current()),
        }
    }
}

/// Whether justification weighs target balances for a state in `epoch`; the
/// totals are only maintained where they are read.
pub fn tracks_epoch(epoch: Epoch) -> bool {
    epoch > crate::beacon::constants::GENESIS_EPOCH + 1
}

/// The totals of `state` from one scan of the registry.
///
/// Fails like [`ParticipationTotals::compute`]. Phase0 states have no
/// participation flags and fail through `altair_validator_lists`.
pub fn compute_target_balances(state: &BeaconState) -> Result<TargetBalances> {
    let (previous, current) = ParticipationTotals::compute_raw_target(state)?;
    Ok(TargetBalances {
        epoch: get_current_epoch(state),
        previous,
        current,
    })
}

/// The block's post-state totals when its parent's are cached for the same
/// epoch: the parent's plus `delta`. `None` means the caller must scan.
///
/// `block_epoch` is the epoch of the block's slot. An entry for a different
/// epoch means `process_slots` crossed a boundary between parent and block,
/// where effective balances and the participation lists changed.
pub fn extend_parent_totals(
    cache: &TargetBalanceCache,
    parent_root: &Root,
    block_epoch: Epoch,
    delta: &TargetBalanceDelta,
) -> Option<TargetBalances> {
    let parent = cache.get(parent_root)?;
    (parent.epoch == block_epoch && tracks_epoch(block_epoch)).then(|| delta.applied_to(parent))
}

/// Whether the block carries an operation that slashes a validator; see the
/// module documentation for why such a block is not extended incrementally.
pub fn block_has_slashings(block: &SignedBeaconBlock) -> bool {
    match block {
        SignedBeaconBlock::Phase0(b) => {
            !b.message.body.proposer_slashings.is_empty()
                || !b.message.body.attester_slashings.is_empty()
        }
        SignedBeaconBlock::Altair(b) => {
            !b.message.body.proposer_slashings.is_empty()
                || !b.message.body.attester_slashings.is_empty()
        }
        SignedBeaconBlock::Bellatrix(b) => {
            !b.message.body.proposer_slashings.is_empty()
                || !b.message.body.attester_slashings.is_empty()
        }
        SignedBeaconBlock::Capella(b) => {
            !b.message.body.proposer_slashings.is_empty()
                || !b.message.body.attester_slashings.is_empty()
        }
        SignedBeaconBlock::Deneb(b) => {
            !b.message.body.proposer_slashings.is_empty()
                || !b.message.body.attester_slashings.is_empty()
        }
        SignedBeaconBlock::Electra(b) | SignedBeaconBlock::Fulu(b) => {
            !b.message.body.proposer_slashings.is_empty()
                || !b.message.body.attester_slashings.is_empty()
        }
        SignedBeaconBlock::Gloas(b) => {
            !b.message.body.proposer_slashings.is_empty()
                || !b.message.body.attester_slashings.is_empty()
        }
        // Not a Beacon Chain block: nothing here ever carries one.
        SignedBeaconBlock::Lean(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_delta_skips_slashed_validators_and_splits_by_epoch() {
        let delta = TargetBalanceDelta::default();
        delta.record_new_target(false, 32, false);
        delta.record_new_target(true, 16, false);
        delta.record_new_target(true, 64, true);
        assert_eq!((delta.previous(), delta.current()), (32, 16));
    }

    #[test]
    fn a_parent_is_extended_only_within_its_own_tracked_epoch() {
        let cache = TargetBalanceCache::default();
        let parent = Root::repeat_byte(1);
        let totals = TargetBalances {
            epoch: 5,
            previous: 100,
            current: 10,
        };
        cache.insert(parent, totals);
        let delta = TargetBalanceDelta::default();
        delta.record_new_target(true, 7, false);

        let extended = extend_parent_totals(&cache, &parent, 5, &delta).unwrap();
        assert_eq!((extended.previous, extended.current), (100, 17));
        assert_eq!(extend_parent_totals(&cache, &parent, 6, &delta), None);
        assert_eq!(
            extend_parent_totals(&cache, &Root::repeat_byte(2), 5, &delta),
            None
        );

        let early = Root::repeat_byte(3);
        cache.insert(early, TargetBalances { epoch: 1, ..totals });
        assert_eq!(extend_parent_totals(&cache, &early, 1, &delta), None);
    }
}
