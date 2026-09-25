//! [`EpochCommittees`]: one epoch's committees, already shuffled and sliced.
//!
//! The type lives here, in `ethlambda-types`, rather than in
//! `ethlambda-state-transition` where it used to, because `ethlambda-storage`'s
//! committee cache needs to name the type it caches, and the dependency only
//! runs one way: storage depends on types, state transition depends on
//! storage, so storage cannot depend on state transition. Deriving one of
//! these from a `BeaconState` needs the shuffle computation
//! (`get_active_validator_indices`, `get_seed`, `shuffle_list`), which stays
//! in `ethlambda-state-transition`; see that crate's
//! `beacon::helpers::accessors::build_epoch_committees`, this type's only
//! real constructor outside tests.

use crate::beacon::error::{Error, Result, verify};
use crate::beacon::preset;
use crate::beacon::primitives::{CommitteeIndex, Epoch, Slot, ValidatorIndex};
use crate::beacon::signing::compute_epoch_at_slot;

/// Everything a caller needs for one `(state, epoch)` pair's committees,
/// computed once so that deriving every committee of that epoch costs one
/// active-set scan and one shuffle between them all, rather than one of each
/// per committee.
///
/// Electra's `get_attesting_indices` needs one committee per bit set in one
/// attestation's `committee_bits`, up to `MAX_COMMITTEES_PER_SLOT` of them,
/// and a block carries up to `MAX_ATTESTATIONS_ELECTRA` attestations;
/// `stf::electra::process_attestation` walks the same committees again to
/// check the aggregation-bit lengths, and fork choice walks them a third time
/// when it replays the block's attestations into the latest-message store.
/// Derived one at a time, each of those committees costs a scan of the whole
/// validator registry plus a `SHUFFLE_ROUND_COUNT`-round shuffle *per member*.
/// Shared through one of these, they cost one scan and one whole-epoch
/// shuffle for the lot.
///
/// # Why the members are stored already shuffled
///
/// `ethlambda-state-transition`'s `compute_committee` derives a committee by
/// shuffling each of its positions individually, which repeats the same
/// rounds of hashing once per member. That crate's `shuffle_list` shuffles
/// the whole active set in one pass instead, in place, at which point the
/// committee at any `(slot, index)` is a contiguous slice of it, so
/// [`Self::committee`] hashes nothing at all and allocates nothing beyond the
/// caller's own copy.
///
/// That is also why building one of these is worth it only when several
/// committees will follow: the whole-epoch permutation moves every active
/// validator through every round, where one committee's per-member shuffle
/// touches that committee's members alone, so a single lookup costs more
/// this way than through `ethlambda-state-transition`'s `get_beacon_committee`,
/// which keeps the per-member derivation for exactly that case. A caller that
/// wants more than one committee of an epoch should hold a `CommitteeCache`
/// (`ethlambda-storage`) instead.
///
/// # Why the active set is not memoized on `epoch` or `seed` alone
///
/// `get_active_validator_indices` reads `activation_epoch` and `exit_epoch`
/// off every validator in `state.validators()`, so it is a function of the
/// state's registry, not of `epoch` or `seed` alone. Two different states can
/// share an epoch number, or even a seed (it comes from a RANDAO mix fixed
/// before either state's fork point, so two sibling branches diverging
/// afterward share it exactly) while disagreeing on which validators are
/// active. That is precisely the situation fork choice holds concurrent
/// states for, and precisely what the spec fixtures construct on purpose. A
/// cross-call cache therefore has to key on the state's *history*, which is
/// what `ethlambda-storage`'s `CommitteeCache` does, keyed by a
/// `ShufflingKey` that `ethlambda-state-transition` derives from that
/// history.
pub struct EpochCommittees {
    /// The epoch these committees belong to, which [`Self::committee`] holds
    /// every `slot` it is asked about against.
    epoch: Epoch,
    /// The epoch's active validators, in shuffled order: position `p` of the
    /// epoch-wide permutation holds `shuffled[p]`. A committee is a
    /// contiguous run of this, which is what makes [`Self::committee`] a
    /// slice rather than a computation.
    shuffled: Vec<ValidatorIndex>,
    committees_per_slot: u64,
}

impl EpochCommittees {
    /// Assembles an `EpochCommittees` from its already-computed parts.
    ///
    /// The derivation from a `BeaconState` (scanning its active set for
    /// `epoch`, deriving the committee count and shuffle seed from it, and
    /// shuffling that set in place) lives in `ethlambda-state-transition`'s
    /// `beacon::helpers::accessors::build_epoch_committees`: this crate
    /// cannot perform it, since the shuffle needs that crate's hashing and a
    /// full `BeaconState`. This constructor exists so that function has
    /// somewhere to put the result, and so tests of [`Self::committee`]'s own
    /// bounds-checking can build one directly from synthetic parts, with no
    /// state at all.
    pub fn new(epoch: Epoch, shuffled: Vec<ValidatorIndex>, committees_per_slot: u64) -> Self {
        Self {
            epoch,
            shuffled,
            committees_per_slot,
        }
    }

    /// How many committees each slot of this epoch has. The same value
    /// `ethlambda-state-transition`'s `get_committee_count_per_slot` would
    /// return, read off this type instead of rescanning the registry for it.
    pub fn committees_per_slot(&self) -> u64 {
        self.committees_per_slot
    }

    /// The committee at `slot` with `index`.
    ///
    /// The same members `ethlambda-state-transition`'s `get_beacon_committee`
    /// returns, in the same order, as a slice of the stored permutation
    /// rather than a fresh `Vec`.
    ///
    /// Rejects a `slot` outside the epoch this was built for. The per-member
    /// derivation cannot get that wrong, since it derives the epoch from the
    /// slot; this type is built for an epoch its caller names separately, and
    /// is shared across calls through `CommitteeCache`, so a mismatch would
    /// otherwise slice another epoch's shuffle at this slot's offset and hand
    /// back a wrong committee instead of an error.
    ///
    /// Rejects an out-of-range `index` rather than returning an empty or
    /// truncated slice, which is the verdict the per-member derivation
    /// reaches too: it would ask `compute_shuffled_index` for a position at
    /// or past the active-set size, and that fails its own
    /// `index < index_count` assertion. That includes an `index` large enough
    /// to overflow the committee number; see [`committee_number`].
    pub fn committee(&self, slot: Slot, index: CommitteeIndex) -> Result<&[ValidatorIndex]> {
        verify(
            compute_epoch_at_slot(slot) == self.epoch,
            "compute_epoch_at_slot(slot) == epoch",
        )?;

        // No `count > 0` check, unlike the per-member `compute_committee`:
        // `committees_per_slot` comes from `committee_count_per_slot`, which
        // never returns less than one, so `count` is at least
        // `SLOTS_PER_EPOCH` and the divisions below cannot divide by zero.
        let count = self.committees_per_slot * preset::SLOTS_PER_EPOCH;
        let committee_index = committee_number(slot, self.committees_per_slot, index)?;
        verify(committee_index < count, "index < count")?;

        let total = self.shuffled.len() as u64;
        let start = (total * committee_index) / count;
        let end = (total * (committee_index + 1)) / count;
        Ok(&self.shuffled[start as usize..end as usize])
    }
}

/// Written by hand rather than derived: the shuffling is one entry per active
/// validator, about 2.4M of them on mainnet, and a derived `Debug` would print
/// every one. What a reader wants from these is the shape, which is the two
/// numbers below.
impl std::fmt::Debug for EpochCommittees {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochCommittees")
            .field("active_validators", &self.shuffled.len())
            .field("committees_per_slot", &self.committees_per_slot)
            .finish()
    }
}

/// Which of its epoch's committees `index` at `slot` names:
/// `(slot % SLOTS_PER_EPOCH) * committees_per_slot + index`, the position
/// the specification's `get_beacon_committee` hands `compute_committee`.
///
/// `pub` despite being conceptually an implementation detail of
/// [`EpochCommittees::committee`]: `ethlambda-state-transition`'s
/// `get_beacon_committee` needs the exact same position formula for its own,
/// independent per-member derivation (see that function's doc for why it
/// stays independent rather than building on this type), and that crate
/// cannot reach a private item of this one.
///
/// The addition is checked because nothing upstream bounds `index`: fork
/// choice's `on_attestation` reaches here with a gossip attestation's own
/// `data.index`. The specification's `uint64` arithmetic raises on that
/// overflow, where a release build would wrap it into a valid committee
/// number and return a real committee. The product needs no check, being at
/// most `SLOTS_PER_EPOCH * MAX_COMMITTEES_PER_SLOT`.
pub fn committee_number(
    slot: Slot,
    committees_per_slot: u64,
    index: CommitteeIndex,
) -> Result<u64> {
    ((slot % preset::SLOTS_PER_EPOCH) * committees_per_slot)
        .checked_add(index)
        .ok_or(Error::ArithmeticOverflow(
            "(slot % SLOTS_PER_EPOCH) * committees_per_slot + index",
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::signing::compute_start_slot_at_epoch;

    /// The epoch these tests build synthetic committees for. Arbitrary, since
    /// nothing here derives from a real state; just non-zero so a slot
    /// arithmetic mistake could not accidentally land on the right answer by
    /// hitting epoch 0.
    const EPOCH: Epoch = 9;

    /// A committee count big enough that a slot has more than one committee,
    /// so the position arithmetic these tests exercise is not degenerate.
    const PER_SLOT: u64 = 4;

    /// Enough shuffled validators that every committee across the epoch gets
    /// at least one member, with an uneven split so the rounding in
    /// [`EpochCommittees::committee`] is exercised the same way
    /// `ethlambda-state-transition`'s own tests exercise it.
    fn synthetic_committees() -> EpochCommittees {
        let total = PER_SLOT * preset::SLOTS_PER_EPOCH * 3 + 1;
        let shuffled = (0..total).collect();
        EpochCommittees::new(EPOCH, shuffled, PER_SLOT)
    }

    /// Which committee indices [`EpochCommittees::committee`] rejects, and
    /// which it leaves to its caller.
    ///
    /// An index at or past `committees_per_slot` is *not* rejected here: the
    /// committee number it lands on is still inside the epoch's split, so it
    /// names a later slot's committee rather than nothing at all. What must
    /// fail is an index that runs off the end of the epoch.
    #[test]
    fn a_committee_index_past_the_epoch_is_rejected() {
        let committees = synthetic_committees();
        let slot = compute_start_slot_at_epoch(EPOCH);

        assert!(
            committees.committee(slot, PER_SLOT).is_ok(),
            "an index past this slot's committees is the caller's check, not this one's"
        );
        assert!(
            committees
                .committee(slot, PER_SLOT * preset::SLOTS_PER_EPOCH)
                .is_err(),
            "an index past the whole epoch's committees has nothing to slice"
        );
    }

    /// An `index` chosen so that the committee number wraps to exactly zero:
    /// unchecked, a release build would return the epoch's first committee for
    /// it, where the specification's `uint64` arithmetic raises. Nothing
    /// upstream bounds `index` on fork choice's gossip path, so this is an
    /// attacker's choice to make, and the derivation must refuse it.
    #[test]
    fn a_committee_number_that_would_wrap_is_rejected() {
        let committees = synthetic_committees();
        let last_slot = compute_start_slot_at_epoch(EPOCH) + preset::SLOTS_PER_EPOCH - 1;
        let wraps_to_zero = 0u64.wrapping_sub((preset::SLOTS_PER_EPOCH - 1) * PER_SLOT);

        assert!(committees.committee(last_slot, wraps_to_zero).is_err());
    }

    /// A slot outside the epoch an [`EpochCommittees`] was built for is an
    /// error, not a slice of the wrong epoch's shuffle at that slot's offset.
    #[test]
    fn a_slot_from_another_epoch_is_rejected() {
        let committees = synthetic_committees();
        let next_epoch_slot = compute_start_slot_at_epoch(EPOCH + 1);
        let previous_epoch_slot = compute_start_slot_at_epoch(EPOCH) - 1;

        assert!(committees.committee(next_epoch_slot, 0).is_err());
        assert!(committees.committee(previous_epoch_slot, 0).is_err());
    }

    /// Across a whole epoch, every member of the synthetic shuffle must be
    /// assigned exactly one committee slot, since the epoch's committees are
    /// one permutation split up; this is the property
    /// [`EpochCommittees::committee`]'s slicing exists to preserve.
    #[test]
    fn committees_cover_every_shuffled_member_once_per_epoch() {
        let committees = synthetic_committees();
        let total = PER_SLOT * preset::SLOTS_PER_EPOCH * 3 + 1;

        let mut all = Vec::new();
        for slot_offset in 0..preset::SLOTS_PER_EPOCH {
            let slot = compute_start_slot_at_epoch(EPOCH) + slot_offset;
            for index in 0..PER_SLOT {
                all.extend_from_slice(committees.committee(slot, index).unwrap());
            }
        }
        all.sort_unstable();
        assert_eq!(all, (0..total).collect::<Vec<_>>());
    }
}
