//! Beacon state accessors.
//!
//! The specification reads its constants from global scope. Here the preset
//! values are compile-time constants, but the configuration values are not, so
//! any accessor needing one takes a [`Config`]. That is the only systematic
//! difference between these signatures and the spec's.

use std::sync::Arc;

use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::BeaconState;
use crate::beacon::error::Result;
use crate::beacon::fork::ForkName;
use crate::beacon::hash::hash;
use crate::beacon::preset;
use crate::beacon::primitives::{
    Bytes32, CommitteeIndex, Domain, DomainType, Epoch, Gwei, Root, Slot, ValidatorIndex,
};

use super::misc::{
    compute_domain, compute_epoch_at_slot, compute_start_slot_at_epoch, fork_version_at_epoch,
};
use super::predicates::is_active_validator;
use super::shuffling::compute_shuffled_indices;

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
    crate::beacon::verify(
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

/// How many committees a slot with `active_count` active validators splits
/// into: at least one, so a small chain still produces committees, and at
/// most `MAX_COMMITTEES_PER_SLOT`.
///
/// The half of [`get_committee_count_per_slot`] that does not need a state,
/// split out so [`EpochCommittees::new`] can share one
/// [`get_active_validator_indices`] scan between this and its own committee
/// derivation, rather than [`get_committee_count_per_slot`] repeating the scan
/// the caller already did to get `active_count` in the first place.
fn committee_count_per_slot(active_count: u64) -> u64 {
    let ideal = active_count / preset::SLOTS_PER_EPOCH / preset::TARGET_COMMITTEE_SIZE;
    ideal.clamp(1, preset::MAX_COMMITTEES_PER_SLOT as u64)
}

/// How many committees each slot of `epoch` has.
///
/// At least one, so a small chain still produces committees, and at most
/// `MAX_COMMITTEES_PER_SLOT`.
pub fn get_committee_count_per_slot(state: &BeaconState, epoch: Epoch) -> u64 {
    committee_count_per_slot(get_active_validator_indices(state, epoch).len() as u64)
}

/// Everything [`get_beacon_committee`] needs for one `(state, epoch)` pair,
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
/// [`super::shuffling::compute_committee`] derives a committee by shuffling
/// each of its positions individually, which repeats the same rounds of
/// hashing once per member. [`super::shuffling::compute_shuffled_indices`]
/// computes the whole epoch's permutation in one pass instead, at which point
/// the committee at any `(slot, index)` is a contiguous slice of it: this
/// stores the active set *through* that permutation, so [`Self::committee`]
/// hashes nothing at all and allocates nothing beyond the caller's own copy.
///
/// That is also why building one of these is worth it only when several
/// committees will follow: the whole-epoch permutation costs about eight
/// times a single committee's own shuffle, and repays that from the second
/// committee on. [`get_beacon_committee`] builds a fresh one per call and so
/// pays it every time; a caller that wants more than one committee of an
/// epoch should hold a [`CommitteeCache`] instead.
///
/// # Why the active set is not memoized on `epoch` or `seed` alone
///
/// [`get_active_validator_indices`] reads `activation_epoch` and `exit_epoch`
/// off every validator in `state.validators()`, so it is a function of the
/// state's registry, not of `epoch` or `seed` alone. Two different states can
/// share an epoch number, or even a seed (it comes from a RANDAO mix fixed
/// before either state's fork point, so two sibling branches diverging
/// afterward share it exactly) while disagreeing on which validators are
/// active. That is precisely the situation fork choice holds concurrent
/// states for, and precisely what the spec fixtures construct on purpose. A
/// cross-call cache therefore has to key on the state's *history*, which is
/// what [`CommitteeCache`] does; see [`ShufflingId`].
pub struct EpochCommittees {
    /// The epoch's active validators, in shuffled order: position `p` of the
    /// epoch-wide permutation holds `shuffled[p]`. A committee is a
    /// contiguous run of this, which is what makes [`Self::committee`] a
    /// slice rather than a computation.
    shuffled: Vec<ValidatorIndex>,
    committees_per_slot: u64,
}

impl EpochCommittees {
    /// Scans `state`'s active set for `epoch` once, derives the committee
    /// count and shuffle seed from it, and applies the epoch's permutation to
    /// that set.
    pub fn new(state: &BeaconState, epoch: Epoch) -> Self {
        let active_indices = get_active_validator_indices(state, epoch);
        let committees_per_slot = committee_count_per_slot(active_indices.len() as u64);
        let seed = get_seed(state, epoch, constants::DOMAIN_BEACON_ATTESTER);

        // `compute_shuffled_indices` returns a permutation of
        // `0..active_indices.len()`, so every position it yields is in range
        // and the index below cannot panic. Written as an index rather than a
        // `get` for that reason: a fallible form would have to invent an
        // error case the permutation's own definition rules out.
        let permutation = compute_shuffled_indices(active_indices.len() as u64, seed);
        let shuffled = permutation
            .iter()
            .map(|position| active_indices[*position as usize])
            .collect();

        Self {
            shuffled,
            committees_per_slot,
        }
    }

    /// How many committees each slot of this epoch has. The same value
    /// [`get_committee_count_per_slot`] would return, read off this type
    /// instead of rescanning the registry for it.
    pub fn committees_per_slot(&self) -> u64 {
        self.committees_per_slot
    }

    /// The committee at `slot` (which must fall in this epoch) with `index`.
    ///
    /// The same members [`get_beacon_committee`] returns, in the same order,
    /// as a slice of the stored permutation rather than a fresh `Vec`.
    ///
    /// Rejects an out-of-range `index` rather than returning an empty or
    /// truncated slice, which is the verdict the per-member derivation
    /// reaches too: it would ask
    /// [`super::shuffling::compute_shuffled_index`] for a position at or past
    /// the active-set size, and that fails its own `index < index_count`
    /// assertion.
    pub fn committee(&self, slot: Slot, index: CommitteeIndex) -> Result<&[ValidatorIndex]> {
        let count = self.committees_per_slot * preset::SLOTS_PER_EPOCH;
        crate::beacon::verify(count > 0, "count > 0")?;

        let committee_index = (slot % preset::SLOTS_PER_EPOCH) * self.committees_per_slot + index;
        crate::beacon::verify(committee_index < count, "index < count")?;

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

/// What pins the committees a state names for an epoch: the epoch itself, and
/// the last block root that could still have changed them.
///
/// The same key lighthouse calls an `AttestationShufflingId`, and for the same
/// reason. An epoch `E`'s committees are fixed by two values and nothing else:
/// the active validator set at `E`, and the shuffle seed at `E`. The seed is
/// the RANDAO mix from epoch `E - MIN_SEED_LOOKAHEAD - 1`, complete once that
/// epoch ends. The active set moves only through `activation_epoch` and
/// `exit_epoch`, and every assignment to either (`process_registry_updates`,
/// `initiate_validator_exit`, and the consolidations and slashings that reach
/// it) goes through `compute_activation_exit_epoch`, which lands at least
/// `MAX_SEED_LOOKAHEAD` epochs ahead of the epoch making the change. So no
/// block after the end of `E - 2` can alter either input.
///
/// The block root at the last slot of `E - 2` therefore identifies the history
/// that determines `E`'s committees: two states agreeing on it agree on the
/// committees of `E`, however much they disagree about everything since.
/// Epoch and decision root together are what makes a cross-state cache sound
/// where `epoch` or `seed` alone would not be; see [`EpochCommittees`] for
/// what goes wrong with those.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShufflingId {
    epoch: Epoch,
    decision_root: Root,
}

impl ShufflingId {
    /// The id of `epoch`'s shuffling as `state` sees it, or `None` if `state`
    /// cannot name the deciding block: the epoch is close enough to genesis
    /// that no slot precedes it, or the deciding slot has fallen out of the
    /// state's `SLOTS_PER_HISTORICAL_ROOT` window.
    ///
    /// `None` is not a failure. It means this lookup cannot be keyed, so the
    /// caller derives the committees without caching them, which is what every
    /// caller did before this type existed.
    fn new(state: &BeaconState, epoch: Epoch) -> Option<Self> {
        let decision_slot = compute_start_slot_at_epoch(epoch.checked_sub(1)?).checked_sub(1)?;
        let decision_root = get_block_root_at_slot(state, decision_slot).ok()?;
        Some(Self {
            epoch,
            decision_root,
        })
    }
}

/// How many distinct shufflings stay resident in a [`CommitteeCache`].
///
/// Two, which is what processing one block actually needs: every fork's
/// `process_attestation` accepts an attestation whose target is the current or
/// the previous epoch and no other, and fork choice replays that same block's
/// attestations against the same two. A third entry would only ever hold a
/// sibling branch's shuffling, and an entry is one `u64` per active validator,
/// about 19 MB at mainnet's ~2.4M.
const COMMITTEE_CACHE_CAPACITY: usize = 2;

/// [`EpochCommittees`] shared across the calls asking for the same epoch's
/// committees, so a block's attestations derive each epoch's shuffling once
/// between all of them instead of once apiece.
///
/// Held by the node's chain actor and passed down through block processing and
/// fork choice, rather than kept in a global or rebuilt inside each helper:
/// which shufflings are worth keeping resident, and how much memory that may
/// cost, is the owner's decision and not something a leaf helper can answer. A
/// caller with no cache of its own (a fixture runner, a one-off lookup) passes
/// a fresh [`CommitteeCache::default`] and gets exactly the behaviour that
/// existed before this type: derive, use, drop.
///
/// Entries are keyed by [`ShufflingId`], which is what keeps sharing sound
/// across states; see that type for why an epoch number alone would not be.
#[derive(Debug, Default)]
pub struct CommitteeCache {
    /// Newest-used entry last, so eviction on a miss always drops index `0`:
    /// an ordinary least-recently-used cache, linear-scanned rather than
    /// hash-indexed because [`COMMITTEE_CACHE_CAPACITY`] is 2 and a `HashMap`
    /// would be more machinery than the two comparisons it replaces.
    entries: Vec<(ShufflingId, Arc<EpochCommittees>)>,
}

impl CommitteeCache {
    /// `epoch`'s committees as `state` names them, derived once and then
    /// served to every later caller naming the same shuffling.
    ///
    /// Hands back an `Arc` rather than a borrow so the caller can go on to
    /// mutate the state (which block processing does between attestations)
    /// while still holding the committees. They stay valid across those
    /// mutations for exactly the reason [`ShufflingId`] gives, and nothing in
    /// the cache borrows the state it was built from.
    pub fn committees(&mut self, state: &BeaconState, epoch: Epoch) -> Arc<EpochCommittees> {
        let Some(id) = ShufflingId::new(state, epoch) else {
            // Unkeyable: derive it for this caller alone rather than risk
            // serving it to a state whose history was never compared.
            return Arc::new(EpochCommittees::new(state, epoch));
        };

        if let Some(position) = self.entries.iter().position(|(cached, _)| *cached == id) {
            let entry = self.entries.remove(position);
            let committees = Arc::clone(&entry.1);
            self.entries.push(entry);
            return committees;
        }

        let committees = Arc::new(EpochCommittees::new(state, epoch));
        if self.entries.len() >= COMMITTEE_CACHE_CAPACITY {
            self.entries.remove(0);
        }
        self.entries.push((id, Arc::clone(&committees)));
        committees
    }
}

/// The committee at `slot` with index `index`.
///
/// One epoch's active set is shuffled once and then split across every slot and
/// committee of that epoch, so the committee index is a position within that
/// single split rather than an independent draw.
///
/// Builds a fresh [`EpochCommittees`] per call and drops it, so this is the
/// right call only for a caller wanting one committee and no more. Anything
/// deriving several committees of an epoch, or several epochs' worth over
/// time, should hold a [`CommitteeCache`] and go through
/// [`CommitteeCache::committees`]; see [`EpochCommittees`] for what the
/// difference costs.
pub fn get_beacon_committee(
    state: &BeaconState,
    slot: Slot,
    index: CommitteeIndex,
) -> Result<Vec<ValidatorIndex>> {
    Ok(EpochCommittees::new(state, compute_epoch_at_slot(slot))
        .committee(slot, index)?
        .to_vec())
}

/// The proposer for the state's current slot, dispatching on fork for the
/// two places `compute_proposer_index` (`beacon-chain.md`'s "Misc" section)
/// changes: the acceptance test electra widens (EIP-7251), and fulu's move to
/// a precomputed lookahead window instead of a shuffle run on demand
/// (EIP-7917).
///
/// Every fork-invariant caller in this module (block header validation,
/// RANDAO, slashing's proposer reward, and every driver in [`crate::beacon::stf`]
/// that reads a block's proposer) reaches this function unconditionally, with
/// no fork of its own to dispatch on, so the dispatch has to live here rather
/// than at each of those call sites. That is also why this cannot simply stay
/// [`super::shuffling::compute_proposer_index`] called with a different
/// `max_effective_balance`: electra's own version
/// ([`super::electra::compute_proposer_index`]) changes the width of the
/// random draw itself, not only the ceiling it is weighed against, and fulu's
/// version ([`super::fulu::get_beacon_proposer_index`]) does not shuffle at
/// all.
pub fn get_beacon_proposer_index(state: &BeaconState) -> Result<ValidatorIndex> {
    // Fulu moves this off the read path entirely: `process_proposer_lookahead`
    // (an epoch-processing step, not implemented in this module) precomputes
    // the whole window ahead of time, so this becomes a lookup into it rather
    // than a shuffle run now. See `crate::beacon::helpers::fulu`'s own module docs for
    // why a seed, and therefore a proposer, is only ever knowable that far
    // ahead of time in the first place.
    if state.fork_name() == ForkName::Fulu {
        return super::fulu::get_beacon_proposer_index(state);
    }

    let epoch = get_current_epoch(state);

    let seed_base = get_seed(state, epoch, constants::DOMAIN_BEACON_PROPOSER);
    let mut input = Vec::with_capacity(40);
    input.extend_from_slice(&seed_base.0);
    input.extend_from_slice(&state.slot().to_le_bytes());
    let seed = hash(&input);

    let indices = get_active_validator_indices(state, epoch);
    if state.fork_name() == ForkName::Electra {
        super::electra::compute_proposer_index(&indices, seed, |index| {
            Ok(state.validator(index)?.effective_balance)
        })
    } else {
        super::shuffling::compute_proposer_index(
            &indices,
            seed,
            preset::MAX_EFFECTIVE_BALANCE,
            |index| Ok(state.validator(index)?.effective_balance),
        )
    }
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
    use super::super::shuffling::compute_committee;
    use super::*;

    #[test]
    fn previous_epoch_is_clamped_at_genesis() {
        let mut state = crate::beacon::helpers::test_state::with_validators(4);
        *state.slot_mut() = 0;
        assert_eq!(get_previous_epoch(&state), constants::GENESIS_EPOCH);

        *state.slot_mut() = preset::SLOTS_PER_EPOCH * 3;
        assert_eq!(get_previous_epoch(&state), 2);
    }

    #[test]
    fn block_root_outside_the_window_is_an_error() {
        let state = crate::beacon::helpers::test_state::with_validators(4);
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
        let state = crate::beacon::helpers::test_state::with_validators(count);
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

    /// The whole-epoch permutation must place each committee exactly where the
    /// specification's own per-member derivation does. Both forms are in the
    /// tree ([`compute_committee`] is still the specification's spelling), so
    /// this pins them to each other rather than to a recorded expectation: a
    /// divergence here is a consensus split, and it would not show up as a
    /// panic or an out-of-range index, only as a different committee.
    #[test]
    fn sliced_committees_match_the_per_member_derivation() {
        let count = 64;
        let state = crate::beacon::helpers::test_state::with_validators(count);
        let epoch = get_current_epoch(&state);
        let committees = EpochCommittees::new(&state, epoch);

        let active_indices = get_active_validator_indices(&state, epoch);
        let seed = get_seed(&state, epoch, constants::DOMAIN_BEACON_ATTESTER);
        let per_slot = committees.committees_per_slot();

        for slot_offset in 0..preset::SLOTS_PER_EPOCH {
            let slot = compute_start_slot_at_epoch(epoch) + slot_offset;
            for index in 0..per_slot {
                let expected = compute_committee(
                    &active_indices,
                    seed,
                    (slot % preset::SLOTS_PER_EPOCH) * per_slot + index,
                    per_slot * preset::SLOTS_PER_EPOCH,
                )
                .unwrap();
                assert_eq!(
                    committees.committee(slot, index).unwrap(),
                    expected.as_slice(),
                    "slot {slot}, committee {index}"
                );
            }
        }
    }

    /// Which committee indices [`EpochCommittees::committee`] rejects, and
    /// which it leaves to its caller.
    ///
    /// An index at or past `committees_per_slot` is *not* rejected here: the
    /// committee number it lands on is still inside the epoch's split, so it
    /// names a later slot's committee rather than nothing at all. That is what
    /// the per-member derivation did too, which is why every caller checks
    /// `index < get_committee_count_per_slot(...)` itself, as the specification
    /// has `process_attestation` do. What must fail is an index that runs off
    /// the end of the epoch.
    #[test]
    fn a_committee_index_past_the_epoch_is_rejected() {
        let state = crate::beacon::helpers::test_state::with_validators(64);
        let epoch = get_current_epoch(&state);
        let committees = EpochCommittees::new(&state, epoch);
        let slot = compute_start_slot_at_epoch(epoch);
        let per_slot = committees.committees_per_slot();

        assert!(
            committees.committee(slot, per_slot).is_ok(),
            "an index past this slot's committees is the caller's check, not this one's"
        );
        assert!(
            committees
                .committee(slot, per_slot * preset::SLOTS_PER_EPOCH)
                .is_err(),
            "an index past the whole epoch's committees has nothing to slice"
        );
    }

    /// A second lookup of the same `(state, epoch)` must serve the first
    /// lookup's `EpochCommittees`, which is the whole point of the type: the
    /// shuffling is what an import spends its time on, and every attestation in
    /// a block asks for the same one.
    #[test]
    fn a_repeat_lookup_is_served_from_the_cache() {
        // Far enough in that the state can name epoch `slot`'s deciding block:
        // the genesis-adjacent epochs cannot be keyed at all, which
        // `an_unkeyable_epoch_is_not_cached` covers separately.
        let mut state = crate::beacon::helpers::test_state::with_validators(64);
        *state.slot_mut() = preset::SLOTS_PER_EPOCH * 4;
        let epoch = get_current_epoch(&state);
        let mut cache = CommitteeCache::default();

        let first = cache.committees(&state, epoch);
        let second = cache.committees(&state, epoch);

        assert!(
            Arc::ptr_eq(&first, &second),
            "the second lookup rebuilt the shuffling instead of reusing it"
        );
    }

    /// Distinct epochs are distinct keys, and the cache must not grow past its
    /// capacity as they accumulate: an entry is one `u64` per active validator,
    /// so an unbounded cache would outgrow the state it was derived from.
    #[test]
    fn the_cache_stays_within_its_capacity_bound() {
        // `2..=current` are all keyable at this slot, and differ in epoch, so
        // each is a distinct entry: `current` is chosen to give more of them
        // than the cache is allowed to hold.
        let mut state = crate::beacon::helpers::test_state::with_validators(64);
        *state.slot_mut() = preset::SLOTS_PER_EPOCH * (COMMITTEE_CACHE_CAPACITY as u64 + 3);
        let current = get_current_epoch(&state);
        let mut cache = CommitteeCache::default();

        for epoch in 2..=current {
            cache.committees(&state, epoch);
            assert!(
                !cache.entries.is_empty(),
                "epoch {epoch} was not keyable, so this asserts nothing about capacity"
            );
            assert!(
                cache.entries.len() <= COMMITTEE_CACHE_CAPACITY,
                "{} entries resident",
                cache.entries.len()
            );
        }
    }

    /// An epoch whose deciding block the state cannot name is derived but not
    /// stored. Genesis is the case that reaches this in practice: there is no
    /// slot before epoch 0, so there is no root to key on, and serving such a
    /// lookup from a key it does not really have is exactly the unsoundness
    /// [`ShufflingId`] exists to prevent.
    #[test]
    fn an_unkeyable_epoch_is_not_cached() {
        let mut state = crate::beacon::helpers::test_state::with_validators(64);
        *state.slot_mut() = 0;
        let mut cache = CommitteeCache::default();

        let first = cache.committees(&state, constants::GENESIS_EPOCH);
        let second = cache.committees(&state, constants::GENESIS_EPOCH);

        assert!(cache.entries.is_empty(), "an unkeyable lookup was cached");
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(first.committees_per_slot(), second.committees_per_slot());
    }

    #[test]
    fn total_balance_is_floored_at_one_increment() {
        // An empty set must not yield zero, since callers divide by this.
        let state = crate::beacon::helpers::test_state::with_validators(4);
        assert_eq!(
            get_total_balance(&state, &[]).unwrap(),
            preset::EFFECTIVE_BALANCE_INCREMENT
        );
    }

    #[test]
    fn proposer_is_drawn_from_the_active_set() {
        let state = crate::beacon::helpers::test_state::with_validators(32);
        let proposer = get_beacon_proposer_index(&state).unwrap();
        assert!(proposer < 32);
    }

    #[test]
    fn churn_limit_respects_its_floor() {
        let config = Config::mainnet();
        // A tiny validator set falls below the proportional limit, so the floor
        // is what applies.
        let state = crate::beacon::helpers::test_state::with_validators(4);
        assert_eq!(
            get_validator_churn_limit(&state, &config),
            config.min_per_epoch_churn_limit
        );
    }
}
