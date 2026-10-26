//! Beacon state accessors.
//!
//! The specification reads its constants from global scope. Here the preset
//! values are compile-time constants, but the configuration values are not, so
//! any accessor needing one takes a [`Config`]. That is the only systematic
//! difference between these signatures and the spec's.

use std::sync::Arc;

// Re-exported at this old path (`crate::beacon::helpers::accessors::CommitteeCache`,
// and so on), so every existing import of the type this module used to define
// is unaffected by its move to `ethlambda-storage`; see [`CommitteeCacheExt`]
// below for what this crate still contributes.
pub use ethlambda_storage::{
    ActiveBalanceCache, ActiveBalanceKey, CommitteeCache, Lookup, ShufflingKey,
};

use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::BeaconState;
use crate::beacon::error::Result;
use crate::beacon::fork::ForkName;
use crate::beacon::hash::hash;
use crate::beacon::lean_state_unreachable;
use crate::beacon::preset;
use crate::beacon::primitives::{
    Bytes32, CommitteeIndex, Domain, DomainType, Epoch, Gwei, Root, Slot, ValidatorIndex,
};

use super::misc::{
    compute_domain, compute_epoch_at_slot, compute_start_slot_at_epoch, fork_version_at_epoch,
};
use super::predicates::is_active_validator;
use super::shuffling::{compute_committee, shuffle_list};

// [`EpochCommittees`] and the position arithmetic it shares with
// [`get_beacon_committee`] now live in `ethlambda-types`, re-exported here at
// their old path: see that crate's `beacon::committees` module for why, and
// [`build_epoch_committees`] below for the derivation that stays on this
// side.
pub use crate::beacon::committees::{EpochCommittees, committee_number};

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
        .iter_validators()
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
/// split out so [`build_epoch_committees`] can share one
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

/// `epoch`'s committees as `state` names them: one scan of the active
/// validator set, this epoch's shuffle seed, and an in-place shuffle over
/// that set.
///
/// This is the derivation half of what used to be `EpochCommittees::new`
/// before that type moved to `ethlambda-types` (see this module's top-level
/// re-export): the type itself cannot depend on this crate's shuffle
/// computation ([`shuffle_list`]) or its [`hash`](crate::beacon::hash)
/// module, so the derivation stays a free function here rather than a method
/// on the type. [`CommitteeCacheExt::committees`] is this function's only
/// caller outside tests; every other consumer goes through the cache.
///
/// Electra's `get_attesting_indices` needs one committee per bit set in one
/// attestation's `committee_bits`, up to `MAX_COMMITTEES_PER_SLOT` of them,
/// and a block carries up to `MAX_ATTESTATIONS_ELECTRA` attestations;
/// `stf::electra::process_attestation` walks the same committees again to
/// check the aggregation-bit lengths, and fork choice walks them a third time
/// when it replays the block's attestations into the latest-message store.
/// Derived one at a time, each of those committees costs a scan of the whole
/// validator registry plus a `SHUFFLE_ROUND_COUNT`-round shuffle *per member*.
/// Shared through one [`EpochCommittees`], they cost one scan and one
/// whole-epoch shuffle for the lot; see that type's own documentation for why
/// its members are stored already shuffled, and why it is worth building only
/// when several committees will follow.
///
/// # Why the active set is not memoized on `epoch` or `seed` alone
///
/// [`get_active_validator_indices`] reads `activation_epoch` and `exit_epoch`
/// off every validator in `state.iter_validators()`, so it is a function of the
/// state's registry, not of `epoch` or `seed` alone. Two different states can
/// share an epoch number, or even a seed (it comes from a RANDAO mix fixed
/// before either state's fork point, so two sibling branches diverging
/// afterward share it exactly) while disagreeing on which validators are
/// active. That is precisely the situation fork choice holds concurrent
/// states for, and precisely what the spec fixtures construct on purpose. A
/// cross-call cache therefore has to key on the state's *history*, which is
/// what [`ShufflingKey`] does; see [`shuffling_key`].
pub fn build_epoch_committees(state: &BeaconState, epoch: Epoch) -> EpochCommittees {
    let active_indices = get_active_validator_indices(state, epoch);
    let committees_per_slot = committee_count_per_slot(active_indices.len() as u64);
    let seed = get_seed(state, epoch, constants::DOMAIN_BEACON_ATTESTER);
    // The active set's own buffer becomes the shuffled set, so a build holds
    // one validator-sized list at a time, not a permutation and a gathered
    // copy beside it.
    let shuffled = shuffle_list(active_indices, seed);
    EpochCommittees::new(epoch, shuffled, committees_per_slot)
}

/// `epoch`'s shuffling key as `state` sees it, or `None` if `state` cannot
/// name the deciding block: the state is not yet past the deciding slot (the
/// genesis state, asked about its own first epochs, is the case that reaches
/// this), or the deciding slot has fallen out of the state's
/// `SLOTS_PER_HISTORICAL_ROOT` window.
///
/// `None` is not a failure. It means this lookup cannot be keyed, so the
/// caller derives the committees for itself alone, without caching them.
///
/// [`ShufflingKey`] (`ethlambda-storage`) is the same key lighthouse calls an
/// `AttestationShufflingId`, and for the same reason. An epoch `E`'s
/// committees are fixed by two values and nothing else: the active validator
/// set at `E`, and the shuffle seed at `E`. The seed is the RANDAO mix from
/// epoch `E - MIN_SEED_LOOKAHEAD - 1`, complete once that epoch ends. The
/// active set moves only through `activation_epoch` and `exit_epoch`, and
/// every assignment to either (`process_registry_updates`,
/// `initiate_validator_exit`, and the consolidations and slashings that reach
/// it) goes through `compute_activation_exit_epoch`, which lands at least
/// `MAX_SEED_LOOKAHEAD` epochs ahead of the epoch making the change. So no
/// block after the end of `E - 2` can alter either input.
///
/// The block root at the last slot of `E - 2` therefore identifies the
/// history that determines `E`'s committees: two states agreeing on it agree
/// on the committees of `E`, however much they disagree about everything
/// since. Epoch and decision root together are what makes a cross-state cache
/// sound where `epoch` or `seed` alone would not be.
///
/// # Epochs 0 and 1
///
/// Neither has an `E - 2` to end, so both take the genesis block, at slot 0,
/// as their deciding block, which is what lighthouse's saturating decision
/// slot does too. Nothing after genesis can reach either input for them.
/// Their seeds read the two RANDAO mixes just below
/// `EPOCHS_PER_HISTORICAL_VECTOR`, which no block writes until the chain is
/// nearly that many epochs old, and by then slot 0 has long left every
/// state's `SLOTS_PER_HISTORICAL_ROOT` window, so the key can no longer be
/// named. A change to the active set made at any epoch lands at least
/// `MAX_SEED_LOOKAHEAD` epochs later, which is past both.
fn shuffling_key(state: &BeaconState, epoch: Epoch) -> Option<ShufflingKey> {
    // Saturating, so that epochs 0 and 1 land on the genesis block's slot;
    // see this function's documentation for why that is sound.
    let decision_slot = compute_start_slot_at_epoch(epoch.saturating_sub(1)).saturating_sub(1);
    let decision_root = get_block_root_at_slot(state, decision_slot).ok()?;
    Some(ShufflingKey {
        epoch,
        decision_root,
    })
}

/// Extends `ethlambda-storage`'s [`CommitteeCache`] with the consensus logic
/// that keys and derives its entries.
///
/// Kept here, as a trait implemented for a foreign type, rather than as
/// inherent methods on [`CommitteeCache`] itself, because deriving a key or
/// an [`EpochCommittees`] needs a [`BeaconState`]: `ethlambda-storage` cannot
/// depend on this crate (state transition depends on storage, not the other
/// way around), so it cannot implement these methods itself. A call site
/// that used to hold `committees: &mut CommitteeCache` now holds
/// `committees: &CommitteeCache` (or an `Arc<CommitteeCache>` it derefs
/// through) plus this trait in scope.
pub trait CommitteeCacheExt {
    /// `epoch`'s committees as `state` names them, derived once and then
    /// served to every later caller naming the same shuffling.
    ///
    /// Hands back an `Arc` rather than a borrow so the caller can go on to
    /// mutate the state (which block processing does between attestations)
    /// while still holding the committees. They stay valid across those
    /// mutations for exactly the reason [`shuffling_key`] gives, and nothing
    /// in the cache borrows the state it was built from.
    fn committees(&self, state: &BeaconState, epoch: Epoch) -> Arc<EpochCommittees>;

    /// Pins the shufflings the canonical head's children will ask for, so
    /// eviction never drops them: `head_state`'s previous, current, and next
    /// epochs'. `head_state` must be block `head_root`'s post-state.
    ///
    /// The keys come from `head_state`'s own `block_roots`, the way every
    /// lookup computes its own. Each epoch's deciding slot falls before the
    /// head's slot, and a descendant of the head inherits every root below
    /// that slot unchanged, so a lookup from any state built on the head
    /// names exactly these keys. Only the pinning is replaced here: whatever
    /// the previous head pinned stays resident until an insertion evicts it
    /// on epoch like any other entry.
    fn update_head(&self, head_root: Root, head_state: &BeaconState);
}

impl CommitteeCacheExt for CommitteeCache {
    fn committees(&self, state: &BeaconState, epoch: Epoch) -> Arc<EpochCommittees> {
        let Some(key) = shuffling_key(state, epoch) else {
            // Unkeyable: derive it for this caller alone rather than risk
            // serving it to a state whose history was never compared.
            crate::metrics::inc_committee_cache_lookups("unkeyable");
            return Arc::new(build_epoch_committees(state, epoch));
        };

        let (committees, lookup) = self.get_or_init(key, || build_epoch_committees(state, epoch));
        crate::metrics::inc_committee_cache_lookups(match lookup {
            Lookup::Hit => "hit",
            Lookup::Miss => "miss",
        });
        committees
    }

    fn update_head(&self, head_root: Root, head_state: &BeaconState) {
        let current = get_current_epoch(head_state);
        let epochs = [get_previous_epoch(head_state), current, current + 1];
        let keys = epochs.map(|epoch| shuffling_key(head_state, epoch));
        self.pin_head(head_root, keys);
    }
}

/// The key `state`'s total active balance is cached under, or `None` if
/// `state` cannot name the block that fixes it: the state has not advanced
/// past that block's slot (the genesis state, asked about its own epoch), or
/// the slot has fallen out of its `SLOTS_PER_HISTORICAL_ROOT` window. `None`
/// means the lookup is computed for its caller alone and not cached.
///
/// The total for a state in epoch `E` sums the effective balances of the
/// validators active at `E`, and both inputs are fixed once epoch `E - 1`
/// ends. Effective balances are written only by `process_effective_balance_updates`,
/// at the end of `E - 1`; an epoch's update is the last writer before `E`'s
/// states exist. The active set moves only through `activation_epoch` and
/// `exit_epoch`, and every assignment goes through `compute_activation_exit_epoch`,
/// at least `MAX_SEED_LOOKAHEAD` epochs ahead, so none can land in `E` for `E`
/// itself. Slashing sets `slashed` and queues an exit but leaves effective
/// balances alone, and the spec's total keeps slashed validators. Deposits
/// append validators that are not yet active, and the Electra upgrade zeroes
/// only never-activated validators. So the block root at the last slot of
/// `E - 1` identifies the history that determines the total: two states
/// agreeing on it agree on the total, however much they disagree after it.
///
/// That is one epoch later than [`shuffling_key`]'s root (the last slot of
/// `E - 2`), because the shuffle's inputs are fixed `MIN_SEED_LOOKAHEAD` epochs
/// ahead of use and the total's are not: an effective balance written at the
/// end of `E - 1` is part of the total for `E`, so a key rooted at `E - 2`
/// would let two branches that diverge during `E - 1` share one entry.
///
/// # Epoch 0
///
/// There is no epoch before it, so it takes the genesis block, at slot 0, as
/// its deciding block, as [`shuffling_key`] does for its first epochs. Nothing
/// after genesis can reach either input within epoch 0 (the effective-balance
/// update at its end writes epoch 1's), and a state from a different genesis
/// has a different genesis block root.
///
/// # Callers must be block processing
///
/// Between `process_effective_balance_updates` and the slot increment that
/// follows it, a state is still in epoch `E - 1` but already carries epoch
/// `E`'s effective balances, so its total would not match a key rooted at
/// `E - 2`'s end. The only callers routed through the cache are block
/// processing's (attestations, sync aggregate), which never run in that
/// window: a block is processed on a state that `process_slots` has already
/// advanced to the block's slot. Epoch processing keeps calling the
/// uncached [`get_total_active_balance`].
fn active_balance_key(state: &BeaconState) -> Option<ActiveBalanceKey> {
    let epoch = get_current_epoch(state);
    let decision_slot = compute_start_slot_at_epoch(epoch).saturating_sub(1);
    let decision_root = get_block_root_at_slot(state, decision_slot).ok()?;
    Some(ActiveBalanceKey {
        epoch,
        decision_root,
    })
}

/// Extends `ethlambda-storage`'s [`ActiveBalanceCache`] with the consensus
/// logic that keys and computes its entries, for the same reason
/// [`CommitteeCacheExt`] lives here and not in `ethlambda-storage`.
pub trait ActiveBalanceCacheExt {
    /// `get_total_active_balance(state)`, computed once per key and then
    /// served to every later caller naming the same one. Equal to the
    /// uncached function for every state it is given; see [`active_balance_key`]
    /// for why, and for who may call it.
    fn total_active_balance(&self, state: &BeaconState) -> Result<Gwei>;
}

impl ActiveBalanceCacheExt for ActiveBalanceCache {
    fn total_active_balance(&self, state: &BeaconState) -> Result<Gwei> {
        let Some(key) = active_balance_key(state) else {
            crate::metrics::inc_total_active_balance_lookups("unkeyable");
            return get_total_active_balance(state);
        };

        let (total, lookup) = self.get_or_compute(key, || compute_total_active_balance(state));
        crate::metrics::inc_total_active_balance_lookups(match lookup {
            Lookup::Hit => "hit",
            Lookup::Miss => "miss",
        });
        // The cross-check the key's soundness argument rests on: a stale hit
        // would mean some writer moved an input mid-epoch.
        if lookup == Lookup::Hit {
            debug_assert_eq!(
                total,
                compute_total_active_balance(state),
                "stale total active balance cache entry"
            );
        }
        Ok(total)
    }
}

/// The committee at `slot` with index `index`.
///
/// One epoch's active set is shuffled once and then split across every slot and
/// committee of that epoch, so the committee index is a position within that
/// single split rather than an independent draw.
///
/// The specification's own per-member derivation: one active-set scan, then
/// one `SHUFFLE_ROUND_COUNT`-round shuffle for each member of this committee
/// alone. That is the cheapest way to get one committee and the most
/// expensive way to get many, so anything deriving several committees of an
/// epoch should hold a [`CommitteeCache`] and go through
/// [`CommitteeCacheExt::committees`] instead; see [`EpochCommittees`] for what
/// the difference costs.
///
/// Kept apart from [`EpochCommittees`] rather than built on it, so the tests
/// holding that type to this function compare two independent derivations
/// of the same committee.
pub fn get_beacon_committee(
    state: &BeaconState,
    slot: Slot,
    index: CommitteeIndex,
) -> Result<Vec<ValidatorIndex>> {
    let epoch = compute_epoch_at_slot(slot);
    let active_indices = get_active_validator_indices(state, epoch);
    let committees_per_slot = committee_count_per_slot(active_indices.len() as u64);
    compute_committee(
        &active_indices,
        get_seed(state, epoch, constants::DOMAIN_BEACON_ATTESTER),
        committee_number(slot, committees_per_slot, index)?,
        committees_per_slot * preset::SLOTS_PER_EPOCH,
    )
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
    match state.fork_name() {
        // Gloas's own `proposer_lookahead` is unchanged from fulu (see
        // `containers::gloas`'s module doc) and gloas does not redefine
        // this function, so both forks share fulu's exact same lookup.
        ForkName::Fulu | ForkName::Gloas => return super::fulu::get_beacon_proposer_index(state),
        ForkName::Phase0
        | ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella
        | ForkName::Deneb
        | ForkName::Electra => {}
        ForkName::Lean => lean_state_unreachable("get_beacon_proposer_index"),
    }

    let epoch = get_current_epoch(state);

    let seed_base = get_seed(state, epoch, constants::DOMAIN_BEACON_PROPOSER);
    let mut input = Vec::with_capacity(40);
    input.extend_from_slice(&seed_base.0);
    input.extend_from_slice(&state.slot().to_le_bytes());
    let seed = hash(&input);

    let indices = get_active_validator_indices(state, epoch);
    match state.fork_name() {
        ForkName::Electra => super::electra::compute_proposer_index(&indices, seed, |index| {
            Ok(state.validator(index)?.effective_balance)
        }),
        ForkName::Phase0
        | ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella
        | ForkName::Deneb => super::shuffling::compute_proposer_index(
            &indices,
            seed,
            preset::MAX_EFFECTIVE_BALANCE,
            |index| Ok(state.validator(index)?.effective_balance),
        ),
        ForkName::Fulu => unreachable!("Fulu returns via the dispatch match above"),
        ForkName::Gloas => unreachable!("Gloas returns via the dispatch match above"),
        ForkName::Lean => lean_state_unreachable("get_beacon_proposer_index"),
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
///
/// One in-order pass over the registry, summing as it goes: the same value as
/// [`get_total_balance`] over [`get_active_validator_indices`] (same
/// saturating sum, same one-increment floor), without the intermediate index
/// list or a tree descent per active validator. `state.iter_validators()`
/// walks the leaves, whereas `state.validator(i)` descends from the root each
/// time.
pub fn get_total_active_balance(state: &BeaconState) -> Result<Gwei> {
    Ok(compute_total_active_balance(state))
}

/// [`get_total_active_balance`]'s body, without the `Result` it never needed.
fn compute_total_active_balance(state: &BeaconState) -> Gwei {
    let epoch = get_current_epoch(state);
    let total = state
        .iter_validators()
        .filter(|validator| is_active_validator(validator, epoch))
        .fold(0, |sum: Gwei, validator| {
            sum.saturating_add(validator.effective_balance)
        });
    total.max(preset::EFFECTIVE_BALANCE_INCREMENT)
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
    use crate::beacon::helpers::test_state::with_validators;

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
    /// specification's own per-member derivation does. [`get_beacon_committee`]
    /// still derives committees that way, so this pins the two to each other
    /// rather than to a recorded expectation: a divergence here is a consensus
    /// split, and it would not show up as a panic or an out-of-range index,
    /// only as a different committee.
    ///
    /// Run at two registry sizes, neither a multiple of the epoch's committee
    /// count, so the split's rounding puts committees of different lengths side
    /// by side; and the larger past the size that gives each slot more than one
    /// committee. An even split with one committee per slot would leave both of
    /// those boundary computations untested.
    #[test]
    fn sliced_committees_match_the_per_member_derivation() {
        let several_per_slot = preset::SLOTS_PER_EPOCH * preset::TARGET_COMMITTEE_SIZE * 2 + 1;

        for count in [100, several_per_slot as usize] {
            let state = with_validators(count);
            let epoch = get_current_epoch(&state);
            let committees = build_epoch_committees(&state, epoch);
            let per_slot = committees.committees_per_slot();
            if count as u64 == several_per_slot {
                assert!(
                    per_slot > 1,
                    "{count} validators gave one committee per slot"
                );
            }

            let mut lengths = Vec::new();
            for slot_offset in 0..preset::SLOTS_PER_EPOCH {
                let slot = compute_start_slot_at_epoch(epoch) + slot_offset;
                for index in 0..per_slot {
                    let sliced = committees.committee(slot, index).unwrap();
                    let expected = get_beacon_committee(&state, slot, index).unwrap();
                    assert_eq!(
                        sliced,
                        expected.as_slice(),
                        "{count} validators, slot {slot}, committee {index}"
                    );
                    lengths.push(sliced.len());
                }
            }
            assert_ne!(
                lengths.iter().min(),
                lengths.iter().max(),
                "{count} validators split evenly, so the rounding went untested"
            );
        }
    }

    /// A second lookup of the same `(state, epoch)` must serve the first
    /// lookup's `EpochCommittees`, which is the whole point of the cache: the
    /// shuffling is what an import spends its time on, and every attestation in
    /// a block asks for the same one.
    #[test]
    fn a_repeat_lookup_is_served_from_the_cache() {
        // Far enough in that the state can name epoch `slot`'s deciding block;
        // the genesis state cannot key its own epochs, which
        // `an_unkeyable_epoch_is_not_cached` covers separately.
        let mut state = with_validators(64);
        *state.slot_mut() = preset::SLOTS_PER_EPOCH * 4;
        let epoch = get_current_epoch(&state);
        let cache = CommitteeCache::default();

        let first = cache.committees(&state, epoch);
        let second = cache.committees(&state, epoch);

        assert!(
            Arc::ptr_eq(&first, &second),
            "the second lookup rebuilt the shuffling instead of reusing it"
        );
    }

    /// The head's previous, current, and next shufflings survive eviction
    /// pressure from many other distinct branches, even though the epoch rule
    /// alone would drop the oldest of them first. Pinning is checked
    /// externally, through [`CommitteeCacheExt::committees`] and
    /// `Arc::ptr_eq`, rather than by inspecting `CommitteeCache`'s own
    /// entries: those are private to `ethlambda-storage`, whose own tests
    /// cover the eviction bookkeeping directly. What this test covers instead
    /// is [`CommitteeCacheExt::update_head`]'s derivation of the three pinned
    /// keys from a real head state.
    #[test]
    fn the_heads_shufflings_are_never_evicted() {
        let head_epoch = *keyable_epochs().start() + 1;
        let head_state = state_on_branch(1, head_epoch);
        let head_root = Root::repeat_byte(0xaa);
        let cache = CommitteeCache::default();

        let pinned_epochs = [head_epoch - 1, head_epoch, head_epoch + 1];
        let pinned: Vec<Arc<EpochCommittees>> = pinned_epochs
            .iter()
            .map(|&epoch| cache.committees(&head_state, epoch))
            .collect();

        cache.update_head(head_root, &head_state);
        assert_eq!(cache.head_root(), Some(head_root));

        // Enough further, unrelated branches (at `LOOKUP_EPOCH`, distinct from
        // every pinned epoch's decision root) to force many evictions.
        for branch in 2..100u8 {
            cache.committees(&state_on_branch(branch, LOOKUP_EPOCH), LOOKUP_EPOCH);
        }

        for (&epoch, original) in pinned_epochs.iter().zip(pinned.iter()) {
            let refetched = cache.committees(&head_state, epoch);
            assert!(
                Arc::ptr_eq(original, &refetched),
                "pinned epoch {epoch} was evicted"
            );
        }
    }

    /// The epoch the branch-pressure tests look up from.
    const LOOKUP_EPOCH: Epoch = 9;

    /// Epochs a state at [`LOOKUP_EPOCH`] can key under either preset. The
    /// minimal preset's `SLOTS_PER_HISTORICAL_ROOT` window reaches back only a
    /// few epochs, and a key needs its deciding slot inside it, so this is
    /// narrower than the mainnet preset alone would allow.
    fn keyable_epochs() -> std::ops::RangeInclusive<Epoch> {
        LOOKUP_EPOCH - 6..=LOOKUP_EPOCH + 1
    }

    /// A state at `epoch`'s first slot whose every block root is `branch`'s
    /// marker, so two branches key every epoch under different deciding
    /// roots: distinct entries without needing distinct epochs, which the
    /// minimal preset's short window has too few of to overfill the cache.
    fn state_on_branch(branch: u8, epoch: Epoch) -> BeaconState {
        let mut state = with_validators(64);
        *state.slot_mut() = compute_start_slot_at_epoch(epoch);
        for slot in 0..preset::SLOTS_PER_HISTORICAL_ROOT {
            state.block_roots_mut()[slot] = Root::repeat_byte(branch);
        }
        state
    }

    /// Past slot 0, epochs 0 and 1 are keyed like any other, on the genesis
    /// block's root, so the chain's first attestations share a shuffling
    /// rather than each deriving its own. A state that descends from a
    /// different genesis block must not be served that entry.
    #[test]
    fn the_first_two_epochs_are_keyed_on_the_genesis_block() {
        let state = with_validators(64);
        let cache = CommitteeCache::default();

        for epoch in [constants::GENESIS_EPOCH, constants::GENESIS_EPOCH + 1] {
            let first = cache.committees(&state, epoch);
            let second = cache.committees(&state, epoch);
            assert!(Arc::ptr_eq(&first, &second), "epoch {epoch} was not cached");
        }

        let genesis_epoch = cache.committees(&state, constants::GENESIS_EPOCH);
        let mut other_genesis = state.clone();
        other_genesis.block_roots_mut()[0] = Root::repeat_byte(0x01);
        let other = cache.committees(&other_genesis, constants::GENESIS_EPOCH);
        assert!(
            !Arc::ptr_eq(&genesis_epoch, &other),
            "a state from another genesis block was served this one's shuffling"
        );
    }

    /// An epoch whose deciding block the state cannot name is derived but not
    /// stored. Genesis is the case that reaches this in practice: the genesis
    /// state sits at slot 0, which is the deciding slot of its own first two
    /// epochs, and a state cannot name the root of the slot it is at. Serving
    /// such a lookup from a key it does not really have is exactly the
    /// unsoundness [`shuffling_key`] exists to prevent.
    #[test]
    fn an_unkeyable_epoch_is_not_cached() {
        let mut state = with_validators(64);
        *state.slot_mut() = 0;
        let cache = CommitteeCache::default();

        let first = cache.committees(&state, constants::GENESIS_EPOCH);
        let second = cache.committees(&state, constants::GENESIS_EPOCH);

        assert!(
            !Arc::ptr_eq(&first, &second),
            "an unkeyable lookup was served from the cache"
        );
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

    /// SplitMix64: a tiny deterministic generator, so the randomized tests
    /// below need no dependency.
    struct SplitMix64(u64);

    impl SplitMix64 {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    /// A state at `epoch` whose validators get random activation and exit
    /// epochs around it and random effective balances.
    fn random_registry_state(rng: &mut SplitMix64, count: usize, epoch: Epoch) -> BeaconState {
        let mut state = with_validators(count);
        *state.slot_mut() = compute_start_slot_at_epoch(epoch);
        for index in 0..count {
            let validator = state.validator_mut(index as ValidatorIndex).unwrap();
            validator.activation_epoch = rng.next() % (epoch + 3);
            validator.exit_epoch = match rng.next() % 3 {
                0 => constants::FAR_FUTURE_EPOCH,
                _ => rng.next() % (epoch + 3),
            };
            validator.effective_balance = match rng.next() % 4 {
                0 => 0,
                1 => u64::MAX - rng.next() % 4,
                _ => (rng.next() % 64) * preset::EFFECTIVE_BALANCE_INCREMENT,
            };
        }
        state.apply_pending_mutations();
        state
    }

    /// The one-pass total is the spec's `get_total_balance` over the active
    /// indices, including its saturation and its floor.
    #[test]
    fn the_one_pass_total_matches_the_spec_formulation() {
        let mut rng = SplitMix64(0x5EED);
        for round in 0..64 {
            let count = (rng.next() % 40) as usize;
            let epoch = rng.next() % 6;
            let state = random_registry_state(&mut rng, count, epoch);
            let indices = get_active_validator_indices(&state, get_current_epoch(&state));
            assert_eq!(
                get_total_active_balance(&state).unwrap(),
                get_total_balance(&state, &indices).unwrap(),
                "round {round}"
            );
        }
    }

    /// An all-zero registry hits the floor, not zero.
    #[test]
    fn the_one_pass_total_is_floored_for_a_zero_registry() {
        let mut state = with_validators(8);
        for index in 0..8 {
            state.validator_mut(index).unwrap().effective_balance = 0;
        }
        state.apply_pending_mutations();
        assert_eq!(
            get_total_active_balance(&state).unwrap(),
            preset::EFFECTIVE_BALANCE_INCREMENT
        );
    }

    /// A state at the first slot of `epoch` whose every block root is `root`.
    fn state_at_epoch_with_root(epoch: Epoch, root: u8) -> BeaconState {
        let mut state = with_validators(16);
        *state.slot_mut() = compute_start_slot_at_epoch(epoch);
        for slot in 0..preset::SLOTS_PER_HISTORICAL_ROOT {
            state.block_roots_mut()[slot] = Root::repeat_byte(root);
        }
        state
    }

    /// A lookup returns the spec value and the second one is a hit.
    #[test]
    fn the_active_balance_cache_serves_the_spec_value() {
        let state = state_at_epoch_with_root(3, 1);
        let cache = ActiveBalanceCache::default();
        let expected = get_total_active_balance(&state).unwrap();

        assert_eq!(cache.total_active_balance(&state).unwrap(), expected);
        let key = active_balance_key(&state).unwrap();
        assert_eq!(cache.get(key), Some(expected));
        assert_eq!(cache.total_active_balance(&state).unwrap(), expected);
    }

    /// Two sibling states in one epoch that disagree on the deciding block
    /// keep separate entries, each with its own registry's total.
    #[test]
    fn sibling_states_with_different_decision_roots_get_different_entries() {
        let cache = ActiveBalanceCache::default();
        let a = state_at_epoch_with_root(3, 1);
        let mut b = state_at_epoch_with_root(3, 2);
        // Sibling `b` has a validator the fork `a` never saw.
        b.validator_mut(0).unwrap().effective_balance = 0;
        b.apply_pending_mutations();

        let total_a = cache.total_active_balance(&a).unwrap();
        let total_b = cache.total_active_balance(&b).unwrap();

        assert_ne!(total_a, total_b);
        assert_eq!(total_a, get_total_active_balance(&a).unwrap());
        assert_eq!(total_b, get_total_active_balance(&b).unwrap());
        assert_eq!(cache.get(active_balance_key(&a).unwrap()), Some(total_a));
        assert_eq!(cache.get(active_balance_key(&b).unwrap()), Some(total_b));
    }

    /// Across an epoch boundary the key changes, so the lookup misses and
    /// fills a new entry instead of serving the old epoch's total.
    #[test]
    fn crossing_an_epoch_boundary_misses_and_refills() {
        let cache = ActiveBalanceCache::default();
        let mut state = state_at_epoch_with_root(3, 1);
        let before = cache.total_active_balance(&state).unwrap();
        let old_key = active_balance_key(&state).unwrap();

        // The effective-balance update at the boundary, then the new epoch
        // with its own deciding root.
        state.validator_mut(0).unwrap().effective_balance = 0;
        state.apply_pending_mutations();
        *state.slot_mut() = compute_start_slot_at_epoch(4);
        let last_slot =
            (compute_start_slot_at_epoch(4) - 1) as usize % preset::SLOTS_PER_HISTORICAL_ROOT;
        state.block_roots_mut()[last_slot] = Root::repeat_byte(9);

        let new_key = active_balance_key(&state).unwrap();
        assert_ne!(old_key, new_key);
        let after = cache.total_active_balance(&state).unwrap();
        assert_eq!(after, get_total_active_balance(&state).unwrap());
        assert_ne!(before, after);
        assert_eq!(cache.get(old_key), Some(before));
        assert_eq!(cache.get(new_key), Some(after));
    }

    /// The genesis state cannot name the deciding block, so it is computed
    /// for its caller alone and not cached.
    #[test]
    fn an_unkeyable_state_is_computed_but_not_cached() {
        let mut state = with_validators(8);
        *state.slot_mut() = 0;
        assert!(active_balance_key(&state).is_none());
        let cache = ActiveBalanceCache::default();
        assert_eq!(
            cache.total_active_balance(&state).unwrap(),
            get_total_active_balance(&state).unwrap()
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
