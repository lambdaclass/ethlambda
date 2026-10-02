//! Electra's new and changed helper functions.
//!
//! Electra's headline change is EIP-7251: a validator's effective balance is no
//! longer pinned to one value. A validator that upgrades its withdrawal
//! credentials to the new compounding prefix
//! ([`constants::COMPOUNDING_WITHDRAWAL_PREFIX`]) can hold up to
//! [`preset::MAX_EFFECTIVE_BALANCE_ELECTRA`] rather than the fixed
//! `MAX_EFFECTIVE_BALANCE` every validator was capped at before. Nearly every
//! function below exists because of that one change, in three groups.
//!
//! **The withdrawal credential predicates** ([`is_compounding_withdrawal_credential`],
//! [`has_compounding_withdrawal_credential`], [`has_execution_withdrawal_credential`],
//! and [`get_max_effective_balance`]) are what let [`is_fully_withdrawable_validator`]
//! and [`is_partially_withdrawable_validator`] ask "what is this validator's
//! ceiling" instead of assuming one fixed answer for everyone.
//! [`has_eth1_withdrawal_credential`] is transcribed here too even though
//! electra does not touch it: it is capella's predicate
//! (`specs/capella/beacon-chain.md`), needed unmodified by
//! [`has_execution_withdrawal_credential`], and this module has no shared
//! cross-fork module to put a single reused predicate in instead.
//!
//! **The churn limit becomes balance-based.** Phase0 rate-limits activation and
//! exit by counting validators: at most one fixed-size churn limit's worth of
//! them may enter or leave the registry per epoch, and every validator counts
//! the same because every validator's effective balance was the same. Once a
//! single validator can hold what used to be dozens of validators' worth of
//! stake, counting validators no longer bounds how much *stake* can move in
//! one epoch: one compounding validator's exit could strand as much
//! finality-relevant weight as an old-style validator committee's worth all at
//! once. So electra rebuilds the limit in Gwei instead of a headcount.
//! [`get_balance_churn_limit`] is phase0's `get_validator_churn_limit` with
//! that swap, and [`get_activation_exit_churn_limit`] and
//! [`get_consolidation_churn_limit`] split that one Gwei budget between the
//! two things competing for it, so a busy exit queue cannot alone starve
//! consolidations (or the reverse).
//!
//! **The exit and consolidation queues track a spendable balance, not just a
//! target epoch.** Phase0's exit queue only ever needed an epoch, since every
//! validator consumed the same one "seat" of churn and the queue epoch was
//! answer enough. A balance-based limit cannot work that way: two small exits
//! in the same epoch might together still fit under that epoch's churn, even
//! though the first one alone already used most of it, while a single huge
//! exit might need several epochs' worth of churn before it can go through at
//! all. [`compute_exit_epoch_and_update_churn`] and
//! [`compute_consolidation_epoch_and_update_churn`] carry that as an
//! `(earliest_epoch, balance_to_consume)` cursor on the state:
//! `balance_to_consume` is how much of `earliest_epoch`'s budget is still
//! unspent, refilled to a full epoch's churn only once an exit or
//! consolidation actually needs to push the cursor past the epoch it
//! currently sits on. [`initiate_validator_exit`] replaces phase0's version
//! (`crate::beacon::helpers::mutators::initiate_validator_exit`) with one that defers
//! to [`compute_exit_epoch_and_update_churn`] instead of scanning every
//! validator's `exit_epoch` to find the queue's current occupancy.
//!
//! [`switch_to_compounding_validator`] and [`queue_excess_active_balance`] are
//! the deposit side of the same change: raising a validator's ceiling, or a
//! deposit that pushes a validator's balance above
//! [`preset::MIN_ACTIVATION_BALANCE`], both risk crediting a large amount of
//! new active stake in a single slot, so rather than applying the balance
//! immediately, both instead queue the excess as a
//! [`electra::PendingDeposit`] that epoch processing (not implemented in this
//! file) drains a bounded amount of at a time.
//! [`queue_entire_balance_and_reset_validator`] is the same queue-then-drain
//! pattern applied to a whole balance rather than an excess over a ceiling.
//! It is **not** itself a named helper in `specs/electra/beacon-chain.md`:
//! it is extracted verbatim from a loop body in `specs/electra/fork.md`'s
//! `upgrade_to_electra` (the fork-upgrade function, implemented elsewhere in
//! this module), which resets every not-yet-activated validator's balance to
//! zero at the fork boundary and queues the whole amount as a pending
//! deposit rather than losing it. It is factored out here so the
//! fork-upgrade code does not have to duplicate
//! [`queue_excess_active_balance`]'s pending-deposit construction by hand.
//!
//! **[`get_attesting_indices`], [`get_indexed_attestation`], and
//! [`is_valid_indexed_attestation`]** exist here, rather than reusing
//! [`crate::beacon::helpers::attestation`]'s phase0 versions, for an unrelated reason
//! (EIP-7549, not EIP-7251): from electra on, one [`electra::Attestation`]
//! can name every committee in a slot instead of one, via the new
//! `committee_bits` field, so `aggregation_bits` widens to match and the
//! function reading attester positions out of it has to walk each named
//! committee at its own offset within that wider bitfield. See
//! [`crate::beacon::helpers::attestation`]'s module doc for why phase0's versions do
//! not generalize (different concrete container types, not just a wider
//! bound), and [`get_attesting_indices`]'s own doc for the offset arithmetic.
//!
//! [`compute_proposer_index`] and [`get_next_sync_committee_indices`] are not
//! on this module's list of required electra signatures, but this file adds
//! them anyway: electra's specification modifies both of them (widening the
//! acceptance test's random draw from one byte to two, and swapping in
//! [`preset::MAX_EFFECTIVE_BALANCE_ELECTRA`]), both fall within this file's
//! assigned "Predicates" and "Beacon state accessors" sections of
//! `specs/electra/beacon-chain.md`, and every electra (and fulu) block needs a
//! correctly weighted proposer draw and, at the sync committee period
//! boundary, a correctly weighted committee draw. They mirror
//! [`crate::beacon::helpers::shuffling::compute_proposer_index`] and
//! [`crate::beacon::helpers::altair::get_next_sync_committee_indices`] respectively,
//! which remain phase0's and altair's own unmodified versions for the earlier
//! forks that still use them.
//!
//! [`crate::beacon::helpers::accessors::get_beacon_proposer_index`] is what actually
//! reaches [`compute_proposer_index`] for an electra state (fulu reads
//! `proposer_lookahead` instead, precomputed through this same function by
//! [`crate::beacon::helpers::fulu::compute_proposer_indices`]): that accessor is the
//! one call site every fork-invariant caller of "the" proposer index already
//! goes through unconditionally, so it is where the fork dispatch lives
//! rather than in each of those callers.
//!
//! # The fork projection
//!
//! `pending_deposits`, `pending_partial_withdrawals`, `exit_balance_to_consume`,
//! `earliest_exit_epoch`, `consolidation_balance_to_consume`, and
//! `earliest_consolidation_epoch` are state fields with no fork-invariant
//! accessor on [`BeaconState`]. Unlike altair's participation flags (see
//! `crate::beacon::helpers::altair::altair_state_ref`'s doc), these fields are not
//! electra-only: fulu keeps every one of them unchanged (see the [`fulu`]
//! module doc), and gloas keeps the churn cursors and (behind a slice view;
//! see [`PendingQueueFields`]'s own doc) the pending queues unchanged too, so
//! [`churn_cursors_mut`] and [`pending_queue_fields`]/[`pending_queue_fields_ref`]
//! match `BeaconState::Electra`, `BeaconState::Fulu`, and `BeaconState::Gloas`
//! rather than only the first. A projection that matched only `Electra`, the way
//! `crate::beacon::helpers::altair::altair_state_ref` matches only `Altair`, would
//! silently break every one of these functions on a fulu state, which is the
//! single easiest mistake to make copying that shape without also copying
//! the reasoning behind it.

use crate::beacon::bls;
use crate::beacon::config::Config;
use crate::beacon::constants::{self, FAR_FUTURE_EPOCH};
use crate::beacon::containers::shared::Validator;
use crate::beacon::containers::{BeaconState, electra, fulu, gloas};
use crate::beacon::error::{Error, Result};
use crate::beacon::fork::ForkName;
use crate::beacon::hash::hash;
use crate::beacon::lean_state_unreachable;
use crate::beacon::preset;
use crate::beacon::primitives::{
    BLS_SIGNATURE_SIZE, BlsSignature, Bytes32, CommitteeIndex, Epoch, Gwei, HashTreeRoot as _,
    Slot, ValidatorIndex,
};

use super::accessors::{
    CommitteeCache, CommitteeCacheExt, get_active_validator_indices, get_current_epoch, get_domain,
    get_seed, get_total_active_balance,
};
use super::math::bytes_to_uint64;
use super::misc::{compute_activation_exit_epoch, compute_epoch_at_slot, compute_signing_root};
use super::predicates::are_indices_sorted_and_unique;
use super::shuffling::compute_shuffled_index;

// ---------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------

/// Whether `validator` has an `0x01`-prefixed "eth1" withdrawal credential.
///
/// Capella's predicate, not electra's: transcribed from
/// `specs/capella/beacon-chain.md` because [`has_execution_withdrawal_credential`]
/// needs it unmodified and this module has nowhere else to put a single
/// cross-fork predicate reused this way.
pub fn has_eth1_withdrawal_credential(validator: &Validator) -> bool {
    validator.withdrawal_credentials.0[0] == constants::ETH1_ADDRESS_WITHDRAWAL_PREFIX
}

/// Whether `withdrawal_credentials` is `0x02`-prefixed ("compounding").
pub fn is_compounding_withdrawal_credential(withdrawal_credentials: Bytes32) -> bool {
    withdrawal_credentials.0[0] == constants::COMPOUNDING_WITHDRAWAL_PREFIX
}

/// Whether `validator` has an `0x02`-prefixed "compounding" withdrawal
/// credential.
pub fn has_compounding_withdrawal_credential(validator: &Validator) -> bool {
    is_compounding_withdrawal_credential(validator.withdrawal_credentials)
}

/// Whether `validator` has an `0x01`- or `0x02`-prefixed withdrawal
/// credential, i.e. can actually receive a withdrawal at all (an
/// un-upgraded `0x00` BLS credential cannot).
pub fn has_execution_withdrawal_credential(validator: &Validator) -> bool {
    has_eth1_withdrawal_credential(validator) || has_compounding_withdrawal_credential(validator)
}

/// Whether `validator` is fully withdrawable at `epoch`.
///
/// Modified from phase0/capella only in which credential predicate it uses:
/// [`has_execution_withdrawal_credential`] accepts either upgraded prefix
/// rather than only the `0x01` one, since a compounding validator is just as
/// withdrawable as an eth1 one once past its `withdrawable_epoch`.
pub fn is_fully_withdrawable_validator(validator: &Validator, balance: Gwei, epoch: Epoch) -> bool {
    has_execution_withdrawal_credential(validator)
        && validator.withdrawable_epoch <= epoch
        && balance > 0
}

/// Whether `validator` is partially withdrawable, i.e. sitting at its own
/// ceiling with a real excess balance above it.
///
/// Modified from phase0/capella to compare against
/// [`get_max_effective_balance`] rather than the single fixed
/// `MAX_EFFECTIVE_BALANCE`: a compounding validator's "at the ceiling, with
/// excess above it" now means its own, higher ceiling, not everyone else's.
pub fn is_partially_withdrawable_validator(validator: &Validator, balance: Gwei) -> bool {
    let max_effective_balance = get_max_effective_balance(validator);
    let has_max_effective_balance = validator.effective_balance == max_effective_balance;
    let has_excess_balance = balance > max_effective_balance;
    has_execution_withdrawal_credential(validator)
        && has_max_effective_balance
        && has_excess_balance
}

/// Whether `validator` may join the activation queue.
///
/// Modified from phase0's version (`crate::beacon::helpers::predicates::is_eligible_for_activation_queue`)
/// to require only [`preset::MIN_ACTIVATION_BALANCE`] or more, rather than
/// exactly the old `MAX_EFFECTIVE_BALANCE`: electra's minimum activation
/// balance is deliberately lower than the new compounding ceiling, so a
/// validator can activate well before it ever tops out.
pub fn is_eligible_for_activation_queue(validator: &Validator) -> bool {
    validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH
        && validator.effective_balance >= preset::MIN_ACTIVATION_BALANCE
}

/// Electra's replacement for [`crate::beacon::helpers::shuffling::compute_proposer_index`]:
/// a proposer sampled from `indices`, weighted by effective balance.
///
/// Two things change from phase0's version, both from EIP-7251. The
/// acceptance test compares against [`preset::MAX_EFFECTIVE_BALANCE_ELECTRA`]
/// rather than a caller-supplied (and necessarily lower, pre-electra) ceiling,
/// since a compounding validator's effective balance can now actually reach
/// that higher value. And the random draw widens from a single random byte to
/// a two-byte (16-bit) value: an 8-bit draw can only ever resolve balance
/// differences to one part in 256, which was fine when every validator's
/// effective balance sat at the same value, but is too coarse a filter now
/// that effective balance can vary by a factor of dozens.
///
/// Like the phase0 version, this takes `effective_balance_of` rather than a
/// state directly, so it stays independent of which fork's state it reads.
pub fn compute_proposer_index(
    indices: &[ValidatorIndex],
    seed: Bytes32,
    mut effective_balance_of: impl FnMut(ValidatorIndex) -> Result<Gwei>,
) -> Result<ValidatorIndex> {
    crate::beacon::verify(!indices.is_empty(), "len(indices) > 0")?;

    // `2**16 - 1`, the largest value a two-byte little-endian draw can take.
    const MAX_RANDOM_VALUE: u64 = u16::MAX as u64;
    let total = indices.len() as u64;

    let mut i = 0u64;
    loop {
        let shuffled = compute_shuffled_index(i % total, total, seed)?;
        let candidate = indices[shuffled as usize];

        let mut random_input = Vec::with_capacity(32 + 8);
        random_input.extend_from_slice(&seed.0);
        random_input.extend_from_slice(&(i / 16).to_le_bytes());
        let random_bytes = hash(&random_input);
        let offset = ((i % 16) * 2) as usize;
        let random_value = bytes_to_uint64(&random_bytes.0[offset..offset + 2]);

        let effective_balance = effective_balance_of(candidate)?;
        if effective_balance * MAX_RANDOM_VALUE
            >= preset::MAX_EFFECTIVE_BALANCE_ELECTRA * random_value
        {
            return Ok(candidate);
        }

        i += 1;
    }
}

/// Whether an indexed attestation names a valid attester set and carries
/// their aggregate signature.
///
/// Logic identical to [`crate::beacon::helpers::attestation::is_valid_indexed_attestation`];
/// this exists as its own copy only because [`electra::IndexedAttestation`]
/// is a different concrete type from phase0's `IndexedAttestation`, bounded
/// by `MAX_VALIDATORS_PER_SLOT` rather than `MAX_VALIDATORS_PER_COMMITTEE`
/// (EIP-7549: one electra attestation can span every committee in a slot).
pub fn is_valid_indexed_attestation(
    state: &BeaconState,
    indexed_attestation: &electra::IndexedAttestation,
) -> bool {
    let indices: &[ValidatorIndex] = &indexed_attestation.attesting_indices;
    if indices.is_empty() || !are_indices_sorted_and_unique(indices) {
        return false;
    }

    let mut pubkeys = Vec::with_capacity(indices.len());
    for index in indices {
        match state.validator(*index) {
            Ok(validator) => pubkeys.push(validator.pubkey),
            Err(_) => return false,
        }
    }

    let domain = get_domain(
        state,
        constants::DOMAIN_BEACON_ATTESTER,
        Some(indexed_attestation.data.target.epoch),
    );
    let signing_root = compute_signing_root(indexed_attestation.data.hash_tree_root(), domain);
    bls::fast_aggregate_verify(&pubkeys, signing_root, &indexed_attestation.signature)
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

/// The committee indices `committee_bits` names, i.e. the positions of its
/// set bits, in ascending order.
///
/// [`get_attesting_indices`] reads this to know which committees an
/// [`electra::Attestation`] covers and in what order its widened
/// `aggregation_bits` names their members.
pub fn get_committee_indices(committee_bits: &electra::CommitteeBits) -> Vec<CommitteeIndex> {
    (0..committee_bits.len())
        .filter(|&index| committee_bits.get(index).unwrap_or(false))
        .map(|index| index as CommitteeIndex)
        .collect()
}

/// The effective balance ceiling for `validator`: the higher
/// [`preset::MAX_EFFECTIVE_BALANCE_ELECTRA`] for a compounding validator, or
/// [`preset::MIN_ACTIVATION_BALANCE`] for everyone else.
///
/// Named "max effective balance" rather than "ceiling" to match the
/// specification, even though [`preset::MIN_ACTIVATION_BALANCE`] is also the
/// minimum a validator needs to activate at all: pre-electra those two
/// numbers were different constants that happened never to both matter to
/// the same validator at once, and electra reuses the minimum as the
/// non-compounding ceiling rather than introducing a third value.
pub fn get_max_effective_balance(validator: &Validator) -> Gwei {
    if has_compounding_withdrawal_credential(validator) {
        preset::MAX_EFFECTIVE_BALANCE_ELECTRA
    } else {
        preset::MIN_ACTIVATION_BALANCE
    }
}

// ---------------------------------------------------------------------------
// Beacon state accessors
// ---------------------------------------------------------------------------

/// The churn limit for the current epoch, in Gwei.
///
/// Phase0's `get_validator_churn_limit`
/// (`crate::beacon::helpers::accessors::get_validator_churn_limit`) counts
/// validators, which only bounds a balance amount because every validator's
/// effective balance used to be the same fixed value. Once a compounding
/// validator can hold up to `MAX_EFFECTIVE_BALANCE_ELECTRA`, the same
/// headcount no longer bounds the same amount of stake, so this counts Gwei
/// directly instead: the same fraction of total active balance
/// (`CHURN_LIMIT_QUOTIENT`), floored at
/// [`Config::min_per_epoch_churn_limit_electra`] rather than a
/// validator-count floor, and rounded down to a whole
/// `EFFECTIVE_BALANCE_INCREMENT` so the budget always divides evenly into the
/// unit every balance change is already rounded to.
pub fn get_balance_churn_limit(state: &BeaconState, config: &Config) -> Result<Gwei> {
    let total_active_balance = get_total_active_balance(state)?;
    let churn = config
        .min_per_epoch_churn_limit_electra
        .max(total_active_balance / config.churn_limit_quotient);
    Ok(churn - churn % preset::EFFECTIVE_BALANCE_INCREMENT)
}

/// The portion of [`get_balance_churn_limit`] set aside for activations and
/// exits, as opposed to consolidations.
///
/// Capped separately from the combined budget
/// ([`Config::max_per_epoch_activation_exit_churn_limit`]) so that on a very
/// large validator set, activations and exits cannot alone consume the whole
/// churn budget and starve consolidations of any share at all.
pub fn get_activation_exit_churn_limit(state: &BeaconState, config: &Config) -> Result<Gwei> {
    Ok(config
        .max_per_epoch_activation_exit_churn_limit
        .min(get_balance_churn_limit(state, config)?))
}

/// The portion of [`get_balance_churn_limit`] left over for consolidations
/// once [`get_activation_exit_churn_limit`] has taken its share.
pub fn get_consolidation_churn_limit(state: &BeaconState, config: &Config) -> Result<Gwei> {
    let balance_churn_limit = get_balance_churn_limit(state, config)?;
    let activation_exit_churn_limit = get_activation_exit_churn_limit(state, config)?;
    // `get_activation_exit_churn_limit` is a `min` against `balance_churn_limit`,
    // so it can never exceed it, and this subtraction cannot underflow.
    Ok(balance_churn_limit - activation_exit_churn_limit)
}

/// The total amount queued in [`electra::PendingPartialWithdrawal`]s for
/// `index`, not yet paid out.
///
/// Read by [`crate::beacon::stf::electra::process_withdrawal_request`] and
/// [`crate::beacon::stf::electra::process_consolidation_request`] to refuse consolidating,
/// or fully exiting, a validator that still has a partial withdrawal in
/// flight: doing either out from under that withdrawal would leave nothing
/// left to pay it from.
///
/// Also served, unmodified, by gloas: nothing in gloas's own `beacon-chain.md`
/// touches this function, and the only thing that kept a gloas state from
/// calling this exact copy was the queue's own type
/// ([`crate::beacon::containers::gloas::PendingPartialWithdrawals`], a
/// [`libssz_types::ProgressiveList`], EIP-7688), which
/// [`PendingQueueFieldsRef::pending_partial_withdrawals`] already abstracts
/// over as a slice.
pub fn get_pending_balance_to_withdraw(state: &BeaconState, index: ValidatorIndex) -> Result<Gwei> {
    let fields = pending_queue_fields_ref(state, "get_pending_balance_to_withdraw")?;
    let mut total: Gwei = 0;
    for withdrawal in fields.pending_partial_withdrawals() {
        if withdrawal.validator_index == index {
            total = total.saturating_add(withdrawal.amount);
        }
    }
    Ok(total)
}

/// The attester indices a slot's named committees cover, filtered by
/// `is_set`, in ascending order.
///
/// EIP-7549 moves the committee index out of `AttestationData` and lets one
/// attestation cover every committee in a slot, so `aggregation_bits` is now
/// the concatenation of each named committee's member bits, in the same
/// ascending committee-index order [`get_committee_indices`] returns them
/// in. Reading attester `position` out of committee `committee_index`'s
/// segment therefore means indexing `aggregation_bits` at `committee_offset +
/// position`, where `committee_offset` is the total length of every
/// previously-*named* committee, not the committee's own index or position
/// in the loop: a naive `committee_index * committee_size` offset would
/// misalign as soon as two named committees differ in size, and skipping an
/// *unnamed* committee (one whose bit is clear in `committee_bits`) must not
/// advance the offset at all, since that committee's members never appear in
/// `aggregation_bits` to begin with. Accumulating `committee_offset` from
/// each named committee's own `len()`, in the order [`get_committee_indices`]
/// visits them, is what keeps the running offset correct regardless of which
/// (possibly non-contiguous) committee indices are actually named.
///
/// Sorted at the end for the same reason
/// [`crate::beacon::helpers::attestation::get_attesting_indices`] sorts: the
/// specification returns a set, and a committee is a *shuffled* slice of the
/// registry, so reading one in position order yields attester indices in
/// shuffle order, almost never ascending. Not deduplicated: a slot's
/// committees partition its active set (see
/// `crate::beacon::helpers::accessors`'s
/// `committees_cover_every_active_validator_once_per_epoch` test), so the
/// same validator index cannot appear under two different named committees,
/// and a single committee cannot name the same position twice.
///
/// `committees` is what keeps this one active-set scan and one shuffle rather
/// than `MAX_COMMITTEES_PER_SLOT` of each: every committee named by one
/// attestation belongs to the same slot, and so to the same epoch's shuffling.
/// See [`CommitteeCache`] for how far that sharing reaches beyond this call.
///
/// `is_set` is this function's own share of what [`get_attesting_indices`]
/// otherwise is verbatim: electra's `aggregation_bits` is a bounded
/// `SszBitlist`, and [`crate::beacon::helpers::gloas::get_attesting_indices`]'s
/// is EIP-7688's unbounded `ProgressiveBitlist`, two different Rust types
/// whose only shared operation this walk needs is "is bit `n` set", which is
/// exactly what a closure abstracts over without either caller allocating or
/// duplicating the walk itself.
pub(crate) fn attesting_indices_from_committee_bits(
    state: &BeaconState,
    slot: Slot,
    committee_bits: &electra::CommitteeBits,
    is_set: impl Fn(usize) -> bool,
    committees: &CommitteeCache,
) -> Result<Vec<ValidatorIndex>> {
    let committee_indices = get_committee_indices(committee_bits);
    let epoch_committees = committees.committees(state, compute_epoch_at_slot(slot));

    let mut indices = Vec::new();
    let mut committee_offset = 0usize;
    for committee_index in committee_indices {
        let committee = epoch_committees.committee(slot, committee_index)?;
        for (position, attester_index) in committee.iter().enumerate() {
            let bit = committee_offset + position;
            if is_set(bit) {
                indices.push(*attester_index);
            }
        }
        committee_offset += committee.len();
    }

    indices.sort_unstable();
    Ok(indices)
}

/// The committee members whose bit is set in `attestation`, in ascending
/// order. See [`attesting_indices_from_committee_bits`] for the walk itself;
/// this is a thin wrapper over it, closing over `attestation`'s own
/// `aggregation_bits`.
pub fn get_attesting_indices(
    state: &BeaconState,
    attestation: &electra::Attestation,
    committees: &CommitteeCache,
) -> Result<Vec<ValidatorIndex>> {
    attesting_indices_from_committee_bits(
        state,
        attestation.data.slot,
        &attestation.committee_bits,
        |bit| attestation.aggregation_bits.get(bit).unwrap_or(false),
        committees,
    )
}

/// The same attestation with its attesters named rather than bit-encoded.
pub fn get_indexed_attestation(
    state: &BeaconState,
    attestation: &electra::Attestation,
    committees: &CommitteeCache,
) -> Result<electra::IndexedAttestation> {
    let indices = get_attesting_indices(state, attestation, committees)?;
    Ok(electra::IndexedAttestation {
        attesting_indices: electra::AttestingIndices::try_from(indices)?,
        data: attestation.data,
        signature: attestation.signature,
    })
}

/// Electra's replacement for
/// [`crate::beacon::helpers::altair::get_next_sync_committee_indices`]: the sync
/// committee indices, with possible duplicates, for the sync committee
/// period starting next epoch.
///
/// Same EIP-7251 change as [`compute_proposer_index`]: the acceptance test's
/// ceiling becomes [`preset::MAX_EFFECTIVE_BALANCE_ELECTRA`] and its random
/// draw widens from one byte to two, for the same reasons.
pub fn get_next_sync_committee_indices(state: &BeaconState) -> Result<Vec<ValidatorIndex>> {
    let epoch = get_current_epoch(state) + 1;

    // `2**16 - 1`, the largest value a two-byte little-endian draw can take.
    const MAX_RANDOM_VALUE: u64 = u16::MAX as u64;

    let active_validator_indices = get_active_validator_indices(state, epoch);
    let active_validator_count = active_validator_indices.len() as u64;
    crate::beacon::verify(
        active_validator_count > 0,
        "len(active_validator_indices) > 0",
    )?;
    let seed = get_seed(state, epoch, constants::DOMAIN_SYNC_COMMITTEE);

    let mut i: u64 = 0;
    let mut sync_committee_indices = Vec::with_capacity(preset::SYNC_COMMITTEE_SIZE);
    while sync_committee_indices.len() < preset::SYNC_COMMITTEE_SIZE {
        let shuffled_index =
            compute_shuffled_index(i % active_validator_count, active_validator_count, seed)?;
        let candidate_index = active_validator_indices[shuffled_index as usize];

        let mut random_input = Vec::with_capacity(32 + 8);
        random_input.extend_from_slice(&seed.0);
        random_input.extend_from_slice(&(i / 16).to_le_bytes());
        let random_bytes = hash(&random_input);
        let offset = ((i % 16) * 2) as usize;
        let random_value = bytes_to_uint64(&random_bytes.0[offset..offset + 2]);

        let effective_balance = state.validator(candidate_index)?.effective_balance;
        if effective_balance * MAX_RANDOM_VALUE
            >= preset::MAX_EFFECTIVE_BALANCE_ELECTRA * random_value
        {
            sync_committee_indices.push(candidate_index);
        }
        i += 1;
    }
    Ok(sync_committee_indices)
}

// ---------------------------------------------------------------------------
// Beacon state mutators
// ---------------------------------------------------------------------------

/// Puts a validator into the exit queue.
///
/// Modified from phase0's version
/// (`crate::beacon::helpers::mutators::initiate_validator_exit`) to compute the exit
/// epoch through [`compute_exit_epoch_and_update_churn`] instead of scanning
/// every validator's `exit_epoch` for the queue's current occupancy: that
/// scan counted validators, which stopped being a valid proxy for churned
/// balance the moment validators stopped all weighing the same.
pub fn initiate_validator_exit(
    state: &mut BeaconState,
    index: ValidatorIndex,
    config: &Config,
) -> Result<()> {
    if state.validator(index)?.exit_epoch != FAR_FUTURE_EPOCH {
        return Ok(());
    }

    let effective_balance = state.validator(index)?.effective_balance;
    let exit_queue_epoch = compute_exit_epoch_and_update_churn(state, effective_balance, config)?;

    // See `crate::beacon::helpers::mutators::initiate_validator_exit` for why this is
    // checked rather than left to wrap: a validator already queued with an
    // exit epoch close to `FAR_FUTURE_EPOCH` could otherwise overflow into a
    // withdrawable epoch in the past.
    let withdrawable = exit_queue_epoch
        .checked_add(config.min_validator_withdrawability_delay)
        .ok_or(Error::ArithmeticOverflow(
            "exit_queue_epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY",
        ))?;

    let validator = state.validator_mut(index)?;
    validator.exit_epoch = exit_queue_epoch;
    validator.withdrawable_epoch = withdrawable;
    Ok(())
}

/// Advances the exit-queue cursor for an exit of `exit_balance`, returning
/// the epoch it may take effect at.
///
/// This is where the "balance to consume" cursor this module's doc describes
/// actually lives: `earliest_exit_epoch` is the earliest epoch that still has
/// unspent churn, and `exit_balance_to_consume` is how much of that epoch's
/// budget remains. A new epoch's budget is only opened (refilled to a full
/// per-epoch churn limit) once the cursor actually needs to move past the
/// epoch it currently sits on; until then, a later, smaller exit in the same
/// epoch spends whatever an earlier one left over instead of always waiting
/// for a fresh epoch.
///
/// Gloas modifies this function by exactly the one line the specification's
/// own diff shows (EIP-8061, beacon-chain.md): the per-epoch churn limit is
/// [`crate::beacon::helpers::gloas::get_exit_churn_limit`]'s own uncapped
/// budget rather than [`get_activation_exit_churn_limit`]'s combined one.
/// Nothing past that line differs, so gloas does not get a copy of its own:
/// this picks the limit by fork and otherwise runs the one shared cursor
/// update, through [`ChurnCursorsMut`] rather than [`PendingQueueFields`] (see
/// that enum's own doc for why). Gloas modifies neither
/// `initiate_validator_exit` (so neither voluntary exits nor registry
/// ejections) nor `process_withdrawal_request`, so calling this from any
/// of them already picks up gloas's churn automatically, the same way
/// pyspec's unmodified callers do.
pub fn compute_exit_epoch_and_update_churn(
    state: &mut BeaconState,
    exit_balance: Gwei,
    config: &Config,
) -> Result<Epoch> {
    let current_epoch = get_current_epoch(state);
    let per_epoch_churn = match state.fork_name() {
        ForkName::Electra | ForkName::Fulu => get_activation_exit_churn_limit(state, config)?,
        ForkName::Gloas => crate::beacon::helpers::gloas::get_exit_churn_limit(state, config)?,
        fork @ (ForkName::Phase0
        | ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella
        | ForkName::Deneb) => {
            return Err(Error::UnsupportedForFork {
                function: "compute_exit_epoch_and_update_churn",
                fork,
            });
        }
        ForkName::Lean => lean_state_unreachable("compute_exit_epoch_and_update_churn"),
    };

    let mut fields = churn_cursors_mut(state, "compute_exit_epoch_and_update_churn")?;

    let mut earliest_exit_epoch = fields
        .earliest_exit_epoch()
        .max(compute_activation_exit_epoch(current_epoch));

    // A later epoch than the cursor currently sits on: that epoch has not
    // spent any of its churn yet, so its budget starts full. Otherwise the
    // cursor has not moved, and whatever it left unspent carries over.
    let mut exit_balance_to_consume = if fields.earliest_exit_epoch() < earliest_exit_epoch {
        per_epoch_churn
    } else {
        fields.exit_balance_to_consume()
    };

    if exit_balance > exit_balance_to_consume {
        let balance_to_process = exit_balance - exit_balance_to_consume;
        // Ceiling division: how many additional epochs' worth of churn this
        // exit needs beyond what the current epoch has left.
        let additional_epochs = balance_to_process
            .checked_sub(1)
            .and_then(|value| value.checked_div(per_epoch_churn))
            .and_then(|value| value.checked_add(1))
            .ok_or(Error::ArithmeticOverflow(
                "(exit_balance - exit_balance_to_consume - 1) / per_epoch_churn + 1",
            ))?;
        let additional_churn =
            additional_epochs
                .checked_mul(per_epoch_churn)
                .ok_or(Error::ArithmeticOverflow(
                    "additional_epochs * per_epoch_churn",
                ))?;
        earliest_exit_epoch =
            earliest_exit_epoch
                .checked_add(additional_epochs)
                .ok_or(Error::ArithmeticOverflow(
                    "earliest_exit_epoch + additional_epochs",
                ))?;
        exit_balance_to_consume = exit_balance_to_consume
            .checked_add(additional_churn)
            .ok_or(Error::ArithmeticOverflow(
                "exit_balance_to_consume + additional_epochs * per_epoch_churn",
            ))?;
    }

    *fields.exit_balance_to_consume_mut() = exit_balance_to_consume
        .checked_sub(exit_balance)
        .ok_or(Error::ArithmeticOverflow(
            "exit_balance_to_consume - exit_balance",
        ))?;
    *fields.earliest_exit_epoch_mut() = earliest_exit_epoch;

    Ok(earliest_exit_epoch)
}

/// The per-epoch consolidation churn limit for `state`'s own fork,
/// dispatching between electra's [`get_consolidation_churn_limit`] (also
/// fulu's, unmodified) and gloas's own
/// [`crate::beacon::helpers::gloas::get_consolidation_churn_limit`]
/// (EIP-8061, independently derived from total active balance rather than
/// left over from the activation/exit split).
///
/// The one call site every consolidation-churn reader reaches, so a gloas
/// state is never charged electra's formula by accident:
/// [`compute_consolidation_epoch_and_update_churn`] and
/// [`crate::beacon::stf::electra::process_consolidation_request`] both go
/// through this rather than either raw formula directly.
pub fn get_consolidation_churn_limit_for_fork(
    state: &BeaconState,
    config: &Config,
) -> Result<Gwei> {
    match state.fork_name() {
        ForkName::Electra | ForkName::Fulu => get_consolidation_churn_limit(state, config),
        ForkName::Gloas => {
            crate::beacon::helpers::gloas::get_consolidation_churn_limit(state, config)
        }
        fork @ (ForkName::Phase0
        | ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella
        | ForkName::Deneb) => Err(Error::UnsupportedForFork {
            function: "get_consolidation_churn_limit_for_fork",
            fork,
        }),
        ForkName::Lean => lean_state_unreachable("get_consolidation_churn_limit_for_fork"),
    }
}

/// Advances the consolidation-queue cursor for a consolidation moving
/// `consolidation_balance`, returning the epoch it may take effect at.
///
/// The consolidation-side counterpart of
/// [`compute_exit_epoch_and_update_churn`], carrying the exact same
/// `(earliest_epoch, balance_to_consume)` cursor shape but drawing from
/// [`get_consolidation_churn_limit_for_fork`]'s separate budget instead of
/// the activation/exit one, so a burst of consolidations cannot also drain
/// the budget an unrelated exit needs.
///
/// Unlike [`compute_exit_epoch_and_update_churn`], gloas does not redefine
/// this function itself: only its callee (electra's
/// [`get_consolidation_churn_limit`]) is gloas-modified. So the cursor
/// read/write below stays the one copy every fork through gloas shares,
/// fed by [`get_consolidation_churn_limit_for_fork`] rather than either raw
/// formula.
pub fn compute_consolidation_epoch_and_update_churn(
    state: &mut BeaconState,
    consolidation_balance: Gwei,
    config: &Config,
) -> Result<Epoch> {
    let current_epoch = get_current_epoch(state);
    let per_epoch_churn = get_consolidation_churn_limit_for_fork(state, config)?;

    let mut fields = churn_cursors_mut(state, "compute_consolidation_epoch_and_update_churn")?;

    let mut earliest_consolidation_epoch = fields
        .earliest_consolidation_epoch()
        .max(compute_activation_exit_epoch(current_epoch));

    let mut consolidation_balance_to_consume =
        if fields.earliest_consolidation_epoch() < earliest_consolidation_epoch {
            per_epoch_churn
        } else {
            fields.consolidation_balance_to_consume()
        };

    if consolidation_balance > consolidation_balance_to_consume {
        let balance_to_process = consolidation_balance - consolidation_balance_to_consume;
        let additional_epochs = balance_to_process
            .checked_sub(1)
            .and_then(|value| value.checked_div(per_epoch_churn))
            .and_then(|value| value.checked_add(1))
            .ok_or(Error::ArithmeticOverflow(
                "(consolidation_balance - consolidation_balance_to_consume - 1) / per_epoch_churn + 1",
            ))?;
        let additional_churn =
            additional_epochs
                .checked_mul(per_epoch_churn)
                .ok_or(Error::ArithmeticOverflow(
                    "additional_epochs * per_epoch_churn",
                ))?;
        earliest_consolidation_epoch = earliest_consolidation_epoch
            .checked_add(additional_epochs)
            .ok_or(Error::ArithmeticOverflow(
                "earliest_consolidation_epoch + additional_epochs",
            ))?;
        consolidation_balance_to_consume = consolidation_balance_to_consume
            .checked_add(additional_churn)
            .ok_or(Error::ArithmeticOverflow(
                "consolidation_balance_to_consume + additional_epochs * per_epoch_churn",
            ))?;
    }

    *fields.consolidation_balance_to_consume_mut() = consolidation_balance_to_consume
        .checked_sub(consolidation_balance)
        .ok_or(Error::ArithmeticOverflow(
            "consolidation_balance_to_consume - consolidation_balance",
        ))?;
    *fields.earliest_consolidation_epoch_mut() = earliest_consolidation_epoch;

    Ok(earliest_consolidation_epoch)
}

/// Upgrades a validator to a compounding withdrawal credential, queuing
/// whatever balance is already above [`preset::MIN_ACTIVATION_BALANCE`] the
/// same way a fresh deposit above it would be.
pub fn switch_to_compounding_validator(
    state: &mut BeaconState,
    index: ValidatorIndex,
) -> Result<()> {
    state.validator_mut(index)?.withdrawal_credentials.0[0] =
        constants::COMPOUNDING_WITHDRAWAL_PREFIX;
    queue_excess_active_balance(state, index)
}

/// Caps a validator's balance at [`preset::MIN_ACTIVATION_BALANCE`], queuing
/// anything above that as a [`electra::PendingDeposit`] rather than
/// crediting it as active stake immediately.
///
/// Does nothing if the balance is already at or below the cap: called after
/// [`switch_to_compounding_validator`] raises a validator's ceiling, and
/// after a deposit, both of which are ordinary, common-case calls that most
/// of the time have nothing to queue.
pub fn queue_excess_active_balance(state: &mut BeaconState, index: ValidatorIndex) -> Result<()> {
    let balance = state.balance(index)?;
    if balance <= preset::MIN_ACTIVATION_BALANCE {
        return Ok(());
    }

    let excess_balance = balance - preset::MIN_ACTIVATION_BALANCE;
    // `state.balance(index)?` above already proved `index` is in range, so
    // this cannot fail.
    *state.balance_mut(index)? = preset::MIN_ACTIVATION_BALANCE;

    let deposit = placeholder_pending_deposit(state.validator(index)?, excess_balance);
    pending_queue_fields(state, "queue_excess_active_balance")?.push_pending_deposit(deposit)
}

/// Zeroes a validator's balance and effective balance, resets its activation
/// eligibility to "not yet eligible", and queues the balance it held as a
/// [`electra::PendingDeposit`].
///
/// Not itself a named helper in `specs/electra/beacon-chain.md`. It is
/// extracted verbatim from a loop body in `specs/electra/fork.md`'s
/// `upgrade_to_electra`, which applies exactly this to every not-yet-active
/// validator at the electra fork boundary rather than losing its balance:
/// [`switch_to_compounding_validator`] and [`queue_excess_active_balance`]
/// already queue a validator's *excess* balance the same way, and the fork
/// upgrade needs the same construction for a validator's *entire* balance,
/// so this factors the shared shape into one function rather than
/// duplicating the pending-deposit literal at both call sites.
pub fn queue_entire_balance_and_reset_validator(
    state: &mut BeaconState,
    index: ValidatorIndex,
) -> Result<()> {
    let balance = state.balance(index)?;
    // See `queue_excess_active_balance` for why this cannot fail.
    *state.balance_mut(index)? = 0;

    let validator = state.validator_mut(index)?;
    validator.effective_balance = 0;
    validator.activation_eligibility_epoch = FAR_FUTURE_EPOCH;

    let deposit = placeholder_pending_deposit(state.validator(index)?, balance);
    pending_queue_fields(state, "queue_entire_balance_and_reset_validator")?
        .push_pending_deposit(deposit)
}

// ---------------------------------------------------------------------------
// Fork projection
// ---------------------------------------------------------------------------

/// The compressed encoding of the identity element of G2
/// (`specs/altair/bls.md`'s `G2_POINT_AT_INFINITY`), used as the placeholder
/// signature on a synthetic pending deposit that never carried a real proof
/// of possession.
///
/// [`crate::beacon::bls`] keeps its own copy of this same encoding for
/// `eth_fast_aggregate_verify`'s empty-committee case, but does not export
/// it, so this file builds its own rather than reaching into that module's
/// internals.
///
/// `pub(crate)`: gloas's
/// [`crate::beacon::stf::gloas::process_execution_payload_bid`] requires a
/// self-built bid to carry exactly this signature, since a self-build is
/// not signed by a builder.
pub(crate) fn g2_point_at_infinity() -> BlsSignature {
    let mut bytes = [0u8; BLS_SIGNATURE_SIZE];
    // The top two bits are the compression and infinity flags; setting both
    // and leaving every other bit zero is the point at infinity's compressed
    // encoding.
    bytes[0] = 0b1100_0000;
    BlsSignature(bytes)
}

/// A [`electra::PendingDeposit`] standing in for a balance that never
/// belonged to a real, signed deposit: the shared shape
/// [`queue_excess_active_balance`] and
/// [`queue_entire_balance_and_reset_validator`] both build, differing only in
/// how much balance they queue.
fn placeholder_pending_deposit(validator: &Validator, amount: Gwei) -> electra::PendingDeposit {
    electra::PendingDeposit {
        pubkey: validator.pubkey,
        withdrawal_credentials: validator.withdrawal_credentials,
        amount,
        signature: g2_point_at_infinity(),
        slot: constants::GENESIS_SLOT,
    }
}

/// Fields the execution-layer-triggered request processors gloas leaves
/// unmodified need, gathered from wherever they sit on electra's, fulu's, or
/// gloas's own state: `deposit_requests_start_index`, the
/// `deposit_balance_to_consume` churn cursor, a new validator's empty
/// participation and inactivity entries
/// ([`Self::push_empty_participation_and_inactivity`]), and the
/// three pending queues (`pending_deposits`, `pending_partial_withdrawals`,
/// `pending_consolidations`), both as element-level slice views (`len()`,
/// `iter()`/`get()` through the returned `&[T]`, one-at-a-time `push_*`) and
/// as a whole (`take_*`/`set_*`, for epoch processing's own whole-queue
/// drains).
///
/// Electra's, fulu's, and gloas's `pending_deposits` (and the other two
/// queues) share one element type each but not one container: electra's and
/// fulu's is the bounded `SszList` (`electra::PendingDeposits` and friends),
/// gloas's is EIP-7688's unbounded [`libssz_types::ProgressiveList`]
/// (`crate::beacon::containers::gloas::PendingDeposits` and friends). Both
/// deref to `[T]` with the same element type, which is what lets the
/// slice-view and element-`push_*` methods below serve all three forks
/// through one match rather than needing a gloas copy of every caller.
///
/// Epoch processing's whole-queue drains and the block-level request
/// processors (`crate::beacon::stf::electra`'s `process_deposit_request`
/// and friends) share this one projection rather than each keeping a
/// near-identical one.
///
/// Deliberately separate from [`ChurnCursorsMut`]: that one carries the four
/// exit/consolidation churn cursor fields, which nothing here reads or
/// writes, and every gloas caller that needs those reaches them through
/// `ChurnCursorsMut` directly, not through this projection.
pub(crate) enum PendingQueueFields<'a> {
    Electra(&'a mut electra::BeaconState),
    Fulu(&'a mut fulu::BeaconState),
    Gloas(&'a mut gloas::BeaconState),
}

impl<'a> PendingQueueFields<'a> {
    /// The execution-layer deposit request index at which the state switched
    /// from crediting deposits off `Eth1Data` votes to crediting them off
    /// `DepositRequest`s directly, read by
    /// `crate::beacon::stf::epoch::electra::drain_pending_deposits` to know
    /// whether any eth1-bridge deposit is still outstanding.
    ///
    /// `pub(crate)`: fulu's own tests read this to assert a test state starts
    /// with it at [`crate::beacon::constants::UNSET_DEPOSIT_REQUESTS_START_INDEX`].
    /// Fulu's and gloas's `process_pending_deposits` retire the gate that
    /// uses it, so the drain reads it only for electra.
    pub(crate) fn deposit_requests_start_index(&self) -> u64 {
        match self {
            PendingQueueFields::Electra(state) => state.deposit_requests_start_index,
            PendingQueueFields::Fulu(state) => state.deposit_requests_start_index,
            PendingQueueFields::Gloas(state) => state.deposit_requests_start_index,
        }
    }

    /// How much of this epoch's deposit balance churn limit remains unused.
    pub(crate) fn deposit_balance_to_consume(&self) -> Gwei {
        match self {
            PendingQueueFields::Electra(state) => state.deposit_balance_to_consume,
            PendingQueueFields::Fulu(state) => state.deposit_balance_to_consume,
            PendingQueueFields::Gloas(state) => state.deposit_balance_to_consume,
        }
    }

    pub(crate) fn deposit_balance_to_consume_mut(&mut self) -> &mut Gwei {
        match self {
            PendingQueueFields::Electra(state) => &mut state.deposit_balance_to_consume,
            PendingQueueFields::Fulu(state) => &mut state.deposit_balance_to_consume,
            PendingQueueFields::Gloas(state) => &mut state.deposit_balance_to_consume,
        }
    }

    /// Queues one more [`electra::PendingDeposit`], pushed by
    /// [`queue_excess_active_balance`], [`queue_entire_balance_and_reset_validator`],
    /// and the deposit-request processors. Infallible on gloas's unbounded
    /// queue; electra's and fulu's bounded one can still reject a length over
    /// its own SSZ limit.
    pub(crate) fn push_pending_deposit(&mut self, deposit: electra::PendingDeposit) -> Result<()> {
        match self {
            PendingQueueFields::Electra(state) => state.pending_deposits.push(deposit)?,
            PendingQueueFields::Fulu(state) => state.pending_deposits.push(deposit)?,
            PendingQueueFields::Gloas(state) => state.pending_deposits.push(deposit),
        }
        Ok(())
    }

    /// Takes the whole pending-deposits queue out, leaving an empty one
    /// behind; [`Self::set_pending_deposits`] puts a (possibly shorter) one
    /// back. `Vec`-level, the same shape
    /// [`Self::take_pending_consolidations`]/[`Self::set_pending_consolidations`]
    /// already use, for the same reason:
    /// `crate::beacon::stf::epoch::electra::drain_pending_deposits` needs
    /// to drain the whole queue into a `Vec` it can freely mutate `state`
    /// around, not a reference still borrowing it.
    pub(crate) fn take_pending_deposits(&mut self) -> Vec<electra::PendingDeposit> {
        match self {
            PendingQueueFields::Electra(state) => {
                core::mem::take(&mut state.pending_deposits).into_inner()
            }
            PendingQueueFields::Fulu(state) => {
                core::mem::take(&mut state.pending_deposits).into_inner()
            }
            PendingQueueFields::Gloas(state) => {
                core::mem::take(&mut state.pending_deposits).into_inner()
            }
        }
    }

    /// See [`Self::take_pending_deposits`]. Fallible only for electra's and
    /// fulu's bounded `SszList`; gloas's progressive one never rejects a
    /// length.
    pub(crate) fn set_pending_deposits(
        &mut self,
        deposits: Vec<electra::PendingDeposit>,
    ) -> Result<()> {
        match self {
            PendingQueueFields::Electra(state) => {
                state.pending_deposits = electra::PendingDeposits::try_from(deposits)?;
            }
            PendingQueueFields::Fulu(state) => {
                state.pending_deposits = electra::PendingDeposits::try_from(deposits)?;
            }
            PendingQueueFields::Gloas(state) => {
                state.pending_deposits = gloas::PendingDeposits::from(deposits);
            }
        }
        Ok(())
    }

    /// Partial withdrawals queued but not yet paid out, as a slice. Read by
    /// [`get_pending_balance_to_withdraw`] and by
    /// [`crate::beacon::stf::electra::process_withdrawal_request`]'s own queue-length
    /// check.
    pub(crate) fn pending_partial_withdrawals(&self) -> &[electra::PendingPartialWithdrawal] {
        match self {
            PendingQueueFields::Electra(state) => &state.pending_partial_withdrawals,
            PendingQueueFields::Fulu(state) => &state.pending_partial_withdrawals,
            PendingQueueFields::Gloas(state) => &state.pending_partial_withdrawals,
        }
    }

    /// Queues one more [`electra::PendingPartialWithdrawal`], pushed by
    /// [`crate::beacon::stf::electra::process_withdrawal_request`].
    pub(crate) fn push_pending_partial_withdrawal(
        &mut self,
        withdrawal: electra::PendingPartialWithdrawal,
    ) -> Result<()> {
        match self {
            PendingQueueFields::Electra(state) => {
                state.pending_partial_withdrawals.push(withdrawal)?
            }
            PendingQueueFields::Fulu(state) => {
                state.pending_partial_withdrawals.push(withdrawal)?
            }
            PendingQueueFields::Gloas(state) => state.pending_partial_withdrawals.push(withdrawal),
        }
        Ok(())
    }

    /// Queued consolidations, as a slice. Read by
    /// [`crate::beacon::stf::electra::process_consolidation_request`]'s own queue-length
    /// check.
    pub(crate) fn pending_consolidations(&self) -> &[electra::PendingConsolidation] {
        match self {
            PendingQueueFields::Electra(state) => &state.pending_consolidations,
            PendingQueueFields::Fulu(state) => &state.pending_consolidations,
            PendingQueueFields::Gloas(state) => &state.pending_consolidations,
        }
    }

    /// Queues one more [`electra::PendingConsolidation`], pushed by
    /// [`crate::beacon::stf::electra::process_consolidation_request`].
    pub(crate) fn push_pending_consolidation(
        &mut self,
        consolidation: electra::PendingConsolidation,
    ) -> Result<()> {
        match self {
            PendingQueueFields::Electra(state) => {
                state.pending_consolidations.push(consolidation)?
            }
            PendingQueueFields::Fulu(state) => state.pending_consolidations.push(consolidation)?,
            PendingQueueFields::Gloas(state) => state.pending_consolidations.push(consolidation),
        }
        Ok(())
    }

    /// Takes the whole pending-consolidations queue out, leaving an empty one
    /// behind; [`Self::set_pending_consolidations`] puts a (possibly
    /// shorter) one back. `Vec`-level, alongside the element-level
    /// [`Self::pending_consolidations`]/[`Self::push_pending_consolidation`],
    /// because `crate::beacon::stf::epoch::electra::process_pending_consolidations`
    /// needs the whole queue in a `Vec` it can freely mutate `state` around
    /// while draining it, not a reference still borrowing it.
    pub(crate) fn take_pending_consolidations(&mut self) -> Vec<electra::PendingConsolidation> {
        match self {
            PendingQueueFields::Electra(state) => {
                core::mem::take(&mut state.pending_consolidations).into_inner()
            }
            PendingQueueFields::Fulu(state) => {
                core::mem::take(&mut state.pending_consolidations).into_inner()
            }
            PendingQueueFields::Gloas(state) => {
                core::mem::take(&mut state.pending_consolidations).into_inner()
            }
        }
    }

    /// See [`Self::take_pending_consolidations`]. Fallible only for electra's
    /// and fulu's bounded `SszList`; gloas's progressive one never rejects a
    /// length.
    pub(crate) fn set_pending_consolidations(
        &mut self,
        consolidations: Vec<electra::PendingConsolidation>,
    ) -> Result<()> {
        match self {
            PendingQueueFields::Electra(state) => {
                state.pending_consolidations =
                    electra::PendingConsolidations::try_from(consolidations)?;
            }
            PendingQueueFields::Fulu(state) => {
                state.pending_consolidations =
                    electra::PendingConsolidations::try_from(consolidations)?;
            }
            PendingQueueFields::Gloas(state) => {
                state.pending_consolidations = gloas::PendingConsolidations::from(consolidations);
            }
        }
        Ok(())
    }

    /// Extends `previous_epoch_participation`, `current_epoch_participation`,
    /// and `inactivity_scores` by one all-zero entry each, keeping them
    /// exactly as long as the registry after a new validator is appended.
    ///
    /// Gloas's own three lists are progressive (`libssz_types::ProgressiveList`),
    /// so their `push` is infallible, unlike electra's and fulu's bounded
    /// `SszList`.
    pub(crate) fn push_empty_participation_and_inactivity(&mut self) -> Result<()> {
        match self {
            PendingQueueFields::Electra(state) => {
                state.previous_epoch_participation.push(0)?;
                state.current_epoch_participation.push(0)?;
                state.inactivity_scores.push(0)?;
            }
            PendingQueueFields::Fulu(state) => {
                state.previous_epoch_participation.push(0)?;
                state.current_epoch_participation.push(0)?;
                state.inactivity_scores.push(0)?;
            }
            PendingQueueFields::Gloas(state) => {
                state.previous_epoch_participation.push(0);
                state.current_epoch_participation.push(0);
                state.inactivity_scores.push(0);
            }
        }
        Ok(())
    }
}

/// The electra, fulu, or gloas state, mutably, through [`PendingQueueFields`].
/// See that enum's own doc for why gloas joins electra and fulu here.
pub(crate) fn pending_queue_fields<'a>(
    state: &'a mut BeaconState,
    function: &'static str,
) -> Result<PendingQueueFields<'a>> {
    match state {
        BeaconState::Electra(state) => Ok(PendingQueueFields::Electra(state)),
        BeaconState::Fulu(state) => Ok(PendingQueueFields::Fulu(state)),
        BeaconState::Gloas(state) => Ok(PendingQueueFields::Gloas(state)),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

/// The read-only counterpart of [`PendingQueueFields`], for a caller (like
/// [`get_pending_balance_to_withdraw`]) that only ever reads a pending queue
/// and so only ever holds a `&BeaconState`.
pub(crate) enum PendingQueueFieldsRef<'a> {
    Electra(&'a electra::BeaconState),
    Fulu(&'a fulu::BeaconState),
    Gloas(&'a gloas::BeaconState),
}

impl<'a> PendingQueueFieldsRef<'a> {
    pub(crate) fn pending_partial_withdrawals(&self) -> &[electra::PendingPartialWithdrawal] {
        match self {
            PendingQueueFieldsRef::Electra(state) => &state.pending_partial_withdrawals,
            PendingQueueFieldsRef::Fulu(state) => &state.pending_partial_withdrawals,
            PendingQueueFieldsRef::Gloas(state) => &state.pending_partial_withdrawals,
        }
    }
}

/// The electra, fulu, or gloas state, immutably. See [`pending_queue_fields`].
pub(crate) fn pending_queue_fields_ref<'a>(
    state: &'a BeaconState,
    function: &'static str,
) -> Result<PendingQueueFieldsRef<'a>> {
    match state {
        BeaconState::Electra(state) => Ok(PendingQueueFieldsRef::Electra(state)),
        BeaconState::Fulu(state) => Ok(PendingQueueFieldsRef::Fulu(state)),
        BeaconState::Gloas(state) => Ok(PendingQueueFieldsRef::Gloas(state)),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

/// Either fork whose state carries the four balance-churn cursor fields
/// (`earliest_exit_epoch`, `exit_balance_to_consume`,
/// `earliest_consolidation_epoch`, `consolidation_balance_to_consume`,
/// EIP-7251) unchanged: electra, fulu, or gloas, which keeps every one of
/// them at the same type (see `containers::gloas`'s module doc) even though
/// gloas redefines which churn limit feeds them
/// (`compute_exit_epoch_and_update_churn`,
/// [`get_consolidation_churn_limit_for_fork`]).
///
/// Deliberately separate from [`PendingQueueFields`]: that one carries the
/// deposit-balance churn cursor and the three pending queues, none of which
/// this projection reads or writes. This one carries only the four
/// exit/consolidation churn cursor fields.
pub(crate) enum ChurnCursorsMut<'a> {
    Electra(&'a mut electra::BeaconState),
    Fulu(&'a mut fulu::BeaconState),
    Gloas(&'a mut gloas::BeaconState),
}

impl<'a> ChurnCursorsMut<'a> {
    pub(crate) fn earliest_exit_epoch(&self) -> Epoch {
        match self {
            ChurnCursorsMut::Electra(state) => state.earliest_exit_epoch,
            ChurnCursorsMut::Fulu(state) => state.earliest_exit_epoch,
            ChurnCursorsMut::Gloas(state) => state.earliest_exit_epoch,
        }
    }

    pub(crate) fn earliest_exit_epoch_mut(&mut self) -> &mut Epoch {
        match self {
            ChurnCursorsMut::Electra(state) => &mut state.earliest_exit_epoch,
            ChurnCursorsMut::Fulu(state) => &mut state.earliest_exit_epoch,
            ChurnCursorsMut::Gloas(state) => &mut state.earliest_exit_epoch,
        }
    }

    pub(crate) fn exit_balance_to_consume(&self) -> Gwei {
        match self {
            ChurnCursorsMut::Electra(state) => state.exit_balance_to_consume,
            ChurnCursorsMut::Fulu(state) => state.exit_balance_to_consume,
            ChurnCursorsMut::Gloas(state) => state.exit_balance_to_consume,
        }
    }

    pub(crate) fn exit_balance_to_consume_mut(&mut self) -> &mut Gwei {
        match self {
            ChurnCursorsMut::Electra(state) => &mut state.exit_balance_to_consume,
            ChurnCursorsMut::Fulu(state) => &mut state.exit_balance_to_consume,
            ChurnCursorsMut::Gloas(state) => &mut state.exit_balance_to_consume,
        }
    }

    pub(crate) fn earliest_consolidation_epoch(&self) -> Epoch {
        match self {
            ChurnCursorsMut::Electra(state) => state.earliest_consolidation_epoch,
            ChurnCursorsMut::Fulu(state) => state.earliest_consolidation_epoch,
            ChurnCursorsMut::Gloas(state) => state.earliest_consolidation_epoch,
        }
    }

    pub(crate) fn earliest_consolidation_epoch_mut(&mut self) -> &mut Epoch {
        match self {
            ChurnCursorsMut::Electra(state) => &mut state.earliest_consolidation_epoch,
            ChurnCursorsMut::Fulu(state) => &mut state.earliest_consolidation_epoch,
            ChurnCursorsMut::Gloas(state) => &mut state.earliest_consolidation_epoch,
        }
    }

    pub(crate) fn consolidation_balance_to_consume(&self) -> Gwei {
        match self {
            ChurnCursorsMut::Electra(state) => state.consolidation_balance_to_consume,
            ChurnCursorsMut::Fulu(state) => state.consolidation_balance_to_consume,
            ChurnCursorsMut::Gloas(state) => state.consolidation_balance_to_consume,
        }
    }

    pub(crate) fn consolidation_balance_to_consume_mut(&mut self) -> &mut Gwei {
        match self {
            ChurnCursorsMut::Electra(state) => &mut state.consolidation_balance_to_consume,
            ChurnCursorsMut::Fulu(state) => &mut state.consolidation_balance_to_consume,
            ChurnCursorsMut::Gloas(state) => &mut state.consolidation_balance_to_consume,
        }
    }
}

/// The electra-or-fulu-or-gloas state, mutably, through [`ChurnCursorsMut`].
/// See that enum's own doc for why it exists apart from [`pending_queue_fields`].
pub(crate) fn churn_cursors_mut<'a>(
    state: &'a mut BeaconState,
    function: &'static str,
) -> Result<ChurnCursorsMut<'a>> {
    match state {
        BeaconState::Electra(state) => Ok(ChurnCursorsMut::Electra(state)),
        BeaconState::Fulu(state) => Ok(ChurnCursorsMut::Fulu(state)),
        BeaconState::Gloas(state) => Ok(ChurnCursorsMut::Gloas(state)),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::containers::shared::AttestationData;
    use crate::beacon::fork::ForkName;
    use crate::beacon::helpers::accessors::get_beacon_committee;

    /// An electra state with `count` fully active, full-balance validators,
    /// positioned the same way `crate::beacon::helpers::test_state::with_validators`
    /// positions its phase0 state: one epoch in, so the previous epoch and
    /// the block-root history window both have entries.
    ///
    /// A thin wrapper around the shared fork-parameterised builder: see
    /// [`crate::beacon::helpers::test_state::with_validators_at`] for the construction
    /// this and every other fork's test module used to duplicate.
    fn electra_state_with_validators(count: usize) -> BeaconState {
        crate::beacon::helpers::test_state::with_validators_at(ForkName::Electra, count)
    }

    /// A fulu state, otherwise identical to [`electra_state_with_validators`],
    /// used only to prove [`pending_queue_fields`]/[`pending_queue_fields_ref`]
    /// accept fulu too and are not accidentally scoped to `BeaconState::Electra`
    /// alone.
    fn fulu_state_with_validators(count: usize) -> BeaconState {
        crate::beacon::helpers::test_state::with_validators_at(ForkName::Fulu, count)
    }

    /// A gloas state, otherwise identical to [`electra_state_with_validators`],
    /// used to prove [`pending_queue_fields`]/[`pending_queue_fields_ref`]
    /// accept gloas too.
    fn gloas_state_with_validators(count: usize) -> BeaconState {
        crate::beacon::helpers::test_state::with_validators_at(ForkName::Gloas, count)
    }

    // -- Predicates ---------------------------------------------------------

    #[test]
    fn withdrawal_credential_predicates_read_the_prefix_byte() {
        let mut validator = Validator {
            withdrawal_credentials: Bytes32::ZERO,
            ..Default::default()
        };
        // 0x00: a raw BLS credential, before the validator has upgraded.
        assert!(!has_eth1_withdrawal_credential(&validator));
        assert!(!has_compounding_withdrawal_credential(&validator));
        assert!(!has_execution_withdrawal_credential(&validator));

        validator.withdrawal_credentials.0[0] = constants::ETH1_ADDRESS_WITHDRAWAL_PREFIX;
        assert!(has_eth1_withdrawal_credential(&validator));
        assert!(!has_compounding_withdrawal_credential(&validator));
        assert!(has_execution_withdrawal_credential(&validator));

        validator.withdrawal_credentials.0[0] = constants::COMPOUNDING_WITHDRAWAL_PREFIX;
        assert!(!has_eth1_withdrawal_credential(&validator));
        assert!(has_compounding_withdrawal_credential(&validator));
        assert!(has_execution_withdrawal_credential(&validator));
    }

    #[test]
    fn max_effective_balance_depends_on_the_compounding_credential() {
        let mut validator = Validator {
            withdrawal_credentials: Bytes32::ZERO,
            ..Default::default()
        };
        validator.withdrawal_credentials.0[0] = constants::ETH1_ADDRESS_WITHDRAWAL_PREFIX;
        assert_eq!(
            get_max_effective_balance(&validator),
            preset::MIN_ACTIVATION_BALANCE
        );

        validator.withdrawal_credentials.0[0] = constants::COMPOUNDING_WITHDRAWAL_PREFIX;
        assert_eq!(
            get_max_effective_balance(&validator),
            preset::MAX_EFFECTIVE_BALANCE_ELECTRA
        );
    }

    #[test]
    fn partially_withdrawable_requires_both_a_full_ceiling_and_excess_balance() {
        let mut validator = Validator {
            withdrawal_credentials: Bytes32::ZERO,
            effective_balance: preset::MIN_ACTIVATION_BALANCE,
            ..Default::default()
        };
        validator.withdrawal_credentials.0[0] = constants::ETH1_ADDRESS_WITHDRAWAL_PREFIX;

        assert!(!is_partially_withdrawable_validator(
            &validator,
            preset::MIN_ACTIVATION_BALANCE
        ));
        assert!(is_partially_withdrawable_validator(
            &validator,
            preset::MIN_ACTIVATION_BALANCE + 1
        ));

        // No longer sitting at its own ceiling, so no longer withdrawable
        // even with a nominally excess balance.
        validator.effective_balance = preset::MIN_ACTIVATION_BALANCE - 1;
        assert!(!is_partially_withdrawable_validator(
            &validator,
            preset::MIN_ACTIVATION_BALANCE + 1
        ));
    }

    #[test]
    fn activation_queue_eligibility_accepts_balance_at_or_above_the_minimum() {
        let mut validator = Validator {
            activation_eligibility_epoch: FAR_FUTURE_EPOCH,
            effective_balance: preset::MIN_ACTIVATION_BALANCE,
            ..Default::default()
        };
        assert!(is_eligible_for_activation_queue(&validator));

        // Unlike phase0's version (exact equality with MAX_EFFECTIVE_BALANCE),
        // electra also accepts a compounding validator's higher balance.
        validator.effective_balance = preset::MAX_EFFECTIVE_BALANCE_ELECTRA;
        assert!(is_eligible_for_activation_queue(&validator));

        validator.effective_balance = preset::MIN_ACTIVATION_BALANCE - 1;
        assert!(!is_eligible_for_activation_queue(&validator));
    }

    #[test]
    fn compute_proposer_index_prefers_a_full_balance_under_the_electra_ceiling() {
        let indices: Vec<ValidatorIndex> = (0..16).collect();
        let max = preset::MAX_EFFECTIVE_BALANCE_ELECTRA;

        let mut chose_the_rich_one = 0;
        for trial in 0..32u8 {
            let chosen = compute_proposer_index(&indices, Bytes32::repeat_byte(trial), |index| {
                Ok(if index == 3 { max } else { 1 })
            })
            .unwrap();
            if chosen == 3 {
                chose_the_rich_one += 1;
            }
        }
        assert!(
            chose_the_rich_one > 16,
            "the full-balance validator was chosen {chose_the_rich_one} times out of 32"
        );
    }

    #[test]
    fn compute_proposer_index_rejects_an_empty_set() {
        assert!(compute_proposer_index(&[], Bytes32::ZERO, |_| Ok(1)).is_err());
    }

    // -- Misc -----------------------------------------------------------

    #[test]
    fn get_committee_indices_lists_only_the_set_bits_in_ascending_order() {
        let mut bits = electra::CommitteeBits::default();
        // `CommitteeBits` is exactly `MAX_COMMITTEES_PER_SLOT` bits long, and
        // minimal's preset shrinks that bound far below mainnet's, so the
        // highest index this vector actually holds has to come from the
        // constant itself: a literal high enough to be interesting under
        // mainnet (e.g. 4) is out of bounds under minimal.
        let last = preset::MAX_COMMITTEES_PER_SLOT - 1;
        bits.set(last, true).unwrap();
        bits.set(1, true).unwrap();
        assert_eq!(
            get_committee_indices(&bits),
            vec![1, last as CommitteeIndex]
        );
    }

    // -- Beacon state accessors ----------------------------------------------

    #[test]
    fn activation_exit_and_consolidation_churn_partition_the_balance_churn_limit() {
        let config = Config::mainnet();
        let state = electra_state_with_validators(64);

        let balance_churn = get_balance_churn_limit(&state, &config).unwrap();
        let activation_exit_churn = get_activation_exit_churn_limit(&state, &config).unwrap();
        let consolidation_churn = get_consolidation_churn_limit(&state, &config).unwrap();

        assert_eq!(activation_exit_churn + consolidation_churn, balance_churn);
    }

    #[test]
    fn balance_churn_limit_respects_its_electra_floor() {
        let config = Config::mainnet();
        // A tiny active set falls below the proportional limit, so the
        // electra-specific floor applies, not phase0's smaller one.
        let state = electra_state_with_validators(4);
        assert_eq!(
            get_balance_churn_limit(&state, &config).unwrap(),
            config.min_per_epoch_churn_limit_electra,
        );
    }

    #[test]
    fn pending_balance_to_withdraw_sums_only_the_matching_validator() {
        let mut state = electra_state_with_validators(4);
        if let BeaconState::Electra(inner) = &mut state {
            inner.pending_partial_withdrawals = vec![
                electra::PendingPartialWithdrawal {
                    validator_index: 0,
                    amount: 10,
                    withdrawable_epoch: 5,
                },
                electra::PendingPartialWithdrawal {
                    validator_index: 1,
                    amount: 20,
                    withdrawable_epoch: 5,
                },
                electra::PendingPartialWithdrawal {
                    validator_index: 0,
                    amount: 30,
                    withdrawable_epoch: 6,
                },
            ]
            .try_into()
            .unwrap();
        } else {
            unreachable!("just built as Electra");
        }

        assert_eq!(get_pending_balance_to_withdraw(&state, 0).unwrap(), 40);
        assert_eq!(get_pending_balance_to_withdraw(&state, 1).unwrap(), 20);
        assert_eq!(get_pending_balance_to_withdraw(&state, 2).unwrap(), 0);
    }

    #[test]
    fn get_attesting_indices_returns_ascending_indices_across_noncontiguous_committees() {
        // Enough active validators that a slot splits into more than one
        // committee under either preset this module compiles for. Exactly how
        // many committees (and what size) `get_committee_count_per_slot`
        // lands on differs by preset: mainnet's larger `TARGET_COMMITTEE_SIZE`
        // but higher `MAX_COMMITTEES_PER_SLOT` ceiling divides this count one
        // way, minimal's smaller versions of both divide it another way. So
        // this test reads the committees it actually gets back rather than
        // asserting a size tied to one preset's arithmetic; what it exercises
        // is the committee-offset bookkeeping in `get_attesting_indices`, not
        // any preset's specific committee count or size. Fewer validators
        // would risk naming only one committee under some preset, which
        // cannot expose a misaligned offset.
        let count = 8192;
        let state = electra_state_with_validators(count);
        let slot = state.slot();

        // Committee indices 0 and 2, deliberately non-contiguous: naming
        // index 1's slot but skipping it must not shift where index 2's
        // segment starts in `aggregation_bits`. This needs at least three
        // committees per slot, true under both presets at this validator
        // count.
        let committee_0 = get_beacon_committee(&state, slot, 0).unwrap();
        let committee_2 = get_beacon_committee(&state, slot, 2).unwrap();
        assert!(!committee_0.is_empty(), "test needs a non-empty committee");
        // `count` divides evenly by the total committee count under both
        // presets, so every committee in this epoch is exactly the same
        // size; asserting that (rather than a preset-specific literal) is
        // what lets the rest of this test use `committee_0.len()` as the
        // offset into committee 2's segment.
        assert_eq!(committee_0.len(), committee_2.len());

        let mut committee_bits = electra::CommitteeBits::default();
        committee_bits.set(0, true).unwrap();
        committee_bits.set(2, true).unwrap();

        let mut aggregation_bits =
            electra::AggregationBits::with_length(committee_0.len() + committee_2.len()).unwrap();
        // Two members of the first named committee's own segment.
        aggregation_bits.set(0, true).unwrap();
        aggregation_bits.set(5, true).unwrap();
        // Two members of the second named committee, offset past the whole
        // first committee's segment (not past committee index 1's, which
        // this attestation never names and which must not consume any
        // offset at all).
        aggregation_bits.set(committee_0.len() + 3, true).unwrap();
        aggregation_bits
            .set(committee_0.len() + committee_2.len() - 1, true)
            .unwrap();

        let attestation = electra::Attestation {
            aggregation_bits,
            data: AttestationData {
                slot,
                ..Default::default()
            },
            signature: BlsSignature::default(),
            committee_bits,
        };

        let indices =
            get_attesting_indices(&state, &attestation, &CommitteeCache::default()).unwrap();

        let mut expected = vec![
            committee_0[0],
            committee_0[5],
            committee_2[3],
            committee_2[committee_2.len() - 1],
        ];
        expected.sort_unstable();

        assert_eq!(indices, expected);
        assert!(
            indices.windows(2).all(|pair| pair[0] < pair[1]),
            "get_attesting_indices must return a strictly ascending, duplicate-free list"
        );
    }

    #[test]
    fn get_indexed_attestation_carries_the_attesting_indices_and_signature() {
        // 16 validators split across a whole epoch's worth of committee slots
        // (32 under the mainnet preset) would leave most of those slots
        // empty; enough validators that every slot's single committee is
        // reliably non-empty is what this test actually needs.
        let state = electra_state_with_validators(1024);
        let slot = state.slot();
        let committee = get_beacon_committee(&state, slot, 0).unwrap();

        let mut committee_bits = electra::CommitteeBits::default();
        committee_bits.set(0, true).unwrap();
        let mut aggregation_bits = electra::AggregationBits::with_length(committee.len()).unwrap();
        aggregation_bits.set(0, true).unwrap();

        let attestation = electra::Attestation {
            aggregation_bits,
            data: AttestationData {
                slot,
                ..Default::default()
            },
            signature: BlsSignature([9; BLS_SIGNATURE_SIZE]),
            committee_bits,
        };

        let indexed =
            get_indexed_attestation(&state, &attestation, &CommitteeCache::default()).unwrap();
        assert_eq!(&*indexed.attesting_indices, &[committee[0]]);
        assert_eq!(indexed.signature, attestation.signature);
        assert_eq!(indexed.data, attestation.data);
    }

    #[test]
    fn next_sync_committee_indices_are_exactly_sync_committee_size() {
        let state = electra_state_with_validators(4);
        let indices = get_next_sync_committee_indices(&state).unwrap();
        assert_eq!(indices.len(), preset::SYNC_COMMITTEE_SIZE);
        assert!(indices.iter().all(|index| *index < 4));
    }

    // -- Beacon state mutators -----------------------------------------------

    #[test]
    fn initiate_validator_exit_is_idempotent_and_sets_withdrawable_epoch() {
        let config = Config::mainnet();
        let mut state = electra_state_with_validators(4);

        initiate_validator_exit(&mut state, 0, &config).unwrap();
        let first_exit_epoch = state.validator(0).unwrap().exit_epoch;
        assert_ne!(first_exit_epoch, FAR_FUTURE_EPOCH);
        assert_eq!(
            state.validator(0).unwrap().withdrawable_epoch,
            first_exit_epoch + config.min_validator_withdrawability_delay,
        );

        initiate_validator_exit(&mut state, 0, &config).unwrap();
        assert_eq!(state.validator(0).unwrap().exit_epoch, first_exit_epoch);
    }

    #[test]
    fn a_large_exit_consumes_more_than_one_epoch_of_churn() {
        let config = Config::mainnet();
        let mut state = electra_state_with_validators(4);

        let per_epoch_churn = get_activation_exit_churn_limit(&state, &config).unwrap();
        let baseline = compute_activation_exit_epoch(get_current_epoch(&state));

        let exit_epoch =
            compute_exit_epoch_and_update_churn(&mut state, per_epoch_churn * 2, &config).unwrap();
        assert!(exit_epoch > baseline);
    }

    #[test]
    fn two_small_exits_in_the_same_epoch_share_its_leftover_churn() {
        let config = Config::mainnet();
        let mut state = electra_state_with_validators(4);
        let per_epoch_churn = get_activation_exit_churn_limit(&state, &config).unwrap();

        let first_epoch =
            compute_exit_epoch_and_update_churn(&mut state, per_epoch_churn / 4, &config).unwrap();
        let second_epoch =
            compute_exit_epoch_and_update_churn(&mut state, per_epoch_churn / 4, &config).unwrap();

        // Together they are still under one epoch's churn limit, so the
        // cursor lets the second exit spend what the first left over instead
        // of always waiting for a fresh epoch.
        assert_eq!(first_epoch, second_epoch);
    }

    #[test]
    fn switch_to_compounding_validator_sets_the_prefix_and_queues_excess() {
        let mut state = electra_state_with_validators(4);
        *state.balance_mut(0).unwrap() = preset::MIN_ACTIVATION_BALANCE + 1_000_000_000;

        switch_to_compounding_validator(&mut state, 0).unwrap();

        assert!(has_compounding_withdrawal_credential(
            state.validator(0).unwrap()
        ));
        assert_eq!(state.balance(0).unwrap(), preset::MIN_ACTIVATION_BALANCE);
    }

    #[test]
    fn queue_excess_active_balance_caps_the_balance_and_queues_the_rest() {
        let mut state = electra_state_with_validators(4);
        let pubkey = state.validator(0).unwrap().pubkey;
        *state.balance_mut(0).unwrap() = preset::MIN_ACTIVATION_BALANCE + 5_000_000_000;

        queue_excess_active_balance(&mut state, 0).unwrap();

        assert_eq!(state.balance(0).unwrap(), preset::MIN_ACTIVATION_BALANCE);
        let BeaconState::Electra(inner) = &state else {
            unreachable!("just built as Electra");
        };
        assert_eq!(inner.pending_deposits.len(), 1);
        assert_eq!(inner.pending_deposits[0].amount, 5_000_000_000);
        assert_eq!(inner.pending_deposits[0].pubkey, pubkey);
    }

    #[test]
    fn queue_excess_active_balance_does_nothing_at_or_below_the_minimum() {
        let mut state = electra_state_with_validators(4);
        *state.balance_mut(0).unwrap() = preset::MIN_ACTIVATION_BALANCE;
        queue_excess_active_balance(&mut state, 0).unwrap();
        let BeaconState::Electra(inner) = &state else {
            unreachable!("just built as Electra");
        };
        assert!(inner.pending_deposits.is_empty());
    }

    #[test]
    fn queue_entire_balance_and_reset_validator_zeroes_the_validator() {
        let mut state = electra_state_with_validators(4);
        *state.balance_mut(0).unwrap() = 12_000_000_000;

        queue_entire_balance_and_reset_validator(&mut state, 0).unwrap();

        assert_eq!(state.balance(0).unwrap(), 0);
        let validator = state.validator(0).unwrap();
        assert_eq!(validator.effective_balance, 0);
        assert_eq!(validator.activation_eligibility_epoch, FAR_FUTURE_EPOCH);

        let BeaconState::Electra(inner) = &state else {
            unreachable!("just built as Electra");
        };
        assert_eq!(inner.pending_deposits.len(), 1);
        assert_eq!(inner.pending_deposits[0].amount, 12_000_000_000);
    }

    // -- Fork projection ------------------------------------------------------

    #[test]
    fn pending_queue_fields_ref_accepts_electra_fulu_and_gloas_but_not_phase0() {
        let electra_state_value = electra_state_with_validators(4);
        assert!(pending_queue_fields_ref(&electra_state_value, "test").is_ok());

        let fulu_state_value = fulu_state_with_validators(4);
        assert!(pending_queue_fields_ref(&fulu_state_value, "test").is_ok());

        let gloas_state_value = gloas_state_with_validators(4);
        assert!(pending_queue_fields_ref(&gloas_state_value, "test").is_ok());

        let phase0_state_value = crate::beacon::helpers::test_state::with_validators(4);
        assert!(pending_queue_fields_ref(&phase0_state_value, "test").is_err());
    }

    #[test]
    fn pending_queue_fields_accepts_electra_fulu_and_gloas_but_not_phase0() {
        let mut electra_state_value = electra_state_with_validators(4);
        assert!(pending_queue_fields(&mut electra_state_value, "test").is_ok());

        let mut fulu_state_value = fulu_state_with_validators(4);
        assert!(pending_queue_fields(&mut fulu_state_value, "test").is_ok());

        let mut gloas_state_value = gloas_state_with_validators(4);
        assert!(pending_queue_fields(&mut gloas_state_value, "test").is_ok());

        let mut phase0_state_value = crate::beacon::helpers::test_state::with_validators(4);
        assert!(pending_queue_fields(&mut phase0_state_value, "test").is_err());
    }

    #[test]
    fn get_pending_balance_to_withdraw_works_on_a_gloas_state() {
        let mut state = gloas_state_with_validators(4);
        {
            let mut fields = pending_queue_fields(&mut state, "test").unwrap();
            fields
                .push_pending_partial_withdrawal(electra::PendingPartialWithdrawal {
                    validator_index: 2,
                    amount: 7,
                    withdrawable_epoch: 0,
                })
                .unwrap();
        }
        assert_eq!(get_pending_balance_to_withdraw(&state, 2).unwrap(), 7);
        assert_eq!(get_pending_balance_to_withdraw(&state, 0).unwrap(), 0);
    }

    #[test]
    fn queue_excess_active_balance_works_on_a_gloas_state() {
        let mut state = gloas_state_with_validators(4);
        *state.balance_mut(0).unwrap() = preset::MIN_ACTIVATION_BALANCE + 5;

        queue_excess_active_balance(&mut state, 0).unwrap();

        assert_eq!(state.balance(0).unwrap(), preset::MIN_ACTIVATION_BALANCE);
        let BeaconState::Gloas(inner) = &state else {
            unreachable!("just built as Gloas");
        };
        assert_eq!(inner.pending_deposits.len(), 1);
        assert_eq!(inner.pending_deposits[0].amount, 5);
    }

    #[test]
    fn compute_exit_epoch_and_update_churn_works_on_a_fulu_state_too() {
        let config = Config::mainnet();
        let mut state = fulu_state_with_validators(4);
        let baseline = compute_activation_exit_epoch(get_current_epoch(&state));

        let exit_epoch = compute_exit_epoch_and_update_churn(&mut state, 1, &config).unwrap();
        assert_eq!(exit_epoch, baseline);
    }

    /// Gloas does not redefine `compute_consolidation_epoch_and_update_churn`
    /// itself: only its churn limit is gloas-modified
    /// ([`get_consolidation_churn_limit_for_fork`]). A gloas state must still
    /// go through this shared cursor update, fed gloas's own churn limit
    /// rather than electra's.
    ///
    /// 2048 validators: with mainnet's `CONSOLIDATION_CHURN_LIMIT_QUOTIENT`
    /// (the wider of the two configs this runs under, `Config::mainnet()`
    /// and `Config::minimal()`), that is exactly the active balance needed
    /// for gloas's independent, from-total-active-balance formula to clear
    /// one whole `EFFECTIVE_BALANCE_INCREMENT` rather than round down to
    /// zero.
    #[test]
    fn compute_consolidation_epoch_and_update_churn_uses_gloas_own_limit_on_a_gloas_state() {
        let config = Config::mainnet();
        let mut state =
            crate::beacon::helpers::test_state::with_validators_at(ForkName::Gloas, 2_048);
        let gloas_limit =
            crate::beacon::helpers::gloas::get_consolidation_churn_limit(&state, &config).unwrap();
        assert!(gloas_limit > 0, "the fixture must exercise a real budget");

        compute_consolidation_epoch_and_update_churn(&mut state, 1, &config).unwrap();

        let fields = churn_cursors_mut(&mut state, "test").unwrap();
        assert_eq!(fields.consolidation_balance_to_consume(), gloas_limit - 1);
    }

    /// Proves [`get_consolidation_churn_limit_for_fork`] actually
    /// discriminates: `process_consolidation_request`
    /// (`crate::beacon::stf::electra`) reads it too, so if it ever collapsed
    /// to always answering with electra's formula, a gloas state would
    /// silently mis-gate consolidation requests against the wrong budget.
    #[test]
    fn get_consolidation_churn_limit_for_fork_differs_between_electra_and_gloas() {
        let config = Config::minimal();
        let electra_state = electra_state_with_validators(64);
        let gloas_state =
            crate::beacon::helpers::test_state::with_validators_at(ForkName::Gloas, 64);

        let electra_limit =
            get_consolidation_churn_limit_for_fork(&electra_state, &config).unwrap();
        let gloas_limit = get_consolidation_churn_limit_for_fork(&gloas_state, &config).unwrap();

        assert_eq!(
            electra_limit,
            get_consolidation_churn_limit(&electra_state, &config).unwrap()
        );
        assert_eq!(
            gloas_limit,
            crate::beacon::helpers::gloas::get_consolidation_churn_limit(&gloas_state, &config)
                .unwrap()
        );
        assert_ne!(electra_limit, gloas_limit);
    }
}
