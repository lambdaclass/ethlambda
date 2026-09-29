//! Gloas's new and changed helper functions.
//!
//! Gloas bundles several EIPs (see `containers::gloas`'s own module doc for
//! the full list); this file carries the *behaviour* each one adds to the
//! specification's "Helpers" section, not the containers it reads and
//! writes.
//!
//! **EIP-7732 (ePBS)** is the largest of them, and most of what is below
//! belongs to it. A block no longer carries its own execution payload: a
//! proposer instead commits to a builder's [`gloas::ExecutionPayloadBid`],
//! and the builder reveals the payload afterward. That split introduces a
//! second registry ([`is_builder_index`], [`is_active_builder`],
//! [`is_builder_withdrawal_credential`], [`convert_builder_index_to_validator_index`],
//! [`convert_validator_index_to_builder_index`] all exist only because
//! builders and validators now share one index space, distinguished by a
//! single flag bit), a second escrow-and-payment accounting
//! ([`get_pending_balance_to_withdraw_for_builder`], [`can_builder_cover_bid`],
//! [`get_builder_payment_quorum_threshold`], [`initiate_builder_exit`],
//! [`settle_builder_payment`]), and a payload timeliness committee that votes
//! on whether the revealed payload showed up on time
//! ([`compute_ptc`], [`get_ptc`], [`get_indexed_payload_attestation`],
//! [`is_valid_indexed_payload_attestation`]). Because a payload can now be
//! revealed a slot late, [`is_attestation_same_slot`] and the payload-index
//! bit [`get_attestation_participation_flag_indices`] reads off
//! `execution_payload_availability` are what let an attester's head vote
//! still name which payload it is voting for.
//!
//! **EIP-8045** narrows the proposer draw
//! ([`get_beacon_proposer_indices`]) to unslashed validators only, and
//! **EIP-8061** replaces the combined activation/exit churn budget electra
//! shares between the two with independent ones
//! ([`get_activation_churn_limit`], [`get_exit_churn_limit`], both read
//! straight from `Config` rather than derived from one another the way
//! electra's [`super::electra::get_activation_exit_churn_limit`] and
//! [`super::electra::get_consolidation_churn_limit`] are).
//! [`super::electra::compute_exit_epoch_and_update_churn`] draws from
//! [`get_exit_churn_limit`]'s uncapped budget on a gloas state rather than
//! electra's combined one: gloas modifies that function by exactly the
//! per-epoch-churn line the specification's own diff shows, so it lives
//! there as a fork dispatch rather than as a copy of its own here; see that
//! function's own doc. [`get_consolidation_churn_limit`] is modified too,
//! independently derived from total active balance rather than left over
//! from the activation/exit split, and reached the same way, through
//! [`super::electra::get_consolidation_churn_limit_for_fork`].
//!
//! **[`compute_balance_weighted_selection`]** is the new sampling primitive
//! behind nearly every draw in this file: [`compute_proposer_indices`] (one
//! draw per slot), [`get_next_sync_committee_indices`] (`SYNC_COMMITTEE_SIZE`
//! draws), and [`compute_ptc`] (`PTC_SIZE` draws) all become thin callers of
//! it rather than each repeating electra's rejection-sampling loop
//! ([`super::electra::compute_proposer_index`],
//! [`super::electra::get_next_sync_committee_indices`]) with a different
//! candidate pool. It reuses a random 32-byte hash across up to 16
//! consecutive draws (recomputing only when a new hash is needed, exactly
//! where the specification's own `if offset == 0` guards it) rather than
//! hashing once per draw the way electra's loop does; ported statement for
//! statement, not simplified into always rehashing, since the two only
//! produce the same bytes because the guard is there.
//!
//! # The fork projection
//!
//! [`gloas_state`] and [`gloas_state_ref`] project a [`BeaconState`] down to
//! gloas's own concrete struct, for functions that mix a gloas-only field
//! with others reached through fork-invariant accessors ([`get_ptc`]'s
//! `ptc_window`, [`get_attestation_participation_flag_indices`]'s
//! `execution_payload_availability`). Functions whose *every* read is
//! gloas-only instead take a [`gloas::BeaconState`] directly
//! ([`is_active_builder`], [`get_pending_balance_to_withdraw_for_builder`],
//! [`can_builder_cover_bid`], [`initiate_builder_exit`],
//! [`settle_builder_payment`]): nothing in them needs a fork-invariant
//! accessor at all, so the caller (already holding a state it knows is
//! gloas) passes the concrete type straight through rather than this module
//! projecting it back out again. Functions that only ever read fields
//! shared with every fork (the registry, `finalized_checkpoint`, block
//! roots, ...) take a [`BeaconState`] and reach those fields through its
//! own fork-invariant accessors, the same split [`super::fulu`]'s module
//! doc draws for its own two kinds of function.
//!
//! The four balance-churn cursor fields are none of these three: their type
//! is shared with electra and fulu, so
//! [`super::electra::compute_exit_epoch_and_update_churn`] and
//! [`super::electra::compute_consolidation_epoch_and_update_churn`] reach
//! them through `helpers::electra`'s own `ChurnCursorsMut` instead of a
//! projection here; see that enum's own doc. `proposer_lookahead` is
//! likewise shared with fulu (unchanged, see `containers::gloas`'s module
//! doc), read through [`super::fulu::get_beacon_proposer_index`] rather
//! than a copy of it here.

use crate::beacon::bls;
use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::shared::AttestationData;
use crate::beacon::containers::{BeaconState, electra, gloas};
use crate::beacon::error::{Error, Result};
use crate::beacon::hash::hash;
use crate::beacon::preset;
use crate::beacon::primitives::{
    BlsPubkey, Bytes32, Epoch, ExecutionAddress, Gwei, HashTreeRoot as _, Slot, ValidatorIndex,
};

use super::accessors::{
    CommitteeCache, CommitteeCacheExt, get_active_validator_indices, get_block_root,
    get_block_root_at_slot, get_current_epoch, get_domain, get_seed, get_total_active_balance,
};
use super::math::{bytes_to_uint64, integer_squareroot};
use super::misc::{compute_epoch_at_slot, compute_signing_root, compute_start_slot_at_epoch};
use super::predicates::are_indices_sorted_and_unique;
use super::shuffling::compute_shuffled_index;

// ---------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------

/// Whether an indexed attestation names a valid attester set and carries
/// their aggregate signature.
///
/// Modified from [`super::electra::is_valid_indexed_attestation`] (EIP-7688):
/// [`gloas::IndexedAttestation::attesting_indices`] is now the unbounded
/// [`gloas::AttestingIndices`], so the length that used to be enforced by the
/// container's own SSZ bound (`MAX_VALIDATORS_PER_SLOT`) is checked here
/// explicitly instead.
pub fn is_valid_indexed_attestation(
    state: &BeaconState,
    indexed_attestation: &gloas::IndexedAttestation,
) -> bool {
    let indices: &[ValidatorIndex] = &indexed_attestation.attesting_indices;
    if indices.is_empty()
        || indices.len() > preset::MAX_VALIDATORS_PER_SLOT
        || !are_indices_sorted_and_unique(indices)
    {
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
// Attestations
// ---------------------------------------------------------------------------

/// The committee members whose bit is set in `attestation`, in ascending
/// order.
///
/// Not modified by gloas's own `beacon-chain.md` (which names no
/// `get_attesting_indices` of its own): [`gloas::Attestation`]'s
/// [`gloas::AggregationBits`] is a different Rust type from
/// [`super::electra::get_attesting_indices`]'s bounded bitlist (EIP-7688), but
/// that is the one thing
/// [`super::electra::attesting_indices_from_committee_bits`] already
/// abstracts over (see its own doc), so this is a thin wrapper over that
/// shared walk, the same shape electra's own `get_attesting_indices` is.
/// `committee_bits` is untouched by the EIP-7688 change ([`gloas::Attestation`]
/// reuses [`electra::CommitteeBits`] outright, see `containers::gloas`'s own
/// module doc), which is what lets both forks share one walk over one type.
pub fn get_attesting_indices(
    state: &BeaconState,
    attestation: &gloas::Attestation,
    committees: &CommitteeCache,
) -> Result<Vec<ValidatorIndex>> {
    super::electra::attesting_indices_from_committee_bits(
        state,
        attestation.data.slot,
        &attestation.committee_bits,
        |bit| attestation.aggregation_bits.get(bit).unwrap_or(false),
        committees,
    )
}

/// The same attestation with its attesters named rather than bit-encoded.
///
/// See [`get_attesting_indices`] for why this is gloas's own copy rather than
/// a call into electra's: [`gloas::IndexedAttestation::attesting_indices`] is
/// the unbounded [`gloas::AttestingIndices`] (`ProgressiveList`), which is
/// built with `From<Vec<_>>` rather than electra's bounds-checked
/// `TryFrom<Vec<_>>`, since a progressive list has no maximum length to
/// exceed.
pub fn get_indexed_attestation(
    state: &BeaconState,
    attestation: &gloas::Attestation,
    committees: &CommitteeCache,
) -> Result<gloas::IndexedAttestation> {
    let indices = get_attesting_indices(state, attestation, committees)?;
    Ok(gloas::IndexedAttestation {
        attesting_indices: gloas::AttestingIndices::from(indices),
        data: attestation.data,
        signature: attestation.signature,
    })
}

/// Whether `validator_index` actually names a [`gloas::BuilderIndex`]
/// (EIP-7732): builders and validators share one index space, distinguished
/// by this one bit.
pub fn is_builder_index(validator_index: ValidatorIndex) -> bool {
    (validator_index & constants::BUILDER_INDEX_FLAG) != 0
}

/// Whether the builder at `builder_index` is active: its placement in the
/// registry is finalized, and it has not initiated an exit.
pub fn is_active_builder(
    state: &gloas::BeaconState,
    builder_index: gloas::BuilderIndex,
) -> Result<bool> {
    let builder = state
        .builders
        .get(builder_index as usize)
        .ok_or(Error::IndexOutOfBounds {
            index: builder_index as usize,
            len: state.builders.len(),
        })?;
    Ok(
        // Placement in builder list is finalized.
        builder.deposit_epoch < state.finalized_checkpoint.epoch
        // Has not initiated exit.
        && builder.withdrawable_epoch == constants::FAR_FUTURE_EPOCH,
    )
}

/// Whether `withdrawal_credentials` is builder-prefixed
/// ([`constants::BUILDER_WITHDRAWAL_PREFIX`]).
pub fn is_builder_withdrawal_credential(withdrawal_credentials: Bytes32) -> bool {
    withdrawal_credentials.0[0] == constants::BUILDER_WITHDRAWAL_PREFIX
}

/// Whether `data` attests to the block proposed at its own slot, rather than
/// to a slot skipped since.
///
/// A payload can be revealed a slot late (EIP-7732), so
/// [`get_attestation_participation_flag_indices`] needs to know whether an
/// attester's payload vote (`data.index`) is about *this* slot's block or an
/// earlier one's, which is what this decides: slot 0 always counts (there is
/// no earlier slot to have skipped from), and otherwise the attested root
/// must both match the block actually proposed at `data.slot` and differ
/// from the one at the slot before it, i.e. `data.slot` was not itself
/// skipped.
pub fn is_attestation_same_slot(state: &BeaconState, data: &AttestationData) -> Result<bool> {
    if data.slot == 0 {
        return Ok(true);
    }

    let block_root = data.beacon_block_root;
    let slot_block_root = get_block_root_at_slot(state, data.slot)?;
    let prev_block_root = get_block_root_at_slot(state, data.slot - 1)?;

    Ok(block_root == slot_block_root && block_root != prev_block_root)
}

/// Whether an indexed payload attestation names a non-empty, sorted attester
/// set and carries their aggregate signature.
///
/// Unlike [`is_valid_indexed_attestation`], a payload timeliness committee's
/// attesting indices need only be sorted, not deduplicated: the payload
/// timeliness committee ([`compute_ptc`]) is drawn with replacement, so the
/// same validator can legitimately hold more than one seat and so appear
/// more than once.
pub fn is_valid_indexed_payload_attestation(
    state: &BeaconState,
    attestation: &gloas::IndexedPayloadAttestation,
) -> bool {
    let indices: &[ValidatorIndex] = &attestation.attesting_indices;
    if indices.is_empty() || !indices.windows(2).all(|pair| pair[0] <= pair[1]) {
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
        constants::DOMAIN_PTC_ATTESTER,
        Some(compute_epoch_at_slot(attestation.data.slot)),
    );
    let signing_root = compute_signing_root(attestation.data.hash_tree_root(), domain);
    bls::fast_aggregate_verify(&pubkeys, signing_root, &attestation.signature)
}

/// Whether a pending deposit with a valid signature is already queued for
/// `pubkey`.
///
/// *Note (from the specification):* this naively reverifies a deposit
/// signature on every call; a caller iterating many pubkeys should cache the
/// verification instead of calling this in a loop.
pub fn is_pending_validator(
    pending_deposits: &[electra::PendingDeposit],
    pubkey: BlsPubkey,
    config: &Config,
) -> bool {
    for pending_deposit in pending_deposits {
        if pending_deposit.pubkey != pubkey {
            continue;
        }
        if crate::beacon::stf::electra::is_valid_deposit_signature(
            pending_deposit.pubkey,
            pending_deposit.withdrawal_credentials,
            pending_deposit.amount,
            &pending_deposit.signature,
            config,
        ) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

/// The [`ValidatorIndex`] a [`gloas::BuilderIndex`] is addressed as in a
/// context (like a `Withdrawal`) that only ever names validators.
pub fn convert_builder_index_to_validator_index(
    builder_index: gloas::BuilderIndex,
) -> ValidatorIndex {
    builder_index | constants::BUILDER_INDEX_FLAG
}

/// The inverse of [`convert_builder_index_to_validator_index`].
pub fn convert_validator_index_to_builder_index(
    validator_index: ValidatorIndex,
) -> gloas::BuilderIndex {
    validator_index & !constants::BUILDER_INDEX_FLAG
}

/// The balance still owed to `builder_index` by withdrawals already queued,
/// whether settled into [`gloas::BeaconState::builder_pending_withdrawals`]
/// or still sitting in an unsettled
/// [`gloas::BeaconState::builder_pending_payments`] entry.
///
/// [`can_builder_cover_bid`] subtracts this from a builder's balance before
/// checking it can cover a new bid, so a builder cannot bid its way into
/// double-spending a balance a withdrawal has already claimed.
pub fn get_pending_balance_to_withdraw_for_builder(
    state: &gloas::BeaconState,
    builder_index: gloas::BuilderIndex,
) -> Result<Gwei> {
    let mut balance: Gwei = 0;
    for withdrawal in state.builder_pending_withdrawals.iter() {
        if withdrawal.builder_index == builder_index {
            balance = balance
                .checked_add(withdrawal.amount)
                .ok_or(Error::ArithmeticOverflow(
                    "get_pending_balance_to_withdraw_for_builder: balance + withdrawal.amount",
                ))?;
        }
    }
    for payment in state.builder_pending_payments.iter() {
        if payment.withdrawal.builder_index == builder_index {
            balance = balance.checked_add(payment.withdrawal.amount).ok_or(
                Error::ArithmeticOverflow(
                    "get_pending_balance_to_withdraw_for_builder: balance + payment.withdrawal.amount",
                ),
            )?;
        }
    }
    Ok(balance)
}

/// Whether the builder at `builder_index` can cover a bid of `bid_amount`,
/// after keeping [`preset::MIN_DEPOSIT_AMOUNT`] and every balance it already
/// owes ([`get_pending_balance_to_withdraw_for_builder`]) in reserve.
pub fn can_builder_cover_bid(
    state: &gloas::BeaconState,
    builder_index: gloas::BuilderIndex,
    bid_amount: Gwei,
) -> Result<bool> {
    let builder_balance = state
        .builders
        .get(builder_index as usize)
        .ok_or(Error::IndexOutOfBounds {
            index: builder_index as usize,
            len: state.builders.len(),
        })?
        .balance;
    let pending_withdrawals_amount =
        get_pending_balance_to_withdraw_for_builder(state, builder_index)?;
    let min_balance = preset::MIN_DEPOSIT_AMOUNT
        .checked_add(pending_withdrawals_amount)
        .ok_or(Error::ArithmeticOverflow(
            "can_builder_cover_bid: MIN_DEPOSIT_AMOUNT + pending_withdrawals_amount",
        ))?;
    if builder_balance < min_balance {
        return Ok(false);
    }
    Ok(builder_balance - min_balance >= bid_amount)
}

/// `size` indices sampled from `indices` by effective balance, with possible
/// duplicates.
///
/// The rejection-sampling primitive behind [`compute_proposer_indices`],
/// [`get_next_sync_committee_indices`], and [`compute_ptc`]: a candidate is
/// drawn (shuffled from `indices` when `shuffle_indices`, or taken in order
/// otherwise) and accepted with probability proportional to its effective
/// balance, exactly [`super::electra::compute_proposer_index`]'s acceptance
/// test, generalised to keep drawing until `size` candidates are accepted
/// rather than stopping at the first.
///
/// Reuses one 32-byte random hash across up to 16 consecutive draws
/// (`sha256(seed + i / 16)` has 16 two-byte slices), recomputing only when
/// `i % 16 == 0`, which is why `random_bytes` is threaded through the loop
/// rather than recomputed every iteration the way
/// [`super::electra::compute_proposer_index`]'s does: both give the same
/// bytes for the same `i`, since the hash input only depends on `i / 16`, but
/// this follows the specification's own guard rather than always rehashing.
pub fn compute_balance_weighted_selection(
    state: &BeaconState,
    indices: &[ValidatorIndex],
    seed: Bytes32,
    size: u64,
    shuffle_indices: bool,
) -> Result<Vec<ValidatorIndex>> {
    // `2**16 - 1`, the largest value a two-byte little-endian draw can take.
    const MAX_RANDOM_VALUE: u64 = u16::MAX as u64;

    let total = indices.len() as u64;
    crate::beacon::verify(total > 0, "compute_balance_weighted_selection: total > 0")?;

    let mut effective_balances = Vec::with_capacity(indices.len());
    for index in indices {
        effective_balances.push(state.validator(*index)?.effective_balance);
    }

    let mut selected = Vec::new();
    let mut random_bytes = Bytes32::ZERO;
    let mut i: u64 = 0;
    while (selected.len() as u64) < size {
        let offset = (i % 16) * 2;
        if offset == 0 {
            let mut input = Vec::with_capacity(32 + 8);
            input.extend_from_slice(&seed.0);
            input.extend_from_slice(&(i / 16).to_le_bytes());
            random_bytes = hash(&input);
        }

        let mut next_index = i % total;
        if shuffle_indices {
            next_index = compute_shuffled_index(next_index, total, seed)?;
        }

        let weight = effective_balances[next_index as usize]
            .checked_mul(MAX_RANDOM_VALUE)
            .ok_or(Error::ArithmeticOverflow(
                "compute_balance_weighted_selection: effective_balance * MAX_RANDOM_VALUE",
            ))?;
        let random_value = bytes_to_uint64(&random_bytes.0[offset as usize..offset as usize + 2]);
        let threshold = preset::MAX_EFFECTIVE_BALANCE_ELECTRA * random_value;
        if weight >= threshold {
            selected.push(indices[next_index as usize]);
        }
        i += 1;
    }
    Ok(selected)
}

/// The proposer for every slot of `epoch`, drawn from `indices` under `seed`.
///
/// Modified from [`super::fulu::compute_proposer_indices`] (EIP-7732): each
/// slot's single proposer now comes from [`compute_balance_weighted_selection`]
/// (`size = 1`, shuffled) rather than
/// [`super::electra::compute_proposer_index`]'s own rejection-sampling loop,
/// otherwise identical, including reusing that per-slot hash (`slot_seed`,
/// the specification's shadowed `seed`) as the selection's own seed rather
/// than the epoch seed passed in.
pub fn compute_proposer_indices(
    state: &BeaconState,
    epoch: Epoch,
    seed: Bytes32,
    indices: &[ValidatorIndex],
) -> Result<Vec<ValidatorIndex>> {
    let start_slot = compute_start_slot_at_epoch(epoch);

    let mut proposer_indices = Vec::with_capacity(preset::SLOTS_PER_EPOCH as usize);
    for offset in 0..preset::SLOTS_PER_EPOCH {
        let slot = start_slot
            .checked_add(offset)
            .ok_or(Error::ArithmeticOverflow(
                "compute_proposer_indices: start_slot + offset",
            ))?;
        let mut input = Vec::with_capacity(32 + 8);
        input.extend_from_slice(&seed.0);
        input.extend_from_slice(&slot.to_le_bytes());
        let slot_seed = hash(&input);

        let selected = compute_balance_weighted_selection(state, indices, slot_seed, 1, true)?;
        proposer_indices.push(
            *selected
                .first()
                .expect("compute_balance_weighted_selection(size=1) returns exactly one index"),
        );
    }
    Ok(proposer_indices)
}

/// The payload timeliness committee, with possible duplicates, for `slot`.
///
/// Concatenates every one of `slot`'s own committees (`0..committees_per_slot`)
/// and samples [`preset::PTC_SIZE`] members from that pool by effective
/// balance.
/// `shuffle_indices=false`: each committee is already a shuffled slice of
/// the active set (the same split [`CommitteeCache`] draws attester
/// committees from), so walking the concatenated pool in order still draws
/// from a shuffled ordering; a second shuffle here would just reorder
/// already-shuffled input.
///
/// Takes `committees` rather than deriving each committee itself
/// (`get_beacon_committee`, one active-set scan and one per-member shuffle
/// apiece): [`crate::beacon::stf::epoch::gloas::process_ptc_window`] calls this
/// once per slot of an epoch, and at mainnet scale that is `SLOTS_PER_EPOCH`
/// calls against a multi-million-validator registry, so sharing one
/// epoch-wide shuffle across all of them (see [`CommitteeCache`]'s own doc) is
/// what keeps that affordable; [`super::electra::get_attesting_indices`] takes
/// the same parameter for the same reason.
pub fn compute_ptc(
    state: &BeaconState,
    slot: Slot,
    committees: &CommitteeCache,
) -> Result<gloas::PayloadTimelinessCommittee> {
    let epoch = compute_epoch_at_slot(slot);
    let mut input = Vec::with_capacity(32 + 8);
    input.extend_from_slice(&get_seed(state, epoch, constants::DOMAIN_PTC_ATTESTER).0);
    input.extend_from_slice(&slot.to_le_bytes());
    let seed = hash(&input);

    let epoch_committees = committees.committees(state, epoch);
    let mut indices = Vec::new();
    for committee_index in 0..epoch_committees.committees_per_slot() {
        indices.extend(epoch_committees.committee(slot, committee_index)?);
    }

    let selected =
        compute_balance_weighted_selection(state, &indices, seed, preset::PTC_SIZE as u64, false)?;
    Ok(selected.try_into()?)
}

// ---------------------------------------------------------------------------
// Beacon state accessors
// ---------------------------------------------------------------------------

/// The proposer indices for `epoch`.
///
/// Modified from [`super::fulu::get_beacon_proposer_indices`] (EIP-8045): the
/// candidate pool excludes slashed validators before the draw, rather than
/// only after, so this call's own draw can never select an already-slashed
/// validator. It does not reach back into a window slot this same call did
/// not compute: a validator slashed after its lookahead entry was already
/// filled still stands in that entry, unrevised, until the window slides
/// forward and recomputes it.
pub fn get_beacon_proposer_indices(
    state: &BeaconState,
    epoch: Epoch,
) -> Result<Vec<ValidatorIndex>> {
    let mut indices = Vec::new();
    for index in get_active_validator_indices(state, epoch) {
        if !state.validator(index)?.slashed {
            indices.push(index);
        }
    }
    let seed = get_seed(state, epoch, constants::DOMAIN_BEACON_PROPOSER);
    compute_proposer_indices(state, epoch, seed, &indices)
}

/// The sync committee indices, with possible duplicates, for the sync
/// committee period starting next epoch.
///
/// Modified from [`super::electra::get_next_sync_committee_indices`]
/// (EIP-7732): the draw is now [`compute_balance_weighted_selection`] rather
/// than a repeated inline rejection-sampling loop, otherwise identical
/// (same seed, same candidate pool, same ceiling).
pub fn get_next_sync_committee_indices(state: &BeaconState) -> Result<Vec<ValidatorIndex>> {
    let epoch = get_current_epoch(state) + 1;
    let seed = get_seed(state, epoch, constants::DOMAIN_SYNC_COMMITTEE);
    let indices = get_active_validator_indices(state, epoch);
    compute_balance_weighted_selection(
        state,
        &indices,
        seed,
        preset::SYNC_COMMITTEE_SIZE as u64,
        true,
    )
}

/// Which of the three participation flags an attestation with `data`,
/// included after `inclusion_delay` slots against a block whose parent was
/// at `parent_slot`, satisfies.
///
/// Modified from [`super::altair::get_attestation_participation_flag_indices`]
/// (EIP-7732): matching the head now also requires the attested payload
/// status to match. A same-slot attestation (`is_attestation_same_slot`)
/// must vote `data.index == 0`; otherwise the vote is checked against
/// `execution_payload_availability` at *`parent_slot`*, not `data.slot`,
/// since the timely-head flag's own minimum-inclusion-delay requirement
/// already ties it to the parent block, and a skipped `data.slot` has no
/// payload availability of its own to read. The timely-target flag also
/// carries no `inclusion_delay <= SLOTS_PER_EPOCH` gate. That is not a
/// gloas change: the gate was already dropped at deneb (EIP-7045, which
/// widened the attestation inclusion window; see
/// `crate::beacon::stf::deneb::attestation_participation_flag_indices`), so
/// its absence here is inherited from deneb onward, unlike altair's own
/// version, which still carries it.
pub fn get_attestation_participation_flag_indices(
    state: &BeaconState,
    data: &AttestationData,
    inclusion_delay: u64,
    parent_slot: Slot,
) -> Result<Vec<usize>> {
    // Matching source.
    let justified_checkpoint = if data.target.epoch == get_current_epoch(state) {
        state.current_justified_checkpoint()
    } else {
        state.previous_justified_checkpoint()
    };
    let is_matching_source = data.source == justified_checkpoint;

    // Matching target.
    let target_root = get_block_root(state, data.target.epoch)?;
    let target_root_matches = data.target.root == target_root;
    let is_matching_target = is_matching_source && target_root_matches;

    // Matching payload.
    let payload_matches = if is_attestation_same_slot(state, data)? {
        crate::beacon::verify(
            data.index == 0,
            "get_attestation_participation_flag_indices: data.index == 0",
        )?;
        true
    } else {
        let inner = gloas_state_ref(state, "get_attestation_participation_flag_indices")?;
        let slot_index = (parent_slot % preset::SLOTS_PER_HISTORICAL_ROOT as u64) as usize;
        let payload_index = inner.execution_payload_availability.get(slot_index).ok_or(
            Error::IndexOutOfBounds {
                index: slot_index,
                len: inner.execution_payload_availability.len(),
            },
        )?;
        data.index == payload_index as u64
    };

    // Matching head.
    let head_root = get_block_root_at_slot(state, data.slot)?;
    let head_root_matches = data.beacon_block_root == head_root;
    let is_matching_head = is_matching_target && head_root_matches && payload_matches;

    crate::beacon::verify(
        is_matching_source,
        "get_attestation_participation_flag_indices: is_matching_source",
    )?;

    let mut participation_flag_indices = Vec::new();
    if is_matching_source && inclusion_delay <= integer_squareroot(preset::SLOTS_PER_EPOCH) {
        participation_flag_indices.push(constants::TIMELY_SOURCE_FLAG_INDEX);
    }
    if is_matching_target {
        participation_flag_indices.push(constants::TIMELY_TARGET_FLAG_INDEX);
    }
    if is_matching_head && inclusion_delay == preset::MIN_ATTESTATION_INCLUSION_DELAY {
        participation_flag_indices.push(constants::TIMELY_HEAD_FLAG_INDEX);
    }

    Ok(participation_flag_indices)
}

/// The payload timeliness committee for `slot`.
///
/// Unlike [`compute_ptc`] (which always derives one fresh), this reads the
/// cached window [`gloas::BeaconState::ptc_window`]
/// [`crate::beacon::stf::epoch::gloas::process_ptc_window`] refreshes each epoch:
/// `slot`'s epoch must be the state's own, the one before it, or within
/// [`preset::MIN_SEED_LOOKAHEAD`] epochs ahead, which is exactly the window's
/// own span.
pub fn get_ptc(
    state: &BeaconState,
    slot: Slot,
    config: &Config,
) -> Result<gloas::PayloadTimelinessCommittee> {
    let epoch = compute_epoch_at_slot(slot);
    crate::beacon::verify(
        epoch >= config.gloas_fork_epoch,
        "get_ptc: epoch >= GLOAS_FORK_EPOCH",
    )?;
    let state_epoch = get_current_epoch(state);
    let inner = gloas_state_ref(state, "get_ptc")?;

    let index =
        if epoch < state_epoch {
            let next_epoch = epoch
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("get_ptc: epoch + 1"))?;
            crate::beacon::verify(
                next_epoch == state_epoch,
                "get_ptc: epoch + 1 == state_epoch",
            )?;
            (slot % preset::SLOTS_PER_EPOCH) as usize
        } else {
            let lookahead_bound = state_epoch.checked_add(preset::MIN_SEED_LOOKAHEAD).ok_or(
                Error::ArithmeticOverflow("get_ptc: state_epoch + MIN_SEED_LOOKAHEAD"),
            )?;
            crate::beacon::verify(
                epoch <= lookahead_bound,
                "get_ptc: epoch <= state_epoch + MIN_SEED_LOOKAHEAD",
            )?;
            let epoch_offset = epoch
                .checked_sub(state_epoch)
                .and_then(|delta| delta.checked_add(1))
                .ok_or(Error::ArithmeticOverflow(
                    "get_ptc: epoch - state_epoch + 1",
                ))?;
            let offset = epoch_offset.checked_mul(preset::SLOTS_PER_EPOCH).ok_or(
                Error::ArithmeticOverflow("get_ptc: (epoch - state_epoch + 1) * SLOTS_PER_EPOCH"),
            )?;
            offset
                .checked_add(slot % preset::SLOTS_PER_EPOCH)
                .ok_or(Error::ArithmeticOverflow(
                    "get_ptc: offset + slot % SLOTS_PER_EPOCH",
                ))? as usize
        };

    inner
        .ptc_window
        .get(index)
        .cloned()
        .ok_or(Error::IndexOutOfBounds {
            index,
            len: inner.ptc_window.len(),
        })
}

/// The same payload attestation with its attesters named rather than
/// bit-encoded, the payload-attestation counterpart of
/// [`super::electra::get_indexed_attestation`].
pub fn get_indexed_payload_attestation(
    state: &BeaconState,
    payload_attestation: &gloas::PayloadAttestation,
    config: &Config,
) -> Result<gloas::IndexedPayloadAttestation> {
    let slot = payload_attestation.data.slot;
    let ptc = get_ptc(state, slot, config)?;
    let bits = &payload_attestation.aggregation_bits;

    let mut attesting_indices = Vec::new();
    for (index, validator_index) in ptc.iter().enumerate() {
        if bits.get(index).unwrap_or(false) {
            attesting_indices.push(*validator_index);
        }
    }
    attesting_indices.sort_unstable();

    Ok(gloas::IndexedPayloadAttestation {
        attesting_indices: attesting_indices.try_into()?,
        data: payload_attestation.data,
        signature: payload_attestation.signature,
    })
}

/// The attesting weight a builder payment needs before
/// [`crate::beacon::stf::epoch::gloas::process_builder_pending_payments`] settles
/// it in full rather than dropping it: [`constants::BUILDER_PAYMENT_THRESHOLD_NUMERATOR`]
/// `/` [`constants::BUILDER_PAYMENT_THRESHOLD_DENOMINATOR`] of one slot's
/// share of the total active balance.
pub fn get_builder_payment_quorum_threshold(state: &BeaconState) -> Result<Gwei> {
    let per_slot_balance = get_total_active_balance(state)? / preset::SLOTS_PER_EPOCH;
    let quorum = per_slot_balance
        .checked_mul(constants::BUILDER_PAYMENT_THRESHOLD_NUMERATOR)
        .ok_or(Error::ArithmeticOverflow(
            "get_builder_payment_quorum_threshold: per_slot_balance * BUILDER_PAYMENT_THRESHOLD_NUMERATOR",
        ))?;
    Ok(quorum / constants::BUILDER_PAYMENT_THRESHOLD_DENOMINATOR)
}

/// The per-epoch churn limit for activations, in Gwei.
///
/// New in gloas (EIP-8061): unlike electra's combined
/// [`super::electra::get_activation_exit_churn_limit`] (a share of one
/// budget split with exits), this is its own independent proportion of total
/// active balance, floored at [`Config::min_per_epoch_churn_limit_electra`]
/// and capped at [`Config::max_per_epoch_activation_churn_limit_gloas`].
pub fn get_activation_churn_limit(state: &BeaconState, config: &Config) -> Result<Gwei> {
    let total_active_balance = get_total_active_balance(state)?;
    let churn = config
        .min_per_epoch_churn_limit_electra
        .max(total_active_balance / config.churn_limit_quotient_gloas);
    let churn = churn - churn % preset::EFFECTIVE_BALANCE_INCREMENT;
    Ok(config.max_per_epoch_activation_churn_limit_gloas.min(churn))
}

/// The per-epoch churn limit for exits, in Gwei.
///
/// New in gloas (EIP-8061): the same proportion and floor as
/// [`get_activation_churn_limit`], but with no upper cap of its own, unlike
/// activations. electra's
/// [`compute_exit_epoch_and_update_churn`](super::electra::compute_exit_epoch_and_update_churn)
/// draws from this on a gloas state
/// rather than electra's combined budget.
pub fn get_exit_churn_limit(state: &BeaconState, config: &Config) -> Result<Gwei> {
    let total_active_balance = get_total_active_balance(state)?;
    let churn = config
        .min_per_epoch_churn_limit_electra
        .max(total_active_balance / config.churn_limit_quotient_gloas);
    Ok(churn - churn % preset::EFFECTIVE_BALANCE_INCREMENT)
}

/// The per-epoch churn limit reserved for consolidations, in Gwei.
///
/// Modified from [`super::electra::get_consolidation_churn_limit`]: no longer
/// left over from the activation/exit split, but its own independent
/// proportion of total active balance. [`Config::consolidation_churn_limit_quotient`]
/// is itself new in gloas: electra's own consolidation limit has no
/// quotient of its own to read, only the combined-budget split this
/// replaces. Floored at zero rather than at
/// [`Config::min_per_epoch_churn_limit_electra`] the way the activation and
/// exit limits are.
pub fn get_consolidation_churn_limit(state: &BeaconState, config: &Config) -> Result<Gwei> {
    let total_active_balance = get_total_active_balance(state)?;
    let churn = total_active_balance / config.consolidation_churn_limit_quotient;
    Ok(churn - churn % preset::EFFECTIVE_BALANCE_INCREMENT)
}

// ---------------------------------------------------------------------------
// Beacon state mutators
// ---------------------------------------------------------------------------

/// Starts the exit of the builder at `builder_index`: sets its withdrawable
/// epoch [`Config::min_builder_withdrawability_delay`] epochs out, the
/// builder-registry counterpart of
/// [`crate::beacon::helpers::mutators::initiate_validator_exit`].
pub fn initiate_builder_exit(
    state: &mut gloas::BeaconState,
    builder_index: gloas::BuilderIndex,
    config: &Config,
) -> Result<()> {
    let current_epoch = compute_epoch_at_slot(state.slot);
    let len = state.builders.len();
    let builder =
        state
            .builders
            .get_mut(builder_index as usize)
            .ok_or(Error::IndexOutOfBounds {
                index: builder_index as usize,
                len,
            })?;
    builder.withdrawable_epoch = current_epoch
        .checked_add(config.min_builder_withdrawability_delay)
        .ok_or(Error::ArithmeticOverflow(
            "initiate_builder_exit: current_epoch + MIN_BUILDER_WITHDRAWABILITY_DELAY",
        ))?;
    Ok(())
}

/// Settles (or drops) one builder payment: pushes its withdrawal onto
/// [`gloas::BeaconState::builder_pending_withdrawals`] if it carries a real
/// amount, then clears the slot.
///
/// Called by [`crate::beacon::stf::gloas::apply_parent_execution_payload`]
/// (parent-payload block processing; gloas `beacon-chain.md`'s "Settle the
/// builder payment"), not by
/// [`crate::beacon::stf::epoch::gloas::process_builder_pending_payments`]: that
/// epoch step evicts and settles the *older* half of `builder_pending_payments`
/// by weight, against [`get_builder_payment_quorum_threshold`]; this settles
/// one parent block's still-live entry unconditionally, the moment that
/// block's payload is applied.
pub fn settle_builder_payment(state: &mut gloas::BeaconState, payment_index: u64) -> Result<()> {
    let len = state.builder_pending_payments.len() as u64;
    crate::beacon::verify(
        payment_index < len,
        "settle_builder_payment: payment index in range",
    )?;
    let payment = state.builder_pending_payments[payment_index as usize].clone();
    if payment.withdrawal.amount > 0 {
        state.builder_pending_withdrawals.push(payment.withdrawal);
    }
    state.builder_pending_payments[payment_index as usize] =
        gloas::BuilderPendingPayment::default();
    Ok(())
}

// ---------------------------------------------------------------------------
// Builder registry (EIP-8282)
// ---------------------------------------------------------------------------

/// `get_index_for_new_builder` (gloas `beacon-chain.md`).
///
/// The registry slot a new builder record can reuse: an already-exited,
/// fully swept builder (`withdrawable_epoch` past, balance zero), or, absent
/// one, the registry's own length, so [`add_builder_to_registry`]'s
/// `set_or_append_list` appends a fresh entry instead of overwriting one.
/// Builder indices are reusable this way, unlike the validator registry,
/// which never removes an entry.
pub fn get_index_for_new_builder(state: &gloas::BeaconState) -> gloas::BuilderIndex {
    let current_epoch = compute_epoch_at_slot(state.slot);
    for (index, builder) in state.builders.iter().enumerate() {
        if builder.withdrawable_epoch <= current_epoch && builder.balance == 0 {
            return index as gloas::BuilderIndex;
        }
    }
    state.builders.len() as gloas::BuilderIndex
}

/// `add_builder_to_registry` (gloas `beacon-chain.md`).
///
/// Registers a new builder record at [`get_index_for_new_builder`]'s slot
/// (the specification's `set_or_append_list`: an append when that slot is
/// the registry's own length, an overwrite of a reused, exited slot
/// otherwise), and returns the index the record now lives at, so a caller
/// keeping its own index of the registry (`onboard_builders_from_pending_deposits`'s
/// pubkey-to-index map, `crate::beacon::upgrade`) can update it without a
/// second lookup. Called from that one-time fork-boundary onboarding pass
/// and from builder deposit requests (EIP-8282's ongoing onboarding path).
pub fn add_builder_to_registry(
    state: &mut gloas::BeaconState,
    pubkey: BlsPubkey,
    version: u8,
    execution_address: ExecutionAddress,
    amount: Gwei,
    slot: Slot,
) -> gloas::BuilderIndex {
    let index = get_index_for_new_builder(state);
    let builder = gloas::Builder {
        pubkey,
        version,
        execution_address,
        balance: amount,
        deposit_epoch: compute_epoch_at_slot(slot),
        withdrawable_epoch: constants::FAR_FUTURE_EPOCH,
    };
    if index == state.builders.len() as gloas::BuilderIndex {
        state.builders.push(builder);
    } else {
        state.builders[index as usize] = builder;
    }
    index
}

// ---------------------------------------------------------------------------
// Fork projection
// ---------------------------------------------------------------------------

/// The gloas state, mutably, or an error naming the function that needs one.
///
/// Kept alongside [`gloas_state_ref`] for mutating a gloas-only field
/// through a generic [`BeaconState`] rather than one already known to be
/// [`BeaconState::Gloas`] the way [`initiate_builder_exit`] and
/// [`settle_builder_payment`] are always called with. The fork upgrade
/// (`crate::beacon::upgrade::upgrade_to_gloas`) and
/// [`crate::beacon::stf::epoch::gloas`] are its callers.
pub(crate) fn gloas_state<'a>(
    state: &'a mut BeaconState,
    function: &'static str,
) -> Result<&'a mut gloas::BeaconState> {
    match state {
        BeaconState::Gloas(inner) => Ok(inner),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

/// The gloas state, immutably. See [`gloas_state`].
pub(crate) fn gloas_state_ref<'a>(
    state: &'a BeaconState,
    function: &'static str,
) -> Result<&'a gloas::BeaconState> {
    match state {
        BeaconState::Gloas(inner) => Ok(inner),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::fork::ForkName;

    /// A gloas state with `count` fully active, full-balance validators,
    /// positioned the same way `crate::beacon::helpers::test_state::with_validators`
    /// positions its phase0 state.
    fn gloas_state_with_validators(count: usize) -> BeaconState {
        crate::beacon::helpers::test_state::with_validators_at(ForkName::Gloas, count)
    }

    #[test]
    fn compute_balance_weighted_selection_returns_exactly_size_indices_from_the_pool() {
        let state = gloas_state_with_validators(16);
        let indices: Vec<ValidatorIndex> = (0..16).collect();
        let selected =
            compute_balance_weighted_selection(&state, &indices, Bytes32::repeat_byte(7), 20, true)
                .unwrap();
        assert_eq!(selected.len(), 20);
        assert!(selected.iter().all(|index| *index < 16));
    }

    #[test]
    fn compute_balance_weighted_selection_rejects_an_empty_pool() {
        let state = gloas_state_with_validators(16);
        assert!(compute_balance_weighted_selection(&state, &[], Bytes32::ZERO, 1, true).is_err());
    }

    #[test]
    fn compute_balance_weighted_selection_is_deterministic_for_a_fixed_seed() {
        let state = gloas_state_with_validators(16);
        let indices: Vec<ValidatorIndex> = (0..16).collect();
        let seed = Bytes32::repeat_byte(3);
        let first = compute_balance_weighted_selection(&state, &indices, seed, 10, true).unwrap();
        let second = compute_balance_weighted_selection(&state, &indices, seed, 10, true).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn compute_ptc_returns_ptc_size_active_indices_deterministically() {
        // 64, not 16: with too few validators relative to `SLOTS_PER_EPOCH`,
        // a committee slices down to zero members (the whole active set
        // split `SLOTS_PER_EPOCH` ways leaves some slices empty), and the
        // current slot lands on exactly one of those under the mainnet
        // preset. 64 safely clears that under both presets:
        // `helpers::accessors`'s own committee tests use the same count for
        // the same reason.
        let count = 64;
        let state = gloas_state_with_validators(count);
        let slot = state.slot();
        let committees = CommitteeCache::default();

        let first = compute_ptc(&state, slot, &committees).unwrap();
        let second = compute_ptc(&state, slot, &committees).unwrap();

        assert_eq!(first.len(), preset::PTC_SIZE);
        assert_eq!(&first[..], &second[..]);
        assert!(first.iter().all(|index| (*index as usize) < count));
    }

    /// The module doc's claim that gloas's proposer draw is otherwise
    /// identical to electra's rejection-sampling loop, checked directly:
    /// `compute_balance_weighted_selection(.., size=1, shuffle_indices=true)`
    /// must select the exact same candidate `electra::compute_proposer_index`
    /// does, for the same indices, seed, and effective balances. Varied
    /// effective balances (not all equal), so the acceptance test actually
    /// discriminates between candidates instead of every candidate passing
    /// (or failing) the same way regardless of which byte a bug reads.
    /// Checked across many seeds, since the two loops could still coincide
    /// on any one seed by chance even with a subtly wrong offset.
    #[test]
    fn compute_balance_weighted_selection_size_one_shuffled_matches_electras_compute_proposer_index()
     {
        let count = 32;
        let mut state = gloas_state_with_validators(count);
        for index in 0..count as ValidatorIndex {
            state.validator_mut(index).unwrap().effective_balance =
                preset::EFFECTIVE_BALANCE_INCREMENT * (1 + index % 8);
        }
        let indices: Vec<ValidatorIndex> = (0..count as u64).collect();

        for seed_byte in 0..32u8 {
            let seed = Bytes32::repeat_byte(seed_byte);
            let expected =
                crate::beacon::helpers::electra::compute_proposer_index(&indices, seed, |index| {
                    Ok(state.validator(index)?.effective_balance)
                })
                .unwrap();
            let selected =
                compute_balance_weighted_selection(&state, &indices, seed, 1, true).unwrap();
            assert_eq!(selected, vec![expected], "seed byte {seed_byte}");
        }
    }

    /// The module doc's claim that gloas's sync committee draw is otherwise
    /// identical to electra's, checked directly: both functions read the
    /// exact same state (active indices, seed domain, effective balances),
    /// so they must return the exact same committee. Varied effective
    /// balances for the same reason the proposer-index equivalence test
    /// above uses them.
    #[test]
    fn get_next_sync_committee_indices_matches_electras_own_function_on_a_gloas_state() {
        let count = 32;
        let mut state = gloas_state_with_validators(count);
        for index in 0..count as ValidatorIndex {
            state.validator_mut(index).unwrap().effective_balance =
                preset::MAX_EFFECTIVE_BALANCE * (1 + index % 8);
        }

        let expected =
            crate::beacon::helpers::electra::get_next_sync_committee_indices(&state).unwrap();
        let actual = get_next_sync_committee_indices(&state).unwrap();
        assert_eq!(actual, expected);
    }

    /// `get_ptc`'s `epoch < state_epoch` branch: the only earlier epoch it
    /// ever accepts is `state_epoch - 1`, read from the window's first
    /// `SLOTS_PER_EPOCH` slice (index `0..SLOTS_PER_EPOCH`).
    #[test]
    fn get_ptc_reads_the_previous_epoch_slice_of_the_window() {
        let mut state = gloas_state_with_validators(4);
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 0);
        mark_ptc_window(&mut state);

        let state_epoch = get_current_epoch(&state);
        let previous_epoch_slot = compute_start_slot_at_epoch(state_epoch - 1);

        let committee = get_ptc(&state, previous_epoch_slot, &config).unwrap();
        assert_eq!(
            committee[0], 0,
            "window index 0 starts the previous-epoch slice"
        );
    }

    /// `get_ptc`'s `epoch >= state_epoch` branch, at its simplest offset
    /// (`epoch == state_epoch`): the window's second `SLOTS_PER_EPOCH` slice
    /// (index `SLOTS_PER_EPOCH..2*SLOTS_PER_EPOCH`).
    #[test]
    fn get_ptc_reads_the_current_epoch_slice_of_the_window() {
        let mut state = gloas_state_with_validators(4);
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 0);
        mark_ptc_window(&mut state);

        let state_epoch = get_current_epoch(&state);
        let current_epoch_slot = compute_start_slot_at_epoch(state_epoch);

        let committee = get_ptc(&state, current_epoch_slot, &config).unwrap();
        assert_eq!(
            committee[0],
            preset::SLOTS_PER_EPOCH,
            "window index SLOTS_PER_EPOCH starts the current-epoch slice"
        );
    }

    /// Fills every `ptc_window` entry with its own window index, repeated
    /// across the committee, so a test can tell which slice `get_ptc` read
    /// back out just by looking at the first element.
    fn mark_ptc_window(state: &mut BeaconState) {
        let BeaconState::Gloas(inner) = state else {
            unreachable!("built as Gloas");
        };
        for window_index in 0..preset::PTC_WINDOW_LENGTH {
            inner.ptc_window[window_index] = vec![window_index as u64; preset::PTC_SIZE]
                .try_into()
                .expect("built at exactly PTC_SIZE");
        }
    }

    /// An arbitrary builder record, active (not exited) at `state`'s current
    /// epoch: `get_index_for_new_builder`'s never-reusable case.
    fn active_builder() -> gloas::Builder {
        gloas::Builder {
            withdrawable_epoch: constants::FAR_FUTURE_EPOCH,
            balance: 1,
            ..Default::default()
        }
    }

    /// A builder exited and fully swept as of `current_epoch`: the one
    /// condition `get_index_for_new_builder` reuses a slot for.
    fn exited_swept_builder(current_epoch: Epoch) -> gloas::Builder {
        gloas::Builder {
            withdrawable_epoch: current_epoch,
            balance: 0,
            ..Default::default()
        }
    }

    #[test]
    fn get_index_for_new_builder_appends_past_an_empty_registry() {
        let BeaconState::Gloas(state) = gloas_state_with_validators(4) else {
            panic!("gloas_state_with_validators returns a gloas state");
        };
        assert_eq!(get_index_for_new_builder(&state), 0);
    }

    #[test]
    fn get_index_for_new_builder_appends_when_every_builder_is_still_active() {
        let BeaconState::Gloas(mut state) = gloas_state_with_validators(4) else {
            panic!("gloas_state_with_validators returns a gloas state");
        };
        state.builders.push(active_builder());
        state.builders.push(active_builder());
        assert_eq!(get_index_for_new_builder(&state), 2);
    }

    #[test]
    fn get_index_for_new_builder_reuses_an_exited_swept_slot() {
        let BeaconState::Gloas(mut state) = gloas_state_with_validators(4) else {
            panic!("gloas_state_with_validators returns a gloas state");
        };
        let current_epoch = compute_epoch_at_slot(state.slot);
        state.builders.push(active_builder());
        // The one reusable slot: exited (`withdrawable_epoch` already past)
        // and fully swept (balance zero).
        state.builders.push(exited_swept_builder(current_epoch));
        state.builders.push(active_builder());
        assert_eq!(get_index_for_new_builder(&state), 1);
    }

    #[test]
    fn get_index_for_new_builder_does_not_reuse_an_exited_but_unswept_slot() {
        let BeaconState::Gloas(mut state) = gloas_state_with_validators(4) else {
            panic!("gloas_state_with_validators returns a gloas state");
        };
        let current_epoch = compute_epoch_at_slot(state.slot);
        // Withdrawable, but balance still nonzero: not yet swept, so not
        // reusable, even though the epoch condition alone holds.
        state.builders.push(gloas::Builder {
            withdrawable_epoch: current_epoch,
            balance: 1,
            ..Default::default()
        });
        assert_eq!(get_index_for_new_builder(&state), 1);
    }

    #[test]
    fn add_builder_to_registry_appends_and_returns_the_new_index() {
        let BeaconState::Gloas(mut state) = gloas_state_with_validators(4) else {
            panic!("gloas_state_with_validators returns a gloas state");
        };
        let pubkey = BlsPubkey([9; crate::beacon::primitives::BLS_PUBKEY_SIZE]);
        let len_before = state.builders.len();
        let slot = state.slot;

        let index = add_builder_to_registry(
            &mut state,
            pubkey,
            constants::PAYLOAD_BUILDER_VERSION,
            ExecutionAddress::ZERO,
            preset::MIN_DEPOSIT_AMOUNT,
            slot,
        );

        assert_eq!(index, len_before as gloas::BuilderIndex);
        assert_eq!(state.builders.len(), len_before + 1);
        assert_eq!(state.builders[index as usize].pubkey, pubkey);
    }

    #[test]
    fn add_builder_to_registry_overwrites_a_reused_slot_without_growing_the_registry() {
        let BeaconState::Gloas(mut state) = gloas_state_with_validators(4) else {
            panic!("gloas_state_with_validators returns a gloas state");
        };
        let current_epoch = compute_epoch_at_slot(state.slot);
        state.builders.push(exited_swept_builder(current_epoch));
        let len_before = state.builders.len();
        let pubkey = BlsPubkey([3; crate::beacon::primitives::BLS_PUBKEY_SIZE]);
        let slot = state.slot;

        let index = add_builder_to_registry(
            &mut state,
            pubkey,
            constants::PAYLOAD_BUILDER_VERSION,
            ExecutionAddress::ZERO,
            preset::MIN_DEPOSIT_AMOUNT,
            slot,
        );

        assert_eq!(index, 0);
        assert_eq!(
            state.builders.len(),
            len_before,
            "reuse must not grow the registry"
        );
        assert_eq!(state.builders[0].pubkey, pubkey);
        assert_eq!(
            state.builders[0].withdrawable_epoch,
            constants::FAR_FUTURE_EPOCH
        );
    }
}
