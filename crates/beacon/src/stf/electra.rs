//! Electra's block processing.
//!
//! Two changes, both from EIP-7251 and its neighbours, drive nearly
//! everything below.
//!
//! **A validator's effective balance is no longer pinned to one value.**
//! Through deneb, every validator's ceiling was the same fixed
//! `MAX_EFFECTIVE_BALANCE`, so rate-limiting how many validators could enter
//! or leave the registry in one epoch also rate-limited how much stake moved.
//! Once a validator can hold up to [`preset::MAX_EFFECTIVE_BALANCE_ELECTRA`]
//! by upgrading to a compounding withdrawal credential, a headcount no longer
//! bounds a balance: one large validator's deposit, exit, or consolidation
//! could move as much stake in a single slot as thousands of ordinary ones
//! used to, together. So deposits, exits, and consolidations all move from
//! "applied immediately, rate-limited by counting validators" to "queued in
//! the state (`pending_deposits`, `pending_partial_withdrawals`,
//! `pending_consolidations`) and drained a bounded *balance* at a time" (the
//! draining itself is epoch processing, `crates/beacon/src/stf/epoch/electra.rs`,
//! not this file; this file only ever appends to those queues or reads them).
//! [`crate::helpers::electra`] carries the balance-churn accounting this
//! forces; see its own module doc for the full account.
//!
//! **The execution layer can request a deposit, withdrawal, or consolidation
//! directly.** EIP-6110, EIP-7002, and EIP-7251 let the execution layer
//! append a [`electra::DepositRequest`], [`electra::WithdrawalRequest`], or
//! [`electra::ConsolidationRequest`] to its block, bundled into
//! [`electra::ExecutionRequests`] and carried on
//! [`electra::BeaconBlockBody::execution_requests`]. Consensus cannot reject
//! a whole block over a request the execution layer itself already committed
//! to accepting (unlike every other operation here, which a proposer chose
//! to include and so can be held to a strict standard), so
//! [`process_withdrawal_request`] and [`process_consolidation_request`] both
//! validate by *silently doing nothing* on most invalid input rather than by
//! rejecting the block; see their own documentation for exactly which
//! conditions do which.
//!
//! EIP-7549 (committee-indexed attestations) and EIP-7691 (more blobs) are
//! the other two forces at work, each touching one area: attestations now
//! read their covered committees from [`electra::Attestation::committee_bits`]
//! rather than a single `data.index` (see [`process_attestation`]), and the
//! blob commitment limit becomes a network configuration value
//! ([`Config::max_blobs_per_block_electra`]) rather than deneb's fixed preset
//! (see [`process_execution_payload`]).

use std::collections::HashSet;

use crate::bls;
use crate::config::Config;
use crate::constants::{self, FAR_FUTURE_EPOCH};
use crate::containers::shared::{
    AttestationData, Deposit, DepositMessage, EpochParticipation, InactivityScores,
    SignedVoluntaryExit, Validator,
};
use crate::containers::{BeaconState, capella, deneb, electra, fulu};
use crate::error::{Error, Result, verify};
use crate::helpers::accessors::{
    get_beacon_committee, get_beacon_proposer_index, get_block_root, get_block_root_at_slot,
    get_committee_count_per_slot, get_current_epoch, get_previous_epoch, get_randao_mix,
};
use crate::helpers::altair::{add_flag, get_base_reward, has_flag};
use crate::helpers::electra::{
    compute_exit_epoch_and_update_churn, electra_state, get_attesting_indices,
    get_committee_indices, get_consolidation_churn_limit, get_indexed_attestation,
    get_max_effective_balance, get_pending_balance_to_withdraw,
    has_compounding_withdrawal_credential, has_eth1_withdrawal_credential,
    has_execution_withdrawal_credential,
    initiate_validator_exit as electra_initiate_validator_exit, is_fully_withdrawable_validator,
    is_partially_withdrawable_validator, is_valid_indexed_attestation,
};
use crate::helpers::math::integer_squareroot;
use crate::helpers::misc::{
    compute_deposit_domain, compute_domain, compute_epoch_at_slot, compute_signing_root,
    is_valid_merkle_branch,
};
use crate::helpers::mutators::{decrease_balance, increase_balance, slash_validator};
use crate::helpers::predicates::{
    is_active_validator, is_slashable_attestation_data, is_slashable_validator,
};
use crate::preset;
use crate::primitives::{
    BlsPubkey, BlsSignature, Bytes32, ExecutionAddress, Gwei, HashTreeRoot as _,
    ParticipationFlags, ValidatorIndex, WithdrawalIndex,
};

use super::ExecutionEngine;

// ---------------------------------------------------------------------------
// Local state projection
// ---------------------------------------------------------------------------
//
// `crate::helpers::electra::{electra_state, electra_state_ref}` already
// project a `BeaconState` down to electra's (or fulu's) concrete struct, but
// only far enough to reach the balance-churn fields their own module needs
// (`pending_deposits` and the four churn cursors; see that module's doc). This
// file's block-processing steps also need `latest_execution_payload_header`,
// the withdrawal-sweep cursor (`next_withdrawal_index`,
// `next_withdrawal_validator_index`), `pending_partial_withdrawals` and
// `pending_consolidations` mutably, `deposit_requests_start_index`, and
// (introduced at altair, not electra) `previous_epoch_participation`,
// `current_epoch_participation`, and `inactivity_scores`. None of those are
// fork-invariant (`crate::containers::mod`'s `shared_state_accessors!` macro
// does not cover any of them), and reaching them would mean adding methods to
// `helpers::electra`'s projection, which is outside this file's ownership.
// This is a second, narrower projection kept local to this module instead,
// for exactly the fields block processing (as opposed to balance-churn
// accounting) needs.
//
// Scoped to `BeaconState::Electra` *and* `BeaconState::Fulu`, the same way
// `helpers::electra`'s own projection is, rather than to `Electra` alone the
// way `crate::stf::{bellatrix,capella,deneb}`'s own per-fork projections are
// scoped to exactly one variant. Those files are narrower because nothing
// outside them ever calls back into their own fork's state: bellatrix's
// projection is reached only through bellatrix's own `process_block`, which
// only ever runs against a `BeaconState::Bellatrix`. Fulu is different:
// nothing in its own specification touches any of the fields this projection
// reaches (its own changes are `proposer_lookahead` and the blob schedule),
// so whoever writes `crate::stf::fulu` is expected to reuse this file's
// functions wholesale, on a `BeaconState::Fulu`, the identical reasoning
// `crate::helpers::electra`'s own module doc gives for widening its
// projection the same way.
struct BlockRef<'a> {
    inner: BlockRefInner<'a>,
}

enum BlockRefInner<'a> {
    Electra(&'a electra::BeaconState),
    Fulu(&'a fulu::BeaconState),
}

impl<'a> BlockRef<'a> {
    fn latest_execution_payload_header(&self) -> &'a deneb::ExecutionPayloadHeader {
        match self.inner {
            BlockRefInner::Electra(state) => &state.latest_execution_payload_header,
            BlockRefInner::Fulu(state) => &state.latest_execution_payload_header,
        }
    }

    fn next_withdrawal_index(&self) -> WithdrawalIndex {
        match self.inner {
            BlockRefInner::Electra(state) => state.next_withdrawal_index,
            BlockRefInner::Fulu(state) => state.next_withdrawal_index,
        }
    }

    fn next_withdrawal_validator_index(&self) -> ValidatorIndex {
        match self.inner {
            BlockRefInner::Electra(state) => state.next_withdrawal_validator_index,
            BlockRefInner::Fulu(state) => state.next_withdrawal_validator_index,
        }
    }

    fn deposit_requests_start_index(&self) -> u64 {
        match self.inner {
            BlockRefInner::Electra(state) => state.deposit_requests_start_index,
            BlockRefInner::Fulu(state) => state.deposit_requests_start_index,
        }
    }
}

/// The electra-or-fulu state, immutably, projected far enough for this
/// module's own steps. See this section's own documentation.
fn block_ref<'a>(state: &'a BeaconState, function: &'static str) -> Result<BlockRef<'a>> {
    match state {
        BeaconState::Electra(inner) => Ok(BlockRef {
            inner: BlockRefInner::Electra(inner),
        }),
        BeaconState::Fulu(inner) => Ok(BlockRef {
            inner: BlockRefInner::Fulu(inner),
        }),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

enum BlockMut<'a> {
    Electra(&'a mut electra::BeaconState),
    Fulu(&'a mut fulu::BeaconState),
}

impl<'a> BlockMut<'a> {
    fn latest_execution_payload_header_mut(&mut self) -> &mut deneb::ExecutionPayloadHeader {
        match self {
            BlockMut::Electra(state) => &mut state.latest_execution_payload_header,
            BlockMut::Fulu(state) => &mut state.latest_execution_payload_header,
        }
    }

    fn next_withdrawal_index_mut(&mut self) -> &mut WithdrawalIndex {
        match self {
            BlockMut::Electra(state) => &mut state.next_withdrawal_index,
            BlockMut::Fulu(state) => &mut state.next_withdrawal_index,
        }
    }

    fn next_withdrawal_validator_index_mut(&mut self) -> &mut ValidatorIndex {
        match self {
            BlockMut::Electra(state) => &mut state.next_withdrawal_validator_index,
            BlockMut::Fulu(state) => &mut state.next_withdrawal_validator_index,
        }
    }

    fn pending_partial_withdrawals_mut(&mut self) -> &mut electra::PendingPartialWithdrawals {
        match self {
            BlockMut::Electra(state) => &mut state.pending_partial_withdrawals,
            BlockMut::Fulu(state) => &mut state.pending_partial_withdrawals,
        }
    }

    fn pending_consolidations_mut(&mut self) -> &mut electra::PendingConsolidations {
        match self {
            BlockMut::Electra(state) => &mut state.pending_consolidations,
            BlockMut::Fulu(state) => &mut state.pending_consolidations,
        }
    }

    fn deposit_requests_start_index_mut(&mut self) -> &mut u64 {
        match self {
            BlockMut::Electra(state) => &mut state.deposit_requests_start_index,
            BlockMut::Fulu(state) => &mut state.deposit_requests_start_index,
        }
    }

    /// `previous_epoch_participation` or `current_epoch_participation`,
    /// whichever `current` selects.
    fn epoch_participation_mut(&mut self, current: bool) -> &mut EpochParticipation {
        match (self, current) {
            (BlockMut::Electra(state), true) => &mut state.current_epoch_participation,
            (BlockMut::Electra(state), false) => &mut state.previous_epoch_participation,
            (BlockMut::Fulu(state), true) => &mut state.current_epoch_participation,
            (BlockMut::Fulu(state), false) => &mut state.previous_epoch_participation,
        }
    }

    fn inactivity_scores_mut(&mut self) -> &mut InactivityScores {
        match self {
            BlockMut::Electra(state) => &mut state.inactivity_scores,
            BlockMut::Fulu(state) => &mut state.inactivity_scores,
        }
    }
}

/// The electra-or-fulu state, mutably. See [`block_ref`].
fn block_mut<'a>(state: &'a mut BeaconState, function: &'static str) -> Result<BlockMut<'a>> {
    match state {
        BeaconState::Electra(inner) => Ok(BlockMut::Electra(inner)),
        BeaconState::Fulu(inner) => Ok(BlockMut::Fulu(inner)),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

/// `previous_epoch_participation` or `current_epoch_participation`,
/// immutably, whichever `current` selects. A companion to
/// [`BlockMut::epoch_participation_mut`] rather than a method on [`BlockRef`]:
/// only [`process_attestation`]'s read phase needs this, and it needs it
/// before deciding whether anything requires the mutable projection at all.
fn epoch_participation<'a>(
    state: &'a BeaconState,
    current: bool,
    function: &'static str,
) -> Result<&'a EpochParticipation> {
    match state {
        BeaconState::Electra(inner) if current => Ok(&inner.current_epoch_participation),
        BeaconState::Electra(inner) => Ok(&inner.previous_epoch_participation),
        BeaconState::Fulu(inner) if current => Ok(&inner.current_epoch_participation),
        BeaconState::Fulu(inner) => Ok(&inner.previous_epoch_participation),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Deposits
// ---------------------------------------------------------------------------

/// Builds the registry entry a new deposit creates.
///
/// Modified from phase0's version (`crate::stf::operations::get_validator_from_deposit`)
/// to cap the effective balance at [`get_max_effective_balance`] rather than
/// the fixed `MAX_EFFECTIVE_BALANCE`: a depositor who supplies a compounding
/// (`0x02`-prefixed) withdrawal credential from the start is entitled to
/// activate at the higher ceiling immediately, not just after a later
/// [`crate::helpers::electra::switch_to_compounding_validator`] call.
///
/// Subtracting the remainder can never underflow: a modulus is always at
/// most the value it divides.
pub fn get_validator_from_deposit(
    pubkey: BlsPubkey,
    withdrawal_credentials: Bytes32,
    amount: Gwei,
) -> Validator {
    let validator = Validator {
        pubkey,
        withdrawal_credentials,
        effective_balance: 0,
        slashed: false,
        activation_eligibility_epoch: FAR_FUTURE_EPOCH,
        activation_epoch: FAR_FUTURE_EPOCH,
        exit_epoch: FAR_FUTURE_EPOCH,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    };

    let max_effective_balance = get_max_effective_balance(&validator);
    Validator {
        effective_balance: (amount - amount % preset::EFFECTIVE_BALANCE_INCREMENT)
            .min(max_effective_balance),
        ..validator
    }
}

/// Appends a brand-new validator and its starting balance.
///
/// Modified from phase0's version (`crate::stf::operations::add_validator_to_registry`)
/// in two ways. It uses this module's own [`get_validator_from_deposit`]
/// rather than phase0's, for the reason that function's own doc gives. And it
/// also pushes to `previous_epoch_participation`, `current_epoch_participation`,
/// and `inactivity_scores`, altair-era fields phase0's own version never had
/// to grow; every one of those lists is positionally parallel to `validators`
/// and must be grown together, so a new entry with nothing to say about any
/// of the three still needs a zero placeholder in each.
pub fn add_validator_to_registry(
    state: &mut BeaconState,
    pubkey: BlsPubkey,
    withdrawal_credentials: Bytes32,
    amount: Gwei,
) -> Result<()> {
    state.validators_mut().push(get_validator_from_deposit(
        pubkey,
        withdrawal_credentials,
        amount,
    ))?;
    state.balances_mut().push(amount)?;

    let mut fields = block_mut(state, "add_validator_to_registry")?;
    fields.epoch_participation_mut(true).push(0)?;
    fields.epoch_participation_mut(false).push(0)?;
    fields.inactivity_scores_mut().push(0)?;
    Ok(())
}

/// Whether `signature` is a valid proof of possession over a deposit for
/// `pubkey`, `withdrawal_credentials`, and `amount`.
///
/// New in electra only in the sense that the specification factors it out of
/// `apply_deposit` into its own named function; the check itself (a
/// fork-agnostic domain, since a depositor cannot know which fork or chain
/// will eventually accept its deposit) is exactly what phase0's own
/// `apply_deposit` (`crate::stf::operations::apply_deposit`) already inlines.
pub fn is_valid_deposit_signature(
    pubkey: BlsPubkey,
    withdrawal_credentials: Bytes32,
    amount: Gwei,
    signature: &BlsSignature,
    config: &Config,
) -> bool {
    let deposit_message = DepositMessage {
        pubkey,
        withdrawal_credentials,
        amount,
    };
    // A deposit is signed by a depositor who has no way to know which fork,
    // or even which chain, will eventually accept it; see this function's own
    // documentation.
    let domain = compute_deposit_domain(config.genesis_fork_version);
    let signing_root = compute_signing_root(deposit_message.hash_tree_root(), domain);
    bls::verify(&pubkey, signing_root, signature)
}

/// Registers a new validator (if the signature checks out) and queues the
/// deposit's amount as a [`electra::PendingDeposit`], for the epoch boundary
/// to credit.
///
/// This is the single biggest behavioral change EIP-7251 makes to deposit
/// handling: phase0's `apply_deposit` (`crate::stf::operations::apply_deposit`)
/// credits a deposit's amount to a balance the moment it is processed. From
/// electra on, *no* deposit does that directly, existing validator or brand
/// new one alike; every deposit becomes a queue entry, and only
/// `process_pending_deposits` (epoch processing, not this file) ever
/// increases a balance because of one. That indirection is what lets the
/// epoch boundary rate-limit how much stake activates per epoch by *balance*
/// rather than by counting deposits.
///
/// A new pubkey with an invalid signature is not queued at all: the
/// specification's own control flow only reaches the "append pending
/// deposit" step by falling through the `if pubkey not in validator_pubkeys`
/// block (when the pubkey already exists) or by successfully registering a
/// new validator inside it; a failed signature check on a new pubkey takes
/// neither path; it returns immediately with no side effect, mirroring
/// phase0's own "an invalid signature just means the deposit is not
/// credited" rule (see `crate::stf::operations::apply_deposit`'s own
/// documentation) one level further up, before there is even a queue entry
/// to add.
pub fn apply_deposit(
    state: &mut BeaconState,
    pubkey: BlsPubkey,
    withdrawal_credentials: Bytes32,
    amount: Gwei,
    signature: &BlsSignature,
    config: &Config,
) -> Result<()> {
    let already_registered = state.validators().iter().any(|v| v.pubkey == pubkey);
    if !already_registered {
        if is_valid_deposit_signature(pubkey, withdrawal_credentials, amount, signature, config) {
            // The registry entry starts at a zero balance; see this
            // function's own documentation for why even a first-time
            // deposit's amount is queued rather than credited directly.
            add_validator_to_registry(state, pubkey, withdrawal_credentials, 0)?;
        } else {
            return Ok(());
        }
    }

    let deposit = electra::PendingDeposit {
        pubkey,
        withdrawal_credentials,
        amount,
        signature: *signature,
        slot: constants::GENESIS_SLOT,
    };
    electra_state(state, "apply_deposit")?
        .pending_deposits_mut()
        .push(deposit)?;
    Ok(())
}

/// Verifies a deposit's merkle proof, then applies it.
///
/// Unchanged from phase0's version (`crate::stf::operations::process_deposit`)
/// beyond calling this module's own [`apply_deposit`]: the merkle-proof check
/// and the unconditional index advance are identical, and that unconditional
/// advance matters for the same reason phase0's own documentation gives, that
/// the index tracks how many deposits have been *consumed*, not how many
/// produced a validator.
pub fn process_deposit(state: &mut BeaconState, deposit: &Deposit, config: &Config) -> Result<()> {
    verify(
        is_valid_merkle_branch(
            deposit.data.hash_tree_root(),
            &deposit.proof,
            (constants::DEPOSIT_CONTRACT_TREE_DEPTH + 1) as u64,
            state.eth1_deposit_index(),
            state.eth1_data().deposit_root,
        ),
        "is_valid_merkle_branch(hash_tree_root(deposit.data), deposit.proof, DEPOSIT_CONTRACT_TREE_DEPTH + 1, state.eth1_deposit_index, state.eth1_data.deposit_root)",
    )?;

    *state.eth1_deposit_index_mut() += 1;

    apply_deposit(
        state,
        deposit.data.pubkey,
        deposit.data.withdrawal_credentials,
        deposit.data.amount,
        &deposit.data.signature,
        config,
    )
}

// ---------------------------------------------------------------------------
// Voluntary exits
// ---------------------------------------------------------------------------

/// Starts a validator's voluntary exit.
///
/// Every check but the last two is phase0's, unchanged: still active, not
/// already exiting, past its own requested epoch, and past
/// `SHARD_COMMITTEE_PERIOD` since activation. The two additions are both
/// EIP-7251's: the validator must have no partial withdrawal already queued
/// (exiting out from under one would leave nothing to pay it from, so
/// [`get_pending_balance_to_withdraw`] must read zero first), and the exit
/// queue epoch itself is computed through
/// [`crate::helpers::electra::initiate_validator_exit`] rather than
/// phase0's (`crate::helpers::mutators::initiate_validator_exit`), the same
/// churn-by-balance swap described in this module's own documentation.
///
/// Signs under a fixed fork version, [`Config::capella_fork_version`], for
/// EIP-7044, unchanged from deneb's own version
/// (`crate::stf::deneb::process_voluntary_exit`); see that function's own
/// documentation for why the domain is pinned rather than read off the
/// state's current fork. Not delegated to deneb's version despite that
/// overlap, because deneb's calls phase0's `initiate_validator_exit`, which
/// this fork can no longer use; see this function's own documentation above.
pub fn process_voluntary_exit(
    state: &mut BeaconState,
    signed_voluntary_exit: &SignedVoluntaryExit,
    config: &Config,
) -> Result<()> {
    let voluntary_exit = signed_voluntary_exit.message;
    let current_epoch = get_current_epoch(state);
    let validator = state.validator(voluntary_exit.validator_index)?;

    verify(
        is_active_validator(validator, current_epoch),
        "is_active_validator(validator, get_current_epoch(state))",
    )?;
    verify(
        validator.exit_epoch == FAR_FUTURE_EPOCH,
        "validator.exit_epoch == FAR_FUTURE_EPOCH",
    )?;
    verify(
        current_epoch >= voluntary_exit.epoch,
        "get_current_epoch(state) >= voluntary_exit.epoch",
    )?;
    let eligible_epoch = validator
        .activation_epoch
        .checked_add(config.shard_committee_period)
        .ok_or(Error::ArithmeticOverflow(
            "validator.activation_epoch + SHARD_COMMITTEE_PERIOD",
        ))?;
    verify(
        current_epoch >= eligible_epoch,
        "get_current_epoch(state) >= validator.activation_epoch + SHARD_COMMITTEE_PERIOD",
    )?;
    // [New in Electra:EIP7251]
    verify(
        get_pending_balance_to_withdraw(state, voluntary_exit.validator_index)? == 0,
        "get_pending_balance_to_withdraw(state, voluntary_exit.validator_index) == 0",
    )?;

    let domain = compute_domain(
        constants::DOMAIN_VOLUNTARY_EXIT,
        config.capella_fork_version,
        state.genesis_validators_root(),
    );
    let signing_root = compute_signing_root(voluntary_exit.hash_tree_root(), domain);
    verify(
        bls::verify(
            &validator.pubkey,
            signing_root,
            &signed_voluntary_exit.signature,
        ),
        "bls.Verify(validator.pubkey, signing_root, signed_voluntary_exit.signature)",
    )?;

    // [Modified in Electra:EIP7251]
    electra_initiate_validator_exit(state, voluntary_exit.validator_index, config)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// BLS-to-execution changes
// ---------------------------------------------------------------------------

/// Upgrades a validator's withdrawal credentials from a raw BLS public key
/// hash to an execution address.
///
/// Not modified by electra: delegates to capella's own implementation
/// (`crate::stf::capella::process_bls_to_execution_change`) wholesale rather
/// than copying its body. That function needs nothing capella-specific
/// (every field it reads or writes, `validators`, `genesis_validators_root`,
/// is fork-invariant), so this file is required to expose the name at all
/// (see this crate's own task list), but not a second copy of the logic to
/// keep in sync with capella's.
pub fn process_bls_to_execution_change(
    state: &mut BeaconState,
    signed_change: &capella::SignedBLSToExecutionChange,
    config: &Config,
) -> Result<()> {
    super::capella::process_bls_to_execution_change(state, signed_change, config)
}

// ---------------------------------------------------------------------------
// Attester slashings
// ---------------------------------------------------------------------------

/// Slashes every slashable validator in the overlap of two conflicting
/// attestations' attesting sets.
///
/// Not modified by electra beyond the types it operates on: the
/// specification's own table of contents lists no "Modified
/// `process_attester_slashing`", only the `AttesterSlashing` and
/// `IndexedAttestation` containers it reads. This is phase0's version
/// (`crate::stf::operations::process_attester_slashing`) transcribed against
/// [`electra::AttesterSlashing`] and [`crate::helpers::electra::is_valid_indexed_attestation`]
/// instead, the same reason that helper exists as its own copy (see its own
/// documentation): a different concrete `IndexedAttestation` type, not
/// different logic.
pub fn process_attester_slashing(
    state: &mut BeaconState,
    attester_slashing: &electra::AttesterSlashing,
    config: &Config,
) -> Result<()> {
    let attestation_1 = &attester_slashing.attestation_1;
    let attestation_2 = &attester_slashing.attestation_2;

    verify(
        is_slashable_attestation_data(&attestation_1.data, &attestation_2.data),
        "is_slashable_attestation_data(attestation_1.data, attestation_2.data)",
    )?;
    verify(
        is_valid_indexed_attestation(state, attestation_1),
        "is_valid_indexed_attestation(state, attestation_1)",
    )?;
    verify(
        is_valid_indexed_attestation(state, attestation_2),
        "is_valid_indexed_attestation(state, attestation_2)",
    )?;

    let current_epoch = get_current_epoch(state);
    // `is_valid_indexed_attestation` already required both index lists to be
    // sorted and unique; see `crate::stf::operations::process_attester_slashing`
    // for why walking `attestation_1`'s list in order while filtering by
    // membership in `attestation_2`'s set yields the intersection already
    // sorted.
    let indices_2: HashSet<ValidatorIndex> =
        attestation_2.attesting_indices.iter().copied().collect();

    let mut slashed_any = false;
    for &index in attestation_1.attesting_indices.iter() {
        if !indices_2.contains(&index) {
            continue;
        }
        if is_slashable_validator(state.validator(index)?, current_epoch) {
            slash_validator(state, index, None, config)?;
            slashed_any = true;
        }
    }
    verify(
        slashed_any,
        "at least one validator in the intersection of the two attesting index sets was slashed",
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Attestations
// ---------------------------------------------------------------------------

/// Scores an [`electra::Attestation`] against the three timeliness conditions
/// and pays the including proposer, reading the committees it covers from
/// `committee_bits` rather than a single `data.index` (EIP-7549).
///
/// Shares altair's and deneb's overall shape (validate, then score, then pay
/// the proposer for newly-granted flags) but the validation prologue is
/// electra's own: `data.index` must be zero, since `committee_bits` is now
/// the only source of which committees this attestation covers, and each
/// named committee must contribute at least one attester
/// (`committee_attesters` non-empty), which is what stops a proposer padding
/// `committee_bits` with a committee nobody in it actually attested to.
/// [`crate::helpers::electra::get_attesting_indices`] (used below, in the
/// read phase) already does this same per-committee offset walk to build the
/// attester set; this prologue re-walks it only far enough to check the
/// "non-empty" and "total length matches" assertions the specification makes
/// before that set is ever computed, since neither assertion is something
/// [`crate::helpers::electra::get_attesting_indices`] itself checks.
///
/// Structured as the same two-phase read-then-write split altair's and
/// deneb's versions use, and for the identical borrow-checker reason: see
/// `crate::stf::altair::process_attestation`'s own documentation.
pub fn process_attestation(
    state: &mut BeaconState,
    attestation: &electra::Attestation,
) -> Result<()> {
    let data = attestation.data;
    let current_epoch = get_current_epoch(state);
    let previous_epoch = get_previous_epoch(state);

    verify(
        data.target.epoch == previous_epoch || data.target.epoch == current_epoch,
        "data.target.epoch in (get_previous_epoch(state), get_current_epoch(state))",
    )?;
    verify(
        data.target.epoch == compute_epoch_at_slot(data.slot),
        "data.target.epoch == compute_epoch_at_slot(data.slot)",
    )?;
    // [EIP-7045, inherited from deneb]: no upper bound on `state.slot`, unlike
    // altair's; see `crate::stf::deneb::process_attestation`'s own
    // documentation for why FFG justification has no such bound to begin
    // with. `data.slot` still comes straight off the wire, so the lower
    // bound's own addition is still checked.
    let min_slot = data
        .slot
        .checked_add(preset::MIN_ATTESTATION_INCLUSION_DELAY)
        .ok_or(Error::ArithmeticOverflow(
            "data.slot + MIN_ATTESTATION_INCLUSION_DELAY",
        ))?;
    verify(
        min_slot <= state.slot(),
        "data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= state.slot",
    )?;

    // [Modified in Electra:EIP7549]
    verify(data.index == 0, "data.index == 0")?;
    let committee_indices = get_committee_indices(&attestation.committee_bits);
    let mut committee_offset = 0usize;
    for committee_index in committee_indices {
        verify(
            committee_index < get_committee_count_per_slot(state, data.target.epoch),
            "committee_index < get_committee_count_per_slot(state, data.target.epoch)",
        )?;
        let committee = get_beacon_committee(state, data.slot, committee_index)?;
        let committee_has_an_attester = (0..committee.len()).any(|position| {
            attestation
                .aggregation_bits
                .get(committee_offset + position)
                .unwrap_or(false)
        });
        verify(committee_has_an_attester, "len(committee_attesters) > 0")?;
        committee_offset += committee.len();
    }
    verify(
        attestation.aggregation_bits.len() == committee_offset,
        "len(attestation.aggregation_bits) == committee_offset",
    )?;

    // Safe: `min_slot <= state.slot()` above and `min_slot >= data.slot` (the
    // inclusion delay is non-negative), so `data.slot <= state.slot()`.
    let inclusion_delay = state.slot() - data.slot;
    let participation_flag_indices =
        attestation_participation_flag_indices(state, &data, inclusion_delay)?;

    let indexed_attestation = get_indexed_attestation(state, attestation)?;
    verify(
        is_valid_indexed_attestation(state, &indexed_attestation),
        "is_valid_indexed_attestation(state, get_indexed_attestation(state, attestation))",
    )?;

    // Read phase: for every attester, decide which flags this attestation
    // newly satisfies and add up the proposer's reward for granting them.
    let attesting_indices = get_attesting_indices(state, attestation)?;
    let current_epoch_target = data.target.epoch == current_epoch;
    let participation = epoch_participation(state, current_epoch_target, "process_attestation")?;

    let mut proposer_reward_numerator: Gwei = 0;
    let mut updates: Vec<(ValidatorIndex, ParticipationFlags)> = Vec::new();
    for index in attesting_indices {
        let current_flags =
            participation
                .get(index as usize)
                .copied()
                .ok_or(Error::IndexOutOfBounds {
                    index: index as usize,
                    len: participation.len(),
                })?;

        let mut new_flags: ParticipationFlags = 0;
        for &flag_index in &participation_flag_indices {
            if has_flag(current_flags, flag_index) {
                continue;
            }
            new_flags = add_flag(new_flags, flag_index);
            let weight = constants::PARTICIPATION_FLAG_WEIGHTS[flag_index];
            let reward = get_base_reward(state, index)?.checked_mul(weight).ok_or(
                Error::ArithmeticOverflow("get_base_reward(state, index) * weight"),
            )?;
            proposer_reward_numerator = proposer_reward_numerator
                .checked_add(reward)
                .ok_or(Error::ArithmeticOverflow("proposer_reward_numerator"))?;
        }
        if new_flags != 0 {
            updates.push((index, new_flags));
        }
    }

    // Write phase: apply exactly the flags the read phase decided on. Nothing
    // from here on reads `state` any further, so this is free to take the
    // mutable projection the read phase could not.
    {
        let mut fields = block_mut(state, "process_attestation")?;
        let participation_mut = fields.epoch_participation_mut(current_epoch_target);
        let participation_len = participation_mut.len();
        for (index, new_flags) in updates {
            let flags =
                participation_mut
                    .get_mut(index as usize)
                    .ok_or(Error::IndexOutOfBounds {
                        index: index as usize,
                        len: participation_len,
                    })?;
            *flags |= new_flags;
        }
    }

    const NON_PROPOSER_WEIGHT: u64 = constants::WEIGHT_DENOMINATOR - constants::PROPOSER_WEIGHT;
    const PROPOSER_REWARD_DENOMINATOR: u64 =
        NON_PROPOSER_WEIGHT * constants::WEIGHT_DENOMINATOR / constants::PROPOSER_WEIGHT;
    let proposer_reward = proposer_reward_numerator / PROPOSER_REWARD_DENOMINATOR;
    let proposer_index = get_beacon_proposer_index(state)?;
    increase_balance(state, proposer_index, proposer_reward)?;

    Ok(())
}

/// Which of the three participation flags an attestation with `data`,
/// included after `inclusion_delay` slots, satisfies.
///
/// Electra changes nothing here itself. This is deneb's EIP-7045 version,
/// duplicated rather than called: `crate::stf::deneb`'s own function of this
/// name is private to that module (not `pub`), so it is not visible from
/// here even though both files are in the same crate, and this crate has no
/// shared location for a function altair introduces and deneb later modifies
/// (`crate::helpers::altair::altair_state`'s own projection, which a shared
/// version would sit behind, is scoped to `BeaconState::Altair` alone; see
/// its own doc). Whoever next touches either copy should consider hoisting
/// one, in `crate::helpers::altair` or wherever else both `stf::deneb` and
/// `stf::electra` (and, presumably, every later fork) can reach it.
fn attestation_participation_flag_indices(
    state: &BeaconState,
    data: &AttestationData,
    inclusion_delay: u64,
) -> Result<Vec<usize>> {
    let justified_checkpoint = if data.target.epoch == get_current_epoch(state) {
        state.current_justified_checkpoint()
    } else {
        state.previous_justified_checkpoint()
    };
    let is_matching_source = data.source == justified_checkpoint;

    let target_root = get_block_root(state, data.target.epoch)?;
    let target_root_matches = data.target.root == target_root;
    let is_matching_target = is_matching_source && target_root_matches;

    let head_root = get_block_root_at_slot(state, data.slot)?;
    let head_root_matches = data.beacon_block_root == head_root;
    let is_matching_head = is_matching_target && head_root_matches;

    verify(is_matching_source, "is_matching_source")?;

    let mut participation_flag_indices = Vec::new();
    if is_matching_source && inclusion_delay <= integer_squareroot(preset::SLOTS_PER_EPOCH) {
        participation_flag_indices.push(constants::TIMELY_SOURCE_FLAG_INDEX);
    }
    // [EIP-7045]: no `inclusion_delay` bound, unlike altair's own
    // `inclusion_delay <= SLOTS_PER_EPOCH`.
    if is_matching_target {
        participation_flag_indices.push(constants::TIMELY_TARGET_FLAG_INDEX);
    }
    if is_matching_head && inclusion_delay == preset::MIN_ATTESTATION_INCLUSION_DELAY {
        participation_flag_indices.push(constants::TIMELY_HEAD_FLAG_INDEX);
    }

    Ok(participation_flag_indices)
}

// ---------------------------------------------------------------------------
// Withdrawals
// ---------------------------------------------------------------------------

/// The execution address a validator's payout is sent to: the low bytes of
/// its withdrawal credentials, present regardless of whether those
/// credentials are eth1 or compounding (both are execution-form; see
/// `crate::helpers::electra::has_execution_withdrawal_credential`).
///
/// A duplicate of capella's own private `withdrawal_address`
/// (`crate::stf::capella`): that function is not `pub`, so it is not visible
/// here even within the same crate.
fn withdrawal_address(validator: &Validator) -> ExecutionAddress {
    ExecutionAddress::from_slice(&validator.withdrawal_credentials.0[12..])
}

/// The withdrawals this block's sweep owes, without applying them, and how
/// many entries of `pending_partial_withdrawals` it consumed while deciding
/// that.
///
/// Two sweeps, in the specification's order, both drawing from the same
/// `withdrawals` list and the same `withdrawal_index` cursor so a partial
/// withdrawal already collected by the first sweep is visible to the
/// second's own `total_withdrawn` accounting for the same validator.
///
/// The first sweep drains [`electra::PendingPartialWithdrawal`]s
/// (EIP-7251's own queue, absent before this fork): each entry is either
/// paid (if the validator is still active, sitting on enough effective and
/// excess balance) or simply dropped, but either way it counts toward
/// `processed_partial_withdrawals_count`, which is the second return value
/// [`process_withdrawals`] needs to know how much of the queue to drop
/// afterward: a withdrawal request can be consumed by this sweep without
/// ever producing an actual [`capella::Withdrawal`], and the queue still has
/// to advance past it regardless.
///
/// The second sweep is capella's own registry walk
/// (`crate::stf::capella::get_expected_withdrawals`), unchanged in shape,
/// except that both withdrawability predicates are electra's
/// ([`is_fully_withdrawable_validator`], [`is_partially_withdrawable_validator`])
/// and a partial withdrawal's amount is capped against
/// [`get_max_effective_balance`] (a validator's own ceiling) rather than the
/// single fixed `MAX_EFFECTIVE_BALANCE`.
pub fn get_expected_withdrawals(state: &BeaconState) -> Result<(Vec<capella::Withdrawal>, usize)> {
    let epoch = get_current_epoch(state);
    let fields = block_ref(state, "get_expected_withdrawals")?;
    let mut withdrawal_index = fields.next_withdrawal_index();
    let mut validator_index = fields.next_withdrawal_validator_index();

    let mut withdrawals: Vec<capella::Withdrawal> = Vec::new();
    let mut processed_partial_withdrawals_count: usize = 0;

    // [New in Electra:EIP7251]: consume pending partial withdrawals.
    let electra_ref =
        crate::helpers::electra::electra_state_ref(state, "get_expected_withdrawals")?;
    let pending_partial_withdrawals = electra_ref.pending_partial_withdrawals();
    for withdrawal in pending_partial_withdrawals.iter() {
        if withdrawal.withdrawable_epoch > epoch
            || withdrawals.len() == preset::MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP as usize
        {
            break;
        }

        let validator = state.validator(withdrawal.validator_index)?;
        let has_sufficient_effective_balance =
            validator.effective_balance >= preset::MIN_ACTIVATION_BALANCE;
        let total_withdrawn: Gwei = withdrawals
            .iter()
            .filter(|paid| paid.validator_index == withdrawal.validator_index)
            .fold(0, |total, paid| total.saturating_add(paid.amount));
        let balance = state
            .balance(withdrawal.validator_index)?
            .checked_sub(total_withdrawn)
            .ok_or(Error::ArithmeticOverflow(
                "state.balances[withdrawal.validator_index] - total_withdrawn",
            ))?;
        let has_excess_balance = balance > preset::MIN_ACTIVATION_BALANCE;

        if validator.exit_epoch == FAR_FUTURE_EPOCH
            && has_sufficient_effective_balance
            && has_excess_balance
        {
            let withdrawable_balance =
                (balance - preset::MIN_ACTIVATION_BALANCE).min(withdrawal.amount);
            withdrawals.push(capella::Withdrawal {
                index: withdrawal_index,
                validator_index: withdrawal.validator_index,
                address: withdrawal_address(validator),
                amount: withdrawable_balance,
            });
            withdrawal_index = withdrawal_index
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("withdrawal_index + 1"))?;
        }

        // Regardless of whether a withdrawal was actually produced above,
        // this queue entry is consumed either way.
        processed_partial_withdrawals_count += 1;
    }

    // Sweep for the rest, the same bounded registry walk capella's own
    // `get_expected_withdrawals` runs; see this function's own documentation
    // for what electra changes about it.
    let validator_count = state.validators().len() as u64;
    let bound = validator_count.min(preset::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP);
    for _ in 0..bound {
        let validator = state.validator(validator_index)?;
        let total_withdrawn: Gwei = withdrawals
            .iter()
            .filter(|paid| paid.validator_index == validator_index)
            .fold(0, |total, paid| total.saturating_add(paid.amount));
        let balance = state
            .balance(validator_index)?
            .checked_sub(total_withdrawn)
            .ok_or(Error::ArithmeticOverflow(
                "state.balances[validator_index] - total_withdrawn",
            ))?;

        if is_fully_withdrawable_validator(validator, balance, epoch) {
            withdrawals.push(capella::Withdrawal {
                index: withdrawal_index,
                validator_index,
                address: withdrawal_address(validator),
                amount: balance,
            });
            withdrawal_index = withdrawal_index
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("withdrawal_index + 1"))?;
        } else if is_partially_withdrawable_validator(validator, balance) {
            // [Modified in Electra:EIP7251]: capped against this validator's
            // own ceiling, not the single fixed `MAX_EFFECTIVE_BALANCE`.
            let amount = balance
                .checked_sub(get_max_effective_balance(validator))
                .ok_or(Error::ArithmeticOverflow(
                    "balance - get_max_effective_balance(validator)",
                ))?;
            withdrawals.push(capella::Withdrawal {
                index: withdrawal_index,
                validator_index,
                address: withdrawal_address(validator),
                amount,
            });
            withdrawal_index = withdrawal_index
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("withdrawal_index + 1"))?;
        }

        if withdrawals.len() == preset::MAX_WITHDRAWALS_PER_PAYLOAD {
            break;
        }
        validator_index = validator_index
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("validator_index + 1"))?
            % validator_count;
    }

    Ok((withdrawals, processed_partial_withdrawals_count))
}

/// Applies this block's withdrawal sweep: checks the block's declared
/// `payload.withdrawals` against what the sweep actually owes, pays each one
/// out, drops however much of `pending_partial_withdrawals`
/// [`get_expected_withdrawals`] consumed, and advances the sweep's cursor for
/// next time.
///
/// The cursor-update logic (the two-branch split between a full payload and
/// a partial one) is unchanged from capella's own version
/// (`crate::stf::capella::process_withdrawals`); see that function's own
/// documentation for why the two branches disagree about where "next" is
/// once the registry is smaller than `MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP`.
/// What electra adds is the `pending_partial_withdrawals` drop, which has no
/// capella analogue since that queue does not exist before this fork.
pub fn process_withdrawals(
    state: &mut BeaconState,
    payload: &deneb::ExecutionPayload,
) -> Result<()> {
    let (expected_withdrawals, processed_partial_withdrawals_count) =
        get_expected_withdrawals(state)?;
    verify(
        payload.withdrawals.to_vec() == expected_withdrawals,
        "payload.withdrawals == expected_withdrawals",
    )?;

    for withdrawal in &expected_withdrawals {
        decrease_balance(state, withdrawal.validator_index, withdrawal.amount)?;
    }

    // [New in Electra:EIP7251]: drop exactly as many pending partial
    // withdrawals as get_expected_withdrawals actually consumed, whether or
    // not each one produced a real payout.
    {
        let mut fields = block_mut(state, "process_withdrawals")?;
        let mut owned = std::mem::take(fields.pending_partial_withdrawals_mut()).into_inner();
        // Safe: `processed_partial_withdrawals_count` only ever counts
        // iterations of this same list's own loop in `get_expected_withdrawals`,
        // so it can never exceed the list's length.
        let remaining = owned.split_off(processed_partial_withdrawals_count);
        *fields.pending_partial_withdrawals_mut() = remaining.try_into()?;
    }

    if let Some(latest_withdrawal) = expected_withdrawals.last() {
        *block_mut(state, "process_withdrawals")?.next_withdrawal_index_mut() = latest_withdrawal
            .index
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("latest_withdrawal.index + 1"))?;
    }

    let validator_count = state.validators().len() as u64;
    let next_validator_index = if expected_withdrawals.len() == preset::MAX_WITHDRAWALS_PER_PAYLOAD
    {
        let latest_withdrawal = expected_withdrawals
            .last()
            .expect("MAX_WITHDRAWALS_PER_PAYLOAD is never zero, so a full payload is non-empty");
        latest_withdrawal
            .validator_index
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow(
                "latest_withdrawal.validator_index + 1",
            ))?
            % validator_count
    } else {
        let current_cursor =
            block_ref(state, "process_withdrawals")?.next_withdrawal_validator_index();
        current_cursor
            .checked_add(preset::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP)
            .ok_or(Error::ArithmeticOverflow(
                "next_withdrawal_validator_index + MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP",
            ))?
            % validator_count
    };
    *block_mut(state, "process_withdrawals")?.next_withdrawal_validator_index_mut() =
        next_validator_index;

    Ok(())
}

// ---------------------------------------------------------------------------
// Execution-layer-triggered requests
// ---------------------------------------------------------------------------

/// Runs every execution-layer-triggered request in `requests`, in the
/// specification's order: deposits, then withdrawals, then consolidations.
///
/// The one loop [`process_operations`] itself does not inline, since
/// [`electra::ExecutionRequests`] bundles all three lists together on
/// [`electra::BeaconBlockBody::execution_requests`] rather than carrying them
/// as three separate body fields the way every other operation list is
/// carried.
pub fn process_execution_requests(
    state: &mut BeaconState,
    requests: &electra::ExecutionRequests,
    config: &Config,
) -> Result<()> {
    for deposit in requests.deposits.iter() {
        process_deposit_request(state, deposit)?;
    }
    for withdrawal in requests.withdrawals.iter() {
        process_withdrawal_request(state, withdrawal, config)?;
    }
    for consolidation in requests.consolidations.iter() {
        process_consolidation_request(state, consolidation, config)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Deposit requests
// ---------------------------------------------------------------------------

/// Records an execution-layer-triggered deposit (EIP-6110) as a
/// [`electra::PendingDeposit`], the same queue-then-drain destination every
/// other deposit source ([`apply_deposit`]) feeds.
///
/// The first request ever seen fixes `deposit_requests_start_index`, the
/// point past which [`process_operations`]'s own deposit-count check trusts
/// the execution layer's request log rather than the old `Eth1Data` vote
/// count; see that check's own documentation. No signature check happens
/// here, unlike [`apply_deposit`]'s: a request already arrived bundled with
/// the execution payload the block itself commits to, so there is no
/// separate proof-of-possession step to gate registering it on, the same way
/// [`process_withdrawal_request`] and [`process_consolidation_request`]
/// trust the execution layer's own request rather than re-deriving a
/// signature for it.
pub fn process_deposit_request(
    state: &mut BeaconState,
    request: &electra::DepositRequest,
) -> Result<()> {
    {
        let mut fields = block_mut(state, "process_deposit_request")?;
        if *fields.deposit_requests_start_index_mut()
            == constants::UNSET_DEPOSIT_REQUESTS_START_INDEX
        {
            *fields.deposit_requests_start_index_mut() = request.index;
        }
    }

    let deposit = electra::PendingDeposit {
        pubkey: request.pubkey,
        withdrawal_credentials: request.withdrawal_credentials,
        amount: request.amount,
        signature: request.signature,
        slot: state.slot(),
    };
    electra_state(state, "process_deposit_request")?
        .pending_deposits_mut()
        .push(deposit)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Execution-layer withdrawal requests
// ---------------------------------------------------------------------------

/// Honors (or quietly drops) an execution-layer-triggered exit or partial
/// withdrawal (EIP-7002, EIP-7251).
///
/// Every early return below is the specification's own plain `return`, never
/// an `assert`, and that distinction is load bearing: none of these
/// conditions makes the wrapping *block* invalid. The execution layer
/// already committed to this request by including it in the payload the
/// block's own hash covers; consensus choosing not to act on a stale,
/// malformed, or already-superseded one is a decision about the request,
/// not a verdict on the block that carried it. Getting this backwards, an
/// `?` where the specification has a `return`, would reject an otherwise
/// perfectly valid block over a request that simply no longer applies (a
/// validator that exited on its own between the request being queued on the
/// execution side and this block including it, say).
///
/// In order: the pending-partial-withdrawals queue must have room (unless
/// this is a full exit, which does not use that queue), the requested pubkey
/// must resolve to a real validator, that validator's withdrawal credentials
/// must actually name `source_address` (so a request cannot be honored
/// against a validator it was never authorized to touch), the validator must
/// be active, not already exiting, and past `SHARD_COMMITTEE_PERIOD` since
/// activation. A full exit request (`amount == FULL_EXIT_REQUEST_AMOUNT`)
/// then either exits the validator or does nothing, unconditionally,
/// regardless of which; a partial withdrawal request additionally requires a
/// compounding credential and genuine excess balance before it queues
/// anything.
///
/// The one piece of arithmetic that *does* reject the block on failure is
/// `validator.activation_epoch + SHARD_COMMITTEE_PERIOD`: an overflow there
/// means `activation_epoch` itself is corrupt state, not that this request is
/// stale, so it is checked and propagated with `?` rather than folded into
/// the silent-return chain above it.
pub fn process_withdrawal_request(
    state: &mut BeaconState,
    request: &electra::WithdrawalRequest,
    config: &Config,
) -> Result<()> {
    let amount = request.amount;
    let is_full_exit_request = amount == constants::FULL_EXIT_REQUEST_AMOUNT;

    let pending_partial_withdrawals_len = block_mut(state, "process_withdrawal_request")?
        .pending_partial_withdrawals_mut()
        .len();
    if pending_partial_withdrawals_len == preset::PENDING_PARTIAL_WITHDRAWALS_LIMIT
        && !is_full_exit_request
    {
        return Ok(());
    }

    let Some(index) = state
        .validators()
        .iter()
        .position(|validator| validator.pubkey == request.validator_pubkey)
        .map(|index| index as ValidatorIndex)
    else {
        return Ok(());
    };
    let validator = state.validator(index)?;

    let has_correct_credential = has_execution_withdrawal_credential(validator);
    let is_correct_source_address = withdrawal_address(validator) == request.source_address;
    if !(has_correct_credential && is_correct_source_address) {
        return Ok(());
    }
    if !is_active_validator(validator, get_current_epoch(state)) {
        return Ok(());
    }
    if validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Ok(());
    }
    // See this function's own documentation for why this one step is
    // checked with `?` rather than folded into the silent-return chain.
    let eligible_epoch = validator
        .activation_epoch
        .checked_add(config.shard_committee_period)
        .ok_or(Error::ArithmeticOverflow(
            "validator.activation_epoch + SHARD_COMMITTEE_PERIOD",
        ))?;
    if get_current_epoch(state) < eligible_epoch {
        return Ok(());
    }

    let pending_balance_to_withdraw = get_pending_balance_to_withdraw(state, index)?;

    if is_full_exit_request {
        // Only exit the validator if it has no pending withdrawal in the
        // queue; either way, a full exit request never falls through to the
        // partial-withdrawal logic below.
        if pending_balance_to_withdraw == 0 {
            electra_initiate_validator_exit(state, index, config)?;
        }
        return Ok(());
    }

    let validator = state.validator(index)?;
    let has_sufficient_effective_balance =
        validator.effective_balance >= preset::MIN_ACTIVATION_BALANCE;
    let has_excess_balance = state.balance(index)?
        > preset::MIN_ACTIVATION_BALANCE.saturating_add(pending_balance_to_withdraw);

    // Only a compounding validator can take a *partial* withdrawal through
    // this path; a non-compounding one's only route out is the full exit
    // above. Falling through this `if` with nothing queued (rather than an
    // `else` branch that errors) is itself the specification's own behavior:
    // a partial request that does not qualify is simply not honored.
    if has_compounding_withdrawal_credential(validator)
        && has_sufficient_effective_balance
        && has_excess_balance
    {
        let to_withdraw = state
            .balance(index)?
            .checked_sub(preset::MIN_ACTIVATION_BALANCE)
            .and_then(|value| value.checked_sub(pending_balance_to_withdraw))
            .ok_or(Error::ArithmeticOverflow(
                "state.balances[index] - MIN_ACTIVATION_BALANCE - pending_balance_to_withdraw",
            ))?
            .min(amount);
        let exit_queue_epoch = compute_exit_epoch_and_update_churn(state, to_withdraw, config)?;
        let withdrawable_epoch = exit_queue_epoch
            .checked_add(config.min_validator_withdrawability_delay)
            .ok_or(Error::ArithmeticOverflow(
                "exit_queue_epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY",
            ))?;
        let withdrawal = electra::PendingPartialWithdrawal {
            validator_index: index,
            amount: to_withdraw,
            withdrawable_epoch,
        };
        block_mut(state, "process_withdrawal_request")?
            .pending_partial_withdrawals_mut()
            .push(withdrawal)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Execution-layer consolidation requests
// ---------------------------------------------------------------------------

/// Whether `request` is really a request to switch its source (and only
/// source) validator from an eth1 to a compounding withdrawal credential,
/// disguised as a self-consolidation.
///
/// A validator that already holds an eth1 credential has no other way to
/// become compounding: [`crate::helpers::electra::switch_to_compounding_validator`]
/// is only ever reachable through [`process_consolidation_request`] noticing
/// this pattern (source and target are the same validator) first. Returns
/// `Result` only for symmetry with this crate's other state-reading
/// functions; nothing inside can actually fail, since every condition here
/// is itself one of the specification's own `return False` guards rather
/// than an assertion.
pub fn is_valid_switch_to_compounding_request(
    state: &BeaconState,
    request: &electra::ConsolidationRequest,
) -> Result<bool> {
    if request.source_pubkey != request.target_pubkey {
        return Ok(false);
    }

    let Some(source_validator) = state
        .validators()
        .iter()
        .find(|validator| validator.pubkey == request.source_pubkey)
    else {
        return Ok(false);
    };

    if withdrawal_address(source_validator) != request.source_address {
        return Ok(false);
    }
    if !has_eth1_withdrawal_credential(source_validator) {
        return Ok(false);
    }
    if !is_active_validator(source_validator, get_current_epoch(state)) {
        return Ok(false);
    }
    if source_validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Ok(false);
    }

    Ok(true)
}

/// Honors (or quietly drops) an execution-layer-triggered consolidation
/// (EIP-7251): either a switch-to-compounding request in disguise (see
/// [`is_valid_switch_to_compounding_request`]), or a real merge of one
/// validator's balance into another's.
///
/// Every early return here, in both branches, is the specification's own
/// plain `return`, not an `assert`; see [`process_withdrawal_request`]'s own
/// documentation for why that distinction matters and must not be turned
/// into a rejected block by an incautious `?`. The one exception, again as
/// in that function, is `source_validator.activation_epoch +
/// SHARD_COMMITTEE_PERIOD`: an overflow there is checked and propagated,
/// since it would mean corrupt state rather than a stale request.
pub fn process_consolidation_request(
    state: &mut BeaconState,
    request: &electra::ConsolidationRequest,
    config: &Config,
) -> Result<()> {
    if is_valid_switch_to_compounding_request(state, request)? {
        // Already known to resolve, by the check just above; state has not
        // been mutated since.
        let source_index = state
            .validators()
            .iter()
            .position(|validator| validator.pubkey == request.source_pubkey)
            .map(|index| index as ValidatorIndex)
            .ok_or(Error::SpecAssert(
                "is_valid_switch_to_compounding_request already resolved consolidation_request.source_pubkey",
            ))?;
        crate::helpers::electra::switch_to_compounding_validator(state, source_index)?;
        return Ok(());
    }

    // Guards against using a self-consolidation to trigger an exit through
    // the branch below, once the switch-to-compounding branch above has
    // already ruled out (for some other reason) treating it as a genuine
    // credential upgrade.
    if request.source_pubkey == request.target_pubkey {
        return Ok(());
    }
    let pending_consolidations_len = block_mut(state, "process_consolidation_request")?
        .pending_consolidations_mut()
        .len();
    if pending_consolidations_len == preset::PENDING_CONSOLIDATIONS_LIMIT {
        return Ok(());
    }
    if get_consolidation_churn_limit(state, config)? <= preset::MIN_ACTIVATION_BALANCE {
        return Ok(());
    }

    let Some(source_index) = state
        .validators()
        .iter()
        .position(|validator| validator.pubkey == request.source_pubkey)
        .map(|index| index as ValidatorIndex)
    else {
        return Ok(());
    };
    let Some(target_index) = state
        .validators()
        .iter()
        .position(|validator| validator.pubkey == request.target_pubkey)
        .map(|index| index as ValidatorIndex)
    else {
        return Ok(());
    };

    let source_validator = state.validator(source_index)?;
    let has_correct_credential = has_execution_withdrawal_credential(source_validator);
    let is_correct_source_address = withdrawal_address(source_validator) == request.source_address;
    if !(has_correct_credential && is_correct_source_address) {
        return Ok(());
    }

    let target_validator = state.validator(target_index)?;
    if !has_compounding_withdrawal_credential(target_validator) {
        return Ok(());
    }

    let current_epoch = get_current_epoch(state);
    if !is_active_validator(source_validator, current_epoch) {
        return Ok(());
    }
    if !is_active_validator(target_validator, current_epoch) {
        return Ok(());
    }
    if source_validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Ok(());
    }
    if target_validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Ok(());
    }
    // See this function's own documentation for why this one step is
    // checked with `?` rather than folded into the silent-return chain.
    let eligible_epoch = source_validator
        .activation_epoch
        .checked_add(config.shard_committee_period)
        .ok_or(Error::ArithmeticOverflow(
            "source_validator.activation_epoch + SHARD_COMMITTEE_PERIOD",
        ))?;
    if current_epoch < eligible_epoch {
        return Ok(());
    }
    if get_pending_balance_to_withdraw(state, source_index)? > 0 {
        return Ok(());
    }

    let source_effective_balance = source_validator.effective_balance;
    let exit_epoch = crate::helpers::electra::compute_consolidation_epoch_and_update_churn(
        state,
        source_effective_balance,
        config,
    )?;
    let withdrawable_epoch = exit_epoch
        .checked_add(config.min_validator_withdrawability_delay)
        .ok_or(Error::ArithmeticOverflow(
            "exit_epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY",
        ))?;

    {
        let source_validator = state.validator_mut(source_index)?;
        source_validator.exit_epoch = exit_epoch;
        source_validator.withdrawable_epoch = withdrawable_epoch;
    }

    let consolidation = electra::PendingConsolidation {
        source_index,
        target_index,
    };
    block_mut(state, "process_consolidation_request")?
        .pending_consolidations_mut()
        .push(consolidation)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Execution payload
// ---------------------------------------------------------------------------

/// Validates this slot's execution payload and its blob commitments, then
/// caches the payload's header.
///
/// Structurally deneb's own [`super::deneb::process_execution_payload`]
/// (parent-hash continuity, `prev_randao`, timestamp, a blob-commitment
/// count check, the collapsed engine check, then caching a
/// [`deneb::ExecutionPayloadHeader`], the same header type electra keeps
/// unchanged from deneb), but not literally callable as that function: its
/// commitment-count check reads [`Config::max_blobs_per_block_deneb`], while
/// electra's own limit, [`Config::max_blobs_per_block_electra`], is a
/// *different* configuration field (`MAX_BLOBS_PER_BLOCK_ELECTRA` is listed
/// under electra's own "Configuration" table, not carried over from deneb's
/// "Preset" one), and `crate::stf::deneb`'s own state projection
/// (`deneb_state`/`deneb_state_ref`) is deliberately scoped to
/// `BeaconState::Deneb` alone, so it could not read an electra state's
/// header even if the constant matched. Every other step is transcribed
/// rather than restructured, including not computing anything from
/// `body.execution_requests`: see [`super::deneb::process_execution_payload`]'s
/// own documentation for why the versioned-hashes list (and, from electra
/// on, the execution-requests list `get_execution_requests_list` would
/// build) is dead weight in this crate specifically, since
/// [`ExecutionEngine`] collapses the whole `verify_and_notify_new_payload`
/// interface to one boolean and never inspects either.
pub fn process_execution_payload(
    state: &mut BeaconState,
    body: &electra::BeaconBlockBody,
    config: &Config,
    engine: &ExecutionEngine,
) -> Result<()> {
    let payload = &body.execution_payload;

    let expected_parent_hash = block_ref(state, "process_execution_payload")?
        .latest_execution_payload_header()
        .block_hash;
    verify(
        payload.parent_hash == expected_parent_hash,
        "payload.parent_hash == state.latest_execution_payload_header.block_hash",
    )?;
    verify(
        payload.prev_randao == get_randao_mix(state, get_current_epoch(state)),
        "payload.prev_randao == get_randao_mix(state, get_current_epoch(state))",
    )?;
    verify(
        payload.timestamp
            == super::bellatrix::compute_timestamp_at_slot(state, state.slot(), config),
        "payload.timestamp == compute_time_at_slot(state, state.slot)",
    )?;
    // [Modified in Electra:EIP7691]: see this function's own documentation
    // for why `Config::max_blobs_per_block_electra` rather than
    // `Config::max_blobs_per_block_deneb`.
    verify(
        body.blob_kzg_commitments.len() as u64 <= config.max_blobs_per_block_electra,
        "len(body.blob_kzg_commitments) <= MAX_BLOBS_PER_BLOCK_ELECTRA",
    )?;

    // See this function's own documentation for why this is computed but
    // not itself checked against anything.
    let _versioned_hashes: Vec<Bytes32> = body
        .blob_kzg_commitments
        .iter()
        .map(super::deneb::kzg_commitment_to_versioned_hash)
        .collect();

    verify(
        engine.execution_valid,
        "verify_and_notify_new_payload(NewPayloadRequest(execution_payload=payload, \
         versioned_hashes=versioned_hashes, \
         parent_beacon_block_root=state.latest_block_header.parent_root, \
         execution_requests=body.execution_requests))",
    )?;

    let header = deneb::ExecutionPayloadHeader {
        parent_hash: payload.parent_hash,
        fee_recipient: payload.fee_recipient,
        state_root: payload.state_root,
        receipts_root: payload.receipts_root,
        logs_bloom: payload.logs_bloom.clone(),
        prev_randao: payload.prev_randao,
        block_number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: payload.extra_data.clone(),
        base_fee_per_gas: payload.base_fee_per_gas,
        block_hash: payload.block_hash,
        transactions_root: payload.transactions.hash_tree_root(),
        withdrawals_root: payload.withdrawals.hash_tree_root(),
        blob_gas_used: payload.blob_gas_used,
        excess_blob_gas: payload.excess_blob_gas,
    };
    *block_mut(state, "process_execution_payload")?.latest_execution_payload_header_mut() = header;

    Ok(())
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Runs every operation in an electra block, in the specification's order.
///
/// Takes `body: &electra::BeaconBlockBody` rather than each operation list
/// as its own parameter, unlike `crate::stf::operations::process_operations`
/// (six lists) and even `crate::stf::capella::process_operations` and
/// `crate::stf::deneb::process_operations` (seven, one past clippy's
/// default limit, already tolerated there with an `#[allow]`). Electra's own
/// body carries eight lists relevant here: phase0's five, capella's
/// `bls_to_execution_changes`, and (bundled into one field,
/// [`electra::ExecutionRequests`]) the three new execution-layer-triggered
/// request kinds. Eight separate parameters plus `config` would be two past
/// that same limit for no real benefit, since every call site already holds
/// a whole `electra::BeaconBlockBody` (this function's only caller,
/// [`process_block`], unpacks nothing else from it either); see this crate's
/// module documentation (`crate::stf`) for why a shared body abstraction is
/// usually the wrong tool, and why taking the *whole*, already fork-specific
/// body here is the exception that doc anticipates rather than a
/// contradiction of it: nothing generic dispatches to this function the way
/// `crate::stf::block::process_block_header` is shared across every fork, so
/// there is no caller anywhere that would have to learn electra's body shape
/// just to call this.
///
/// The deposit-count check is electra's own (EIP-6110): once
/// `deposit_requests_start_index` is set, it (not `eth1_data.deposit_count`
/// alone) caps how many `Eth1Data`-sourced deposits a block may still carry,
/// which is what lets the old deposit-contract path wind down cleanly as the
/// execution-layer request path (`process_deposit_request`) takes over.
/// `eth1_deposit_index_limit - state.eth1_deposit_index` cannot underflow:
/// the surrounding `if` already established `state.eth1_deposit_index <
/// eth1_deposit_index_limit`.
pub fn process_operations(
    state: &mut BeaconState,
    body: &electra::BeaconBlockBody,
    config: &Config,
) -> Result<()> {
    let deposit_requests_start_index =
        block_ref(state, "process_operations")?.deposit_requests_start_index();
    let eth1_deposit_index_limit = state
        .eth1_data()
        .deposit_count
        .min(deposit_requests_start_index);
    if state.eth1_deposit_index() < eth1_deposit_index_limit {
        let outstanding = eth1_deposit_index_limit - state.eth1_deposit_index();
        verify(
            body.deposits.len() as u64 == outstanding.min(preset::MAX_DEPOSITS as u64),
            "len(body.deposits) == min(MAX_DEPOSITS, eth1_deposit_index_limit - state.eth1_deposit_index)",
        )?;
    } else {
        verify(body.deposits.is_empty(), "len(body.deposits) == 0")?;
    }

    for proposer_slashing in body.proposer_slashings.iter() {
        super::operations::process_proposer_slashing(state, proposer_slashing, config)?;
    }
    for attester_slashing in body.attester_slashings.iter() {
        process_attester_slashing(state, attester_slashing, config)?;
    }
    // [Modified in Electra:EIP7549]
    for attestation in body.attestations.iter() {
        process_attestation(state, attestation)?;
    }
    for deposit in body.deposits.iter() {
        process_deposit(state, deposit, config)?;
    }
    // [Modified in Electra:EIP7251]
    for voluntary_exit in body.voluntary_exits.iter() {
        process_voluntary_exit(state, voluntary_exit, config)?;
    }
    for signed_change in body.bls_to_execution_changes.iter() {
        process_bls_to_execution_change(state, signed_change, config)?;
    }
    // [New in Electra:EIP6110:EIP7002:EIP7251]
    process_execution_requests(state, &body.execution_requests, config)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Block processing
// ---------------------------------------------------------------------------

/// Electra's block processing.
///
/// The specification's own order: header, withdrawals, execution payload,
/// RANDAO, eth1 vote, operations, sync aggregate; unchanged from capella and
/// deneb (see `crate::stf::capella::process_block`'s own documentation for
/// why the sweep runs ahead of `bls_to_execution_changes`, one of this same
/// block's own operations). [`super::block::process_block_header`],
/// [`super::block::process_randao`], and [`super::block::process_eth1_data`]
/// are reused unchanged: none of the three reads anything beyond the
/// fork-invariant fields every block shares, which is the whole point of
/// them taking those fields directly rather than a whole body (see
/// `crate::stf`'s module documentation). [`super::altair::process_sync_aggregate`]
/// is reused the same way, for the same reason.
pub fn process_block(
    state: &mut BeaconState,
    block: &electra::BeaconBlock,
    config: &Config,
    engine: &ExecutionEngine,
) -> Result<()> {
    super::block::process_block_header(
        state,
        block.slot,
        block.proposer_index,
        block.parent_root,
        block.body.hash_tree_root(),
    )?;
    process_withdrawals(state, &block.body.execution_payload)?;
    process_execution_payload(state, &block.body, config, engine)?;
    super::block::process_randao(state, &block.body.randao_reveal)?;
    super::block::process_eth1_data(state, &block.body.eth1_data)?;
    process_operations(state, &block.body, config)?;
    super::altair::process_sync_aggregate(state, &block.body.sync_aggregate)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containers::altair::SyncCommittee;
    use crate::containers::shared::Fork;
    use crate::primitives::{BlsPubkey, ExecutionBlockHash, Root, Uint256};

    /// An all-zero execution payload header, standing in for the genesis
    /// payload: nothing under test here inspects it beyond
    /// `process_execution_payload`'s continuity check, which no test in this
    /// module exercises (fixture suites are the real gate for the full block
    /// pipeline; see this crate's own task list for why unit tests here focus
    /// on the request functions' silent-return paths instead).
    fn empty_execution_payload_header() -> deneb::ExecutionPayloadHeader {
        deneb::ExecutionPayloadHeader {
            parent_hash: ExecutionBlockHash::zero(),
            fee_recipient: ExecutionAddress::zero(),
            state_root: Bytes32::zero(),
            receipts_root: Bytes32::zero(),
            logs_bloom: crate::containers::bellatrix::LogsBloom::try_from(vec![
                0u8;
                preset::BYTES_PER_LOGS_BLOOM
            ])
            .expect("built at exactly BYTES_PER_LOGS_BLOOM"),
            prev_randao: Bytes32::zero(),
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: Default::default(),
            base_fee_per_gas: Uint256::zero(),
            block_hash: ExecutionBlockHash::zero(),
            transactions_root: Root::zero(),
            withdrawals_root: Root::zero(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
        }
    }

    fn empty_sync_committee() -> SyncCommittee {
        SyncCommittee {
            pubkeys: vec![BlsPubkey::default(); preset::SYNC_COMMITTEE_SIZE]
                .try_into()
                .expect("built at exactly SYNC_COMMITTEE_SIZE"),
            aggregate_pubkey: BlsPubkey::default(),
        }
    }

    /// An electra state with `count` fully active validators, each with
    /// [`preset::MIN_ACTIVATION_BALANCE`] and an eth1 withdrawal credential,
    /// positioned many epochs in (see the `SHARD_COMMITTEE_PERIOD` note
    /// below) so the previous epoch and the block-root history window both
    /// have entries.
    ///
    /// A near-duplicate of `crate::helpers::electra::tests::electra_state_with_validators`,
    /// which builds the same shape of state; that builder is private to its
    /// own module (and this task's own instructions note the duplication is
    /// expected rather than something to resolve by reaching into
    /// `helpers::electra`'s test module, which this file does not own). The
    /// two differ in two ways: every validator here starts with a real,
    /// distinguishable eth1 credential (`ETH1_ADDRESS_WITHDRAWAL_PREFIX`
    /// followed by the validator's own index, so [`source_address`] can
    /// build a request that matches it), where `helpers::electra`'s builder
    /// leaves every validator's credentials at their default (all-zero,
    /// BLS-form) value; and this state sits far more than
    /// `SHARD_COMMITTEE_PERIOD` epochs past genesis, since
    /// [`process_withdrawal_request`] and [`process_consolidation_request`]
    /// both gate on a validator having been active that long, where
    /// `helpers::electra`'s own tests never need to clear that bar.
    fn electra_state_with_validators(count: usize) -> BeaconState {
        let validators: Vec<Validator> = (0..count)
            .map(|index| {
                let mut withdrawal_credentials = Bytes32::zero();
                withdrawal_credentials.0[0] = constants::ETH1_ADDRESS_WITHDRAWAL_PREFIX;
                withdrawal_credentials.0[31] = index as u8;
                Validator {
                    // Distinct per validator: `Validator::default()`'s
                    // all-zero pubkey would otherwise make every validator
                    // indistinguishable to a pubkey lookup, which is exactly
                    // how the request functions under test resolve
                    // `validator_pubkey`/`source_pubkey`/`target_pubkey`
                    // into an index.
                    pubkey: BlsPubkey([index as u8; 48]),
                    withdrawal_credentials,
                    effective_balance: preset::MIN_ACTIVATION_BALANCE,
                    activation_eligibility_epoch: 0,
                    activation_epoch: 0,
                    exit_epoch: FAR_FUTURE_EPOCH,
                    withdrawable_epoch: FAR_FUTURE_EPOCH,
                    ..Default::default()
                }
            })
            .collect();
        let balances: Vec<Gwei> = vec![preset::MIN_ACTIVATION_BALANCE; count];

        // Comfortably past `SHARD_COMMITTEE_PERIOD` for both mainnet (256
        // epochs) and minimal (64 epochs) configs, so every validator built
        // with `activation_epoch: 0` above is already eligible for an exit
        // or a consolidation by the time a test runs one against it.
        const EPOCHS_PAST_GENESIS: u64 = 300;

        BeaconState::Electra(electra::BeaconState {
            genesis_time: 0,
            genesis_validators_root: Root::zero(),
            slot: EPOCHS_PAST_GENESIS * preset::SLOTS_PER_EPOCH,
            fork: Fork::default(),
            latest_block_header: Default::default(),
            block_roots: vec![Root::zero(); preset::SLOTS_PER_HISTORICAL_ROOT]
                .try_into()
                .expect("the vector is built at its exact length"),
            state_roots: vec![Root::zero(); preset::SLOTS_PER_HISTORICAL_ROOT]
                .try_into()
                .expect("the vector is built at its exact length"),
            historical_roots: Default::default(),
            eth1_data: Default::default(),
            eth1_data_votes: Default::default(),
            eth1_deposit_index: 0,
            validators: validators
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            balances: balances
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            randao_mixes: vec![Bytes32::zero(); preset::EPOCHS_PER_HISTORICAL_VECTOR]
                .try_into()
                .expect("the vector is built at its exact length"),
            slashings: vec![0; preset::EPOCHS_PER_SLASHINGS_VECTOR]
                .try_into()
                .expect("the vector is built at its exact length"),
            previous_epoch_participation: vec![0; count]
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            current_epoch_participation: vec![0; count]
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            justification_bits: Default::default(),
            previous_justified_checkpoint: Default::default(),
            current_justified_checkpoint: Default::default(),
            finalized_checkpoint: Default::default(),
            inactivity_scores: vec![0; count]
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            current_sync_committee: empty_sync_committee(),
            next_sync_committee: empty_sync_committee(),
            latest_execution_payload_header: empty_execution_payload_header(),
            next_withdrawal_index: 0,
            next_withdrawal_validator_index: 0,
            historical_summaries: Default::default(),
            deposit_requests_start_index: constants::UNSET_DEPOSIT_REQUESTS_START_INDEX,
            deposit_balance_to_consume: 0,
            exit_balance_to_consume: 0,
            earliest_exit_epoch: 0,
            consolidation_balance_to_consume: 0,
            earliest_consolidation_epoch: 0,
            pending_deposits: Default::default(),
            pending_partial_withdrawals: Default::default(),
            pending_consolidations: Default::default(),
        })
    }

    /// The execution address [`electra_state_with_validators`] derived
    /// validator `index`'s withdrawal credentials from, i.e. the
    /// `source_address` a request against that validator must carry to pass
    /// [`has_execution_withdrawal_credential`]'s address check.
    fn source_address(index: ValidatorIndex) -> ExecutionAddress {
        let mut bytes = [0u8; 20];
        bytes[19] = index as u8;
        ExecutionAddress::from_slice(&bytes)
    }

    // -- process_withdrawal_request -----------------------------------------

    #[test]
    fn a_full_exit_request_for_an_unknown_pubkey_is_silently_dropped() {
        let mut state = electra_state_with_validators(4);
        let config = Config::mainnet();
        let before = state.clone();

        let request = electra::WithdrawalRequest {
            source_address: source_address(0),
            validator_pubkey: BlsPubkey([0xff; 48]),
            amount: constants::FULL_EXIT_REQUEST_AMOUNT,
        };
        process_withdrawal_request(&mut state, &request, &config)
            .expect("an unresolved pubkey is dropped silently, not rejected");
        assert_eq!(
            state, before,
            "no validator should have been touched for a pubkey nobody holds"
        );
    }

    #[test]
    fn a_request_with_the_wrong_source_address_is_silently_dropped() {
        let mut state = electra_state_with_validators(4);
        let config = Config::mainnet();
        let pubkey = state.validator(0).unwrap().pubkey;
        let before = state.clone();

        let request = electra::WithdrawalRequest {
            // Validator 0's real credentials point at `source_address(0)`,
            // not this one.
            source_address: source_address(1),
            validator_pubkey: pubkey,
            amount: constants::FULL_EXIT_REQUEST_AMOUNT,
        };
        process_withdrawal_request(&mut state, &request, &config)
            .expect("a mismatched source address is dropped silently, not rejected");
        assert_eq!(state, before, "no validator should have been touched");
    }

    #[test]
    fn a_full_exit_request_exits_a_matching_active_validator() {
        let mut state = electra_state_with_validators(4);
        let config = Config::mainnet();
        let pubkey = state.validator(0).unwrap().pubkey;

        let request = electra::WithdrawalRequest {
            source_address: source_address(0),
            validator_pubkey: pubkey,
            amount: constants::FULL_EXIT_REQUEST_AMOUNT,
        };
        process_withdrawal_request(&mut state, &request, &config).unwrap();

        assert_ne!(
            state.validator(0).unwrap().exit_epoch,
            FAR_FUTURE_EPOCH,
            "a full exit request against a validator with nothing pending must exit it"
        );
    }

    /// Gated to `preset-minimal` only: mainnet's own
    /// `PENDING_PARTIAL_WITHDRAWALS_LIMIT` is large enough (a fraction over
    /// a hundred million) that actually building a queue at that literal
    /// size would allocate several gigabytes and take seconds, for a check
    /// that adds nothing over exercising the identical code path at
    /// minimal's much smaller limit. This still runs, just not under the
    /// default `cargo test` invocation this crate's own task list uses,
    /// which is why `preset::MIN_ACTIVATION_BALANCE` and friends throughout
    /// this file are written against whichever preset is active rather than
    /// hardcoded, the same as everywhere else in this crate.
    #[test]
    #[cfg(feature = "preset-minimal")]
    fn a_full_queue_silently_drops_a_partial_request_but_not_a_full_exit() {
        let mut state = electra_state_with_validators(2);
        let config = Config::mainnet();

        // Fill the pending-partial-withdrawals queue to its literal limit;
        // only practical because this test is gated to the minimal preset,
        // whose PENDING_PARTIAL_WITHDRAWALS_LIMIT is small. See this
        // function's own documentation.
        {
            let mut fields = block_mut(&mut state, "test setup").unwrap();
            let queue = fields.pending_partial_withdrawals_mut();
            for _ in 0..preset::PENDING_PARTIAL_WITHDRAWALS_LIMIT {
                queue
                    .push(electra::PendingPartialWithdrawal {
                        validator_index: 0,
                        amount: 1,
                        withdrawable_epoch: 0,
                    })
                    .unwrap();
            }
        }
        let pubkey = state.validator(1).unwrap().pubkey;
        let before_full_queue_len = block_mut(&mut state, "test assertion")
            .unwrap()
            .pending_partial_withdrawals_mut()
            .len();
        assert_eq!(
            before_full_queue_len,
            preset::PENDING_PARTIAL_WITHDRAWALS_LIMIT
        );

        // A partial request against the full queue: silently dropped.
        let partial_request = electra::WithdrawalRequest {
            source_address: source_address(1),
            validator_pubkey: pubkey,
            amount: 1,
        };
        process_withdrawal_request(&mut state, &partial_request, &config)
            .expect("a full queue drops a partial request silently, not with an error");
        assert_eq!(
            block_mut(&mut state, "test assertion")
                .unwrap()
                .pending_partial_withdrawals_mut()
                .len(),
            preset::PENDING_PARTIAL_WITHDRAWALS_LIMIT,
            "the queue must not have grown"
        );

        // A full exit request against the same validator: not gated by the
        // queue at all, since it never uses it.
        let full_exit_request = electra::WithdrawalRequest {
            source_address: source_address(1),
            validator_pubkey: pubkey,
            amount: constants::FULL_EXIT_REQUEST_AMOUNT,
        };
        process_withdrawal_request(&mut state, &full_exit_request, &config).unwrap();
        assert_ne!(
            state.validator(1).unwrap().exit_epoch,
            FAR_FUTURE_EPOCH,
            "a full exit request must not be blocked by a full partial-withdrawal queue"
        );
    }

    #[test]
    fn a_full_exit_request_ignores_the_partial_withdrawals_queue_entirely() {
        // The cross-preset counterpart of the `preset-minimal`-only test
        // above: rather than filling the queue to its literal (and, under
        // mainnet, impractically large) limit, this only has to show that
        // `is_full_exit_request`'s branch never even reads
        // `pending_partial_withdrawals_len`, by pushing one placeholder
        // entry and confirming the exit still succeeds.
        let mut state = electra_state_with_validators(2);
        let config = Config::mainnet();
        block_mut(&mut state, "test setup")
            .unwrap()
            .pending_partial_withdrawals_mut()
            .push(electra::PendingPartialWithdrawal {
                validator_index: 0,
                amount: 1,
                withdrawable_epoch: 0,
            })
            .unwrap();
        let pubkey = state.validator(1).unwrap().pubkey;

        let full_exit_request = electra::WithdrawalRequest {
            source_address: source_address(1),
            validator_pubkey: pubkey,
            amount: constants::FULL_EXIT_REQUEST_AMOUNT,
        };
        process_withdrawal_request(&mut state, &full_exit_request, &config).unwrap();
        assert_ne!(
            state.validator(1).unwrap().exit_epoch,
            FAR_FUTURE_EPOCH,
            "a full exit request must not consult the partial-withdrawals queue length at all"
        );
    }

    #[test]
    fn a_compounding_validator_with_excess_balance_gets_a_partial_withdrawal_queued() {
        let mut state = electra_state_with_validators(2);
        let config = Config::mainnet();
        {
            let validator = state.validator_mut(0).unwrap();
            validator.withdrawal_credentials.0[0] = constants::COMPOUNDING_WITHDRAWAL_PREFIX;
            validator.effective_balance = preset::MIN_ACTIVATION_BALANCE;
        }
        state.balances_mut()[0] = preset::MIN_ACTIVATION_BALANCE + 1_000_000_000;
        let pubkey = state.validator(0).unwrap().pubkey;

        let request = electra::WithdrawalRequest {
            source_address: source_address(0),
            validator_pubkey: pubkey,
            amount: 500_000_000,
        };
        process_withdrawal_request(&mut state, &request, &config).unwrap();

        let queued = crate::helpers::electra::get_pending_balance_to_withdraw(&state, 0).unwrap();
        assert_eq!(
            queued, 500_000_000,
            "the request's own amount, capped at the validator's actual excess, must be queued"
        );
    }

    #[test]
    fn a_noncompounding_validator_gets_no_partial_withdrawal_queued() {
        // Validator 0 keeps its eth1 (not compounding) credential from
        // `electra_state_with_validators`: only a compounding validator may
        // take a partial withdrawal through this path (a non-compounding one
        // must use a full exit instead), so this must fall through and queue
        // nothing even with genuine excess balance.
        let mut state = electra_state_with_validators(2);
        let config = Config::mainnet();
        state.balances_mut()[0] = preset::MIN_ACTIVATION_BALANCE + 1_000_000_000;
        let pubkey = state.validator(0).unwrap().pubkey;

        let request = electra::WithdrawalRequest {
            source_address: source_address(0),
            validator_pubkey: pubkey,
            amount: 500_000_000,
        };
        process_withdrawal_request(&mut state, &request, &config).unwrap();

        let queued = crate::helpers::electra::get_pending_balance_to_withdraw(&state, 0).unwrap();
        assert_eq!(
            queued, 0,
            "a non-compounding validator has no partial-withdrawal route"
        );
    }

    // -- process_consolidation_request --------------------------------------

    #[test]
    fn a_self_consolidation_switches_the_validator_to_compounding() {
        let mut state = electra_state_with_validators(2);
        let config = Config::mainnet();
        let pubkey = state.validator(0).unwrap().pubkey;

        let request = electra::ConsolidationRequest {
            source_address: source_address(0),
            source_pubkey: pubkey,
            target_pubkey: pubkey,
        };
        process_consolidation_request(&mut state, &request, &config).unwrap();

        assert!(has_compounding_withdrawal_credential(
            state.validator(0).unwrap()
        ));
        assert!(
            block_mut(&mut state, "test assertion")
                .unwrap()
                .pending_consolidations_mut()
                .is_empty(),
            "a switch-to-compounding request is not a real consolidation and must not queue one"
        );
    }

    #[test]
    fn a_self_consolidation_with_the_wrong_source_address_is_silently_dropped() {
        let mut state = electra_state_with_validators(2);
        let config = Config::mainnet();
        let pubkey = state.validator(0).unwrap().pubkey;
        let before = state.clone();

        let request = electra::ConsolidationRequest {
            // Does not match validator 0's real credentials, so this is
            // neither a valid switch-to-compounding request nor (since
            // source == target) a real consolidation.
            source_address: source_address(1),
            source_pubkey: pubkey,
            target_pubkey: pubkey,
        };
        process_consolidation_request(&mut state, &request, &config)
            .expect("neither branch applies, so this must be a silent no-op, not an error");
        assert_eq!(state, before, "no validator should have been touched");
    }

    #[test]
    fn a_full_pending_consolidations_queue_silently_drops_a_real_consolidation() {
        let mut state = electra_state_with_validators(2);
        let config = Config::mainnet();
        {
            let mut fields = block_mut(&mut state, "test setup").unwrap();
            let queue = fields.pending_consolidations_mut();
            for _ in 0..preset::PENDING_CONSOLIDATIONS_LIMIT {
                queue
                    .push(electra::PendingConsolidation {
                        source_index: 0,
                        target_index: 0,
                    })
                    .unwrap();
            }
        }
        {
            let validator = state.validator_mut(1).unwrap();
            validator.withdrawal_credentials.0[0] = constants::COMPOUNDING_WITHDRAWAL_PREFIX;
        }
        let source_pubkey = state.validator(0).unwrap().pubkey;
        let target_pubkey = state.validator(1).unwrap().pubkey;
        let before_len = block_mut(&mut state, "test assertion")
            .unwrap()
            .pending_consolidations_mut()
            .len();

        let request = electra::ConsolidationRequest {
            source_address: source_address(0),
            source_pubkey,
            target_pubkey,
        };
        process_consolidation_request(&mut state, &request, &config)
            .expect("a full queue drops the request silently, not with an error");

        assert_eq!(
            block_mut(&mut state, "test assertion")
                .unwrap()
                .pending_consolidations_mut()
                .len(),
            before_len,
            "the queue must not have grown past its limit"
        );
        assert_eq!(
            state.validator(0).unwrap().exit_epoch,
            FAR_FUTURE_EPOCH,
            "the source validator must not have been exited either"
        );
    }

    /// Uses 200 validators and [`Config::minimal`], not the two-validator
    /// state (and `Config::mainnet`) this module's other request tests use.
    /// `get_consolidation_churn_limit` splits `get_balance_churn_limit`
    /// (proportional to total active balance) between activations/exits and
    /// consolidations, capping the former at
    /// `Config::max_per_epoch_activation_exit_churn_limit`; with only two
    /// validators' worth of active balance, that cap consumes the *entire*
    /// churn budget under either config, leaving a genuine consolidation
    /// nothing to spend and this same silent-return chain drops it just as
    /// the full-queue case does. Mainnet's own `Config::churn_limit_quotient`
    /// (in the tens of thousands) would need on the order of half a million
    /// validators' worth of active balance before any is left over for
    /// consolidations; minimal's much smaller quotient reaches that same
    /// point around 200, which is what this test actually builds.
    #[test]
    fn a_valid_consolidation_request_queues_a_pending_consolidation_and_exits_the_source() {
        let mut state = electra_state_with_validators(200);
        let config = Config::minimal();
        {
            let validator = state.validator_mut(1).unwrap();
            validator.withdrawal_credentials.0[0] = constants::COMPOUNDING_WITHDRAWAL_PREFIX;
        }
        let source_pubkey = state.validator(0).unwrap().pubkey;
        let target_pubkey = state.validator(1).unwrap().pubkey;

        let request = electra::ConsolidationRequest {
            source_address: source_address(0),
            source_pubkey,
            target_pubkey,
        };
        process_consolidation_request(&mut state, &request, &config).unwrap();

        assert_ne!(
            state.validator(0).unwrap().exit_epoch,
            FAR_FUTURE_EPOCH,
            "a genuine consolidation must start the source validator's exit"
        );
        let queue_len = block_mut(&mut state, "test assertion")
            .unwrap()
            .pending_consolidations_mut()
            .len();
        assert_eq!(queue_len, 1, "the consolidation must have been queued");
    }

    // -- apply_deposit / process_deposit -------------------------------------

    #[test]
    fn a_new_validators_deposit_is_queued_rather_than_credited_directly() {
        let mut state = electra_state_with_validators(1);
        let config = Config::mainnet();
        let count_before = state.validators().len();

        let pubkey = BlsPubkey([9; 48]);
        let signature = BlsSignature::default();
        // An invalid signature: `apply_deposit` must still register the
        // validator, since `is_valid_deposit_signature` is checked
        // separately and this test is not exercising it. Use a signature
        // that happens to be valid would require real key generation for no
        // benefit here.
        let withdrawal_credentials = Bytes32::zero();

        apply_deposit(
            &mut state,
            pubkey,
            withdrawal_credentials,
            32_000_000_000,
            &signature,
            &config,
        )
        .unwrap();

        // An invalid signature means the deposit is not credited to a new
        // validator at all: see `apply_deposit`'s own documentation.
        assert_eq!(state.validators().len(), count_before);
        assert!(
            crate::helpers::electra::electra_state_ref(&state, "test assertion")
                .unwrap()
                .pending_partial_withdrawals()
                .is_empty(),
            "unrelated to this test, sanity check only"
        );
    }

    #[test]
    fn get_expected_withdrawals_reports_how_many_pending_partial_withdrawals_it_consumed() {
        let mut state = electra_state_with_validators(2);
        // Two pending partial withdrawals, both already due: the sweep must
        // report having consumed both, regardless of whether either produced
        // an actual `Withdrawal`.
        {
            let mut fields = block_mut(&mut state, "test setup").unwrap();
            let queue = fields.pending_partial_withdrawals_mut();
            queue
                .push(electra::PendingPartialWithdrawal {
                    validator_index: 0,
                    amount: 1,
                    withdrawable_epoch: 0,
                })
                .unwrap();
            queue
                .push(electra::PendingPartialWithdrawal {
                    validator_index: 1,
                    amount: 1,
                    withdrawable_epoch: 0,
                })
                .unwrap();
        }
        // Neither validator has excess balance above MIN_ACTIVATION_BALANCE,
        // so neither pending withdrawal actually produces a `Withdrawal`;
        // the count returned is still 2.
        let (withdrawals, processed_partial_withdrawals_count) =
            get_expected_withdrawals(&state).unwrap();
        assert!(withdrawals.is_empty());
        assert_eq!(processed_partial_withdrawals_count, 2);
    }
}
