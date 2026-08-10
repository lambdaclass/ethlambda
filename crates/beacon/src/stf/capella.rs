//! Capella's block processing: withdrawals.
//!
//! Before this fork a validator's balance could shrink, through penalties or
//! slashing, but it could never leave the consensus layer: there was nowhere
//! for it to go, since withdrawal credentials named only a BLS public key,
//! which the execution layer has no way to pay out to. Capella gives every
//! validator a way to get its balance out without ever submitting anything:
//! [`process_withdrawals`] sweeps a bounded slice of the validator registry
//! on every single block, pays out anyone it finds fully or partially
//! withdrawable, and [`BeaconState::next_withdrawal_index`] /
//! [`BeaconState::next_withdrawal_validator_index`] (reached here through
//! [`capella::BeaconState`]'s own fields) are the cursor that makes each
//! block's share of that sweep bounded regardless of how large the registry
//! grows. [`get_expected_withdrawals`] is the sweep itself;
//! [`process_bls_to_execution_change`] is the one new operation, a
//! validator's one-time upgrade from a raw BLS withdrawal credential to an
//! execution address, which is what makes it eligible for a payout in the
//! first place.
//!
//! # Why the sweep runs before the operations, not after
//!
//! [`process_block`]'s order, transcribed from the specification's own
//! `process_block`, is header, withdrawals, execution payload, RANDAO, eth1
//! vote, operations, sync aggregate. `bls_to_execution_changes` is one of the
//! operations, processed by [`process_operations`] near the end of that list,
//! well after [`process_withdrawals`] already ran. That placement is load
//! bearing, not incidental: it means a validator that upgrades its withdrawal
//! credentials in this very block is not swept by this same block, since the
//! sweep already read (and committed to) the old credentials before the
//! upgrade was even processed. The earliest a freshly upgraded validator can
//! be paid out is the next block's sweep.
//!
//! # Execution payload processing
//!
//! Capella's [`process_execution_payload`] is bellatrix's, minus the
//! [`super::bellatrix::is_merge_transition_complete`] check the specification
//! explicitly marks "Removed in Capella": every capella state's transition is
//! already behind it, so the check is redundant rather than differently
//! evaluated. Everything else bellatrix's version does, including
//! [`super::bellatrix::compute_timestamp_at_slot`] for the timestamp check,
//! is reused rather than copied; only the header-building step is written
//! fresh here, since capella's own [`capella::ExecutionPayloadHeader`] adds
//! `withdrawals_root` and is a distinct type from bellatrix's.

use crate::bls;
use crate::config::Config;
use crate::constants;
use crate::containers::shared::{Deposit, ProposerSlashing, SignedVoluntaryExit, Validator};
use crate::containers::{BeaconState, capella, phase0};
use crate::error::{Error, Result, verify};
use crate::hash::hash;
use crate::helpers::accessors::{get_current_epoch, get_randao_mix};
use crate::helpers::capella::{
    is_fully_withdrawable_validator, is_partially_withdrawable_validator,
};
use crate::helpers::misc::{compute_domain, compute_signing_root};
use crate::helpers::mutators::decrease_balance;
use crate::preset;
use crate::primitives::{ExecutionAddress, H256, HashTreeRoot as _};

use super::ExecutionEngine;

// ---------------------------------------------------------------------------
// Block processing
// ---------------------------------------------------------------------------

/// Capella's block processing: the withdrawal sweep and the execution payload
/// step ahead of everything altair and bellatrix already run, in the
/// specification's own order.
///
/// See this module's own documentation for why [`process_withdrawals`] runs
/// before [`process_operations`], and so before this same block's own
/// `bls_to_execution_changes` are processed.
pub fn process_block(
    state: &mut BeaconState,
    block: &capella::BeaconBlock,
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
    process_execution_payload(state, &block.body.execution_payload, config, engine)?;
    super::block::process_randao(state, &block.body.randao_reveal)?;
    super::block::process_eth1_data(state, &block.body.eth1_data)?;
    process_operations(
        state,
        &block.body.proposer_slashings,
        &block.body.attester_slashings,
        &block.body.attestations,
        &block.body.deposits,
        &block.body.voluntary_exits,
        &block.body.bls_to_execution_changes,
        config,
    )?;
    super::altair::process_sync_aggregate(state, &block.body.sync_aggregate)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Withdrawals
// ---------------------------------------------------------------------------

/// The execution address a validator's payout is sent to: the low bytes of
/// its eth1 withdrawal credentials, the same bytes
/// [`process_bls_to_execution_change`] writes when a validator upgrades into
/// this form.
fn withdrawal_address(validator: &Validator) -> ExecutionAddress {
    ExecutionAddress::from_slice(&validator.withdrawal_credentials.0[12..])
}

/// The withdrawals this block's sweep owes, without applying them.
///
/// A bounded walk of the validator registry starting at
/// [`capella::BeaconState::next_withdrawal_validator_index`], not a scan of
/// the whole thing: `bound` caps how many validators one call ever visits at
/// [`preset::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP`], and the loop also stops
/// the moment it has collected [`preset::MAX_WITHDRAWALS_PER_PAYLOAD`]
/// withdrawals, whichever comes first. Both are what keep a single block's
/// share of the sweep bounded regardless of how large the registry grows:
/// without them, a registry of unbounded size would make one block's
/// state-transition cost unbounded too.
///
/// The index advances past `validator_count` by wrapping with `%`, so the
/// sweep revisits validator zero right after the last one rather than
/// stopping at the end of the registry; [`process_withdrawals`] is what
/// persists the cursor this function starts from and leaves behind.
pub fn get_expected_withdrawals(state: &BeaconState) -> Result<Vec<capella::Withdrawal>> {
    let epoch = get_current_epoch(state);
    // Through the fork-generic cursor accessor rather than this module's
    // projection to `capella::BeaconState`. Deneb reuses this function unchanged
    // (its own `process_withdrawals` calls straight into it), and a projection
    // to capella's concrete state rejects a deneb state outright, so reading the
    // cursor that way made every deneb block carrying a withdrawal fail at
    // runtime.
    let (mut withdrawal_index, mut validator_index) = state.withdrawal_cursor()?;

    let validator_count = state.validators().len() as u64;
    let bound = validator_count.min(preset::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP);

    let mut withdrawals = Vec::new();
    for _ in 0..bound {
        let validator = state.validator(validator_index)?;
        let balance = state.balance(validator_index)?;

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
            // `is_partially_withdrawable_validator` already requires `balance
            // > MAX_EFFECTIVE_BALANCE`, so this cannot underflow; checked
            // anyway, since the cost of checking is free and nothing here
            // should ever rely on a predicate elsewhere staying exactly this
            // strict.
            let amount = balance
                .checked_sub(preset::MAX_EFFECTIVE_BALANCE)
                .ok_or(Error::ArithmeticOverflow("balance - MAX_EFFECTIVE_BALANCE"))?;
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

        // First early stop: a full payload's worth of withdrawals, regardless
        // of how much of the sweep bound is left to visit.
        if withdrawals.len() == preset::MAX_WITHDRAWALS_PER_PAYLOAD {
            break;
        }
        validator_index = validator_index
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("validator_index + 1"))?
            % validator_count;
    }
    // Second early stop: the loop above never runs more than `bound`
    // iterations, so a registry larger than
    // `MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP` with nothing withdrawable in this
    // round's window returns an empty list here rather than scanning every
    // validator in the registry.

    Ok(withdrawals)
}

/// Applies this block's withdrawal sweep: checks the block's declared
/// `payload.withdrawals` against what the sweep actually owes, pays each one
/// out, and advances the sweep's cursor for next time.
///
/// The cursor update has two cases, and they diverge in a way that is easy to
/// miss reading only the "happy path": when the sweep filled a whole payload
/// (`expected_withdrawals.len() == MAX_WITHDRAWALS_PER_PAYLOAD`),
/// `next_withdrawal_validator_index` resumes right after the last validator
/// actually paid. Otherwise the sweep ran its entire bound without filling
/// the payload, and the cursor instead advances by the *constant*
/// `MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP`, added to the cursor's value from
/// before this call, not to wherever [`get_expected_withdrawals`]'s loop
/// happened to land. On a registry smaller than that constant, those are
/// different validators: the loop itself only ever visits
/// `min(validator_count, MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP)` indices and
/// wraps `validator_count`-periodically, while this update wraps the larger,
/// unclamped constant, so the next sweep can start from a position the
/// previous one never actually reached.
pub fn process_withdrawals(
    state: &mut BeaconState,
    payload: &capella::ExecutionPayload,
) -> Result<()> {
    let expected_withdrawals = get_expected_withdrawals(state)?;
    verify(
        payload.withdrawals.to_vec() == expected_withdrawals,
        "payload.withdrawals == expected_withdrawals",
    )?;

    for withdrawal in &expected_withdrawals {
        decrease_balance(state, withdrawal.validator_index, withdrawal.amount)?;
    }

    // Update the next withdrawal index if this block contained withdrawals.
    if let Some(latest_withdrawal) = expected_withdrawals.last() {
        capella_state(state, "process_withdrawals")?.next_withdrawal_index = latest_withdrawal
            .index
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("latest_withdrawal.index + 1"))?;
    }

    // Update the next validator index to start the next withdrawal sweep. See
    // this function's own documentation for why the two branches below do not
    // agree on where "next" is once the registry is smaller than
    // MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP.
    let validator_count = state.validators().len() as u64;
    let next_validator_index = if expected_withdrawals.len() == preset::MAX_WITHDRAWALS_PER_PAYLOAD
    {
        // A full payload: the next sweep resumes right after the last
        // validator this block actually paid.
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
        // Not a full payload: advance the sweep by its own maximum length,
        // from the cursor as it stood before this call, not from wherever the
        // (already-exhausted) sweep loop ended up.
        let current_cursor =
            capella_state_ref(state, "process_withdrawals")?.next_withdrawal_validator_index;
        current_cursor
            .checked_add(preset::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP)
            .ok_or(Error::ArithmeticOverflow(
                "next_withdrawal_validator_index + MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP",
            ))?
            % validator_count
    };
    capella_state(state, "process_withdrawals")?.next_withdrawal_validator_index =
        next_validator_index;

    Ok(())
}

// ---------------------------------------------------------------------------
// Execution payload
// ---------------------------------------------------------------------------

/// Validates this slot's execution payload and caches its header.
///
/// Bellatrix's [`super::bellatrix::process_execution_payload`] with the
/// `is_merge_transition_complete` check the specification marks "Removed in
/// Capella" dropped, and reusing bellatrix's own
/// [`super::bellatrix::compute_timestamp_at_slot`] for the timestamp check
/// rather than a second copy of it. Takes `config` for the same reason
/// bellatrix's version does: the specification's `compute_time_at_slot`
/// reaches `SECONDS_PER_SLOT` from global scope, but this crate keeps that
/// value as [`Config::seconds_per_slot`], a runtime value rather than a
/// preset, so anything that calls through to it needs one.
pub fn process_execution_payload(
    state: &mut BeaconState,
    payload: &capella::ExecutionPayload,
    config: &Config,
    engine: &ExecutionEngine,
) -> Result<()> {
    verify(
        payload.parent_hash
            == capella_state_ref(state, "process_execution_payload")?
                .latest_execution_payload_header
                .block_hash,
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
    verify(
        engine.execution_valid,
        "verify_and_notify_new_payload(NewPayloadRequest(execution_payload=payload))",
    )?;

    let header = capella::ExecutionPayloadHeader {
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
        // [New in Capella]
        withdrawals_root: payload.withdrawals.hash_tree_root(),
    };
    capella_state(state, "process_execution_payload")?.latest_execution_payload_header = header;

    Ok(())
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Runs every operation in a block, in the specification's order: phase0's
/// five lists, unchanged, plus this fork's own `bls_to_execution_changes`
/// appended after them.
///
/// Delegates the first five lists to [`super::operations::process_operations`]
/// wholesale (deposit-count check included) rather than re-running each
/// per-operation function here: that function already calls the identical
/// functions in the identical order for every fork through deneb, and capella
/// changes none of them, so there is nothing for this to do differently
/// beyond adding the one new loop.
///
/// Eight parameters, one past clippy's default limit, because this mirrors
/// the specification's own `process_operations(state, body)` unpacked into
/// the fields it reads rather than a whole body; see [`crate::stf`]'s module
/// documentation for why that unpacking is the point rather than an accident.
#[allow(clippy::too_many_arguments)]
pub fn process_operations(
    state: &mut BeaconState,
    proposer_slashings: &[ProposerSlashing],
    attester_slashings: &[phase0::AttesterSlashing],
    attestations: &[phase0::Attestation],
    deposits: &[Deposit],
    voluntary_exits: &[SignedVoluntaryExit],
    bls_to_execution_changes: &[capella::SignedBLSToExecutionChange],
    config: &Config,
) -> Result<()> {
    super::operations::process_operations(
        state,
        proposer_slashings,
        attester_slashings,
        attestations,
        deposits,
        voluntary_exits,
        config,
    )?;
    for signed_change in bls_to_execution_changes {
        process_bls_to_execution_change(state, signed_change, config)?;
    }
    Ok(())
}

/// Upgrades a validator's withdrawal credentials from a raw BLS public key
/// hash to an execution address, the one operation that makes a validator
/// eligible for [`get_expected_withdrawals`]'s sweep at all.
///
/// Checked, in order: the credential really is the BLS-prefixed form (an
/// eth1-form credential has nothing left to upgrade), the credential's tail
/// really is the hash of the pubkey the request claims to be upgrading from
/// (proving the request is not renaming someone else's validator), and the
/// signature over the request verifies against that same pubkey.
///
/// The signature is checked against
/// [`constants::DOMAIN_BLS_TO_EXECUTION_CHANGE`] combined with
/// [`Config::genesis_fork_version`], not the state's current fork version the
/// way [`crate::helpers::accessors::get_domain`] would compute it. That looks
/// like a bug, since every other signed message in this crate signs under
/// whichever fork was active when the message was produced, but the
/// specification calls it out explicitly ("Fork-agnostic domain since address
/// changes are valid across forks") and means it: the validator holding the
/// BLS credential being replaced may not have been online, or even
/// instantiated, since genesis, so pinning the domain to a version that
/// cannot itself be superseded is what keeps this specific signature valid no
/// matter how many later forks have happened by the time it is actually
/// submitted.
pub fn process_bls_to_execution_change(
    state: &mut BeaconState,
    signed_change: &capella::SignedBLSToExecutionChange,
    config: &Config,
) -> Result<()> {
    let change = &signed_change.message;

    let validator = state.validator(change.validator_index)?;
    verify(
        validator.withdrawal_credentials.0[0] == constants::BLS_WITHDRAWAL_PREFIX,
        "validator.withdrawal_credentials[:1] == BLS_WITHDRAWAL_PREFIX",
    )?;
    let hashed_pubkey = hash(&change.from_bls_pubkey.0);
    verify(
        validator.withdrawal_credentials.0[1..] == hashed_pubkey.0[1..],
        "validator.withdrawal_credentials[1:] == hash(address_change.from_bls_pubkey)[1:]",
    )?;

    let domain = compute_domain(
        constants::DOMAIN_BLS_TO_EXECUTION_CHANGE,
        config.genesis_fork_version,
        state.genesis_validators_root(),
    );
    let signing_root = compute_signing_root(change.hash_tree_root(), domain);
    verify(
        bls::verify(
            &change.from_bls_pubkey,
            signing_root,
            &signed_change.signature,
        ),
        "bls.Verify(address_change.from_bls_pubkey, signing_root, signed_address_change.signature)",
    )?;

    let mut credentials = [0u8; 32];
    credentials[0] = constants::ETH1_ADDRESS_WITHDRAWAL_PREFIX;
    credentials[12..].copy_from_slice(&change.to_execution_address.0);
    state
        .validator_mut(change.validator_index)?
        .withdrawal_credentials = H256(credentials);

    Ok(())
}

// ---------------------------------------------------------------------------
// Fork projection
// ---------------------------------------------------------------------------

/// The capella state, mutably, or an error naming the function that needs
/// one.
///
/// Scoped to `BeaconState::Capella` alone, not to every later fork that keeps
/// the same withdrawal-cursor fields. Every caller in this file is reached
/// only through [`process_block`], which [`super::block::process_block`]
/// dispatches to precisely when `state` is already `BeaconState::Capella`, so
/// nothing here ever needs to read a deneb, electra, or fulu state. See
/// [`super::bellatrix::bellatrix_state`]'s own documentation for the identical
/// reasoning one fork earlier: each later fork's own block-processing module
/// will need its own projection of this same shape to reach its own
/// `latest_execution_payload_header` (a distinct type per fork from bellatrix
/// on) and its own withdrawal cursor, not this one widened to somehow return
/// a different concrete type per caller.
fn capella_state<'a>(
    state: &'a mut BeaconState,
    function: &'static str,
) -> Result<&'a mut capella::BeaconState> {
    match state {
        BeaconState::Capella(state) => Ok(state),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

/// The capella state, immutably. See [`capella_state`].
fn capella_state_ref<'a>(
    state: &'a BeaconState,
    function: &'static str,
) -> Result<&'a capella::BeaconState> {
    match state {
        BeaconState::Capella(state) => Ok(state),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use blst::min_pk::SecretKey;

    use super::*;
    use crate::fork::ForkName;
    use crate::primitives::{
        BlsPubkey, BlsSignature, ExecutionBlockHash, Gwei, Root, Uint256, ValidatorIndex,
    };
    use libssz_types::SszVector;

    /// A capella state with `count` fully active, full-balance validators, one
    /// epoch in (so the block-root history window already has entries).
    ///
    /// Every validator's pubkey is left at its all-zero default rather than a
    /// real curve point: nothing under test here (the withdrawal sweep, its
    /// cursor arithmetic, or the BLS-to-execution-change operation) ever
    /// verifies a signature against a validator's own `pubkey`, so paying for
    /// real key generation on every validator, which matters once a test
    /// needs a registry larger than `MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP`,
    /// would buy nothing.
    ///
    /// A thin wrapper around the shared fork-parameterised builder: see
    /// [`crate::helpers::test_state::with_validators_at`] for the construction
    /// this and every other fork's test module used to duplicate.
    fn capella_state_with_validators(count: usize) -> BeaconState {
        crate::helpers::test_state::with_validators_at(ForkName::Capella, count)
    }

    /// Marks validator `index` fully withdrawable: an eth1 credential, a
    /// withdrawable epoch already past, and a positive balance.
    fn make_fully_withdrawable(state: &mut BeaconState, index: ValidatorIndex, balance: Gwei) {
        {
            let validator = state.validator_mut(index).unwrap();
            validator.withdrawal_credentials.0[0] = constants::ETH1_ADDRESS_WITHDRAWAL_PREFIX;
            validator.withdrawable_epoch = 0;
        }
        state.balances_mut()[index as usize] = balance;
    }

    fn empty_execution_payload() -> capella::ExecutionPayload {
        capella::ExecutionPayload {
            parent_hash: ExecutionBlockHash::zero(),
            fee_recipient: ExecutionAddress::zero(),
            state_root: Root::zero(),
            receipts_root: Root::zero(),
            logs_bloom: SszVector::try_from(vec![0u8; preset::BYTES_PER_LOGS_BLOOM])
                .expect("built at exactly BYTES_PER_LOGS_BLOOM"),
            prev_randao: Root::zero(),
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: Default::default(),
            base_fee_per_gas: Uint256::zero(),
            block_hash: ExecutionBlockHash::zero(),
            transactions: Default::default(),
            withdrawals: Default::default(),
        }
    }

    // -----------------------------------------------------------------------
    // get_expected_withdrawals
    // -----------------------------------------------------------------------

    #[test]
    fn the_sweep_wraps_around_past_the_end_of_the_registry() {
        let mut state = capella_state_with_validators(3);
        for index in 0..3u64 {
            make_fully_withdrawable(&mut state, index, preset::MAX_EFFECTIVE_BALANCE);
        }
        // Starting the cursor at the last validator forces a bound of three
        // (or more) to wrap back to index 0 rather than running off the end
        // of the registry.
        capella_state(&mut state, "test setup")
            .unwrap()
            .next_withdrawal_validator_index = 2;

        let withdrawals = get_expected_withdrawals(&state).unwrap();
        let visited: Vec<ValidatorIndex> = withdrawals.iter().map(|w| w.validator_index).collect();
        assert_eq!(
            visited,
            vec![2, 0, 1],
            "the sweep must wrap through index 0 rather than stop or error at the end"
        );
    }

    #[test]
    fn the_sweep_stops_once_a_full_payload_is_collected() {
        let count = preset::MAX_WITHDRAWALS_PER_PAYLOAD + 5;
        let mut state = capella_state_with_validators(count);
        for index in 0..count as u64 {
            make_fully_withdrawable(&mut state, index, preset::MAX_EFFECTIVE_BALANCE);
        }

        let withdrawals = get_expected_withdrawals(&state).unwrap();
        assert_eq!(
            withdrawals.len(),
            preset::MAX_WITHDRAWALS_PER_PAYLOAD,
            "the sweep must stop the moment a full payload is collected, even though \
             every remaining validator in the bound is also withdrawable"
        );
    }

    #[test]
    fn the_sweep_never_visits_past_its_own_bound() {
        // A registry one validator larger than the sweep bound, with only the
        // validator just past the bound withdrawable: if the sweep reached
        // it, the bound would not be doing anything. Every validator here
        // keeps its all-default (non-real) pubkey, which is what makes a
        // registry this large cheap to build.
        let bound = preset::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP as usize;
        let count = bound + 1;
        let mut state = capella_state_with_validators(count);
        make_fully_withdrawable(
            &mut state,
            bound as ValidatorIndex,
            preset::MAX_EFFECTIVE_BALANCE,
        );

        let withdrawals = get_expected_withdrawals(&state).unwrap();
        assert!(
            withdrawals.is_empty(),
            "the sweep must not visit a validator past MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP"
        );
    }

    // -----------------------------------------------------------------------
    // process_withdrawals
    // -----------------------------------------------------------------------

    #[test]
    fn a_full_payload_resumes_the_cursor_right_after_the_last_withdrawal_paid() {
        let count = preset::MAX_WITHDRAWALS_PER_PAYLOAD + 2;
        let mut state = capella_state_with_validators(count);
        for index in 0..count as u64 {
            make_fully_withdrawable(&mut state, index, preset::MAX_EFFECTIVE_BALANCE);
        }

        let expected = get_expected_withdrawals(&state).unwrap();
        assert_eq!(expected.len(), preset::MAX_WITHDRAWALS_PER_PAYLOAD);
        let last = expected.last().unwrap().clone();

        let payload = capella::ExecutionPayload {
            withdrawals: expected.try_into().unwrap(),
            ..empty_execution_payload()
        };
        process_withdrawals(&mut state, &payload).unwrap();

        let inner = capella_state_ref(&state, "test assertion").unwrap();
        assert_eq!(inner.next_withdrawal_index, last.index + 1);
        assert_eq!(
            inner.next_withdrawal_validator_index,
            (last.validator_index + 1) % count as u64
        );
    }

    #[test]
    fn a_partial_sweep_advances_the_cursor_by_the_bound_from_before_the_call() {
        // Nobody in this registry is withdrawable, so the sweep runs its
        // whole bound and returns nothing. The cursor must still move: by
        // MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP from wherever it stood before
        // this call, not by however many validators the (empty) sweep loop
        // actually visited.
        let count = 5;
        let mut state = capella_state_with_validators(count);
        capella_state(&mut state, "test setup")
            .unwrap()
            .next_withdrawal_validator_index = 2;

        let expected = get_expected_withdrawals(&state).unwrap();
        assert!(
            expected.is_empty(),
            "nobody in this registry is withdrawable"
        );

        let payload = capella::ExecutionPayload {
            withdrawals: Default::default(),
            ..empty_execution_payload()
        };
        process_withdrawals(&mut state, &payload).unwrap();

        let inner = capella_state_ref(&state, "test assertion").unwrap();
        let expected_next = (2 + preset::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP) % count as u64;
        assert_eq!(inner.next_withdrawal_validator_index, expected_next);
    }

    #[test]
    fn a_block_declaring_the_wrong_withdrawals_is_rejected() {
        let mut state = capella_state_with_validators(3);
        make_fully_withdrawable(&mut state, 0, preset::MAX_EFFECTIVE_BALANCE);

        let payload = capella::ExecutionPayload {
            // The sweep owes one withdrawal; declaring none must fail.
            withdrawals: Default::default(),
            ..empty_execution_payload()
        };
        assert!(process_withdrawals(&mut state, &payload).is_err());
    }

    // -----------------------------------------------------------------------
    // process_bls_to_execution_change
    // -----------------------------------------------------------------------

    /// `specs/altair/bls.md`'s BLS proof-of-possession domain separation tag,
    /// the same one every other real-signature test in this crate signs
    /// under.
    const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    #[test]
    fn a_credential_change_verifies_under_the_genesis_fork_version_not_the_current_one() {
        let config = Config::mainnet();
        let mut state = capella_state_with_validators(2);
        // A capella state's own fork version is not the genesis one: proves
        // the signature is checked against `config.genesis_fork_version`
        // specifically, not `state.fork().current_version`, which would also
        // be available here and would silently pass a same-fork test without
        // proving anything about which version is actually used.
        state.fork_mut().current_version = config.capella_fork_version;
        state.fork_mut().epoch = config.capella_fork_epoch;
        assert_ne!(config.capella_fork_version, config.genesis_fork_version);

        let secret_key = SecretKey::key_gen(&[3u8; 32], &[]).expect("32 bytes of key material");
        let from_pubkey = BlsPubkey(secret_key.sk_to_pk().to_bytes());
        let hashed = hash(&from_pubkey.0);
        {
            let validator = state.validator_mut(0).unwrap();
            validator.withdrawal_credentials.0[0] = constants::BLS_WITHDRAWAL_PREFIX;
            validator.withdrawal_credentials.0[1..].copy_from_slice(&hashed.0[1..]);
        }

        let message = capella::BLSToExecutionChange {
            validator_index: 0,
            from_bls_pubkey: from_pubkey,
            to_execution_address: ExecutionAddress::repeat_byte(0xab),
        };
        let genesis_domain = compute_domain(
            constants::DOMAIN_BLS_TO_EXECUTION_CHANGE,
            config.genesis_fork_version,
            state.genesis_validators_root(),
        );
        let signing_root = compute_signing_root(message.hash_tree_root(), genesis_domain);
        let signature = BlsSignature(
            secret_key
                .sign(signing_root.as_bytes(), DST, &[])
                .to_bytes(),
        );
        let signed_change = capella::SignedBLSToExecutionChange { message, signature };

        process_bls_to_execution_change(&mut state, &signed_change, &config).unwrap();

        let validator = state.validator(0).unwrap();
        assert_eq!(
            validator.withdrawal_credentials.0[0],
            constants::ETH1_ADDRESS_WITHDRAWAL_PREFIX
        );
        assert_eq!(
            &validator.withdrawal_credentials.0[12..],
            ExecutionAddress::repeat_byte(0xab).as_bytes()
        );
    }

    #[test]
    fn a_signature_made_under_the_current_fork_version_is_rejected() {
        let config = Config::mainnet();
        let mut state = capella_state_with_validators(2);
        state.fork_mut().current_version = config.capella_fork_version;
        state.fork_mut().epoch = config.capella_fork_epoch;

        let secret_key = SecretKey::key_gen(&[4u8; 32], &[]).expect("32 bytes of key material");
        let from_pubkey = BlsPubkey(secret_key.sk_to_pk().to_bytes());
        let hashed = hash(&from_pubkey.0);
        {
            let validator = state.validator_mut(0).unwrap();
            validator.withdrawal_credentials.0[0] = constants::BLS_WITHDRAWAL_PREFIX;
            validator.withdrawal_credentials.0[1..].copy_from_slice(&hashed.0[1..]);
        }

        let message = capella::BLSToExecutionChange {
            validator_index: 0,
            from_bls_pubkey: from_pubkey,
            to_execution_address: ExecutionAddress::repeat_byte(0xab),
        };
        // Signed under the state's current (capella) fork version, which
        // process_bls_to_execution_change must not accept.
        let wrong_domain = compute_domain(
            constants::DOMAIN_BLS_TO_EXECUTION_CHANGE,
            config.capella_fork_version,
            state.genesis_validators_root(),
        );
        let signing_root = compute_signing_root(message.hash_tree_root(), wrong_domain);
        let signature = BlsSignature(
            secret_key
                .sign(signing_root.as_bytes(), DST, &[])
                .to_bytes(),
        );
        let signed_change = capella::SignedBLSToExecutionChange { message, signature };

        assert!(process_bls_to_execution_change(&mut state, &signed_change, &config).is_err());
    }

    #[test]
    fn a_credential_not_in_the_bls_form_is_rejected() {
        let config = Config::mainnet();
        let mut state = capella_state_with_validators(1);
        state.validator_mut(0).unwrap().withdrawal_credentials.0[0] =
            constants::ETH1_ADDRESS_WITHDRAWAL_PREFIX;

        let secret_key = SecretKey::key_gen(&[5u8; 32], &[]).expect("32 bytes of key material");
        let message = capella::BLSToExecutionChange {
            validator_index: 0,
            from_bls_pubkey: BlsPubkey(secret_key.sk_to_pk().to_bytes()),
            to_execution_address: ExecutionAddress::repeat_byte(0xab),
        };
        let signed_change = capella::SignedBLSToExecutionChange {
            message,
            signature: BlsSignature::default(),
        };

        assert!(process_bls_to_execution_change(&mut state, &signed_change, &config).is_err());
    }
}
