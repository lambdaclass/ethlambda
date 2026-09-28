//! Gloas's block processing, withdrawals, execution payload bid, parent
//! execution payload processing, and execution payload envelope verification
//! (EIP-7732).
//!
//! Withdrawals gain two new sweeps of their own: builders can be paid out
//! ([`get_builder_withdrawals`], draining
//! [`gloas::BeaconState::builder_pending_withdrawals`]) and swept the same
//! way validators are ([`get_builders_sweep_withdrawals`]), both ahead of the
//! validator-side sweeps `crate::beacon::stf::electra::get_pending_partial_withdrawals`
//! and `crate::beacon::stf::electra::get_validators_sweep_withdrawals` carry
//! over from electra unmodified (see [`get_expected_withdrawals`] for the
//! order all four run in). [`process_withdrawals`] itself drops its
//! `payload` parameter entirely: withdrawals are now deterministic from the
//! state alone, since there is no payload for a block to carry them in.
//!
//! A block no longer embeds its own payload at all. It commits to a builder's
//! bid instead ([`process_execution_payload_bid`]), and the previous slot's
//! payload is only processed once the *next* block reveals whether it showed
//! up ([`process_parent_execution_payload`]): [`apply_parent_execution_payload`]
//! is where a "full" parent's execution-layer-triggered requests are finally
//! run and its builder paid.
//!
//! # Execution-layer-triggered requests live here, not with block operations
//!
//! Deposit, withdrawal, and consolidation requests, and the two new builder
//! registry requests ([`process_builder_deposit_request`],
//! [`process_builder_exit_request`]), are reached exactly one way: through
//! [`apply_parent_execution_payload`]'s `requests` parameter. Gloas's own
//! `process_operations` *removes* the calls to the first three outright, and
//! neither builder request is ever on that list to begin with, so none of
//! the five belong with block operations at all.
//!
//! The first three are not *behaviorally* new: no fork after fulu lists a
//! modified version of any of them, so [`apply_parent_execution_payload`]
//! calls straight into `crate::beacon::stf::fulu::process_deposit_request`
//! and `crate::beacon::stf::electra::{process_withdrawal_request,
//! process_consolidation_request}` rather than keeping copies. What changed
//! is only the Rust type of the lists those functions touch:
//! [`gloas::BeaconState::pending_deposits`],
//! [`gloas::BeaconState::pending_partial_withdrawals`], and
//! [`gloas::BeaconState::pending_consolidations`] are EIP-7688's progressive
//! lists, a different Rust type from electra's and fulu's bounded ones, so
//! those shared functions reach them through
//! [`crate::beacon::helpers::electra::PendingQueueFields`] (and its
//! read-only counterpart), which abstracts over exactly that type change,
//! rather than through a gloas-only copy.

use libssz::SszEncode as _;

use crate::beacon::bls;
use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::shared::{DepositMessage, ProposerSlashing};
use crate::beacon::containers::{BeaconState, capella, gloas};
use crate::beacon::error::{Error, Result, verify};
use crate::beacon::helpers::accessors::{
    CommitteeCache, CommitteeCacheExt, get_beacon_proposer_index, get_block_root_at_slot,
    get_current_epoch, get_domain, get_previous_epoch, get_randao_mix,
};
use crate::beacon::helpers::altair::{add_flag, get_base_reward_per_increment, has_flag};
use crate::beacon::helpers::electra::{g2_point_at_infinity, get_committee_indices};
use crate::beacon::helpers::gloas::{
    add_builder_to_registry, can_builder_cover_bid, convert_builder_index_to_validator_index,
    convert_validator_index_to_builder_index, get_attestation_participation_flag_indices,
    get_indexed_attestation, get_indexed_payload_attestation, gloas_state, gloas_state_ref,
    initiate_builder_exit, is_active_builder, is_attestation_same_slot, is_builder_index,
    is_builder_withdrawal_credential, is_valid_indexed_attestation,
    is_valid_indexed_payload_attestation, settle_builder_payment,
};
use crate::beacon::helpers::misc::{compute_domain, compute_epoch_at_slot, compute_signing_root};
use crate::beacon::helpers::mutators::{decrease_balance, increase_balance, slash_validator};
use crate::beacon::helpers::predicates::is_slashable_attestation_data;
use crate::beacon::preset;
use crate::beacon::primitives::{
    Bytes32, ExecutionAddress, Gwei, HashTreeRoot as _, ParticipationFlags, Root, Slot,
    ValidatorIndex, WithdrawalIndex,
};

use super::ExecutionEngine;

// ---------------------------------------------------------------------------
// Block processing
// ---------------------------------------------------------------------------

/// `process_block` (gloas `beacon-chain.md`).
///
/// No execution payload is embedded in a gloas block, unlike every earlier
/// fork's own `process_block`: the body only commits to a builder's bid
/// ([`process_execution_payload_bid`]), and the payload itself is verified
/// separately, once revealed, by [`verify_execution_payload_envelope`]. So,
/// unlike [`crate::beacon::stf::fulu::process_block`] and its own siblings,
/// this function takes no [`ExecutionEngine`].
///
/// `parent_slot` is read from `state.latest_block_header` before anything
/// else runs: [`process_parent_execution_payload`], the very next step,
/// processes the payload that header's own slot names, and
/// [`super::block::process_block_header`], two steps after that, overwrites
/// the header with this block's own. Reading it any later would read this
/// block's slot instead of its parent's.
pub fn process_block(
    state: &mut BeaconState,
    block: &gloas::BeaconBlock,
    config: &Config,
    committees: &CommitteeCache,
) -> Result<()> {
    // [New in Gloas:EIP7732]
    let parent_slot = state.latest_block_header().slot;

    // [New in Gloas:EIP7732]
    process_parent_execution_payload(state, block, config)?;
    super::block::process_block_header(
        state,
        block.slot,
        block.proposer_index,
        block.parent_root,
        block.body.hash_tree_root(),
    )?;
    // [Modified in Gloas:EIP7732]
    process_withdrawals(state)?;
    // [Modified in Gloas:EIP7732] Removed `process_execution_payload`.
    // [New in Gloas:EIP7732]
    process_execution_payload_bid(state, &block.body.signed_execution_payload_bid, config)?;
    super::block::process_randao(state, &block.body.randao_reveal)?;
    super::block::process_eth1_data(state, &block.body.eth1_data)?;
    // [Modified in Gloas:EIP7732]
    process_operations(state, &block.body, parent_slot, config, committees)?;
    super::altair::process_sync_aggregate(state, &block.body.sync_aggregate)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Withdrawals
// ---------------------------------------------------------------------------

/// `ExpectedWithdrawals` (gloas `beacon-chain.md`): a plain Rust struct, not
/// an SSZ container, since the specification's dataclass never crosses the
/// wire itself, only [`Self::withdrawals`] does, as
/// [`gloas::BeaconState::payload_expected_withdrawals`].
pub struct ExpectedWithdrawals {
    pub withdrawals: Vec<capella::Withdrawal>,
    pub processed_builder_withdrawals_count: u64,
    pub processed_partial_withdrawals_count: u64,
    pub processed_builders_sweep_count: u64,
    pub processed_sweep_withdrawals_count: u64,
}

/// `get_builder_withdrawals` (gloas `beacon-chain.md`): the withdrawals owed
/// to builders queued in [`gloas::BeaconState::builder_pending_withdrawals`],
/// oldest first, up to `MAX_WITHDRAWALS_PER_PAYLOAD - 1` (one slot is always
/// reserved for the validator sweep further down [`get_expected_withdrawals`]'s
/// own order).
pub fn get_builder_withdrawals(
    state: &BeaconState,
    mut withdrawal_index: WithdrawalIndex,
    prior_withdrawals: &[capella::Withdrawal],
) -> Result<(Vec<capella::Withdrawal>, WithdrawalIndex, u64)> {
    let withdrawals_limit = preset::MAX_WITHDRAWALS_PER_PAYLOAD - 1;
    verify(
        prior_withdrawals.len() <= withdrawals_limit,
        "get_builder_withdrawals: len(prior_withdrawals) <= withdrawals_limit",
    )?;

    let mut processed_count: u64 = 0;
    let mut withdrawals = Vec::new();
    let inner = gloas_state_ref(state, "get_builder_withdrawals")?;
    for withdrawal in inner.builder_pending_withdrawals.iter() {
        if prior_withdrawals.len() + withdrawals.len() >= withdrawals_limit {
            break;
        }

        withdrawals.push(capella::Withdrawal {
            index: withdrawal_index,
            validator_index: convert_builder_index_to_validator_index(withdrawal.builder_index),
            address: withdrawal.fee_recipient,
            amount: withdrawal.amount,
        });
        withdrawal_index = withdrawal_index
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow(
                "get_builder_withdrawals: withdrawal_index + 1",
            ))?;
        processed_count += 1;
    }

    Ok((withdrawals, withdrawal_index, processed_count))
}

/// `get_builders_sweep_withdrawals` (gloas `beacon-chain.md`): the builder
/// registry's own counterpart of
/// [`get_validators_sweep_withdrawals`](crate::beacon::stf::electra::get_validators_sweep_withdrawals),
/// swept
/// from [`gloas::BeaconState::next_withdrawal_builder_index`] the same
/// bounded, wrapping way.
pub fn get_builders_sweep_withdrawals(
    state: &BeaconState,
    mut withdrawal_index: WithdrawalIndex,
    prior_withdrawals: &[capella::Withdrawal],
) -> Result<(Vec<capella::Withdrawal>, WithdrawalIndex, u64)> {
    let epoch = get_current_epoch(state);
    let inner = gloas_state_ref(state, "get_builders_sweep_withdrawals")?;
    let builders_len = inner.builders.len() as u64;
    let builders_limit = builders_len.min(preset::MAX_BUILDERS_PER_WITHDRAWALS_SWEEP);
    let withdrawals_limit = preset::MAX_WITHDRAWALS_PER_PAYLOAD - 1;
    verify(
        prior_withdrawals.len() <= withdrawals_limit,
        "get_builders_sweep_withdrawals: len(prior_withdrawals) <= withdrawals_limit",
    )?;

    let mut processed_count: u64 = 0;
    let mut withdrawals = Vec::new();
    let mut builder_index = inner.next_withdrawal_builder_index;
    for _ in 0..builders_limit {
        if prior_withdrawals.len() + withdrawals.len() >= withdrawals_limit {
            break;
        }

        let builder =
            inner
                .builders
                .get(builder_index as usize)
                .ok_or(Error::IndexOutOfBounds {
                    index: builder_index as usize,
                    len: inner.builders.len(),
                })?;
        if builder.withdrawable_epoch <= epoch && builder.balance > 0 {
            withdrawals.push(capella::Withdrawal {
                index: withdrawal_index,
                validator_index: convert_builder_index_to_validator_index(builder_index),
                address: builder.execution_address,
                amount: builder.balance,
            });
            withdrawal_index = withdrawal_index
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow(
                    "get_builders_sweep_withdrawals: withdrawal_index + 1",
                ))?;
        }

        // `builders_limit <= builders_len`, and this loop only ever runs when
        // `builders_limit > 0`, so `builders_len` is never zero here.
        builder_index = builder_index
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow(
                "get_builders_sweep_withdrawals: builder_index + 1",
            ))?
            % builders_len;
        processed_count += 1;
    }

    Ok((withdrawals, withdrawal_index, processed_count))
}

/// `get_expected_withdrawals` (modified, EIP-7732): builder withdrawals, then
/// pending partial withdrawals, then the builders sweep, then the validators
/// sweep, each sweep's own `prior_withdrawals` accumulating every withdrawal
/// an earlier sweep in this same call already produced, so none double-pays a
/// balance an earlier sweep already claimed.
///
/// The last two sweeps are unmodified since electra (`beacon-chain.md` does
/// not redefine `get_pending_partial_withdrawals` or
/// `get_validators_sweep_withdrawals` for gloas), so they are shared calls
/// into [`crate::beacon::stf::electra`] rather than copies: the former
/// through [`crate::beacon::helpers::electra::PendingQueueFieldsRef`], which
/// abstracts over `pending_partial_withdrawals`'s type change (EIP-7688); the
/// latter touches no gloas-changed list at all, so it needs no widening
/// beyond [`BeaconState`]'s own fork-invariant accessors.
pub fn get_expected_withdrawals(state: &BeaconState) -> Result<ExpectedWithdrawals> {
    let (mut withdrawal_index, _) = state.withdrawal_cursor()?;
    let mut withdrawals: Vec<capella::Withdrawal> = Vec::new();

    let (builder_withdrawals, next_index, processed_builder_withdrawals_count) =
        get_builder_withdrawals(state, withdrawal_index, &withdrawals)?;
    withdrawal_index = next_index;
    withdrawals.extend(builder_withdrawals);

    let (partial_withdrawals, next_index, processed_partial_withdrawals_count) =
        crate::beacon::stf::electra::get_pending_partial_withdrawals(
            state,
            withdrawal_index,
            &withdrawals,
        )?;
    withdrawal_index = next_index;
    withdrawals.extend(partial_withdrawals);

    let (builders_sweep_withdrawals, next_index, processed_builders_sweep_count) =
        get_builders_sweep_withdrawals(state, withdrawal_index, &withdrawals)?;
    withdrawal_index = next_index;
    withdrawals.extend(builders_sweep_withdrawals);

    let (validators_sweep_withdrawals, _, processed_sweep_withdrawals_count) =
        crate::beacon::stf::electra::get_validators_sweep_withdrawals(
            state,
            withdrawal_index,
            &withdrawals,
        )?;
    withdrawals.extend(validators_sweep_withdrawals);

    Ok(ExpectedWithdrawals {
        withdrawals,
        processed_builder_withdrawals_count,
        processed_partial_withdrawals_count,
        processed_builders_sweep_count,
        processed_sweep_withdrawals_count,
    })
}

/// `apply_withdrawals` (modified, EIP-7732): a builder-indexed withdrawal
/// (`is_builder_index`) saturates the builder's own balance down rather than
/// going through [`decrease_balance`], the same "cannot go negative, no error
/// either" contract `saturating_sub` already gives ordinary validator
/// balances through that function.
pub fn apply_withdrawals(
    state: &mut BeaconState,
    withdrawals: &[capella::Withdrawal],
) -> Result<()> {
    for withdrawal in withdrawals {
        if is_builder_index(withdrawal.validator_index) {
            let builder_index =
                convert_validator_index_to_builder_index(withdrawal.validator_index);
            let inner = gloas_state(state, "apply_withdrawals")?;
            let len = inner.builders.len();
            let builder =
                inner
                    .builders
                    .get_mut(builder_index as usize)
                    .ok_or(Error::IndexOutOfBounds {
                        index: builder_index as usize,
                        len,
                    })?;
            builder.balance = builder.balance.saturating_sub(withdrawal.amount);
        } else {
            decrease_balance(state, withdrawal.validator_index, withdrawal.amount)?;
        }
    }
    Ok(())
}

/// `update_payload_expected_withdrawals` (gloas `beacon-chain.md`): caches
/// this block's withdrawal sweep on the state itself, since there is no
/// payload for a block to carry it in for the execution layer to read back.
pub fn update_payload_expected_withdrawals(
    state: &mut BeaconState,
    withdrawals: &[capella::Withdrawal],
) -> Result<()> {
    gloas_state(state, "update_payload_expected_withdrawals")?.payload_expected_withdrawals =
        gloas::Withdrawals::from(withdrawals.to_vec());
    Ok(())
}

/// `update_builder_pending_withdrawals` (gloas `beacon-chain.md`): drops
/// however many entries [`get_builder_withdrawals`] actually consumed off the
/// front of the queue.
///
/// No block queues a builder withdrawal at all most of the time, so the
/// common case returns before touching the queue; when there is work,
/// `mem::take` + `split_off` move the surviving entries into their
/// replacement rather than cloning the whole queue to build it, the same way
/// `crate::beacon::stf::electra::process_withdrawals` drops its own
/// `pending_partial_withdrawals` entries.
pub fn update_builder_pending_withdrawals(
    state: &mut BeaconState,
    processed_builder_withdrawals_count: u64,
) -> Result<()> {
    if processed_builder_withdrawals_count == 0 {
        return Ok(());
    }
    let inner = gloas_state(state, "update_builder_pending_withdrawals")?;
    let mut owned = core::mem::take(&mut inner.builder_pending_withdrawals).into_inner();
    let remaining = owned.split_off(processed_builder_withdrawals_count as usize);
    inner.builder_pending_withdrawals = gloas::BuilderPendingWithdrawals::from(remaining);
    Ok(())
}

/// `update_pending_partial_withdrawals` (unmodified since electra, whose
/// `process_withdrawals` drains the same queue inline). See
/// [`update_builder_pending_withdrawals`]'s own doc for why the common,
/// nothing-consumed case returns early and why the rest moves entries
/// instead of cloning them.
pub fn update_pending_partial_withdrawals(
    state: &mut BeaconState,
    processed_partial_withdrawals_count: u64,
) -> Result<()> {
    if processed_partial_withdrawals_count == 0 {
        return Ok(());
    }
    let inner = gloas_state(state, "update_pending_partial_withdrawals")?;
    let mut owned = core::mem::take(&mut inner.pending_partial_withdrawals).into_inner();
    let remaining = owned.split_off(processed_partial_withdrawals_count as usize);
    inner.pending_partial_withdrawals = gloas::PendingPartialWithdrawals::from(remaining);
    Ok(())
}

/// `update_next_withdrawal_builder_index` (gloas `beacon-chain.md`): the
/// builder-side counterpart of [`update_next_withdrawal_validator_index`],
/// advanced by however many builders [`get_builders_sweep_withdrawals`]
/// actually visited rather than by a fixed bound, since that sweep's own
/// bound is already `min(len(state.builders), MAX_BUILDERS_PER_WITHDRAWALS_SWEEP)`.
/// Left untouched on an empty builder registry, which has no valid index to
/// wrap into.
pub fn update_next_withdrawal_builder_index(
    state: &mut BeaconState,
    processed_builders_sweep_count: u64,
) -> Result<()> {
    let inner = gloas_state(state, "update_next_withdrawal_builder_index")?;
    let builders_len = inner.builders.len() as u64;
    if builders_len > 0 {
        let next_index = inner
            .next_withdrawal_builder_index
            .checked_add(processed_builders_sweep_count)
            .ok_or(Error::ArithmeticOverflow(
                "update_next_withdrawal_builder_index: next_withdrawal_builder_index + processed_builders_sweep_count",
            ))?;
        inner.next_withdrawal_builder_index = next_index % builders_len;
    }
    Ok(())
}

/// `update_next_withdrawal_index` (unchanged since capella; ported here
/// because gloas's own `process_withdrawals` still calls it by name).
fn update_next_withdrawal_index(
    state: &mut BeaconState,
    withdrawals: &[capella::Withdrawal],
) -> Result<()> {
    if let Some(latest) = withdrawals.last() {
        let (withdrawal_index, _) = state.withdrawal_cursor_mut()?;
        *withdrawal_index = latest
            .index
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow(
                "update_next_withdrawal_index: latest_withdrawal.index + 1",
            ))?;
    }
    Ok(())
}

/// `update_next_withdrawal_validator_index` (unchanged since capella; ported
/// here for the same reason as [`update_next_withdrawal_index`]).
fn update_next_withdrawal_validator_index(
    state: &mut BeaconState,
    withdrawals: &[capella::Withdrawal],
) -> Result<()> {
    let validator_count = state.validator_count() as u64;
    verify(
        validator_count > 0,
        "update_next_withdrawal_validator_index: len(state.validators) > 0",
    )?;
    let next_validator_index = if withdrawals.len() == preset::MAX_WITHDRAWALS_PER_PAYLOAD {
        let latest = withdrawals
            .last()
            .expect("MAX_WITHDRAWALS_PER_PAYLOAD is never zero, so a full payload is non-empty");
        latest
            .validator_index
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow(
                "update_next_withdrawal_validator_index: latest_withdrawal.validator_index + 1",
            ))?
            % validator_count
    } else {
        let (_, current_cursor) = state.withdrawal_cursor()?;
        current_cursor
            .checked_add(preset::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP)
            .ok_or(Error::ArithmeticOverflow(
                "update_next_withdrawal_validator_index: next_withdrawal_validator_index + MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP",
            ))?
            % validator_count
    };
    let (_, validator_index) = state.withdrawal_cursor_mut()?;
    *validator_index = next_validator_index;
    Ok(())
}

/// `process_withdrawals` (modified, EIP-7732): takes only `state`. Returns
/// early, doing nothing at all, when the parent block was empty (its bid's
/// `block_hash` never landed in `state.latest_block_hash`): withdrawals are
/// deterministic from the state alone, and an empty parent leaves nothing new
/// to sweep beyond what the last block that actually revealed a payload
/// already swept. `payload_expected_withdrawals` is left exactly as that
/// last sweep set it rather than cleared: no execution payload has paid it
/// out yet either (there was none to reveal it), so the field still
/// correctly names what the *next* revealed payload owes.
pub fn process_withdrawals(state: &mut BeaconState) -> Result<()> {
    let inner = gloas_state_ref(state, "process_withdrawals")?;
    if inner.latest_block_hash != inner.latest_execution_payload_bid.block_hash {
        return Ok(());
    }

    let expected = get_expected_withdrawals(state)?;
    apply_withdrawals(state, &expected.withdrawals)?;

    update_next_withdrawal_index(state, &expected.withdrawals)?;
    update_payload_expected_withdrawals(state, &expected.withdrawals)?;
    update_builder_pending_withdrawals(state, expected.processed_builder_withdrawals_count)?;
    update_pending_partial_withdrawals(state, expected.processed_partial_withdrawals_count)?;
    update_next_withdrawal_builder_index(state, expected.processed_builders_sweep_count)?;
    update_next_withdrawal_validator_index(state, &expected.withdrawals)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Execution payload
// ---------------------------------------------------------------------------

/// `get_execution_requests_list` (modified, EIP-8282): electra's three
/// request-type prefixes, plus [`gloas::ExecutionRequests::builder_deposits`]
/// and [`gloas::ExecutionRequests::builder_exits`] under their own new
/// prefixes.
///
/// The specification files this under "Execution payload", not "Operations":
/// it is read by `execution_engine.verify_and_notify_new_payload`'s own
/// `NewPayloadRequest.execution_requests`, in [`verify_execution_payload_envelope`],
/// built from the revealed envelope's own `execution_requests`. Not from
/// `state.latest_execution_payload_bid`: the bid commits to that list only
/// by its hash ([`gloas::ExecutionPayloadBid::execution_requests_root`]), it
/// never carries the list itself. Nothing calls this even now that envelope
/// verification is transcribed, the same place electra's own
/// [`crate::beacon::stf::electra::get_execution_requests_list`] already is
/// (see [`crate::beacon::stf::deneb::process_execution_payload`]'s own
/// documentation for why: [`ExecutionEngine`] collapses the whole
/// `verify_and_notify_new_payload` interface to one boolean and never
/// inspects the list either implementation builds).
pub fn get_execution_requests_list(requests: &gloas::ExecutionRequests) -> Vec<Vec<u8>> {
    let mut list = Vec::new();

    let mut push = |request_type: u8, is_empty: bool, encoded: Vec<u8>| {
        if is_empty {
            return;
        }
        let mut element = Vec::with_capacity(1 + encoded.len());
        element.push(request_type);
        element.extend_from_slice(&encoded);
        list.push(element);
    };

    push(
        constants::DEPOSIT_REQUEST_TYPE,
        requests.deposits.is_empty(),
        requests.deposits.to_ssz(),
    );
    push(
        constants::WITHDRAWAL_REQUEST_TYPE,
        requests.withdrawals.is_empty(),
        requests.withdrawals.to_ssz(),
    );
    push(
        constants::CONSOLIDATION_REQUEST_TYPE,
        requests.consolidations.is_empty(),
        requests.consolidations.to_ssz(),
    );
    push(
        constants::BUILDER_DEPOSIT_REQUEST_TYPE,
        requests.builder_deposits.is_empty(),
        requests.builder_deposits.to_ssz(),
    );
    push(
        constants::BUILDER_EXIT_REQUEST_TYPE,
        requests.builder_exits.is_empty(),
        requests.builder_exits.to_ssz(),
    );

    list
}

/// `verify_execution_payload_envelope_signature` (gloas `beacon-chain.md`).
///
/// `Result<bool>` rather than a bare `bool`, the same deviation
/// [`verify_execution_payload_bid_signature`]'s own doc explains: a
/// self-build reads a real validator index
/// (`state.latest_block_header.proposer_index`) into `state.validators`,
/// and a non-self-build one reads `builder_index` into `state.builders`;
/// either can be out of range for a caller that has not already checked it,
/// which this reports rather than folding into "signature invalid".
pub fn verify_execution_payload_envelope_signature(
    state: &BeaconState,
    signed_envelope: &gloas::SignedExecutionPayloadEnvelope,
) -> Result<bool> {
    let builder_index = signed_envelope.message.builder_index;
    let pubkey = if builder_index == constants::BUILDER_INDEX_SELF_BUILD {
        let validator_index = state.latest_block_header().proposer_index;
        state.validator(validator_index)?.pubkey
    } else {
        let inner = gloas_state_ref(state, "verify_execution_payload_envelope_signature")?;
        inner
            .builders
            .get(builder_index as usize)
            .ok_or(Error::IndexOutOfBounds {
                index: builder_index as usize,
                len: inner.builders.len(),
            })?
            .pubkey
    };

    let domain = get_domain(state, constants::DOMAIN_BEACON_BUILDER, None);
    let signing_root = compute_signing_root(signed_envelope.message.hash_tree_root(), domain);
    Ok(bls::verify(
        &pubkey,
        signing_root,
        &signed_envelope.signature,
    ))
}

/// `verify_execution_payload_envelope` (gloas `fork-choice.md`).
///
/// A pure verification helper: it mutates nothing, matching the
/// specification's own note that `process_execution_payload` has been
/// replaced by this function plus the deferred [`apply_parent_execution_payload`]
/// (see this module's own doc). Called once a builder's envelope for the
/// slot's committed bid has been received, in addition to the checks
/// [`process_execution_payload_bid`] already made against the bid itself:
/// this checks the *envelope* is the one thing that bid actually promised.
///
/// The engine check has the same collapsed shape
/// [`crate::beacon::stf::fulu::process_execution_payload`]'s own: see
/// [`ExecutionEngine`]'s own doc for why the versioned hashes below are
/// computed but never themselves checked against anything beyond the
/// engine's own opaque verdict.
pub fn verify_execution_payload_envelope(
    state: &BeaconState,
    signed_envelope: &gloas::SignedExecutionPayloadEnvelope,
    config: &Config,
    engine: &ExecutionEngine,
) -> Result<()> {
    let envelope = &signed_envelope.message;
    let payload = &envelope.payload;

    // Verify signature.
    verify(
        verify_execution_payload_envelope_signature(state, signed_envelope)?,
        "verify_execution_payload_envelope: verify_execution_payload_envelope_signature(state, signed_envelope)",
    )?;

    // Verify consistency with the beacon block.
    //
    // `BeaconState::compute_state_root`, not a bare `hash_tree_root`. The
    // specification's own `header.state_root = hash_tree_root(state)` is
    // exactly right for a state fresh out of block processing, whose own
    // `latest_block_header.state_root` is still left zero (see
    // `super::process_slot`'s own doc for why). But this function's
    // real caller, `on_execution_payload_envelope`, hands in a *stored*
    // state, and this repository caches the real root into that same field
    // right after `state_transition` returns (`fork_choice::on_block`, the
    // checkpoint anchor), not one slot later the way a raw spec state would.
    // Hashing such a state unconditionally would hash a header whose own
    // `state_root` is already set, a different value from the one the
    // header actually committed to when it was still zero, so every stored
    // state's envelope would be rejected. `compute_state_root` returns the
    // cached value directly once it is set and only falls back to a fresh
    // hash while it is still zero, so both shapes resolve to the same root.
    let mut header = state.latest_block_header().clone();
    header.state_root = state.compute_state_root();
    verify(
        envelope.beacon_block_root == header.hash_tree_root(),
        "verify_execution_payload_envelope: envelope.beacon_block_root == hash_tree_root(header)",
    )?;
    verify(
        envelope.parent_beacon_block_root == state.latest_block_header().parent_root,
        "verify_execution_payload_envelope: envelope.parent_beacon_block_root == state.latest_block_header.parent_root",
    )?;

    // Verify consistency with the committed bid.
    let inner = gloas_state_ref(state, "verify_execution_payload_envelope")?;
    let bid = &inner.latest_execution_payload_bid;
    verify(
        envelope.builder_index == bid.builder_index,
        "verify_execution_payload_envelope: envelope.builder_index == bid.builder_index",
    )?;
    verify(
        payload.prev_randao == bid.prev_randao,
        "verify_execution_payload_envelope: payload.prev_randao == bid.prev_randao",
    )?;
    verify(
        payload.gas_limit == bid.gas_limit,
        "verify_execution_payload_envelope: payload.gas_limit == bid.gas_limit",
    )?;
    verify(
        payload.block_hash == bid.block_hash,
        "verify_execution_payload_envelope: payload.block_hash == bid.block_hash",
    )?;
    verify(
        envelope.execution_requests.hash_tree_root() == bid.execution_requests_root,
        "verify_execution_payload_envelope: hash_tree_root(envelope.execution_requests) == bid.execution_requests_root",
    )?;

    // Verify the execution payload is valid.
    verify(
        payload.slot_number == state.slot(),
        "verify_execution_payload_envelope: payload.slot_number == state.slot",
    )?;
    verify(
        payload.parent_hash == inner.latest_block_hash,
        "verify_execution_payload_envelope: payload.parent_hash == state.latest_block_hash",
    )?;
    verify(
        payload.timestamp
            == super::bellatrix::compute_timestamp_at_slot(state, state.slot(), config),
        "verify_execution_payload_envelope: payload.timestamp == compute_time_at_slot(state, state.slot)",
    )?;
    verify(
        payload.withdrawals.hash_tree_root() == inner.payload_expected_withdrawals.hash_tree_root(),
        "verify_execution_payload_envelope: hash_tree_root(payload.withdrawals) == hash_tree_root(state.payload_expected_withdrawals)",
    )?;

    // Compute versioned hashes.
    let _versioned_hashes: Vec<Bytes32> = bid
        .blob_kzg_commitments
        .iter()
        .map(super::deneb::kzg_commitment_to_versioned_hash)
        .collect();

    verify(
        engine.execution_valid,
        "verify_execution_payload_envelope: execution_engine.verify_and_notify_new_payload(\
         NewPayloadRequest(execution_payload=payload, versioned_hashes=versioned_hashes, \
         parent_beacon_block_root=envelope.parent_beacon_block_root, \
         execution_requests=envelope.execution_requests))",
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Execution payload bid
// ---------------------------------------------------------------------------

/// `verify_execution_payload_bid_signature` (gloas `beacon-chain.md`).
///
/// `Result` rather than a bare `bool`, unlike the specification's own
/// signature: [`process_execution_payload_bid`] only ever calls this after
/// `is_active_builder` has already proven `builder_index` is in range, but an
/// out-of-bounds index is still a real possibility for a caller that does
/// not, so this reports it rather than silently treating it as "signature
/// invalid".
pub fn verify_execution_payload_bid_signature(
    state: &BeaconState,
    signed_bid: &gloas::SignedExecutionPayloadBid,
) -> Result<bool> {
    let builder_index = signed_bid.message.builder_index;
    let inner = gloas_state_ref(state, "verify_execution_payload_bid_signature")?;
    let builder = inner
        .builders
        .get(builder_index as usize)
        .ok_or(Error::IndexOutOfBounds {
            index: builder_index as usize,
            len: inner.builders.len(),
        })?;
    let domain = get_domain(state, constants::DOMAIN_BEACON_BUILDER, None);
    let signing_root = compute_signing_root(signed_bid.message.hash_tree_root(), domain);
    Ok(bls::verify(
        &builder.pubkey,
        signing_root,
        &signed_bid.signature,
    ))
}

/// `process_execution_payload_bid` (gloas `beacon-chain.md`).
pub fn process_execution_payload_bid(
    state: &mut BeaconState,
    signed_bid: &gloas::SignedExecutionPayloadBid,
    config: &Config,
) -> Result<()> {
    let bid = signed_bid.message.clone();
    let builder_index = bid.builder_index;
    let amount = bid.value;

    if builder_index == constants::BUILDER_INDEX_SELF_BUILD {
        // For self-builds, amount must be zero regardless of withdrawal
        // credential prefix.
        verify(amount == 0, "process_execution_payload_bid: amount == 0")?;
        verify(
            signed_bid.signature == g2_point_at_infinity(),
            "process_execution_payload_bid: signature == G2_POINT_AT_INFINITY",
        )?;
    } else {
        // Verify that the builder is active.
        verify(
            is_active_builder(
                gloas_state_ref(state, "process_execution_payload_bid")?,
                builder_index,
            )?,
            "process_execution_payload_bid: is_active_builder(state, builder_index)",
        )?;
        // Verify that the builder is a payload builder.
        let version = {
            let inner = gloas_state_ref(state, "process_execution_payload_bid")?;
            inner
                .builders
                .get(builder_index as usize)
                .ok_or(Error::IndexOutOfBounds {
                    index: builder_index as usize,
                    len: inner.builders.len(),
                })?
                .version
        };
        verify(
            version == constants::PAYLOAD_BUILDER_VERSION,
            "process_execution_payload_bid: state.builders[builder_index].version == PAYLOAD_BUILDER_VERSION",
        )?;
        // Verify that the builder has funds to cover the bid.
        verify(
            can_builder_cover_bid(
                gloas_state_ref(state, "process_execution_payload_bid")?,
                builder_index,
                amount,
            )?,
            "process_execution_payload_bid: can_builder_cover_bid(state, builder_index, amount)",
        )?;
        // Verify that the bid signature is valid.
        verify(
            verify_execution_payload_bid_signature(state, signed_bid)?,
            "process_execution_payload_bid: verify_execution_payload_bid_signature(state, signed_bid)",
        )?;
    }

    // Verify commitments are under limit.
    verify(
        bid.blob_kzg_commitments.len() as u64
            <= config.max_blobs_per_block(get_current_epoch(state)),
        "process_execution_payload_bid: len(bid.blob_kzg_commitments) <= get_blob_parameters(current_epoch).max_blobs_per_block",
    )?;

    // Verify that the bid is for the current slot.
    verify(
        bid.slot == state.slot(),
        "process_execution_payload_bid: bid.slot == state.slot",
    )?;
    verify(
        state.slot() > constants::GENESIS_SLOT,
        "process_execution_payload_bid: state.slot > GENESIS_SLOT",
    )?;
    // Verify that the bid is for the right parent block.
    verify(
        bid.parent_block_hash
            == gloas_state_ref(state, "process_execution_payload_bid")?.latest_block_hash,
        "process_execution_payload_bid: bid.parent_block_hash == state.latest_block_hash",
    )?;
    // Verify that the bid's block hash differs from its parent block hash.
    verify(
        bid.block_hash != bid.parent_block_hash,
        "process_execution_payload_bid: bid.block_hash != bid.parent_block_hash",
    )?;
    verify(
        bid.parent_block_root == get_block_root_at_slot(state, state.slot() - 1)?,
        "process_execution_payload_bid: bid.parent_block_root == get_block_root_at_slot(state, state.slot - 1)",
    )?;
    verify(
        bid.prev_randao == get_randao_mix(state, get_current_epoch(state)),
        "process_execution_payload_bid: bid.prev_randao == get_randao_mix(state, get_current_epoch(state))",
    )?;

    // Record the pending payment if there is some payment.
    if amount > 0 {
        let proposer_index = get_beacon_proposer_index(state)?;
        let pending_payment = gloas::BuilderPendingPayment {
            weight: 0,
            withdrawal: gloas::BuilderPendingWithdrawal {
                fee_recipient: bid.fee_recipient,
                amount,
                builder_index,
            },
            proposer_index,
        };
        let index = preset::SLOTS_PER_EPOCH
            .checked_add(bid.slot % preset::SLOTS_PER_EPOCH)
            .ok_or(Error::ArithmeticOverflow(
                "process_execution_payload_bid: SLOTS_PER_EPOCH + bid.slot % SLOTS_PER_EPOCH",
            ))? as usize;
        let inner = gloas_state(state, "process_execution_payload_bid")?;
        let len = inner.builder_pending_payments.len();
        if index >= len {
            return Err(Error::IndexOutOfBounds { index, len });
        }
        inner.builder_pending_payments[index] = pending_payment;
    }

    // Cache the signed execution payload bid.
    gloas_state(state, "process_execution_payload_bid")?.latest_execution_payload_bid = bid;

    Ok(())
}

// ---------------------------------------------------------------------------
// Parent execution payload
// ---------------------------------------------------------------------------

/// `apply_parent_execution_payload` (gloas `beacon-chain.md`).
///
/// Processes the parent's execution-layer-triggered requests, settles (or
/// directly queues) its builder payment, and marks its payload available.
/// Called by [`process_parent_execution_payload`] during block processing,
/// and (per the specification's own note) by the validator during block
/// production before computing withdrawals.
pub fn apply_parent_execution_payload(
    state: &mut BeaconState,
    requests: &gloas::ExecutionRequests,
    config: &Config,
) -> Result<()> {
    let (parent_bid, parent_slot, parent_epoch) = {
        let inner = gloas_state_ref(state, "apply_parent_execution_payload")?;
        let parent_slot = inner.latest_block_header.slot;
        (
            inner.latest_execution_payload_bid.clone(),
            parent_slot,
            compute_epoch_at_slot(parent_slot),
        )
    };

    verify(
        requests.withdrawals.len() <= preset::MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        "apply_parent_execution_payload: len(requests.withdrawals) <= MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD",
    )?;
    verify(
        requests.consolidations.len() <= preset::MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
        "apply_parent_execution_payload: len(requests.consolidations) <= MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD",
    )?;
    verify(
        requests.builder_deposits.len() as u64 <= preset::MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD,
        "apply_parent_execution_payload: len(requests.builder_deposits) <= MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD",
    )?;
    verify(
        requests.builder_exits.len() as u64 <= preset::MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD,
        "apply_parent_execution_payload: len(requests.builder_exits) <= MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD",
    )?;

    // Process execution requests from the parent's payload. The execution
    // requests are processed at state.slot (child's slot), not the parent's
    // slot.
    //
    // Deposits, withdrawals, and consolidations are unmodified since electra
    // (fulu, for deposits): see this module's own doc for why these three
    // are shared calls into `stf::fulu`/`stf::electra` rather than copies.
    for deposit in requests.deposits.iter() {
        crate::beacon::stf::fulu::process_deposit_request(state, deposit)?;
    }
    for withdrawal in requests.withdrawals.iter() {
        crate::beacon::stf::electra::process_withdrawal_request(state, withdrawal, config)?;
    }
    for consolidation in requests.consolidations.iter() {
        crate::beacon::stf::electra::process_consolidation_request(state, consolidation, config)?;
    }
    for builder_deposit in requests.builder_deposits.iter() {
        process_builder_deposit_request(state, builder_deposit, config)?;
    }
    for builder_exit in requests.builder_exits.iter() {
        process_builder_exit_request(state, builder_exit, config)?;
    }

    // Settle the builder payment.
    let current_epoch = get_current_epoch(state);
    if parent_epoch == current_epoch {
        let payment_index = preset::SLOTS_PER_EPOCH
            .checked_add(parent_slot % preset::SLOTS_PER_EPOCH)
            .ok_or(Error::ArithmeticOverflow(
                "apply_parent_execution_payload: SLOTS_PER_EPOCH + parent_slot % SLOTS_PER_EPOCH",
            ))?;
        settle_builder_payment(
            gloas_state(state, "apply_parent_execution_payload")?,
            payment_index,
        )?;
    } else if parent_epoch == get_previous_epoch(state) {
        let payment_index = parent_slot % preset::SLOTS_PER_EPOCH;
        settle_builder_payment(
            gloas_state(state, "apply_parent_execution_payload")?,
            payment_index,
        )?;
    } else if parent_bid.value > 0 {
        // Parent is older than the previous epoch, its payment entry has
        // been evicted from builder_pending_payments. Append the withdrawal
        // directly.
        gloas_state(state, "apply_parent_execution_payload")?
            .builder_pending_withdrawals
            .push(gloas::BuilderPendingWithdrawal {
                fee_recipient: parent_bid.fee_recipient,
                amount: parent_bid.value,
                builder_index: parent_bid.builder_index,
            });
    }

    // Update parent payload availability and latest block hash.
    let slot_index = (parent_slot as usize) % preset::SLOTS_PER_HISTORICAL_ROOT;
    let inner = gloas_state(state, "apply_parent_execution_payload")?;
    inner
        .execution_payload_availability
        .set(slot_index, true)
        .map_err(|err| Error::IndexOutOfBounds {
            index: err.index,
            len: err.len,
        })?;
    inner.latest_block_hash = parent_bid.block_hash;

    Ok(())
}

/// `process_parent_execution_payload` (gloas `beacon-chain.md`).
///
/// *Note (from the specification):* must be called before
/// [`process_execution_payload_bid`] (which overwrites
/// `state.latest_execution_payload_bid`).
pub fn process_parent_execution_payload(
    state: &mut BeaconState,
    block: &gloas::BeaconBlock,
    config: &Config,
) -> Result<()> {
    let bid = &block.body.signed_execution_payload_bid.message;
    let parent_bid = gloas_state_ref(state, "process_parent_execution_payload")?
        .latest_execution_payload_bid
        .clone();
    let requests = &block.body.parent_execution_requests;

    if bid.parent_block_hash != parent_bid.block_hash {
        // Parent was EMPTY: no execution requests expected.
        verify(
            *requests == gloas::ExecutionRequests::default(),
            "process_parent_execution_payload: requests == ExecutionRequests.empty()",
        )?;
        return Ok(());
    }

    // Parent was FULL: verify the bid commitment and apply the payload.
    verify(
        requests.hash_tree_root() == parent_bid.execution_requests_root,
        "process_parent_execution_payload: hash_tree_root(requests) == parent_bid.execution_requests_root",
    )?;
    apply_parent_execution_payload(state, requests, config)
}

// ---------------------------------------------------------------------------
// Builder deposit and exit requests (EIP-8282)
// ---------------------------------------------------------------------------

/// `is_valid_builder_deposit_signature` (gloas `beacon-chain.md`).
///
/// Signed under its own domain, `DOMAIN_BUILDER_DEPOSIT`, rather than
/// ordinary validator deposits' `DOMAIN_DEPOSIT`: the specification's own
/// note is that the dedicated domain is what keeps a validator deposit
/// signature and a builder deposit signature from being replayed against the
/// other deposit contract, since the two now sign over identical
/// `DepositMessage` bytes otherwise.
///
/// Like [`crate::beacon::stf::electra::is_valid_deposit_signature`], it is
/// signed under `GENESIS_FORK_VERSION` and an all-zero genesis validators
/// root rather than [`get_domain`]'s state-dependent ones. The
/// specification's own `compute_domain(DOMAIN_BUILDER_DEPOSIT)`, passing
/// neither argument, defaults to exactly that; `config` is this file's way
/// of reaching `GENESIS_FORK_VERSION`, the same deviation
/// `is_valid_deposit_signature` already makes from the specification's
/// global-constant signature.
pub fn is_valid_builder_deposit_signature(
    request: &gloas::BuilderDepositRequest,
    config: &Config,
) -> bool {
    let deposit_message = DepositMessage {
        pubkey: request.pubkey,
        withdrawal_credentials: request.withdrawal_credentials,
        amount: request.amount,
    };
    let domain = compute_domain(
        constants::DOMAIN_BUILDER_DEPOSIT,
        config.genesis_fork_version,
        Root::ZERO,
    );
    let signing_root = compute_signing_root(deposit_message.hash_tree_root(), domain);
    bls::verify(&request.pubkey, signing_root, &request.signature)
}

/// `process_builder_deposit_request` (gloas `beacon-chain.md`).
///
/// *Note (from the specification):* builder indices are reusable. When a
/// builder exits, its index may later be reassigned to a different builder
/// with a new public key.
pub fn process_builder_deposit_request(
    state: &mut BeaconState,
    request: &gloas::BuilderDepositRequest,
    config: &Config,
) -> Result<()> {
    // Ignore deposits with unexpected withdrawal credential prefixes.
    if !is_builder_withdrawal_credential(request.withdrawal_credentials) {
        return Ok(());
    }

    let inner = gloas_state(state, "process_builder_deposit_request")?;
    let existing = inner
        .builders
        .iter()
        .position(|builder| builder.pubkey == request.pubkey);

    match existing {
        None => {
            if is_valid_builder_deposit_signature(request, config) {
                let slot = inner.slot;
                add_builder_to_registry(
                    inner,
                    request.pubkey,
                    constants::PAYLOAD_BUILDER_VERSION,
                    ExecutionAddress::from_slice(&request.withdrawal_credentials.0[12..]),
                    request.amount,
                    slot,
                );
            }
        }
        Some(builder_index) => {
            let epoch = compute_epoch_at_slot(inner.slot);
            let builder = &mut inner.builders[builder_index];

            // If exited and swept, reset the withdrawable epoch.
            if builder.withdrawable_epoch != constants::FAR_FUTURE_EPOCH && builder.balance == 0 {
                builder.withdrawable_epoch =
                    epoch
                        .checked_add(config.min_builder_withdrawability_delay)
                        .ok_or(Error::ArithmeticOverflow(
                            "process_builder_deposit_request: epoch + MIN_BUILDER_WITHDRAWABILITY_DELAY",
                        ))?;
            }

            // Increase balance by deposit amount.
            builder.balance =
                builder
                    .balance
                    .checked_add(request.amount)
                    .ok_or(Error::ArithmeticOverflow(
                        "process_builder_deposit_request: builder.balance + request.amount",
                    ))?;
        }
    }
    Ok(())
}

/// `process_builder_exit_request` (gloas `beacon-chain.md`).
pub fn process_builder_exit_request(
    state: &mut BeaconState,
    request: &gloas::BuilderExitRequest,
    config: &Config,
) -> Result<()> {
    let inner = gloas_state(state, "process_builder_exit_request")?;
    let Some(builder_index) = inner
        .builders
        .iter()
        .position(|builder| builder.pubkey == request.pubkey)
    else {
        return Ok(());
    };
    let builder_index = builder_index as gloas::BuilderIndex;

    if !is_active_builder(inner, builder_index)? {
        return Ok(());
    }
    if inner.builders[builder_index as usize].execution_address != request.source_address {
        return Ok(());
    }
    if crate::beacon::helpers::gloas::get_pending_balance_to_withdraw_for_builder(
        inner,
        builder_index,
    )? != 0
    {
        return Ok(());
    }

    initiate_builder_exit(inner, builder_index, config)
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// `process_proposer_slashing` (modified, EIP-7732): the shared
/// `crate::beacon::stf::operations::verify_proposer_slashing` prologue, plus
/// clearing the [`gloas::BeaconState::builder_pending_payments`] entry tied
/// to the slashed proposal, if the slashing lands the slashed validator
/// itself as the payment's own proposer and the payment is still inside the
/// live two-epoch window. An unrelated same-slot equivocation (a different
/// validator's evidence about the same proposal) must not grief an honest
/// proposer's payment, which is exactly what comparing `payment.proposer_index`
/// against the slashed proposer's own index, rather than clearing
/// unconditionally, prevents.
pub fn process_proposer_slashing(
    state: &mut BeaconState,
    proposer_slashing: &ProposerSlashing,
    config: &Config,
) -> Result<()> {
    let (proposer_index, current_epoch) =
        crate::beacon::stf::operations::verify_proposer_slashing(state, proposer_slashing)?;

    // [New in Gloas:EIP7732] Remove the `BuilderPendingPayment` corresponding
    // to this proposal if it is still in the 2-epoch window.
    let slot = proposer_slashing.signed_header_1.message.slot;
    let proposal_epoch = compute_epoch_at_slot(slot);
    if proposal_epoch == current_epoch {
        let payment_index = preset::SLOTS_PER_EPOCH
            .checked_add(slot % preset::SLOTS_PER_EPOCH)
            .ok_or(Error::ArithmeticOverflow(
                "process_proposer_slashing: SLOTS_PER_EPOCH + slot % SLOTS_PER_EPOCH",
            ))? as usize;
        clear_builder_pending_payment_if_owned_by(state, payment_index, proposer_index)?;
    } else if proposal_epoch == get_previous_epoch(state) {
        let payment_index = (slot % preset::SLOTS_PER_EPOCH) as usize;
        clear_builder_pending_payment_if_owned_by(state, payment_index, proposer_index)?;
    }

    slash_validator(state, proposer_index, None, config)?;
    Ok(())
}

/// Clears `state.builder_pending_payments[payment_index]` if it is recorded
/// against `proposer_index`, [`process_proposer_slashing`]'s own helper for
/// its two (current-epoch, previous-epoch) payment-window branches.
fn clear_builder_pending_payment_if_owned_by(
    state: &mut BeaconState,
    payment_index: usize,
    proposer_index: ValidatorIndex,
) -> Result<()> {
    let inner = gloas_state(state, "process_proposer_slashing")?;
    let len = inner.builder_pending_payments.len();
    let payment = inner
        .builder_pending_payments
        .get_mut(payment_index)
        .ok_or(Error::IndexOutOfBounds {
            index: payment_index,
            len,
        })?;
    if payment.proposer_index == proposer_index {
        *payment = gloas::BuilderPendingPayment::default();
    }
    Ok(())
}

/// `process_attester_slashing` (unmodified since electra). Transcribed here,
/// not called through [`crate::beacon::stf::electra::process_attester_slashing`],
/// only because [`gloas::AttesterSlashing`] is its own Rust type: EIP-7688
/// makes [`gloas::IndexedAttestation::attesting_indices`] the unbounded
/// [`gloas::AttestingIndices`] rather than electra's bounded one, the same
/// reason [`crate::beacon::helpers::gloas::get_attesting_indices`] cannot reuse
/// electra's copy either. See that function's own doc. The prologue below is
/// the one part that genuinely cannot be shared (it is checked against
/// gloas's own [`gloas::IndexedAttestation`]); once both attestations check
/// out, the rest is
/// `crate::beacon::stf::operations::slash_attesting_index_intersection`, the same
/// shared walk phase0's and electra's own versions delegate to.
pub fn process_attester_slashing(
    state: &mut BeaconState,
    attester_slashing: &gloas::AttesterSlashing,
    config: &Config,
) -> Result<()> {
    let attestation_1 = &attester_slashing.attestation_1;
    let attestation_2 = &attester_slashing.attestation_2;

    verify(
        is_slashable_attestation_data(&attestation_1.data, &attestation_2.data),
        "process_attester_slashing: is_slashable_attestation_data(attestation_1.data, attestation_2.data)",
    )?;
    verify(
        is_valid_indexed_attestation(state, attestation_1),
        "process_attester_slashing: is_valid_indexed_attestation(state, attestation_1)",
    )?;
    verify(
        is_valid_indexed_attestation(state, attestation_2),
        "process_attester_slashing: is_valid_indexed_attestation(state, attestation_2)",
    )?;

    crate::beacon::stf::operations::slash_attesting_index_intersection(
        state,
        &attestation_1.attesting_indices,
        &attestation_2.attesting_indices,
        config,
    )
}

/// `process_attestation` (modified, EIP-7732): the new `parent_slot`
/// parameter (the parent block's slot) is threaded straight into
/// [`get_attestation_participation_flag_indices`], which is what lets an
/// attester's payload vote (`data.index`, now 0 or 1 rather than always 0)
/// be checked against the payload the attested block actually revealed. The
/// other addition is builder-payment weight accounting: each attester whose
/// participation for that epoch was still empty (`had_no_participation`, the
/// specification's own name for it) who newly satisfies a flag via a
/// same-slot attestation, while a nonzero builder payment for that slot is
/// still pending, adds their effective balance to that payment's `weight`,
/// which is what
/// `crate::beacon::stf::epoch::gloas::process_builder_pending_payments` later
/// checks against [`crate::beacon::helpers::gloas::get_builder_payment_quorum_threshold`]
/// to decide whether the builder gets paid in full or not at all.
///
/// Structured as the same read-then-write split
/// [`crate::beacon::stf::altair::process_attestation`] uses, and for the identical
/// borrow-checker reason: the read phase borrows `state` immutably (through
/// [`BeaconState::altair_validator_lists`], which covers gloas), and the
/// write phase borrows it mutably (through
/// [`BeaconState::epoch_participation_mut`], gloas's own widened element-only
/// view of the same list; see that accessor's own doc for why it, and not
/// [`BeaconState::altair_validator_lists_mut`], is the one gloas can use).
pub fn process_attestation(
    state: &mut BeaconState,
    attestation: &gloas::Attestation,
    parent_slot: Slot,
    committees: &CommitteeCache,
) -> Result<()> {
    let data = attestation.data;
    let current_epoch = get_current_epoch(state);
    let previous_epoch = get_previous_epoch(state);

    verify(
        data.target.epoch == previous_epoch || data.target.epoch == current_epoch,
        "process_attestation: data.target.epoch in (get_previous_epoch(state), get_current_epoch(state))",
    )?;
    verify(
        data.target.epoch == compute_epoch_at_slot(data.slot),
        "process_attestation: data.target.epoch == compute_epoch_at_slot(data.slot)",
    )?;
    let min_slot = data
        .slot
        .checked_add(preset::MIN_ATTESTATION_INCLUSION_DELAY)
        .ok_or(Error::ArithmeticOverflow(
            "process_attestation: data.slot + MIN_ATTESTATION_INCLUSION_DELAY",
        ))?;
    verify(
        min_slot <= state.slot(),
        "process_attestation: data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= state.slot",
    )?;

    // [Modified in Gloas:EIP7732] `data.index` is now a payload-availability
    // bit (0 or 1), not always zero.
    verify(data.index < 2, "process_attestation: data.index < 2")?;
    let committee_indices = get_committee_indices(&attestation.committee_bits);
    let epoch_committees = committees.committees(state, data.target.epoch);
    let mut committee_offset = 0usize;
    for committee_index in committee_indices {
        verify(
            committee_index < epoch_committees.committees_per_slot(),
            "process_attestation: committee_index < get_committee_count_per_slot(state, data.target.epoch)",
        )?;
        let committee = epoch_committees.committee(data.slot, committee_index)?;
        let committee_has_an_attester = (0..committee.len()).any(|position| {
            attestation
                .aggregation_bits
                .get(committee_offset + position)
                .unwrap_or(false)
        });
        verify(
            committee_has_an_attester,
            "process_attestation: len(committee_attesters) > 0",
        )?;
        committee_offset += committee.len();
    }
    verify(
        attestation.aggregation_bits.len() == committee_offset,
        "process_attestation: len(attestation.aggregation_bits) == committee_offset",
    )?;

    // Safe: `min_slot <= state.slot()` above and `min_slot >= data.slot` (the
    // inclusion delay is non-negative), so `data.slot <= state.slot()`.
    let inclusion_delay = state.slot() - data.slot;
    let participation_flag_indices =
        get_attestation_participation_flag_indices(state, &data, inclusion_delay, parent_slot)?;

    let indexed_attestation = get_indexed_attestation(state, attestation, committees)?;
    verify(
        is_valid_indexed_attestation(state, &indexed_attestation),
        "process_attestation: is_valid_indexed_attestation(state, get_indexed_attestation(state, attestation))",
    )?;

    let current_epoch_target = data.target.epoch == current_epoch;
    let payment_index = if current_epoch_target {
        preset::SLOTS_PER_EPOCH
            .checked_add(data.slot % preset::SLOTS_PER_EPOCH)
            .ok_or(Error::ArithmeticOverflow(
                "process_attestation: SLOTS_PER_EPOCH + data.slot % SLOTS_PER_EPOCH",
            ))? as usize
    } else {
        (data.slot % preset::SLOTS_PER_EPOCH) as usize
    };
    let mut payment = {
        let inner = gloas_state_ref(state, "process_attestation")?;
        let len = inner.builder_pending_payments.len();
        inner
            .builder_pending_payments
            .get(payment_index)
            .cloned()
            .ok_or(Error::IndexOutOfBounds {
                index: payment_index,
                len,
            })?
    };

    let attesting_indices: Vec<ValidatorIndex> = indexed_attestation.attesting_indices.to_vec();
    // The specification calls `is_attestation_same_slot(state, data)` inside
    // the per-attester short-circuit below, so hoisting it out to a single
    // call here changes nothing: `get_attestation_participation_flag_indices`
    // above already called it once against this same, still-unmutated
    // `state`, so every attester's own check would read the identical
    // result regardless of where it is evaluated.
    let is_same_slot = is_attestation_same_slot(state, &data)?;
    // Hoisted for the same reason `crate::beacon::stf::electra::process_attestation`
    // hoists it: `get_base_reward(state, index)` is `increments *
    // get_base_reward_per_increment(state)`, and the second factor is
    // constant across this whole read phase (nothing here mutates `state`
    // yet), so computing it once outside the loop below avoids one
    // `get_total_active_balance` scan of the registry per attester per flag.
    let base_reward_per_increment = get_base_reward_per_increment(state)?;

    // Read phase: for every attester, decide which flags this attestation
    // newly satisfies, add up the proposer's reward for granting them, and
    // credit the pending builder payment's weight where the specification
    // says to. Nothing here mutates `state`.
    let mut proposer_reward_numerator: Gwei = 0;
    let mut flag_updates: Vec<(ValidatorIndex, ParticipationFlags)> = Vec::new();
    {
        let (previous_participation, current_participation, _) = state.altair_validator_lists()?;
        let epoch_participation = if current_epoch_target {
            current_participation
        } else {
            previous_participation
        };
        for index in attesting_indices {
            let current_flags = epoch_participation.get(index as usize).copied().ok_or(
                Error::IndexOutOfBounds {
                    index: index as usize,
                    len: epoch_participation.len(),
                },
            )?;
            let had_no_participation = current_flags == 0;

            let mut new_flags: ParticipationFlags = 0;
            for &flag_index in &participation_flag_indices {
                if has_flag(current_flags, flag_index) {
                    continue;
                }
                new_flags = add_flag(new_flags, flag_index);
                let weight = constants::PARTICIPATION_FLAG_WEIGHTS[flag_index];
                let increments =
                    state.validator(index)?.effective_balance / preset::EFFECTIVE_BALANCE_INCREMENT;
                let base_reward = increments.checked_mul(base_reward_per_increment).ok_or(
                    Error::ArithmeticOverflow("process_attestation: get_base_reward(state, index)"),
                )?;
                let reward = base_reward
                    .checked_mul(weight)
                    .ok_or(Error::ArithmeticOverflow(
                        "process_attestation: get_base_reward(state, index) * weight",
                    ))?;
                proposer_reward_numerator = proposer_reward_numerator.checked_add(reward).ok_or(
                    Error::ArithmeticOverflow("process_attestation: proposer_reward_numerator"),
                )?;
            }
            let will_set_new_flag = new_flags != 0;

            if will_set_new_flag
                && had_no_participation
                && is_same_slot
                && payment.withdrawal.amount > 0
            {
                let effective_balance = state.validator(index)?.effective_balance;
                payment.weight = payment.weight.checked_add(effective_balance).ok_or(
                    Error::ArithmeticOverflow(
                        "process_attestation: payment.weight + validator.effective_balance",
                    ),
                )?;
            }
            if will_set_new_flag {
                flag_updates.push((index, new_flags));
            }
        }
    }

    // Write phase: apply exactly the flags the read phase decided on.
    {
        let participation_mut = state.epoch_participation_mut(current_epoch_target)?;
        let participation_len = participation_mut.len();
        for (index, new_flags) in flag_updates {
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

    // Update builder payment weight.
    {
        let inner = gloas_state(state, "process_attestation")?;
        let len = inner.builder_pending_payments.len();
        let entry = inner
            .builder_pending_payments
            .get_mut(payment_index)
            .ok_or(Error::IndexOutOfBounds {
                index: payment_index,
                len,
            })?;
        *entry = payment;
    }

    Ok(())
}

/// `process_payload_attestation` (gloas `beacon-chain.md`): checks a payload
/// timeliness committee vote against the *parent* block (the previous slot's
/// proposal, whose payload it is attesting to) rather than against the head
/// [`process_attestation`] checks attestations against.
pub fn process_payload_attestation(
    state: &mut BeaconState,
    payload_attestation: &gloas::PayloadAttestation,
    config: &Config,
) -> Result<()> {
    let data = payload_attestation.data;

    // Check that the attestation is for the parent beacon block.
    verify(
        data.beacon_block_root == state.latest_block_header().parent_root,
        "process_payload_attestation: data.beacon_block_root == state.latest_block_header.parent_root",
    )?;
    // Check that the attestation is for the previous slot.
    let expected_slot = data.slot.checked_add(1).ok_or(Error::ArithmeticOverflow(
        "process_payload_attestation: data.slot + 1",
    ))?;
    verify(
        expected_slot == state.slot(),
        "process_payload_attestation: data.slot + 1 == state.slot",
    )?;

    // Verify signature.
    let indexed_payload_attestation =
        get_indexed_payload_attestation(state, payload_attestation, config)?;
    verify(
        is_valid_indexed_payload_attestation(state, &indexed_payload_attestation),
        "process_payload_attestation: is_valid_indexed_payload_attestation(state, indexed_payload_attestation)",
    )?;
    Ok(())
}

/// `process_operations` (modified, EIP-7732 and EIP-7688): removes the calls
/// to `process_deposit_request`, `process_withdrawal_request`, and
/// `process_consolidation_request` (see this module's own doc for where the
/// five execution-layer-triggered requests go instead), adds the new
/// `parent_slot` argument [`process_attestation`] needs and the payload
/// timeliness committee's own operation list, and, since every list here is
/// now an EIP-7688 progressive one with no SSZ-enforced bound of its own,
/// checks each list's length against its preset maximum explicitly (bounds
/// every earlier fork's container shape enforced by construction).
///
/// `assert len(body.deposits) == 0` unconditionally, with no `process_deposit`
/// call at all: like fulu, gloas has no eth1-bridge deposit path left to
/// drain (`crate::beacon::stf::fulu::process_operations`'s own doc explains why).
pub fn process_operations(
    state: &mut BeaconState,
    body: &gloas::BeaconBlockBody,
    parent_slot: Slot,
    config: &Config,
    committees: &CommitteeCache,
) -> Result<()> {
    verify(
        body.deposits.is_empty(),
        "process_operations: len(body.deposits) == 0",
    )?;

    // [New in Gloas:EIP7688]
    verify(
        body.proposer_slashings.len() <= preset::MAX_PROPOSER_SLASHINGS,
        "process_operations: len(body.proposer_slashings) <= MAX_PROPOSER_SLASHINGS",
    )?;
    verify(
        body.attester_slashings.len() <= preset::MAX_ATTESTER_SLASHINGS_ELECTRA,
        "process_operations: len(body.attester_slashings) <= MAX_ATTESTER_SLASHINGS_ELECTRA",
    )?;
    verify(
        body.attestations.len() <= preset::MAX_ATTESTATIONS_ELECTRA,
        "process_operations: len(body.attestations) <= MAX_ATTESTATIONS_ELECTRA",
    )?;
    verify(
        body.voluntary_exits.len() <= preset::MAX_VOLUNTARY_EXITS,
        "process_operations: len(body.voluntary_exits) <= MAX_VOLUNTARY_EXITS",
    )?;
    verify(
        body.bls_to_execution_changes.len() <= preset::MAX_BLS_TO_EXECUTION_CHANGES,
        "process_operations: len(body.bls_to_execution_changes) <= MAX_BLS_TO_EXECUTION_CHANGES",
    )?;
    verify(
        body.payload_attestations.len() as u64 <= preset::MAX_PAYLOAD_ATTESTATIONS,
        "process_operations: len(body.payload_attestations) <= MAX_PAYLOAD_ATTESTATIONS",
    )?;

    // [Modified in Gloas:EIP7732]
    for proposer_slashing in body.proposer_slashings.iter() {
        process_proposer_slashing(state, proposer_slashing, config)?;
    }
    for attester_slashing in body.attester_slashings.iter() {
        process_attester_slashing(state, attester_slashing, config)?;
    }
    // [Modified in Gloas:EIP7732]
    for attestation in body.attestations.iter() {
        process_attestation(state, attestation, parent_slot, committees)?;
    }
    for voluntary_exit in body.voluntary_exits.iter() {
        crate::beacon::stf::electra::process_voluntary_exit(state, voluntary_exit, config)?;
    }
    for signed_change in body.bls_to_execution_changes.iter() {
        crate::beacon::stf::capella::process_bls_to_execution_change(state, signed_change, config)?;
    }
    // [Modified in Gloas:EIP7732] Removed `process_deposit_request`,
    // `process_withdrawal_request`, and `process_consolidation_request`.
    // [New in Gloas:EIP7732]
    for payload_attestation in body.payload_attestations.iter() {
        process_payload_attestation(state, payload_attestation, config)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::containers::BeaconBlockHeader;
    use crate::beacon::fork::ForkName;
    use crate::beacon::primitives::{BlsPubkey, BlsSignature, ExecutionBlockHash, Uint256};

    fn gloas_state_with_validators(count: usize) -> BeaconState {
        crate::beacon::helpers::test_state::with_validators_at(ForkName::Gloas, count)
    }

    #[test]
    fn a_self_build_bid_needs_no_signature_or_value() {
        let mut state = gloas_state_with_validators(4);
        let config = Config::mainnet();

        let signed_bid = gloas::SignedExecutionPayloadBid {
            message: gloas::ExecutionPayloadBid {
                builder_index: constants::BUILDER_INDEX_SELF_BUILD,
                slot: state.slot(),
                value: 0,
                parent_block_hash: gloas_state_ref(&state, "test").unwrap().latest_block_hash,
                parent_block_root: get_block_root_at_slot(&state, state.slot() - 1).unwrap(),
                prev_randao: get_randao_mix(&state, get_current_epoch(&state)),
                block_hash: crate::beacon::primitives::ExecutionBlockHash::repeat_byte(1),
                ..Default::default()
            },
            signature: g2_point_at_infinity(),
        };

        process_execution_payload_bid(&mut state, &signed_bid, &config).unwrap();
        assert_eq!(
            gloas_state_ref(&state, "test")
                .unwrap()
                .latest_execution_payload_bid
                .block_hash,
            signed_bid.message.block_hash
        );
    }

    #[test]
    fn a_self_build_bid_with_a_nonzero_value_is_rejected() {
        let mut state = gloas_state_with_validators(4);
        let config = Config::mainnet();

        let signed_bid = gloas::SignedExecutionPayloadBid {
            message: gloas::ExecutionPayloadBid {
                builder_index: constants::BUILDER_INDEX_SELF_BUILD,
                slot: state.slot(),
                value: 1,
                parent_block_hash: gloas_state_ref(&state, "test").unwrap().latest_block_hash,
                parent_block_root: get_block_root_at_slot(&state, state.slot() - 1).unwrap(),
                prev_randao: get_randao_mix(&state, get_current_epoch(&state)),
                block_hash: crate::beacon::primitives::ExecutionBlockHash::repeat_byte(1),
                ..Default::default()
            },
            signature: g2_point_at_infinity(),
        };

        let result = process_execution_payload_bid(&mut state, &signed_bid, &config);
        assert!(
            matches!(
                result,
                Err(Error::SpecAssert(
                    "process_execution_payload_bid: amount == 0"
                ))
            ),
            "expected the self-build amount == 0 assertion to fail, got {result:?}"
        );
    }

    #[test]
    fn apply_withdrawals_saturates_a_builders_balance_rather_than_erroring() {
        let mut state = gloas_state_with_validators(1);
        {
            let inner = gloas_state(&mut state, "test").unwrap();
            inner.builders.push(gloas::Builder {
                balance: 10,
                ..Default::default()
            });
        }

        let withdrawal = capella::Withdrawal {
            index: 0,
            validator_index: convert_builder_index_to_validator_index(0),
            address: ExecutionAddress::ZERO,
            amount: 20,
        };
        apply_withdrawals(&mut state, std::slice::from_ref(&withdrawal)).unwrap();

        let inner = gloas_state_ref(&state, "test").unwrap();
        assert_eq!(inner.builders.first().unwrap().balance, 0);
    }

    #[test]
    fn get_execution_requests_list_orders_every_kind_by_its_own_prefix() {
        use crate::beacon::containers::electra;
        use crate::beacon::primitives::Bytes32;

        let requests = gloas::ExecutionRequests {
            deposits: gloas::DepositRequests::from(vec![electra::DepositRequest {
                pubkey: Default::default(),
                withdrawal_credentials: Bytes32::ZERO,
                amount: 0,
                signature: Default::default(),
                index: 0,
            }]),
            withdrawals: gloas::WithdrawalRequests::from(vec![electra::WithdrawalRequest {
                source_address: ExecutionAddress::ZERO,
                validator_pubkey: Default::default(),
                amount: 0,
            }]),
            consolidations: gloas::ConsolidationRequests::from(vec![
                electra::ConsolidationRequest {
                    source_address: ExecutionAddress::ZERO,
                    source_pubkey: Default::default(),
                    target_pubkey: Default::default(),
                },
            ]),
            builder_deposits: gloas::BuilderDepositRequests::from(vec![
                gloas::BuilderDepositRequest::default(),
            ]),
            builder_exits: gloas::BuilderExitRequests::from(vec![
                gloas::BuilderExitRequest::default(),
            ]),
        };

        let list = get_execution_requests_list(&requests);

        let prefixes: Vec<u8> = list.iter().map(|element| element[0]).collect();
        assert_eq!(
            prefixes,
            vec![
                constants::DEPOSIT_REQUEST_TYPE,
                constants::WITHDRAWAL_REQUEST_TYPE,
                constants::CONSOLIDATION_REQUEST_TYPE,
                constants::BUILDER_DEPOSIT_REQUEST_TYPE,
                constants::BUILDER_EXIT_REQUEST_TYPE,
            ],
            "every non-empty list appears, in its own fixed prefix order: \
             DEPOSIT_REQUEST_TYPE, WITHDRAWAL_REQUEST_TYPE, CONSOLIDATION_REQUEST_TYPE, \
             BUILDER_DEPOSIT_REQUEST_TYPE, BUILDER_EXIT_REQUEST_TYPE"
        );
        assert_eq!(
            &list[0][1..],
            requests.deposits.to_ssz(),
            "the element after the prefix byte is the request list's own SSZ encoding"
        );
    }

    #[test]
    fn get_execution_requests_list_skips_empty_lists() {
        let requests = gloas::ExecutionRequests {
            builder_exits: gloas::BuilderExitRequests::from(vec![
                gloas::BuilderExitRequest::default(),
            ]),
            ..Default::default()
        };

        // Every list but `builder_exits` is empty, so only its own element
        // appears; an all-empty `ExecutionRequests` produces an empty list.
        assert_eq!(
            get_execution_requests_list(&requests)
                .iter()
                .map(|element| element[0])
                .collect::<Vec<_>>(),
            vec![constants::BUILDER_EXIT_REQUEST_TYPE]
        );
        assert!(get_execution_requests_list(&gloas::ExecutionRequests::default()).is_empty());
    }

    #[test]
    fn process_operations_rejects_each_length_checked_list_past_its_max() {
        use crate::beacon::containers::shared;

        // Sanity does not run for gloas yet, so nothing else pins
        // these EIP-7688 length checks: every list here lost the SSZ bound a
        // bounded `SszList` used to enforce, so `process_operations` itself
        // is now the only thing standing between an oversized list and
        // `for_ops` processing it anyway.
        let state = gloas_state_with_validators(4);
        let config = Config::mainnet();

        let empty_indexed_attestation = || gloas::IndexedAttestation {
            attesting_indices: Default::default(),
            data: Default::default(),
            signature: Default::default(),
        };

        let cases: Vec<(&str, gloas::BeaconBlockBody)> = vec![
            (
                "process_operations: len(body.proposer_slashings) <= MAX_PROPOSER_SLASHINGS",
                gloas::BeaconBlockBody {
                    proposer_slashings: gloas::ProposerSlashings::from(vec![
                        shared::ProposerSlashing::default();
                        preset::MAX_PROPOSER_SLASHINGS + 1
                    ]),
                    ..gloas::BeaconBlockBody::empty()
                },
            ),
            (
                "process_operations: len(body.attester_slashings) <= MAX_ATTESTER_SLASHINGS_ELECTRA",
                gloas::BeaconBlockBody {
                    attester_slashings: gloas::AttesterSlashings::from(vec![
                        gloas::AttesterSlashing {
                            attestation_1: empty_indexed_attestation(),
                            attestation_2: empty_indexed_attestation(),
                        };
                        preset::MAX_ATTESTER_SLASHINGS_ELECTRA + 1
                    ]),
                    ..gloas::BeaconBlockBody::empty()
                },
            ),
            (
                "process_operations: len(body.attestations) <= MAX_ATTESTATIONS_ELECTRA",
                gloas::BeaconBlockBody {
                    attestations: gloas::Attestations::from(vec![
                        gloas::Attestation {
                            aggregation_bits: Default::default(),
                            data: Default::default(),
                            signature: Default::default(),
                            committee_bits: Default::default(),
                        };
                        preset::MAX_ATTESTATIONS_ELECTRA
                            + 1
                    ]),
                    ..gloas::BeaconBlockBody::empty()
                },
            ),
            (
                "process_operations: len(body.voluntary_exits) <= MAX_VOLUNTARY_EXITS",
                gloas::BeaconBlockBody {
                    voluntary_exits: gloas::VoluntaryExits::from(vec![
                        shared::SignedVoluntaryExit::default();
                        preset::MAX_VOLUNTARY_EXITS + 1
                    ]),
                    ..gloas::BeaconBlockBody::empty()
                },
            ),
            (
                "process_operations: len(body.bls_to_execution_changes) <= MAX_BLS_TO_EXECUTION_CHANGES",
                gloas::BeaconBlockBody {
                    bls_to_execution_changes: gloas::BlsToExecutionChanges::from(vec![
                        capella::SignedBLSToExecutionChange {
                            message: capella::BLSToExecutionChange {
                                validator_index: 0,
                                from_bls_pubkey: Default::default(),
                                to_execution_address: Default::default(),
                            },
                            signature: Default::default(),
                        };
                        preset::MAX_BLS_TO_EXECUTION_CHANGES + 1
                    ]),
                    ..gloas::BeaconBlockBody::empty()
                },
            ),
            (
                "process_operations: len(body.payload_attestations) <= MAX_PAYLOAD_ATTESTATIONS",
                gloas::BeaconBlockBody {
                    payload_attestations: gloas::PayloadAttestations::from(vec![
                        gloas::PayloadAttestation {
                            aggregation_bits: Default::default(),
                            data: Default::default(),
                            signature: Default::default(),
                        };
                        (preset::MAX_PAYLOAD_ATTESTATIONS + 1) as usize
                    ]),
                    ..gloas::BeaconBlockBody::empty()
                },
            ),
        ];

        for (expected_message, body) in cases {
            let mut state = state.clone();
            let committees = CommitteeCache::default();
            let result = process_operations(&mut state, &body, 0, &config, &committees);
            assert!(
                matches!(result, Err(Error::SpecAssert(message)) if message == expected_message),
                "expected {expected_message:?} to fail, got {result:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // verify_execution_payload_envelope
    // -----------------------------------------------------------------------

    /// A syntactically valid but otherwise arbitrary [`gloas::ExecutionPayload`],
    /// for a test that only cares about the envelope wrapping it, not the
    /// payload's own contents. [`gloas::ExecutionPayload`] has no
    /// `#[derive(Default)]` (see its own doc: `logs_bloom` has no meaningful
    /// empty value), so every field is filled by hand instead.
    fn arbitrary_execution_payload() -> gloas::ExecutionPayload {
        gloas::ExecutionPayload {
            parent_hash: ExecutionBlockHash::ZERO,
            fee_recipient: ExecutionAddress::ZERO,
            state_root: Bytes32::ZERO,
            receipts_root: Bytes32::ZERO,
            logs_bloom: crate::beacon::containers::bellatrix::LogsBloom::try_from(vec![
                0u8;
                preset::BYTES_PER_LOGS_BLOOM
            ])
            .expect("built at exactly BYTES_PER_LOGS_BLOOM"),
            prev_randao: Bytes32::ZERO,
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: Default::default(),
            base_fee_per_gas: Uint256::ZERO,
            block_hash: ExecutionBlockHash::ZERO,
            transactions: Default::default(),
            withdrawals: Default::default(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
            block_access_list: Default::default(),
            slot_number: 0,
        }
    }

    /// A self-build gloas state and the unsigned message an envelope for its
    /// current slot must match field for field to pass every check in
    /// [`verify_execution_payload_envelope`] but the engine's own.
    ///
    /// Returned unsigned and paired with the proposer's real secret key, so
    /// a test can tamper with exactly one field before signing: signing
    /// *after* the tamper keeps the signature real, over the tampered
    /// message, rather than merely malformed, which is what lets a test
    /// isolate the one assertion downstream of the signature check that the
    /// tamper is meant to trip. `tweak_bid` runs before the state's own
    /// fields (and so its `hash_tree_root`) are finalized, for a tamper that
    /// must land in the committed bid itself; `tweak_message` runs after,
    /// against the otherwise-consistent message, for one that must not.
    fn consistent_envelope_message(
        tweak_bid: impl FnOnce(&mut gloas::ExecutionPayloadBid),
        tweak_message: impl FnOnce(&mut gloas::ExecutionPayloadEnvelope),
    ) -> (
        BeaconState,
        Config,
        blst::min_pk::SecretKey,
        gloas::ExecutionPayloadEnvelope,
    ) {
        let mut state = gloas_state_with_validators(1);
        let secret = crate::beacon::helpers::test_state::secret_key_for(0);
        state.validator_mut(0).unwrap().pubkey = BlsPubkey(secret.sk_to_pk().to_bytes());

        let slot = state.slot();
        *state.latest_block_header_mut() = BeaconBlockHeader {
            slot,
            proposer_index: 0,
            parent_root: Root::repeat_byte(0x11),
            state_root: Root::ZERO,
            body_root: Root::repeat_byte(0x22),
        };

        let config = Config::mainnet();
        let parent_hash = ExecutionBlockHash::repeat_byte(0x33);
        let execution_requests = gloas::ExecutionRequests::default();
        let mut bid = gloas::ExecutionPayloadBid {
            parent_block_hash: ExecutionBlockHash::ZERO,
            parent_block_root: Root::ZERO,
            block_hash: ExecutionBlockHash::repeat_byte(0x44),
            prev_randao: Bytes32::repeat_byte(0x55),
            fee_recipient: ExecutionAddress::ZERO,
            gas_limit: 30_000_000,
            builder_index: constants::BUILDER_INDEX_SELF_BUILD,
            slot,
            value: 0,
            execution_payment: 0,
            blob_kzg_commitments: Default::default(),
            execution_requests_root: execution_requests.hash_tree_root(),
        };
        tweak_bid(&mut bid);

        {
            let inner = gloas_state(&mut state, "test").unwrap();
            inner.latest_block_hash = parent_hash;
            inner.latest_execution_payload_bid = bid.clone();
            inner.payload_expected_withdrawals = gloas::Withdrawals::default();
        }
        // `validators` is the tree-backed field `validator_mut` above
        // buffered a write against; flush it before `state.compute_state_root()`
        // below, the same way `gossip::test_support::fulu_parent` does.
        state.apply_pending_mutations();

        // The same `compute_state_root` call `verify_execution_payload_envelope`
        // itself now makes; see that function's own doc for why. The header's
        // own `state_root` is still zero at this point, so this falls to a
        // fresh `hash_tree_root`, matching a state fresh out of block
        // processing.
        let mut header = state.latest_block_header().clone();
        header.state_root = state.compute_state_root();
        let beacon_block_root = header.hash_tree_root();

        let payload = gloas::ExecutionPayload {
            parent_hash,
            fee_recipient: ExecutionAddress::ZERO,
            state_root: Bytes32::ZERO,
            receipts_root: Bytes32::ZERO,
            logs_bloom: crate::beacon::containers::bellatrix::LogsBloom::try_from(vec![
                0u8;
                preset::BYTES_PER_LOGS_BLOOM
            ])
            .expect("built at exactly BYTES_PER_LOGS_BLOOM"),
            prev_randao: bid.prev_randao,
            block_number: 0,
            gas_limit: bid.gas_limit,
            gas_used: 0,
            timestamp: crate::beacon::stf::bellatrix::compute_timestamp_at_slot(
                &state, slot, &config,
            ),
            extra_data: Default::default(),
            base_fee_per_gas: Uint256::ZERO,
            block_hash: bid.block_hash,
            transactions: Default::default(),
            withdrawals: gloas::Withdrawals::default(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
            block_access_list: Default::default(),
            slot_number: slot,
        };

        let mut message = gloas::ExecutionPayloadEnvelope {
            payload,
            execution_requests,
            builder_index: constants::BUILDER_INDEX_SELF_BUILD,
            beacon_block_root,
            parent_beacon_block_root: state.latest_block_header().parent_root,
        };
        tweak_message(&mut message);

        (state, config, secret, message)
    }

    /// Signs `message` the way a builder (or, for a self-build, the
    /// proposer) would: over `hash_tree_root(message)` under
    /// `DOMAIN_BEACON_BUILDER`, matching
    /// [`verify_execution_payload_envelope_signature`] exactly.
    fn sign_envelope(
        state: &BeaconState,
        secret: &blst::min_pk::SecretKey,
        message: gloas::ExecutionPayloadEnvelope,
    ) -> gloas::SignedExecutionPayloadEnvelope {
        let domain = get_domain(state, constants::DOMAIN_BEACON_BUILDER, None);
        let signing_root = compute_signing_root(message.hash_tree_root(), domain);
        let signature = BlsSignature(
            secret
                .sign(signing_root.as_slice(), bls::DST, &[])
                .to_bytes(),
        );
        gloas::SignedExecutionPayloadEnvelope { message, signature }
    }

    #[test]
    fn a_consistent_envelope_only_fails_the_engine_check() {
        let (state, config, secret, message) = consistent_envelope_message(|_| {}, |_| {});
        let signed = sign_envelope(&state, &secret, message);

        assert!(
            matches!(
                verify_execution_payload_envelope(
                    &state,
                    &signed,
                    &config,
                    &ExecutionEngine::invalid()
                ),
                Err(Error::SpecAssert(
                    "verify_execution_payload_envelope: execution_engine.verify_and_notify_new_payload(\
                     NewPayloadRequest(execution_payload=payload, versioned_hashes=versioned_hashes, \
                     parent_beacon_block_root=envelope.parent_beacon_block_root, \
                     execution_requests=envelope.execution_requests))"
                ))
            ),
            "every check but the engine's should have already passed"
        );
        verify_execution_payload_envelope(&state, &signed, &config, &ExecutionEngine::valid())
            .expect("a consistent envelope passes every check, including a valid engine's");
    }

    #[test]
    fn a_stored_states_cached_state_root_still_matches_the_envelope() {
        // `consistent_envelope_message` builds the state the way a state
        // fresh out of block processing looks: `latest_block_header.state_root`
        // still zero. This repository's stored states do not stay that way:
        // `fork_choice::on_block` (and the checkpoint anchor) cache the real
        // root into that same field right after `state_transition` returns,
        // which is what `verify_execution_payload_envelope`'s only real
        // caller, `on_execution_payload_envelope`, actually hands in.
        let (mut state, config, secret, message) = consistent_envelope_message(|_| {}, |_| {});
        let signed = sign_envelope(&state, &secret, message);

        // Computed, not asserted: `compute_state_root` on this still-zero
        // state falls to a fresh hash, the same value
        // `consistent_envelope_message` already built `envelope.beacon_block_root`
        // from. Caching it into the header mimics the stored shape without
        // changing what that value actually is.
        let cached_root = state.compute_state_root();
        state.latest_block_header_mut().state_root = cached_root;

        verify_execution_payload_envelope(&state, &signed, &config, &ExecutionEngine::valid())
            .expect("a stored state's cached header.state_root must still match the envelope");
    }

    #[test]
    fn a_wrong_beacon_block_root_is_rejected() {
        let (state, config, secret, message) = consistent_envelope_message(
            |_| {},
            |message| message.beacon_block_root = Root::repeat_byte(0xee),
        );
        // Signed *after* the tamper, so the signature itself still checks
        // out: what should fail is the block-root consistency check, not
        // the signature.
        let signed = sign_envelope(&state, &secret, message);

        let result =
            verify_execution_payload_envelope(&state, &signed, &config, &ExecutionEngine::valid());
        assert!(
            matches!(
                result,
                Err(Error::SpecAssert(
                    "verify_execution_payload_envelope: envelope.beacon_block_root == hash_tree_root(header)"
                ))
            ),
            "expected the beacon_block_root check to fail, got {result:?}"
        );
    }

    #[test]
    fn a_wrong_builder_index_is_rejected() {
        // Only the committed bid's own `builder_index` disagrees; the
        // envelope stays self-build-consistent (signed by the proposer,
        // `builder_index == BUILDER_INDEX_SELF_BUILD`), so the signature
        // check still passes and the mismatch is isolated to the one
        // assertion it is meant to trip. `bid.builder_index` is otherwise
        // unread by `verify_execution_payload_envelope`.
        let (state, config, secret, message) =
            consistent_envelope_message(|bid| bid.builder_index = 0, |_| {});
        let signed = sign_envelope(&state, &secret, message);

        let result =
            verify_execution_payload_envelope(&state, &signed, &config, &ExecutionEngine::valid());
        assert!(
            matches!(
                result,
                Err(Error::SpecAssert(
                    "verify_execution_payload_envelope: envelope.builder_index == bid.builder_index"
                ))
            ),
            "expected the builder_index check to fail, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // verify_execution_payload_envelope_signature
    // -----------------------------------------------------------------------

    #[test]
    fn a_builder_signed_envelope_passes_the_signature_check() {
        let mut state = gloas_state_with_validators(1);
        let secret = crate::beacon::helpers::test_state::secret_key_for(1);
        let builder_index: gloas::BuilderIndex = {
            let inner = gloas_state(&mut state, "test").unwrap();
            inner.builders.push(gloas::Builder {
                pubkey: BlsPubkey(secret.sk_to_pk().to_bytes()),
                ..Default::default()
            });
            (inner.builders.len() - 1) as gloas::BuilderIndex
        };
        state.apply_pending_mutations();

        let message = gloas::ExecutionPayloadEnvelope {
            payload: arbitrary_execution_payload(),
            execution_requests: gloas::ExecutionRequests::default(),
            builder_index,
            beacon_block_root: Root::ZERO,
            parent_beacon_block_root: Root::ZERO,
        };
        let signed = sign_envelope(&state, &secret, message);

        assert!(
            verify_execution_payload_envelope_signature(&state, &signed).unwrap(),
            "a builder's own signature over an envelope naming its own index must verify"
        );
    }

    #[test]
    fn a_self_build_envelope_signed_with_a_builders_key_is_rejected() {
        let mut state = gloas_state_with_validators(1);
        // The proposer's own key, distinct from the builder's below, so a
        // self-build envelope genuinely needs it rather than accepting any
        // signature.
        let proposer_secret = crate::beacon::helpers::test_state::secret_key_for(0);
        state.validator_mut(0).unwrap().pubkey = BlsPubkey(proposer_secret.sk_to_pk().to_bytes());
        *state.latest_block_header_mut() = BeaconBlockHeader {
            proposer_index: 0,
            ..Default::default()
        };
        state.apply_pending_mutations();

        let builder_secret = crate::beacon::helpers::test_state::secret_key_for(1);
        let message = gloas::ExecutionPayloadEnvelope {
            payload: arbitrary_execution_payload(),
            execution_requests: gloas::ExecutionRequests::default(),
            builder_index: constants::BUILDER_INDEX_SELF_BUILD,
            beacon_block_root: Root::ZERO,
            parent_beacon_block_root: Root::ZERO,
        };
        // Signed with the builder's key, not the proposer's: a self-build
        // envelope must verify against the proposer named in
        // `state.latest_block_header.proposer_index`, so this signature must
        // not check out.
        let signed = sign_envelope(&state, &builder_secret, message);

        assert!(
            !verify_execution_payload_envelope_signature(&state, &signed).unwrap(),
            "a self-build envelope signed by a builder, not the proposer, must not verify"
        );
    }
}
