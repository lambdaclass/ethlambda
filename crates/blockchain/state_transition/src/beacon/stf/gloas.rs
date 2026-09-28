//! Gloas's withdrawals, execution payload bid, and parent execution payload
//! processing (EIP-7732).
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

use crate::beacon::bls;
use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::shared::DepositMessage;
use crate::beacon::containers::{BeaconState, capella, gloas};
use crate::beacon::error::{Error, Result, verify};
use crate::beacon::helpers::accessors::{
    get_beacon_proposer_index, get_block_root_at_slot, get_current_epoch, get_domain,
    get_previous_epoch, get_randao_mix,
};
use crate::beacon::helpers::electra::g2_point_at_infinity;
use crate::beacon::helpers::gloas::{
    add_builder_to_registry, can_builder_cover_bid, convert_builder_index_to_validator_index,
    convert_validator_index_to_builder_index, gloas_state, gloas_state_ref, initiate_builder_exit,
    is_active_builder, is_builder_index, is_builder_withdrawal_credential, settle_builder_payment,
};
use crate::beacon::helpers::misc::{compute_domain, compute_epoch_at_slot, compute_signing_root};
use crate::beacon::helpers::mutators::decrease_balance;
use crate::beacon::preset;
use crate::beacon::primitives::{ExecutionAddress, HashTreeRoot as _, Root, WithdrawalIndex};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::fork::ForkName;

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
}
