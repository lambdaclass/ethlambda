//! Bellatrix's block processing: the Merge.
//!
//! Before this fork, the beacon chain and the execution chain ran two separate
//! consensus mechanisms: proof-of-work miners built the execution chain on
//! their own schedule, joined to the beacon chain only by the deposit
//! contract. Bellatrix retires the execution chain's own consensus outright:
//! from here on a beacon block carries its execution block whole, as an
//! [`bellatrix::ExecutionPayload`], and [`process_execution_payload`] is the
//! one new step [`process_block`] adds to validate it and hand it to
//! [`super::ExecutionEngine`]'s stand-in for a real execution client.
//!
//! [`BeaconState`] keeps only [`bellatrix::ExecutionPayloadHeader`], never the
//! whole payload. Everything a later block needs from the one before it is
//! enough to check continuity, that the new payload's `parent_hash` chains to
//! the stored header's own `block_hash`, and [`process_execution_payload`]
//! does exactly that without ever asking the execution layer what came
//! before. Keeping every transaction, in every state, forever, would cost far
//! more than that one check needs, so the header substitutes
//! `transactions_root` for `transactions`, the same substitution
//! [`crate::containers::shared::BeaconBlockHeader`] already makes for a
//! beacon block's own body.
//!
//! [`is_merge_transition_complete`], [`is_merge_transition_block`], and
//! [`is_execution_enabled`] exist only for the fork in which the transition
//! itself can happen. Once a chain's first real payload lands,
//! `is_merge_transition_complete` answers the same way forever, and capella's
//! own specification drops the whole family of checks rather than keep
//! evaluating a question every later block already answers identically. See
//! [`bellatrix_state_ref`]'s documentation for what that implies about how
//! far this file's own state projection needs to reach.

use crate::config::Config;
use crate::constants;
use crate::containers::{BeaconState, bellatrix};
use crate::error::{Error, Result, verify};
use crate::helpers::accessors::{get_current_epoch, get_randao_mix};
use crate::preset;
use crate::primitives::{
    Bytes32, ExecutionAddress, ExecutionBlockHash, HashTreeRoot as _, Root, Slot, Uint256,
};

use super::ExecutionEngine;

// ---------------------------------------------------------------------------
// Block processing
// ---------------------------------------------------------------------------

/// Bellatrix's block processing: altair's steps, with the execution payload
/// inserted between the header and the RANDAO reveal.
///
/// That insertion point is the one place this fork's own order matters, and
/// the specification says so explicitly: [`process_execution_payload`] must
/// run before [`super::block::process_randao`], because the payload's
/// `prev_randao` has to match the *previous* block's mix, the very one
/// [`super::block::process_randao`] is about to overwrite with this block's
/// own reveal. Running them in the other order would check `prev_randao`
/// against a mix this same block already replaced, which no honest proposer
/// could ever satisfy.
///
/// The payload step is conditional on [`is_execution_enabled`]: bellatrix is
/// the one fork where a block might still legitimately carry no real payload,
/// if this chain's merge transition has not happened yet. Every later fork
/// drops the condition outright, since by then it is always true.
pub fn process_block(
    state: &mut BeaconState,
    block: &bellatrix::BeaconBlock,
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
    if is_execution_enabled(state, &block.body.execution_payload)? {
        process_execution_payload(state, &block.body.execution_payload, config, engine)?;
    }
    super::block::process_randao(state, &block.body.randao_reveal)?;
    super::block::process_eth1_data(state, &block.body.eth1_data)?;
    super::operations::process_operations(
        state,
        &block.body.proposer_slashings,
        &block.body.attester_slashings,
        &block.body.attestations,
        &block.body.deposits,
        &block.body.voluntary_exits,
        config,
    )?;
    super::altair::process_sync_aggregate(state, &block.body.sync_aggregate)?;
    Ok(())
}

/// Validates this slot's execution payload against the state and the
/// stand-in execution engine, then caches its header.
///
/// Takes `payload` alone rather than a whole body, the same way every shared
/// step in [`super::block`] takes only the fields it reads; see
/// [`crate::stf`]'s module documentation for why no shared body type exists to
/// pass instead. Takes `config`, which the specification's own
/// `process_execution_payload(state, body, execution_engine)` does not: the
/// specification reaches `SECONDS_PER_SLOT` from global scope the way every
/// specification function reaches every constant, but that value is a
/// network's own [`Config::seconds_per_slot`] here, not a preset, so
/// [`compute_timestamp_at_slot`], the one thing this calls that actually needs
/// it, has to be handed one, and so must this.
///
/// Collapses the specification's `verify_and_notify_new_payload` (itself
/// `is_valid_block_hash` and `notify_new_payload`, both calls to a real
/// execution client) into reading [`ExecutionEngine::execution_valid`]
/// straight off the stand-in `engine`; see that type's own documentation for
/// why nothing here can call out to a real one.
pub fn process_execution_payload(
    state: &mut BeaconState,
    payload: &bellatrix::ExecutionPayload,
    config: &Config,
    engine: &ExecutionEngine,
) -> Result<()> {
    if is_merge_transition_complete(state)? {
        let bellatrix_ref = bellatrix_state_ref(state, "process_execution_payload")?;
        verify(
            payload.parent_hash == bellatrix_ref.latest_execution_payload_header.block_hash,
            "payload.parent_hash == state.latest_execution_payload_header.block_hash",
        )?;
    }
    verify(
        payload.prev_randao == get_randao_mix(state, get_current_epoch(state)),
        "payload.prev_randao == get_randao_mix(state, get_current_epoch(state))",
    )?;
    verify(
        payload.timestamp == compute_timestamp_at_slot(state, state.slot(), config),
        "payload.timestamp == compute_timestamp_at_slot(state, state.slot, config)",
    )?;
    verify(
        engine.execution_valid,
        "verify_and_notify_new_payload(NewPayloadRequest(execution_payload=payload))",
    )?;

    let header = bellatrix::ExecutionPayloadHeader {
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
        // The header substitutes a root for the whole transaction list; see
        // this module's own documentation for why the state keeps only that
        // much.
        transactions_root: payload.transactions.hash_tree_root(),
    };
    bellatrix_state(state, "process_execution_payload")?.latest_execution_payload_header = header;

    Ok(())
}

// ---------------------------------------------------------------------------
// Merge-transition predicates
// ---------------------------------------------------------------------------

/// Whether this chain's merge transition has already happened: whether some
/// earlier block already set `latest_execution_payload_header` to anything
/// other than the all-default value every pre-merge state carries.
///
/// Once true, stays true forever: nothing ever resets
/// `latest_execution_payload_header` back to its default. Capella's own
/// specification relies on exactly that monotonicity to drop this whole
/// question; see [`bellatrix_state_ref`]'s documentation for what that means
/// for this file's own state projection.
pub fn is_merge_transition_complete(state: &BeaconState) -> Result<bool> {
    let bellatrix_ref = bellatrix_state_ref(state, "is_merge_transition_complete")?;
    Ok(bellatrix_ref.latest_execution_payload_header != default_execution_payload_header()?)
}

/// Whether `payload` is the one block that carries this chain's transition:
/// the merge has not completed yet, and this payload is not the empty
/// placeholder either.
///
/// A block proposed before the transition still has to put *something* in its
/// `execution_payload` field, since bellatrix's `BeaconBlockBody` carries one
/// unconditionally rather than making it optional; the specification's own
/// convention is that such a block carries the all-default
/// [`bellatrix::ExecutionPayload`], which this treats as "no real payload
/// yet" rather than as a payload to validate.
pub fn is_merge_transition_block(
    state: &BeaconState,
    payload: &bellatrix::ExecutionPayload,
) -> Result<bool> {
    Ok(!is_merge_transition_complete(state)? && *payload != default_execution_payload()?)
}

/// Whether [`process_execution_payload`] should run at all for this block:
/// either the transition already happened, or this block is the one that
/// makes it happen.
///
/// The only way this is false is a pre-merge block carrying no real payload;
/// every later fork drops this check because that possibility itself stops
/// existing once a chain's transition is behind it.
pub fn is_execution_enabled(
    state: &BeaconState,
    payload: &bellatrix::ExecutionPayload,
) -> Result<bool> {
    Ok(is_merge_transition_block(state, payload)? || is_merge_transition_complete(state)?)
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// The wall-clock Unix time a slot's block is due, from the chain's genesis
/// time and [`Config::seconds_per_slot`].
///
/// Named `compute_timestamp_at_slot` here rather than the specification's own
/// `compute_time_at_slot`; [`Config::seconds_per_slot`]'s own doc comment
/// already anticipates the specification's name, so the two disagree, and
/// whoever next touches either should settle on one name in both places.
///
/// The specification flags this arithmetic as "unsafe with respect to
/// overflows and underflows", a warning aimed at Python's own
/// arbitrary-precision integers never actually needing it. This function
/// cannot return an error (its caller, [`process_execution_payload`], only
/// ever compares the result against a value the block itself supplies, so
/// there is nothing to reject the block *for* here), so an overflow
/// saturates rather than wraps: wrapping could land on a small value that
/// looks like a plausible, if wrong, timestamp, where saturating cannot.
pub fn compute_timestamp_at_slot(state: &BeaconState, slot: Slot, config: &Config) -> u64 {
    // `GENESIS_SLOT` is `Slot`'s zero point, so subtracting it from any slot
    // can never underflow.
    let slots_since_genesis = slot - constants::GENESIS_SLOT;
    slots_since_genesis
        .saturating_mul(config.seconds_per_slot)
        .saturating_add(state.genesis_time())
}

// ---------------------------------------------------------------------------
// Fork projection
// ---------------------------------------------------------------------------

/// The bellatrix state, mutably, or an error naming the function that needs
/// one.
///
/// Scoped to `BeaconState::Bellatrix` alone, not to every fork from bellatrix
/// through fulu. That narrower scope is deliberate. Every caller in this file
/// is reached only through [`process_block`], which
/// [`super::block::process_block`] dispatches to precisely when `state` is
/// already `BeaconState::Bellatrix` (checked once, before any per-fork
/// dispatch, by [`super::state_transition`]), and nothing outside this file
/// ever calls back into it for a later fork's own state. Capella's
/// specification is explicit about why that is safe: its own `process_block`
/// drops the `is_execution_enabled` call, and its own
/// `process_execution_payload` drops the `is_merge_transition_complete`
/// check, both marked "Removed" rather than "Modified", because once a
/// chain's transition is behind it, every later block answers both questions
/// the same way regardless of anything this projection could tell it. Each
/// fork from capella on keeps its own `latest_execution_payload_header`, of
/// its own distinct type (withdrawals added at capella, blob fields at deneb,
/// and so on), and will need its own projection of this same shape to reach
/// it, not this one widened to somehow return a different concrete type per
/// caller.
pub(crate) fn bellatrix_state<'a>(
    state: &'a mut BeaconState,
    function: &'static str,
) -> Result<&'a mut bellatrix::BeaconState> {
    match state {
        BeaconState::Bellatrix(state) => Ok(state),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

/// The bellatrix state, immutably. See [`bellatrix_state`].
pub(crate) fn bellatrix_state_ref<'a>(
    state: &'a BeaconState,
    function: &'static str,
) -> Result<&'a bellatrix::BeaconState> {
    match state {
        BeaconState::Bellatrix(state) => Ok(state),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Default values
// ---------------------------------------------------------------------------

/// The all-default [`bellatrix::ExecutionPayloadHeader`]: the value the
/// specification's bare `ExecutionPayloadHeader()` constructor builds, every
/// field at its type's zero value.
///
/// Not `#[derive(Default)]`: `logs_bloom` is an [`libssz_types::SszVector`],
/// and the patched `libssz` this crate builds against gives that type no
/// `Default` impl at all, since, unlike a list, a fixed-length vector has no
/// value that is validly empty. [`crate::upgrade`] already builds this exact
/// value the same way, for the same reason, when altair's state upgrades into
/// bellatrix's; its helper is private to that module, and this file may only
/// touch its own, so this is a deliberate second copy rather than a shared
/// one. [`is_merge_transition_complete`] is this function's only caller.
fn default_execution_payload_header() -> Result<bellatrix::ExecutionPayloadHeader> {
    Ok(bellatrix::ExecutionPayloadHeader {
        parent_hash: ExecutionBlockHash::zero(),
        fee_recipient: ExecutionAddress::zero(),
        state_root: Bytes32::zero(),
        receipts_root: Bytes32::zero(),
        logs_bloom: bellatrix::LogsBloom::try_from(vec![0u8; preset::BYTES_PER_LOGS_BLOOM])?,
        prev_randao: Bytes32::zero(),
        block_number: 0,
        gas_limit: 0,
        gas_used: 0,
        timestamp: 0,
        extra_data: bellatrix::ExtraData::default(),
        base_fee_per_gas: Uint256::zero(),
        block_hash: ExecutionBlockHash::zero(),
        transactions_root: Root::zero(),
    })
}

/// The all-default [`bellatrix::ExecutionPayload`]: the value the
/// specification's bare `ExecutionPayload()` constructor builds. See
/// [`default_execution_payload_header`] for why this is built field by field
/// rather than derived. [`is_merge_transition_block`] is this function's only
/// caller.
fn default_execution_payload() -> Result<bellatrix::ExecutionPayload> {
    Ok(bellatrix::ExecutionPayload {
        parent_hash: ExecutionBlockHash::zero(),
        fee_recipient: ExecutionAddress::zero(),
        state_root: Bytes32::zero(),
        receipts_root: Bytes32::zero(),
        logs_bloom: bellatrix::LogsBloom::try_from(vec![0u8; preset::BYTES_PER_LOGS_BLOOM])?,
        prev_randao: Bytes32::zero(),
        block_number: 0,
        gas_limit: 0,
        gas_used: 0,
        timestamp: 0,
        extra_data: bellatrix::ExtraData::default(),
        base_fee_per_gas: Uint256::zero(),
        block_hash: ExecutionBlockHash::zero(),
        transactions: Default::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containers::altair::SyncCommittee;
    use crate::containers::shared::Validator;
    use crate::primitives::BlsPubkey;

    /// A bellatrix state with `count` fully active, full-balance validators,
    /// one epoch in (so the block-root history window already has entries),
    /// and `header` as its `latest_execution_payload_header`.
    ///
    /// Modeled on `crate::helpers::altair::tests::altair_state_with_validators`,
    /// which builds the same shape of state one fork earlier; this crate has
    /// no shared per-fork test-state builder yet, so each fork's own test
    /// module grows a near-duplicate of the last one, the same way this one
    /// does.
    fn bellatrix_state_with_validators(
        count: usize,
        header: bellatrix::ExecutionPayloadHeader,
    ) -> BeaconState {
        let validators: Vec<Validator> = (0..count)
            .map(|_| Validator {
                effective_balance: preset::MAX_EFFECTIVE_BALANCE,
                activation_eligibility_epoch: 0,
                activation_epoch: 0,
                exit_epoch: constants::FAR_FUTURE_EPOCH,
                withdrawable_epoch: constants::FAR_FUTURE_EPOCH,
                ..Default::default()
            })
            .collect();

        let empty_sync_committee = || SyncCommittee {
            pubkeys: vec![BlsPubkey::default(); preset::SYNC_COMMITTEE_SIZE]
                .try_into()
                .expect("built at exactly SYNC_COMMITTEE_SIZE"),
            aggregate_pubkey: BlsPubkey::default(),
        };

        BeaconState::Bellatrix(bellatrix::BeaconState {
            genesis_time: 0,
            genesis_validators_root: Root::zero(),
            slot: preset::SLOTS_PER_EPOCH,
            fork: Default::default(),
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
            balances: vec![preset::MAX_EFFECTIVE_BALANCE; count]
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
            latest_execution_payload_header: header,
        })
    }

    /// A payload that is not the all-default placeholder: distinct from
    /// [`default_execution_payload`] in exactly one field, which is enough
    /// for every predicate under test here.
    fn non_default_payload() -> bellatrix::ExecutionPayload {
        let mut payload = default_execution_payload().unwrap();
        payload.parent_hash = ExecutionBlockHash::repeat_byte(0xab);
        payload
    }

    // The three states worth distinguishing: a chain that has not started its
    // merge transition and whose block carries no real payload either, a
    // chain mid-transition whose block is the transition block itself, and a
    // chain whose transition is already behind it.

    #[test]
    fn pre_merge_state_with_no_real_payload_leaves_execution_disabled() {
        let header = default_execution_payload_header().unwrap();
        let state = bellatrix_state_with_validators(4, header);
        let payload = default_execution_payload().unwrap();

        assert!(!is_merge_transition_complete(&state).unwrap());
        assert!(!is_merge_transition_block(&state, &payload).unwrap());
        assert!(!is_execution_enabled(&state, &payload).unwrap());
    }

    #[test]
    fn pre_merge_state_with_a_real_payload_is_the_transition_block() {
        let header = default_execution_payload_header().unwrap();
        let state = bellatrix_state_with_validators(4, header);
        let payload = non_default_payload();

        assert!(!is_merge_transition_complete(&state).unwrap());
        assert!(is_merge_transition_block(&state, &payload).unwrap());
        assert!(
            is_execution_enabled(&state, &payload).unwrap(),
            "the transition block itself must still run process_execution_payload"
        );
    }

    #[test]
    fn post_merge_state_has_execution_enabled_regardless_of_the_payload() {
        let mut header = default_execution_payload_header().unwrap();
        header.block_hash = ExecutionBlockHash::repeat_byte(0xcd);
        let state = bellatrix_state_with_validators(4, header);

        assert!(is_merge_transition_complete(&state).unwrap());

        // Once the transition is behind a chain, `is_merge_transition_block`
        // is false no matter what the payload looks like: the first half of
        // its own condition already failed, so the payload's own shape
        // cannot rescue it.
        let empty_payload = default_execution_payload().unwrap();
        assert!(!is_merge_transition_block(&state, &empty_payload).unwrap());
        assert!(is_execution_enabled(&state, &empty_payload).unwrap());

        let real_payload = non_default_payload();
        assert!(!is_merge_transition_block(&state, &real_payload).unwrap());
        assert!(is_execution_enabled(&state, &real_payload).unwrap());
    }

    #[test]
    fn compute_timestamp_at_slot_matches_genesis_time_plus_slot_seconds() {
        let header = default_execution_payload_header().unwrap();
        let state = bellatrix_state_with_validators(4, header);
        let config = Config::minimal();

        let expected = state.genesis_time() + state.slot() * config.seconds_per_slot;
        assert_eq!(
            compute_timestamp_at_slot(&state, state.slot(), &config),
            expected
        );
    }

    #[test]
    fn process_execution_payload_rejects_an_invalid_engine_but_accepts_a_valid_one() {
        let header = default_execution_payload_header().unwrap();
        let mut state = bellatrix_state_with_validators(4, header);
        let config = Config::minimal();

        let mut payload = non_default_payload();
        payload.prev_randao = get_randao_mix(&state, get_current_epoch(&state));
        payload.timestamp = compute_timestamp_at_slot(&state, state.slot(), &config);

        assert!(
            process_execution_payload(
                &mut state.clone(),
                &payload,
                &config,
                &ExecutionEngine::invalid()
            )
            .is_err(),
            "an execution client that rejects the payload must fail the block"
        );

        process_execution_payload(&mut state, &payload, &config, &ExecutionEngine::valid())
            .unwrap();

        assert!(is_merge_transition_complete(&state).unwrap());
        let stored_header = &bellatrix_state_ref(&state, "test assertion")
            .unwrap()
            .latest_execution_payload_header;
        assert_eq!(stored_header.parent_hash, payload.parent_hash);
        assert_eq!(
            stored_header.transactions_root,
            payload.transactions.hash_tree_root()
        );
    }
}
