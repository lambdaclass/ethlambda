//! Fulu-specific block processing.
//!
//! Fulu changes no field of a block and redefines no step of `process_block`
//! itself: `beacon-chain.md`'s "Block processing" section for this fork
//! contains exactly one item, a modified `process_execution_payload`. So
//! [`process_block`] dispatches on [`electra::BeaconBlock`], the same type
//! fulu's own [`crate::containers::SignedBeaconBlock::Fulu`] variant wraps,
//! rather than a `fulu::BeaconBlock` that does not exist, and every step
//! but one is [`super::electra`]'s own function, called directly rather than
//! transcribed.
//!
//! The one change is why a block's blob commitment count stops being checked
//! against a single network-wide constant. Through electra, a block could
//! carry at most [`Config::max_blobs_per_block_electra`] blobs, each
//! downloaded and verified whole by every node that wants to check it. Fulu
//! moves to a sampling model instead (`das-core.md`): a blob is
//! erasure-coded into a wide row of columns, and a node gains the same
//! confidence that the data behind a commitment is available by sampling a
//! handful of those columns rather than downloading the blob itself. That
//! changes what the per-block limit is even bounding: no longer "how much
//! data must every node download," but "how many columns exist for the
//! network to sample from," a quantity the network can raise again and
//! again without a further hard fork, since nothing about an individual
//! node's own workload scales with it the way whole-blob downloads used to.
//! EIP-7892's blob schedule ([`Config::blob_schedule`]) is what carries a
//! raised limit into effect at a chosen epoch, and [`process_execution_payload`]
//! is the one place in block processing that reads it, through
//! [`Config::max_blobs_per_block`], in place of electra's fixed field.
//!
//! [`super::block::process_block_header`], [`super::block::process_randao`],
//! and [`super::block::process_eth1_data`] are reused because they always
//! were fork-shared; [`super::electra::process_withdrawals`],
//! [`super::electra::process_operations`], and
//! [`super::altair::process_sync_aggregate`] are reused because fulu's
//! specification never mentions any of the three. [`process_execution_payload`]
//! itself cannot be [`super::electra::process_execution_payload`] called
//! unchanged, for the same reason electra's own version could not be
//! deneb's: it reads a different [`Config`] field for the one check that
//! changed.

use crate::config::Config;
use crate::containers::{BeaconState, deneb, electra};
use crate::error::{Result, verify};
use crate::helpers::accessors::{get_current_epoch, get_randao_mix};
use crate::helpers::fulu::{fulu_state, fulu_state_ref};
use crate::primitives::{Bytes32, HashTreeRoot as _};

use super::ExecutionEngine;

// ---------------------------------------------------------------------------
// Block processing
// ---------------------------------------------------------------------------

/// Fulu's block processing: electra's own steps, in electra's own order,
/// with [`process_execution_payload`] standing in for
/// [`super::electra::process_execution_payload`]. See the module docs for
/// why that is the only step this fork's specification asks to change.
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
    super::electra::process_withdrawals(state, &block.body.execution_payload)?;
    process_execution_payload(state, &block.body, config, engine)?;
    super::block::process_randao(state, &block.body.randao_reveal)?;
    super::block::process_eth1_data(state, &block.body.eth1_data)?;
    super::electra::process_operations(state, &block.body, config)?;
    super::altair::process_sync_aggregate(state, &block.body.sync_aggregate)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Execution payload
// ---------------------------------------------------------------------------

/// Validates this slot's execution payload and its blob commitments, then
/// caches the payload's header.
///
/// Structurally [`super::electra::process_execution_payload`] (parent-hash
/// continuity, `prev_randao`, timestamp, a blob-commitment count check, the
/// collapsed engine check, then caching a [`deneb::ExecutionPayloadHeader`],
/// the same header type fulu keeps unchanged from deneb through electra),
/// but not literally callable as that function: its commitment-count check
/// reads [`Config::max_blobs_per_block_electra`], a single fixed
/// configuration value, while fulu's own limit comes from
/// [`Config::max_blobs_per_block`], which consults
/// [`Config::blob_schedule`] (EIP-7892) for the epoch the block belongs to
/// and only falls back to that same fixed value once the schedule has
/// nothing to say about it (see that method's own documentation, which
/// mirrors the specification's `get_blob_parameters`). [`super::electra`]'s
/// own state projection reads and writes `latest_execution_payload_header`
/// through functions private to that module, so this instead goes through
/// [`fulu_state_ref`] and [`fulu_state`], the same projection
/// [`crate::helpers::fulu::get_beacon_proposer_index`] already uses to reach
/// fulu's own state.
///
/// Every other step is transcribed unchanged, including not computing
/// anything from `body.execution_requests`: see
/// [`super::deneb::process_execution_payload`]'s own documentation for why
/// the versioned-hashes list, and the execution-requests list a real
/// execution client would also need, are dead weight in this crate
/// specifically. [`ExecutionEngine`] collapses the whole
/// `verify_and_notify_new_payload` interface to one boolean and never
/// inspects either, but the versioned hashes are still computed
/// unconditionally so that a future engine model with something real to
/// check against has the value ready to hand it.
pub fn process_execution_payload(
    state: &mut BeaconState,
    body: &electra::BeaconBlockBody,
    config: &Config,
    engine: &ExecutionEngine,
) -> Result<()> {
    let payload = &body.execution_payload;

    let expected_parent_hash = fulu_state_ref(state, "process_execution_payload")?
        .latest_execution_payload_header
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
    // [Modified in Fulu:EIP7892]: the schedule-aware limit rather than
    // electra's fixed `max_blobs_per_block_electra`; see this function's own
    // documentation for why the two cannot share one check.
    verify(
        body.blob_kzg_commitments.len() as u64
            <= config.max_blobs_per_block(get_current_epoch(state)),
        "len(body.blob_kzg_commitments) <= get_blob_parameters(get_current_epoch(state)).max_blobs_per_block",
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
    fulu_state(state, "process_execution_payload")?.latest_execution_payload_header = header;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BlobScheduleEntry;
    use crate::containers::bellatrix::LogsBloom;
    use crate::fork::ForkName;
    use crate::helpers::accessors::{get_current_epoch, get_randao_mix};
    use crate::preset;
    use crate::primitives::{ExecutionAddress, ExecutionBlockHash, KzgCommitment, Root, Uint256};

    /// An all-zero execution payload header, standing in for the genesis
    /// payload.
    fn empty_execution_payload_header() -> deneb::ExecutionPayloadHeader {
        deneb::ExecutionPayloadHeader {
            parent_hash: ExecutionBlockHash::zero(),
            fee_recipient: ExecutionAddress::zero(),
            state_root: Bytes32::zero(),
            receipts_root: Bytes32::zero(),
            logs_bloom: LogsBloom::try_from(vec![0u8; preset::BYTES_PER_LOGS_BLOOM])
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

    /// A fulu state with `count` fully active, full-balance validators, one
    /// epoch in (so the block-root history window already has entries), and
    /// `header` as its `latest_execution_payload_header`.
    ///
    /// A thin wrapper around the shared fork-parameterised builder, which has
    /// no header to take as a parameter, so this overrides the placeholder it
    /// builds with the one every real caller here actually wants under test.
    /// See [`crate::helpers::test_state::with_validators_at`] for the
    /// construction this and every other fork's test module used to
    /// duplicate.
    fn fulu_state_with_validators(
        count: usize,
        header: deneb::ExecutionPayloadHeader,
    ) -> BeaconState {
        let mut state = crate::helpers::test_state::with_validators_at(ForkName::Fulu, count);
        if let BeaconState::Fulu(inner) = &mut state {
            inner.latest_execution_payload_header = header;
        }
        state
    }

    /// A block body carrying `commitment_count` blob commitments and an
    /// otherwise-empty operation list, with a payload that matches `state`
    /// and `header` closely enough to pass every check in
    /// [`process_execution_payload`] except the one under test.
    fn body_with_commitments(
        state: &BeaconState,
        config: &Config,
        header: &deneb::ExecutionPayloadHeader,
        commitment_count: usize,
    ) -> electra::BeaconBlockBody {
        let payload = deneb::ExecutionPayload {
            parent_hash: header.block_hash,
            fee_recipient: ExecutionAddress::zero(),
            state_root: Bytes32::zero(),
            receipts_root: Bytes32::zero(),
            logs_bloom: LogsBloom::try_from(vec![0u8; preset::BYTES_PER_LOGS_BLOOM])
                .expect("built at exactly BYTES_PER_LOGS_BLOOM"),
            prev_randao: get_randao_mix(state, get_current_epoch(state)),
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: crate::stf::bellatrix::compute_timestamp_at_slot(
                state,
                state.slot(),
                config,
            ),
            extra_data: Default::default(),
            base_fee_per_gas: Uint256::zero(),
            block_hash: ExecutionBlockHash::repeat_byte(0xcd),
            transactions: Default::default(),
            withdrawals: Default::default(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
        };

        electra::BeaconBlockBody {
            randao_reveal: Default::default(),
            eth1_data: Default::default(),
            graffiti: Bytes32::zero(),
            proposer_slashings: Default::default(),
            attester_slashings: Default::default(),
            attestations: Default::default(),
            deposits: Default::default(),
            voluntary_exits: Default::default(),
            sync_aggregate: Default::default(),
            execution_payload: payload,
            bls_to_execution_changes: Default::default(),
            blob_kzg_commitments: vec![KzgCommitment::default(); commitment_count]
                .try_into()
                .expect("commitment_count stays well within MAX_BLOB_COMMITMENTS_PER_BLOCK here"),
            execution_requests: electra::ExecutionRequests {
                deposits: Default::default(),
                withdrawals: Default::default(),
                consolidations: Default::default(),
            },
        }
    }

    /// The one behavior fulu actually changes: a commitment count above
    /// electra's fixed ceiling but within a raised schedule entry is
    /// rejected by electra's own function and accepted by fulu's.
    ///
    /// Calls `crate::stf::electra::process_execution_payload` directly on
    /// the same fulu state, rather than building a separate electra one:
    /// that function's internal state projection already accepts a fulu
    /// state (see this file's own module docs), so this exercises the real
    /// function fulu diverges from instead of a stand-in for it.
    #[test]
    fn process_execution_payload_uses_the_schedule_aware_limit_electra_does_not() {
        let header = empty_execution_payload_header();
        let mut config = Config::minimal();
        let raised_limit = config.max_blobs_per_block_electra + 3;
        config.blob_schedule = vec![BlobScheduleEntry {
            epoch: 0,
            max_blobs_per_block: raised_limit,
        }];

        let state = fulu_state_with_validators(4, header.clone());
        let commitment_count = (config.max_blobs_per_block_electra + 1) as usize;
        let body = body_with_commitments(&state, &config, &header, commitment_count);
        let engine = ExecutionEngine::valid();

        assert!(
            crate::stf::electra::process_execution_payload(
                &mut state.clone(),
                &body,
                &config,
                &engine
            )
            .is_err(),
            "electra's own fixed ceiling must still reject a count above it"
        );
        process_execution_payload(&mut state.clone(), &body, &config, &engine)
            .expect("the schedule raised the limit above this count");
    }

    /// The schedule is a ceiling, not a suggestion: a count above even the
    /// raised limit is still rejected.
    #[test]
    fn process_execution_payload_still_rejects_more_than_the_schedule_allows() {
        let header = empty_execution_payload_header();
        let mut config = Config::minimal();
        let raised_limit = config.max_blobs_per_block_electra + 3;
        config.blob_schedule = vec![BlobScheduleEntry {
            epoch: 0,
            max_blobs_per_block: raised_limit,
        }];

        let state = fulu_state_with_validators(4, header.clone());
        let body = body_with_commitments(&state, &config, &header, (raised_limit + 1) as usize);
        let engine = ExecutionEngine::valid();

        assert!(process_execution_payload(&mut state.clone(), &body, &config, &engine).is_err());
    }

    /// With no schedule entries at all, [`Config::max_blobs_per_block`]
    /// falls back to electra's own fixed limit, so fulu's check and
    /// electra's must agree at that same boundary.
    #[test]
    fn process_execution_payload_matches_electra_when_the_schedule_is_empty() {
        let header = empty_execution_payload_header();
        let config = Config::minimal();
        assert!(config.blob_schedule.is_empty());

        let state = fulu_state_with_validators(4, header.clone());
        let engine = ExecutionEngine::valid();

        let at_limit = body_with_commitments(
            &state,
            &config,
            &header,
            config.max_blobs_per_block_electra as usize,
        );
        process_execution_payload(&mut state.clone(), &at_limit, &config, &engine)
            .expect("exactly electra's own limit must still pass with no schedule");

        let over_limit = body_with_commitments(
            &state,
            &config,
            &header,
            (config.max_blobs_per_block_electra + 1) as usize,
        );
        assert!(
            process_execution_payload(&mut state.clone(), &over_limit, &config, &engine).is_err()
        );
    }
}
