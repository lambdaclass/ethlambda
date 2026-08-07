//! Execution-payload processing for the state transition.
//!
//! Lives in its own module so the EL integration keeps its footprint out of
//! the core STF in `lib.rs`.

use ethlambda_types::{block::Block, state::State};

use crate::Error;

/// Seconds elapsed per consensus slot.
///
/// Must stay in lock-step with `ethlambda_blockchain::MILLISECONDS_PER_SLOT`
/// (defined as `INTERVALS_PER_SLOT * MILLISECONDS_PER_INTERVAL = 5 * 800 = 4000`).
/// The blockchain crate owns the millisecond resolution (actor tick scheduling
/// reasons); STF only needs the integer-seconds form.
pub const SECONDS_PER_SLOT: u64 = 4;

/// Compute the Unix-seconds timestamp the canonical chain assigns to `slot`.
///
/// Genesis is `slot = 0`, timestamp `genesis_time`. Each subsequent slot adds
/// `SECONDS_PER_SLOT`. Mirrors the Capella spec's `compute_time_at_slot`,
/// taking `genesis_time` directly so callers without a full `State` (e.g. the
/// blockchain actor preparing `PayloadAttributes`) can share the same
/// formula as the STF.
pub fn compute_time_at_slot(genesis_time: u64, slot: u64) -> u64 {
    genesis_time + slot * SECONDS_PER_SLOT
}

/// Validate the block's execution payload and cache its header into state.
///
/// Mirrors the Capella spec's `process_execution_payload` minus the
/// `verify_and_notify_new_payload` EL roundtrip — that lands in the
/// blockchain actor in Phase 3 (`engine_newPayload` on import). The
/// `prev_randao` check is also omitted: Lean state has no randao mix yet,
/// and leanSpec hasn't defined one. The two remaining assertions are
/// purely state-internal and run cheaply:
///
///   1. `parent_hash` chains forward from the last applied payload.
///   2. `timestamp` matches `compute_time_at_slot(slot)` so proposers
///      can't backdate or forward-date blocks.
///
/// On success, caches the new payload header onto state so the next block
/// can validate against it.
pub(crate) fn process_execution_payload(state: &mut State, block: &Block) -> Result<(), Error> {
    let payload = &block.body.execution_payload;

    let expected_parent = state.latest_execution_payload_header.block_hash;
    if payload.parent_hash != expected_parent {
        return Err(Error::InvalidPayloadParentHash {
            expected: expected_parent,
            found: payload.parent_hash,
        });
    }

    let expected_timestamp = compute_time_at_slot(state.config.genesis_time, state.slot);
    if payload.timestamp != expected_timestamp {
        return Err(Error::InvalidPayloadTimestamp {
            expected: expected_timestamp,
            found: payload.timestamp,
        });
    }

    state.latest_execution_payload_header = payload.to_header();
    Ok(())
}

#[cfg(test)]
mod execution_payload_tests {
    use super::*;
    use ethlambda_types::{
        block::BlockBody, execution_payload::ExecutionPayloadV3, primitives::H256, state::Validator,
    };

    const GENESIS_TIME: u64 = 1_700_000_000;

    fn dummy_validator() -> Validator {
        Validator {
            attestation_pubkey: [0xaa; 52],
            proposal_pubkey: [0xbb; 52],
            index: 0,
        }
    }

    fn state_at_slot(slot: u64) -> State {
        let mut state = State::from_genesis(GENESIS_TIME, vec![dummy_validator()]);
        state.slot = slot;
        state
    }

    fn block_with_payload(slot: u64, payload: ExecutionPayloadV3) -> Block {
        Block {
            slot,
            proposer_index: 0,
            parent_root: H256::ZERO,
            state_root: H256::ZERO,
            body: BlockBody {
                attestations: Default::default(),
                execution_payload: payload,
            },
        }
    }

    #[test]
    fn process_execution_payload_accepts_matching_parent_and_timestamp_and_caches_header() {
        let mut state = state_at_slot(1);
        // Genesis header is all-zero, so parent_hash matches ZERO. Timestamp
        // for slot 1 = GENESIS_TIME + 4.
        let payload = ExecutionPayloadV3 {
            parent_hash: H256::ZERO,
            timestamp: GENESIS_TIME + SECONDS_PER_SLOT,
            block_hash: H256([0xab; 32]),
            ..Default::default()
        };
        let block = block_with_payload(1, payload.clone());

        process_execution_payload(&mut state, &block).expect("happy path");

        // Header is now cached and would chain forward in the next block.
        assert_eq!(
            state.latest_execution_payload_header.block_hash,
            payload.block_hash
        );
        assert_eq!(
            state.latest_execution_payload_header.timestamp,
            payload.timestamp
        );
    }

    #[test]
    fn process_execution_payload_rejects_parent_hash_mismatch() {
        let mut state = state_at_slot(1);
        let payload = ExecutionPayloadV3 {
            parent_hash: H256([0xff; 32]), // expected ZERO (genesis header.block_hash)
            timestamp: GENESIS_TIME + SECONDS_PER_SLOT,
            ..Default::default()
        };
        let block = block_with_payload(1, payload);

        let err = process_execution_payload(&mut state, &block).unwrap_err();
        assert!(
            matches!(err, Error::InvalidPayloadParentHash { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn process_execution_payload_rejects_timestamp_mismatch() {
        let mut state = state_at_slot(2);
        let payload = ExecutionPayloadV3 {
            parent_hash: H256::ZERO,
            // Off-by-one slot: expected GENESIS_TIME + 8, sending GENESIS_TIME + 4.
            timestamp: GENESIS_TIME + SECONDS_PER_SLOT,
            ..Default::default()
        };
        let block = block_with_payload(2, payload);

        let err = process_execution_payload(&mut state, &block).unwrap_err();
        assert!(
            matches!(err, Error::InvalidPayloadTimestamp { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn process_execution_payload_chains_forward_across_two_blocks() {
        // First block (slot 1): payload with block_hash = X. State caches X.
        let mut state = state_at_slot(1);
        let first_payload = ExecutionPayloadV3 {
            parent_hash: H256::ZERO,
            timestamp: GENESIS_TIME + SECONDS_PER_SLOT,
            block_hash: H256([0x11; 32]),
            ..Default::default()
        };
        let block_one = block_with_payload(1, first_payload);
        process_execution_payload(&mut state, &block_one).expect("first block");

        // Second block (slot 2): payload with parent_hash = X (the cached
        // header's block_hash). Should pass.
        state.slot = 2;
        let second_payload = ExecutionPayloadV3 {
            parent_hash: H256([0x11; 32]),
            timestamp: GENESIS_TIME + 2 * SECONDS_PER_SLOT,
            block_hash: H256([0x22; 32]),
            ..Default::default()
        };
        let block_two = block_with_payload(2, second_payload);
        process_execution_payload(&mut state, &block_two).expect("chained second block");

        assert_eq!(
            state.latest_execution_payload_header.block_hash,
            H256([0x22; 32])
        );
    }
}
