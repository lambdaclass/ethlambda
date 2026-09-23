//! Byte-domain state deltas for the beacon chain.
//!
//! `state_diff.rs` beside this module is lean's own diff algorithm and stays
//! untouched: it is field-shaped, storing each `State` field verbatim or
//! omitting it (`validators` is dropped on the documented assumption that it
//! never changes; `historical_block_hashes` is regenerated from the slot gap
//! rather than stored). Lean states are small enough that a byte-delta's
//! machinery would be pure overhead there.
//!
//! A beacon validator registry breaks the `validators`-never-changes
//! assumption every epoch, so lean's [`crate::state_diff::StateDiff`] cannot
//! be reused as-is here. Rather than growing it with beacon-only,
//! length-aware handling for `validators`/`balances`/`inactivity_scores`,
//! this module works in the byte domain instead of the field domain: VCDIFF
//! (via `xdelta3`) diffs the SSZ encoding of the whole state against a base
//! state's encoding. When a variable-length SSZ list grows, every offset
//! after it shifts; VCDIFF emits a COPY at the new offset rather than the
//! byte-for-byte mismatch an xor delta would produce, so the three big
//! arrays need no special handling of their own.
//!
//! `insert_state`/`get_state` (in `store.rs`) call into this module for the
//! beacon arm: `insert_state` writes a snapshot at anchors and a
//! [`frame`]d [`encode`] otherwise, and `get_state` walks the resulting
//! chain and [`decode`]s it back, via [`unframe`].

use ethlambda_types::primitives::H256;

/// Headroom over the target's length for VCDIFF's own framing, for the case
/// where a delta is nearly as large as the target it produces (an epoch
/// boundary, where most of the state genuinely changed).
const DELTA_FRAMING_MARGIN: usize = 4096;

/// The delta taking `base` to `target`.
///
/// Uses `encode_with_output_len` rather than the crate's `encode`, which sizes
/// its output as `(input.len() + src.len()) * 2`: at beacon scale that is a
/// ~1.4 GB transient allocation per call, and the `u32` cast wraps above a
/// ~1.07 GB source. A delta is never larger than the target plus framing, so
/// the target's own length plus a margin is the real bound.
///
/// An empty target has no bytes to diff; `xd3_encode_memory` is not exercised
/// for it, so the empty delta stands in directly rather than round-tripping
/// through the C API for a case it need not see. A beacon state is never
/// empty, but a codec that panics on one is a sharp edge worth avoiding.
pub(crate) fn encode(target: &[u8], base: &[u8]) -> Vec<u8> {
    if target.is_empty() {
        return Vec::new();
    }
    let output_buffer_len = u32::try_from(target.len() + DELTA_FRAMING_MARGIN)
        .expect("target length plus margin fits a u32 at beacon scale");
    xdelta3::encode_with_output_len(target, base, output_buffer_len).unwrap_or_else(|err| {
        panic!(
            "xdelta3 encode failed against a {output_buffer_len}-byte output bound \
             (target {} bytes, margin {DELTA_FRAMING_MARGIN}): {err:?}",
            target.len()
        )
    })
}

/// The inverse of [`encode`].
///
/// `target_len` comes from the frame, so the output buffer is sized exactly
/// rather than at `(delta + base) * 2`. Panics on a delta this build cannot
/// apply: `from_db_state` has already rejected a directory of the wrong
/// format version, so anything reaching here is corruption rather than an old
/// database, which matches how every other read in this crate treats a bad
/// value.
///
/// A `target_len` of zero is [`encode`]'s empty-target case; the empty
/// output stands in directly for the same reason encode short-circuits it.
pub(crate) fn decode(delta: &[u8], base: &[u8], target_len: usize) -> Vec<u8> {
    if target_len == 0 {
        return Vec::new();
    }
    let output_buffer_len =
        u32::try_from(target_len).expect("target length fits a u32 at beacon scale");
    xdelta3::decode_with_output_len(delta, base, output_buffer_len).unwrap_or_else(|err| {
        panic!("xdelta3 decode failed against exact target length {target_len}: {err:?}")
    })
}

/// A `StateDiffs` value on the beacon arm:
/// `base_root (32) || slot (8, big-endian) || target_len (8, big-endian) || delta`.
///
/// Raw rather than SSZ, like `Metadata["chain"]` and the `States` fork tag: an
/// SSZ `ByteList` would need a bound, and an epoch-boundary delta runs to
/// megabytes, well past the `ByteList512KiB` every existing block-level byte
/// field uses. `target_len` rides along so `decode` can size its output
/// exactly.
pub(crate) fn frame(base_root: H256, slot: u64, target_len: u64, delta: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + 8 + 8 + delta.len());
    bytes.extend_from_slice(base_root.as_slice());
    bytes.extend_from_slice(&slot.to_be_bytes());
    bytes.extend_from_slice(&target_len.to_be_bytes());
    bytes.extend_from_slice(delta);
    bytes
}

/// The inverse of [`frame`].
pub(crate) fn unframe(bytes: &[u8]) -> (H256, u64, u64, &[u8]) {
    let base_root = H256::from_slice(&bytes[0..32]);
    let slot = u64::from_be_bytes(
        bytes[32..40]
            .try_into()
            .expect("frame carries an 8-byte slot"),
    );
    let target_len = u64::from_be_bytes(
        bytes[40..48]
            .try_into()
            .expect("frame carries an 8-byte target_len"),
    );
    (base_root, slot, target_len, &bytes[48..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn a_delta_round_trips() {
        let base = vec![7u8; 4096];
        let mut target = base.clone();
        target[100] = 9;
        target.extend_from_slice(&[1u8; 64]);

        let delta = encode(&target, &base);
        assert_eq!(decode(&delta, &base, target.len()), target);
    }

    #[test]
    fn a_delta_survives_an_insertion_that_shifts_everything_after_it() {
        // The case an xor delta cannot handle and VCDIFF can: a
        // variable-length SSZ list grows, so every later offset moves.
        let base: Vec<u8> = (0..8192u32).map(|i| i as u8).collect();
        let mut target = base.clone();
        target.splice(10..10, [0xffu8; 128]);

        let delta = encode(&target, &base);
        assert_eq!(decode(&delta, &base, target.len()), target);
        assert!(
            delta.len() < target.len() / 4,
            "a shift defeated the delta: {} bytes for a {} byte target",
            delta.len(),
            target.len()
        );
    }

    #[test]
    fn an_identical_target_is_nearly_all_copy() {
        // Pins that the output bound comes from the target rather than from
        // (input + src) * 2, which is what the crate's convenience wrappers
        // would ask for.
        let base = vec![1u8; 4096];
        let delta = encode(&base, &base);
        assert!(delta.len() < 512, "got {} bytes", delta.len());
        assert_eq!(decode(&delta, &base, base.len()), base);
    }

    #[test]
    fn a_frame_round_trips() {
        let base_root = H256::from([4u8; 32]);
        let framed = frame(base_root, 77, 4096, &[1, 2, 3]);
        let (root, slot, target_len, delta) = unframe(&framed);
        assert_eq!(
            (root, slot, target_len, delta),
            (base_root, 77, 4096, &[1, 2, 3][..])
        );
    }

    proptest! {
        #[test]
        fn any_delta_round_trips(
            base in prop::collection::vec(any::<u8>(), 0..8192),
            target in prop::collection::vec(any::<u8>(), 0..8192),
        ) {
            let delta = encode(&target, &base);
            prop_assert_eq!(decode(&delta, &base, target.len()), target);
        }
    }

    // -------------------------------------------------------------------
    // Mainnet-scale measurement.
    //
    // The synthetic 64 MiB probe behind the design doc's "encode cost is
    // largely retired by measurement" claim extrapolates linearly from a
    // change pattern far more structured than a real reward distribution,
    // which flatters delta *size* even though timings are less
    // shape-sensitive. This measures the real thing: an electra state at
    // mainnet's validator count, diffed across the two shapes the codec
    // actually sees (an ordinary slot, and the epoch boundary the design's
    // snapshot-interval choice hinges on).
    //
    // This repo has no `benches/` directory or bench harness; slow
    // measurements are ordinary `#[ignore]`d tests here (see
    // `crates/common/crypto/src/signature.rs`), not a criterion target.
    //
    // `ethlambda-storage` cannot take `ethlambda-state-transition` as a
    // dev-dependency to reuse its `test_state` helper: state-transition
    // already depends on storage, so the reverse would be a cycle. The
    // container types both crates build from live in `ethlambda_types`
    // regardless (state-transition's `beacon` module re-exports them), so
    // the state below is built directly from there instead.
    // -------------------------------------------------------------------

    use ethlambda_types::beacon::constants;
    use ethlambda_types::beacon::containers::{
        BeaconBlockHeader, BeaconState, Checkpoint, Validator, altair, deneb, electra,
    };
    use ethlambda_types::beacon::preset;
    use ethlambda_types::beacon::primitives::{ExecutionAddress, Uint256};

    use crate::state_codec::encode_state_value;

    /// Validators in the synthesized state. Mainnet's active set is this order of
    /// magnitude, and the codec's cost is a function of the encoded length, which
    /// this drives.
    const VALIDATOR_COUNT: usize = 2_000_000;

    /// A sync committee with every seat at its all-default (invalid-as-a-curve-
    /// point) pubkey. `ethlambda-state-transition`'s own state builder derives
    /// real BLS keys instead, because its tests exercise sync committee
    /// aggregation; this benchmark only round-trips the byte-domain codec, so a
    /// default key is enough to get the field's length right.
    fn empty_sync_committee() -> altair::SyncCommittee {
        altair::SyncCommittee {
            pubkeys: vec![Default::default(); preset::SYNC_COMMITTEE_SIZE]
                .try_into()
                .expect("built at exactly SYNC_COMMITTEE_SIZE"),
            aggregate_pubkey: Default::default(),
        }
    }

    /// A root with `n` embedded in its low bytes, so roots built from
    /// different `n` never collide and, unlike a repeated-byte fixture root,
    /// never hand xdelta3 a long run of identical bytes to exploit.
    fn root_for_index(n: u64) -> H256 {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&n.to_le_bytes());
        H256(bytes)
    }

    /// An execution payload header whose every field is derived from `slot`,
    /// matching how a real payload header is replaced wholesale every block.
    fn execution_payload_header_for_slot(slot: u64) -> deneb::ExecutionPayloadHeader {
        deneb::ExecutionPayloadHeader {
            parent_hash: root_for_index(slot),
            fee_recipient: ExecutionAddress::ZERO,
            state_root: H256::ZERO,
            receipts_root: H256::ZERO,
            logs_bloom: vec![0u8; preset::BYTES_PER_LOGS_BLOOM]
                .try_into()
                .expect("built at exactly BYTES_PER_LOGS_BLOOM"),
            prev_randao: root_for_index(slot),
            block_number: slot,
            gas_limit: 30_000_000,
            gas_used: 15_000_000,
            timestamp: slot,
            extra_data: Default::default(),
            base_fee_per_gas: Uint256::ZERO,
            block_hash: root_for_index(slot + 1),
            transactions_root: H256::ZERO,
            withdrawals_root: H256::ZERO,
            blob_gas_used: 0,
            excess_blob_gas: 0,
        }
    }

    /// A balance that grows with `index` rather than sitting at one constant.
    /// A constant fill compresses far better than a real reward distribution
    /// would and would flatter the measurement, which is the specific thing
    /// this benchmark exists to stop doing.
    fn balance_for_index(index: usize) -> u64 {
        preset::MIN_ACTIVATION_BALANCE + index as u64
    }

    /// An inactivity score that varies with `index`, for the same reason
    /// [`balance_for_index`] does.
    fn inactivity_score_for_index(index: usize) -> u64 {
        index as u64
    }

    /// An electra state at mainnet scale: `VALIDATOR_COUNT` validators,
    /// balances, participation entries and inactivity scores, and every ring
    /// buffer at its full preset length.
    ///
    /// Allocates on the order of a gigabyte once its SSZ encoding and the two
    /// mutated states built from it (see [`advance_one_slot`] and
    /// [`advance_across_epoch_boundary`]) are counted too, which is why every
    /// test that calls this is `#[ignore]`d.
    fn mainnet_scale_electra_state() -> electra::BeaconState {
        let validators: Vec<Validator> = (0..VALIDATOR_COUNT)
            .map(|_| Validator {
                effective_balance: preset::MIN_ACTIVATION_BALANCE,
                activation_eligibility_epoch: 0,
                activation_epoch: 0,
                exit_epoch: constants::FAR_FUTURE_EPOCH,
                withdrawable_epoch: constants::FAR_FUTURE_EPOCH,
                ..Default::default()
            })
            .collect();

        electra::BeaconState {
            genesis_time: 0,
            genesis_validators_root: H256::ZERO,
            // An interior slot of its epoch, well clear of a boundary, since
            // `advance_one_slot` needs a `+= 1` that does not itself cross one.
            slot: preset::SLOTS_PER_EPOCH * 2,
            fork: Default::default(),
            latest_block_header: Default::default(),
            block_roots: vec![H256::ZERO; preset::SLOTS_PER_HISTORICAL_ROOT]
                .try_into()
                .expect("the vector is built at its exact length"),
            state_roots: vec![H256::ZERO; preset::SLOTS_PER_HISTORICAL_ROOT]
                .try_into()
                .expect("the vector is built at its exact length"),
            historical_roots: Default::default(),
            eth1_data: Default::default(),
            eth1_data_votes: Default::default(),
            eth1_deposit_index: 0,
            validators: validators
                .try_into()
                .expect("VALIDATOR_COUNT is far below VALIDATOR_REGISTRY_LIMIT"),
            balances: vec![preset::MIN_ACTIVATION_BALANCE; VALIDATOR_COUNT]
                .try_into()
                .expect("VALIDATOR_COUNT is far below VALIDATOR_REGISTRY_LIMIT"),
            randao_mixes: vec![H256::ZERO; preset::EPOCHS_PER_HISTORICAL_VECTOR]
                .try_into()
                .expect("the vector is built at its exact length"),
            slashings: vec![0; preset::EPOCHS_PER_SLASHINGS_VECTOR]
                .try_into()
                .expect("the vector is built at its exact length"),
            previous_epoch_participation: vec![0u8; VALIDATOR_COUNT]
                .try_into()
                .expect("VALIDATOR_COUNT is far below VALIDATOR_REGISTRY_LIMIT"),
            // Uniform and non-zero, standing in for "everyone was timely last
            // epoch": what makes advance_across_epoch_boundary's shift of this
            // into `previous_epoch_participation` a real change rather than a
            // zero-to-zero no-op.
            current_epoch_participation: vec![0b0000_0111u8; VALIDATOR_COUNT]
                .try_into()
                .expect("VALIDATOR_COUNT is far below VALIDATOR_REGISTRY_LIMIT"),
            justification_bits: Default::default(),
            previous_justified_checkpoint: Default::default(),
            current_justified_checkpoint: Default::default(),
            finalized_checkpoint: Default::default(),
            inactivity_scores: vec![0u64; VALIDATOR_COUNT]
                .try_into()
                .expect("VALIDATOR_COUNT is far below VALIDATOR_REGISTRY_LIMIT"),
            current_sync_committee: empty_sync_committee(),
            next_sync_committee: empty_sync_committee(),
            latest_execution_payload_header: execution_payload_header_for_slot(0),
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
        }
    }

    /// What one ordinary block's transition touches: the header, one ring
    /// buffer entry each in `block_roots`/`state_roots`, a handful of
    /// balances, one slot's worth of attesters in `current_epoch_participation`,
    /// and the execution payload header. Everything else is untouched, which is
    /// the shape a per-slot delta should stay cheap against.
    fn advance_one_slot(base: &electra::BeaconState) -> electra::BeaconState {
        let mut state = base.clone();
        state.slot += 1;

        state.latest_block_header = BeaconBlockHeader {
            slot: state.slot,
            proposer_index: state.slot % VALIDATOR_COUNT as u64,
            parent_root: root_for_index(base.slot),
            state_root: H256::ZERO,
            body_root: root_for_index(state.slot),
        };

        let ring_index = (state.slot as usize) % preset::SLOTS_PER_HISTORICAL_ROOT;
        state.block_roots[ring_index] = root_for_index(state.slot);
        state.state_roots[ring_index] = root_for_index(state.slot + 1);

        // A proposer reward plus one block's worth of attesters.
        for i in 0..5 {
            let index = (i * VALIDATOR_COUNT) / 5;
            state.balances[index] = balance_for_index(index);
        }

        // One slot's attesters: one epoch's worth of committees split across
        // SLOTS_PER_EPOCH slots.
        let attesters = VALIDATOR_COUNT / preset::SLOTS_PER_EPOCH as usize;
        for participation in state.current_epoch_participation[..attesters].iter_mut() {
            *participation = 0b0000_0111;
        }

        state.latest_execution_payload_header = execution_payload_header_for_slot(state.slot);
        state
    }

    /// What a slot transition touches when it also crosses an epoch boundary:
    /// every balance and inactivity score, most validators' effective balance,
    /// both participation lists, one `randao_mixes`/`slashings` ring entry
    /// each, and all three checkpoints. This is the shape an epoch-sized
    /// snapshot interval has to survive.
    fn advance_across_epoch_boundary(base: &electra::BeaconState) -> electra::BeaconState {
        let mut state = base.clone();
        // Repositioned to the last slot of its own epoch, so the `+= 1` below
        // is a genuine epoch crossing regardless of where `base` itself sits.
        state.slot = (base.slot / preset::SLOTS_PER_EPOCH + 1) * preset::SLOTS_PER_EPOCH - 1;
        state.slot += 1;
        let epoch = state.slot / preset::SLOTS_PER_EPOCH;

        for (index, balance) in state.balances.iter_mut().enumerate() {
            *balance = balance_for_index(index);
        }
        for (index, score) in state.inactivity_scores.iter_mut().enumerate() {
            *score = inactivity_score_for_index(index);
        }

        // Most validators' effective balance moves; hysteresis means a
        // validator only updates once its real balance crosses a threshold,
        // which a minority miss in any given epoch.
        for (index, validator) in state.validators.iter_mut().enumerate() {
            if index % 997 != 0 {
                validator.effective_balance = balance_for_index(index);
            }
        }

        let zeroed_participation = vec![0u8; VALIDATOR_COUNT]
            .try_into()
            .expect("VALIDATOR_COUNT is far below VALIDATOR_REGISTRY_LIMIT");
        state.previous_epoch_participation =
            std::mem::replace(&mut state.current_epoch_participation, zeroed_participation);

        let randao_index = (epoch as usize) % preset::EPOCHS_PER_HISTORICAL_VECTOR;
        state.randao_mixes[randao_index] = root_for_index(epoch);
        let slashings_index = (epoch as usize) % preset::EPOCHS_PER_SLASHINGS_VECTOR;
        state.slashings[slashings_index] = balance_for_index(slashings_index);

        state.previous_justified_checkpoint = state.current_justified_checkpoint;
        state.current_justified_checkpoint = Checkpoint {
            epoch,
            root: root_for_index(epoch),
        };
        state.finalized_checkpoint = Checkpoint {
            epoch: epoch.saturating_sub(1),
            root: root_for_index(epoch.saturating_sub(1)),
        };

        state
    }

    /// Encodes `base` (once, by the caller) and `target`, times the delta
    /// round trip, prints the numbers under the `delta_bench` prefix so they
    /// can be pulled out of a log with `grep delta_bench`, and asserts the
    /// round trip: a benchmark that silently produced a wrong delta would be
    /// worse than none.
    fn measure_shape(shape: &str, base_bytes: &[u8], target: electra::BeaconState) {
        let target_bytes = encode_state_value(&BeaconState::Electra(target));

        let encode_start = std::time::Instant::now();
        let delta = encode(&target_bytes, base_bytes);
        let encode_elapsed = encode_start.elapsed();

        let decode_start = std::time::Instant::now();
        let round_tripped = decode(&delta, base_bytes, target_bytes.len());
        let decode_elapsed = decode_start.elapsed();

        println!(
            "delta_bench shape={shape} base_len={base_len} target_len={target_len} \
             delta_len={delta_len} encode_ms={encode_ms:.3} decode_ms={decode_ms:.3}",
            base_len = base_bytes.len(),
            target_len = target_bytes.len(),
            delta_len = delta.len(),
            encode_ms = encode_elapsed.as_secs_f64() * 1000.0,
            decode_ms = decode_elapsed.as_secs_f64() * 1000.0,
        );

        assert_eq!(
            round_tripped, target_bytes,
            "{shape}: decoded delta did not reproduce the target's encoding"
        );
    }

    #[test]
    #[ignore = "slow: synthesizes two mainnet-scale beacon states (~1 GB, minutes)"]
    fn measure_delta_cost_at_mainnet_scale() {
        let base = mainnet_scale_electra_state();
        let base_bytes = encode_state_value(&BeaconState::Electra(base.clone()));

        measure_shape("one_slot", &base_bytes, advance_one_slot(&base));
        measure_shape(
            "epoch_boundary",
            &base_bytes,
            advance_across_epoch_boundary(&base),
        );
    }
}
