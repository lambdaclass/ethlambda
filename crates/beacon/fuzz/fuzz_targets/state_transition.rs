//! Differentially fuzzes the block-level state transition: decode a pre-state
//! and a signed block, run both implementations, and check that they agree on
//! whether to accept the block and, if both accept, on the resulting state.
//!
//! See `README.md` for the corpus's byte layout and what a disagreement here
//! means.
#![no_main]

use ethlambda_beacon::containers::{BeaconState, SignedBeaconBlock};
use ethlambda_beacon::stf;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((fork, state_bytes, block_bytes)) = ethlambda_beacon_fuzz::split_two(data) else {
        return;
    };
    if !ethlambda_beacon_fuzz::is_implemented(fork) {
        return;
    }

    // A decode failure on either side, in either implementation, is an
    // uninteresting input: the mutator has not yet produced a well-formed
    // fixture-shaped case, and that is not itself a finding. Only a
    // *disagreement* about acceptance, once both sides have something to run,
    // is.
    let Ok(mut our_state) = BeaconState::from_ssz(fork, state_bytes) else {
        return;
    };
    let Ok(our_block) = SignedBeaconBlock::from_ssz(fork, block_bytes) else {
        return;
    };

    let lh_fork = ethlambda_beacon_fuzz::to_lighthouse_fork(fork);
    let lh_spec = ethlambda_beacon_fuzz::lighthouse_spec();
    let Ok(mut lh_pre) =
        types::BeaconState::<ethlambda_beacon_fuzz::LhSpec>::from_ssz_bytes(state_bytes, &lh_spec)
    else {
        return;
    };
    let Ok(lh_block) = types::SignedBeaconBlock::<ethlambda_beacon_fuzz::LhSpec>::from_ssz_bytes(
        block_bytes,
        &lh_spec,
    ) else {
        return;
    };

    // Both implementations decoded the same bytes under the same fork; if
    // either disagrees with the fork it was asked to decode as (lighthouse
    // checks this explicitly through `fork_name`; `ethlambda_beacon` cannot
    // even express it, since `from_ssz` is handed the fork directly), the
    // input says nothing about the two state transitions and is discarded.
    if lh_pre.fork_name(&lh_spec) != Ok(lh_fork) {
        return;
    }

    let our_config = ethlambda_beacon_fuzz::our_config();
    let our_result = stf::state_transition(&mut our_state, &our_block, true, &our_config);

    lh_pre
        .build_caches(&lh_spec)
        .expect("a state that decoded cleanly should build its caches cleanly");
    let lh_result =
        ethlambda_beacon_fuzz::lighthouse_state_transition(&mut lh_pre, &lh_block, &lh_spec);

    match (our_result.is_ok(), lh_result.is_ok()) {
        (true, true) => {
            let our_root = our_state.hash_tree_root();
            let lh_root = lh_pre
                .canonical_root()
                .expect("a state both sides just finished processing should hash cleanly");
            assert_eq!(
                our_root.0, lh_root.0,
                "ethlambda and lighthouse both accepted the block but landed on \
                 different post-states (fork {fork:?})"
            );
        }
        (false, false) => {
            // Both rejected. The reason may differ (this crate's `Error`
            // variants and lighthouse's `BlockProcessingError` are not the
            // same enum and were never going to line up), and that is not a
            // finding: only whether to reject is.
        }
        (ours_ok, lh_ok) => {
            panic!(
                "ethlambda and lighthouse disagree on whether to accept the block \
                 (fork {fork:?}): ethlambda accepted = {ours_ok}, lighthouse accepted \
                 = {lh_ok}; ethlambda error = {our_result:?}, lighthouse error = {lh_result:?}"
            );
        }
    }
});
