//! Differentially fuzzes epoch processing in isolation: decode a state, run
//! one full epoch transition on both implementations (not one step of it;
//! see `README.md`), and compare the resulting `hash_tree_root`s.
//!
//! Running a whole epoch transition rather than one step at a time, unlike
//! this crate's own `tests/spec/epoch_processing.rs`, is deliberate: that
//! fixture runner can dispatch by handler name because each fixture case
//! already names the one step it exercises, but a fuzz input carries no such
//! label, and the two implementations do not slice epoch processing into the
//! same set of named steps to match one up against.
#![no_main]

use ethlambda_beacon::containers::BeaconState;
use ethlambda_beacon::stf::epoch;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((fork, state_bytes)) = ethlambda_beacon_fuzz::split_one(data) else {
        return;
    };
    if !ethlambda_beacon_fuzz::is_implemented(fork) {
        return;
    }

    let Ok(mut our_state) = BeaconState::from_ssz(fork, state_bytes) else {
        return;
    };

    let lh_fork = ethlambda_beacon_fuzz::to_lighthouse_fork(fork);
    let lh_spec = ethlambda_beacon_fuzz::lighthouse_spec();
    let Ok(mut lh_state) =
        types::BeaconState::<ethlambda_beacon_fuzz::LhSpec>::from_ssz_bytes(state_bytes, &lh_spec)
    else {
        return;
    };
    if lh_state.fork_name(&lh_spec) != Ok(lh_fork) {
        return;
    }

    let our_config = ethlambda_beacon_fuzz::our_config();
    let our_result = epoch::process_epoch(&mut our_state, &our_config);

    // Epoch processing reads the committee and slashings caches rather than
    // building them itself; lighthouse's own `ef_tests` epoch-processing
    // cases build both before calling any step, so this mirrors that rather
    // than assuming `per_epoch_processing` is self-sufficient.
    lh_state
        .build_all_committee_caches(&lh_spec)
        .expect("a state that decoded cleanly should build its committee caches cleanly");
    lh_state
        .build_slashings_cache()
        .expect("a state that decoded cleanly should build its slashings cache cleanly");
    let lh_result = state_processing::per_epoch_processing(&mut lh_state, &lh_spec);

    match (our_result.is_ok(), lh_result.is_ok()) {
        (true, true) => {
            let our_root = our_state.hash_tree_root();
            let lh_root = lh_state
                .canonical_root()
                .expect("a state both sides just finished processing should hash cleanly");
            assert_eq!(
                our_root.0, lh_root.0,
                "ethlambda and lighthouse both completed epoch processing but landed \
                 on different post-states (fork {fork:?})"
            );
        }
        (false, false) => {
            // Both rejected; the reason may differ, which is not a finding.
        }
        (ours_ok, lh_ok) => {
            panic!(
                "ethlambda and lighthouse disagree on whether epoch processing \
                 succeeds (fork {fork:?}): ethlambda ok = {ours_ok}, lighthouse ok = \
                 {lh_ok}; ethlambda error = {our_result:?}, lighthouse error = {lh_result:?}"
            );
        }
    }
});
