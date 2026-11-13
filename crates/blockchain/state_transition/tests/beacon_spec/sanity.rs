//! The `sanity`, `finality`, and `random` runners.
//!
//! All three have the same shape, so they share one implementation: a `pre`
//! state, a sequence of blocks, and a `post` state, with the absence of `post`
//! meaning some block in the sequence must be rejected. They differ only in what
//! they choose to exercise, which is the whole point of keeping them separate
//! upstream: `finality` drives the four finalization rules, `random` drives
//! pseudo-random operation mixes, and `sanity` covers the ordinary cases.
//!
//! `sanity/slots` is the exception, advancing slots with no blocks at all, which
//! is what isolates epoch processing from block processing.
//!
//! Unlike the `operations` suite, these run the full [`state_transition`], so
//! they check the proposer signature and the committed `state_root` too.

use ethlambda_state_transition::beacon::ForkName;
use ethlambda_state_transition::beacon::config::Config;
use ethlambda_state_transition::beacon::containers::{BeaconState, SignedBeaconBlock};
use ethlambda_state_transition::beacon::helpers::accessors::{ActiveBalanceCache, CommitteeCache};
use ethlambda_state_transition::beacon::stf::{self, ExecutionEngine};
use libtest_mimic::Trial;

use super::{Case, PRESET, collect};

#[derive(serde::Deserialize)]
struct BlocksMeta {
    blocks_count: usize,
}

/// Applies every block in the case, stopping at the first one rejected.
///
/// With `warm`, the shuffling's committee key sums are built before each block,
/// from the state it applies to, the way the node's epoch precompute worker
/// builds them ahead of the epoch's first block. A fresh cache would otherwise
/// only ever run the attestation key builder's cold branch.
fn apply_blocks(
    case: &Case,
    state: &mut BeaconState,
    config: &Config,
    warm: bool,
) -> Result<(), String> {
    let meta: BlocksMeta = case.yaml("meta");

    // `sanity/blocks`, `finality`, and `random` ship no `execution.yaml`
    // (unlike the fork suites from bellatrix on that exercise
    // `notify_new_payload`), so there is no engine answer to read from the
    // case. A valid engine is the right default here: these cases are
    // testing consensus-layer rules, not execution-payload rejection, so an
    // engine that never objects keeps that variable out of the result.
    let engine = ExecutionEngine::valid();

    // Cache the previous block's state root the way `fork_choice::on_block`
    // does, so every multi-block case drives `BeaconState::compute_state_root`'s
    // cached arm and the `post` comparison proves it changes nothing. Applied
    // before the next block and never after the last, so what
    // `check_transition` hashes is the specification's own state.
    let mut previous_state_root = None;

    // One cache across the case's blocks, as the node holds one across its
    // imports, so consecutive blocks of an epoch share its shuffling.
    let committees = CommitteeCache::default();
    let active_balances = ActiveBalanceCache::default();

    for index in 0..meta.blocks_count {
        let bytes = case.ssz_bytes_indexed("blocks", index);
        let block = SignedBeaconBlock::from_ssz(case.fork, &bytes)
            .map_err(|err| format!("block {index} does not decode: {err:?}"))?;

        if let Some(root) = previous_state_root.take() {
            state.latest_block_header_mut().state_root = root;
        }

        if warm {
            super::warm_key_sums_around(&committees, state);
        }

        stf::state_transition(
            state,
            &block,
            true,
            config,
            &engine,
            &committees,
            &active_balances,
        )
        .map_err(|err| format!("block {index} rejected: {err:?}"))?;

        previous_state_root = Some(block.state_root());
    }

    Ok(())
}

/// Advances the state by the case's slot count, applying no blocks.
fn apply_slots(case: &Case, state: &mut BeaconState, config: &Config) -> Result<(), String> {
    // `slots.yaml` holds a bare integer, and it is a count to advance BY, not a
    // slot to advance TO.
    let count: u64 = case.yaml("slots");
    let target = state.slot() + count;
    stf::process_slots(state, target, config).map_err(|err| format!("{err:?}"))
}

/// Builds one runner and handler pair's trials, since all four share this shape.
fn run(runner: &str, handler: &str, slots: bool) -> Vec<Trial> {
    let cases = collect(PRESET, runner, handler);
    let mut trials = vec![super::discovery_trial(runner, cases.len())];

    for case in cases {
        trials.push(super::case_trial(runner, case, move |case| {
            let mut state = BeaconState::from_ssz(case.fork, &case.ssz_bytes("pre"))
                .map_err(|err| format!("the fixture's pre-state does not decode: {err:?}"))?;
            let config = super::case_config(case);

            if slots {
                let outcome = apply_slots(case, &mut state, &config);
                return super::check_transition(case, outcome, &state);
            }

            // Electra and later pick an attestation's aggregate key from
            // warmed committee key sums when there are any, so those cases run
            // a second time with the sums built. Both runs must reach the same
            // verdict and the same post-state.
            if case.fork >= ForkName::Electra {
                let mut warm_state = state.clone();
                let warm = apply_blocks(case, &mut warm_state, &config, true);
                let cold = apply_blocks(case, &mut state, &config, false);
                if warm != cold {
                    return Err(format!(
                        "the warm-sums run answered {warm:?} where the cold run answered {cold:?}"
                    ));
                }
                super::check_transition(case, warm, &warm_state)
                    .map_err(|err| format!("warm sums: {err}"))?;
                return super::check_transition(case, cold, &state);
            }
            let outcome = apply_blocks(case, &mut state, &config, false);
            super::check_transition(case, outcome, &state)
        }));
    }

    trials
}

pub fn trials() -> Vec<Trial> {
    let mut trials = run("sanity", "blocks", false);
    trials.extend(run("sanity", "slots", true));
    trials.extend(run("finality", "finality", false));
    trials.extend(run("random", "random", false));
    trials
}
