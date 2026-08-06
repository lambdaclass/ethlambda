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

use ethlambda_beacon::config::Config;
use ethlambda_beacon::containers::{BeaconState, SignedBeaconBlock};
use ethlambda_beacon::stf::{self, ExecutionEngine};

use super::{Case, PRESET, Report, collect, map_cases};

#[derive(serde::Deserialize)]
struct BlocksMeta {
    blocks_count: usize,
}

/// Applies every block in the case, stopping at the first one rejected.
fn apply_blocks(case: &Case, state: &mut BeaconState, config: &Config) -> Result<(), String> {
    let meta: BlocksMeta = case.yaml("meta");

    // `sanity/blocks`, `finality`, and `random` ship no `execution.yaml`
    // (unlike the fork suites from bellatrix on that exercise
    // `notify_new_payload`), so there is no engine answer to read from the
    // case. A valid engine is the right default here: these cases are
    // testing consensus-layer rules, not execution-payload rejection, so an
    // engine that never objects keeps that variable out of the result.
    let engine = ExecutionEngine::valid();

    for index in 0..meta.blocks_count {
        let bytes = case.ssz_bytes_indexed("blocks", index);
        let block = SignedBeaconBlock::from_ssz(case.fork, &bytes)
            .map_err(|err| format!("block {index} does not decode: {err:?}"))?;

        stf::state_transition(state, &block, true, config, &engine)
            .map_err(|err| format!("block {index} rejected: {err:?}"))?;
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

/// Runs one runner and handler pair, since all four share this body.
fn run(runner: &str, handler: &str, slots: bool) {
    let mut report = Report::new();
    let config = Config::active();
    let cases = collect(PRESET, runner, handler);

    let outcomes = map_cases(&cases, |case| {
        if !case.in_scope() {
            return None;
        }

        let mut state = BeaconState::from_ssz(case.fork, &case.ssz_bytes("pre"))
            .expect("the fixture's pre-state decodes");

        let outcome = if slots {
            apply_slots(case, &mut state, &config)
        } else {
            apply_blocks(case, &mut state, &config)
        };
        Some(super::check_transition(case, outcome, &state))
    });

    for (case, outcome) in cases.iter().zip(outcomes) {
        report.record_or_skip(case, outcome);
    }

    report.finish(&format!("{runner}/{handler}"));
}

#[test]
fn sanity_blocks() {
    run("sanity", "blocks", false);
}

#[test]
fn sanity_slots() {
    run("sanity", "slots", true);
}

#[test]
fn finality() {
    run("finality", "finality", false);
}

#[test]
fn random() {
    run("random", "random", false);
}
