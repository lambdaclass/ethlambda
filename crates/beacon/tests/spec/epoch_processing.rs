//! The `epoch_processing` runner.
//!
//! Each handler names one step of epoch processing and each case runs that step
//! alone against a `pre` state. Testing the steps in isolation is what makes a
//! failure here diagnostic: the `sanity` and `finality` suites run whole blocks,
//! so a wrong rounding in one step surfaces there as an opaque state root
//! mismatch, while here it names the step.

use ethlambda_beacon::ForkName;
use ethlambda_beacon::config::Config;
use ethlambda_beacon::containers::BeaconState;
use ethlambda_beacon::stf::epoch;

use super::{Case, PRESET, Report, collect_all_handlers};

/// Runs the single epoch-processing step the handler names.
fn apply(handler: &str, state: &mut BeaconState, config: &Config) -> Result<(), String> {
    let outcome = match handler {
        "justification_and_finalization" => {
            epoch::justification::process_justification_and_finalization(state, config)
        }
        "rewards_and_penalties" => epoch::rewards::process_rewards_and_penalties(state, config),
        "registry_updates" => epoch::registry::process_registry_updates(state, config),
        "slashings" => epoch::registry::process_slashings(state, config),
        "eth1_data_reset" => epoch::process_eth1_data_reset(state),
        "effective_balance_updates" => epoch::process_effective_balance_updates(state),
        "slashings_reset" => epoch::process_slashings_reset(state),
        "randao_mixes_reset" => epoch::process_randao_mixes_reset(state),
        "historical_roots_update" => epoch::process_historical_roots_update(state),
        "participation_record_updates" => epoch::process_participation_record_updates(state),
        other => return Err(format!("unhandled epoch step `{other}`")),
    };

    outcome.map_err(|err| format!("{err:?}"))
}

#[test]
fn epoch_processing() {
    let mut report = Report::new();
    let config = Config::active();
    let mut skipped = 0usize;

    for (handler, case) in collect_all_handlers(PRESET, "epoch_processing") {
        if case.fork != ForkName::Phase0 {
            skipped += 1;
            continue;
        }

        let mut state = BeaconState::from_ssz(case.fork, &case.ssz_bytes("pre"))
            .expect("the fixture's pre-state decodes");

        let outcome = apply(&handler, &mut state, &config);
        report.record(&case, super::check_transition(&case, outcome, &state));
    }

    if skipped > 0 {
        println!("epoch_processing: {skipped} cases skipped, from forks after phase0");
    }

    report.finish("epoch_processing");
}

/// Handlers the fixture release ships that this runner does not dispatch.
///
/// A missing arm in `apply` would otherwise be reported per case as a failure,
/// which is correct but noisy. This asserts the set of handlers is the one the
/// runner knows about, so a fixture release that adds a step fails here, once,
/// with a clear message.
#[test]
fn every_shipped_handler_is_dispatched() {
    let known = [
        "justification_and_finalization",
        "rewards_and_penalties",
        "registry_updates",
        "slashings",
        "eth1_data_reset",
        "effective_balance_updates",
        "slashings_reset",
        "randao_mixes_reset",
        "historical_roots_update",
        "participation_record_updates",
    ];

    let mut unknown: Vec<String> = collect_all_handlers(PRESET, "epoch_processing")
        .into_iter()
        .filter(|(_, case): &(String, Case)| case.fork == ForkName::Phase0)
        .map(|(handler, _)| handler)
        .filter(|handler| !known.contains(&handler.as_str()))
        .collect();
    unknown.sort_unstable();
    unknown.dedup();

    assert!(
        unknown.is_empty(),
        "the fixture release ships phase0 epoch steps this runner does not dispatch: {unknown:?}"
    );
}
