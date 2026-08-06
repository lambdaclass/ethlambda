//! The `rewards` runner.
//!
//! Unlike the other suites, these cases do not compare states. They compare the
//! five per-component delta vectors directly, each as a `Deltas` container of
//! rewards and penalties indexed by validator. That is a much sharper instrument
//! than a post-state comparison: `process_rewards_and_penalties` sums all five
//! components into balances, so a sign error in one component and a compensating
//! error in another would produce the right balances and the wrong deltas.

use ethlambda_beacon::ForkName;
use ethlambda_beacon::config::Config;
use ethlambda_beacon::containers::BeaconState;
use ethlambda_beacon::primitives::Gwei;
use ethlambda_beacon::stf::epoch::rewards;
use libssz::SszDecode;
use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::SszList;

use super::{PRESET, Report, collect_all_handlers};

/// One component's reward and penalty per validator, as the fixtures encode it.
///
/// Declared here rather than in the crate because the specification has no such
/// container: it is purely how the test format packages the two vectors that
/// every delta function returns as a pair.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
struct Deltas {
    rewards: SszList<Gwei, { ethlambda_beacon::preset::VALIDATOR_REGISTRY_LIMIT }>,
    penalties: SszList<Gwei, { ethlambda_beacon::preset::VALIDATOR_REGISTRY_LIMIT }>,
}

/// One delta function's output: a reward and a penalty per validator.
type DeltaPair = (Vec<Gwei>, Vec<Gwei>);

/// Compares one component against its fixture file.
fn compare(name: &str, expected: &Deltas, actual: &DeltaPair) -> Result<(), String> {
    let (rewards, penalties) = actual;

    for (label, computed, want) in [
        ("rewards", rewards, &*expected.rewards),
        ("penalties", penalties, &*expected.penalties),
    ] {
        if computed.len() != want.len() {
            return Err(format!(
                "{name} {label}: {} entries, expected {}",
                computed.len(),
                want.len()
            ));
        }
        // Report the first differing validator rather than the whole vector,
        // since a systematic error differs at every index and the first one is
        // enough to find it.
        if let Some((index, (got, want))) = computed
            .iter()
            .zip(want.iter())
            .enumerate()
            .find(|(_, (got, want))| got != want)
        {
            return Err(format!(
                "{name} {label}: validator {index} got {got}, expected {want}"
            ));
        }
    }

    Ok(())
}

#[test]
fn rewards() {
    let mut report = Report::new();
    let config = Config::active();
    let mut skipped = 0usize;

    for (_handler, case) in collect_all_handlers(PRESET, "rewards") {
        if case.fork != ForkName::Phase0 {
            skipped += 1;
            continue;
        }

        let state = BeaconState::from_ssz(case.fork, &case.ssz_bytes("pre"))
            .expect("the fixture's pre-state decodes");

        let outcome = (|| {
            let components: [(&str, ethlambda_beacon::Result<DeltaPair>); 5] = [
                ("source_deltas", rewards::get_source_deltas(&state, &config)),
                ("target_deltas", rewards::get_target_deltas(&state, &config)),
                ("head_deltas", rewards::get_head_deltas(&state, &config)),
                (
                    "inclusion_delay_deltas",
                    rewards::get_inclusion_delay_deltas(&state, &config),
                ),
                (
                    "inactivity_penalty_deltas",
                    rewards::get_inactivity_penalty_deltas(&state, &config),
                ),
            ];

            for (name, computed) in components {
                let computed = computed.map_err(|err| format!("{name}: {err:?}"))?;
                let bytes = case.ssz_bytes(name);
                let expected = Deltas::from_ssz_bytes(&bytes)
                    .map_err(|err| format!("{name} does not decode: {err:?}"))?;
                compare(name, &expected, &computed)?;
            }

            Ok(())
        })();

        report.record(&case, outcome);
    }

    if skipped > 0 {
        println!("rewards: {skipped} cases skipped, from forks after phase0");
    }

    report.finish("rewards");
}
