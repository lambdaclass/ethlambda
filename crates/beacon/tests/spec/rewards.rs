//! The `rewards` runner.
//!
//! Unlike the other suites, these cases do not compare states. They compare
//! per-component delta vectors directly, each as a `Deltas` container of
//! rewards and penalties indexed by validator. That is a much sharper instrument
//! than a post-state comparison: `process_rewards_and_penalties` sums every
//! component into balances, so a sign error in one component and a compensating
//! error in another would produce the right balances and the wrong deltas.
//!
//! Phase0 and altair ship different components, because altair pays an
//! attestation's reward the moment it is included rather than at the epoch
//! boundary (see [`super::epoch_processing`]'s module doc for the same point
//! made about the epoch-processing steps this reward change is entangled
//! with). Phase0 ships `source_deltas`, `target_deltas`, `head_deltas`,
//! `inclusion_delay_deltas`, and `inactivity_penalty_deltas`. Altair ships the
//! same five minus `inclusion_delay_deltas`, since there is no inclusion-delay
//! reward left to isolate once inclusion itself is when the reward is paid;
//! its first three come from
//! [`altair_helpers::get_flag_index_deltas`] called once per timeliness flag
//! (source, target, head, in that order), and its `inactivity_penalty_deltas`
//! from [`altair_helpers::get_inactivity_penalty_deltas`]. [`components`]
//! below is where each fork's file list is declared, so the absence of
//! `inclusion_delay_deltas` for altair is an expected shape, not a missing
//! file to fall back from.
//!
//! Every fork's own `beacon-chain.md` was checked for a "Modified"
//! `get_flag_index_deltas` or `get_inactivity_penalty_deltas` section, since
//! either would mean altair's four-file shape stops applying somewhere past
//! it. Only bellatrix's carries one, "Modified `get_inactivity_penalty_deltas`",
//! and the change it documents is a swapped denominator constant
//! (`INACTIVITY_PENALTY_QUOTIENT_BELLATRIX` for
//! `INACTIVITY_PENALTY_QUOTIENT_ALTAIR`), not a different set of files or a
//! different function shape; capella, deneb, electra, and fulu redefine
//! neither function at all. So altair's four components, and the two helper
//! functions that produce them, serve every fork through fulu; the fixture
//! directories confirm this, shipping the same four files from altair on.

use ethlambda_beacon::ForkName;
use ethlambda_beacon::config::Config;
use ethlambda_beacon::constants::{
    TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX,
};
use ethlambda_beacon::containers::BeaconState;
use ethlambda_beacon::helpers::altair as altair_helpers;
use ethlambda_beacon::primitives::Gwei;
use ethlambda_beacon::stf::epoch::rewards;
use libssz::SszDecode;
use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::SszList;

use super::{PRESET, Report, collect_all_handlers, map_cases};

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

/// The named delta components a fork's `rewards` cases ship, in the order the
/// fixture computed them.
///
/// One place to look up "what should this fork's case directory hold," so
/// [`rewards`] itself does not have to know why the two lists differ.
fn components(
    fork: ForkName,
    state: &BeaconState,
    config: &Config,
) -> Result<Vec<(&'static str, DeltaPair)>, String> {
    let raw: Vec<(&'static str, ethlambda_beacon::Result<DeltaPair>)> = match fork {
        ForkName::Phase0 => vec![
            ("source_deltas", rewards::get_source_deltas(state, config)),
            ("target_deltas", rewards::get_target_deltas(state, config)),
            ("head_deltas", rewards::get_head_deltas(state, config)),
            (
                "inclusion_delay_deltas",
                rewards::get_inclusion_delay_deltas(state, config),
            ),
            (
                "inactivity_penalty_deltas",
                rewards::get_inactivity_penalty_deltas(state, config),
            ),
        ],
        // No `inclusion_delay_deltas` here: see this module's doc for why
        // altair has nothing left for that component to compute. Bellatrix
        // through fulu reuse this same list; see this module's doc for why
        // none of them changes it.
        ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella
        | ForkName::Deneb
        | ForkName::Electra
        | ForkName::Fulu => vec![
            (
                "source_deltas",
                altair_helpers::get_flag_index_deltas(state, TIMELY_SOURCE_FLAG_INDEX),
            ),
            (
                "target_deltas",
                altair_helpers::get_flag_index_deltas(state, TIMELY_TARGET_FLAG_INDEX),
            ),
            (
                "head_deltas",
                altair_helpers::get_flag_index_deltas(state, TIMELY_HEAD_FLAG_INDEX),
            ),
            (
                "inactivity_penalty_deltas",
                altair_helpers::get_inactivity_penalty_deltas(state, config),
            ),
        ],
    };

    raw.into_iter()
        .map(|(name, result)| {
            result
                .map(|deltas| (name, deltas))
                .map_err(|err| format!("{name}: {err:?}"))
        })
        .collect()
}

#[test]
fn rewards() {
    let mut report = Report::new();
    let config = Config::active();
    let cases = collect_all_handlers(PRESET, "rewards");

    let outcomes = map_cases(&cases, |(_handler, case)| {
        if !case.in_scope() {
            return None;
        }

        let state = BeaconState::from_ssz(case.fork, &case.ssz_bytes("pre"))
            .expect("the fixture's pre-state decodes");

        Some((|| {
            for (name, computed) in components(case.fork, &state, &config)? {
                let bytes = case.ssz_bytes(name);
                let expected = Deltas::from_ssz_bytes(&bytes)
                    .map_err(|err| format!("{name} does not decode: {err:?}"))?;
                compare(name, &expected, &computed)?;
            }

            Ok(())
        })())
    });

    for ((_, case), outcome) in cases.iter().zip(outcomes) {
        report.record_or_skip(case, outcome);
    }

    report.finish("rewards");
}
