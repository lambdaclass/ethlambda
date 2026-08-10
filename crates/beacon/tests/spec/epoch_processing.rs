//! The `epoch_processing` runner.
//!
//! Each handler names one step of epoch processing and each case runs that step
//! alone against a `pre` state. Testing the steps in isolation is what makes a
//! failure here diagnostic: the `sanity` and `finality` suites run whole blocks,
//! so a wrong rounding in one step surfaces there as an opaque state root
//! mismatch, while here it names the step.
//!
//! Altair keeps most of phase0's steps unchanged (`registry_updates`,
//! `slashings`, and the four resets, plus `historical_roots_update`, which does
//! not become `historical_summaries_update` until capella) and replaces two
//! outright: `justification_and_finalization` now reads participation flags
//! instead of replaying `PendingAttestation`s, and `rewards_and_penalties` scores
//! those same flags instead of the five phase0 delta components. It also adds
//! three steps of its own (`inactivity_updates`, `participation_flag_updates`,
//! `sync_committee_updates`) that have no phase0 handler at all, so [`apply`]
//! matches on `(handler, fork)` rather than on the handler name alone wherever a
//! handler's function actually differs between the two.
//!
//! Later forks split further along that same `(handler, fork)` axis, and each
//! boundary below is transcribed from `beacon-chain.md`'s own "Modified in
//! <fork>" markers rather than assumed:
//!
//! - `registry_updates`: deneb's own change (EIP-7514's activation-churn cap)
//!   is selected internally, by fork, inside `registry::process_registry_updates`
//!   itself, so phase0 through deneb still share one call here. Electra
//!   rewrites the function outright around a balance budget instead of a
//!   per-epoch headcount, and fulu never revives the older rule, so both route
//!   to electra's version instead.
//! - `effective_balance_updates`: phase0 through deneb round every validator
//!   toward the one ceiling every validator shared before EIP-7251. Electra's
//!   version reads a per-validator ceiling instead, since a compounding
//!   validator's can be far higher, and fulu never reverts that, so both route
//!   to electra's version too.
//! - `historical_roots_update` becomes `historical_summaries_update`, a
//!   different handler name rather than a different fork's version of this
//!   one, starting at capella.
//! - Electra adds `pending_deposits` and `pending_consolidations`, with no
//!   earlier-fork counterpart at all; fulu carries both forward unchanged and
//!   adds `proposer_lookahead` of its own, likewise with no earlier-fork
//!   counterpart.

use std::sync::Arc;

use ethlambda_beacon::ForkName;
use ethlambda_beacon::config::Config;
use ethlambda_beacon::containers::BeaconState;
use ethlambda_beacon::stf::epoch;
use libtest_mimic::{Failed, Trial};

use super::{Case, PRESET, collect_all_handlers};

/// Runs the single epoch-processing step the handler names.
fn apply(
    handler: &str,
    fork: ForkName,
    state: &mut BeaconState,
    config: &Config,
) -> Result<(), String> {
    let outcome = match handler {
        // `epoch::process_justification_and_finalization` dispatches on
        // `state.fork_name()` itself, unlike `rewards_and_penalties` below,
        // which has no such wrapper yet: calling it here rather than reaching
        // into `epoch::justification` (phase0-only) or `epoch::altair`
        // directly is what keeps this arm correct as later forks add their
        // own justification changes, with no edit needed here when they do.
        "justification_and_finalization" => {
            epoch::process_justification_and_finalization(state, config)
        }
        // Altair rewrites this to score participation flags instead of
        // replaying `PendingAttestation`s. No later fork's `beacon-chain.md`
        // touches it again: bellatrix, capella, deneb, electra, and fulu each
        // call it straight through as part of reusing altair's larger driver
        // (see each fork module's own doc), so altair's version serves
        // everything from altair on, the same boundary
        // `process_justification_and_finalization` above already encodes for
        // its own step.
        "rewards_and_penalties" => match fork {
            ForkName::Phase0 => epoch::rewards::process_rewards_and_penalties(state, config),
            _ => epoch::altair::process_rewards_and_penalties(state, config),
        },
        // Deneb's own change (EIP-7514's activation-churn cap) is selected
        // internally, by fork, inside `process_registry_updates` itself, so
        // phase0 through deneb share one call here. Electra replaces the
        // function outright with a balance-budget version, and fulu never
        // revives the validator-count rule after that, so both route to
        // electra's instead: the shared function refuses to run for either on
        // purpose (`Error::UnsupportedForFork`), rather than silently applying
        // deneb's superseded rule, so routing them here would fail loudly, not
        // incorrectly.
        "registry_updates" => match fork {
            ForkName::Electra | ForkName::Fulu => {
                epoch::electra::process_registry_updates(state, config)
            }
            _ => epoch::registry::process_registry_updates(state, config),
        },
        // Altair's and bellatrix's own changes here are scoped to the
        // proportional multiplier `registry::process_slashings` already selects
        // by fork through `preset::retuned`, so one copy serves them. Electra is
        // different: it restructures the division itself, dividing the adjusted
        // slashing balance by the increment count once and multiplying per
        // validator, rather than dividing by the total balance per validator and
        // multiplying by the increment at the end. Those disagree under integer
        // rounding, so electra and fulu need their own function, not just their
        // own constant.
        "slashings" => match fork {
            ForkName::Electra | ForkName::Fulu => epoch::electra::process_slashings(state, config),
            _ => epoch::registry::process_slashings(state, config),
        },
        "eth1_data_reset" => epoch::process_eth1_data_reset(state),
        // Phase0 through deneb round each validator toward the single ceiling
        // every validator shared before EIP-7251. Electra's version instead
        // reads a per-validator ceiling (`get_max_effective_balance`), since a
        // compounding validator's can be far higher, and fulu never reverts
        // that, so both route to electra's.
        "effective_balance_updates" => match fork {
            ForkName::Electra | ForkName::Fulu => {
                epoch::electra::process_effective_balance_updates(state)
            }
            _ => epoch::process_effective_balance_updates(state),
        },
        "slashings_reset" => epoch::process_slashings_reset(state),
        "randao_mixes_reset" => epoch::process_randao_mixes_reset(state),
        // Still `historical_roots_update` through bellatrix; the specification
        // renames this to `historical_summaries_update` starting at capella,
        // which is a different handler name, not a different fork's version
        // of this one.
        "historical_roots_update" => epoch::process_historical_roots_update(state),
        // New in capella, replacing `historical_roots_update` above, and
        // carried unchanged through every later fork: `historical_summaries_mut`
        // itself accepts capella, deneb, electra, and fulu states alike (see
        // its own doc for why), so one call here serves all four.
        "historical_summaries_update" => epoch::capella::process_historical_summaries_update(state),
        // Phase0 only: altair replaces the backlog this replays with
        // participation flags, which have no epoch-end "roll the backlog
        // over" step of their own to speak of here (see
        // `participation_flag_updates` below).
        "participation_record_updates" => epoch::process_participation_record_updates(state),
        // New in altair; no phase0 case ever reaches these, and no later
        // fork's own `process_epoch` redefines any of the three (each calls
        // straight through to `epoch::altair`, per its own module doc), so one
        // call per handler serves every fork that has it.
        "inactivity_updates" => epoch::altair::process_inactivity_updates(state, config),
        "participation_flag_updates" => epoch::altair::process_participation_flag_updates(state),
        "sync_committee_updates" => epoch::altair::process_sync_committee_updates(state),
        // New in electra (EIP-7251); fulu carries both pending queues forward
        // unchanged, calling the very same functions (see
        // `electra::process_epoch`'s own doc for why fulu's driver needs no
        // rewrite of either).
        "pending_deposits" => epoch::electra::process_pending_deposits(state, config),
        "pending_consolidations" => epoch::electra::process_pending_consolidations(state, config),
        // New in fulu (EIP-7917); no earlier fork has this handler at all.
        "proposer_lookahead" => epoch::fulu::process_proposer_lookahead(state),
        other => return Err(format!("unhandled epoch step `{other}`")),
    };

    outcome.map_err(|err| format!("{err:?}"))
}

pub fn trials() -> Vec<Trial> {
    let config = Arc::new(Config::active());
    let cases = collect_all_handlers(PRESET, "epoch_processing");
    let mut trials = vec![super::discovery_trial("epoch_processing", cases.len())];

    for (handler, case) in cases {
        let config = Arc::clone(&config);
        trials.push(super::case_trial("epoch_processing", case, move |case| {
            let mut state = BeaconState::from_ssz(case.fork, &case.ssz_bytes("pre"))
                .map_err(|err| format!("the fixture's pre-state does not decode: {err:?}"))?;

            let outcome = apply(&handler, case.fork, &mut state, &config);
            super::check_transition(case, outcome, &state)
        }));
    }

    trials.push(every_shipped_handler_is_dispatched());

    trials
}

/// Builds the trial checking that every handler the fixture release ships is
/// dispatched by [`apply`].
///
/// A missing arm in `apply` would otherwise be reported per case as a failure,
/// which is correct but noisy. This checks the set of handlers is the one the
/// runner knows about, so a fixture release that adds a step fails here, once,
/// with a clear message. The list is flat across forks (it does not say which
/// handler belongs to which fork) because that is exactly what [`apply`]'s
/// `(handler, fork)` match already encodes and enforces at run time; duplicating
/// it here would only give the two a chance to drift apart.
///
/// Built with [`Trial::test`] directly rather than [`super::case_trial`],
/// since it checks the whole handler set rather than one fixture case.
fn every_shipped_handler_is_dispatched() -> Trial {
    Trial::test(
        "epoch_processing/every_shipped_handler_is_dispatched",
        || {
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
                "historical_summaries_update",
                "participation_record_updates",
                "inactivity_updates",
                "participation_flag_updates",
                "sync_committee_updates",
                "pending_deposits",
                "pending_consolidations",
                "proposer_lookahead",
            ];

            let mut unknown: Vec<String> = collect_all_handlers(PRESET, "epoch_processing")
                .into_iter()
                .filter(|(_, case): &(String, Case)| case.in_scope())
                .map(|(handler, _)| handler)
                .filter(|handler| !known.contains(&handler.as_str()))
                .collect();
            unknown.sort_unstable();
            unknown.dedup();

            if !unknown.is_empty() {
                return Err(Failed::from(format!(
                    "the fixture release ships epoch steps this runner does not dispatch: {unknown:?}"
                )));
            }

            Ok(())
        },
    )
}
