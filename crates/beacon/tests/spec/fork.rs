//! The `fork` runner, handler `fork`.
//!
//! Each case ships a `pre` state in the *previous* fork's shape and a `post`
//! state in the *new* fork's shape, with no block: the case is purely a check
//! of the irregular state change itself. `case.fork` names the target fork
//! (the directory this crate's harness walks is `tests/<config>/<fork>/...`,
//! where `<fork>` is the one the case upgrades *to*), matching every case's
//! `meta.yaml`, which carries the same name under its own `fork` key. The
//! source fork is not carried anywhere in the fixture beyond that: it is
//! always `ForkName::previous` of the target, since every upgrade in the
//! specification is defined from the one fork immediately before it.
//!
//! Gated on [`super::HIGHEST_IMPLEMENTED_FORK`] like every other runner, so
//! cases whose target this crate does not implement yet are counted as
//! skipped rather than silently dropped, the way `ssz_static` counts
//! container/fork pairs it does not decode. [`super::HIGHEST_IMPLEMENTED_FORK`]
//! is now fulu, and [`ethlambda_beacon::upgrade::upgrade_state`] routes every
//! fork through its own `upgrade_to_*` function, so the two agree by
//! construction all the way to fulu; the two are still checking different
//! things, though: this gate is "has this crate's state transition caught up
//! to this fork at all," which is deliberately conservative, since running a
//! fork's upgrade before its state transition exists would let this suite go
//! green on a fork nothing else here can actually process yet.
//!
//! This exercises [`ethlambda_beacon::upgrade::upgrade_state`] rather than each
//! fork's own `upgrade_to_*` function directly, so the dispatch by
//! `ForkName` gets fixture coverage too, not just the per-fork function it
//! delegates to. That is also what makes picking up a later fork here a
//! one-line change once its own `upgrade_to_*` lands: `upgrade_state` already
//! routes to it by name, so once [`super::HIGHEST_IMPLEMENTED_FORK`] moves
//! past this fork, [`fork_case`] finds its `pre` and `post` shapes on its own.

use ethlambda_beacon::config::Config;
use ethlambda_beacon::containers::BeaconState;
use ethlambda_beacon::upgrade::upgrade_state;

use super::{Case, PRESET, Report, collect, map_cases};

/// Runs one case: decode `pre` in the source fork's shape, upgrade it, and
/// compare against `post` by `hash_tree_root`.
///
/// Does not go through `super::check_transition`: that helper assumes the
/// post-state has the same fork as the pre-state, which is exactly what a
/// fork-upgrade case never does, so it is reimplemented here without the
/// `has("post")` branch that a rejection-capable runner needs. Every case in
/// this handler ships a `post`; none of the specification's `upgrade_to_*`
/// functions have an assertion that can fail on a wellformed pre-state, so
/// there is no rejection case to model.
fn fork_case(case: &Case, config: &Config) -> Result<(), String> {
    let source = case
        .fork
        .previous()
        .ok_or_else(|| format!("fork `{}` has no previous fork to upgrade from", case.fork))?;
    let pre = BeaconState::from_ssz(source, &case.ssz_bytes("pre"))
        .map_err(|err| format!("decoding the fixture's pre-state: {err:?}"))?;

    let actual =
        upgrade_state(&pre, case.fork, config).map_err(|err| format!("upgrade_state: {err}"))?;

    let expected = BeaconState::from_ssz(case.fork, &case.ssz_bytes("post"))
        .map_err(|err| format!("decoding the fixture's post-state: {err:?}"))?;

    let actual_root = actual.hash_tree_root();
    let expected_root = expected.hash_tree_root();
    if actual_root != expected_root {
        return Err(format!(
            "post-state root 0x{} != expected 0x{}",
            hex::encode(actual_root.0),
            hex::encode(expected_root.0)
        ));
    }

    Ok(())
}

#[test]
fn fork() {
    let config = Config::active();
    let mut report = Report::new();
    let cases = collect(PRESET, "fork", "fork");

    let outcomes = map_cases(&cases, |case| {
        case.in_scope().then(|| fork_case(case, &config))
    });

    for (case, outcome) in cases.iter().zip(outcomes) {
        report.record_or_skip(case, outcome);
    }

    report.finish("fork");
}
