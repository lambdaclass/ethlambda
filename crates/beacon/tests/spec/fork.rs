//! The `fork` runner, handler `fork`.
//!
//! Each case ships a `pre` state in the *previous* fork's shape and a `post`
//! state in the *new* fork's shape, with no block: the case is purely a check
//! of the irregular state change itself. `case.fork` names the target fork
//! (the directory this crate's harness walks is `tests/<config>/<fork>/...`,
//! where `<fork>` is the one the case upgrades *to*), matching every case's
//! `meta.yaml`, which carries the same name under its own `fork` key.
//!
//! Only altair's cases are runnable so far, since [`ethlambda_beacon::upgrade`]
//! implements only the phase0-to-altair upgrade. Cases for later forks are
//! counted as unimplemented rather than silently skipped, the way
//! `ssz_static` counts container/fork pairs it does not decode, so a fixture
//! release that this crate has partially caught up with is never reported as
//! fully covered.
//!
//! This exercises [`ethlambda_beacon::upgrade::upgrade_state`] rather than
//! [`ethlambda_beacon::upgrade::upgrade_to_altair`] directly, so the dispatch
//! by [`ForkName`] gets fixture coverage too, not just the per-fork function
//! it delegates to.

use std::collections::BTreeSet;

use ethlambda_beacon::ForkName;
use ethlambda_beacon::config::Config;
use ethlambda_beacon::containers::BeaconState;
use ethlambda_beacon::upgrade::upgrade_state;

use super::{Case, PRESET, Report, collect};

/// Runs one case: decode `pre` in the source fork's shape, upgrade it, and
/// compare against `post` by `hash_tree_root`.
///
/// Does not go through `super::check_transition`: that helper assumes the
/// post-state has the same fork as the pre-state, which is exactly what a
/// fork-upgrade case never does, so it is reimplemented here without the
/// `has("post")` branch that a rejection-capable runner needs. Every case in
/// this handler ships a `post`; the specification's `upgrade_to_altair` has
/// no assertion that can fail on a wellformed pre-state, so there is no
/// rejection case to model.
fn fork_case(case: &Case, config: &Config) -> Result<(), String> {
    // The caller only reaches this function for `case.fork == ForkName::Altair`,
    // so `pre` is always shaped like the fork altair upgrades from: phase0.
    let pre = BeaconState::from_ssz(ForkName::Phase0, &case.ssz_bytes("pre"))
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
    let mut skipped = 0usize;
    let mut unimplemented_targets: BTreeSet<ForkName> = BTreeSet::new();

    for case in collect(PRESET, "fork", "fork") {
        if case.fork != ForkName::Altair {
            skipped += 1;
            unimplemented_targets.insert(case.fork);
            continue;
        }

        report.record(&case, fork_case(&case, &config));
    }

    if skipped > 0 {
        let targets: Vec<String> = unimplemented_targets
            .iter()
            .map(ForkName::to_string)
            .collect();
        println!(
            "fork: {skipped} cases skipped, from upgrades this crate does not implement yet: {}",
            targets.join(", ")
        );
    }

    report.finish("fork");
}
