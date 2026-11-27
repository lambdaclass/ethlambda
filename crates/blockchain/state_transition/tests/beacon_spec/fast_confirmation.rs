//! The `fast_confirmation` runner: the Fast Confirmation Rule
//! (`beacon::fast_confirmation`), against consensus-specs' own vectors
//! (`tests/formats/fast_confirmation/README.md`), first shipped in
//! v1.7.0-beta.5.
//!
//! The format is the `fork_choice` runner's plus the rule's variables in some
//! of its `checks` steps, so the cases run through that runner's
//! [`super::fork_choice::run_case`], which runs `on_fast_confirmation` where
//! such a step says the generator did.
//!
//! Every v1.7.0-beta.5 case is generated with BLS ignored (`bls_setting: 2`):
//! its blocks and attestations carry stub signatures that are not curve
//! points. Signature checks are never switched off here, so each such case is
//! reported as ignored, by name, rather than run; a release that ships signed
//! vectors runs without a change. Do not add a feature or switch to skip
//! signature checks so these can run: it could easily end up skipping checks
//! in a production build (see the `ethlambda_crypto::bls` module doc).
//!
//! The release ships these for the minimal preset only, so the mainnet tree
//! contributes no trial at all, not even the empty-suite check.

use libtest_mimic::Trial;

use super::{collect_all_handlers, preset};

pub fn trials() -> Vec<Trial> {
    if preset() != "minimal" {
        return Vec::new();
    }
    let cases = collect_all_handlers(preset(), "fast_confirmation");
    let mut trials = vec![super::discovery_trial("fast_confirmation", cases.len())];

    for (_handler, case) in cases {
        let unsigned = super::fork_choice::bls_ignored(&case);
        let trial = super::case_trial("fast_confirmation", case, |case| {
            super::fork_choice::run_case(case, &super::case_config(case))
        });
        // `case_trial` already ignores a fork past the implemented one.
        trials.push(if unsigned {
            trial.with_ignored_flag(true)
        } else {
            trial
        });
    }

    trials
}
