//! The `operations` runner.
//!
//! Each case holds a `pre` state, one operation, and a `post` state. The absence
//! of `post` is the assertion: the operation must be rejected, and a run that
//! accepts it fails. That makes this suite the crate's main check that invalid
//! input is refused rather than absorbed, so the "expected rejection" path gets
//! as much attention here as the success path.
//!
//! The handler names the operation, and the operation's file is named after the
//! handler, except `block_header`, whose input is a whole block.

use ethlambda_beacon::ForkName;
use ethlambda_beacon::config::Config;
use ethlambda_beacon::containers::{BeaconState, phase0, shared};
use ethlambda_beacon::stf::{block, operations};

use super::{Case, PRESET, Report, collect_all_handlers};

/// Applies one operation to the case's pre-state.
///
/// Returns the post-state on success. Anything the crate rejects comes back as an
/// error, which the caller compares against whether the case has a `post`.
fn apply(
    handler: &str,
    case: &Case,
    state: &mut BeaconState,
    config: &Config,
) -> Result<(), String> {
    let outcome = match handler {
        "block_header" => {
            let block: phase0::BeaconBlock = case.ssz("block");
            block::process_block_header(state, &block)
        }
        "attestation" => {
            let attestation: phase0::Attestation = case.ssz("attestation");
            operations::process_attestation(state, &attestation, config)
        }
        "attester_slashing" => {
            let slashing: phase0::AttesterSlashing = case.ssz("attester_slashing");
            operations::process_attester_slashing(state, &slashing, config)
        }
        "proposer_slashing" => {
            let slashing: shared::ProposerSlashing = case.ssz("proposer_slashing");
            operations::process_proposer_slashing(state, &slashing, config)
        }
        "deposit" => {
            let deposit: shared::Deposit = case.ssz("deposit");
            operations::process_deposit(state, &deposit, config)
        }
        "voluntary_exit" => {
            let exit: shared::SignedVoluntaryExit = case.ssz("voluntary_exit");
            operations::process_voluntary_exit(state, &exit, config)
        }
        other => return Err(format!("unhandled operation `{other}`")),
    };

    outcome.map_err(|err| format!("{err:?}"))
}

#[test]
fn operations() {
    let mut report = Report::new();
    let config = Config::active();
    let mut skipped = 0usize;

    for (handler, case) in collect_all_handlers(PRESET, "operations") {
        // Only phase0's operations are implemented so far. Later forks reshape
        // the attestation containers and add operations of their own.
        if case.fork != ForkName::Phase0 {
            skipped += 1;
            continue;
        }

        let mut state = BeaconState::from_ssz(case.fork, &case.ssz_bytes("pre"))
            .expect("the fixture's pre-state decodes");

        let outcome = apply(&handler, &case, &mut state, &config);
        report.record(&case, super::check_transition(&case, outcome, &state));
    }

    if skipped > 0 {
        println!("operations: {skipped} cases skipped, from forks after phase0");
    }

    report.finish("operations");
}
