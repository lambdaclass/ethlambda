//! What leanVM's prover does on this machine (`ethlambda pq-prover-check`).
//!
//! On a network that schedules the PQ fork, the node proves each of its
//! aggregators' committees between that seat's cutoff and its broadcast: the
//! difference of `AGGREGATE_DUE_BPS_PQ` and `AGGREGATION_CUTOFF_BPS`, 2.4 s of
//! a 12-second slot. leanVM makes one proof at a time, so a proof that does
//! not fit is an aggregate that is never broadcast. How long one takes
//! depends on the host: its cores, and which instructions its CPU has that
//! the build can use.
//!
//! This starts the prover as the node does, proves and verifies an aggregate
//! of as many signatures as asked, a few times over, and reports what each
//! round took against that budget. It touches no network and no data
//! directory, so it answers before a devnet's genesis rather than at its
//! first aggregation duty.

use std::time::Duration;

use ethlambda_crypto::stark::leanvm::{
    LEANVM_REV, LeanVmBackend, LeanVmConfig, MAX_SELF_CHECK_SIGNATURES,
};
use ethlambda_types::beacon::config::Config;
use eyre::WrapErr as _;
use tracing::{info, warn};

#[derive(Debug, clap::Args)]
pub(crate) struct PqProverCheckOptions {
    /// How many signatures one aggregate proves: the attesters of one
    /// committee.
    #[arg(
        long,
        default_value_t = 128,
        value_parser = clap::value_parser!(u32).range(1..=i64::from(MAX_SELF_CHECK_SIGNATURES))
    )]
    signatures: u32,

    /// How many threads leanVM's prover runs on, 0 for one per core: the
    /// node's `--pq-prover-threads`.
    #[arg(long, default_value_t = 0)]
    threads: usize,

    /// How many times to prove. The first round pays for whatever the prover
    /// sets up on first use.
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u32).range(1..))]
    rounds: u32,
}

pub(crate) fn run(options: PqProverCheckOptions) -> eyre::Result<()> {
    let config = LeanVmConfig {
        threads: options.threads,
        ..LeanVmConfig::default()
    };
    let backend = LeanVmBackend::setup(config).wrap_err("cannot start leanVM's prover")?;
    let signatures = options.signatures as usize;
    let rounds = backend
        .measure(signatures, options.rounds as usize)
        .wrap_err("leanVM's prover failed")?;

    let budget = seat_budget(&Config::mainnet());
    for (round, check) in rounds.iter().enumerate() {
        info!(
            round = round + 1,
            signatures,
            prove_ms = check.prove.as_millis() as u64,
            verify_ms = check.verify.as_millis() as u64,
            proof_bytes = check.proof_bytes,
            "Proved and verified an aggregate"
        );
    }
    let slowest = rounds
        .iter()
        .map(|check| check.prove)
        .max()
        .unwrap_or_default();
    let (slowest_ms, budget_ms) = (slowest.as_millis() as u64, budget.as_millis() as u64);
    if slowest < budget {
        info!(
            signatures,
            slowest_ms,
            budget_ms,
            leanvm_rev = LEANVM_REV,
            "One aggregate of this size fits a seat's proving window on a 12-second slot"
        );
    } else {
        warn!(
            signatures,
            slowest_ms,
            budget_ms,
            leanvm_rev = LEANVM_REV,
            "One aggregate of this size does not fit a seat's proving window on a 12-second \
             slot: this host would miss its aggregates"
        );
    }
    Ok(())
}

/// How long a seat has to prove on `config`'s timing: from its cutoff to its
/// broadcast, the same for every seat.
fn seat_budget(config: &Config) -> Duration {
    let bps = config
        .aggregate_due_bps_pq
        .saturating_sub(config.aggregation_cutoff_bps);
    Duration::from_millis(bps.saturating_mul(config.slot_duration_ms) / 10_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PQ `validator.md`'s 12-second example: a seat stops collecting at 4.8 s
    /// and broadcasts at 7.2 s.
    #[test]
    fn a_seat_has_the_cutoff_to_broadcast_window_to_prove_in() {
        assert_eq!(
            seat_budget(&Config::mainnet()),
            Duration::from_millis(2_400)
        );
    }
}
