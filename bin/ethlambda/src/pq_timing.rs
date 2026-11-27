//! What a `--pq-timing-output` run records about itself: the network, the
//! prover, and where in a slot this node does each step of PQ aggregation.
//! The export itself is `ethlambda_telemetry::pq_timing`; see
//! `docs/pq_timing.md`.

use std::path::PathBuf;
use std::time::Duration;

use ethlambda_blockchain::payload_attributes::lookahead_start;
use ethlambda_crypto::stark::{
    self,
    leanvm::{LEANVM_REV, LeanVmConfig, PROTOCOL_VERSION},
};
use ethlambda_state_transition::beacon::fork_choice::{
    get_aggregation_cutoff_ms, get_attestation_due_ms, get_pq_aggregate_due_ms,
};
use ethlambda_telemetry::pq_timing::{Prover, Run, Timing};
use ethlambda_types::beacon::{
    config::Config, fork::ForkName, preset::MIN_ATTESTATION_INCLUSION_DELAY_PQ,
};

use crate::beacon::Genesis;

/// The run for a node on `network`, recording under `output`, whose prover
/// was asked for `prover_threads` threads (0 for one per core). Call after
/// the prover is installed: the run names the backend in use.
pub(crate) fn run(
    output: PathBuf,
    network: &str,
    genesis: Genesis,
    config: &Config,
    prover_threads: usize,
) -> Run {
    let cores = std::thread::available_parallelism().map_or(1, usize::from);
    Run {
        output,
        network: network.to_string(),
        client_version: crate::version::client_version().to_string(),
        genesis_time: genesis.genesis_time,
        genesis_validators_root: genesis.genesis_validators_root.0,
        prover: Prover {
            backend: stark::backend_name(),
            leanvm_revision: LEANVM_REV,
            leanvm_protocol_version: PROTOCOL_VERSION,
            log_inv_rate: LeanVmConfig::default().log_inv_rate,
            // Left to leanVM, the count is its own: one per physical core.
            threads: (prover_threads > 0).then(|| prover_threads.min(cores)),
            threads_configured: prover_threads,
        },
        timing: timing(config),
    }
}

/// Where in a slot this node does each step, on `config`'s PQ timing: the
/// first aggregator seat's cutoff and broadcast, and when the merge ahead of
/// a proposal starts, counted from the start of its votes' slot.
fn timing(config: &Config) -> Timing {
    let ms = Duration::from_millis;
    let slot_ms = config.slot_duration_ms;
    let pq_epoch = config.fork_epoch(ForkName::Pq);
    let aggregate_due = get_pq_aggregate_due_ms(0, config);
    // A block packs votes from `MIN_ATTESTATION_INCLUSION_DELAY_PQ` slots
    // back, and its packing starts with its payload build, in the slot
    // before it.
    let slots_before_packing = MIN_ATTESTATION_INCLUSION_DELAY_PQ.saturating_sub(1);
    Timing {
        slot: ms(slot_ms),
        attestation_due: ms(get_attestation_due_ms(pq_epoch, config)),
        committee_collection: ms(get_aggregation_cutoff_ms(0, config)),
        aggregator_delay: ms(get_pq_aggregate_due_ms(1, config).saturating_sub(aggregate_due)),
        aggregate_due: ms(aggregate_due),
        initial_merge: ms(slots_before_packing.saturating_mul(slot_ms)) + lookahead_start(slot_ms),
        proposal_lag_slots: MIN_ATTESTATION_INCLUSION_DELAY_PQ,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 12-second slot: attestations due at 3 s, the first seat collects
    /// until 4.8 s and broadcasts at 7.2 s, each next seat 0.6 s later, and a
    /// block's packing starts 8 s into the slot before it, 20 s after its
    /// newest votes' slot began.
    #[test]
    fn the_timing_is_the_pq_slots_own() {
        let config = Config::mainnet()
            .with_fork_epoch(ForkName::Gloas, 0)
            .with_fork_epoch(ForkName::Eip8483, 0)
            .with_fork_epoch(ForkName::Pq, 0);
        let timing = timing(&config);
        let ms = Duration::from_millis;
        assert_eq!(timing.slot, ms(12_000));
        assert_eq!(timing.attestation_due, ms(3_000));
        assert_eq!(timing.committee_collection, ms(4_800));
        assert_eq!(timing.aggregator_delay, ms(600));
        assert_eq!(timing.aggregate_due, ms(7_200));
        assert_eq!(timing.initial_merge, ms(20_000));
        assert_eq!(timing.proposal_lag_slots, 2);
    }
}
