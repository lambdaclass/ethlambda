//! Report emission for the synthetic block-building benchmark.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Serialize;

use super::common::{CV_WARN_THRESHOLD, Environment, Stats, format_ms, stats};

#[derive(Debug, Serialize)]
pub(crate) struct Sample {
    pub iteration: u64,
    pub slot: u64,
    pub proposer: u64,
    /// Determinism checksum: same seed + params must reproduce the same roots.
    pub block_root: String,
    pub wall_seconds: f64,
    /// Per-phase seconds from histogram sum deltas.
    pub phases: BTreeMap<String, f64>,
    /// Wall time not attributed to any phase: the `produce_block_with_signatures`
    /// preamble (tick advance, pool promotion, fork-choice head update, pool
    /// deep-clone, block-roots scan) plus measurement slack.
    pub overhead_seconds: f64,
    pub attestations_packed: usize,
    pub aggregates: usize,
    /// Pool entries (new + known) visible to this build; reported so pool
    /// growth across iterations is visible in the samples.
    pub pool_entries: usize,
    /// Seconds spent producing this slot's pool entries: every validator's
    /// XMSS attestation signature plus their type-1 aggregation. That is
    /// aggregator-side work a proposer never does, so it sits outside `wall`.
    /// Zero in mock mode.
    pub aggregate_seconds: f64,
    /// Seconds to import the block after the measured span; in real mode this
    /// includes verifying the merged multi-message aggregate.
    pub import_seconds: f64,
}

#[derive(Debug, Serialize)]
pub(crate) struct Params {
    pub mode: &'static str,
    pub mock_crypto: bool,
    pub num_validators: u64,
    pub warmup_slots: u64,
    pub proofs_per_data: u64,
    pub seed: u64,
    pub iterations: u64,
    pub enable_proposer_aggregation: bool,
    pub max_attestations_per_block: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct Summary {
    pub phases: BTreeMap<String, Stats>,
    pub overhead: Stats,
    pub wall: Stats,
    pub aggregate: Stats,
    pub import: Stats,
}

#[derive(Debug, Serialize)]
pub(crate) struct Report {
    pub schema_version: u32,
    pub environment: Environment,
    pub params: Params,
    pub samples: Vec<Sample>,
    pub summary: Summary,
}

impl Report {
    pub(crate) fn new(environment: Environment, params: Params, samples: Vec<Sample>) -> Self {
        let mut phases: BTreeMap<String, Stats> = BTreeMap::new();
        if let Some(first) = samples.first() {
            for phase in first.phases.keys() {
                let values: Vec<f64> = samples
                    .iter()
                    .filter_map(|sample| sample.phases.get(phase).copied())
                    .collect();
                phases.insert(phase.clone(), stats(&values));
            }
        }
        let column =
            |value: fn(&Sample) -> f64| stats(&samples.iter().map(value).collect::<Vec<_>>());
        let overhead = column(|sample| sample.overhead_seconds);
        let wall = column(|sample| sample.wall_seconds);
        let aggregate = column(|sample| sample.aggregate_seconds);
        let import = column(|sample| sample.import_seconds);

        if wall.cv > CV_WARN_THRESHOLD {
            eprintln!(
                "warning: wall-time coefficient of variation is {:.1}% (>{:.0}%); \
                 results are noisy — check for background load or increase --iterations",
                wall.cv * 100.0,
                CV_WARN_THRESHOLD * 100.0
            );
        }

        Self {
            schema_version: 1,
            environment,
            params,
            samples,
            summary: Summary {
                phases,
                overhead,
                wall,
                aggregate,
                import,
            },
        }
    }

    pub(crate) fn to_json(&self) -> eyre::Result<String> {
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    pub(crate) fn human_table(&self) -> String {
        let mut out = String::new();
        let params = &self.params;
        let env = &self.environment;
        let crypto = if params.mock_crypto { "mock" } else { "real" };
        let _ = writeln!(
            out,
            "Block-building benchmark — {} workload ({crypto} crypto)",
            params.mode
        );
        let _ = writeln!(
            out,
            "  validators={} warmup_slots={} iterations={} proofs_per_data={} seed={}",
            params.num_validators,
            params.warmup_slots,
            params.iterations,
            params.proofs_per_data,
            params.seed
        );
        let _ = writeln!(
            out,
            "  enable_proposer_aggregation={} max_attestations_per_block={}",
            params.enable_proposer_aggregation, params.max_attestations_per_block
        );
        let _ = writeln!(
            out,
            "  {} leansig={} leanvm={} os={} arch={} threads={}",
            env.client_version,
            env.leansig_rev,
            env.leanvm_rev,
            env.os,
            env.arch,
            env.available_parallelism
        );
        let _ = writeln!(out);

        // Phase columns come from the first sample: every build observes the
        // same phases, and `run_synthetic` asserts each advanced exactly once.
        let phases: Vec<&String> = match self.samples.first() {
            Some(sample) => sample.phases.keys().collect(),
            None => return out,
        };
        let _ = write!(out, "  {:<5}", "iter");
        for phase in &phases {
            let _ = write!(out, " {phase:>16}");
        }
        let _ = writeln!(
            out,
            " {:>10} {:>10} {:>10} {:>10} {:>12}",
            "overhead", "wall", "aggregate", "import", "root"
        );

        for sample in &self.samples {
            let _ = write!(out, "  {:<5}", sample.iteration);
            for phase in &phases {
                let seconds = sample.phases.get(*phase).copied().unwrap_or(0.0);
                let _ = write!(out, " {:>16}", format_ms(seconds));
            }
            let _ = writeln!(
                out,
                " {:>10} {:>10} {:>10} {:>10} {:>12}",
                format_ms(sample.overhead_seconds),
                format_ms(sample.wall_seconds),
                format_ms(sample.aggregate_seconds),
                format_ms(sample.import_seconds),
                &sample.block_root[..10],
            );
        }

        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "  {:<18} {:>5} {:>10} {:>10} {:>10} {:>10} {:>10}",
            "phase", "count", "min", "mean", "p50", "p90", "max"
        );
        for (phase, stats) in &self.summary.phases {
            let _ = writeln!(out, "{}", stats_row(phase, stats));
        }
        let _ = writeln!(out, "{}", stats_row("overhead", &self.summary.overhead));
        let _ = writeln!(out, "{}", stats_row("wall", &self.summary.wall));
        let _ = writeln!(out);
        let _ = writeln!(out, "  outside the measured span:");
        let _ = writeln!(out, "{}", stats_row("aggregate", &self.summary.aggregate));
        let _ = writeln!(out, "{}", stats_row("import", &self.summary.import));
        out
    }
}

fn stats_row(name: &str, stats: &Stats) -> String {
    format!(
        "  {:<18} {:>5} {:>10} {:>10} {:>10} {:>10} {:>10}",
        name,
        stats.count,
        format_ms(stats.min_seconds),
        format_ms(stats.mean_seconds),
        format_ms(stats.p50_seconds),
        format_ms(stats.p90_seconds),
        format_ms(stats.max_seconds),
    )
}
