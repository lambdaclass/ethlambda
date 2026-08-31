//! Report emission for the block-building benchmark.
//!
//! Every measured iteration is reported on its own row: outliers are never
//! discarded (XMSS signing and OTS window advancement produce legitimate heavy
//! tails worth inspecting), and the per-iteration block roots let a
//! baseline-vs-optimized diff prove an optimization changed only speed, not
//! which attestations get selected.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Serialize;

use crate::version;

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
}

#[derive(Debug, Serialize)]
pub(crate) struct Environment {
    pub client_version: &'static str,
    pub os: &'static str,
    pub arch: &'static str,
    pub available_parallelism: usize,
}

impl Environment {
    pub(crate) fn collect() -> Self {
        Self {
            client_version: version::CLIENT_VERSION,
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            available_parallelism: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(0),
        }
    }
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
pub(crate) struct Report {
    pub environment: Environment,
    pub params: Params,
    pub samples: Vec<Sample>,
}

impl Report {
    pub(crate) fn new(environment: Environment, params: Params, samples: Vec<Sample>) -> Self {
        Self {
            environment,
            params,
            samples,
        }
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
            "  {} os={} arch={} threads={}",
            env.client_version, env.os, env.arch, env.available_parallelism
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
        let _ = writeln!(out, " {:>10} {:>10} {:>12}", "overhead", "wall", "root");

        for sample in &self.samples {
            let _ = write!(out, "  {:<5}", sample.iteration);
            for phase in &phases {
                let seconds = sample.phases.get(*phase).copied().unwrap_or(0.0);
                let _ = write!(out, " {:>16}", format_ms(seconds));
            }
            let _ = writeln!(
                out,
                " {:>10} {:>10} {:>12}",
                format_ms(sample.overhead_seconds),
                format_ms(sample.wall_seconds),
                &sample.block_root[..10],
            );
        }
        out
    }
}

fn format_ms(seconds: f64) -> String {
    format!("{:.3}ms", seconds * 1e3)
}
