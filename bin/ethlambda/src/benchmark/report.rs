//! Statistics and report emission for the block-building benchmark.
//!
//! Raw per-iteration samples are always included in the JSON report: outliers
//! are never discarded (XMSS signing and OTS window advancement produce
//! legitimate heavy tails worth inspecting), and per-iteration block roots let
//! a baseline-vs-optimized diff prove an optimization changed only speed, not
//! which attestations get selected.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Serialize;

use crate::version;

/// Coefficient-of-variation threshold above which wall-time results are
/// flagged as too noisy to compare, per the benchmarking workflow standard.
const CV_WARN_THRESHOLD: f64 = 0.10;

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
    /// Resolved leansig git revision from Cargo.lock. leansig is pinned to a
    /// moving branch, so results are not comparable across revisions.
    pub leansig_rev: &'static str,
    pub os: &'static str,
    pub arch: &'static str,
    pub available_parallelism: usize,
}

impl Environment {
    pub(crate) fn collect() -> Self {
        Self {
            client_version: version::CLIENT_VERSION,
            leansig_rev: env!("ETHLAMBDA_LEANSIG_REV"),
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
pub(crate) struct Stats {
    pub count: usize,
    pub min_seconds: f64,
    pub mean_seconds: f64,
    pub p50_seconds: f64,
    pub p90_seconds: f64,
    pub max_seconds: f64,
    /// Coefficient of variation (stddev / mean); NaN-free (0 when mean is 0).
    pub cv: f64,
}

#[derive(Debug, Serialize)]
pub(crate) struct Summary {
    pub phases: BTreeMap<String, Stats>,
    pub overhead: Stats,
    pub wall: Stats,
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
        let overhead = stats(
            &samples
                .iter()
                .map(|sample| sample.overhead_seconds)
                .collect::<Vec<_>>(),
        );
        let wall = stats(
            &samples
                .iter()
                .map(|sample| sample.wall_seconds)
                .collect::<Vec<_>>(),
        );

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
            "  {} leansig={} os={} arch={} threads={}",
            env.client_version, env.leansig_rev, env.os, env.arch, env.available_parallelism
        );
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

fn format_ms(seconds: f64) -> String {
    format!("{:.3}ms", seconds * 1e3)
}

fn stats(values: &[f64]) -> Stats {
    if values.is_empty() {
        return Stats {
            count: 0,
            min_seconds: 0.0,
            mean_seconds: 0.0,
            p50_seconds: 0.0,
            p90_seconds: 0.0,
            max_seconds: 0.0,
            cv: 0.0,
        };
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let count = sorted.len();
    let mean = sorted.iter().sum::<f64>() / count as f64;
    let variance = sorted
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / count as f64;
    let cv = if mean > 0.0 {
        variance.sqrt() / mean
    } else {
        0.0
    };
    Stats {
        count,
        min_seconds: sorted[0],
        mean_seconds: mean,
        p50_seconds: percentile(&sorted, 0.50),
        p90_seconds: percentile(&sorted, 0.90),
        max_seconds: sorted[count - 1],
        cv,
    }
}

/// Nearest-rank percentile over a sorted slice (no interpolation; sample
/// counts are small so exact sample values are preferable to blends).
fn percentile(sorted: &[f64], q: f64) -> f64 {
    let index = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_handles_single_sample() {
        let sorted = [7.0];
        assert_eq!(percentile(&sorted, 0.0), 7.0);
        assert_eq!(percentile(&sorted, 0.5), 7.0);
        assert_eq!(percentile(&sorted, 1.0), 7.0);
    }

    #[test]
    fn percentile_odd_and_even_lengths() {
        let odd = [1.0, 2.0, 3.0, 4.0, 5.0];
        assert_eq!(percentile(&odd, 0.5), 3.0);
        assert_eq!(percentile(&odd, 1.0), 5.0);
        let even = [1.0, 2.0, 3.0, 4.0];
        assert_eq!(percentile(&even, 0.5), 3.0);
        assert_eq!(percentile(&even, 0.0), 1.0);
    }

    #[test]
    fn stats_on_known_values() {
        let stats = stats(&[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]);
        assert_eq!(stats.count, 8);
        assert_eq!(stats.min_seconds, 2.0);
        assert_eq!(stats.max_seconds, 9.0);
        assert_eq!(stats.mean_seconds, 5.0);
        // population stddev of this classic set is 2.0 => cv = 0.4
        assert!((stats.cv - 0.4).abs() < 1e-12);
    }

    #[test]
    fn stats_on_empty_input_is_zeroed() {
        let stats = stats(&[]);
        assert_eq!(stats.count, 0);
        assert_eq!(stats.mean_seconds, 0.0);
        assert_eq!(stats.cv, 0.0);
    }
}
