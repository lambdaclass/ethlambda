//! The import workload's report.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::Serialize;

use super::common::{Environment, Stats, format_ms, stats};

#[derive(Debug, Serialize)]
pub(crate) struct Params {
    pub mode: &'static str,
    pub corpus: String,
    pub network: String,
    pub anchor_block_root: String,
    pub anchor_slot: u64,
    /// Blocks imported between the anchor and `range_start` without being
    /// sampled.
    pub warmup_blocks: usize,
    pub range_start: u64,
    /// Inclusive, as `fetch --to` is.
    pub range_end: u64,
    pub blocks: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct Sample {
    pub iteration: u64,
    pub slot: u64,
    /// Determinism checksum: two runs over one corpus must produce the same
    /// roots in the same order.
    pub block_root: String,
    pub wall_seconds: f64,
    /// Per-phase seconds from `lean_block_import_phase_seconds` sum deltas.
    /// A phase that did not run is absent, not zero.
    pub phases: BTreeMap<String, f64>,
    /// `"imported"`. A run that reaches a report has no other outcome: a
    /// held or rejected block aborts it.
    pub outcome: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct Summary {
    pub phases: BTreeMap<String, Stats>,
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
        // Union over every sample's phase keys, not just the first sample's:
        // unlike a synthetic build (where every phase runs on every block), a
        // corpus block legitimately skips phases (decode, defer, parent_wait,
        // columns_wait), and which ones it skips can differ block to block.
        let mut phase_names: BTreeSet<&str> = BTreeSet::new();
        for sample in &samples {
            phase_names.extend(sample.phases.keys().map(String::as_str));
        }
        let mut phases: BTreeMap<String, Stats> = BTreeMap::new();
        for phase in phase_names {
            let values: Vec<f64> = samples
                .iter()
                .filter_map(|sample| sample.phases.get(phase).copied())
                .collect();
            phases.insert(phase.to_string(), stats(&values));
        }
        // No coefficient-of-variation warning, unlike the synthetic report:
        // there every iteration is the same work, so spread is noise, while
        // here every sample is a different block, and the spread is mostly
        // the blocks themselves. Run-to-run noise shows up as the difference
        // between two replays of one corpus, not within one.
        let wall = stats(
            &samples
                .iter()
                .map(|sample| sample.wall_seconds)
                .collect::<Vec<_>>(),
        );

        Self {
            schema_version: 1,
            environment,
            params,
            samples,
            summary: Summary { phases, wall },
        }
    }

    pub(crate) fn to_json(&self) -> eyre::Result<String> {
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    pub(crate) fn human_table(&self) -> String {
        let mut out = String::new();
        let params = &self.params;
        let env = &self.environment;
        let _ = writeln!(out, "Block-import benchmark — {} workload", params.mode);
        let _ = writeln!(
            out,
            "  corpus={} network={} anchor_slot={} warmup_blocks={} range=[{}, {}] blocks={}",
            params.corpus,
            params.network,
            params.anchor_slot,
            params.warmup_blocks,
            params.range_start,
            params.range_end,
            params.blocks
        );
        let _ = writeln!(
            out,
            "  {} leanvm={} os={} arch={} threads={}",
            env.client_version, env.leanvm_rev, env.os, env.arch, env.available_parallelism
        );
        let _ = writeln!(out);

        if self.samples.is_empty() {
            return out;
        }

        // Phase columns are the union over every sample's keys, matching
        // `Report::new`: the first sample alone is not representative, since a
        // phase absent from it may still be present on a later block.
        let mut phase_names: BTreeSet<&String> = BTreeSet::new();
        for sample in &self.samples {
            phase_names.extend(sample.phases.keys());
        }
        let phases: Vec<&String> = phase_names.into_iter().collect();

        let _ = write!(out, "  {:<5}", "iter");
        for phase in &phases {
            let _ = write!(out, " {phase:>16}");
        }
        let _ = writeln!(out, " {:>10} {:>12}", "wall", "root");

        for sample in &self.samples {
            let _ = write!(out, "  {:<5}", sample.iteration);
            for phase in &phases {
                match sample.phases.get(*phase) {
                    Some(seconds) => {
                        let _ = write!(out, " {:>16}", format_ms(*seconds));
                    }
                    None => {
                        let _ = write!(out, " {:>16}", "-");
                    }
                }
            }
            let _ = writeln!(
                out,
                " {:>10} {:>12}",
                format_ms(sample.wall_seconds),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(iteration: u64, phases: &[(&str, f64)]) -> Sample {
        Sample {
            iteration,
            slot: iteration,
            block_root: format!("0x{iteration:064x}"),
            wall_seconds: 0.01,
            phases: phases.iter().map(|(k, v)| ((*k).to_string(), *v)).collect(),
            outcome: "imported",
        }
    }

    fn params() -> Params {
        Params {
            mode: "import",
            corpus: "corpus.ssz".to_string(),
            network: "devnet".to_string(),
            anchor_block_root: "0xabc".to_string(),
            anchor_slot: 0,
            warmup_blocks: 0,
            range_start: 1,
            range_end: 3,
            blocks: 2,
        }
    }

    #[test]
    fn the_range_prints_inclusive_as_fetch_takes_it() {
        let report = Report::new(Environment::collect(), params(), Vec::new());

        assert!(
            report.human_table().contains("range=[1, 3]"),
            "`--to` is inclusive, so the range must not print half-open"
        );
    }

    #[test]
    fn a_phase_missing_from_one_sample_still_gets_a_column_with_stats_over_only_the_samples_that_have_it()
     {
        let samples = vec![
            sample(1, &[("stf", 0.1), ("decode", 0.2)]),
            sample(2, &[("stf", 0.3)]),
        ];
        let report = Report::new(Environment::collect(), params(), samples);

        // `decode` ran on one of two samples: its Stats reflect only that one
        // observation, not a zero-filled second one.
        assert_eq!(report.summary.phases["stf"].count, 2);
        assert_eq!(report.summary.phases["decode"].count, 1);
        assert!((report.summary.phases["decode"].mean_seconds - 0.2).abs() < 1e-9);

        let table = report.human_table();
        assert!(table.contains("decode"), "column missing from human_table");
        assert!(table.contains("stf"), "column missing from human_table");
        // The second sample's row has no `decode` entry: it must render as a
        // placeholder, not a fabricated zero.
        assert!(
            table.contains(" - "),
            "missing phase should render as a placeholder, not 0"
        );
    }
}
