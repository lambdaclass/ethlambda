//! The import workload's report.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::Serialize;

use super::common::{Environment, Stats, format_ms, stats};

/// What a block's `process_slots` had to do, which is the first-order
/// predictor of how long its state transition takes: crossing an epoch
/// boundary runs `process_epoch` over the whole registry, and skipping slots
/// runs the per-slot bookkeeping once per slot.
///
/// Decided from the block's own slot and its parent's, so it describes the
/// work the block asked for, not what a cache happened to spare it: an
/// `epoch_boundary` block whose epoch transition was precomputed is still one.
///
/// A replayed corpus is linear (`fetch` refuses a block whose parent is not
/// the one before it), so a block's parent is always the previous block and
/// there is no fourth class for a reorg: the state a block is applied to never
/// sits on another branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BlockClass {
    /// `process_slots` crosses an epoch boundary: the block's slot is in a later
    /// epoch than its parent's.
    EpochBoundary,
    /// Within one epoch, but the parent is more than one slot back.
    AfterSkip,
    /// The parent is the previous slot, in the same epoch.
    Ordinary,
}

impl BlockClass {
    /// The label a class is reported under, which is also its JSON value.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            BlockClass::EpochBoundary => "epoch_boundary",
            BlockClass::AfterSkip => "after_skip",
            BlockClass::Ordinary => "ordinary",
        }
    }

    /// Classify a block at `slot` applied to a parent post-state at
    /// `parent_slot`. An epoch crossing takes precedence over a skip: a block
    /// that skipped slots across a boundary is dominated by the epoch work.
    pub(crate) const fn classify(parent_slot: u64, slot: u64, slots_per_epoch: u64) -> Self {
        if parent_slot / slots_per_epoch < slot / slots_per_epoch {
            BlockClass::EpochBoundary
        } else if slot > parent_slot + 1 {
            BlockClass::AfterSkip
        } else {
            BlockClass::Ordinary
        }
    }
}

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
    /// Milliseconds slept after each block's import, outside every measured
    /// span. 0 means blocks were fed back to back.
    pub block_delay_ms: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct Sample {
    pub iteration: u64,
    pub slot: u64,
    /// The slot of the block this one was applied to, which is what `class`
    /// was decided from.
    pub parent_slot: u64,
    pub class: BlockClass,
    /// Determinism checksum: two runs over one corpus must produce the same
    /// roots in the same order.
    pub block_root: String,
    pub wall_seconds: f64,
    /// Per-phase seconds from `lean_block_import_phase_seconds` sum deltas.
    /// A phase that did not run is absent, not zero.
    pub phases: BTreeMap<String, f64>,
    /// Per-step seconds of the beacon state transition, from
    /// `lean_beacon_stf_phase_seconds` sum deltas over the `import` context
    /// only, so nothing a background thread did is in them. A step that did not
    /// run is absent, not zero; one that ran several times (`process_epoch`
    /// across a long skip) is the sum of its runs.
    pub stf_phases: BTreeMap<String, f64>,
    /// What the `stf` phase spent outside every step in `stf_phases`: cloning
    /// the parent state, building the epoch-boundary balances, and anything
    /// else not given a step of its own. Absent when `stf` did not run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stf_unattributed_seconds: Option<f64>,
    /// User plus system CPU seconds the whole process spent during the import,
    /// all threads included. Absent if the host refused the reading.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_seconds: Option<f64>,
    /// Resident set size right after the import. Linux only: absent elsewhere.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rss_bytes: Option<u64>,
    /// The process's peak resident set size so far, a high-water mark.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_rss_bytes: Option<u64>,
    /// `"imported"`. A run that reaches a report has no other outcome: a
    /// held or rejected block aborts it.
    pub outcome: &'static str,
}

/// The distributions of a set of samples: every block of the run, or the
/// blocks of one class.
#[derive(Debug, Serialize)]
pub(crate) struct Distribution {
    pub phases: BTreeMap<String, Stats>,
    pub stf_phases: BTreeMap<String, Stats>,
    pub stf_unattributed: Stats,
    pub wall: Stats,
    pub cpu: Stats,
}

impl Distribution {
    fn of(samples: &[&Sample]) -> Self {
        // Union over every sample's phase keys, not just the first sample's:
        // unlike a synthetic build (where every phase runs on every block), a
        // corpus block legitimately skips phases (decode, defer, parent_wait,
        // columns_wait), and which ones it skips can differ block to block.
        let phases = phase_stats(samples, |sample| &sample.phases);
        let stf_phases = phase_stats(samples, |sample| &sample.stf_phases);
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
        let cpu = stats(
            &samples
                .iter()
                .filter_map(|sample| sample.cpu_seconds)
                .collect::<Vec<_>>(),
        );
        let stf_unattributed = stats(
            &samples
                .iter()
                .filter_map(|sample| sample.stf_unattributed_seconds)
                .collect::<Vec<_>>(),
        );
        Self {
            phases,
            stf_phases,
            stf_unattributed,
            wall,
            cpu,
        }
    }
}

/// Stats per phase name over `samples`, for the phase map `select` picks.
fn phase_stats(
    samples: &[&Sample],
    select: impl Fn(&Sample) -> &BTreeMap<String, f64>,
) -> BTreeMap<String, Stats> {
    let mut names: BTreeSet<&str> = BTreeSet::new();
    for sample in samples {
        names.extend(select(sample).keys().map(String::as_str));
    }
    names
        .into_iter()
        .map(|name| {
            let values: Vec<f64> = samples
                .iter()
                .filter_map(|sample| select(sample).get(name).copied())
                .collect();
            (name.to_string(), stats(&values))
        })
        .collect()
}

/// One block class's share of the run.
#[derive(Debug, Serialize)]
pub(crate) struct ClassSummary {
    pub blocks: usize,
    #[serde(flatten)]
    pub distribution: Distribution,
}

#[derive(Debug, Serialize)]
pub(crate) struct Summary {
    #[serde(flatten)]
    pub overall: Distribution,
    /// Only the classes at least one block fell into.
    pub by_class: BTreeMap<String, ClassSummary>,
}

/// The lookups one cache served during the measured blocks.
#[derive(Debug, Serialize)]
pub(crate) struct LookupCounts {
    pub hit: u64,
    pub miss: u64,
    /// Lookups that could not be keyed and so were computed for one caller and
    /// not cached. Absent for caches that have no such outcome.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unkeyable: Option<u64>,
    /// `hit / (hit + miss)`, absent when nothing was looked up. Unkeyable
    /// lookups are not in the denominator: they never had a chance to hit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hit_rate: Option<f64>,
}

impl LookupCounts {
    /// From the per-`result` counter deltas of one cache. `keyless` says
    /// whether the cache has an `unkeyable` outcome to report.
    pub(crate) fn from_results(results: &BTreeMap<String, u64>, keyless: bool) -> Self {
        let get = |result: &str| results.get(result).copied().unwrap_or(0);
        let (hit, miss) = (get("hit"), get("miss"));
        let hit_rate = (hit + miss > 0).then(|| hit as f64 / (hit + miss) as f64);
        Self {
            hit,
            miss,
            unkeyable: keyless.then(|| get("unkeyable")),
            hit_rate,
        }
    }
}

/// The lookup counters of the caches the state transition leans on, as deltas
/// over the measured blocks (warm-up excluded). A replay has no epoch
/// precompute worker, so `epoch_precompute` reports what an epoch-crossing
/// import costs when nothing has precomputed its boundary: its misses are the
/// epoch-boundary blocks.
#[derive(Debug, Serialize)]
pub(crate) struct Caches {
    pub epoch_precompute: LookupCounts,
    pub committee_cache: LookupCounts,
    pub total_active_balance: LookupCounts,
    pub justified_balances: LookupCounts,
}

#[derive(Debug, Serialize)]
pub(crate) struct Report {
    pub schema_version: u32,
    pub environment: Environment,
    pub params: Params,
    pub samples: Vec<Sample>,
    pub summary: Summary,
    pub caches: Caches,
}

/// The JSON layout version of this report.
///
/// 2: samples gained `parent_slot`, `class`, `stf_phases`,
/// `stf_unattributed_seconds`, `cpu_seconds`, `rss_bytes` and
/// `peak_rss_bytes`; every `Stats` gained `p95_seconds` and `p99_seconds`;
/// the summary gained `stf_phases`, `stf_unattributed`, `cpu` and `by_class`;
/// the report gained `caches`.
pub(crate) const SCHEMA_VERSION: u32 = 2;

impl Report {
    pub(crate) fn new(
        environment: Environment,
        params: Params,
        samples: Vec<Sample>,
        caches: Caches,
    ) -> Self {
        let everyone: Vec<&Sample> = samples.iter().collect();
        let overall = Distribution::of(&everyone);

        let mut by_class: BTreeMap<String, ClassSummary> = BTreeMap::new();
        for class in [
            BlockClass::EpochBoundary,
            BlockClass::AfterSkip,
            BlockClass::Ordinary,
        ] {
            let members: Vec<&Sample> = samples
                .iter()
                .filter(|sample| sample.class == class)
                .collect();
            if !members.is_empty() {
                by_class.insert(
                    class.label().to_string(),
                    ClassSummary {
                        blocks: members.len(),
                        distribution: Distribution::of(&members),
                    },
                );
            }
        }

        Self {
            schema_version: SCHEMA_VERSION,
            environment,
            params,
            samples,
            summary: Summary { overall, by_class },
            caches,
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
            "  corpus={} network={} anchor_slot={} warmup_blocks={} range=[{}, {}] blocks={} block_delay_ms={}",
            params.corpus,
            params.network,
            params.anchor_slot,
            params.warmup_blocks,
            params.range_start,
            params.range_end,
            params.blocks,
            params.block_delay_ms
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
        let _ = writeln!(
            out,
            " {:>14} {:>9} {:>10} {:>10} {:>12}",
            "class", "cpu", "stf_unattr", "wall", "root"
        );

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
                " {:>14} {:>9} {:>10} {:>10} {:>12}",
                sample.class.label(),
                optional_ms(sample.cpu_seconds),
                optional_ms(sample.stf_unattributed_seconds),
                format_ms(sample.wall_seconds),
                &sample.block_root[..10],
            );
        }

        // The per-block STF steps are not columns above: there are close to
        // twenty of them, so the table would stop fitting any terminal. They
        // are in each sample's `stf_phases` in the JSON, and summarized here.
        let _ = writeln!(out);
        let overall = &self.summary.overall;
        write_stats_header(&mut out, "phase");
        for (phase, stats) in &overall.phases {
            let _ = writeln!(out, "{}", stats_row(phase, stats));
        }
        let _ = writeln!(out, "{}", stats_row("wall", &overall.wall));
        let _ = writeln!(out, "{}", stats_row("cpu", &overall.cpu));

        let _ = writeln!(out);
        write_stats_header(&mut out, "stf step");
        for (phase, stats) in &overall.stf_phases {
            let _ = writeln!(out, "{}", stats_row(phase, stats));
        }
        let _ = writeln!(
            out,
            "{}",
            stats_row("(unattributed)", &overall.stf_unattributed)
        );

        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "  {:<16} {:>6} {:>10} {:>10} {:>10} {:>10} {:>10}",
            "class", "blocks", "wall p50", "wall p95", "wall p99", "stf p50", "stf p99"
        );
        for (class, summary) in &self.summary.by_class {
            let stf = summary.distribution.phases.get("stf");
            let _ = writeln!(
                out,
                "  {:<16} {:>6} {:>10} {:>10} {:>10} {:>10} {:>10}",
                class,
                summary.blocks,
                format_ms(summary.distribution.wall.p50_seconds),
                format_ms(summary.distribution.wall.p95_seconds),
                format_ms(summary.distribution.wall.p99_seconds),
                optional_ms(stf.map(|stats| stats.p50_seconds)),
                optional_ms(stf.map(|stats| stats.p99_seconds)),
            );
        }

        let _ = writeln!(out);
        let caches = &self.caches;
        for (name, counts) in [
            ("epoch_precompute", &caches.epoch_precompute),
            ("committee_cache", &caches.committee_cache),
            ("total_active_balance", &caches.total_active_balance),
            ("justified_balances", &caches.justified_balances),
        ] {
            let rate = counts
                .hit_rate
                .map_or_else(|| "-".to_string(), |rate| format!("{:.1}%", rate * 100.0));
            let unkeyable = counts
                .unkeyable
                .map_or_else(String::new, |count| format!(" unkeyable={count}"));
            let _ = writeln!(
                out,
                "  cache {name:<21} hit={} miss={}{unkeyable} hit_rate={rate}",
                counts.hit, counts.miss
            );
        }
        out
    }
}

/// A duration in milliseconds, or `-` where the reading is absent.
fn optional_ms(seconds: Option<f64>) -> String {
    seconds.map_or_else(|| "-".to_string(), format_ms)
}

fn write_stats_header(out: &mut String, first: &str) {
    let _ = writeln!(
        out,
        "  {:<26} {:>5} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
        first, "count", "min", "mean", "p50", "p90", "p95", "p99", "max"
    );
}

fn stats_row(name: &str, stats: &Stats) -> String {
    format!(
        "  {:<26} {:>5} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
        name,
        stats.count,
        format_ms(stats.min_seconds),
        format_ms(stats.mean_seconds),
        format_ms(stats.p50_seconds),
        format_ms(stats.p90_seconds),
        format_ms(stats.p95_seconds),
        format_ms(stats.p99_seconds),
        format_ms(stats.max_seconds),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLOTS_PER_EPOCH: u64 = 32;

    fn sample(iteration: u64, phases: &[(&str, f64)]) -> Sample {
        Sample {
            iteration,
            slot: iteration,
            parent_slot: iteration.saturating_sub(1),
            class: BlockClass::Ordinary,
            block_root: format!("0x{iteration:064x}"),
            wall_seconds: 0.01,
            phases: phases.iter().map(|(k, v)| ((*k).to_string(), *v)).collect(),
            stf_phases: BTreeMap::new(),
            stf_unattributed_seconds: None,
            cpu_seconds: None,
            rss_bytes: None,
            peak_rss_bytes: None,
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
            block_delay_ms: 0,
        }
    }

    fn no_caches() -> Caches {
        let none = BTreeMap::new();
        Caches {
            epoch_precompute: LookupCounts::from_results(&none, false),
            committee_cache: LookupCounts::from_results(&none, true),
            total_active_balance: LookupCounts::from_results(&none, true),
            justified_balances: LookupCounts::from_results(&none, false),
        }
    }

    fn report(samples: Vec<Sample>) -> Report {
        Report::new(Environment::collect(), params(), samples, no_caches())
    }

    #[test]
    fn the_block_delay_is_recorded_in_the_json_and_the_header() {
        let mut params = params();
        params.block_delay_ms = 750;
        let report = Report::new(Environment::collect(), params, Vec::new(), no_caches());

        let json: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
        assert_eq!(json["params"]["block_delay_ms"], 750);
        assert!(report.human_table().contains("block_delay_ms=750"));
    }

    #[test]
    fn the_range_prints_inclusive_as_fetch_takes_it() {
        let report = report(Vec::new());

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
        let report = report(samples);

        // `decode` ran on one of two samples: its Stats reflect only that one
        // observation, not a zero-filled second one.
        let phases = &report.summary.overall.phases;
        assert_eq!(phases["stf"].count, 2);
        assert_eq!(phases["decode"].count, 1);
        assert!((phases["decode"].mean_seconds - 0.2).abs() < 1e-9);

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

    #[test]
    fn a_block_crossing_an_epoch_boundary_is_an_epoch_boundary_whatever_it_skipped() {
        let classify = |parent, slot| BlockClass::classify(parent, slot, SLOTS_PER_EPOCH);

        // The last slot of an epoch to the first of the next, no skip.
        assert_eq!(classify(31, 32), BlockClass::EpochBoundary);
        // A skip that lands in the next epoch is still dominated by the epoch.
        assert_eq!(classify(30, 33), BlockClass::EpochBoundary);
        // Several epochs at once.
        assert_eq!(classify(31, 100), BlockClass::EpochBoundary);
    }

    #[test]
    fn a_block_that_skipped_slots_inside_one_epoch_is_after_skip() {
        let classify = |parent, slot| BlockClass::classify(parent, slot, SLOTS_PER_EPOCH);

        assert_eq!(classify(33, 35), BlockClass::AfterSkip);
        // The skip ends exactly on the epoch's last slot: still one epoch.
        assert_eq!(classify(32, 63), BlockClass::AfterSkip);
    }

    #[test]
    fn a_block_one_slot_after_its_parent_in_the_same_epoch_is_ordinary() {
        let classify = |parent, slot| BlockClass::classify(parent, slot, SLOTS_PER_EPOCH);

        assert_eq!(classify(33, 34), BlockClass::Ordinary);
        assert_eq!(classify(62, 63), BlockClass::Ordinary);
    }

    #[test]
    fn the_class_label_is_the_json_value() {
        for class in [
            BlockClass::EpochBoundary,
            BlockClass::AfterSkip,
            BlockClass::Ordinary,
        ] {
            assert_eq!(
                serde_json::to_value(class).unwrap(),
                serde_json::Value::String(class.label().to_string())
            );
        }
    }

    #[test]
    fn the_summary_splits_by_class_and_leaves_out_classes_nothing_fell_into() {
        let mut boundary = sample(1, &[("stf", 0.9)]);
        boundary.class = BlockClass::EpochBoundary;
        boundary.wall_seconds = 1.0;
        let ordinary_a = sample(2, &[("stf", 0.1)]);
        let ordinary_b = sample(3, &[("stf", 0.2), ("decode", 0.01)]);
        let report = report(vec![boundary, ordinary_a, ordinary_b]);

        let by_class = &report.summary.by_class;
        assert_eq!(
            by_class.len(),
            2,
            "no after_skip block, so no after_skip row"
        );
        assert_eq!(by_class["epoch_boundary"].blocks, 1);
        assert_eq!(by_class["ordinary"].blocks, 2);
        assert!(!by_class.contains_key("after_skip"));

        let ordinary = &by_class["ordinary"].distribution;
        assert!((ordinary.phases["stf"].mean_seconds - 0.15).abs() < 1e-9);
        assert_eq!(ordinary.phases["decode"].count, 1);
        assert!((by_class["epoch_boundary"].distribution.wall.mean_seconds - 1.0).abs() < 1e-9);
        // The whole-run summary still covers all three.
        assert_eq!(report.summary.overall.phases["stf"].count, 3);
    }

    #[test]
    fn the_report_carries_the_new_shape_at_the_documented_paths() {
        let mut block = sample(1, &[("stf", 0.5)]);
        block.stf_phases = [("process_epoch".to_string(), 0.3)].into_iter().collect();
        block.stf_unattributed_seconds = Some(0.05);
        block.cpu_seconds = Some(0.7);
        block.rss_bytes = Some(1 << 30);
        block.peak_rss_bytes = Some(2 << 30);
        let mut bare = sample(2, &[]);
        bare.class = BlockClass::AfterSkip;

        let mut results = BTreeMap::new();
        results.insert("hit".to_string(), 3);
        results.insert("miss".to_string(), 1);
        let caches = Caches {
            epoch_precompute: LookupCounts::from_results(&results, false),
            committee_cache: LookupCounts::from_results(&results, true),
            ..no_caches()
        };
        let report = Report::new(Environment::collect(), params(), vec![block, bare], caches);

        let json: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
        assert_eq!(json["schema_version"], 2);

        let first = &json["samples"][0];
        assert_eq!(first["class"], "ordinary");
        assert_eq!(first["parent_slot"], 0);
        assert_eq!(first["stf_phases"]["process_epoch"], 0.3);
        assert_eq!(first["cpu_seconds"], 0.7);
        assert_eq!(first["rss_bytes"], 1u64 << 30);
        assert_eq!(first["peak_rss_bytes"], 2u64 << 30);

        // A reading that is absent is omitted from the sample, not null or 0.
        let second = json["samples"][1].as_object().unwrap();
        for key in [
            "cpu_seconds",
            "rss_bytes",
            "peak_rss_bytes",
            "stf_unattributed_seconds",
        ] {
            assert!(!second.contains_key(key), "{key} should be absent");
        }
        assert_eq!(second["class"], "after_skip");

        // Summary paths: the old ones are where they were, flattened.
        let summary = &json["summary"];
        assert_eq!(summary["phases"]["stf"]["count"], 1);
        assert!(summary["phases"]["stf"]["p95_seconds"].is_number());
        assert!(summary["phases"]["stf"]["p99_seconds"].is_number());
        assert_eq!(summary["stf_phases"]["process_epoch"]["count"], 1);
        assert_eq!(summary["cpu"]["count"], 1, "only one sample had a reading");
        assert_eq!(summary["stf_unattributed"]["count"], 1);
        assert_eq!(summary["wall"]["count"], 2);
        assert_eq!(summary["by_class"]["ordinary"]["blocks"], 1);
        assert_eq!(summary["by_class"]["after_skip"]["blocks"], 1);

        let caches = &json["caches"];
        assert_eq!(caches["epoch_precompute"]["hit"], 3);
        assert_eq!(caches["epoch_precompute"]["miss"], 1);
        assert_eq!(caches["epoch_precompute"]["hit_rate"], 0.75);
        assert!(
            !caches["epoch_precompute"]
                .as_object()
                .unwrap()
                .contains_key("unkeyable")
        );
        assert_eq!(caches["committee_cache"]["unkeyable"], 0);
        assert!(
            !caches["justified_balances"]
                .as_object()
                .unwrap()
                .contains_key("hit_rate"),
            "no lookups means no rate, not a rate of zero"
        );
    }

    #[test]
    fn the_hit_rate_ignores_unkeyable_lookups() {
        let results: BTreeMap<String, u64> = [("hit", 1), ("miss", 1), ("unkeyable", 98)]
            .into_iter()
            .map(|(result, count)| (result.to_string(), count))
            .collect();

        let counts = LookupCounts::from_results(&results, true);
        assert_eq!(counts.unkeyable, Some(98));
        assert_eq!(counts.hit_rate, Some(0.5));
    }

    #[test]
    fn the_human_table_names_the_new_columns_and_sections() {
        let mut block = sample(1, &[("stf", 0.5)]);
        block.stf_phases = [("state_root".to_string(), 0.2)].into_iter().collect();
        block.cpu_seconds = Some(0.6);
        let table = report(vec![block]).human_table();

        for expected in [
            "class",
            "cpu",
            "p95",
            "p99",
            "state_root",
            "(unattributed)",
            "epoch_precompute",
            "justified_balances",
        ] {
            assert!(table.contains(expected), "`{expected}` missing:\n{table}");
        }
    }
}
