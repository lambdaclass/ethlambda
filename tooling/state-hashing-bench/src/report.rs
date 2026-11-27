//! Summaries of the replays: per phase (block, epoch transition), per list,
//! printed as Markdown tables and optionally written as JSON.

use std::path::Path;

use serde::Serialize;

use crate::Runner;
use crate::format::{LIST_NAMES, StepKind};
use crate::trace::Trace;

#[derive(Serialize)]
pub struct Summary {
    pub name: String,
    pub threads: usize,
    pub build_ms: f64,
    pub built_mib: f64,
    pub retained_mib: f64,
    pub block: Phase,
    pub epoch: Phase,
    pub total_ms: f64,
    /// Each round's build and whole-trace time, in run order: rounds that
    /// disagree much point at a machine that was not quiet.
    pub round_build_ms: Vec<f64>,
    pub round_total_ms: Vec<f64>,
    /// Per step and list, the median over rounds, in milliseconds.
    pub steps_ms: Vec<[f64; 5]>,
}

/// One kind of step's per-step totals (every list together).
#[derive(Serialize, Default)]
pub struct Phase {
    pub steps: usize,
    pub median_ms: f64,
    pub mean_ms: f64,
    pub p90_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub total_ms: f64,
    /// Per list, in `LIST_NAMES` order.
    pub list_median_ms: [f64; 5],
    pub list_mean_ms: [f64; 5],
}

fn ms(duration: std::time::Duration) -> f64 {
    duration.as_secs_f64() * 1e3
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1 << 20) as f64
}

fn median(values: &mut [f64]) -> f64 {
    percentile(values, 0.5)
}

/// Nearest-rank percentile; sorts `values`.
fn percentile(values: &mut [f64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(f64::total_cmp);
    let rank = ((p * values.len() as f64).ceil() as usize).clamp(1, values.len());
    values[rank - 1]
}

pub fn summarize(runner: &Runner, trace: &Trace) -> Summary {
    let rounds = &runner.rounds;
    let step_count = rounds[0].steps.len();
    let steps_ms: Vec<[f64; 5]> = (0..step_count)
        .map(|step| {
            std::array::from_fn(|list| {
                let mut values: Vec<f64> = rounds
                    .iter()
                    .map(|round| ms(round.steps[step][list]))
                    .collect();
                median(&mut values)
            })
        })
        .collect();
    let round_build_ms: Vec<f64> = rounds.iter().map(|round| ms(round.build)).collect();
    let round_total_ms = rounds
        .iter()
        .map(|round| round.steps.iter().flatten().copied().map(ms).sum())
        .collect();
    let last = rounds.last().expect("at least one round");
    Summary {
        name: runner.name.clone(),
        threads: runner.threads,
        build_ms: median(&mut round_build_ms.clone()),
        built_mib: mib(last.built_bytes),
        retained_mib: mib(last.retained_bytes),
        block: phase(trace, &steps_ms, StepKind::Block),
        epoch: phase(trace, &steps_ms, StepKind::Epoch),
        total_ms: steps_ms.iter().flatten().sum(),
        round_build_ms,
        round_total_ms,
        steps_ms,
    }
}

fn phase(trace: &Trace, steps_ms: &[[f64; 5]], kind: StepKind) -> Phase {
    let lists: Vec<[f64; 5]> = trace
        .steps
        .iter()
        .zip(steps_ms)
        .filter(|(step, _)| step.kind == kind)
        .map(|(_, times)| *times)
        .collect();
    if lists.is_empty() {
        return Phase::default();
    }
    let mut totals: Vec<f64> = lists.iter().map(|times| times.iter().sum()).collect();
    let total_ms: f64 = totals.iter().sum();
    let count = totals.len();
    let list_median_ms = std::array::from_fn(|list| {
        let mut values: Vec<f64> = lists.iter().map(|times| times[list]).collect();
        median(&mut values)
    });
    let list_mean_ms = std::array::from_fn(|list| {
        lists.iter().map(|times| times[list]).sum::<f64>() / count as f64
    });
    Phase {
        steps: count,
        median_ms: median(&mut totals),
        mean_ms: total_ms / count as f64,
        p90_ms: percentile(&mut totals, 0.9),
        p99_ms: percentile(&mut totals, 0.99),
        max_ms: percentile(&mut totals, 1.0),
        total_ms,
        list_median_ms,
        list_mean_ms,
    }
}

/// Mean elements written per step of `kind`, per list.
fn mean_writes(trace: &Trace, kind: StepKind) -> [f64; 5] {
    let counts: Vec<[usize; 5]> = trace
        .steps
        .iter()
        .filter(|step| step.kind == kind)
        .map(|step| step.counts())
        .collect();
    std::array::from_fn(|list| {
        if counts.is_empty() {
            return 0.0;
        }
        counts.iter().map(|count| count[list]).sum::<usize>() as f64 / counts.len() as f64
    })
}

fn row(label: &str, summaries: &[Summary], value: impl Fn(&Summary) -> f64) {
    let cells: Vec<String> = summaries
        .iter()
        .map(|summary| format!("{:.3}", value(summary)))
        .collect();
    println!("| {label} | {} |", cells.join(" | "));
}

fn text_row(label: &str, summaries: &[Summary], value: impl Fn(&Summary) -> String) {
    let cells: Vec<String> = summaries.iter().map(value).collect();
    println!("| {label} | {} |", cells.join(" | "));
}

fn join(values: &[f64]) -> String {
    let values: Vec<String> = values.iter().map(|value| format!("{value:.1}")).collect();
    values.join(" / ")
}

fn header(first: &str, summaries: &[Summary]) {
    let names: Vec<&str> = summaries
        .iter()
        .map(|summary| summary.name.as_str())
        .collect();
    println!("| {first} | {} |", names.join(" | "));
    println!("|---|{}", "---:|".repeat(summaries.len()));
}

pub fn print(trace: &Trace, summaries: &[Summary], rounds: usize, keep: usize) {
    let header_info = &trace.header;
    let blocks = trace.steps.iter().filter(|s| s.kind == StepKind::Block);
    let first_slot = blocks.clone().map(|s| s.slot).min().unwrap_or(0);
    let last_slot = blocks.clone().map(|s| s.slot).max().unwrap_or(0);
    println!("## Trace\n");
    println!(
        "{} {} state at slot {}, {} validators ({} at the end). {} blocks (slots \
         {first_slot}..={last_slot}), {} epoch transitions.",
        header_info.network,
        header_info.fork,
        header_info.slot,
        trace.initial.validators.len(),
        trace
            .steps
            .last()
            .map_or(trace.initial.validators.len(), |step| step.validators.len
                as usize),
        blocks.count(),
        trace
            .steps
            .iter()
            .filter(|s| s.kind == StepKind::Epoch)
            .count(),
    );
    println!(
        "Each step's time is its median over {rounds} rounds; {keep} versions are kept alive \
         behind the head.\n"
    );
    println!("Elements written per step, mean:\n");
    println!("| | {} |", LIST_NAMES.join(" | "));
    println!("|---|{}", "---:|".repeat(5));
    for (label, kind) in [
        ("block", StepKind::Block),
        ("epoch transition", StepKind::Epoch),
    ] {
        let writes = mean_writes(trace, kind);
        let cells: Vec<String> = writes.iter().map(|w| format!("{w:.0}")).collect();
        println!("| {label} | {} |", cells.join(" | "));
    }

    println!("\n## Time (ms), writes plus new roots for all five lists\n");
    header("", summaries);
    row("Build + roots", summaries, |s| s.build_ms);
    row("Block, median", summaries, |s| s.block.median_ms);
    row("Block, mean", summaries, |s| s.block.mean_ms);
    row("Block, p90", summaries, |s| s.block.p90_ms);
    row("Block, p99", summaries, |s| s.block.p99_ms);
    row("Block, max", summaries, |s| s.block.max_ms);
    row("Epoch transition, median", summaries, |s| s.epoch.median_ms);
    row("Epoch transition, mean", summaries, |s| s.epoch.mean_ms);
    row("Epoch transition, max", summaries, |s| s.epoch.max_ms);
    row("Whole trace", summaries, |s| s.total_ms);
    text_row("Whole trace, each round", summaries, |s| {
        join(&s.round_total_ms)
    });
    text_row("Build, each round", summaries, |s| join(&s.round_build_ms));

    println!("\n## Block, median per list (ms)\n");
    header("list", summaries);
    for (list, name) in LIST_NAMES.iter().enumerate() {
        row(name, summaries, |s| s.block.list_median_ms[list]);
    }

    println!("\n## Epoch transition, mean per list (ms)\n");
    header("list", summaries);
    for (list, name) in LIST_NAMES.iter().enumerate() {
        row(name, summaries, |s| s.epoch.list_mean_ms[list]);
    }

    println!("\n## Memory (MiB allocated, jemalloc)\n");
    header("", summaries);
    row("After build", summaries, |s| s.built_mib);
    row(
        &format!("After the replay, head + {keep} kept"),
        summaries,
        |s| s.retained_mib,
    );
    println!(
        "\nSilver's page arenas keep freed pages for reuse rather than returning them, so its \
         second memory row is closer to a high-water mark than to what is live."
    );
}

#[derive(Serialize)]
struct Json<'a> {
    network: &'a str,
    fork: &'a str,
    start_slot: u64,
    validators: usize,
    rounds: usize,
    keep: usize,
    lists: [&'static str; 5],
    step_kinds: Vec<&'static str>,
    step_slots: Vec<u64>,
    step_writes: Vec<[usize; 5]>,
    summaries: &'a [Summary],
}

pub fn write_json(
    path: &Path,
    trace: &Trace,
    summaries: &[Summary],
    rounds: usize,
    keep: usize,
) -> std::io::Result<()> {
    let json = Json {
        network: &trace.header.network,
        fork: &trace.header.fork,
        start_slot: trace.header.slot,
        validators: trace.initial.validators.len(),
        rounds,
        keep,
        lists: LIST_NAMES,
        step_kinds: trace
            .steps
            .iter()
            .map(|step| match step.kind {
                StepKind::Block => "block",
                StepKind::Epoch => "epoch",
            })
            .collect(),
        step_slots: trace.steps.iter().map(|step| step.slot).collect(),
        step_writes: trace.steps.iter().map(|step| step.counts()).collect(),
        summaries,
    };
    let bytes = serde_json::to_vec(&json).map_err(std::io::Error::other)?;
    std::fs::write(path, bytes)
}
