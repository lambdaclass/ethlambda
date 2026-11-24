//! Replays a state-hashing trace through two beacon-state Merkle trees and
//! times them side by side: ethlambda's `ethlambda-ssz-tree` and Silver's
//! `silver_state_hashing`. See README.md for recording a trace and for what
//! is timed.

mod ours;
mod report;
mod silver;
mod trace;

/// The trace format, shared with the node that writes it.
#[path = "../../../bin/ethlambda/src/era/hashing_trace.rs"]
mod format;

use std::collections::VecDeque;
use std::error::Error;
use std::fmt::Display;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Parser;

use format::{LIST_NAMES, Roots};
use trace::{Initial, Step, Trace};

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Parser)]
#[command(about = "Replay a state-hashing trace through ethlambda's and Silver's Merkle trees")]
struct Args {
    /// A trace written by `ethlambda replay-era --hashing-trace`.
    #[arg(long)]
    trace: PathBuf,
    /// Replays of the whole trace per library; each step reports its median.
    #[arg(long, default_value_t = 3)]
    rounds: usize,
    /// Versions kept alive behind the head, as a node keeps recent states
    /// for fork choice. With none kept, nothing is ever copied on write.
    #[arg(long, default_value_t = 32)]
    keep: usize,
    /// Replay only the first N steps of the trace.
    #[arg(long)]
    max_steps: Option<usize>,
    /// Threads for ethlambda's parallel run (it hashes large subtrees on
    /// rayon); every core by default. Silver hashes on one thread.
    #[arg(long)]
    threads: Option<usize>,
    /// Also write every summary and per-step time to this JSON file.
    #[arg(long)]
    json: Option<PathBuf>,
    /// Run one library only, for a quicker loop while working on it.
    #[arg(long, value_enum)]
    only: Option<Library>,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Library {
    Silver,
    Ours,
}

/// Time per list, in [`LIST_NAMES`] order.
pub type ListTimes = [Duration; 5];

/// A Merkle-tree library holding the five lists.
pub trait Candidate {
    /// Builds every list and its root.
    fn build(initial: Initial) -> Self;
    /// A new version: `self` with `step` applied and every root recomputed,
    /// each list's share of the time added to `times`. `self` stays as it
    /// was, and alive, as a node's parent state does.
    fn step(&self, step: &Step, times: &mut ListTimes) -> Self;
    /// The roots the last `build` or `step` computed.
    fn roots(&self) -> Roots;
}

/// Runs `f`, adding its wall time to `total`.
pub fn timed<R>(total: &mut Duration, f: impl FnOnce() -> R) -> R {
    let started = Instant::now();
    let result = f();
    *total += started.elapsed();
    result
}

/// One replay of the whole trace.
pub struct Round {
    pub build: Duration,
    pub steps: Vec<ListTimes>,
    /// Bytes allocated over the starting point once the lists are built.
    pub built_bytes: u64,
    /// The same at the end, with the head and `keep` versions behind it alive.
    pub retained_bytes: u64,
}

/// One library at one thread count.
pub struct Runner {
    pub name: String,
    pub threads: usize,
    pool: rayon::ThreadPool,
    replay: fn(&Trace, usize) -> Round,
    pub rounds: Vec<Round>,
}

impl Runner {
    fn new<C: Candidate>(name: String, threads: usize) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            name,
            threads,
            pool: rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()?,
            replay: replay::<C>,
            rounds: Vec::new(),
        })
    }
}

fn replay<C: Candidate>(trace: &Trace, keep: usize) -> Round {
    let baseline = allocated();
    let initial = trace.initial.clone();
    let started = Instant::now();
    let mut head = C::build(initial);
    let build = started.elapsed();
    let built_bytes = allocated().saturating_sub(baseline);
    check(&head.roots(), &trace.initial_roots, &"the starting lists");

    let mut kept = VecDeque::with_capacity(keep + 1);
    let mut steps = Vec::with_capacity(trace.steps.len());
    for step in &trace.steps {
        let mut times = ListTimes::default();
        let next = head.step(step, &mut times);
        check(
            &next.roots(),
            &step.roots,
            &format_args!("the {:?} step at slot {}", step.kind, step.slot),
        );
        kept.push_back(std::mem::replace(&mut head, next));
        // Dropping the oldest version is not timed, for either library.
        if kept.len() > keep {
            kept.pop_front();
        }
        steps.push(times);
    }
    let retained_bytes = allocated().saturating_sub(baseline);
    Round {
        build,
        steps,
        built_bytes,
        retained_bytes,
    }
}

/// A root that differs from the one mainnet committed to ends the run: the
/// timings of a library computing something else mean nothing.
fn check(actual: &Roots, expected: &Roots, at: &dyn Display) {
    let lists = LIST_NAMES
        .iter()
        .zip(actual.as_array())
        .zip(expected.as_array());
    for ((name, actual), expected) in lists {
        assert!(
            actual == expected,
            "{name} root after {at}: expected 0x{}, got 0x{}",
            hex(&expected),
            hex(&actual)
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// jemalloc's count of live allocated bytes, process wide.
fn allocated() -> u64 {
    let _ = tikv_jemalloc_ctl::epoch::advance();
    tikv_jemalloc_ctl::stats::allocated::read().unwrap_or(0) as u64
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    eprintln!("Loading {}", args.trace.display());
    let trace = trace::load(&args.trace, args.max_steps)?;
    eprintln!(
        "Loaded {} steps over {} validators",
        trace.steps.len(),
        trace.initial.validators.len()
    );

    let threads = match args.threads {
        Some(threads) => threads,
        None => std::thread::available_parallelism()?.get(),
    };
    let runs = |library| args.only.is_none_or(|only| only == library);
    let mut runners = Vec::new();
    if runs(Library::Silver) {
        runners.push(Runner::new::<silver::Silver>(
            "silver_state_hashing 0.2.0, 1 thread".into(),
            1,
        )?);
    }
    if runs(Library::Ours) {
        runners.push(Runner::new::<ours::Ours>(
            "ethlambda-ssz-tree, 1 thread".into(),
            1,
        )?);
        if threads > 1 {
            runners.push(Runner::new::<ours::Ours>(
                format!("ethlambda-ssz-tree, {threads} threads"),
                threads,
            )?);
        }
    }

    // Rounds interleave the libraries, so a drift in the machine's speed
    // (thermal, frequency, neighbours) lands on all of them alike.
    for round in 1..=args.rounds {
        for runner in &mut runners {
            eprintln!("Round {round}/{}: {}", args.rounds, runner.name);
            let replay = runner.replay;
            let keep = args.keep;
            let result = runner.pool.install(|| replay(&trace, keep));
            runner.rounds.push(result);
        }
    }

    let summaries: Vec<_> = runners
        .iter()
        .map(|runner| report::summarize(runner, &trace))
        .collect();
    report::print(&trace, &summaries, args.rounds, args.keep);
    if let Some(path) = &args.json {
        report::write_json(path, &trace, &summaries, args.rounds, args.keep)?;
        eprintln!("Wrote {}", path.display());
    }
    Ok(())
}
