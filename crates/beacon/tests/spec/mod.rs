//! Loading the Ethereum consensus spec test fixtures.
//!
//! The fixture tree is the definition of correctness for this crate. Every
//! runner below discovers its cases from disk rather than listing them, so a
//! fixture release that adds cases is picked up without touching code, and a
//! suite that silently stops matching any case fails instead of reporting green.
//!
//! # Layout
//!
//! The three release tarballs all unpack to `tests/<config>/...`, so they extract
//! into one directory:
//!
//! ```text
//! consensus-spec-tests/tests/<config>/<fork>/<runner>/<handler>/<suite>/<case>/
//! ```
//!
//! `<config>` is `general` for the configuration-independent suites (BLS, KZG),
//! and the preset name otherwise. Since the preset is compiled in, a test run
//! walks only the tree matching its own build.
//!
//! # File formats
//!
//! State and container files are `.ssz_snappy`: SSZ, compressed with *raw*
//! snappy, not the framed format. Everything else is YAML.

#![allow(
    dead_code,
    reason = "each runner uses a different part of this harness"
)]

mod epoch_processing;
mod fork;
mod fork_choice;
mod genesis;
mod harness;
mod operations;
mod rewards;
mod sanity;
mod shuffling;
mod ssz_static;
mod transition;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use ethlambda_beacon::ForkName;
use ethlambda_beacon::containers::BeaconState;
use libssz::SszDecode;
use rayon::prelude::*;
use serde::de::DeserializeOwned;

/// The configuration directory whose fixtures match the compiled-in preset.
pub const PRESET: &str = if cfg!(feature = "preset-minimal") {
    "minimal"
} else {
    "mainnet"
};

/// The newest fork whose state transition this crate implements.
///
/// Every runner gates on this and *counts and reports* the cases it skips, so
/// the output can never imply more coverage than exists. Turning on a fork is
/// a one-line change here once its state transition lands: bump this constant
/// and every runner that uses [`Case::in_scope`] (or [`Report::skip`]) picks up
/// that fork's cases on its own, with no other edit required to the gate
/// itself. A runner may still need its own edit to *map* a fork's new or
/// changed handlers to the right function, since that mapping is specific to
/// each runner; only the gate is one line.
pub const HIGHEST_IMPLEMENTED_FORK: ForkName = ForkName::Fulu;

/// The root of the extracted fixture tree.
///
/// Panics rather than skipping when the fixtures are absent. A spec suite that
/// reports success because it found nothing to run is worse than one that fails.
pub fn fixture_root() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../consensus-spec-tests")
        .join("tests");
    assert!(
        root.is_dir(),
        "spec test fixtures are missing from {}; run `make consensus-spec-tests`",
        root.display()
    );
    root
}

/// One fixture case: a directory of input and expected-output files.
#[derive(Debug, Clone)]
pub struct Case {
    /// The case directory.
    pub path: PathBuf,
    /// The fork whose rules apply.
    pub fork: ForkName,
    /// The suite directory name, which groups related cases.
    pub suite: String,
    /// The case directory name, which is what test output should identify.
    pub name: String,
}

impl Case {
    /// A human-readable identifier for failure messages.
    ///
    /// Includes the two directory levels above the case, since case names repeat
    /// across handlers and a bare name would not say which one failed.
    pub fn id(&self) -> String {
        let handler = self
            .path
            .parent()
            .and_then(|suite| suite.parent())
            .and_then(|handler| handler.file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        format!("{}/{}/{}/{}", self.fork, handler, self.suite, self.name)
    }

    /// Whether the case carries the named file.
    ///
    /// Absence is meaningful: an operations case with no `post` expects the
    /// operation to be rejected.
    pub fn has(&self, name: &str) -> bool {
        self.path.join(format!("{name}.ssz_snappy")).is_file()
            || self.path.join(format!("{name}.yaml")).is_file()
    }

    /// Reads and decompresses `<name>.ssz_snappy`, returning the SSZ bytes.
    ///
    /// Containers whose shape depends on the fork are decoded by the caller,
    /// which knows the fork, so this stops at the bytes.
    pub fn ssz_bytes(&self, name: &str) -> Vec<u8> {
        let path = self.path.join(format!("{name}.ssz_snappy"));
        let compressed =
            fs::read(&path).unwrap_or_else(|err| panic!("reading {}: {err}", path.display()));
        snap::raw::Decoder::new()
            .decompress_vec(&compressed)
            .unwrap_or_else(|err| panic!("decompressing {}: {err}", path.display()))
    }

    /// Decodes `<name>.ssz_snappy` into a fork-independent container.
    pub fn ssz<T: SszDecode>(&self, name: &str) -> T {
        let bytes = self.ssz_bytes(name);
        T::from_ssz_bytes(&bytes)
            .unwrap_or_else(|err| panic!("decoding {} of {}: {err:?}", name, self.id()))
    }

    /// Decodes an indexed file such as `blocks_0.ssz_snappy`.
    pub fn ssz_bytes_indexed(&self, name: &str, index: usize) -> Vec<u8> {
        self.ssz_bytes(&format!("{name}_{index}"))
    }

    /// Parses `<name>.yaml`.
    pub fn yaml<T: DeserializeOwned>(&self, name: &str) -> T {
        let path = self.path.join(format!("{name}.yaml"));
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("reading {}: {err}", path.display()));
        serde_yaml_ng::from_str(&text)
            .unwrap_or_else(|err| panic!("parsing {}: {err}", path.display()))
    }

    /// Parses `<name>.yaml` if it exists.
    pub fn yaml_opt<T: DeserializeOwned>(&self, name: &str) -> Option<T> {
        self.path
            .join(format!("{name}.yaml"))
            .is_file()
            .then(|| self.yaml(name))
    }

    /// Whether this case's fork has a state transition this crate implements.
    ///
    /// The one gate every runner checks before running a case. Forks after
    /// [`HIGHEST_IMPLEMENTED_FORK`] fail this and must be routed to
    /// [`Report::skip`] rather than run, so a fixture release this crate has
    /// only partially caught up with is never misreported as fully covered.
    pub fn in_scope(&self) -> bool {
        self.fork <= HIGHEST_IMPLEMENTED_FORK
    }
}

/// Collects every case for one runner and handler across all supported forks.
///
/// `config` selects the fixture tree: [`PRESET`] for the preset-dependent
/// suites, or `"general"` for the configuration-independent ones. Forks this
/// crate does not implement are skipped, so an upstream release that adds a fork
/// does not break the build.
pub fn collect(config: &str, runner: &str, handler: &str) -> Vec<Case> {
    let root = fixture_root().join(config);
    let mut cases = Vec::new();

    for fork_entry in read_dir_sorted(&root) {
        let Some(fork) = fork_entry.file_name().to_str().and_then(ForkName::parse) else {
            continue;
        };

        let handler_dir = fork_entry.path().join(runner).join(handler);
        collect_suites(&handler_dir, fork, &mut |case| cases.push(case));
    }

    cases
}

/// Collects cases for one runner across every handler it has.
///
/// Returns pairs of handler name and case, which suits runners like
/// `epoch_processing` where the handler names the sub-function under test.
pub fn collect_all_handlers(config: &str, runner: &str) -> Vec<(String, Case)> {
    let root = fixture_root().join(config);
    let mut out = Vec::new();

    for fork_entry in read_dir_sorted(&root) {
        let Some(fork) = fork_entry.file_name().to_str().and_then(ForkName::parse) else {
            continue;
        };
        let runner_dir = fork_entry.path().join(runner);
        if !runner_dir.is_dir() {
            continue;
        }

        for handler_entry in read_dir_sorted(&runner_dir) {
            let handler = handler_entry.file_name().to_string_lossy().into_owned();
            // Walk this fork's handler directory directly. Delegating to
            // `collect` here would be wrong: `collect` walks every fork itself,
            // so nesting it inside this fork loop would yield each case once per
            // fork that happens to ship the runner.
            collect_suites(&handler_entry.path(), fork, &mut |case| {
                out.push((handler.clone(), case))
            });
        }
    }

    out
}

/// Walks the suite and case directories under one fork's handler directory.
///
/// Shared by both collectors so there is one definition of what a case directory
/// is, and so neither can drift from the other.
fn collect_suites(handler_dir: &Path, fork: ForkName, emit: &mut impl FnMut(Case)) {
    if !handler_dir.is_dir() {
        return;
    }

    for suite_entry in read_dir_sorted(handler_dir) {
        let suite = suite_entry.file_name().to_string_lossy().into_owned();
        for case_entry in read_dir_sorted(&suite_entry.path()) {
            emit(Case {
                path: case_entry.path(),
                fork,
                suite: suite.clone(),
                name: case_entry.file_name().to_string_lossy().into_owned(),
            });
        }
    }
}

/// Directory entries, sorted, so a failing run is reproducible and its output
/// is comparable between runs.
fn read_dir_sorted(path: &Path) -> Vec<fs::DirEntry> {
    let mut entries: Vec<_> = match fs::read_dir(path) {
        Ok(entries) => entries.filter_map(Result::ok).collect(),
        Err(_) => return Vec::new(),
    };
    entries.sort_by_key(fs::DirEntry::file_name);
    entries
}

/// Runs `run` over every case at once, returning the outcomes in fixture order.
///
/// Every runner is a loop over independent cases: each is a directory of inputs
/// and one expected output, sharing no state with its neighbours, so the loop was
/// the only thing holding a whole suite to a single core. The test harness does
/// run the suites concurrently, but that parallelism is as coarse as the suites
/// are uneven, and the slowest one alone sets the wall clock.
///
/// Rayon's pool is process-wide, and relying on that is the point rather than an
/// incidental detail: several suites call this at the same time, and one shared
/// pool keeps the total number of cases in flight at the core count however many
/// of them are running, where a pool per suite would oversubscribe by the number
/// of suites and multiply peak memory by it too, since a case in flight holds
/// whole beacon states.
///
/// Outcomes come back in the input order, which is the order the sequential loop
/// reported them in, so a failure list stays comparable between runs for the
/// same reason [`read_dir_sorted`] sorts.
pub fn map_cases<C, R>(cases: &[C], run: impl Fn(&C) -> R + Send + Sync) -> Vec<R>
where
    C: Send + Sync,
    R: Send,
{
    cases.par_iter().map(run).collect()
}

/// Judges a state transition against what the case expects.
///
/// The rule the whole fixture format rests on: a case with a `post` state must
/// succeed and land exactly on it, and a case *without* one must be rejected.
/// Getting the second half right is what keeps the suites honest, since an
/// implementation that accepted everything would otherwise pass every case that
/// ships a `post`.
///
/// Comparison is by `hash_tree_root` rather than field by field, because that is
/// the value consensus actually agrees on, and a mismatch anywhere in the state
/// changes it.
pub fn check_transition(
    case: &Case,
    outcome: Result<(), String>,
    state: &BeaconState,
) -> Result<(), String> {
    match (case.has("post"), outcome) {
        (true, Ok(())) => {
            let expected = BeaconState::from_ssz(case.fork, &case.ssz_bytes("post"))
                .map_err(|err| format!("the fixture's post-state does not decode: {err:?}"))?;
            let actual_root = state.hash_tree_root();
            let expected_root = expected.hash_tree_root();
            if actual_root != expected_root {
                return Err(format!(
                    "post-state root 0x{} != expected 0x{}",
                    hex::encode(actual_root.0),
                    hex::encode(expected_root.0)
                ));
            }
            Ok(())
        }
        (true, Err(err)) => Err(format!(
            "rejected, but the case expects a post-state: {err}"
        )),
        (false, Ok(())) => {
            Err("accepted, but the case has no post-state, so it must be rejected".to_string())
        }
        (false, Err(_)) => Ok(()),
    }
}

/// Accumulates per-case results so one run reports every failure instead of
/// stopping at the first, and so a suite that matched no case fails loudly.
///
/// Also accumulates skips, through [`Report::skip`], so that "not yet
/// implemented" and "matched nothing at all" stay distinguishable in
/// [`finish`](Report::finish)'s output: the former is expected and printed,
/// the latter is the "fixture layout or the suite name is wrong" failure this
/// harness has always guarded against.
pub struct Report {
    /// When the runner started, so [`finish`](Report::finish) can report how
    /// long the suite took. Printed per suite rather than left to the harness's
    /// one total, because that total cannot say which suite to look at.
    started: Instant,
    passed: usize,
    skipped: usize,
    /// Which forks the skipped cases came from, for the summary line.
    /// A set rather than a count per fork, since the count is rarely
    /// interesting and the *names* are what tell a reader how far behind the
    /// suite still is.
    skipped_forks: BTreeSet<ForkName>,
    failures: Vec<String>,
}

impl Default for Report {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            passed: 0,
            skipped: 0,
            skipped_forks: BTreeSet::new(),
            failures: Vec::new(),
        }
    }
}

impl Report {
    /// Starts a report, and with it the clock the suite is timed against, so a
    /// runner should build one before discovering its cases rather than after.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the outcome of one case.
    pub fn record(&mut self, case: &Case, outcome: Result<(), String>) {
        match outcome {
            Ok(()) => self.passed += 1,
            Err(message) => self.failures.push(format!("{}: {message}", case.id())),
        }
    }

    /// Records that `case` was not run because its fork is not yet
    /// implemented (see [`Case::in_scope`] and [`HIGHEST_IMPLEMENTED_FORK`]).
    ///
    /// Counting the skip, rather than just `continue`-ing past the case
    /// unrecorded, is what keeps a fixture release this crate has only
    /// partially caught up with from silently looking like full coverage:
    /// [`finish`](Report::finish) prints this count, and the forks it came
    /// from, alongside the pass/fail tally.
    pub fn skip(&mut self, case: &Case) {
        self.skipped += 1;
        self.skipped_forks.insert(case.fork);
    }

    /// Records one case's outcome, where `None` means the case was skipped.
    ///
    /// The half of [`map_cases`] that runs back on one thread. A runner's
    /// parallel closure cannot call [`record`](Report::record) or
    /// [`skip`](Report::skip) itself, since both need `&mut Report` and the
    /// closure is shared across the pool, so it returns what happened instead
    /// and this folds the sequence afterwards. Folding is cheap next to running
    /// the cases, and it keeps failure ordering deterministic.
    pub fn record_or_skip(&mut self, case: &Case, outcome: Option<Result<(), String>>) {
        match outcome {
            Some(outcome) => self.record(case, outcome),
            None => self.skip(case),
        }
    }

    /// Fails the test if any case failed, or if no case was even matched.
    ///
    /// A case that matched but was skipped still counts toward "matched
    /// something": the fixture layout and suite name are fine, this crate
    /// just is not caught up with every fork yet, and that is what the skip
    /// line below reports.
    pub fn finish(self, suite: &str) {
        assert!(
            self.passed > 0 || !self.failures.is_empty() || self.skipped > 0,
            "{suite} matched no fixture cases; the fixture layout or the suite name is wrong"
        );

        // Printed before the failure assert, not after. Panicking first would
        // throw away the pass and skip counts in exactly the situation they are
        // most useful: working out whether a suite failed on two cases or on two
        // hundred, and how much of the tree it even reached, without first
        // reading through every failure line.
        if self.skipped > 0 {
            let forks: Vec<String> = self.skipped_forks.iter().map(ForkName::to_string).collect();
            println!(
                "{suite}: {} cases skipped, from forks after {HIGHEST_IMPLEMENTED_FORK}: {}",
                self.skipped,
                forks.join(", ")
            );
        }
        println!(
            "{suite}: {} of {} cases passed in {:.1?}",
            self.passed,
            self.passed + self.failures.len(),
            self.started.elapsed()
        );

        assert!(
            self.failures.is_empty(),
            "{} of {} {suite} cases failed:\n{}",
            self.failures.len(),
            self.failures.len() + self.passed,
            self.failures.join("\n")
        );
    }
}
