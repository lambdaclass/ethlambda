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

pub mod bls;
pub mod epoch_processing;
pub mod fork;
pub mod fork_choice;
pub mod genesis;
pub mod harness;
pub mod kzg;
pub mod operations;
pub mod rewards;
pub mod sanity;
pub mod shuffling;
pub mod ssz_static;
pub mod transition;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use ethlambda_beacon::ForkName;
use ethlambda_beacon::containers::BeaconState;
use libssz::SszDecode;
use libtest_mimic::{Failed, Trial};
use serde::de::DeserializeOwned;

/// The configuration directory whose fixtures match the compiled-in preset.
pub const PRESET: &str = if cfg!(feature = "preset-minimal") {
    "minimal"
} else {
    "mainnet"
};

/// The newest fork whose state transition this crate implements.
///
/// Every runner gates on this, and a case past it becomes an ignored test
/// rather than a missing one, so the output can never imply more coverage than
/// exists. Turning on a fork is a one-line change here once its state
/// transition lands: bump this constant and every runner picks up that fork's
/// cases on its own, since [`case_trial`] reads the gate itself. A runner may
/// still need its own edit to *map* a fork's new or changed handlers to the
/// right function, since that mapping is specific to each runner; only the gate
/// is one line.
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
    /// [`HIGHEST_IMPLEMENTED_FORK`] fail this, and [`case_trial`] marks such a
    /// case ignored rather than running it, so a fixture release this crate has
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

/// Fixture fork directories this crate deliberately does not model.
///
/// `gloas` is the fork after fulu, and this crate stops at fulu. `eip7805` is not
/// a fork in the sequence at all: the release ships a directory per in-flight EIP
/// whose cases are generated against a variant of some fork's rules, so there is
/// no [`ForkName`] for it to parse as.
///
/// Naming them is not bookkeeping for its own sake. A directory [`ForkName::parse`]
/// does not recognize is how [`collect`] skips a fork, and that skip is *silent*
/// in a way [`Case::in_scope`] is not: the cases never become tests at all, so
/// they are not counted as ignored either, and nothing in the output says they
/// exist. This module's own doc promises the opposite, that a suite which stops
/// matching fails rather than reporting green, and an unparsed fork slips past
/// [`HIGHEST_IMPLEMENTED_FORK`] entirely because the gate never sees the case.
/// So [`fixture_fork_trials`] checks this list against the tree instead.
pub const UNMODELED_FORKS: &[&str] = &["gloas", "eip7805"];

/// Accounts for every fork directory the fixture release ships.
///
/// Reports each directory in [`UNMODELED_FORKS`] as an ignored test, so a
/// deliberate exclusion is visible in the output rather than inferred from its
/// absence, and fails when the tree holds a fork directory that is neither
/// parseable nor listed. That failure is the point: a release that adds a fork
/// would otherwise have its cases skipped without a trace, and someone has to
/// decide whether to implement it or name it here.
pub fn fixture_fork_trials() -> Vec<Trial> {
    let mut unknown: Vec<String> = Vec::new();
    let mut unmodeled: BTreeSet<String> = BTreeSet::new();

    // Both trees, since `collect` is called with `general` for the
    // configuration-independent suites as well as with the preset's own name.
    for config in [PRESET, "general"] {
        for entry in read_dir_sorted(&fixture_root().join(config)) {
            if !entry.path().is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if ForkName::parse(&name).is_some() {
                continue;
            }
            if UNMODELED_FORKS.contains(&name.as_str()) {
                unmodeled.insert(name);
            } else {
                unknown.push(format!("{config}/{name}"));
            }
        }
    }

    let mut trials: Vec<Trial> = unmodeled
        .into_iter()
        .map(|name| {
            Trial::test(format!("fixture_forks/unmodeled/{name}"), || Ok(()))
                .with_ignored_flag(true)
        })
        .collect();

    trials.push(Trial::test(
        "fixture_forks/every_directory_is_accounted_for",
        move || {
            if unknown.is_empty() {
                return Ok(());
            }
            Err(Failed::from(format!(
                "the fixture release ships fork directories this harness neither parses nor \
                 lists in UNMODELED_FORKS, so every case under them is skipped without \
                 appearing anywhere in the output: {}",
                unknown.join(", ")
            )))
        },
    ));

    trials
}

/// Wraps one fixture case as a test of its own.
///
/// Each case becomes a separate entry in the test binary, named for the case
/// rather than for the suite around it, so a failure points at the one case that
/// failed and every other case in that suite still reports its own result. The
/// suites used to be one test apiece, aggregating outcomes and failing as a
/// whole, which meant a single bad case marked thousands of passing ones as part
/// of a failed test and the name in the output was the suite's.
///
/// The name is prefixed with `runner` so that a filter can select a whole suite
/// (`cargo test --test spec_tests -- operations`) as well as one case. The
/// runner name is not part of [`Case::id`], which starts at the fork, so nothing
/// is repeated here.
///
/// A case whose fork this crate does not implement is marked ignored rather than
/// run, which is what [`Case::in_scope`] gates. The harness used to tally those
/// itself and print the count; the test harness counts ignored tests already,
/// and names each one, which is strictly more than the tally said.
///
/// A panic inside `run` fails this case alone: the harness catches it per test.
/// So a fixture that will not decode takes its own case down and no other.
pub fn case_trial(
    runner: &str,
    case: Case,
    run: impl FnOnce(&Case) -> Result<(), String> + Send + 'static,
) -> Trial {
    let ignored = !case.in_scope();
    let name = format!("{runner}/{}", case.id());
    Trial::test(name, move || run(&case).map_err(Failed::from)).with_ignored_flag(ignored)
}

/// Asserts a suite matched at least one fixture case.
///
/// The aggregate each suite used to report through carried this check, and
/// dropping it along with that aggregate would have quietly given up the thing
/// it guarded: a suite whose
/// fixtures moved, or whose runner or handler name went stale upstream, matches
/// nothing, and a run of no cases at all passes. Per-case tests make that worse
/// rather than better, since a suite that matches nothing now contributes no
/// tests to even look for. Hence one test per suite whose whole job is to fail
/// when the suite is empty.
///
/// A case that matched but was skipped still counts as matching: the fixture
/// layout is fine, this crate just does not implement that fork yet, which is
/// what the ignored tests report.
pub fn discovery_trial(runner: &str, matched: usize) -> Trial {
    let runner = runner.to_string();
    Trial::test(format!("{runner}/matched_fixture_cases"), move || {
        if matched == 0 {
            return Err(Failed::from(format!(
                "{runner} matched no fixture cases; the fixture layout or the suite name is wrong"
            )));
        }
        Ok(())
    })
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
