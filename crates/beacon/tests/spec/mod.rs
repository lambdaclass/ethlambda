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
mod genesis;
mod harness;
mod operations;
mod rewards;
mod sanity;
mod shuffling;
mod ssz_static;

use std::fs;
use std::path::{Path, PathBuf};

use ethlambda_beacon::ForkName;
use ethlambda_beacon::containers::BeaconState;
use libssz::SszDecode;
use serde::de::DeserializeOwned;

/// The configuration directory whose fixtures match the compiled-in preset.
pub const PRESET: &str = if cfg!(feature = "preset-minimal") {
    "minimal"
} else {
    "mainnet"
};

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
#[derive(Default)]
pub struct Report {
    passed: usize,
    failures: Vec<String>,
}

impl Report {
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

    /// Fails the test if any case failed, or if no case ran at all.
    pub fn finish(self, suite: &str) {
        assert!(
            self.passed > 0 || !self.failures.is_empty(),
            "{suite} matched no fixture cases; the fixture layout or the suite name is wrong"
        );
        assert!(
            self.failures.is_empty(),
            "{} of {} {suite} cases failed:\n{}",
            self.failures.len(),
            self.failures.len() + self.passed,
            self.failures.join("\n")
        );
        println!("{suite}: {} cases passed", self.passed);
    }
}
