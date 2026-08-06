//! Builds each fuzz target's seed corpus from the real fixture tree.
//!
//! Run via `../seed_corpus.sh`, or directly as `cargo run --example
//! seed_corpus --release -- [target ...]` from this directory, where each
//! optional `target` is one of `state_transition`, `epoch_processing`, or
//! `ssz_roundtrip`; with none given, all three are (re)built.
//!
//! See `README.md` for why the corpus is seeded from fixtures at all, and
//! `src/lib.rs`'s framing doc comments for the exact byte layout each
//! target's corpus entries follow. In short: this decompresses the fixtures'
//! `.ssz_snappy` files once, here, so that every target's corpus already
//! holds plain SSZ bytes and no target needs a snappy dependency of its own
//! just to make sense of its seeds. Entries land in
//! `corpus/<target>/<preset>/<case>`, one subdirectory per preset rather
//! than flat, so a `mainnet`-preset build is never accidentally fed a
//! `minimal`-shaped seed or the reverse; see `write_seed`'s doc comment.

use std::fs;
use std::path::{Path, PathBuf};

use ethlambda_beacon::ForkName;

/// The preset/fork pairs seeded today.
///
/// Kept in step with `ethlambda_beacon_fuzz::IMPLEMENTED_FORKS`: seeding a
/// fork this crate cannot yet run a comparison against would only fill the
/// corpus with inputs every target discards on its first line, which is
/// wasted disk space and wasted mutation time for no coverage in return.
/// Extend this alongside that list.
const PRESETS_AND_FORKS: &[(&str, ForkName)] =
    &[("mainnet", ForkName::Phase0), ("minimal", ForkName::Phase0)];

/// The fixture suite seeded from. `sanity/blocks` is the natural choice: each
/// case already pairs a pre-state with at least one signed block that is
/// known to apply to it, which is exactly the shape `state_transition`'s
/// corpus needs, and every other target's corpus is a strict subset of the
/// same information (just the state, for `epoch_processing` and
/// `ssz_roundtrip`).
const RUNNER: &str = "sanity";
const HANDLER: &str = "blocks";

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../consensus-spec-tests/tests")
}

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus")
}

/// Decompresses a raw-snappy `.ssz_snappy` fixture file.
///
/// Fixture files are raw snappy, not the framed format: see this repository's
/// `crates/beacon/tests/spec/mod.rs` doc comment, which this mirrors.
fn read_ssz_snappy(path: &Path) -> Vec<u8> {
    let compressed =
        fs::read(path).unwrap_or_else(|err| panic!("reading {}: {err}", path.display()));
    snap::raw::Decoder::new()
        .decompress_vec(&compressed)
        .unwrap_or_else(|err| panic!("decompressing {}: {err}", path.display()))
}

/// The bare integer `meta.yaml`'s `blocks_count` field holds.
///
/// Hand-parsed instead of pulling in a YAML parser: every case's `meta.yaml`
/// this script reads has exactly one field this script needs, so a small
/// string search is the simpler dependency to carry for a seeding script that
/// runs once and is not part of any fuzz target's own binary.
fn blocks_count(meta_path: &Path) -> usize {
    let text = fs::read_to_string(meta_path)
        .unwrap_or_else(|err| panic!("reading {}: {err}", meta_path.display()));
    text.lines()
        .find_map(|line| line.strip_prefix("blocks_count:"))
        .unwrap_or_else(|| panic!("{} has no blocks_count field", meta_path.display()))
        .trim()
        .parse()
        .unwrap_or_else(|err| panic!("parsing blocks_count in {}: {err}", meta_path.display()))
}

/// Encodes the `state_transition` and `epoch_processing`/`ssz_roundtrip`
/// framings; see `ethlambda_beacon_fuzz::split_two` and `::split_one`'s doc
/// comments for the layouts these are the write side of.
fn frame_one(fork_byte: u8, state: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + state.len());
    out.push(fork_byte);
    out.extend_from_slice(state);
    out
}

fn frame_two(fork_byte: u8, state: &[u8], block: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + state.len() + block.len());
    out.push(fork_byte);
    out.extend_from_slice(&(state.len() as u32).to_le_bytes());
    out.extend_from_slice(state);
    out.extend_from_slice(block);
    out
}

/// Writes one corpus entry, kept in a preset-named subdirectory of the
/// target's corpus directory rather than flat alongside every other preset's.
///
/// A `mainnet`-shaped seed simply fails to decode under a `minimal` build and
/// gets discarded, and vice versa, most of the time; the risk this avoids is
/// the coincidental case where it does not (see `README.md`'s "Differing
/// preset" false-positive note), and a corpus that never mixes the two
/// removes the possibility entirely rather than relying on that coincidence
/// staying rare. `cargo fuzz run` takes the corpus directory as an explicit
/// argument, so pointing a `--features preset-minimal` run at
/// `corpus/<target>/minimal` (and a default run at `corpus/<target>/mainnet`)
/// is one flag away; see `README.md`'s "Running the targets" section.
fn write_seed(target: &str, preset: &str, name: &str, bytes: &[u8]) {
    let dir = corpus_root().join(target).join(preset);
    fs::create_dir_all(&dir).unwrap_or_else(|err| panic!("creating {}: {err}", dir.display()));
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap_or_else(|err| panic!("writing {}: {err}", path.display()));
}

fn main() {
    let requested: Vec<String> = std::env::args().skip(1).collect();
    let wants = |target: &str| requested.is_empty() || requested.iter().any(|t| t == target);

    let mut seeded = 0usize;

    for &(preset, fork) in PRESETS_AND_FORKS {
        let fork_byte = ForkName::ALL
            .iter()
            .position(|&f| f == fork)
            .expect("fork is in ForkName::ALL") as u8;

        let handler_dir = fixture_root()
            .join(preset)
            .join(fork.as_str())
            .join(RUNNER)
            .join(HANDLER);
        let Ok(suites) = fs::read_dir(&handler_dir) else {
            eprintln!(
                "skipping {} (not on disk; run `make consensus-spec-tests` first)",
                handler_dir.display()
            );
            continue;
        };

        for suite in suites.filter_map(Result::ok) {
            let Ok(cases) = fs::read_dir(suite.path()) else {
                continue;
            };
            for case in cases.filter_map(Result::ok) {
                let case_path = case.path();
                let case_name =
                    format!("{}_{}", fork.as_str(), case.file_name().to_string_lossy(),);

                let state = read_ssz_snappy(&case_path.join("pre.ssz_snappy"));

                if wants("epoch_processing") {
                    write_seed(
                        "epoch_processing",
                        preset,
                        &case_name,
                        &frame_one(fork_byte, &state),
                    );
                }
                if wants("ssz_roundtrip") {
                    write_seed(
                        "ssz_roundtrip",
                        preset,
                        &case_name,
                        &frame_one(fork_byte, &state),
                    );
                }

                if wants("state_transition") && blocks_count(&case_path.join("meta.yaml")) >= 1 {
                    let block = read_ssz_snappy(&case_path.join("blocks_0.ssz_snappy"));
                    write_seed(
                        "state_transition",
                        preset,
                        &case_name,
                        &frame_two(fork_byte, &state, &block),
                    );
                }

                seeded += 1;
            }
        }
    }

    assert!(
        seeded > 0,
        "seeded no cases at all; check that consensus-spec-tests fixtures are on disk \
         and that PRESETS_AND_FORKS names real preset/fork directories"
    );
    println!("seeded corpus entries from {seeded} fixture cases");
}
