//! Self-tests for the fixture harness.
//!
//! These check the harness itself, not the crate under test: that it finds the
//! fixture tree, that discovery reaches every supported fork, that it skips
//! forks this crate does not implement, and that snappy decompression produces
//! bytes an SSZ decoder accepts. A harness bug otherwise shows up as a suite
//! that quietly matches nothing.
//!
//! No case collection to guard here, unlike every other runner: these trials
//! are fixed in number and known before the fixture tree is even walked, so
//! there is no [`super::discovery_trial`] alongside them.

use ethlambda_beacon::ForkName;
use ethlambda_beacon::primitives::{HashTreeRoot as _, Root};
use libssz::{SszDecode as _, SszEncode as _};
use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libtest_mimic::Trial;

use super::{Case, PRESET, collect, fixture_root};

#[derive(serde::Deserialize)]
struct RootFile {
    root: String,
}

/// The specification's `Checkpoint`, declared here rather than imported.
///
/// This is the harness proving out the whole chain a container runner depends
/// on: raw-snappy decompression, SSZ decoding, merkleization, and re-encoding,
/// checked against a fixture's own expected root. `Checkpoint` is the smallest
/// container that exists in every fork, so it isolates that chain from anything
/// fork-specific. The real containers land with their own suites.
#[derive(Debug, Clone, PartialEq, SszEncode, SszDecode, HashTreeRoot)]
struct Checkpoint {
    epoch: u64,
    root: Root,
}

pub fn trials() -> Vec<Trial> {
    vec![
        Trial::test("harness/fixture_tree_is_present", || {
            let root = fixture_root();
            assert!(
                root.join(PRESET).is_dir(),
                "no {PRESET} fixtures under {}",
                root.display()
            );
            assert!(
                root.join("general").is_dir(),
                "no general fixtures under {}",
                root.display()
            );
            Ok(())
        }),
        Trial::test("harness/discovery_finds_a_known_suite", || {
            // Checkpoint exists in every fork's ssz_static suite, and is the smallest
            // container that does, which makes it a stable canary for discovery.
            let cases = collect(PRESET, "ssz_static", "Checkpoint");
            assert!(!cases.is_empty(), "no ssz_static/Checkpoint cases found");

            for case in &cases {
                assert!(
                    case.has("serialized"),
                    "{} has no serialized file",
                    case.id()
                );
                assert!(case.has("roots"), "{} has no roots file", case.id());
            }
            Ok(())
        }),
        Trial::test("harness/discovery_covers_every_supported_fork", || {
            let cases = collect(PRESET, "ssz_static", "Checkpoint");
            for fork in ForkName::ALL {
                assert!(
                    cases.iter().any(|case| case.fork == fork),
                    "discovery found no {fork} cases; the fixture release is expected to \
                     cover every fork this crate implements"
                );
            }
            Ok(())
        }),
        Trial::test("harness/discovery_skips_forks_out_of_scope", || {
            // The release ships suites for forks after fulu, and for standalone EIPs.
            // Those must not reach a runner, since this crate has no types for them.
            let cases = collect(PRESET, "ssz_static", "Checkpoint");
            for case in &cases {
                assert!(
                    ForkName::ALL.contains(&case.fork),
                    "{} is outside the implemented forks",
                    case.id()
                );
            }
            Ok(())
        }),
        Trial::test("harness/snappy_decompression_yields_decodable_ssz", || {
            let cases = collect(PRESET, "ssz_static", "Checkpoint");
            let case: &Case = cases.first().expect("at least one Checkpoint case");

            // A Checkpoint is an epoch and a root, so its SSZ encoding is fixed-length.
            let bytes = case.ssz_bytes("serialized");
            assert_eq!(
                bytes.len(),
                40,
                "a Checkpoint is a u64 epoch followed by a 32-byte root"
            );

            let roots: RootFile = case.yaml("roots");
            assert!(roots.root.starts_with("0x"), "roots.yaml holds a hex root");
            Ok(())
        }),
        Trial::test(
            "harness/container_round_trip_matches_the_fixture_root",
            || {
                for case in collect(PRESET, "ssz_static", "Checkpoint") {
                    let bytes = case.ssz_bytes("serialized");
                    let expected: RootFile = case.yaml("roots");

                    let checkpoint = Checkpoint::from_ssz_bytes(&bytes)
                        .map_err(|err| format!("{}: decode failed: {err:?}", case.id()))?;
                    let root = format!("0x{}", hex::encode(checkpoint.hash_tree_root().0));
                    if root != expected.root {
                        return Err(format!(
                            "{}: root {root} != expected {}",
                            case.id(),
                            expected.root
                        )
                        .into());
                    }
                    if checkpoint.to_ssz() != bytes {
                        return Err(format!(
                            "{}: re-encoding did not reproduce the fixture bytes",
                            case.id()
                        )
                        .into());
                    }
                }

                Ok(())
            },
        ),
    ]
}
