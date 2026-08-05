//! Self-tests for the fixture harness.
//!
//! These check the harness itself, not the crate under test: that it finds the
//! fixture tree, that discovery reaches every supported fork, that it skips
//! forks this crate does not implement, and that snappy decompression produces
//! bytes an SSZ decoder accepts. A harness bug otherwise shows up as a suite
//! that quietly matches nothing.

use ethlambda_beacon::ForkName;
use ethlambda_beacon::primitives::{HashTreeRoot as _, Root};
use libssz::{SszDecode as _, SszEncode as _};
use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};

use super::{Case, PRESET, collect, fixture_root};

#[test]
fn fixture_tree_is_present() {
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
}

#[test]
fn discovery_finds_a_known_suite() {
    // Checkpoint exists in every fork's ssz_static suite, and is the smallest
    // container that does, which makes it a stable canary for discovery.
    let cases = collect(PRESET, "ssz_static", "Checkpoint");
    assert!(!cases.is_empty(), "no ssz_static/Checkpoint cases found");

    for case in &cases {
        assert!(case.has("serialized"), "{} has no serialized file", case.id());
        assert!(case.has("roots"), "{} has no roots file", case.id());
    }
}

#[test]
fn discovery_covers_every_supported_fork() {
    let cases = collect(PRESET, "ssz_static", "Checkpoint");
    for fork in ForkName::ALL {
        assert!(
            cases.iter().any(|case| case.fork == fork),
            "discovery found no {fork} cases; the fixture release is expected to \
             cover every fork this crate implements"
        );
    }
}

#[test]
fn discovery_skips_forks_out_of_scope() {
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
}

#[test]
fn snappy_decompression_yields_decodable_ssz() {
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
}

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

#[test]
fn container_round_trip_matches_the_fixture_root() {
    let mut report = super::Report::new();

    for case in collect(PRESET, "ssz_static", "Checkpoint") {
        let bytes = case.ssz_bytes("serialized");
        let expected: RootFile = case.yaml("roots");

        let outcome = match Checkpoint::from_ssz_bytes(&bytes) {
            Err(err) => Err(format!("decode failed: {err:?}")),
            Ok(checkpoint) => {
                let root = format!("0x{}", hex::encode(checkpoint.hash_tree_root().0));
                if root != expected.root {
                    Err(format!("root {root} != expected {}", expected.root))
                } else if checkpoint.to_ssz() != bytes {
                    Err("re-encoding did not reproduce the fixture bytes".to_string())
                } else {
                    Ok(())
                }
            }
        };
        report.record(&case, outcome);
    }

    report.finish("ssz_static/Checkpoint");
}
