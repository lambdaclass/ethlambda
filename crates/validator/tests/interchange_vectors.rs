//! EIP-3076's shared interchange test vectors
//! (`eth-clients/slashing-protection-interchange-tests`), run against
//! `SlashingProtection`.
//!
//! Each case starts from an empty record, then for every step imports the
//! step's interchange and attempts its blocks and attestations, each of which
//! must be allowed or refused as the case says. This client keeps EIP-3076's
//! minimal watermarks, so the expectation read is `should_succeed`, the
//! minimal strategy's, rather than `should_succeed_complete`.
//!
//! The vectors are a download: `make slashing-protection-interchange-tests`,
//! which `make test` runs first.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use ethlambda_types::beacon::containers::shared::{AttestationData, Checkpoint};
use ethlambda_types::beacon::primitives::{BlsPubkey, H256, Root};
use ethlambda_validator::beacon_node::dto::parse_pubkey;
use ethlambda_validator::slashing_protection::SlashingProtection;
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    name: String,
    genesis_validators_root: String,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
struct Step {
    should_succeed: bool,
    contains_slashable_data: bool,
    interchange: serde_json::Value,
    blocks: Vec<Block>,
    attestations: Vec<Attestation>,
}

#[derive(Deserialize)]
struct Block {
    pubkey: String,
    slot: String,
    should_succeed: bool,
}

#[derive(Deserialize)]
struct Attestation {
    pubkey: String,
    source_epoch: String,
    target_epoch: String,
    should_succeed: bool,
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../slashing-protection-interchange-tests/tests/generated")
}

#[test]
fn eip_3076_interchange_vectors() {
    let dir = vectors_dir();
    assert!(
        dir.is_dir(),
        "{} is missing: run `make slashing-protection-interchange-tests`",
        dir.display()
    );

    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("reads the vectors directory")
        .map(|entry| entry.expect("reads an entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no vectors in {}", dir.display());

    let failures: Vec<String> = paths
        .iter()
        .filter_map(|path| {
            let text = std::fs::read_to_string(path).expect("reads a vector");
            let case: Case = serde_json::from_str(&text).expect("parses a vector");
            run(&case)
                .err()
                .map(|reason| format!("{}: {reason}", case.name))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} vectors failed:\n{}",
        failures.len(),
        paths.len(),
        failures.join("\n")
    );
}

fn run(case: &Case) -> Result<(), String> {
    let root = parse_root(&case.genesis_validators_root)?;

    // The vectors start from an empty database in which any validator may
    // sign, so every key a case signs for is registered as never having signed.
    let mut keys: Vec<BlsPubkey> = Vec::new();
    let mut seen = HashSet::new();
    for step in &case.steps {
        let texts = step.blocks.iter().map(|block| &block.pubkey).chain(
            step.attestations
                .iter()
                .map(|attestation| &attestation.pubkey),
        );
        for text in texts {
            let pubkey = parse_pubkey(text).map_err(|err| err.to_string())?;
            if seen.insert(pubkey.0) {
                keys.push(pubkey);
            }
        }
    }

    let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
    let mut protection =
        SlashingProtection::open(dir.path(), root, &keys, true).map_err(|err| err.to_string())?;

    for (index, step) in case.steps.iter().enumerate() {
        let imported = protection.import(&step.interchange.to_string());
        match (imported.is_ok(), step.should_succeed) {
            (true, true) | (false, false) => {}
            // The README lets an importer refuse an interchange holding
            // slashable data, in which case the rest of the case is skipped.
            // This one absorbs it instead, so reaching here is still a
            // failure: it would mean an import was refused for some other
            // reason.
            (false, true) => {
                return Err(format!(
                    "step {index}: import failed but should succeed (slashable data: {}): {}",
                    step.contains_slashable_data,
                    imported
                        .err()
                        .map(|err| err.to_string())
                        .unwrap_or_default()
                ));
            }
            (true, false) => {
                return Err(format!("step {index}: import succeeded but should fail"));
            }
        }

        for (position, block) in step.blocks.iter().enumerate() {
            let pubkey = parse_pubkey(&block.pubkey).map_err(|err| err.to_string())?;
            let slot = parse_u64(&block.slot)?;
            let allowed = protection
                .check_and_record_block(&pubkey, slot)
                .map_err(|err| err.to_string())?
                .is_ok();
            if allowed != block.should_succeed {
                return Err(format!(
                    "step {index}, block {position} at slot {slot}: allowed {allowed}, \
                     expected {}",
                    block.should_succeed
                ));
            }
        }

        for (position, attestation) in step.attestations.iter().enumerate() {
            let pubkey = parse_pubkey(&attestation.pubkey).map_err(|err| err.to_string())?;
            let source = parse_u64(&attestation.source_epoch)?;
            let target = parse_u64(&attestation.target_epoch)?;
            let verdicts = protection
                .check_and_record_attestations(&[pubkey], &data(source, target))
                .map_err(|err| err.to_string())?;
            let allowed = verdicts.first().is_some_and(|verdict| verdict.is_ok());
            if allowed != attestation.should_succeed {
                return Err(format!(
                    "step {index}, attestation {position} ({source} -> {target}): allowed \
                     {allowed}, expected {}",
                    attestation.should_succeed
                ));
            }
        }
    }
    Ok(())
}

/// Only the epochs are judged; the rest of the data is filler.
fn data(source: u64, target: u64) -> AttestationData {
    AttestationData {
        slot: target * 32,
        index: 0,
        beacon_block_root: Root::ZERO,
        source: Checkpoint {
            epoch: source,
            root: Root::ZERO,
        },
        target: Checkpoint {
            epoch: target,
            root: Root::ZERO,
        },
    }
}

fn parse_u64(text: &str) -> Result<u64, String> {
    text.parse().map_err(|err| format!("{text:?}: {err}"))
}

fn parse_root(text: &str) -> Result<Root, String> {
    let bytes = hex::decode(text.trim_start_matches("0x")).map_err(|err| err.to_string())?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{text} is not 32 bytes"))?;
    Ok(H256(bytes))
}
