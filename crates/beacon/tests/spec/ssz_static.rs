//! The `ssz_static` runner.
//!
//! For each case: decode `serialized.ssz_snappy`, check its `hash_tree_root`
//! against `roots.yaml`, and check that re-encoding reproduces the fixture's
//! bytes exactly. That covers all three of the things a container has to get
//! right, and the round trip catches a field that decodes but encodes back
//! differently, which a root check alone can miss.
//!
//! The case's `value.yaml` is deliberately unused. Reading it would mean a serde
//! implementation for every container, and it tests nothing the other two files
//! do not already pin down.
//!
//! Containers this crate has not defined yet are counted and reported rather
//! than passed over quietly, so the output never implies more coverage than
//! there is.

use std::collections::BTreeSet;

use ethlambda_beacon::ForkName;
use ethlambda_beacon::containers::{phase0, shared};
use ethlambda_beacon::primitives::{HashTreeRoot, Root};
use libssz::{SszDecode, SszEncode};

use super::{Case, PRESET, Report, collect_all_handlers};

/// Decodes a case, then checks its root and its re-encoding.
fn check<T>(case: &Case) -> Result<(), String>
where
    T: SszDecode + SszEncode + HashTreeRoot,
{
    let bytes = case.ssz_bytes("serialized");

    let value = T::from_ssz_bytes(&bytes).map_err(|err| format!("decode failed: {err:?}"))?;

    let expected: RootFile = case.yaml("roots");
    let expected_root: Root = parse_root(&expected.root);
    // Disambiguated because the generic bound brings both this crate's
    // convenience trait and libssz's underlying one into scope.
    let actual = HashTreeRoot::hash_tree_root(&value);
    if actual != expected_root {
        return Err(format!(
            "hash_tree_root 0x{} != expected {}",
            hex::encode(actual.0),
            expected.root
        ));
    }

    let reencoded = value.to_ssz();
    if reencoded != bytes {
        return Err(format!(
            "re-encoding produced {} bytes, fixture has {}",
            reencoded.len(),
            bytes.len()
        ));
    }

    Ok(())
}

#[derive(serde::Deserialize)]
struct RootFile {
    root: String,
}

fn parse_root(hex_root: &str) -> Root {
    let stripped = hex_root.strip_prefix("0x").unwrap_or(hex_root);
    let bytes = hex::decode(stripped).expect("roots.yaml holds a hex string");
    Root::from_slice(&bytes)
}

#[test]
fn ssz_static() {
    let mut report = Report::new();
    let mut unimplemented: BTreeSet<String> = BTreeSet::new();

    for (handler, case) in collect_all_handlers(PRESET, "ssz_static") {
        let fork = case.fork;

        // The fork-invariant containers are checked against every fork's cases,
        // since a container that does not change shape should decode identically
        // under all of them. That is coverage for free, and it would catch a
        // container wrongly believed to be fork-invariant.
        let outcome = match handler.as_str() {
            "Fork" => check::<shared::Fork>(&case),
            "ForkData" => check::<shared::ForkData>(&case),
            "Checkpoint" => check::<shared::Checkpoint>(&case),
            "Validator" => check::<shared::Validator>(&case),
            "AttestationData" => check::<shared::AttestationData>(&case),
            "Eth1Data" => check::<shared::Eth1Data>(&case),
            "Eth1Block" => check::<shared::Eth1Block>(&case),
            "DepositMessage" => check::<shared::DepositMessage>(&case),
            "DepositData" => check::<shared::DepositData>(&case),
            "Deposit" => check::<shared::Deposit>(&case),
            "SigningData" => check::<shared::SigningData>(&case),
            "HistoricalBatch" => check::<shared::HistoricalBatch>(&case),
            "HistoricalSummary" => check::<shared::HistoricalSummary>(&case),
            "BeaconBlockHeader" => check::<shared::BeaconBlockHeader>(&case),
            "SignedBeaconBlockHeader" => check::<shared::SignedBeaconBlockHeader>(&case),
            "ProposerSlashing" => check::<shared::ProposerSlashing>(&case),
            "VoluntaryExit" => check::<shared::VoluntaryExit>(&case),
            "SignedVoluntaryExit" => check::<shared::SignedVoluntaryExit>(&case),

            // Electra reshapes the attestation containers, widening the
            // aggregation bits and attesting indices from one committee to a
            // whole slot's worth, so phase0's definitions hold only through
            // deneb.
            "Attestation" if fork <= ForkName::Deneb => check::<phase0::Attestation>(&case),
            "IndexedAttestation" if fork <= ForkName::Deneb => {
                check::<phase0::IndexedAttestation>(&case)
            }
            "AttesterSlashing" if fork <= ForkName::Deneb => {
                check::<phase0::AttesterSlashing>(&case)
            }
            "AggregateAndProof" if fork <= ForkName::Deneb => {
                check::<phase0::AggregateAndProof>(&case)
            }
            "SignedAggregateAndProof" if fork <= ForkName::Deneb => {
                check::<phase0::SignedAggregateAndProof>(&case)
            }
            "PendingAttestation" => check::<phase0::PendingAttestation>(&case),

            // The state and the block change shape in almost every fork.
            "BeaconState" if fork == ForkName::Phase0 => check::<phase0::BeaconState>(&case),
            "BeaconBlock" if fork == ForkName::Phase0 => check::<phase0::BeaconBlock>(&case),
            "BeaconBlockBody" if fork == ForkName::Phase0 => {
                check::<phase0::BeaconBlockBody>(&case)
            }
            "SignedBeaconBlock" if fork == ForkName::Phase0 => {
                check::<phase0::SignedBeaconBlock>(&case)
            }

            _ => {
                unimplemented.insert(format!("{fork}/{handler}"));
                continue;
            }
        };

        report.record(&case, outcome);
    }

    if !unimplemented.is_empty() {
        println!(
            "ssz_static: {} container/fork pairs not implemented yet:\n  {}",
            unimplemented.len(),
            unimplemented.iter().cloned().collect::<Vec<_>>().join("\n  ")
        );
    }

    report.finish("ssz_static");
}
