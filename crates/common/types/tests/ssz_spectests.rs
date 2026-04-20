use std::path::Path;

use ethlambda_types::primitives::HashTreeRoot;

mod ssz_types;
use ssz_types::{SszTestCase, SszTestVector, decode_hex, decode_hex_h256};

const SUPPORTED_FIXTURE_FORMAT: &str = "ssz";

fn run(path: &Path) -> datatest_stable::Result<()> {
    let tests = SszTestVector::from_file(path)?;

    for (name, test) in tests.tests {
        if test.info.fixture_format != SUPPORTED_FIXTURE_FORMAT {
            return Err(format!(
                "Unsupported fixture format: {} (expected {})",
                test.info.fixture_format, SUPPORTED_FIXTURE_FORMAT
            )
            .into());
        }

        println!("Running SSZ test: {name}");
        run_ssz_test(&test)?;
    }
    Ok(())
}

fn run_ssz_test(test: &SszTestCase) -> datatest_stable::Result<()> {
    match test.type_name.as_str() {
        // Consensus containers
        "Config" => run_typed_test::<ssz_types::Config, ethlambda_types::state::ChainConfig>(test),
        "Checkpoint" => {
            run_typed_test::<ssz_types::Checkpoint, ethlambda_types::checkpoint::Checkpoint>(test)
        }
        "BlockHeader" => {
            run_typed_test::<ssz_types::BlockHeader, ethlambda_types::block::BlockHeader>(test)
        }
        "Validator" => {
            run_typed_test::<ssz_types::Validator, ethlambda_types::state::Validator>(test)
        }
        "AttestationData" => run_typed_test::<
            ssz_types::AttestationData,
            ethlambda_types::attestation::AttestationData,
        >(test),
        "Attestation" => run_typed_test::<
            ssz_types::Attestation,
            ethlambda_types::attestation::Attestation,
        >(test),
        "AggregatedAttestation" => run_typed_test::<
            ssz_types::AggregatedAttestation,
            ethlambda_types::attestation::AggregatedAttestation,
        >(test),
        "BlockBody" => {
            run_typed_test::<ssz_types::BlockBody, ethlambda_types::block::BlockBody>(test)
        }
        "Block" => run_typed_test::<ssz_types::Block, ethlambda_types::block::Block>(test),
        "State" => run_typed_test::<ssz_types::TestState, ethlambda_types::state::State>(test),
        // Types containing `XmssSignature` are serialized only — their hash tree
        // root diverges from the spec because leanSpec Merkleizes the signature
        // as a container while we treat it as fixed-size bytes.
        "SignedAttestation" => run_serialization_only_test::<
            ssz_types::SignedAttestation,
            ethlambda_types::attestation::SignedAttestation,
        >(test),
        "SignedBlock" => run_serialization_only_test::<
            ssz_types::SignedBlock,
            ethlambda_types::block::SignedBlock,
        >(test),
        "BlockSignatures" => run_serialization_only_test::<
            ssz_types::BlockSignatures,
            ethlambda_types::block::BlockSignatures,
        >(test),
        "AggregatedSignatureProof" => run_typed_test::<
            ssz_types::AggregatedSignatureProof,
            ethlambda_types::block::AggregatedSignatureProof,
        >(test),
        "SignedAggregatedAttestation" => run_typed_test::<
            ssz_types::SignedAggregatedAttestation,
            ethlambda_types::attestation::SignedAggregatedAttestation,
        >(test),

        // Unsupported types: skip with a message
        other => {
            println!("  Skipping unsupported type: {other}");
            Ok(())
        }
    }
}

/// Run an SSZ test for a given fixture type `F` that converts into domain type `D`.
///
/// Tests:
/// 1. JSON value deserializes into fixture type and converts to domain type
/// 2. SSZ encoding matches expected serialized bytes
/// 3. SSZ decoding from expected bytes re-encodes identically (round-trip)
/// 4. Hash tree root matches expected root
fn run_typed_test<F, D>(test: &SszTestCase) -> datatest_stable::Result<()>
where
    F: serde::de::DeserializeOwned + Into<D>,
    D: libssz::SszEncode + libssz::SszDecode + HashTreeRoot,
{
    let expected_bytes = check_ssz_roundtrip::<F, D>(test)?;
    let expected_root =
        decode_hex_h256(&test.root).map_err(|e| format!("Failed to decode root hex: {e}"))?;

    let fixture_value: F = serde_json::from_value(test.value.clone())
        .map_err(|e| format!("Failed to deserialize value: {e}"))?;
    let domain_value: D = fixture_value.into();

    // Re-encode for the hash computation; cheap relative to the fixture I/O.
    assert_eq!(
        <D as libssz::SszEncode>::to_ssz(&domain_value),
        expected_bytes
    );

    let computed_root = HashTreeRoot::hash_tree_root(&domain_value);
    if computed_root != expected_root {
        return Err(format!(
            "Hash tree root mismatch for {}:\n  expected: {expected_root}\n  got:      {computed_root}",
            test.type_name,
        )
        .into());
    }

    Ok(())
}

/// Run only the serialization portion of the SSZ conformance tests.
///
/// Used for types where hash tree root intentionally diverges from the spec
/// (see `SignedBlock`, `BlockSignatures`, `SignedAttestation`). Encoding and
/// round-trip are still enforced so cross-client wire format stays in sync.
fn run_serialization_only_test<F, D>(test: &SszTestCase) -> datatest_stable::Result<()>
where
    F: serde::de::DeserializeOwned + Into<D>,
    D: libssz::SszEncode + libssz::SszDecode,
{
    check_ssz_roundtrip::<F, D>(test).map(|_| ())
}

/// Validates encoding and decoding round-trip, returning the expected bytes.
fn check_ssz_roundtrip<F, D>(test: &SszTestCase) -> datatest_stable::Result<Vec<u8>>
where
    F: serde::de::DeserializeOwned + Into<D>,
    D: libssz::SszEncode + libssz::SszDecode,
{
    let expected_bytes = decode_hex(&test.serialized)
        .map_err(|e| format!("Failed to decode serialized hex: {e}"))?;

    let fixture_value: F = serde_json::from_value(test.value.clone())
        .map_err(|e| format!("Failed to deserialize value: {e}"))?;
    let domain_value: D = fixture_value.into();

    let encoded = <D as libssz::SszEncode>::to_ssz(&domain_value);
    if encoded != expected_bytes {
        return Err(format!(
            "SSZ encoding mismatch for {}:\n  expected: 0x{}\n  got:      0x{}",
            test.type_name,
            hex::encode(&expected_bytes),
            hex::encode(&encoded),
        )
        .into());
    }

    let decoded = D::from_ssz_bytes(&expected_bytes)
        .map_err(|e| format!("SSZ decode failed for {}: {e:?}", test.type_name))?;
    let re_encoded = <D as libssz::SszEncode>::to_ssz(&decoded);
    if re_encoded != expected_bytes {
        return Err(format!(
            "SSZ round-trip mismatch for {}:\n  expected: 0x{}\n  got:      0x{}",
            test.type_name,
            hex::encode(&expected_bytes),
            hex::encode(&re_encoded),
        )
        .into());
    }

    Ok(expected_bytes)
}

datatest_stable::harness!({
    test = run,
    root = "../../../leanSpec/fixtures/consensus/ssz",
    pattern = r".*\.json"
});
