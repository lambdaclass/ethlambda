use std::collections::HashMap;
use std::path::Path;

// `BlockBody` and `TestState` re-exports are unused while the M6 schema
// skip is active in `ssz_spectests.rs` (the dispatch arms are commented
// out). Keep them re-exported so the skip can be lifted by editing only
// `ssz_spectests.rs` once leanSpec ships the executionPayload schema.
// TODO(M6): drop the allow once the dispatch uses these again.
#[allow(unused_imports)]
pub use ethlambda_test_fixtures::{
    AggregatedAttestation, AttestationData, Block, BlockBody, BlockHeader, Checkpoint, Config,
    TestInfo, TestState, Validator,
};
use ethlambda_types::{
    attestation::{
        Attestation as DomainAttestation, SignedAttestation as DomainSignedAttestation,
        XmssSignature,
    },
    primitives::H256,
};
use libssz_types::SszVector;
use serde::Deserialize;

// ============================================================================
// Root Structure
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct SszTestVector {
    #[serde(flatten)]
    pub tests: HashMap<String, SszTestCase>,
}

impl SszTestVector {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let test_vector = serde_json::from_str(&content)?;
        Ok(test_vector)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SszTestCase {
    #[allow(dead_code)]
    pub network: String,
    #[serde(rename = "leanEnv")]
    #[allow(dead_code)]
    pub lean_env: String,
    #[serde(rename = "typeName")]
    pub type_name: String,
    pub value: serde_json::Value,
    pub serialized: String,
    pub root: String,
    #[serde(rename = "_info")]
    pub info: TestInfo,
}

// ============================================================================
// Hex Helpers
// ============================================================================

pub fn decode_hex(hex_str: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    Ok(hex::decode(stripped)?)
}

pub fn decode_hex_h256(hex_str: &str) -> Result<H256, Box<dyn std::error::Error>> {
    let bytes = decode_hex(hex_str)?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes for H256, got {}", bytes.len()).into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(H256(arr))
}

// ============================================================================
// Attestation (not in test-fixtures: unsigned non-aggregated attestation)
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct Attestation {
    #[serde(rename = "validatorIndex")]
    pub validator_id: u64,
    pub data: AttestationData,
}

impl From<Attestation> for DomainAttestation {
    fn from(value: Attestation) -> Self {
        Self {
            validator_id: value.validator_id,
            data: value.data.into(),
        }
    }
}

// ============================================================================
// Signed Types (SSZ-specific fixtures)
// ============================================================================

fn deser_signature_hex<'de, D>(d: D) -> Result<XmssSignature, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let value = String::deserialize(d)?;
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(&value))
        .map_err(|_| D::Error::custom("Signature value is not valid hex"))?;
    SszVector::try_from(bytes)
        .map_err(|e| D::Error::custom(format!("Invalid signature length: {e:?}")))
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignedAttestation {
    #[serde(rename = "validatorIndex")]
    pub validator_id: u64,
    pub data: AttestationData,
    #[serde(deserialize_with = "deser_signature_hex")]
    pub signature: XmssSignature,
}

impl From<SignedAttestation> for DomainSignedAttestation {
    fn from(value: SignedAttestation) -> Self {
        Self {
            validator_id: value.validator_id,
            data: value.data.into(),
            signature: value.signature,
        }
    }
}

// NOTE: After Phase 3 the legacy `BlockSignatures` / `AttestationSignatures` /
// `AggregatedSignatureProof` containers are removed from the domain, and
// `SignedBlock` now carries a single `proof: MultiMessageAggregate` field. The pinned
// leanSpec fixtures still use the old shape, so SSZ-byte and root assertions
// for `SignedBlock`, `BlockSignatures`, `AggregatedSignatureProof`, and
// `SignedAggregatedAttestation` are intentionally skipped in
// `ssz_spectests.rs::run_ssz_test` until the fixture commit is bumped to the
// Type-1/Type-2 schema.
