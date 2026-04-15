use std::collections::HashMap;
use std::path::Path;

pub use ethlambda_test_fixtures::{
    AggregatedAttestation, AggregationBits, AttestationData, Block, BlockBody, BlockHeader,
    Checkpoint, Config, Container, TestInfo, TestState, Validator,
};
use ethlambda_types::{
    attestation::{
        Attestation as DomainAttestation,
        SignedAggregatedAttestation as DomainSignedAggregatedAttestation,
        SignedAttestation as DomainSignedAttestation, XmssSignature,
    },
    block::{
        AggregatedSignatureProof as DomainAggregatedSignatureProof, AttestationSignatures,
        BlockSignatures as DomainBlockSignatures, ByteListMiB, SignedBlock as DomainSignedBlock,
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
    #[serde(rename = "validatorId")]
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
    #[serde(rename = "validatorId")]
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

#[derive(Debug, Clone, Deserialize)]
pub struct SignedBlock {
    pub block: Block,
    pub signature: BlockSignatures,
}

impl From<SignedBlock> for DomainSignedBlock {
    fn from(value: SignedBlock) -> Self {
        Self {
            message: value.block.into(),
            signature: value.signature.into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockSignatures {
    #[serde(rename = "attestationSignatures")]
    pub attestation_signatures: Container<AggregatedSignatureProof>,
    #[serde(rename = "proposerSignature")]
    #[serde(deserialize_with = "deser_signature_hex")]
    pub proposer_signature: XmssSignature,
}

impl From<BlockSignatures> for DomainBlockSignatures {
    fn from(value: BlockSignatures) -> Self {
        let att_sigs: Vec<DomainAggregatedSignatureProof> = value
            .attestation_signatures
            .data
            .into_iter()
            .map(Into::into)
            .collect();
        Self {
            attestation_signatures: AttestationSignatures::try_from(att_sigs)
                .expect("too many attestation signatures"),
            proposer_signature: value.proposer_signature,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AggregatedSignatureProof {
    pub participants: AggregationBits,
    #[serde(rename = "proofData")]
    pub proof_data: HexByteList,
}

impl From<AggregatedSignatureProof> for DomainAggregatedSignatureProof {
    fn from(value: AggregatedSignatureProof) -> Self {
        let proof_bytes: Vec<u8> = value.proof_data.into();
        Self {
            participants: value.participants.into(),
            proof_data: ByteListMiB::try_from(proof_bytes).expect("proof data too large"),
        }
    }
}

/// Hex-encoded byte list in the fixture format: `{ "data": "0xdeadbeef" }`
#[derive(Debug, Clone, Deserialize)]
pub struct HexByteList {
    data: String,
}

impl From<HexByteList> for Vec<u8> {
    fn from(value: HexByteList) -> Self {
        let stripped = value.data.strip_prefix("0x").unwrap_or(&value.data);
        hex::decode(stripped).expect("invalid hex in proof data")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignedAggregatedAttestation {
    pub data: AttestationData,
    pub proof: AggregatedSignatureProof,
}

impl From<SignedAggregatedAttestation> for DomainSignedAggregatedAttestation {
    fn from(value: SignedAggregatedAttestation) -> Self {
        Self {
            data: value.data.into(),
            proof: value.proof.into(),
        }
    }
}
