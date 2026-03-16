use super::common::{AggregationBits, Block, Container, TestInfo, TestState};
use ethlambda_types::attestation::{AggregationBits as EthAggregationBits, XmssSignature};
use ethlambda_types::block::{
    AggregatedSignatureProof, AttestationSignatures, BlockSignatures, SignedBlock,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Root struct for verify signatures test vectors
#[derive(Debug, Clone, Deserialize)]
pub struct VerifySignaturesTestVector {
    #[serde(flatten)]
    pub tests: HashMap<String, VerifySignaturesTest>,
}

impl VerifySignaturesTestVector {
    /// Load a verify signatures test vector from a JSON file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let test_vector = serde_json::from_str(&content)?;
        Ok(test_vector)
    }
}

/// A single verify signatures test case
#[derive(Debug, Clone, Deserialize)]
pub struct VerifySignaturesTest {
    #[allow(dead_code)]
    pub network: String,
    #[serde(rename = "leanEnv")]
    #[allow(dead_code)]
    pub lean_env: String,
    #[serde(rename = "anchorState")]
    pub anchor_state: TestState,
    #[serde(rename = "signedBlock")]
    pub signed_block: TestSignedBlock,
    #[serde(rename = "expectException")]
    pub expect_exception: Option<String>,
    #[serde(rename = "_info")]
    #[allow(dead_code)]
    pub info: TestInfo,
}

// ============================================================================
// Signed Block Types
// ============================================================================

/// Signed block with signature bundle (devnet4: no proposer attestation wrapper)
#[derive(Debug, Clone, Deserialize)]
pub struct TestSignedBlock {
    pub message: Block,
    pub signature: TestSignatureBundle,
}

impl From<TestSignedBlock> for SignedBlock {
    fn from(value: TestSignedBlock) -> Self {
        let block = value.message.into();
        let proposer_signature = value.signature.proposer_signature;

        let attestation_signatures: AttestationSignatures = value
            .signature
            .attestation_signatures
            .data
            .into_iter()
            .map(|att_sig| {
                let participants: EthAggregationBits = att_sig.participants.into();
                AggregatedSignatureProof::empty(participants)
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("too many attestation signatures");

        SignedBlock {
            message: block,
            signature: BlockSignatures {
                attestation_signatures,
                proposer_signature,
            },
        }
    }
}

// ============================================================================
// Signature Types
// ============================================================================

/// Bundle of signatures for block and attestations
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct TestSignatureBundle {
    #[serde(rename = "proposerSignature", deserialize_with = "deser_xmss_hex")]
    pub proposer_signature: XmssSignature,
    #[serde(rename = "attestationSignatures")]
    pub attestation_signatures: Container<AttestationSignature>,
}

/// Attestation signature from a validator
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct AttestationSignature {
    pub participants: AggregationBits,
    #[serde(rename = "proofData")]
    pub proof_data: ProofData,
}

/// Placeholder for future SNARK proof data
#[derive(Debug, Clone, Deserialize)]
pub struct ProofData {
    pub data: String,
}

// ============================================================================
// Helpers
// ============================================================================

pub fn deser_xmss_hex<'de, D>(d: D) -> Result<XmssSignature, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let value = String::deserialize(d)?;
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(&value))
        .map_err(|_| D::Error::custom("XmssSignature value is not valid hex"))?;
    XmssSignature::new(bytes).map_err(|_| D::Error::custom("XmssSignature length != 3112"))
}
