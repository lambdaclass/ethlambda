use super::common::{AggregationBits, Block, Container, ProposerAttestation, TestInfo, TestState};
use ethlambda_types::attestation::{AggregationBits as EthAggregationBits, XmssSignature};
use ethlambda_types::block::{
    AggregatedSignatureProof, AttestationSignatures, BlockSignatures, BlockWithAttestation,
    SignedBlockWithAttestation,
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
    #[serde(rename = "signedBlockWithAttestation")]
    pub signed_block_with_attestation: TestSignedBlockWithAttestation,
    #[serde(rename = "expectException")]
    pub expect_exception: Option<String>,
    #[serde(rename = "_info")]
    #[allow(dead_code)]
    pub info: TestInfo,
}

// ============================================================================
// Signed Block Types
// ============================================================================

/// Signed block with attestation and signature
#[derive(Debug, Clone, Deserialize)]
pub struct TestSignedBlockWithAttestation {
    pub message: TestBlockWithAttestation,
    pub signature: TestSignatureBundle,
}

impl From<TestSignedBlockWithAttestation> for SignedBlockWithAttestation {
    fn from(value: TestSignedBlockWithAttestation) -> Self {
        let message = BlockWithAttestation {
            block: value.message.block.into(),
            proposer_attestation: value.message.proposer_attestation.into(),
        };

        let proposer_signature = value.signature.proposer_signature;

        // Convert attestation signatures to AggregatedSignatureProof.
        // Each proof contains the participants bitfield from the test data.
        // The proof_data is currently empty (placeholder for future leanVM aggregation).
        let attestation_signatures: AttestationSignatures = value
            .signature
            .attestation_signatures
            .data
            .into_iter()
            .map(|att_sig| {
                // Convert participants bitfield
                let participants: EthAggregationBits = att_sig.participants.into();
                // Create proof with participants but empty proof_data
                AggregatedSignatureProof::empty(participants)
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("too many attestation signatures");

        SignedBlockWithAttestation {
            message,
            signature: BlockSignatures {
                attestation_signatures,
                proposer_signature,
            },
        }
    }
}

/// Block with proposer attestation (the message that gets signed)
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct TestBlockWithAttestation {
    pub block: Block,
    #[serde(rename = "proposerAttestation")]
    pub proposer_attestation: ProposerAttestation,
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
/// Note: proofData is for future SNARK aggregation, currently just placeholder
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
    XmssSignature::try_from(bytes).map_err(|_| D::Error::custom("XmssSignature length != 3112"))
}
