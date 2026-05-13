//! Signature-verification test fixture types.
//!
//! Used both by the offline spec-test runner and the Hive
//! `/lean/v0/test_driver/verify_signatures/run` endpoint, which receives the
//! same JSON shapes from the lean spec-assets simulator.

use crate::{AggregationBits, Block, Container, TestInfo, TestState, deser_xmss_hex};
use ethlambda_types::attestation::{AggregationBits as EthAggregationBits, XmssSignature};
use ethlambda_types::block::{
    AggregatedSignatureProof, AttestationSignatures, BlockSignatures, ByteListMiB, SignedBlock,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;
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
    #[serde(alias = "message")]
    pub block: Block,
    pub signature: TestSignatureBundle,
}

/// Lossy fixture-to-SignedBlock conversion: per-attestation proof bytes from
/// the fixture are dropped, leaving empty payloads. Adequate for callers that
/// don't reach the leanVM aggregate verifier (e.g. signature spec tests whose
/// fixtures all set `expectException`). For real signature verification use
/// [`TestSignedBlock::try_into_signed_block_with_proofs`].
impl From<TestSignedBlock> for SignedBlock {
    fn from(value: TestSignedBlock) -> Self {
        let block = value.block.into();
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

/// Error returned by [`TestSignedBlock::try_into_signed_block_with_proofs`].
#[derive(Debug)]
pub enum SignedBlockConvertError {
    InvalidProofHex { index: usize, reason: String },
    ProofTooLarge { index: usize, len: usize },
    TooManyAttestationSignatures,
}

impl fmt::Display for SignedBlockConvertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProofHex { index, reason } => {
                write!(
                    f,
                    "attestation_signatures[{index}].proofData: invalid hex: {reason}"
                )
            }
            Self::ProofTooLarge { index, len } => {
                write!(
                    f,
                    "attestation_signatures[{index}].proofData: {len} bytes exceeds ByteListMiB limit"
                )
            }
            Self::TooManyAttestationSignatures => {
                f.write_str("attestation_signatures list exceeds AttestationSignatures limit")
            }
        }
    }
}

impl std::error::Error for SignedBlockConvertError {}

impl TestSignedBlock {
    /// Materialize a `SignedBlock` that preserves the fixture-supplied
    /// per-attestation proof bytes verbatim. Required for verifying signatures
    /// against the leanVM aggregate path; the lossy [`From`] impl above drops
    /// these bytes.
    pub fn try_into_signed_block_with_proofs(self) -> Result<SignedBlock, SignedBlockConvertError> {
        let block = self.block.into();
        let proposer_signature = self.signature.proposer_signature;

        let proofs: Vec<AggregatedSignatureProof> = self
            .signature
            .attestation_signatures
            .data
            .into_iter()
            .enumerate()
            .map(|(index, att_sig)| {
                let participants: EthAggregationBits = att_sig.participants.into();
                let raw = &att_sig.proof_data.data;
                let stripped = raw.strip_prefix("0x").unwrap_or(raw);
                let bytes = hex::decode(stripped).map_err(|err| {
                    SignedBlockConvertError::InvalidProofHex {
                        index,
                        reason: err.to_string(),
                    }
                })?;
                let len = bytes.len();
                let proof_data = ByteListMiB::try_from(bytes)
                    .map_err(|_| SignedBlockConvertError::ProofTooLarge { index, len })?;
                Ok(AggregatedSignatureProof::new(participants, proof_data))
            })
            .collect::<Result<_, SignedBlockConvertError>>()?;

        let attestation_signatures: AttestationSignatures = AttestationSignatures::try_from(proofs)
            .map_err(|_| SignedBlockConvertError::TooManyAttestationSignatures)?;

        Ok(SignedBlock {
            message: block,
            signature: BlockSignatures {
                attestation_signatures,
                proposer_signature,
            },
        })
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
