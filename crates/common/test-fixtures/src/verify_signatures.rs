//! Signature-verification test fixture types.
//!
//! Used both by the offline spec-test runner and the Hive
//! `/lean/v0/test_driver/verify_signatures/run` endpoint, which receives the
//! same JSON shapes from the lean spec-assets simulator.

use crate::{AggregationBits, Block, Container, TestInfo, TestState, deser_xmss_hex};
use ethlambda_types::attestation::{AggregationBits as EthAggregationBits, XmssSignature};
use ethlambda_types::block::{
    ByteListMiB, SignedBlock, TypeOneMultiSignature, TypeTwoMultiSignature,
};
use libssz::SszEncode as _;
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
/// the fixture are dropped, leaving empty payloads. The merged Type-2 proof
/// preserves the per-attestation metadata (`message`, `slot`, `participants`)
/// and the proposer's XMSS signature so structural verification passes.
/// Adequate for callers that don't reach the leanVM aggregate verifier (e.g.
/// signature spec tests whose fixtures all set `expectException`). For real
/// signature verification use [`TestSignedBlock::try_into_signed_block_with_proofs`].
impl From<TestSignedBlock> for SignedBlock {
    fn from(value: TestSignedBlock) -> Self {
        let block: ethlambda_types::block::Block = value.block.into();
        let proposer_proof = ByteListMiB::try_from(value.signature.proposer_signature.to_vec())
            .expect("XMSS signature fits in ByteListMiB");

        let attestation_t1s: Vec<TypeOneMultiSignature> = value
            .signature
            .attestation_signatures
            .data
            .into_iter()
            .map(|att_sig| {
                let participants: EthAggregationBits = att_sig.participants.into();
                TypeOneMultiSignature::empty(participants)
            })
            .collect();

        let mut all = attestation_t1s;
        all.push(TypeOneMultiSignature::for_proposer(
            block.proposer_index,
            proposer_proof,
        ));
        let merged = TypeTwoMultiSignature::from_type_1s(all);
        let proof = ByteListMiB::try_from(merged.to_ssz())
            .expect("merged Type-2 proof fits in ByteListMiB");

        SignedBlock {
            message: block,
            proof,
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
    /// per-attestation proof bytes verbatim by folding every Type-1 plus the
    /// proposer Type-1 into the block's merged Type-2 proof. The lossy
    /// [`From`] impl above drops these bytes — use this one when the consumer
    /// needs the original aggregate bytes (e.g. the Hive test-driver feeds
    /// them through `verify_block_signatures`).
    pub fn try_into_signed_block_with_proofs(self) -> Result<SignedBlock, SignedBlockConvertError> {
        let block: ethlambda_types::block::Block = self.block.into();
        let proposer_proof = ByteListMiB::try_from(self.signature.proposer_signature.to_vec())
            .expect("XMSS signature fits in ByteListMiB");

        let attestation_t1s: Vec<TypeOneMultiSignature> = self
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
                Ok(TypeOneMultiSignature::new(participants, proof_data))
            })
            .collect::<Result<_, SignedBlockConvertError>>()?;

        if attestation_t1s.len() >= 17 {
            return Err(SignedBlockConvertError::TooManyAttestationSignatures);
        }

        let mut all = attestation_t1s;
        all.push(TypeOneMultiSignature::for_proposer(
            block.proposer_index,
            proposer_proof,
        ));
        let merged = TypeTwoMultiSignature::from_type_1s(all);
        let proof = ByteListMiB::try_from(merged.to_ssz())
            .expect("merged Type-2 proof fits in ByteListMiB");

        Ok(SignedBlock {
            message: block,
            proof,
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
