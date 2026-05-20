//! Signature-verification test fixture types.
//!
//! Used both by the offline spec-test runner and the Hive
//! `/lean/v0/test_driver/verify_signatures/run` endpoint, which receives the
//! same JSON shapes from the lean spec-assets simulator.

use crate::{AggregationBits, Block, Container, TestInfo, TestState, deser_xmss_hex};
use ethlambda_types::attestation::XmssSignature;
use ethlambda_types::block::{ByteList512KiB, SignedBlock};
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

/// Lossy fixture-to-SignedBlock conversion: every signature byte is dropped.
///
/// Under the leanSpec PR #717 wire format the block envelope carries a single
/// opaque merged proof blob, not per-attestation Type-1s plus a proposer
/// signature. Existing devnet4-shaped fixtures predate that change and don't
/// ship a merged Type-2 blob — they ship per-attestation signature metadata
/// plus a raw XMSS proposer signature. There is no way to reconstruct the
/// merged Type-2 blob from those bytes without running the lean-multisig
/// prover, so this `From` impl yields an empty `proof` and the resulting
/// block fails real `verify_block_signatures`. Callers that don't reach the
/// verifier (fixtures with `expectException`) are unaffected.
impl From<TestSignedBlock> for SignedBlock {
    fn from(value: TestSignedBlock) -> Self {
        SignedBlock {
            message: value.block.into(),
            proof: ByteList512KiB::default(),
        }
    }
}

/// Error returned by [`TestSignedBlock::try_into_signed_block_with_proofs`].
#[derive(Debug)]
pub enum SignedBlockConvertError {
    /// Devnet4-shaped fixtures cannot be converted to the leanSpec PR #717
    /// wire format without rebuilding the merged Type-2 proof through the
    /// lean-multisig prover. Until fixtures ship the merged proof blob
    /// directly, the Hive driver path returns this error.
    LegacyFixtureNotConvertible,
}

impl fmt::Display for SignedBlockConvertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LegacyFixtureNotConvertible => {
                f.write_str("fixture predates leanSpec PR #717 — merged Type-2 proof unavailable")
            }
        }
    }
}

impl std::error::Error for SignedBlockConvertError {}

impl TestSignedBlock {
    /// Materialize a `SignedBlock` that preserves the fixture-supplied
    /// merged proof bytes. Until fixtures are updated to ship the merged
    /// Type-2 proof blob directly (post leanSpec PR #717), this returns
    /// [`SignedBlockConvertError::LegacyFixtureNotConvertible`].
    pub fn try_into_signed_block_with_proofs(self) -> Result<SignedBlock, SignedBlockConvertError> {
        let _ = self;
        Err(SignedBlockConvertError::LegacyFixtureNotConvertible)
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
