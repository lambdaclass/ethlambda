//! Signature-verification test fixture types (leanSpec PR #799 schema).
//!
//! Used both by the offline spec-test runner and the Hive
//! `/lean/v0/test_driver/verify_signatures/run` endpoint, which receive the
//! same JSON shapes from the lean spec-assets simulator.
//!
//! Fixture shape after PR #799:
//!
//!   signedBlock:
//!     block:  {...standard block fields...}
//!     proof:  { proof: { data: "0x<hex-encoded merged Type-2 bytes>" } }

use crate::{Block, TestInfo, TestState};
use ethlambda_types::block::SignedBlock;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;
use std::path::Path;

/// Root struct for verify signatures test vectors.
#[derive(Debug, Clone, Deserialize)]
pub struct VerifySignaturesTestVector {
    #[serde(flatten)]
    pub tests: HashMap<String, VerifySignaturesTest>,
}

impl VerifySignaturesTestVector {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let test_vector = serde_json::from_str(&content)?;
        Ok(test_vector)
    }
}

/// A single verify-signatures test case.
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

/// Fixture-side signed block: a block plus its raw merged Type-2 proof bytes.
#[derive(Debug, Clone, Deserialize)]
pub struct TestSignedBlock {
    #[serde(alias = "message")]
    pub block: Block,
    pub proof: MergedProof,
}

/// Merged Type-2 proof container for `SignedBlock.proof` (leanSpec PR #799).
///
/// The multi-signature container nests the raw lean-multisig wire one level
/// deep: `{ "proof": { "data": "0x..." } }`.
#[derive(Debug, Clone, Deserialize)]
pub struct MergedProof {
    pub proof: HexBytes,
}

impl MergedProof {
    pub fn decode(&self) -> Result<Vec<u8>, hex::FromHexError> {
        self.proof.decode()
    }
}

/// `{ "data": "0x..." }` wrapper used by leanSpec fixtures for byte fields.
#[derive(Debug, Clone, Deserialize)]
pub struct HexBytes {
    pub data: String,
}

impl HexBytes {
    pub fn decode(&self) -> Result<Vec<u8>, hex::FromHexError> {
        let s = self.data.strip_prefix("0x").unwrap_or(&self.data);
        hex::decode(s)
    }
}

/// Error returned by [`TestSignedBlock::try_into_signed_block_with_proofs`].
#[derive(Debug)]
pub enum SignedBlockConvertError {
    InvalidProofHex(String),
    ProofTooLarge(usize),
}

impl fmt::Display for SignedBlockConvertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProofHex(reason) => write!(f, "proof.data hex decode failed: {reason}"),
            Self::ProofTooLarge(len) => write!(f, "proof bytes exceed cap: {len}"),
        }
    }
}

impl std::error::Error for SignedBlockConvertError {}

/// Lossy fixture-to-SignedBlock conversion that preserves the merged proof.
///
/// The conversion is fallible because the proof bytes may not decode as hex
/// or may exceed the wire cap. Tests with `expectException` set tolerate
/// failures upstream; the From impl panics so test runners get a clear
/// signal when fixture shape drifts.
impl From<TestSignedBlock> for SignedBlock {
    fn from(value: TestSignedBlock) -> Self {
        value
            .try_into_signed_block_with_proofs()
            .expect("fixture proof decode")
    }
}

impl TestSignedBlock {
    /// Materialize a `SignedBlock` preserving the fixture-supplied merged
    /// Type-2 proof bytes verbatim.
    ///
    /// The container carries the raw lean-multisig wire, so it gets wrapped
    /// into the SSZ-container envelope that `SignedBlock.proof` stores.
    pub fn try_into_signed_block_with_proofs(self) -> Result<SignedBlock, SignedBlockConvertError> {
        let bytes = self
            .proof
            .decode()
            .map_err(|err| SignedBlockConvertError::InvalidProofHex(err.to_string()))?;
        let len = bytes.len();
        let proof = SignedBlock::wrap_merged_proof(&bytes)
            .map_err(|_| SignedBlockConvertError::ProofTooLarge(len))?;
        Ok(SignedBlock {
            message: self.block.into(),
            proof,
        })
    }
}
