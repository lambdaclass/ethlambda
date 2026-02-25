use super::common::{AggregationBits, Block, Container, ProposerAttestation, TestInfo, TestState};
use ethlambda_types::attestation::{AggregationBits as EthAggregationBits, XmssSignature};
use ethlambda_types::block::{
    AggregatedSignatureProof, AttestationSignatures, BlockSignatures, BlockWithAttestation,
    SignedBlockWithAttestation,
};
use ethlambda_types::primitives::ssz::{Decode as SszDecode, Encode as SszEncode};
use serde::Deserialize;
use ssz_types::FixedVector;
use ssz_types::typenum::{U28, U32};
use std::collections::HashMap;
use std::path::Path;

// ============================================================================
// SSZ Types matching leansig's GeneralizedXMSSSignature structure
// ============================================================================

/// A single hash digest (8 field elements = 32 bytes)
pub type HashDigest = FixedVector<u8, U32>;

/// Randomness (7 field elements = 28 bytes)
pub type Rho = FixedVector<u8, U28>;

/// SSZ-compatible HashTreeOpening matching leansig's structure
#[derive(Clone, SszEncode, SszDecode)]
pub struct SszHashTreeOpening {
    pub co_path: Vec<HashDigest>,
}

/// SSZ-compatible XMSS Signature matching leansig's GeneralizedXMSSSignature
#[derive(Clone, SszEncode, SszDecode)]
pub struct SszXmssSignature {
    pub path: SszHashTreeOpening,
    pub rho: Rho,
    pub hashes: Vec<HashDigest>,
}

// ============================================================================
// Root Structures
// ============================================================================

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

        let proposer_signature = value.signature.proposer_signature.to_xmss_signature();

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
    #[serde(rename = "proposerSignature")]
    pub proposer_signature: ProposerSignature,
    #[serde(rename = "attestationSignatures")]
    pub attestation_signatures: Container<AttestationSignature>,
}

/// XMSS signature structure as it appears in JSON
#[derive(Debug, Clone, Deserialize)]
pub struct ProposerSignature {
    pub path: SignaturePath,
    pub rho: RhoData,
    pub hashes: HashesData,
}

impl ProposerSignature {
    /// Convert to XmssSignature (FixedVector of bytes).
    ///
    /// Constructs an SSZ-encoded signature matching leansig's GeneralizedXMSSSignature format.
    pub fn to_xmss_signature(&self) -> XmssSignature {
        // Build SSZ types from JSON data
        let ssz_sig = self.to_ssz_signature();

        // Encode to SSZ bytes
        let bytes = ssz_sig.as_ssz_bytes();

        // Pad to exactly SignatureSize bytes (3112)
        let sig_size = 3112;
        let mut padded = bytes.clone();
        padded.resize(sig_size, 0);

        XmssSignature::new(padded).expect("signature size mismatch")
    }

    /// Convert to SSZ signature type
    fn to_ssz_signature(&self) -> SszXmssSignature {
        // Convert path siblings to HashDigest (Vec<u8> of 32 bytes each)
        let co_path: Vec<HashDigest> = self
            .path
            .siblings
            .data
            .iter()
            .map(|sibling| {
                let bytes: Vec<u8> = sibling
                    .data
                    .iter()
                    .flat_map(|&val| val.to_le_bytes())
                    .collect();
                HashDigest::new(bytes).expect("Invalid sibling length")
            })
            .collect();

        // Convert rho (7 field elements = 28 bytes)
        let rho_bytes: Vec<u8> = self
            .rho
            .data
            .iter()
            .flat_map(|&val| val.to_le_bytes())
            .collect();
        let rho = Rho::new(rho_bytes).expect("Invalid rho length");

        // Convert hashes to HashDigest
        let hashes: Vec<HashDigest> = self
            .hashes
            .data
            .iter()
            .map(|hash| {
                let bytes: Vec<u8> = hash
                    .data
                    .iter()
                    .flat_map(|&val| val.to_le_bytes())
                    .collect();
                HashDigest::new(bytes).expect("Invalid hash length")
            })
            .collect();

        SszXmssSignature {
            path: SszHashTreeOpening { co_path },
            rho,
            hashes,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignaturePath {
    pub siblings: Container<HashElement>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct HashElement {
    pub data: [u32; 8],
}

#[derive(Debug, Clone, Deserialize)]
pub struct RhoData {
    pub data: [u32; 7],
}

#[derive(Debug, Clone, Deserialize)]
pub struct HashesData {
    pub data: Vec<HashElement>,
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
