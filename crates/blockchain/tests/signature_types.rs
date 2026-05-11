use super::common::{AggregationBits, Block, Container, TestInfo, TestState, deser_xmss_hex};
use ethlambda_blockchain::aggregation::{aggregate_type_2, proposer_type_one};
use ethlambda_types::attestation::{AggregationBits as EthAggregationBits, XmssSignature};
use ethlambda_types::block::{ByteListMiB, SignedBlock, TypeOneMultiSignature};
use ethlambda_types::primitives::HashTreeRoot as _;
use libssz::SszEncode as _;
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
    #[serde(alias = "message")]
    pub block: Block,
    pub signature: TestSignatureBundle,
}

impl From<TestSignedBlock> for SignedBlock {
    fn from(value: TestSignedBlock) -> Self {
        let block: ethlambda_types::block::Block = value.block.into();
        let block_root = block.hash_tree_root();
        let proposer_signature_bytes = value.signature.proposer_signature.to_vec();
        let proposer_proof = ByteListMiB::try_from(proposer_signature_bytes)
            .expect("XMSS signature fits in ByteListMiB");

        // The legacy fixture lists one `attestationSignatures` entry per
        // block-body attestation; pair them up to derive per-Type-1 message
        // and slot metadata, then fold every Type-1 plus the proposer Type-1
        // into the merged Type-2 blob.
        let attestation_t1s: Vec<TypeOneMultiSignature> = value
            .signature
            .attestation_signatures
            .data
            .into_iter()
            .zip(block.body.attestations.iter())
            .map(|(att_sig, att)| {
                let participants: EthAggregationBits = att_sig.participants.into();
                TypeOneMultiSignature::empty(participants, att.data.hash_tree_root(), att.data.slot)
            })
            .collect();

        let mut all = attestation_t1s;
        all.push(proposer_type_one(
            block.proposer_index,
            proposer_proof,
            block_root,
            block.slot,
        ));
        let merged = aggregate_type_2(all);
        let proof =
            ByteListMiB::try_from(merged.to_ssz()).expect("merged proof fits in ByteListMiB");

        SignedBlock {
            message: block,
            proof,
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
