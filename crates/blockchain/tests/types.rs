use super::common::{self, Block, TestInfo, TestState, deser_xmss_hex};
use ethlambda_types::attestation::XmssSignature;
use ethlambda_types::primitives::H256;
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::path::Path;

// ============================================================================
// Root Structures
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct ForkChoiceTestVector {
    #[serde(flatten)]
    pub tests: HashMap<String, ForkChoiceTest>,
}

impl ForkChoiceTestVector {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let test_vector = serde_json::from_str(&content)?;
        Ok(test_vector)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ForkChoiceTest {
    #[allow(dead_code)]
    pub network: String,
    #[serde(rename = "leanEnv")]
    #[allow(dead_code)]
    pub lean_env: String,
    #[serde(rename = "anchorState")]
    pub anchor_state: TestState,
    #[serde(rename = "anchorBlock")]
    pub anchor_block: Block,
    pub steps: Vec<ForkChoiceStep>,
    #[serde(rename = "maxSlot")]
    #[allow(dead_code)]
    pub max_slot: u64,
    #[serde(rename = "_info")]
    pub info: TestInfo,
}

// ============================================================================
// Step Types
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct ForkChoiceStep {
    pub valid: bool,
    pub checks: Option<StoreChecks>,
    #[serde(rename = "stepType")]
    pub step_type: String,
    pub block: Option<BlockStepData>,
    pub attestation: Option<AttestationStepData>,
    /// UNIX time in seconds for `tick` steps (exclusive with `interval`).
    pub time: Option<u64>,
    /// Absolute interval count since genesis for `tick` steps (exclusive with `time`).
    pub interval: Option<u64>,
    #[serde(rename = "hasProposal")]
    pub has_proposal: Option<bool>,
    #[serde(rename = "isAggregator")]
    pub is_aggregator: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AttestationStepData {
    #[serde(rename = "validatorId")]
    pub validator_id: Option<u64>,
    pub data: common::AttestationData,
    #[serde(default, deserialize_with = "deser_opt_xmss_hex")]
    pub signature: Option<XmssSignature>,
    /// Present on `gossipAggregatedAttestation` steps.
    pub proof: Option<ProofStepData>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProofStepData {
    pub participants: common::AggregationBits,
    #[serde(rename = "proofData")]
    pub proof_data: HexByteList,
}

/// Hex-encoded byte list in the fixture format: `{ "data": "0xdeadbeef" }`.
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

fn deser_opt_xmss_hex<'de, D>(d: D) -> Result<Option<XmssSignature>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct Wrap(#[serde(deserialize_with = "deser_xmss_hex")] XmssSignature);

    Ok(Option::<Wrap>::deserialize(d)?.map(|w| w.0))
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockStepData {
    pub slot: u64,
    #[serde(rename = "proposerIndex")]
    pub proposer_index: u64,
    #[serde(rename = "parentRoot")]
    pub parent_root: H256,
    #[serde(rename = "stateRoot")]
    pub state_root: H256,
    pub body: common::BlockBody,
    #[serde(rename = "blockRootLabel")]
    pub block_root_label: Option<String>,
}

impl BlockStepData {
    pub fn to_block(&self) -> ethlambda_types::block::Block {
        Block {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root: self.state_root,
            body: self.body.clone(),
        }
        .into()
    }
}

// ============================================================================
// Check Types
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct StoreChecks {
    // Validated fields
    #[serde(rename = "headSlot")]
    pub head_slot: Option<u64>,
    #[serde(rename = "headRoot")]
    pub head_root: Option<H256>,
    #[serde(rename = "attestationChecks")]
    pub attestation_checks: Option<Vec<AttestationCheck>>,
    #[serde(rename = "attestationTargetSlot")]
    pub attestation_target_slot: Option<u64>,

    /// Expected store time in intervals since genesis (validated when present).
    pub time: Option<u64>,

    // Unsupported fields (will error if present in test fixture)
    #[serde(rename = "headRootLabel")]
    pub head_root_label: Option<String>,
    #[serde(rename = "latestJustifiedSlot")]
    pub latest_justified_slot: Option<u64>,
    #[serde(rename = "latestJustifiedRoot")]
    pub latest_justified_root: Option<H256>,
    #[serde(rename = "latestJustifiedRootLabel")]
    pub latest_justified_root_label: Option<String>,
    #[serde(rename = "latestFinalizedSlot")]
    pub latest_finalized_slot: Option<u64>,
    #[serde(rename = "latestFinalizedRoot")]
    pub latest_finalized_root: Option<H256>,
    #[serde(rename = "latestFinalizedRootLabel")]
    pub latest_finalized_root_label: Option<String>,
    #[serde(rename = "safeTarget")]
    pub safe_target: Option<H256>,
    #[serde(rename = "lexicographicHeadAmong")]
    pub lexicographic_head_among: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AttestationCheck {
    pub validator: u64,
    #[serde(rename = "attestationSlot")]
    pub attestation_slot: Option<u64>,
    #[serde(rename = "headSlot")]
    pub head_slot: Option<u64>,
    #[serde(rename = "sourceSlot")]
    pub source_slot: Option<u64>,
    #[serde(rename = "targetSlot")]
    pub target_slot: Option<u64>,
    pub location: String,
}
