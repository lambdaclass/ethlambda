use super::common::{Block, ProposerAttestation, TestInfo, TestState};
use ethlambda_types::primitives::H256;
use serde::Deserialize;
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
    pub time: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockStepData {
    pub block: Block,
    #[serde(rename = "proposerAttestation")]
    pub proposer_attestation: ProposerAttestation,
    #[serde(rename = "blockRootLabel")]
    pub block_root_label: Option<String>,
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

    // Unsupported fields (will error if present in test fixture)
    pub time: Option<u64>,
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
