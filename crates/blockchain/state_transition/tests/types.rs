pub use ethlambda_test_fixtures::*;

use ethlambda_types::primitives::H256;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Root struct for state transition test vectors
#[derive(Debug, Clone, Deserialize)]
pub struct StateTransitionTestVector {
    #[serde(flatten)]
    pub tests: HashMap<String, StateTransitionTest>,
}

impl StateTransitionTestVector {
    /// Load a state transition test vector from a JSON file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let test_vector = serde_json::from_str(&content)?;
        Ok(test_vector)
    }
}

/// A single state transition test case
#[derive(Debug, Clone, Deserialize)]
pub struct StateTransitionTest {
    #[allow(dead_code)]
    pub network: String,
    #[serde(rename = "leanEnv")]
    #[allow(dead_code)]
    pub lean_env: String,
    pub pre: TestState,
    pub blocks: Vec<Block>,
    pub post: Option<PostState>,
    #[serde(rename = "_info")]
    #[allow(dead_code)]
    pub info: TestInfo,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostState {
    #[serde(rename = "configGenesisTime")]
    pub config_genesis_time: Option<u64>,
    pub slot: Option<u64>,

    #[serde(rename = "latestBlockHeaderSlot")]
    pub latest_block_header_slot: Option<u64>,
    #[serde(rename = "latestBlockHeaderStateRoot")]
    pub latest_block_header_state_root: Option<H256>,
    #[serde(rename = "latestBlockHeaderProposerIndex")]
    pub latest_block_header_proposer_index: Option<u64>,
    #[serde(rename = "latestBlockHeaderParentRoot")]
    pub latest_block_header_parent_root: Option<H256>,
    #[serde(rename = "latestBlockHeaderBodyRoot")]
    pub latest_block_header_body_root: Option<H256>,

    #[serde(rename = "latestJustifiedSlot")]
    pub latest_justified_slot: Option<u64>,
    #[serde(rename = "latestJustifiedRoot")]
    pub latest_justified_root: Option<H256>,

    #[serde(rename = "latestFinalizedSlot")]
    pub latest_finalized_slot: Option<u64>,
    #[serde(rename = "latestFinalizedRoot")]
    pub latest_finalized_root: Option<H256>,

    #[serde(rename = "historicalBlockHashesCount")]
    pub historical_block_hashes_count: Option<u64>,
    #[serde(rename = "historicalBlockHashes")]
    pub historical_block_hashes: Option<Container<H256>>,

    #[serde(rename = "justifiedSlots")]
    pub justified_slots: Option<Container<bool>>,

    #[serde(rename = "justificationsRoots")]
    pub justifications_roots: Option<Container<H256>>,

    #[serde(rename = "justificationsValidators")]
    pub justifications_validators: Option<Container<bool>>,

    #[serde(rename = "validatorCount")]
    pub validator_count: Option<u64>,

    // Label-based root checks: "block_N" labels resolved to hash_tree_root of the Nth block.
    #[serde(rename = "latestJustifiedRootLabel")]
    pub latest_justified_root_label: Option<String>,
    #[serde(rename = "latestFinalizedRootLabel")]
    pub latest_finalized_root_label: Option<String>,
    #[serde(rename = "justificationsRootsLabels")]
    pub justifications_roots_labels: Option<Vec<String>>,

    // Count checks for variable-length collections.
    #[serde(rename = "justificationsRootsCount")]
    pub justifications_roots_count: Option<u64>,
    #[serde(rename = "justificationsValidatorsCount")]
    pub justifications_validators_count: Option<u64>,
}
