use ethlambda_types::state::State;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Root struct for state transition test vectors
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransitionTest {
    pub network: String,
    #[serde(rename = "leanEnv")]
    pub lean_env: String,
    pub pre: BeaconState,
    pub blocks: Vec<Block>,
    pub post: Option<PostState>,
    #[serde(rename = "_info")]
    pub info: TestInfo,
}

/// Pre-state of the beacon chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconState {
    pub config: Config,
    pub slot: u64,
    #[serde(rename = "latestBlockHeader")]
    pub latest_block_header: BlockHeader,
    #[serde(rename = "latestJustified")]
    pub latest_justified: Checkpoint,
    #[serde(rename = "latestFinalized")]
    pub latest_finalized: Checkpoint,
    #[serde(rename = "historicalBlockHashes")]
    pub historical_block_hashes: Container<String>,
    #[serde(rename = "justifiedSlots")]
    pub justified_slots: Container<u64>,
    pub validators: Container<Validator>,
    #[serde(rename = "justificationsRoots")]
    pub justifications_roots: Container<String>,
    #[serde(rename = "justificationsValidators")]
    pub justifications_validators: Container<serde_json::Value>,
}

impl From<BeaconState> for State {
    fn from(value: BeaconState) -> Self {
        State {
            config: value.config.into(),
            slot: value.slot,
            latest_block_header: value.latest_block_header.into(),
            latest_justified: (),
            latest_finalized: (),
            historical_block_hashes: (),
            justified_slots: (),
            validators: (),
            justifications_roots: (),
            justifications_validators: (),
        }
    }
}

/// Configuration for the beacon chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(rename = "genesisTime")]
    pub genesis_time: u64,
}

impl From<Config> for ethlambda_types::state::ChainConfig {
    fn from(value: Config) -> Self {
        ethlambda_types::state::ChainConfig {
            genesis_time: value.genesis_time,
        }
    }
}

/// Block header representing the latest block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub slot: u64,
    #[serde(rename = "proposerIndex")]
    pub proposer_index: u64,
    #[serde(rename = "parentRoot")]
    pub parent_root: String,
    #[serde(rename = "stateRoot")]
    pub state_root: String,
    #[serde(rename = "bodyRoot")]
    pub body_root: String,
}

/// Checkpoint (root + slot pair)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub root: String,
    pub slot: u64,
}

/// Validator information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub pubkey: String,
    pub index: u64,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawal_credentials: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_balance: Option<u64>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slashed: Option<bool>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation_eligibility_epoch: Option<u64>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation_epoch: Option<u64>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_epoch: Option<u64>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawable_epoch: Option<u64>,
}

/// Generic container for arrays
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Container<T> {
    pub data: Vec<T>,
}

/// A block to be processed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub slot: u64,
    #[serde(rename = "proposerIndex")]
    pub proposer_index: u64,
    #[serde(rename = "parentRoot")]
    pub parent_root: String,
    #[serde(rename = "stateRoot")]
    pub state_root: String,
    pub body: BlockBody,
}

/// Block body containing attestations and other data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockBody {
    pub attestations: Container<serde_json::Value>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deposits: Option<Container<serde_json::Value>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawals: Option<Container<serde_json::Value>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voluntary_exits: Option<Container<serde_json::Value>>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Post-state expectations after processing blocks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostState {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<u64>,
    #[serde(default)]
    #[serde(rename = "latestJustifiedSlot")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_justified_slot: Option<u64>,
    #[serde(default)]
    #[serde(rename = "latestJustifiedRoot")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_justified_root: Option<String>,
    #[serde(default)]
    #[serde(rename = "latestFinalizedSlot")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_finalized_slot: Option<u64>,
    #[serde(default)]
    #[serde(rename = "latestFinalizedRoot")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_finalized_root: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_count: Option<u64>,
    #[serde(default)]
    #[serde(rename = "configGenesisTime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_genesis_time: Option<u64>,
    #[serde(default)]
    #[serde(rename = "latestBlockHeaderSlot")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_block_header_slot: Option<u64>,
    #[serde(default)]
    #[serde(rename = "latestBlockHeaderProposerIndex")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_block_header_proposer_index: Option<u64>,
    #[serde(default)]
    #[serde(rename = "latestBlockHeaderParentRoot")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_block_header_parent_root: Option<String>,
    #[serde(default)]
    #[serde(rename = "latestBlockHeaderStateRoot")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_block_header_state_root: Option<String>,
    #[serde(default)]
    #[serde(rename = "latestBlockHeaderBodyRoot")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_block_header_body_root: Option<String>,
    #[serde(default)]
    #[serde(rename = "historicalBlockHashes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub historical_block_hashes: Option<Container<String>>,
    #[serde(default)]
    #[serde(rename = "justifiedSlots")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justified_slots: Option<Container<u64>>,
    #[serde(default)]
    #[serde(rename = "justificationsRoots")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justifications_roots: Option<Container<String>>,
    #[serde(default)]
    #[serde(rename = "justificationsValidators")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justifications_validators: Option<Container<serde_json::Value>>,
    #[serde(default)]
    #[serde(rename = "historicalBlockHashesCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub historical_block_hashes_count: Option<u64>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Test metadata and information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestInfo {
    pub hash: String,
    pub comment: String,
    #[serde(rename = "testId")]
    pub test_id: String,
    pub description: String,
    #[serde(rename = "fixtureFormat")]
    pub fixture_format: String,
}
