use ethlambda_types::primitives::{BitList, H256, VariableList};
use ethlambda_types::state::{State, ValidatorPubkey};
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
    pub network: String,
    #[serde(rename = "leanEnv")]
    pub lean_env: String,
    pub pre: BeaconState,
    pub blocks: Vec<Block>,
    pub post: Option<BeaconState>,
    #[serde(rename = "_info")]
    pub info: TestInfo,
}

/// Pre-state of the beacon chain
#[derive(Debug, Clone, Deserialize)]
pub struct BeaconState {
    pub config: Option<Config>,
    pub slot: Option<u64>,
    #[serde(rename = "latestBlockHeader")]
    pub latest_block_header: Option<BlockHeader>,
    #[serde(rename = "latestJustified")]
    pub latest_justified: Option<Checkpoint>,
    #[serde(rename = "latestFinalized")]
    pub latest_finalized: Option<Checkpoint>,
    #[serde(rename = "historicalBlockHashes")]
    pub historical_block_hashes: Option<Container<H256>>,
    #[serde(rename = "justifiedSlots")]
    pub justified_slots: Option<Container<u64>>,
    pub validators: Option<Container<Validator>>,
    #[serde(rename = "justificationsRoots")]
    pub justifications_roots: Option<Container<H256>>,
    #[serde(rename = "justificationsValidators")]
    pub justifications_validators: Option<Container<bool>>,
}

impl From<BeaconState> for State {
    fn from(value: BeaconState) -> Self {
        let historical_block_hashes =
            VariableList::new(value.historical_block_hashes.unwrap().data).unwrap();
        let validators = VariableList::new(
            value
                .validators
                .unwrap()
                .data
                .into_iter()
                .map(Into::into)
                .collect(),
        )
        .unwrap();
        let justifications_roots =
            VariableList::new(value.justifications_roots.unwrap().data).unwrap();

        State {
            config: value.config.unwrap().into(),
            slot: value.slot.unwrap(),
            latest_block_header: value.latest_block_header.unwrap().into(),
            latest_justified: value.latest_justified.unwrap().into(),
            latest_finalized: value.latest_finalized.unwrap().into(),
            historical_block_hashes,
            justified_slots: BitList::with_capacity(0).unwrap(),
            validators,
            justifications_roots,
            justifications_validators: BitList::with_capacity(0).unwrap(),
        }
    }
}

/// Configuration for the beacon chain
#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct Checkpoint {
    pub root: H256,
    pub slot: u64,
}

impl From<Checkpoint> for ethlambda_types::state::Checkpoint {
    fn from(value: Checkpoint) -> Self {
        Self {
            root: value.root,
            slot: value.slot,
        }
    }
}

/// Block header representing the latest block
#[derive(Debug, Clone, Deserialize)]
pub struct BlockHeader {
    pub slot: u64,
    #[serde(rename = "proposerIndex")]
    pub proposer_index: u64,
    #[serde(rename = "parentRoot")]
    pub parent_root: H256,
    #[serde(rename = "stateRoot")]
    pub state_root: H256,
    #[serde(rename = "bodyRoot")]
    pub body_root: H256,
}

impl From<BlockHeader> for ethlambda_types::block::BlockHeader {
    fn from(value: BlockHeader) -> Self {
        Self {
            slot: value.slot,
            proposer_index: value.proposer_index,
            parent_root: value.parent_root,
            state_root: value.state_root,
            body_root: value.body_root,
        }
    }
}

/// Validator information
#[derive(Debug, Clone, Deserialize)]
pub struct Validator {
    index: u64,
    #[serde(deserialize_with = "deser_pubkey_hex")]
    pubkey: ValidatorPubkey,
}

impl From<Validator> for ethlambda_types::state::Validator {
    fn from(value: Validator) -> Self {
        Self {
            index: value.index,
            pubkey: value.pubkey,
        }
    }
}

/// Generic container for arrays
#[derive(Debug, Clone, Deserialize)]
pub struct Container<T> {
    pub data: Vec<T>,
}

/// A block to be processed
#[derive(Debug, Clone, Deserialize)]
pub struct Block {
    pub slot: u64,
    #[serde(rename = "proposerIndex")]
    pub proposer_index: u64,
    #[serde(rename = "parentRoot")]
    pub parent_root: H256,
    #[serde(rename = "stateRoot")]
    pub state_root: H256,
    pub body: BlockBody,
}

impl From<Block> for ethlambda_types::block::Block {
    fn from(value: Block) -> Self {
        Self {
            slot: value.slot,
            proposer_index: value.proposer_index,
            parent_root: value.parent_root,
            state_root: value.state_root,
            body: value.body.into(),
        }
    }
}

/// Block body containing attestations and other data
#[derive(Debug, Clone, Deserialize)]
pub struct BlockBody {
    pub attestations: Container<()>,
}

impl From<BlockBody> for ethlambda_types::block::BlockBody {
    fn from(value: BlockBody) -> Self {
        Self {
            attestations: VariableList::new(vec![]).unwrap(),
        }
    }
}

/// Test metadata and information
#[derive(Debug, Clone, Deserialize)]
pub struct TestInfo {
    pub hash: String,
    pub comment: String,
    #[serde(rename = "testId")]
    pub test_id: String,
    pub description: String,
    #[serde(rename = "fixtureFormat")]
    pub fixture_format: String,
}

// Helpers

pub fn deser_pubkey_hex<'de, D>(d: D) -> Result<ValidatorPubkey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let value = String::deserialize(d)?;
    let pubkey: ValidatorPubkey = hex::decode(value.strip_prefix("0x").unwrap_or(&value))
        .map_err(|_| D::Error::custom("ValidatorPubkey value is not valid hex"))?
        .try_into()
        .map_err(|_| D::Error::custom("ValidatorPubkey length != 52"))?;
    Ok(pubkey)
}
