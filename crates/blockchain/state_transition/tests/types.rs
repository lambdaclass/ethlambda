use ethlambda_types::primitives::{BitList, H256, VariableList};
use ethlambda_types::state::{State, ValidatorPubkeyBytes};
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

/// Pre-state of the beacon chain
#[derive(Debug, Clone, Deserialize)]
pub struct TestState {
    pub config: Config,
    pub slot: u64,
    #[serde(rename = "latestBlockHeader")]
    pub latest_block_header: BlockHeader,
    #[serde(rename = "latestJustified")]
    pub latest_justified: Checkpoint,
    #[serde(rename = "latestFinalized")]
    pub latest_finalized: Checkpoint,
    #[serde(rename = "historicalBlockHashes")]
    pub historical_block_hashes: Container<H256>,
    #[serde(rename = "justifiedSlots")]
    pub justified_slots: Container<u64>,
    pub validators: Container<Validator>,
    #[serde(rename = "justificationsRoots")]
    pub justifications_roots: Container<H256>,
    #[serde(rename = "justificationsValidators")]
    pub justifications_validators: Container<bool>,
}

impl From<TestState> for State {
    fn from(value: TestState) -> Self {
        let historical_block_hashes =
            VariableList::new(value.historical_block_hashes.data).unwrap();
        let validators =
            VariableList::new(value.validators.data.into_iter().map(Into::into).collect()).unwrap();
        let justifications_roots = VariableList::new(value.justifications_roots.data).unwrap();

        State {
            config: value.config.into(),
            slot: value.slot,
            latest_block_header: value.latest_block_header.into(),
            latest_justified: value.latest_justified.into(),
            latest_finalized: value.latest_finalized.into(),
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
    pubkey: ValidatorPubkeyBytes,
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
    pub attestations: Container<AggregatedAttestation>,
}

impl From<BlockBody> for ethlambda_types::block::BlockBody {
    fn from(value: BlockBody) -> Self {
        // Expand aggregated attestations into individual attestations
        let attestations: Vec<ethlambda_types::attestation::Attestation> = value
            .attestations
            .data
            .into_iter()
            .flat_map(|agg| {
                // For each true bit in aggregation_bits, create an individual attestation
                agg.aggregation_bits
                    .data
                    .iter()
                    .enumerate()
                    .filter(|(_, voted)| **voted)
                    .map(|(validator_id, _)| ethlambda_types::attestation::Attestation {
                        validator_id: validator_id as u64,
                        data: agg.data.clone().into(),
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        Self {
            attestations: VariableList::new(attestations).expect("too many attestations"),
        }
    }
}

/// Aggregated attestation from test fixtures (expands to individual attestations)
#[derive(Debug, Clone, Deserialize)]
pub struct AggregatedAttestation {
    #[serde(rename = "aggregationBits")]
    pub aggregation_bits: AggregationBits,
    pub data: AttestationData,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AggregationBits {
    pub data: Vec<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AttestationData {
    pub slot: u64,
    pub head: Checkpoint,
    pub target: Checkpoint,
    pub source: Checkpoint,
}

impl From<AttestationData> for ethlambda_types::attestation::AttestationData {
    fn from(value: AttestationData) -> Self {
        Self {
            slot: value.slot,
            head: value.head.into(),
            target: value.target.into(),
            source: value.source.into(),
        }
    }
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
    pub justified_slots: Option<Container<u64>>,

    #[serde(rename = "justificationsRoots")]
    pub justifications_roots: Option<Container<H256>>,

    #[serde(rename = "justificationsValidators")]
    pub justifications_validators: Option<Container<bool>>,

    #[serde(rename = "validatorCount")]
    pub validator_count: Option<u64>,
}

/// Test metadata and information
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
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

pub fn deser_pubkey_hex<'de, D>(d: D) -> Result<ValidatorPubkeyBytes, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let value = String::deserialize(d)?;
    let pubkey: ValidatorPubkeyBytes = hex::decode(value.strip_prefix("0x").unwrap_or(&value))
        .map_err(|_| D::Error::custom("ValidatorPubkey value is not valid hex"))?
        .try_into()
        .map_err(|_| D::Error::custom("ValidatorPubkey length != 52"))?;
    Ok(pubkey)
}
