#![allow(dead_code)]

use ethlambda_types::{
    attestation::{
        AggregatedAttestation as DomainAggregatedAttestation,
        AggregationBits as DomainAggregationBits, Attestation as DomainAttestation,
        AttestationData as DomainAttestationData,
    },
    block::{Block as DomainBlock, BlockBody as DomainBlockBody},
    primitives::{BitList, H256, VariableList},
    state::{
        ChainConfig, Checkpoint as DomainCheckpoint, State, Validator as DomainValidator,
        ValidatorPubkeyBytes,
    },
};
use serde::Deserialize;

// ============================================================================
// Generic Container
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct Container<T> {
    pub data: Vec<T>,
}

// ============================================================================
// Config
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(rename = "genesisTime")]
    pub genesis_time: u64,
}

impl From<Config> for ChainConfig {
    fn from(value: Config) -> Self {
        ChainConfig {
            genesis_time: value.genesis_time,
        }
    }
}

// ============================================================================
// Checkpoint
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct Checkpoint {
    pub root: H256,
    pub slot: u64,
}

impl From<Checkpoint> for DomainCheckpoint {
    fn from(value: Checkpoint) -> Self {
        Self {
            root: value.root,
            slot: value.slot,
        }
    }
}

// ============================================================================
// BlockHeader
// ============================================================================

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

// ============================================================================
// Validator
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct Validator {
    index: u64,
    #[serde(deserialize_with = "deser_pubkey_hex")]
    pubkey: ValidatorPubkeyBytes,
}

impl From<Validator> for DomainValidator {
    fn from(value: Validator) -> Self {
        Self {
            index: value.index,
            pubkey: value.pubkey,
        }
    }
}

// ============================================================================
// State
// ============================================================================

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

// ============================================================================
// Block Types
// ============================================================================

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

impl From<Block> for DomainBlock {
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

#[derive(Debug, Clone, Deserialize)]
pub struct BlockBody {
    pub attestations: Container<AggregatedAttestation>,
}

impl From<BlockBody> for DomainBlockBody {
    fn from(value: BlockBody) -> Self {
        let attestations = value
            .attestations
            .data
            .into_iter()
            .map(Into::into)
            .collect();
        Self {
            attestations: VariableList::new(attestations).expect("too many attestations"),
        }
    }
}

// ============================================================================
// Attestation Types
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct AggregatedAttestation {
    #[serde(rename = "aggregationBits")]
    pub aggregation_bits: AggregationBits,
    pub data: AttestationData,
}

impl From<AggregatedAttestation> for DomainAggregatedAttestation {
    fn from(value: AggregatedAttestation) -> Self {
        Self {
            aggregation_bits: value.aggregation_bits.into(),
            data: value.data.into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AggregationBits {
    pub data: Vec<bool>,
}

impl From<AggregationBits> for DomainAggregationBits {
    fn from(value: AggregationBits) -> Self {
        let mut bits = DomainAggregationBits::with_capacity(value.data.len()).unwrap();
        for (i, &b) in value.data.iter().enumerate() {
            bits.set(i, b).unwrap();
        }
        bits
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AttestationData {
    pub slot: u64,
    pub head: Checkpoint,
    pub target: Checkpoint,
    pub source: Checkpoint,
}

impl From<AttestationData> for DomainAttestationData {
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
pub struct ProposerAttestation {
    #[serde(rename = "validatorId")]
    pub validator_id: u64,
    pub data: AttestationData,
}

impl From<ProposerAttestation> for DomainAttestation {
    fn from(value: ProposerAttestation) -> Self {
        Self {
            validator_id: value.validator_id,
            data: value.data.into(),
        }
    }
}

// ============================================================================
// Metadata
// ============================================================================

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

// ============================================================================
// Helpers
// ============================================================================

pub fn deser_pubkey_hex<'de, D>(d: D) -> Result<ValidatorPubkeyBytes, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    use serde::de::Error;

    let value = String::deserialize(d)?;
    let pubkey: ValidatorPubkeyBytes = hex::decode(value.strip_prefix("0x").unwrap_or(&value))
        .map_err(|_| D::Error::custom("ValidatorPubkey value is not valid hex"))?
        .try_into()
        .map_err(|_| D::Error::custom("ValidatorPubkey length != 52"))?;
    Ok(pubkey)
}
