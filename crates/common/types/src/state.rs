use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::typenum::{U4096, U262144};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    block::{BlockBody, BlockHeader},
    genesis::Genesis,
    primitives::H256,
};

// Constants

/// The maximum number of validators that can be in the registry.
pub type ValidatorRegistryLimit = U4096;

/// The main consensus state object
#[derive(Debug, Clone, Encode, Decode, TreeHash)]
pub struct State {
    /// The chain's configuration parameters
    config: NetworkConfig,
    /// The current slot number
    slot: u64,
    /// The header of the most recent block
    latest_block_header: BlockHeader,
    /// The latest justified checkpoint
    latest_justified: Checkpoint,
    /// The latest finalized checkpoint
    latest_finalized: Checkpoint,
    /// A list of historical block root hashes
    historical_block_hashes: HistoricalBlockHashes,
    /// A bitfield indicating which historical slots were justified
    justified_slots: JustifiedSlots,
    /// Registry of validators tracked by the state
    validators: ssz_types::VariableList<Validator, ValidatorRegistryLimit>,
    /// Roots of justified blocks
    justifications_roots: JustificationRoots,
    /// A bitlist of validators who participated in justifications
    justifications_validators: JustificationValidators,
}

/// The maximum number of historical block roots to store in the state.
///
/// With a 4-second slot, this corresponds to a history
/// of approximately 12.1 days.
type HistoricalRootsLimit = U262144; // 2**18

/// List of historical block root hashes up to historical_roots_limit.
type HistoricalBlockHashes = ssz_types::VariableList<H256, HistoricalRootsLimit>;

/// Bitlist tracking justified slots up to historical roots limit.
type JustifiedSlots = ssz_types::BitList<HistoricalRootsLimit>;

/// List of justified block roots up to historical_roots_limit.
type JustificationRoots = ssz_types::VariableList<H256, HistoricalRootsLimit>;

/// Bitlist for tracking validator justifications per historical root.
type JustificationValidators =
    ssz_types::BitList<ssz_types::typenum::Prod<HistoricalRootsLimit, ValidatorRegistryLimit>>;

/// Represents a validator's static metadata and operational interface.
#[derive(Debug, Clone, Encode, Decode, TreeHash)]
pub struct Validator {
    /// XMSS one-time signature public key.
    pub pubkey: ValidatorPubkey,
    /// Validator index in the registry.
    pub index: u64,
}

pub type ValidatorPubkey = [u8; 52];

impl State {
    pub fn from_genesis(genesis: &Genesis, validators: Vec<Validator>) -> Self {
        let genesis_header = BlockHeader {
            slot: 0,
            proposer_index: 0,
            parent_root: H256::ZERO,
            state_root: H256::ZERO,
            body_root: BlockBody::default().tree_hash_root(),
        };
        let validators = ssz_types::VariableList::new(validators).unwrap();
        let justified_slots =
            JustifiedSlots::with_capacity(0).expect("failed to initialize empty list");
        let justifications_validators =
            JustificationValidators::with_capacity(0).expect("failed to initialize empty list");

        let state = State {
            config: genesis.config.clone(),
            slot: 0,
            latest_block_header: genesis_header,
            latest_justified: genesis.latest_justified.clone(),
            latest_finalized: genesis.latest_finalized.clone(),
            historical_block_hashes: Default::default(),
            justified_slots,
            validators,
            justifications_roots: Default::default(),
            justifications_validators,
        };

        dbg!(state.tree_hash_root());

        state
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct Checkpoint {
    pub root: H256,
    // Used U256 due to it being serialized as string
    #[serde(deserialize_with = "deser_dec_str")]
    pub slot: u64,
}

// Taken from ethrex-common
pub fn deser_dec_str<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let value = String::deserialize(d)?;
    value
        .parse()
        .map_err(|_| D::Error::custom("Failed to deserialize u64 value"))
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct NetworkConfig {
    pub genesis_time: u64,
}
