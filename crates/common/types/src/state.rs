use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::{block::BlockHeader, genesis::Genesis, primitives::H256};

/// The maximum number of validators that can be in the registry.
pub const VALIDATOR_REGISTRY_LIMIT: u64 = 4096; // 2 ** 12

/// The main consensus state object
#[derive(Debug)]
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
    // /// A list of historical block root hashes
    // historical_block_hashes: HistoricalBlockHashes,
    // /// A bitfield indicating which historical slots were justified
    // justified_slots: JustifiedSlots,
    // /// Registry of validators tracked by the state
    // validators: Validators,
    // /// Roots of justified blocks
    // justifications_roots: JustificationRoots,
    // /// A bitlist of validators who participated in justifications
    // justifications_validators: JustificationValidators,
}

impl State {
    pub fn from_genesis(genesis: &Genesis) -> Self {
        State {
            config: genesis.config.clone(),
            slot: 0,
            latest_block_header: BlockHeader {
                slot: 0,
                proposer_index: 0,
                parent_root: H256::ZERO,
                state_root: H256::ZERO,
                // TODO: this should be the hash_tree_root of an empty block body
                body_root: H256::ZERO,
            },
            latest_justified: genesis.latest_justified.clone(),
            latest_finalized: genesis.latest_finalized.clone(),
        }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub num_validators: u64,
    pub genesis_time: u64,
}
