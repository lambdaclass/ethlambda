use ethereum_types::{H256, U256};
use serde::{Deserialize, Serialize};

use crate::{block::BlockHeader, genesis::Genesis};

#[derive(Debug)]
pub struct Slot(u64);

/// The main consensus state object
#[derive(Debug)]
pub struct State {
    /// The chain's configuration parameters
    config: NetworkConfig,
    /// The current slot number
    slot: Slot,
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
            slot: Slot(0),
            latest_block_header: BlockHeader {
                slot: Slot(0),
                proposer_index: 0,
                parent_root: H256::zero(),
                state_root: H256::zero(),
                // TODO: this should be the hash_tree_root of an empty block body
                body_root: H256::zero(),
            },
            latest_justified: genesis.latest_justified.clone(),
            latest_finalized: genesis.latest_finalized.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Checkpoint {
    root: H256,
    // Used U256 due to it being serialized as string
    slot: U256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    num_validators: u64,
    genesis_time: u64,
}
