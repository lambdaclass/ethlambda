use ethereum_types::{H256, U256};
use serde::{Deserialize, Serialize};

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
    /// A list of historical block root hashes
    historical_block_hashes: HistoricalBlockHashes,
    /// A bitfield indicating which historical slots were justified
    justified_slots: JustifiedSlots,
    /// Registry of validators tracked by the state
    validators: Validators,
    /// Roots of justified blocks
    justifications_roots: JustificationRoots,
    /// A bitlist of validators who participated in justifications
    justifications_validators: JustificationValidators,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Checkpoint {
    root: H256,
    // Used U256 due to it being serialized as string
    slot: U256,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    num_validators: u64,
    genesis_time: u64,
}
