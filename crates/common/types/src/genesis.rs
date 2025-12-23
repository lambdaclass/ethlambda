use ethereum_types::H256;
use serde::{Deserialize, Serialize};

use crate::state::{Checkpoint, NetworkConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Genesis {
    pub config: NetworkConfig,
    pub latest_justified: Checkpoint,
    pub latest_finalized: Checkpoint,
    pub historical_block_hashes: Vec<H256>,
    pub justified_slots: Vec<bool>,
    // TODO: uncomment
    // pub justifications_roots: Vec<String>,
    // TODO: this is an SSZ bitlist
    // pub justifications_validators: String,
}
