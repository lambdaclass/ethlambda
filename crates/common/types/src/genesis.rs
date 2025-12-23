use ethereum_types::H256;
use serde::{Deserialize, Serialize};

use crate::state::{Checkpoint, NetworkConfig};

#[derive(Debug, Serialize, Deserialize)]
pub struct Genesis {
    config: NetworkConfig,
    latest_justified: Checkpoint,
    latest_finalized: Checkpoint,
    historical_block_hashes: Vec<H256>,
    justified_slots: Vec<bool>,
    // justifications_roots: Vec<String>,
    // TODO: this is an SSZ bitlist
    // justifications_validators: String,
}
