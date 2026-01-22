use serde::{Deserialize, Serialize};
use ssz::DecodeError;
use ssz_derive::{Decode, Encode};
use ssz_types::typenum::{U4096, U262144};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    block::{BlockBody, BlockHeader},
    genesis::Genesis,
    primitives::H256,
    signature::ValidatorPublicKey,
};

// Constants

/// The maximum number of validators that can be in the registry.
pub type ValidatorRegistryLimit = U4096;

/// The main consensus state object
#[derive(Debug, Clone, Encode, Decode, TreeHash)]
pub struct State {
    /// The chain's configuration parameters
    pub config: ChainConfig,
    /// The current slot number
    pub slot: u64,
    /// The header of the most recent block
    pub latest_block_header: BlockHeader,
    /// The latest justified checkpoint
    pub latest_justified: Checkpoint,
    /// The latest finalized checkpoint
    pub latest_finalized: Checkpoint,
    /// A list of historical block root hashes
    pub historical_block_hashes: HistoricalBlockHashes,
    /// A bitfield indicating which historical slots were justified
    pub justified_slots: JustifiedSlots,
    /// Registry of validators tracked by the state
    pub validators: ssz_types::VariableList<Validator, ValidatorRegistryLimit>,
    /// Roots of justified blocks
    pub justifications_roots: JustificationRoots,
    /// A bitlist of validators who participated in justifications
    pub justifications_validators: JustificationValidators,
}

/// The maximum number of historical block roots to store in the state.
///
/// With a 4-second slot, this corresponds to a history
/// of approximately 12.1 days.
type HistoricalRootsLimit = U262144; // 2**18

/// List of historical block root hashes up to historical_roots_limit.
type HistoricalBlockHashes = ssz_types::VariableList<H256, HistoricalRootsLimit>;

/// Bitlist tracking justified slots up to historical roots limit.
pub type JustifiedSlots = ssz_types::BitList<HistoricalRootsLimit>;

/// List of justified block roots up to historical_roots_limit.
pub type JustificationRoots = ssz_types::VariableList<H256, HistoricalRootsLimit>;

/// Bitlist for tracking validator justifications per historical root.
pub type JustificationValidators =
    ssz_types::BitList<ssz_types::typenum::Prod<HistoricalRootsLimit, ValidatorRegistryLimit>>;

/// Represents a validator's static metadata and operational interface.
#[derive(Debug, Clone, Encode, Decode, TreeHash)]
pub struct Validator {
    /// XMSS one-time signature public key.
    pub pubkey: ValidatorPubkeyBytes,
    /// Validator index in the registry.
    pub index: u64,
}

impl Validator {
    pub fn get_pubkey(&self) -> Result<ValidatorPublicKey, DecodeError> {
        // TODO: make this unfallible by moving check to the constructor
        ValidatorPublicKey::from_bytes(&self.pubkey)
    }
}

pub type ValidatorPubkeyBytes = [u8; 52];

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

        Self {
            config: genesis.config.clone(),
            slot: 0,
            latest_block_header: genesis_header,
            latest_justified: genesis.latest_justified,
            latest_finalized: genesis.latest_finalized,
            historical_block_hashes: Default::default(),
            justified_slots,
            validators,
            justifications_roots: Default::default(),
            justifications_validators,
        }
    }
}

/// Represents a checkpoint in the chain's history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct Checkpoint {
    /// The root hash of the checkpoint's block.
    pub root: H256,
    /// The slot number of the checkpoint's block.
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
pub struct ChainConfig {
    pub genesis_time: u64,
}
