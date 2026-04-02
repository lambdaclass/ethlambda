use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszBitlist, SszList};
use serde::{Deserialize, Serialize};

use crate::{
    block::{BlockBody, BlockHeader},
    checkpoint::Checkpoint,
    primitives::{self, H256},
    signature::{SignatureParseError, ValidatorPublicKey},
};

// Convenience trait for calling hash_tree_root() without a hasher argument
use primitives::HashTreeRoot as _;

/// The main consensus state object
#[derive(Debug, Clone, SszEncode, SszDecode, HashTreeRoot)]
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
    pub validators: SszList<Validator, VALIDATOR_REGISTRY_LIMIT>,
    /// Roots of justified blocks
    pub justifications_roots: JustificationRoots,
    /// A bitlist of validators who participated in justifications
    pub justifications_validators: JustificationValidators,
}

/// The maximum number of historical block roots to store in the state.
///
/// With a 4-second slot, this corresponds to a history
/// of approximately 12.1 days.
pub const HISTORICAL_ROOTS_LIMIT: usize = 262_144; // 2**18

/// List of historical block root hashes up to historical_roots_limit.
type HistoricalBlockHashes = SszList<H256, HISTORICAL_ROOTS_LIMIT>;

/// Bitlist tracking justified slots up to historical roots limit.
pub type JustifiedSlots = SszBitlist<HISTORICAL_ROOTS_LIMIT>;

/// List of justified block roots up to historical_roots_limit.
pub type JustificationRoots = SszList<H256, HISTORICAL_ROOTS_LIMIT>;

/// Maximum number of validators in the registry.
pub const VALIDATOR_REGISTRY_LIMIT: usize = 4096;

/// Bitlist for tracking validator justifications per historical root.
///
/// Maximum size is HISTORICAL_ROOTS_LIMIT × VALIDATOR_REGISTRY_LIMIT.
pub type JustificationValidators =
    SszBitlist<{ HISTORICAL_ROOTS_LIMIT * VALIDATOR_REGISTRY_LIMIT }>;

/// Represents a validator's static metadata and operational interface.
#[derive(Debug, Clone, Serialize, SszEncode, SszDecode, HashTreeRoot)]
pub struct Validator {
    /// XMSS one-time signature public key.
    #[serde(serialize_with = "serialize_pubkey_hex")]
    pub pubkey: ValidatorPubkeyBytes,
    /// Validator index in the registry.
    pub index: u64,
}

fn serialize_pubkey_hex<S>(pubkey: &ValidatorPubkeyBytes, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(pubkey))
}

impl Validator {
    pub fn get_pubkey(&self) -> Result<ValidatorPublicKey, SignatureParseError> {
        // TODO: make this unfallible by moving check to the constructor
        ValidatorPublicKey::from_bytes(&self.pubkey)
    }
}

pub type ValidatorPubkeyBytes = [u8; 52];

impl State {
    pub fn from_genesis(genesis_time: u64, validators: Vec<Validator>) -> Self {
        let genesis_header = BlockHeader {
            slot: 0,
            proposer_index: 0,
            parent_root: H256::ZERO,
            state_root: H256::ZERO,
            body_root: BlockBody::default().hash_tree_root(),
        };
        let validators = SszList::try_from(validators).unwrap();
        let justified_slots = JustifiedSlots::new();
        let justifications_validators = JustificationValidators::new();

        Self {
            config: ChainConfig { genesis_time },
            slot: 0,
            latest_block_header: genesis_header,
            latest_justified: Checkpoint::default(),
            latest_finalized: Checkpoint::default(),
            historical_block_hashes: Default::default(),
            justified_slots,
            validators,
            justifications_roots: Default::default(),
            justifications_validators,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SszEncode, SszDecode, HashTreeRoot)]
pub struct ChainConfig {
    pub genesis_time: u64,
}
