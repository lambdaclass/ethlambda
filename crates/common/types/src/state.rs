use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszBitlist, SszList};
use serde::{Deserialize, Serialize};

use crate::{
    block::{Block, BlockBody, BlockHeader},
    checkpoint::Checkpoint,
    primitives::{self, H256},
};

// Convenience trait for calling hash_tree_root() without a hasher argument
use primitives::HashTreeRoot as _;

/// The main consensus state object
#[derive(Debug, Clone, PartialEq, SszEncode, SszDecode, HashTreeRoot)]
pub struct State {
    /// The chain's genesis parameters
    pub config: StateConfig,
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
/// With the default 4-second slot, this corresponds to a history of
/// approximately 12.1 days; a network running a longer slot covers
/// proportionally more time with the same limit.
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
///
/// Each validator has two independent XMSS keys: one for signing attestations
/// and one for signing block proposals. This allows signing both in the same
/// slot without violating OTS (one-time signature) constraints.
#[derive(Debug, Clone, PartialEq, Serialize, SszEncode, SszDecode, HashTreeRoot)]
pub struct Validator {
    /// XMSS public key used for attestation signing.
    #[serde(serialize_with = "serialize_pubkey_hex")]
    pub attestation_pubkey: ValidatorPubkeyBytes,
    /// XMSS public key used for block proposal signing.
    #[serde(serialize_with = "serialize_pubkey_hex")]
    pub proposal_pubkey: ValidatorPubkeyBytes,
    /// Validator index in the registry.
    pub index: u64,
}

fn serialize_pubkey_hex<S>(pubkey: &ValidatorPubkeyBytes, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(pubkey))
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
            config: StateConfig { genesis_time },
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

/// The genesis parameters baked into the state and hashed into its root, the
/// spec's `Config` container (leanSpec's `GenesisConfig`,
/// `forks/lstar/containers/state.py`).
///
/// Spec-fixed and cross-client: adding a field here changes every lean state
/// root and forks this client off every other one.
/// [`crate::chain_config::ChainConfig`] is the node's own runtime view, a
/// different type for a different job: this plus the slot duration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, SszEncode, SszDecode, HashTreeRoot)]
pub struct StateConfig {
    pub genesis_time: u64,
}

/// Validate that an `(anchor_state, anchor_block)` pair is structurally consistent.
///
/// Used by every code path that bootstraps a fork-choice store (Store
/// constructor, checkpoint-sync client, hive test driver) to enforce the same
/// invariants without duplicating the check:
///
/// 1. `anchor_block.header()` and `state.latest_block_header` must agree on
///    every field once `state_root` is zeroed.
/// 2. `state.latest_block_header.state_root` must be either zero (raw /
///    pre-fill form) or match the tree-hash root of the state computed with
///    that field zeroed.
/// 3. `anchor_block.state_root` must equal that same canonical tree-hash root.
///    A block whose `state_root` disagrees with the supplied anchor state is
///    structurally inconsistent and must be refused at init.
///
/// Takes `&mut State` to zero `latest_block_header.state_root` in place around
/// the hash computation rather than cloning the whole state (validator set +
/// historical roots can be hundreds of KB). The original `state_root` is
/// restored before the function returns.
pub fn anchor_pair_is_consistent(state: &mut State, block: &Block) -> bool {
    let mut state_header = state.latest_block_header.clone();
    let mut block_header = block.header();
    state_header.state_root = H256::ZERO;
    block_header.state_root = H256::ZERO;
    if state_header != block_header {
        return false;
    }

    let saved = state.latest_block_header.state_root;
    state.latest_block_header.state_root = H256::ZERO;
    let computed = state.hash_tree_root();
    state.latest_block_header.state_root = saved;

    if saved != H256::ZERO && saved != computed {
        return false;
    }

    block.state_root == computed
}

#[cfg(test)]
mod tests {
    use super::State;
    use crate::primitives::HashTreeRoot as _;

    /// Captured from the build that introduced this test.
    const EXPECTED_GENESIS_ROOT: &str =
        "97720dcece1942bac508933252fb58550e4ec357842b4465956459a42920d053";

    /// The container's layout is cross-client, so this pins the genesis
    /// state's root: a field reorder, an added field, or a type change
    /// disguised as a rename fails here rather than in interop.
    #[test]
    fn the_genesis_state_root_is_fixed() {
        let state = State::from_genesis(1234, vec![]);
        let root = state.hash_tree_root();

        assert_eq!(
            hex::encode(root.0),
            EXPECTED_GENESIS_ROOT,
            "the genesis state root changed; every other lean client disagrees now"
        );
    }
}
