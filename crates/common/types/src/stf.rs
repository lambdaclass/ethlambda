use libssz::{SszDecode, SszEncode};
use serde::{Deserialize, Serialize};

use crate::{block::Block, primitives::H256, state::State};

/// Input type for the zkVM's
///
/// The inputs to the zkVM need to derive serde Serialize/deserialize
/// which is not derived for state (libssz traits)
/// wrapping pre-serialized SSZ bytes sidesteps that part.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StfInput {
    state: Vec<u8>,
    block: Vec<u8>,
}

/// Public values committed by the STF guest program.
///
/// These bind a proof to one concrete transition: applying the block with
/// `block_root` to the state with `pre_state_root` yields the state with
/// `post_state_root`. A verifier reads these back from the proof without ever
/// seeing the full pre-state or block, and can chain proofs by matching one
/// transition's `post_state_root` to the next's `pre_state_root`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StfPublicValues {
    /// `hash_tree_root` of the pre-state.
    pub pre_state_root: H256,
    /// `hash_tree_root` of the block being applied.
    pub block_root: H256,
    /// `hash_tree_root` of the post-state (equals `block.state_root`).
    pub post_state_root: H256,
}

impl StfInput {
    pub fn new(state: State, block: Block) -> Self {
        StfInput {
            state: state.to_ssz(),
            block: block.to_ssz(),
        }
    }

    pub fn state(&self) -> State {
        State::from_ssz_bytes(&self.state).expect("error decoding State")
    }

    pub fn block(&self) -> Block {
        Block::from_ssz_bytes(&self.block).expect("error decoding block")
    }
}
