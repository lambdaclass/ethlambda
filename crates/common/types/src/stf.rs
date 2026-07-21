use libssz::{SszDecode, SszEncode};
use serde::{Deserialize, Serialize};

use crate::{block::Block, state::State};

// we will pass as bytes, as we want this to be definitely serializable and both implement Sszencode and decode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StfInput {
    state: Vec<u8>,
    block: Vec<u8>,
}

impl StfInput {
    pub fn new(state: State, block: Block) -> Self {
        StfInput {
            state: state.to_ssz(),
            block: block.to_ssz(),
        }
    }

    pub fn return_state(input: Self) -> State {
        State::from_ssz_bytes(&input.state).expect("error decoding State")
    }

    pub fn return_block(input: Self) -> Block {
        Block::from_ssz_bytes(&input.block).expect("error decoding block")
    }
}
