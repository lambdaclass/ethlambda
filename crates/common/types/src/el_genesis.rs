//! Genesis anchor construction for nodes paired with an execution layer.
//!
//! Lives in its own module (rather than `state.rs`) so the EL integration
//! keeps its footprint out of the core consensus types.

use crate::{
    block::{Block, BlockBody},
    execution_payload::ExecutionPayloadV3,
    primitives::{H256, HashTreeRoot as _},
    state::{State, Validator},
};

impl State {
    /// Genesis state + block pair for a node paired with an execution layer,
    /// seeded with the EL's genesis block hash.
    ///
    /// The hash must be seeded in two places, and the anchor pair must stay
    /// self-consistent — this constructor owns that protocol:
    ///
    /// 1. `latest_execution_payload_header.block_hash = el_hash` — drives the
    ///    STF's `process_execution_payload` parent-hash check for the first
    ///    non-genesis block.
    /// 2. The genesis block body's `execution_payload.block_hash = el_hash` —
    ///    what the fork choice reads back into `engine_forkchoiceUpdatedV3`'s
    ///    `head_block_hash`. The header's `body_root` is re-stamped to match.
    /// 3. `latest_block_header.state_root` (and the block's `state_root`) is
    ///    the state's hash-tree-root computed with that field zeroed —
    ///    `Store::get_forkchoice_store` requires the pair to match exactly.
    ///
    /// Without seeding *both* hashes, either the first non-genesis block fails
    /// the STF or every FCU stays at `H256::ZERO` and the EL never accepts a
    /// build request.
    pub fn from_genesis_with_el_hash(
        genesis_time: u64,
        validators: Vec<Validator>,
        el_hash: H256,
    ) -> (Self, Block) {
        let mut state = Self::from_genesis(genesis_time, validators);
        state.latest_execution_payload_header.block_hash = el_hash;

        let body = BlockBody {
            attestations: Default::default(),
            execution_payload: ExecutionPayloadV3 {
                block_hash: el_hash,
                ..Default::default()
            },
        };
        state.latest_block_header.body_root = body.hash_tree_root();

        state.latest_block_header.state_root = H256::ZERO;
        let anchor_state_root = state.hash_tree_root();
        state.latest_block_header.state_root = anchor_state_root;

        let genesis_block = Block {
            slot: state.latest_block_header.slot,
            proposer_index: state.latest_block_header.proposer_index,
            parent_root: state.latest_block_header.parent_root,
            state_root: anchor_state_root,
            body,
        };

        (state, genesis_block)
    }
}
