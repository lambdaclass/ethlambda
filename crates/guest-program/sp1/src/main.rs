#![no_main]
sp1_zkvm::entrypoint!(main);

use ethlambda_state_transition::state_transition;
use ethlambda_types::{primitives::HashTreeRoot, stf::StfInput};

fn main() {
    let input: StfInput = sp1_zkvm::io::read();
    let mut state = StfInput::return_state(input.clone());
    let block = &StfInput::return_block(input.clone());
    let _ = state_transition(&mut state, block);
    sp1_zkvm::io::commit(&state.hash_tree_root());
}
