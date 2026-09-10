#![no_main]
sp1_zkvm::entrypoint!(main);

use ethlambda_state_transition::state_transition;
use ethlambda_types::{
    primitives::HashTreeRoot,
    stf::{StfInput, StfPublicValues},
};

fn main() {
    let input: StfInput = sp1_zkvm::io::read(); 
    let mut state = input.state();
    let block = input.block();

    // Capture the pre-state and block roots before mutating the state, so the
    // committed public values bind the proof to this specific transition.
    let pre_state_root = state.hash_tree_root();
    let block_root = block.hash_tree_root();

    state_transition(&mut state, &block).expect("state transition failed");

    let public_values = StfPublicValues {
        pre_state_root,
        block_root,
        // state_transition already asserts this equals block.state_root.
        post_state_root: state.hash_tree_root(),
    };
    sp1_zkvm::io::commit(&public_values);
}
