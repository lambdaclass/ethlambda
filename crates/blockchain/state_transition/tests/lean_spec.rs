use std::path::Path;

use ethlambda_state_transition::state_transition;
use ethlambda_types::{block::Block, primitives::TreeHash, state::State};

mod types;

fn run(path: &Path) -> datatest_stable::Result<()> {
    let tests = types::StateTransitionTestVector::from_file(path)?;
    for (name, test) in tests.tests {
        println!("Running test: {}", name);

        let mut pre_state: State = test.pre.into();
        dbg!(&pre_state.latest_block_header);
        dbg!(pre_state.latest_block_header.tree_hash_root());
        let mut result = Ok(());
        for block in test.blocks {
            let block: Block = block.into();
            result = state_transition(&mut pre_state, &block);
            if result.is_err() {
                break;
            }
        }
        match (result, test.post) {
            (Ok(_), Some(expected_post)) => {}
            (Ok(_), None) => {
                return Err(
                    format!("Test '{name}' failed: expected failure but got success").into(),
                );
            }
            (Err(_), None) => {
                // Expected failure
            }
            (Err(err), Some(_)) => {
                return Err(format!(
                    "Test '{name}' failed: expected success but got failure ({err})"
                )
                .into());
            }
        }
    }
    return Ok(());
}

datatest_stable::harness!({test = run, root = "../../../leanSpec/fixtures/consensus/state_transition", pattern = r".*\.json"});
