use std::path::Path;

use ethlambda_state_transition::state_transition;
use ethlambda_types::{block::Block, primitives::TreeHash, state::State};

use crate::types::PostState;

mod types;

fn run(path: &Path) -> datatest_stable::Result<()> {
    let tests = types::StateTransitionTestVector::from_file(path)?;
    for (name, test) in tests.tests {
        println!("Running test: {}", name);

        let mut pre_state: State = test.pre.into();
        let mut result = Ok(());

        for block in test.blocks {
            let block: Block = block.into();
            result = state_transition(&mut pre_state, &block);
            if result.is_err() {
                break;
            }
        }
        let post_state = pre_state;
        match (result, test.post) {
            (Ok(_), Some(expected_post)) => {
                compare_post_states(&post_state, &expected_post)?;
            }
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

fn compare_post_states(
    post_state: &State,
    expected_post: &PostState,
) -> datatest_stable::Result<()> {
    let PostState {
        config_genesis_time,
        slot,
        latest_block_header_slot,
        latest_block_header_state_root,
        latest_block_header_proposer_index,
        latest_block_header_parent_root,
        latest_block_header_body_root,
        latest_justified_slot,
        latest_justified_root,
        latest_finalized_slot,
        latest_finalized_root,
        historical_block_hashes_count,
        historical_block_hashes,
        justified_slots,
        justifications_roots,
        justifications_validators,
        validator_count,
    } = expected_post;
    if let Some(config_genesis_time) = config_genesis_time {
        if post_state.config.genesis_time != *config_genesis_time {
            return Err(format!(
                "genesis_time mismatch: expected {}, got {}",
                config_genesis_time, post_state.config.genesis_time
            )
            .into());
        }
    }
    if let Some(slot) = slot {
        if post_state.slot != *slot {
            return Err(
                format!("slot mismatch: expected {}, got {}", slot, post_state.slot).into(),
            );
        }
    }
    if let Some(latest_block_header_slot) = latest_block_header_slot {
        if post_state.latest_block_header.slot != *latest_block_header_slot {
            return Err(format!(
                "latest_block_header.slot mismatch: expected {}, got {}",
                latest_block_header_slot, post_state.latest_block_header.slot
            )
            .into());
        }
    }
    Ok(())
}

datatest_stable::harness!({test = run, root = "../../../leanSpec/fixtures/consensus/state_transition", pattern = r".*\.json"});
