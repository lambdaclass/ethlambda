use std::path::Path;

use ethlambda_state_transition::state_transition;
use ethlambda_types::{block::Block, state::State};

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
    if let Some(latest_block_header_state_root) = latest_block_header_state_root {
        if post_state.latest_block_header.state_root != *latest_block_header_state_root {
            return Err(format!(
                "latest_block_header.state_root mismatch: expected {:?}, got {:?}",
                latest_block_header_state_root, post_state.latest_block_header.state_root
            )
            .into());
        }
    }
    if let Some(latest_block_header_proposer_index) = latest_block_header_proposer_index {
        if post_state.latest_block_header.proposer_index != *latest_block_header_proposer_index {
            return Err(format!(
                "latest_block_header.proposer_index mismatch: expected {}, got {}",
                latest_block_header_proposer_index, post_state.latest_block_header.proposer_index
            )
            .into());
        }
    }
    if let Some(latest_block_header_parent_root) = latest_block_header_parent_root {
        if post_state.latest_block_header.parent_root != *latest_block_header_parent_root {
            return Err(format!(
                "latest_block_header.parent_root mismatch: expected {:?}, got {:?}",
                latest_block_header_parent_root, post_state.latest_block_header.parent_root
            )
            .into());
        }
    }
    if let Some(latest_block_header_body_root) = latest_block_header_body_root {
        if post_state.latest_block_header.body_root != *latest_block_header_body_root {
            return Err(format!(
                "latest_block_header.body_root mismatch: expected {:?}, got {:?}",
                latest_block_header_body_root, post_state.latest_block_header.body_root
            )
            .into());
        }
    }
    if let Some(latest_justified_slot) = latest_justified_slot {
        if post_state.latest_justified.slot != *latest_justified_slot {
            return Err(format!(
                "latest_justified.slot mismatch: expected {}, got {}",
                latest_justified_slot, post_state.latest_justified.slot
            )
            .into());
        }
    }
    if let Some(latest_justified_root) = latest_justified_root {
        if post_state.latest_justified.root != *latest_justified_root {
            return Err(format!(
                "latest_justified.root mismatch: expected {:?}, got {:?}",
                latest_justified_root, post_state.latest_justified.root
            )
            .into());
        }
    }
    if let Some(latest_finalized_slot) = latest_finalized_slot {
        if post_state.latest_finalized.slot != *latest_finalized_slot {
            return Err(format!(
                "latest_finalized.slot mismatch: expected {}, got {}",
                latest_finalized_slot, post_state.latest_finalized.slot
            )
            .into());
        }
    }
    if let Some(latest_finalized_root) = latest_finalized_root {
        if post_state.latest_finalized.root != *latest_finalized_root {
            return Err(format!(
                "latest_finalized.root mismatch: expected {:?}, got {:?}",
                latest_finalized_root, post_state.latest_finalized.root
            )
            .into());
        }
    }
    if let Some(historical_block_hashes_count) = historical_block_hashes_count {
        let count = post_state.historical_block_hashes.len() as u64;
        if count != *historical_block_hashes_count {
            return Err(format!(
                "historical_block_hashes count mismatch: expected {}, got {}",
                historical_block_hashes_count, count
            )
            .into());
        }
    }
    if let Some(historical_block_hashes) = historical_block_hashes {
        let post_hashes: Vec<_> = post_state.historical_block_hashes.iter().copied().collect();
        if post_hashes != historical_block_hashes.data {
            return Err(format!(
                "historical_block_hashes mismatch: expected {:?}, got {:?}",
                historical_block_hashes.data, post_hashes
            )
            .into());
        }
    }
    if let Some(justified_slots) = justified_slots {
        let post_slots: Vec<_> = post_state
            .justified_slots
            .iter()
            .enumerate()
            .filter_map(|(i, bit)| if bit { Some(i as u64) } else { None })
            .collect();
        if post_slots != justified_slots.data {
            return Err(format!(
                "justified_slots mismatch: expected {:?}, got {:?}",
                justified_slots.data, post_slots
            )
            .into());
        }
    }
    if let Some(justifications_roots) = justifications_roots {
        let post_roots: Vec<_> = post_state.justifications_roots.iter().copied().collect();
        if post_roots != justifications_roots.data {
            return Err(format!(
                "justifications_roots mismatch: expected {:?}, got {:?}",
                justifications_roots.data, post_roots
            )
            .into());
        }
    }
    if let Some(justifications_validators) = justifications_validators {
        let post_validators: Vec<_> = post_state.justifications_validators.iter().collect();
        if post_validators != justifications_validators.data {
            return Err(format!(
                "justifications_validators mismatch: expected {:?}, got {:?}",
                justifications_validators.data, post_validators
            )
            .into());
        }
    }
    if let Some(validator_count) = validator_count {
        let count = post_state.validators.len() as u64;
        if count != *validator_count {
            return Err(format!(
                "validator count mismatch: expected {}, got {}",
                validator_count, count
            )
            .into());
        }
    }
    Ok(())
}

datatest_stable::harness!({test = run, root = "../../../leanSpec/fixtures/consensus/state_transition", pattern = r".*\.json"});
