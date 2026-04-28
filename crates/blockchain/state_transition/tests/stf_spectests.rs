use std::collections::HashMap;
use std::path::Path;

use ethlambda_state_transition::state_transition;
use ethlambda_types::{
    block::Block,
    primitives::{H256, HashTreeRoot as _},
    state::State,
};

use crate::types::PostState;

const SUPPORTED_FIXTURE_FORMAT: &str = "state_transition_test";

mod types;

fn run(path: &Path) -> datatest_stable::Result<()> {
    let tests = types::StateTransitionTestVector::from_file(path)?;
    for (name, test) in tests.tests {
        if test.info.fixture_format != SUPPORTED_FIXTURE_FORMAT {
            return Err(format!(
                "Unsupported fixture format: {} (expected {})",
                test.info.fixture_format, SUPPORTED_FIXTURE_FORMAT
            )
            .into());
        }
        println!("Running test: {}", name);

        let mut pre_state: State = test.pre.into();
        let mut result = Ok(());

        // Build a block registry mapping "block_N" labels to hash tree roots.
        // Labels are 1-indexed: "block_1" is the first block in the array.
        let mut block_registry: HashMap<String, H256> = HashMap::new();
        let blocks_empty = test.blocks.is_empty();
        for (i, block) in test.blocks.into_iter().enumerate() {
            let block: Block = block.into();
            let label = format!("block_{}", i + 1);
            block_registry.insert(label, block.hash_tree_root());
            result = state_transition(&mut pre_state, &block);
            if result.is_err() {
                break;
            }
        }
        let post_state = pre_state;
        match (result, test.post) {
            (Ok(_), Some(expected_post)) => {
                compare_post_states(&post_state, &expected_post, &block_registry)?;
            }
            (Ok(_), None) if blocks_empty && test.expect_exception.is_some() => {
                // Negative test where the spec filler raised during pre-block
                // construction (so `blocks: []` in the fixture). The intended
                // failure is recorded in `expectException`; ethlambda has no
                // block to replay, so the spec framework's verdict stands.
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
    Ok(())
}

fn resolve_label(
    label: &str,
    block_registry: &HashMap<String, H256>,
) -> datatest_stable::Result<H256> {
    block_registry.get(label).copied().ok_or_else(|| {
        format!(
            "label '{}' not found in block registry. Available: {:?}",
            label,
            block_registry.keys().collect::<Vec<_>>()
        )
        .into()
    })
}

fn compare_post_states(
    post_state: &State,
    expected_post: &PostState,
    block_registry: &HashMap<String, H256>,
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
        latest_justified_root_label,
        latest_finalized_root_label,
        justifications_roots_labels,
        justifications_roots_count,
        justifications_validators_count,
    } = expected_post;
    if let Some(config_genesis_time) = config_genesis_time
        && post_state.config.genesis_time != *config_genesis_time
    {
        return Err(format!(
            "genesis_time mismatch: expected {}, got {}",
            config_genesis_time, post_state.config.genesis_time
        )
        .into());
    }
    if let Some(slot) = slot
        && post_state.slot != *slot
    {
        return Err(format!("slot mismatch: expected {}, got {}", slot, post_state.slot).into());
    }
    if let Some(latest_block_header_slot) = latest_block_header_slot
        && post_state.latest_block_header.slot != *latest_block_header_slot
    {
        return Err(format!(
            "latest_block_header.slot mismatch: expected {}, got {}",
            latest_block_header_slot, post_state.latest_block_header.slot
        )
        .into());
    }
    if let Some(latest_block_header_state_root) = latest_block_header_state_root
        && post_state.latest_block_header.state_root != *latest_block_header_state_root
    {
        return Err(format!(
            "latest_block_header.state_root mismatch: expected {:?}, got {:?}",
            latest_block_header_state_root, post_state.latest_block_header.state_root
        )
        .into());
    }
    if let Some(latest_block_header_proposer_index) = latest_block_header_proposer_index
        && post_state.latest_block_header.proposer_index != *latest_block_header_proposer_index
    {
        return Err(format!(
            "latest_block_header.proposer_index mismatch: expected {}, got {}",
            latest_block_header_proposer_index, post_state.latest_block_header.proposer_index
        )
        .into());
    }
    if let Some(latest_block_header_parent_root) = latest_block_header_parent_root
        && post_state.latest_block_header.parent_root != *latest_block_header_parent_root
    {
        return Err(format!(
            "latest_block_header.parent_root mismatch: expected {:?}, got {:?}",
            latest_block_header_parent_root, post_state.latest_block_header.parent_root
        )
        .into());
    }
    if let Some(latest_block_header_body_root) = latest_block_header_body_root
        && post_state.latest_block_header.body_root != *latest_block_header_body_root
    {
        return Err(format!(
            "latest_block_header.body_root mismatch: expected {:?}, got {:?}",
            latest_block_header_body_root, post_state.latest_block_header.body_root
        )
        .into());
    }
    if let Some(latest_justified_slot) = latest_justified_slot
        && post_state.latest_justified.slot != *latest_justified_slot
    {
        return Err(format!(
            "latest_justified.slot mismatch: expected {}, got {}",
            latest_justified_slot, post_state.latest_justified.slot
        )
        .into());
    }
    if let Some(latest_justified_root) = latest_justified_root
        && post_state.latest_justified.root != *latest_justified_root
    {
        return Err(format!(
            "latest_justified.root mismatch: expected {:?}, got {:?}",
            latest_justified_root, post_state.latest_justified.root
        )
        .into());
    }
    if let Some(latest_finalized_slot) = latest_finalized_slot
        && post_state.latest_finalized.slot != *latest_finalized_slot
    {
        return Err(format!(
            "latest_finalized.slot mismatch: expected {}, got {}",
            latest_finalized_slot, post_state.latest_finalized.slot
        )
        .into());
    }
    if let Some(latest_finalized_root) = latest_finalized_root
        && post_state.latest_finalized.root != *latest_finalized_root
    {
        return Err(format!(
            "latest_finalized.root mismatch: expected {:?}, got {:?}",
            latest_finalized_root, post_state.latest_finalized.root
        )
        .into());
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
        let post_slots: Vec<bool> = (0..justified_slots.data.len())
            .map(|i| post_state.justified_slots.get(i) == Some(true))
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
        let post_validators: Vec<_> = (0..post_state.justifications_validators.len())
            .map(|i| post_state.justifications_validators.get(i) == Some(true))
            .collect();
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
    if let Some(label) = latest_justified_root_label {
        let expected = resolve_label(label, block_registry)?;
        if post_state.latest_justified.root != expected {
            return Err(format!(
                "latest_justified.root mismatch (via label '{label}'): expected {expected:?}, got {:?}",
                post_state.latest_justified.root
            )
            .into());
        }
    }
    if let Some(label) = latest_finalized_root_label {
        let expected = resolve_label(label, block_registry)?;
        if post_state.latest_finalized.root != expected {
            return Err(format!(
                "latest_finalized.root mismatch (via label '{label}'): expected {expected:?}, got {:?}",
                post_state.latest_finalized.root
            )
            .into());
        }
    }
    if let Some(labels) = justifications_roots_labels {
        let expected_roots: Vec<H256> = labels
            .iter()
            .map(|label| resolve_label(label, block_registry))
            .collect::<datatest_stable::Result<Vec<_>>>()?;
        let post_roots: Vec<_> = post_state.justifications_roots.iter().copied().collect();
        if post_roots != expected_roots {
            return Err(format!(
                "justifications_roots mismatch (via labels {labels:?}): expected {expected_roots:?}, got {post_roots:?}",
            )
            .into());
        }
    }
    if let Some(expected_count) = justifications_roots_count {
        let count = post_state.justifications_roots.len() as u64;
        if count != *expected_count {
            return Err(format!(
                "justifications_roots count mismatch: expected {expected_count}, got {count}",
            )
            .into());
        }
    }
    if let Some(expected_count) = justifications_validators_count {
        let count = post_state.justifications_validators.len() as u64;
        if count != *expected_count {
            return Err(format!(
                "justifications_validators count mismatch: expected {expected_count}, got {count}",
            )
            .into());
        }
    }
    Ok(())
}

datatest_stable::harness!({test = run, root = "../../../leanSpec/fixtures/consensus/state_transition", pattern = r".*\.json"});
