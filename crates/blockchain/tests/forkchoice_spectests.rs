use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use ethlambda_blockchain::{SECONDS_PER_SLOT, store::Store};
use ethlambda_types::{
    attestation::Attestation,
    block::{Block, BlockSignatures, BlockWithAttestation, SignedBlockWithAttestation},
    primitives::{H256, TreeHash, VariableList},
    state::State,
};

use crate::types::{ForkChoiceTestVector, StoreChecks};

const SUPPORTED_FIXTURE_FORMAT: &str = "fork_choice_test";

mod types;

fn run(path: &Path) -> datatest_stable::Result<()> {
    let tests = ForkChoiceTestVector::from_file(path)?;

    for (name, test) in tests.tests {
        if test.info.fixture_format != SUPPORTED_FIXTURE_FORMAT {
            return Err(format!(
                "Unsupported fixture format: {} (expected {})",
                test.info.fixture_format, SUPPORTED_FIXTURE_FORMAT
            )
            .into());
        }
        println!("Running test: {}", name);

        // Initialize store from anchor state/block
        let anchor_state: State = test.anchor_state.into();
        let anchor_block: Block = test.anchor_block.into();
        let genesis_time = anchor_state.config.genesis_time;
        let mut store = Store::get_forkchoice_store(anchor_state, anchor_block);

        // Block registry: maps block labels to their roots
        let mut block_registry: HashMap<String, H256> = HashMap::new();

        // Process steps
        for (step_idx, step) in test.steps.into_iter().enumerate() {
            match step.step_type.as_str() {
                "block" => {
                    let block_data = step.block.expect("block step missing block data");

                    // Register block label if present
                    if let Some(ref label) = block_data.block_root_label {
                        let block: Block = block_data.block.clone().into();
                        let root = H256::from(block.tree_hash_root());
                        block_registry.insert(label.clone(), root);
                    }

                    let signed_block = build_signed_block(block_data);

                    let block_time =
                        signed_block.message.block.slot * SECONDS_PER_SLOT + genesis_time;

                    // NOTE: the has_proposal argument is set to true, following the spec
                    store.on_tick(block_time, true);
                    let result = store.on_block(signed_block);

                    match (result.is_ok(), step.valid) {
                        (true, false) => {
                            return Err(format!(
                                "Step {} expected failure but got success",
                                step_idx
                            )
                            .into());
                        }
                        (false, true) => {
                            return Err(format!(
                                "Step {} expected success but got failure: {:?}",
                                step_idx,
                                result.err()
                            )
                            .into());
                        }
                        _ => {}
                    }
                }
                "tick" => {
                    let timestamp = step.time.expect("tick step missing time");
                    // NOTE: the has_proposal argument is set to false, following the spec
                    store.on_tick(timestamp, false);
                }
                other => {
                    // Fail for unsupported step types for now
                    return Err(format!("Unsupported step type '{other}'",).into());
                }
            }

            // Validate checks
            if let Some(checks) = step.checks {
                validate_checks(&store, &checks, step_idx, &block_registry)?;
            }
        }
    }
    Ok(())
}

fn build_signed_block(block_data: types::BlockStepData) -> SignedBlockWithAttestation {
    let block: Block = block_data.block.into();
    let proposer_attestation: Attestation = block_data.proposer_attestation.into();

    SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block,
            proposer_attestation,
        },
        signature: BlockSignatures {
            proposer_signature: Default::default(),
            attestation_signatures: VariableList::empty(),
        },
    }
}

fn validate_checks(
    store: &Store,
    checks: &StoreChecks,
    step_idx: usize,
    block_registry: &HashMap<String, H256>,
) -> datatest_stable::Result<()> {
    // Error on unsupported check fields
    if checks.time.is_some() {
        return Err(format!("Step {}: 'time' check not supported", step_idx).into());
    }
    if checks.head_root_label.is_some() && checks.head_root.is_none() {
        return Err(format!(
            "Step {}: 'headRootLabel' without 'headRoot' not supported",
            step_idx
        )
        .into());
    }
    if checks.latest_justified_root_label.is_some() && checks.latest_justified_root.is_none() {
        return Err(format!(
            "Step {}: 'latestJustifiedRootLabel' without 'latestJustifiedRoot' not supported",
            step_idx
        )
        .into());
    }
    if checks.latest_finalized_root_label.is_some() && checks.latest_finalized_root.is_none() {
        return Err(format!(
            "Step {}: 'latestFinalizedRootLabel' without 'latestFinalizedRoot' not supported",
            step_idx
        )
        .into());
    }
    if checks.safe_target.is_some() {
        return Err(format!("Step {}: 'safeTarget' check not supported", step_idx).into());
    }
    if checks.attestation_target_slot.is_some() {
        return Err(format!(
            "Step {}: 'attestationTargetSlot' check not supported",
            step_idx
        )
        .into());
    }

    // Validate headSlot
    if let Some(expected_slot) = checks.head_slot {
        let head_root = store.head();
        let head_block = store
            .blocks()
            .get(&head_root)
            .ok_or_else(|| format!("Step {}: head block not found", step_idx))?;
        if head_block.slot != expected_slot {
            return Err(format!(
                "Step {}: headSlot mismatch: expected {}, got {}",
                step_idx, expected_slot, head_block.slot
            )
            .into());
        }
    }

    // Validate headRoot
    if let Some(ref expected_root) = checks.head_root {
        let head_root = store.head();
        if head_root != *expected_root {
            return Err(format!(
                "Step {}: headRoot mismatch: expected {:?}, got {:?}",
                step_idx, expected_root, head_root
            )
            .into());
        }
    }

    // Validate latestJustifiedSlot
    if let Some(expected_slot) = checks.latest_justified_slot {
        let justified = store.latest_justified();
        if justified.slot != expected_slot {
            return Err(format!(
                "Step {}: latestJustifiedSlot mismatch: expected {}, got {}",
                step_idx, expected_slot, justified.slot
            )
            .into());
        }
    }

    // Validate latestJustifiedRoot
    if let Some(ref expected_root) = checks.latest_justified_root {
        let justified = store.latest_justified();
        if justified.root != *expected_root {
            return Err(format!(
                "Step {}: latestJustifiedRoot mismatch: expected {:?}, got {:?}",
                step_idx, expected_root, justified.root
            )
            .into());
        }
    }

    // Validate latestFinalizedSlot
    if let Some(expected_slot) = checks.latest_finalized_slot {
        let finalized = store.latest_finalized();
        if finalized.slot != expected_slot {
            return Err(format!(
                "Step {}: latestFinalizedSlot mismatch: expected {}, got {}",
                step_idx, expected_slot, finalized.slot
            )
            .into());
        }
    }

    // Validate latestFinalizedRoot
    if let Some(ref expected_root) = checks.latest_finalized_root {
        let finalized = store.latest_finalized();
        if finalized.root != *expected_root {
            return Err(format!(
                "Step {}: latestFinalizedRoot mismatch: expected {:?}, got {:?}",
                step_idx, expected_root, finalized.root
            )
            .into());
        }
    }

    // Validate attestationChecks
    if let Some(ref att_checks) = checks.attestation_checks {
        for att_check in att_checks {
            validate_attestation_check(store, att_check, step_idx)?;
        }
    }

    // Validate lexicographicHeadAmong
    if let Some(ref fork_labels) = checks.lexicographic_head_among {
        validate_lexicographic_head_among(store, fork_labels, step_idx, block_registry)?;
    }

    Ok(())
}

fn validate_attestation_check(
    store: &Store,
    check: &types::AttestationCheck,
    step_idx: usize,
) -> datatest_stable::Result<()> {
    let validator_id = check.validator;
    let location = check.location.as_str();

    let attestations = match location {
        "new" => store.latest_new_attestations(),
        "known" => store.latest_known_attestations(),
        other => {
            return Err(
                format!("Step {}: unknown attestation location: {}", step_idx, other).into(),
            );
        }
    };

    let attestation = attestations.get(&validator_id).ok_or_else(|| {
        format!(
            "Step {}: attestation for validator {} not found in '{}'",
            step_idx, validator_id, location
        )
    })?;

    // Validate attestation slot if specified
    if let Some(expected_slot) = check.attestation_slot {
        if attestation.slot != expected_slot {
            return Err(format!(
                "Step {}: attestation slot mismatch for validator {}: expected {}, got {}",
                step_idx, validator_id, expected_slot, attestation.slot
            )
            .into());
        }
    }

    if let Some(expected_head_slot) = check.head_slot {
        if attestation.head.slot != expected_head_slot {
            return Err(format!(
                "Step {}: attestation head slot mismatch: expected {}, got {}",
                step_idx, expected_head_slot, attestation.head.slot
            )
            .into());
        }
    }

    // Validate source slot if specified
    if let Some(expected_source_slot) = check.source_slot {
        if attestation.source.slot != expected_source_slot {
            return Err(format!(
                "Step {}: attestation source slot mismatch: expected {}, got {}",
                step_idx, expected_source_slot, attestation.source.slot
            )
            .into());
        }
    }

    // Validate target slot if specified
    if let Some(expected_target_slot) = check.target_slot {
        if attestation.target.slot != expected_target_slot {
            return Err(format!(
                "Step {}: attestation target slot mismatch: expected {}, got {}",
                step_idx, expected_target_slot, attestation.target.slot
            )
            .into());
        }
    }

    Ok(())
}

fn validate_lexicographic_head_among(
    store: &Store,
    fork_labels: &[String],
    step_idx: usize,
    block_registry: &HashMap<String, H256>,
) -> datatest_stable::Result<()> {
    // Require at least 2 forks to test tiebreaker
    if fork_labels.len() < 2 {
        return Err(format!(
            "Step {}: lexicographicHeadAmong requires at least 2 forks, got {}",
            step_idx,
            fork_labels.len()
        )
        .into());
    }

    let blocks = store.blocks();

    // Resolve all fork labels to roots and compute their weights
    // Map: label -> (root, slot, weight)
    let mut fork_data: HashMap<&str, (H256, u64, usize)> = HashMap::new();

    for label in fork_labels {
        let root = block_registry.get(label).ok_or_else(|| {
            format!(
                "Step {}: lexicographicHeadAmong label '{}' not found in block registry. Available: {:?}",
                step_idx, label, block_registry.keys().collect::<Vec<_>>()
            )
        })?;

        let block = blocks.get(root).ok_or_else(|| {
            format!(
                "Step {}: block for label '{}' not found in store",
                step_idx, label
            )
        })?;
        let slot = block.slot;

        // Calculate attestation weight: count attestations voting for this fork
        // An attestation votes for this fork if its head is this block or a descendant
        let mut weight = 0;
        for attestation in store.latest_known_attestations().values() {
            let att_head_root = attestation.head.root;
            // Check if attestation head is this block or a descendant
            if att_head_root == *root {
                weight += 1;
            } else if let Some(att_block) = blocks.get(&att_head_root) {
                // Walk back from attestation head to see if we reach this block
                let mut current = att_head_root;
                let mut current_slot = att_block.slot;
                while current_slot > slot {
                    if let Some(blk) = blocks.get(&current) {
                        if blk.parent_root == *root {
                            weight += 1;
                            break;
                        }
                        current = blk.parent_root;
                        current_slot = blocks.get(&current).map(|b| b.slot).unwrap_or(0);
                    } else {
                        break;
                    }
                }
            }
        }

        fork_data.insert(label.as_str(), (*root, slot, weight));
    }

    // Verify all forks are at the same slot
    let slots: HashSet<u64> = fork_data.values().map(|(_, slot, _)| *slot).collect();
    if slots.len() > 1 {
        let slot_info: Vec<_> = fork_data
            .iter()
            .map(|(label, (_, slot, _))| format!("{}: {}", label, slot))
            .collect();
        return Err(format!(
            "Step {}: lexicographicHeadAmong forks have different slots: {}",
            step_idx,
            slot_info.join(", ")
        )
        .into());
    }

    // Verify all forks have equal weight
    let weights: HashSet<usize> = fork_data.values().map(|(_, _, weight)| *weight).collect();
    if weights.len() > 1 {
        let weight_info: Vec<_> = fork_data
            .iter()
            .map(|(label, (_, _, weight))| format!("{}: {}", label, weight))
            .collect();
        return Err(format!(
            "Step {}: lexicographicHeadAmong forks have unequal weights: {}. \
             All forks must have equal attestation weight for tiebreaker to apply.",
            step_idx,
            weight_info.join(", ")
        )
        .into());
    }

    // Find the lexicographically highest root among the equal-weight forks
    let expected_head_root = fork_data
        .values()
        .map(|(root, _, _)| *root)
        .max()
        .expect("fork_data is not empty");

    // Verify the current head matches the lexicographically highest root
    let actual_head_root = store.head();
    if actual_head_root != expected_head_root {
        let highest_label = fork_data
            .iter()
            .find(|(_, (root, _, _))| *root == expected_head_root)
            .map(|(label, _)| *label)
            .unwrap_or("unknown");
        let actual_label = fork_data
            .iter()
            .find(|(_, (root, _, _))| *root == actual_head_root)
            .map(|(label, _)| *label)
            .unwrap_or("unknown");

        let fork_info: Vec<_> = fork_data
            .iter()
            .map(|(label, (root, _, weight))| {
                format!("  {label}: root={root:?} weight={weight}")
            })
            .collect();

        let weight = weights.iter().next().unwrap_or(&0);
        let fork_info = fork_info.join("\n");
        return Err(format!(
            "Step {step_idx}: lexicographic tiebreaker failed.\n\
             Expected head: '{highest_label}' ({expected_head_root:?})\n\
             Actual head:   '{actual_label}' ({actual_head_root:?})\n\
             All competing forks (equal weight={weight}):\n{fork_info}"
        )
        .into());
    }

    Ok(())
}

datatest_stable::harness!({
    test = run,
    root = "../../leanSpec/fixtures/consensus/fork_choice",
    pattern = r".*\.json"
});
