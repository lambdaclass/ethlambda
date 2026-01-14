use std::path::Path;

use ethlambda_blockchain::store::Store;
use ethlambda_types::{
    attestation::Attestation,
    block::{Block, BlockSignatures, BlockWithAttestation, SignedBlockWithAttestation},
    primitives::VariableList,
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
        let mut store = Store::get_forkchoice_store(anchor_state, anchor_block);

        // Process steps
        for (step_idx, step) in test.steps.into_iter().enumerate() {
            match step.step_type.as_str() {
                "block" => {
                    let block_data = step.block.expect("block step missing block data");
                    let signed_block = build_signed_block(block_data);
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
                other => {
                    // Fail for unsupported step types for now
                    return Err(format!("Unsupported step type '{other}'",).into());
                }
            }

            // Validate checks
            if let Some(checks) = step.checks {
                validate_checks(&store, &checks, step_idx)?;
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
) -> datatest_stable::Result<()> {
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

    // Validate attestationChecks
    if let Some(ref att_checks) = checks.attestation_checks {
        for att_check in att_checks {
            validate_attestation_check(store, att_check, step_idx)?;
        }
    }

    // Validate attestationTargetSlot (safe_target)
    if let Some(expected_slot) = checks.attestation_target_slot {
        let safe_target = store.safe_target();
        let target_block = store
            .blocks()
            .get(&safe_target)
            .ok_or_else(|| format!("Step {}: safe_target block not found", step_idx))?;
        if target_block.slot != expected_slot {
            return Err(format!(
                "Step {}: attestationTargetSlot mismatch: expected {}, got {}",
                step_idx, expected_slot, target_block.slot
            )
            .into());
        }
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
            )
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

datatest_stable::harness!({
    test = run,
    root = "../../leanSpec/fixtures/consensus/fork_choice",
    pattern = r".*\.json"
});
