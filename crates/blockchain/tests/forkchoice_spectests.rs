use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
};

use ethlambda_blockchain::{MILLISECONDS_PER_INTERVAL, MILLISECONDS_PER_SLOT, store};
use ethlambda_storage::{Store, backend::InMemoryBackend};
use ethlambda_types::{
    attestation::{AttestationData, SignedAggregatedAttestation, SignedAttestation, XmssSignature},
    block::{AggregatedSignatureProof, Block, BlockSignatures, SignedBlock},
    primitives::{ByteList, H256, HashTreeRoot as _},
    signature::SIGNATURE_SIZE,
    state::State,
};

use crate::types::{ForkChoiceTestVector, StoreChecks};

const SUPPORTED_FIXTURE_FORMAT: &str = "fork_choice_test";

mod common;
mod types;

/// List of skipped tests
const SKIP_TESTS: &[&str] = &[];

fn run(path: &Path) -> datatest_stable::Result<()> {
    if let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        && SKIP_TESTS.contains(&stem)
    {
        println!("Skipping {stem} (see SKIP_TESTS comment)");
        return Ok(());
    }
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
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::get_forkchoice_store(backend, anchor_state, anchor_block);

        // Block registry: maps block labels to their roots
        let mut block_registry: HashMap<String, H256> = HashMap::new();

        // Process steps
        for (step_idx, step) in test.steps.into_iter().enumerate() {
            match step.step_type.as_str() {
                "block" => {
                    let block_data = step.block.expect("block step missing block data");

                    // Register block label if present
                    if let Some(ref label) = block_data.block_root_label {
                        let block: Block = block_data.to_block();
                        let root = block.hash_tree_root();
                        block_registry.insert(label.clone(), root);
                    }

                    let signed_block = build_signed_block(block_data);

                    let block_time_ms =
                        genesis_time * 1000 + signed_block.message.slot * MILLISECONDS_PER_SLOT;

                    // NOTE: the has_proposal argument is set to true, following the spec
                    store::on_tick(&mut store, block_time_ms, true);
                    let result = store::on_block_without_verification(&mut store, signed_block);
                    assert_step_outcome(step_idx, step.valid, result)?;
                }
                "tick" => {
                    // Fixtures use either `time` (UNIX seconds) or `interval`
                    // (absolute interval count since genesis). Interval fixtures
                    // encode `genesis_time_ms + interval * MILLISECONDS_PER_INTERVAL`.
                    let timestamp_ms = match (step.time, step.interval) {
                        (Some(time_s), _) => time_s * 1000,
                        (None, Some(interval)) => {
                            genesis_time * 1000 + interval * MILLISECONDS_PER_INTERVAL
                        }
                        (None, None) => panic!("tick step missing both time and interval"),
                    };
                    let has_proposal = step.has_proposal.unwrap_or(false);
                    store::on_tick(&mut store, timestamp_ms, has_proposal);
                }
                "attestation" => {
                    let att_data = step
                        .attestation
                        .expect("attestation step missing attestation data");
                    let signed_attestation = SignedAttestation {
                        validator_id: att_data
                            .validator_id
                            .expect("attestation step missing validator_id"),
                        data: att_data.data.into(),
                        signature: att_data
                            .signature
                            .expect("attestation step missing signature"),
                    };
                    let is_aggregator = step.is_aggregator.unwrap_or(false);

                    let result = store::on_gossip_attestation(
                        &mut store,
                        &signed_attestation,
                        is_aggregator,
                    );
                    assert_step_outcome(step_idx, step.valid, result)?;
                }
                "gossipAggregatedAttestation" => {
                    let att_data = step
                        .attestation
                        .expect("gossipAggregatedAttestation step missing attestation data");
                    let proof_fixture = att_data
                        .proof
                        .expect("gossipAggregatedAttestation step missing proof");
                    let proof_bytes: Vec<u8> = proof_fixture.proof_data.into();
                    let proof_data = ByteList::try_from(proof_bytes)
                        .expect("aggregated proof data fits in ByteListMiB");
                    let aggregated = SignedAggregatedAttestation {
                        data: att_data.data.into(),
                        proof: AggregatedSignatureProof::new(
                            proof_fixture.participants.into(),
                            proof_data,
                        ),
                    };

                    let result = store::on_gossip_aggregated_attestation(&mut store, aggregated);
                    assert_step_outcome(step_idx, step.valid, result)?;
                }
                other => {
                    return Err(format!("Unsupported step type '{other}'").into());
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

fn assert_step_outcome<T, E: std::fmt::Debug>(
    step_idx: usize,
    expected_valid: bool,
    result: Result<T, E>,
) -> datatest_stable::Result<()> {
    match (result, expected_valid) {
        (Ok(_), false) => Err(format!("Step {step_idx} expected failure but got success").into()),
        (Err(err), true) => {
            Err(format!("Step {step_idx} expected success but got failure: {err:?}").into())
        }
        _ => Ok(()),
    }
}

fn build_signed_block(block_data: types::BlockStepData) -> SignedBlock {
    let block: Block = block_data.to_block();

    // Build one empty proof per attestation, matching the aggregation_bits from
    // each attestation in the block body. Block processing zips attestations with
    // signatures, so they must be the same length for attestations to reach
    // fork choice.
    let proofs: Vec<_> = block
        .body
        .attestations
        .iter()
        .map(|att| AggregatedSignatureProof::empty(att.aggregation_bits.clone()))
        .collect();

    SignedBlock {
        message: block,
        signature: BlockSignatures {
            proposer_signature: XmssSignature::try_from(vec![0u8; SIGNATURE_SIZE]).unwrap(),
            attestation_signatures: proofs.try_into().expect("attestation proofs within limit"),
        },
    }
}

fn validate_checks(
    st: &Store,
    checks: &StoreChecks,
    step_idx: usize,
    block_registry: &HashMap<String, H256>,
) -> datatest_stable::Result<()> {
    // Validate time check: fixtures encode the expected store time in intervals
    // since genesis (matching `Store::time()`).
    if let Some(expected_time) = checks.time {
        let actual_time = st.time();
        if actual_time != expected_time {
            return Err(format!(
                "Step {}: time mismatch: expected {}, got {}",
                step_idx, expected_time, actual_time
            )
            .into());
        }
    }
    // Resolve headRootLabel to headRoot if only the label is provided
    let resolved_head_root = checks.head_root.or_else(|| {
        checks
            .head_root_label
            .as_ref()
            .and_then(|label| block_registry.get(label).copied())
    });
    let resolved_justified_root = checks.latest_justified_root.or_else(|| {
        checks
            .latest_justified_root_label
            .as_ref()
            .and_then(|label| block_registry.get(label).copied())
    });
    let resolved_finalized_root = checks.latest_finalized_root.or_else(|| {
        checks
            .latest_finalized_root_label
            .as_ref()
            .and_then(|label| block_registry.get(label).copied())
    });
    let resolved_safe_target_root = checks.safe_target.or_else(|| {
        checks
            .safe_target_root_label
            .as_ref()
            .and_then(|label| block_registry.get(label).copied())
    });
    // Validate attestationTargetSlot
    if let Some(expected_slot) = checks.attestation_target_slot {
        let target = store::get_attestation_target(st);
        if target.slot != expected_slot {
            return Err(format!(
                "Step {}: attestationTargetSlot mismatch: expected {}, got {}",
                step_idx, expected_slot, target.slot
            )
            .into());
        }

        // Also validate the root matches a block at this slot
        let blocks = st.get_live_chain();
        let block_found = blocks
            .iter()
            .any(|(root, (slot, _))| *slot == expected_slot && *root == target.root);

        if !block_found {
            let available: Vec<_> = blocks
                .iter()
                .filter(|(_, (slot, _))| *slot == expected_slot)
                .map(|(root, _)| format!("{:?}", root))
                .collect();
            return Err(format!(
                "Step {}: attestationTarget.root {:?} does not match any block at slot {}. Available blocks: {:?}",
                step_idx, target.root, expected_slot, available
            )
            .into());
        }
    }

    // Validate headSlot
    if let Some(expected_slot) = checks.head_slot {
        let head_root = st.head();
        let head_header = st
            .get_block_header(&head_root)
            .ok_or_else(|| format!("Step {}: head block not found", step_idx))?;
        if head_header.slot != expected_slot {
            return Err(format!(
                "Step {}: headSlot mismatch: expected {}, got {}",
                step_idx, expected_slot, head_header.slot
            )
            .into());
        }
    }

    // Validate headRoot (resolved from headRootLabel if headRoot not provided)
    if let Some(ref expected_root) = resolved_head_root {
        let head_root = st.head();
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
        let justified = st.latest_justified();
        if justified.slot != expected_slot {
            return Err(format!(
                "Step {}: latestJustifiedSlot mismatch: expected {}, got {}",
                step_idx, expected_slot, justified.slot
            )
            .into());
        }
    }

    // Validate latestJustifiedRoot (resolved from label if root not provided)
    if let Some(ref expected_root) = resolved_justified_root {
        let justified = st.latest_justified();
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
        let finalized = st.latest_finalized();
        if finalized.slot != expected_slot {
            return Err(format!(
                "Step {}: latestFinalizedSlot mismatch: expected {}, got {}",
                step_idx, expected_slot, finalized.slot
            )
            .into());
        }
    }

    // Validate latestFinalizedRoot (resolved from label if root not provided)
    if let Some(ref expected_root) = resolved_finalized_root {
        let finalized = st.latest_finalized();
        if finalized.root != *expected_root {
            return Err(format!(
                "Step {}: latestFinalizedRoot mismatch: expected {:?}, got {:?}",
                step_idx, expected_root, finalized.root
            )
            .into());
        }
    }

    // Validate safeTargetSlot
    if let Some(expected_slot) = checks.safe_target_slot {
        let actual_slot = st.safe_target_slot();
        if actual_slot != expected_slot {
            return Err(format!(
                "Step {}: safeTargetSlot mismatch: expected {}, got {}",
                step_idx, expected_slot, actual_slot
            )
            .into());
        }
    }

    // Validate safeTarget root (resolved from label if root not provided)
    if let Some(ref expected_root) = resolved_safe_target_root {
        let actual_root = st.safe_target();
        if actual_root != *expected_root {
            return Err(format!(
                "Step {}: safeTarget mismatch: expected {:?}, got {:?}",
                step_idx, expected_root, actual_root
            )
            .into());
        }
    }

    // Validate attestationChecks
    if let Some(ref att_checks) = checks.attestation_checks {
        for att_check in att_checks {
            validate_attestation_check(st, att_check, step_idx)?;
        }
    }

    // Validate lexicographicHeadAmong
    if let Some(ref fork_labels) = checks.lexicographic_head_among {
        validate_lexicographic_head_among(st, fork_labels, step_idx, block_registry)?;
    }

    Ok(())
}

fn validate_attestation_check(
    st: &Store,
    check: &types::AttestationCheck,
    step_idx: usize,
) -> datatest_stable::Result<()> {
    let validator_id = check.validator;
    let location = check.location.as_str();

    let attestations: HashMap<u64, AttestationData> = match location {
        "new" => st.extract_latest_new_attestations(),
        "known" => st.extract_latest_known_attestations(),
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
    if let Some(expected_slot) = check.attestation_slot
        && attestation.slot != expected_slot
    {
        return Err(format!(
            "Step {}: attestation slot mismatch for validator {}: expected {}, got {}",
            step_idx, validator_id, expected_slot, attestation.slot
        )
        .into());
    }

    if let Some(expected_head_slot) = check.head_slot
        && attestation.head.slot != expected_head_slot
    {
        return Err(format!(
            "Step {}: attestation head slot mismatch: expected {}, got {}",
            step_idx, expected_head_slot, attestation.head.slot
        )
        .into());
    }

    // Validate source slot if specified
    if let Some(expected_source_slot) = check.source_slot
        && attestation.source.slot != expected_source_slot
    {
        return Err(format!(
            "Step {}: attestation source slot mismatch: expected {}, got {}",
            step_idx, expected_source_slot, attestation.source.slot
        )
        .into());
    }

    // Validate target slot if specified
    if let Some(expected_target_slot) = check.target_slot
        && attestation.target.slot != expected_target_slot
    {
        return Err(format!(
            "Step {}: attestation target slot mismatch: expected {}, got {}",
            step_idx, expected_target_slot, attestation.target.slot
        )
        .into());
    }

    Ok(())
}

fn validate_lexicographic_head_among(
    st: &Store,
    fork_labels: &[String],
    step_idx: usize,
    block_registry: &HashMap<String, H256>,
) -> datatest_stable::Result<()> {
    use ethlambda_types::attestation::AttestationData;

    // Require at least 2 forks to test tiebreaker
    if fork_labels.len() < 2 {
        return Err(format!(
            "Step {}: lexicographicHeadAmong requires at least 2 forks, got {}",
            step_idx,
            fork_labels.len()
        )
        .into());
    }

    let blocks = st.get_live_chain();
    let known_attestations: HashMap<u64, AttestationData> = st.extract_latest_known_attestations();

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

        let (slot, _parent_root) = blocks.get(root).ok_or_else(|| {
            format!(
                "Step {}: block for label '{}' not found in store",
                step_idx, label
            )
        })?;

        // Calculate attestation weight: count attestations voting for this fork
        // An attestation votes for this fork if its head is this block or a descendant
        let mut weight = 0;
        for attestation in known_attestations.values() {
            let att_head_root = attestation.head.root;
            // Check if attestation head is this block or a descendant
            if att_head_root == *root {
                weight += 1;
            } else if let Some(&(att_slot, _)) = blocks.get(&att_head_root) {
                // Walk back from attestation head to see if we reach this block
                let mut current = att_head_root;
                let mut current_slot = att_slot;
                while current_slot > *slot {
                    if let Some(&(_, parent_root)) = blocks.get(&current) {
                        if parent_root == *root {
                            weight += 1;
                            break;
                        }
                        current = parent_root;
                        current_slot = blocks.get(&current).map(|(s, _)| *s).unwrap_or(0);
                    } else {
                        break;
                    }
                }
            }
        }

        fork_data.insert(label.as_str(), (*root, *slot, weight));
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
    let actual_head_root = st.head();
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
            .map(|(label, (root, _, weight))| format!("  {label}: root={root:?} weight={weight}"))
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
