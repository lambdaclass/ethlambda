use std::{
    collections::{BTreeSet, HashMap, HashSet},
    path::Path,
    sync::Arc,
};

use ethlambda_blockchain::{spec_test_runner::apply_fork_choice_step, store};
use ethlambda_storage::{Store, backend::InMemoryBackend};
use ethlambda_types::{
    attestation::{AttestationData, validator_indices},
    block::Block,
    primitives::{H256, HashTreeRoot as _},
    state::{State, anchor_pair_is_consistent},
};

use ethlambda_test_fixtures::fork_choice::{
    AttestationCheck, BlockAttestationCheck, ForkChoiceTestVector, StoreChecks,
};

const SUPPORTED_FIXTURE_FORMAT: &str = "fork_choice_test";

/// List of skipped tests.
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

        // Mocked-proof vectors (`proofSetting == 0`) carry placeholder
        // aggregation proofs that must not be cryptographically verified.
        let proofs_are_mocked = test.proofs_are_mocked();

        // Initialize store from anchor state/block.
        //
        // Fixtures whose `steps` is empty are "anchor rejection" cases (e.g.
        // `test_store_from_anchor_rejects_mismatched_state_root`): they assert
        // that init refuses an inconsistent (state, block) pair. We detect that
        // up front with the non-panicking helper instead of letting
        // `get_forkchoice_store`'s assert! panic out of the test harness.
        let mut anchor_state: State = test.anchor_state.into();
        let anchor_block: Block = test.anchor_block.into();
        let pair_ok = anchor_pair_is_consistent(&mut anchor_state, &anchor_block);
        if test.steps.is_empty() {
            if pair_ok {
                return Err(format!(
                    "Fixture '{name}' has no steps (expects anchor rejection) \
                     but the (state, block) pair is consistent"
                )
                .into());
            }
            continue;
        }
        if !pair_ok {
            return Err(format!(
                "Fixture '{name}' has steps (expects anchor acceptance) \
                 but the (state, block) pair is inconsistent"
            )
            .into());
        }

        // The anchor is always reachable under the label "genesis", matching
        // leanSpec's harness which seeds `block_registry = {"genesis": anchor}`
        // (true even for checkpoint-sync fixtures anchored past slot 0). Label
        // checks such as `sourceRootLabel` and `labelsInStore` rely on it.
        let anchor_root = anchor_block.hash_tree_root();

        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::get_forkchoice_store(backend, anchor_state, anchor_block)
            .expect("anchor state and block must match");

        // Block registry: maps block labels to their roots
        let mut block_registry: HashMap<String, H256> = HashMap::new();
        block_registry.insert("genesis".to_string(), anchor_root);

        // Cumulative block tree (root -> (slot, parent_root)), never pruned.
        // Mirrors leanSpec's `store.blocks`, which only ever grows: the store's
        // `LiveChain` index drops entries below the finalized slot, but the
        // reference harness keeps every block it ever imported. `reorgDepth`
        // and `labelsInStore` must resolve blocks that finalization has already
        // pruned from `LiveChain`, so we accumulate live-chain snapshots here
        // instead of re-reading the pruned index at check time.
        let mut all_blocks: HashMap<H256, (u64, H256)> = store.get_live_chain()?;

        // Process steps
        for (step_idx, step) in test.steps.into_iter().enumerate() {
            // Head before this step executes, for the `reorgDepth` check.
            let old_head = store.head()?;
            // Block built/imported this step, for the block-body checks. Mirrors
            // leanSpec's per-step `filled_block` (only a block step sets it).
            let filled_block = step.block.as_ref().map(|block_data| block_data.to_block());
            if let Some(block_data) = step.block.as_ref()
                && let Some(label) = block_data.block_root_label.as_ref()
            {
                block_registry.insert(label.clone(), block_data.to_block().hash_tree_root());
            }

            let result = apply_fork_choice_step(&mut store, &step, Some(proofs_are_mocked));
            assert_step_outcome(step_idx, step.valid, result)?;

            // Fold this step's blocks into the cumulative tree before checks so
            // ancestry walks see blocks finalization may have just pruned from
            // the live-chain index (see `all_blocks` above).
            all_blocks.extend(store.get_live_chain()?);

            // Validate checks
            if let Some(checks) = step.checks {
                validate_checks(
                    &store,
                    &checks,
                    step_idx,
                    &block_registry,
                    old_head,
                    filled_block.as_ref(),
                    &all_blocks,
                )?;
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

fn validate_checks(
    st: &Store,
    checks: &StoreChecks,
    step_idx: usize,
    block_registry: &HashMap<String, H256>,
    old_head: H256,
    filled_block: Option<&Block>,
    all_blocks: &HashMap<H256, (u64, H256)>,
) -> datatest_stable::Result<()> {
    // Validate time check: fixtures encode the expected store time in intervals
    // since genesis (matching `Store::time()`).
    if let Some(expected_time) = checks.time {
        let actual_time = st.time().expect("store time is always set");
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
        let blocks = st.get_live_chain().expect("live chain is not empty");
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
        let head_root = st.head().expect("head block exists");
        let head_header = st
            .get_block_header(&head_root)
            .expect("block header not found")
            .unwrap();
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
        let head_root = st.head().expect("head block exists");
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
        let justified = st.latest_justified().expect("justified block exists");
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
        let justified = st.latest_justified().expect("justified block exists");
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
        let finalized = st.latest_finalized().expect("finalized block exists");
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
        let finalized = st.latest_finalized().expect("finalized block exists");
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
        let actual_root = st.safe_target().expect("safe target exists");
        if actual_root != *expected_root {
            return Err(format!(
                "Step {}: safeTarget mismatch: expected {:?}, got {:?}",
                step_idx, expected_root, actual_root
            )
            .into());
        }
    }

    // Validate attestationTargetRootLabel: the attestation target root must
    // resolve to the labeled block.
    if let Some(ref label) = checks.attestation_target_root_label {
        let expected = resolve_label(label, block_registry, step_idx)?;
        let actual = store::get_attestation_target(st).root;
        if actual != expected {
            return Err(format!(
                "Step {step_idx}: attestationTargetRootLabel mismatch (label '{label}'): \
                 expected {expected:?}, got {actual:?}"
            )
            .into());
        }
    }

    // Validate attestationChecks
    if let Some(ref att_checks) = checks.attestation_checks {
        for att_check in att_checks {
            validate_attestation_check(st, att_check, step_idx, block_registry)?;
        }
    }

    // Validate the accepted (known) pool's target-slot set: the sorted-unique
    // set of target slots keyed in the known aggregated pool must match.
    // Mirrors leanSpec's `{data.target.slot for data in pool}` over all
    // distinct pool entries.
    if let Some(ref expected) = checks.latest_known_aggregated_target_slots {
        // Sorted, de-duplicated set of target slots keyed in the known pool.
        let actual: Vec<u64> = st
            .known_aggregated_payloads()
            .values()
            .map(|(data, _)| data.target.slot)
            .collect::<BTreeSet<u64>>()
            .into_iter()
            .collect();
        let mut expected_sorted = expected.to_vec();
        expected_sorted.sort_unstable();
        expected_sorted.dedup();
        if actual != expected_sorted.as_slice() {
            return Err(format!(
                "Step {step_idx}: latestKnownAggregatedTargetSlots mismatch: \
                 expected {expected_sorted:?}, got {actual:?}"
            )
            .into());
        }
    }

    // NOTE: `latestNewAggregatedTargetSlots`, `attestationSignatureTargetSlots`
    // and `newPoolProofParticipants` are parsed but NOT asserted here. They
    // read the pending (new) aggregated pool and the raw gossip-signature pool,
    // which this offline runner does not drive the way leanSpec's harness does:
    // it advances ticks without the aggregator role and folds block-borne votes
    // straight into the known pool, so the new/signature pools do not track
    // leanSpec's contents. The accepted (known) pool, which the runner does
    // populate, is asserted above.
    // TODO(leanSpec new/signature pools): assert these once the runner drives
    // interval-2 aggregation with the aggregator role so the pending and raw
    // signature pools mirror leanSpec's.

    // Validate block-body checks against the block built this step.
    if let Some(expected_count) = checks.block_attestation_count {
        let block = filled_block.ok_or_else(|| {
            format!("Step {step_idx}: blockAttestationCount set but no block was built this step")
        })?;
        let actual = block.body.attestations.len() as u64;
        if actual != expected_count {
            return Err(format!(
                "Step {step_idx}: blockAttestationCount mismatch: expected {expected_count}, \
                 got {actual}"
            )
            .into());
        }
    }
    if let Some(ref block_checks) = checks.block_attestations {
        let block = filled_block.ok_or_else(|| {
            format!("Step {step_idx}: blockAttestations set but no block was built this step")
        })?;
        validate_block_attestations(block, block_checks, step_idx)?;
    }

    // Validate lexicographicHeadAmong
    if let Some(ref fork_labels) = checks.lexicographic_head_among {
        validate_lexicographic_head_among(st, fork_labels, step_idx, block_registry)?;
    }

    // Validate canonicalEquivocationHeadAmong (leanSpec #1189)
    if let Some(ref fork_labels) = checks.canonical_equivocation_head_among {
        validate_canonical_equivocation_head_among(st, fork_labels, step_idx, block_registry)?;
    }

    // Validate reorgDepth: blocks reachable from the old head but not the new.
    // Walk the cumulative block tree, not the live-chain index: a reorg that
    // also advanced finalization may have pruned the abandoned branch from
    // `LiveChain`, which would undercount the depth. leanSpec walks its
    // never-pruned `store.blocks` here for the same reason.
    if let Some(expected_depth) = checks.reorg_depth {
        let old_ancestors = ancestor_set(all_blocks, old_head);
        let new_ancestors = ancestor_set(all_blocks, st.head()?);
        let actual_depth = old_ancestors.difference(&new_ancestors).count() as u64;
        if actual_depth != expected_depth {
            return Err(format!(
                "Step {step_idx}: reorgDepth mismatch: expected {expected_depth}, got {actual_depth}"
            )
            .into());
        }
    }

    // Validate labelsInStore: each labeled block must still be in the block
    // tree. Mirrors leanSpec's `root in store.blocks` against the never-pruned
    // tree, so a finalized block pruned from the live-chain index still counts.
    if let Some(ref labels) = checks.labels_in_store {
        for label in labels {
            let root = resolve_label(label, block_registry, step_idx)?;
            if !all_blocks.contains_key(&root) {
                return Err(format!(
                    "Step {step_idx}: labelsInStore: block '{label}' (root={root:?}) \
                     not found in the store"
                )
                .into());
            }
        }
    }

    Ok(())
}

/// Resolve a block label to its root via the step's block registry.
fn resolve_label(
    label: &str,
    block_registry: &HashMap<String, H256>,
    step_idx: usize,
) -> datatest_stable::Result<H256> {
    block_registry.get(label).copied().ok_or_else(|| {
        format!(
            "Step {step_idx}: label '{label}' not found in block registry. Available: {:?}",
            block_registry.keys().collect::<Vec<_>>()
        )
        .into()
    })
}

/// Walk parent links from `head`, collecting every reachable block root.
///
/// Mirrors leanSpec's `_ancestor_set`: only roots present in the block tree are
/// collected, so the walk stops at the anchor (whose parent is not in the tree).
fn ancestor_set(blocks: &HashMap<H256, (u64, H256)>, head: H256) -> HashSet<H256> {
    let mut seen = HashSet::new();
    let mut root = head;
    while let Some(&(_, parent_root)) = blocks.get(&root) {
        seen.insert(root);
        if parent_root == H256::ZERO {
            break;
        }
        root = parent_root;
    }
    seen
}

/// Validate the detailed per-aggregate checks against a built block body.
///
/// Mirrors leanSpec's `_validate_block_attestations`: each expected check must
/// match an aggregate whose participant set is exactly equal, then the matched
/// aggregate's slot/target-slot are compared.
fn validate_block_attestations(
    block: &Block,
    expected_checks: &[BlockAttestationCheck],
    step_idx: usize,
) -> datatest_stable::Result<()> {
    let actual: Vec<(BTreeSet<u64>, &AttestationData)> = block
        .body
        .attestations
        .iter()
        .map(|att| {
            (
                validator_indices(&att.aggregation_bits).collect(),
                &att.data,
            )
        })
        .collect();

    for check in expected_checks {
        let expected_participants: BTreeSet<u64> = check.participants.iter().copied().collect();
        let matched = actual
            .iter()
            .find(|(participants, _)| *participants == expected_participants);
        let (_, data) = matched.ok_or_else(|| {
            let available: Vec<_> = actual
                .iter()
                .map(|(p, _)| p.iter().collect::<Vec<_>>())
                .collect();
            format!(
                "Step {step_idx}: blockAttestations: no aggregate with participants \
                 {expected_participants:?}. Available: {available:?}"
            )
        })?;

        if let Some(expected_slot) = check.attestation_slot
            && data.slot != expected_slot
        {
            return Err(format!(
                "Step {step_idx}: blockAttestations: aggregate {expected_participants:?} \
                 attestationSlot mismatch: expected {expected_slot}, got {}",
                data.slot
            )
            .into());
        }
        if let Some(expected_target) = check.target_slot
            && data.target.slot != expected_target
        {
            return Err(format!(
                "Step {step_idx}: blockAttestations: aggregate {expected_participants:?} \
                 targetSlot mismatch: expected {expected_target}, got {}",
                data.target.slot
            )
            .into());
        }
    }
    Ok(())
}

/// Validate the equal-slot equivocation tiebreak (leanSpec #1189).
///
/// Each listed fork must be targeted by an attestation in the accepted (known)
/// aggregated pool; the head must sit on the fork whose targeting attestation
/// carries the largest `hash_tree_root` (the pool key). Scheme-independent:
/// roots are read from the store, never pinned by the fixture.
fn validate_canonical_equivocation_head_among(
    st: &Store,
    fork_labels: &[String],
    step_idx: usize,
    block_registry: &HashMap<String, H256>,
) -> datatest_stable::Result<()> {
    if fork_labels.len() < 2 {
        return Err(format!(
            "Step {step_idx}: canonicalEquivocationHeadAmong requires at least 2 forks, got {}",
            fork_labels.len()
        )
        .into());
    }

    // The known aggregated pool is keyed by hash_tree_root(AttestationData).
    let known = st.known_aggregated_payloads();

    // Per fork: block root, and the largest attestation-data root targeting it.
    let mut fork_data: Vec<(&str, H256, H256)> = Vec::with_capacity(fork_labels.len());
    for label in fork_labels {
        let fork_root = resolve_label(label, block_registry, step_idx)?;
        let max_att_root = known
            .iter()
            .filter(|(_, (data, _))| data.target.root == fork_root)
            .map(|(data_root, _)| *data_root)
            .max()
            .ok_or_else(|| {
                format!(
                    "Step {step_idx}: canonicalEquivocationHeadAmong fork '{label}' \
                     (block_root={fork_root:?}) has no attestation targeting it in the \
                     accepted aggregated pool"
                )
            })?;
        fork_data.push((label.as_str(), fork_root, max_att_root));
    }

    // Winner: the fork carrying the largest attestation-data root.
    let (winning_label, winning_fork_root, _) = fork_data
        .iter()
        .max_by_key(|(_, _, att_root)| *att_root)
        .expect("fork_data is non-empty");

    let actual_head = st.head()?;
    if actual_head != *winning_fork_root {
        let actual_label = fork_data
            .iter()
            .find(|(_, root, _)| *root == actual_head)
            .map(|(label, _, _)| *label)
            .unwrap_or("unknown");
        let fork_info: Vec<String> = fork_data
            .iter()
            .map(|(label, root, att_root)| {
                format!("  {label}: block_root={root:?} attestation_data_root={att_root:?}")
            })
            .collect();
        return Err(format!(
            "Step {step_idx}: canonical equivocation tiebreak failed.\n\
             The head must be the fork with the largest attestation-data root.\n\
             Expected head: '{winning_label}' ({winning_fork_root:?})\n\
             Actual head:   '{actual_label}' ({actual_head:?})\n\
             Competing forks:\n{}",
            fork_info.join("\n")
        )
        .into());
    }

    Ok(())
}

fn validate_attestation_check(
    st: &Store,
    check: &AttestationCheck,
    step_idx: usize,
    block_registry: &HashMap<String, H256>,
) -> datatest_stable::Result<()> {
    let validator_id = check.validator;
    let location = check.location.as_str();

    let attestations: HashMap<u64, AttestationData> = match location {
        "new" => st.extract_latest_new_attestations(),
        "known" => st.extract_latest_known_attestations(),
        "signatures" => st.extract_latest_signature_attestations(),
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

    // Validate source root by label if specified.
    if let Some(ref label) = check.source_root_label {
        let expected = resolve_label(label, block_registry, step_idx)?;
        if attestation.source.root != expected {
            return Err(format!(
                "Step {step_idx}: attestation source root mismatch for validator {validator_id} \
                 (label '{label}'): expected {expected:?}, got {:?}",
                attestation.source.root
            )
            .into());
        }
    }

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

    let blocks = st.get_live_chain().expect("live chain is not empty");
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
    let actual_head_root = st.head().expect("head block exists");
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
