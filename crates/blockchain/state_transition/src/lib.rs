use std::collections::HashMap;

use ethlambda_types::{
    ShortRoot,
    attestation::AttestationData,
    block::{AggregatedAttestations, Block, BlockHeader},
    checkpoint::Checkpoint,
    primitives::{H256, HashTreeRoot as _},
    state::{HISTORICAL_ROOTS_LIMIT, JustificationValidators, State},
};
use tracing::{info, warn};

mod execution_payload;
pub mod justified_slots_ops;
pub mod metrics;

pub use execution_payload::{SECONDS_PER_SLOT, compute_time_at_slot};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("target slot {target_slot} is in the past (current is {current_slot})")]
    StateSlotIsNewer { target_slot: u64, current_slot: u64 },
    #[error("advanced state slot {state_slot} is different from block slot {block_slot}")]
    SlotMismatch { state_slot: u64, block_slot: u64 },
    #[error("parent slot {parent_slot} is newer than block slot {block_slot}")]
    ParentSlotIsNewer { parent_slot: u64, block_slot: u64 },
    #[error("invalid proposer: expected {expected}, found {found}")]
    InvalidProposer { expected: u64, found: u64 },
    #[error("parent root mismatch: expected {expected}, found {found}")]
    InvalidParent { expected: H256, found: H256 },
    #[error("no validators in state")]
    NoValidators,
    #[error("state root mismatch: expected {expected}, computed {computed}")]
    StateRootMismatch { expected: H256, computed: H256 },
    #[error("slot gap {gap} would exceed historical roots limit (current: {current}, max: {max})")]
    SlotGapTooLarge {
        gap: usize,
        current: usize,
        max: usize,
    },
    #[error("zero hash found in justifications_roots")]
    ZeroHashInJustificationRoots,
    #[error("execution payload parent_hash mismatch: expected {expected}, found {found}")]
    InvalidPayloadParentHash { expected: H256, found: H256 },
    #[error("execution payload timestamp mismatch: expected {expected}, found {found}")]
    InvalidPayloadTimestamp { expected: u64, found: u64 },
    #[error("aggregated attestation has no participants")]
    EmptyAggregationBits,
    #[error("aggregation bit set at index {index} beyond validator count {validator_count}")]
    AggregationBitsOutOfBounds {
        index: usize,
        validator_count: usize,
    },
}

/// Transition the given pre-state to the block's post-state.
///
/// Similar to the spec's `State.state_transition`: https://github.com/leanEthereum/leanSpec/blob/bf0f606a75095cf1853529bc770516b1464d9716/src/lean_spec/subspecs/containers/state/state.py#L569
pub fn state_transition(state: &mut State, block: &Block) -> Result<(), Error> {
    let _timing = metrics::time_state_transition();

    process_slots(state, block.slot)?;
    process_block(state, block)?;

    // Uncomment for debugging state transitions
    // std::fs::write(
    //     &format!("block_slot_{}.ssz", state.slot),
    //     block.as_ssz_bytes(),
    // )
    // .unwrap();
    // std::fs::write(
    //     &format!("post_state_slot_{}.ssz", state.slot),
    //     state.as_ssz_bytes(),
    // )
    // .unwrap();

    let computed_state_root = state.hash_tree_root();
    if block.state_root != computed_state_root {
        return Err(Error::StateRootMismatch {
            expected: block.state_root,
            computed: computed_state_root,
        });
    }
    Ok(())
}

/// Advance the state through empty slots up to, but not including, target_slot.
///
/// The spec (`state.py` process_slots) iterates slot-by-slot in a while loop.
/// We jump directly to target_slot instead, which is equivalent because:
///
/// 1. The state root is only cached on the first iteration (when state_root == ZERO).
///    After that, subsequent iterations only increment the slot counter.
/// 2. The hash is computed from the same state in both approaches: slot = current,
///    state_root = ZERO (the check happens before the slot assignment).
/// 3. No other state fields are modified in the spec's loop body.
///
/// If the spec ever adds per-slot side effects, this must be revisited.
pub fn process_slots(state: &mut State, target_slot: u64) -> Result<(), Error> {
    let _timing = metrics::time_slots_processing();

    if state.slot >= target_slot {
        return Err(Error::StateSlotIsNewer {
            target_slot,
            current_slot: state.slot,
        });
    }
    if state.latest_block_header.state_root == H256::ZERO {
        state.latest_block_header.state_root = state.hash_tree_root();
    }
    let slots_processed = target_slot - state.slot;
    state.slot = target_slot;
    metrics::inc_slots_processed(slots_processed);
    Ok(())
}

/// Apply full block processing including header and body.
pub fn process_block(state: &mut State, block: &Block) -> Result<(), Error> {
    let _timing = metrics::time_block_processing();

    process_block_header(state, block)?;
    execution_payload::process_execution_payload(state, block)?;
    process_attestations(state, &block.body.attestations)?;

    Ok(())
}

/// Validate the block header and update header-linked state.
fn process_block_header(state: &mut State, block: &Block) -> Result<(), Error> {
    let parent_header = &state.latest_block_header;

    // Validation

    // TODO: this is redundant if we assume process_slots has been called
    if block.slot != state.slot {
        return Err(Error::SlotMismatch {
            state_slot: state.slot,
            block_slot: block.slot,
        });
    }
    if block.slot <= parent_header.slot {
        return Err(Error::ParentSlotIsNewer {
            parent_slot: parent_header.slot,
            block_slot: block.slot,
        });
    }
    let num_validators = state.validators.len() as u64;
    let expected_proposer =
        current_proposer(block.slot, num_validators).ok_or(Error::NoValidators)?;
    if block.proposer_index != expected_proposer {
        return Err(Error::InvalidProposer {
            expected: expected_proposer,
            found: block.proposer_index,
        });
    }
    // TODO: this is redundant in normal operation
    let parent_root = parent_header.hash_tree_root();
    if block.parent_root != parent_root {
        return Err(Error::InvalidParent {
            expected: parent_root,
            found: block.parent_root,
        });
    }

    // State Updates

    // Special case: first block after genesis.
    // TODO: this could be moved to genesis state initialization
    let is_genesis_parent = parent_header.slot == 0;
    if is_genesis_parent {
        state.latest_justified.root = parent_root;
        state.latest_finalized.root = parent_root;
    }

    // Guard: reject blocks whose slot gap would overflow historical_block_hashes.
    // The spec relies on the SSZ list limit (HISTORICAL_ROOTS_LIMIT) to enforce
    // this implicitly during serialization. We check explicitly before allocating
    // to prevent OOM from a crafted block with a large slot gap.
    let num_empty_slots = (block.slot - parent_header.slot - 1) as usize;
    let current_len = state.historical_block_hashes.len();
    let new_total = current_len + 1 + num_empty_slots; // +1 for parent_root push
    if new_total > HISTORICAL_ROOTS_LIMIT {
        return Err(Error::SlotGapTooLarge {
            gap: num_empty_slots,
            current: current_len,
            max: HISTORICAL_ROOTS_LIMIT,
        });
    }

    let mut historical_block_hashes: Vec<_> =
        std::mem::take(&mut state.historical_block_hashes).into_inner();
    historical_block_hashes.push(parent_root);
    historical_block_hashes.extend(std::iter::repeat_n(H256::ZERO, num_empty_slots));

    state.historical_block_hashes = historical_block_hashes
        .try_into()
        .expect("pre-validated: total does not exceed limit");

    // Extend justified_slots to cover slots up to (block.slot - 1)
    //
    // The storage is relative to the finalized boundary.
    // The current block's slot is not materialized until processing completes,
    // so we only extend up to the last materialized slot.
    let last_materialized_slot = block.slot - 1;
    justified_slots_ops::extend_to_slot(
        &mut state.justified_slots,
        state.latest_finalized.slot,
        last_materialized_slot,
    );

    let new_header = BlockHeader {
        slot: block.slot,
        proposer_index: block.proposer_index,
        parent_root: block.parent_root,
        body_root: block.body.hash_tree_root(),
        // Zeroed out until local state root computation.
        // This is later filled with the state root after all processing is done.
        state_root: H256::ZERO,
    };
    state.latest_block_header = new_header;
    Ok(())
}

/// Determine the proposer for a given slot using round-robin selection.
///
/// Returns `None` when `num_validators` is zero. The spec (validator.py L25)
/// does `slot % num_validators` without checking for zero, which would panic
/// on division by zero. This can't happen in practice (genesis always has at
/// least one validator), but we guard explicitly to avoid panics from crafted
/// inputs.
fn current_proposer(slot: u64, num_validators: u64) -> Option<u64> {
    (num_validators > 0).then(|| slot % num_validators)
}

/// Check if a validator is the proposer for a given slot.
///
/// Proposer selection uses simple round-robin: `slot % num_validators`.
pub fn is_proposer(validator_index: u64, slot: u64, num_validators: u64) -> bool {
    current_proposer(slot, num_validators) == Some(validator_index)
}

/// Apply attestations and update justification/finalization
/// according to the Lean Consensus 3SF-mini rules.
fn process_attestations(
    state: &mut State,
    attestations: &AggregatedAttestations,
) -> Result<(), Error> {
    let _timing = metrics::time_attestations_processing();
    // Precondition: justifications_roots must not contain zero hashes (spec state.py L389).
    if state
        .justifications_roots
        .iter()
        .any(|root| root == &H256::ZERO)
    {
        return Err(Error::ZeroHashInJustificationRoots);
    }
    let validator_count = state.validators.len();
    let mut attestations_processed: u64 = 0;
    let mut justifications: HashMap<H256, Vec<bool>> = state
        .justifications_roots
        .iter()
        .enumerate()
        .map(|(i, root)| {
            let votes = (i * validator_count..(i + 1) * validator_count)
                .map(|j| state.justifications_validators.get(j) == Some(true))
                .collect::<Vec<bool>>();
            (*root, votes)
        })
        .collect();

    // Map roots to their latest slot for pruning.
    //
    // Votes for zero hash are ignored, so we only need the most recent slot
    // where a root appears to decide whether it is still unfinalized.
    let mut root_to_slot: HashMap<H256, u64> = HashMap::new();
    for slot in (state.latest_finalized.slot + 1)..state.historical_block_hashes.len() as u64 {
        if let Some(root) = state.historical_block_hashes.get(slot as usize) {
            root_to_slot
                .entry(*root)
                .and_modify(|x| *x = (*x).max(slot))
                .or_insert(slot);
        }
    }

    for attestation in attestations {
        let attestation_data = &attestation.data;
        let source = attestation_data.source;
        let target = attestation_data.target;

        if !is_valid_vote(state, attestation_data) {
            continue;
        }

        // The spec asserts that an aggregated attestation references at least
        // one validator; the failed assert invalidates the whole block.
        if attestation.aggregation_bits.count_ones() == 0 {
            return Err(Error::EmptyAggregationBits);
        }

        // The spec indexes the per-root vote list with each participant index,
        // so a set bit beyond the validator set crashes it (IndexError) and
        // invalidates the whole block; Zeam and Lantern also reject such
        // blocks. The spec has no bitlist length check: oversized
        // aggregation_bits whose set bits are all in range process normally.
        let oob_bit = (validator_count..attestation.aggregation_bits.len())
            .find(|&i| attestation.aggregation_bits.get(i) == Some(true));
        if let Some(index) = oob_bit {
            return Err(Error::AggregationBitsOutOfBounds {
                index,
                validator_count,
            });
        }

        // Record the vote
        attestations_processed += 1;
        let votes = justifications
            .entry(target.root)
            .or_insert_with(|| std::iter::repeat_n(false, validator_count).collect());

        // Mark that each validator in this aggregation has voted for the target.
        for (validator_id, voted) in votes
            .iter_mut()
            .enumerate()
            .take(attestation.aggregation_bits.len())
        {
            if attestation.aggregation_bits.get(validator_id) == Some(true) {
                *voted = true;
            }
        }

        // Check whether the vote count crosses the supermajority threshold
        let vote_count = votes.iter().filter(|voted| **voted).count();
        if 3 * vote_count >= 2 * validator_count {
            // If the slot is higher, update the latest justified
            state.latest_justified =
                std::cmp::max_by_key(state.latest_justified, target, |c| c.slot);
            justified_slots_ops::set_justified(
                &mut state.justified_slots,
                state.latest_finalized.slot,
                target.slot,
            );

            let justified_slot = target.slot;
            let threshold = (2 * validator_count).div_ceil(3);
            info!(
                justified_slot,
                justified_root = %ShortRoot(&target.root.0),
                vote_count,
                threshold,
                "Checkpoint justified"
            );

            justifications.remove(&target.root);

            try_finalize(state, source, target, &mut justifications, &root_to_slot);
        }
    }

    serialize_justifications(state, justifications, validator_count);
    metrics::inc_attestations_processed(attestations_processed);
    Ok(())
}

/// Returns whether an attestation should be counted for fork choice.
///
/// Checks (all must pass):
/// 1. Source is already justified
/// 2. Target is not yet justified
/// 3. Both checkpoints match the canonical chain at their slots (which also
///    rejects zero-hash source or target roots)
/// 4. Target slot > source slot
/// 5. Target slot is justifiable after the finalized slot
fn is_valid_vote(state: &State, data: &AttestationData) -> bool {
    let source = data.source;
    let target = data.target;

    // Check that the source is already justified
    if !justified_slots_ops::is_slot_justified(
        &state.justified_slots,
        state.latest_finalized.slot,
        source.slot,
    ) {
        // TODO: why doesn't this make the block invalid?
        return false;
    }

    // Ignore votes for targets that have already reached consensus
    if justified_slots_ops::is_slot_justified(
        &state.justified_slots,
        state.latest_finalized.slot,
        target.slot,
    ) {
        return false;
    }

    // Ensure the vote refers to blocks that actually exist on our chain;
    // also rejects zero-hash source or target inline.
    if !attestation_data_matches_chain(&state.historical_block_hashes, data) {
        return false;
    }

    // Ensure time flows forward
    if target.slot <= source.slot {
        return false;
    }

    // Ensure the target falls on a slot that can be justified after the finalized one.
    if !slot_is_justifiable_after(target.slot, state.latest_finalized.slot) {
        return false;
    }

    true
}

/// Attempt to advance finalization from source to target.
///
/// Finalization advances only when the source lies past the old finalized point
/// and there are no justifiable slots between source.slot and target.slot
/// (exclusive). A source at or behind the finalized boundary is already final:
/// it may justify a newer target, but it must not re-finalize or scan below the
/// finalized boundary. When finalization advances, shifts the justified_slots
/// window and prunes stale justifications.
fn try_finalize(
    state: &mut State,
    source: Checkpoint,
    target: Checkpoint,
    justifications: &mut HashMap<H256, Vec<bool>>,
    root_to_slot: &HashMap<H256, u64>,
) {
    // A stale or boundary source is already finalized; advancing from it would
    // rewind the finalized checkpoint and scan slots below the boundary.
    if source.slot <= state.latest_finalized.slot {
        return;
    }

    // Consider whether finalization can advance.
    if ((source.slot + 1)..target.slot)
        .any(|slot| slot_is_justifiable_after(slot, state.latest_finalized.slot))
    {
        metrics::inc_finalizations("error");
        return;
    }

    let old_finalized_slot = state.latest_finalized.slot;
    state.latest_finalized = source;
    metrics::inc_finalizations("success");

    let finalized_slot = source.slot;
    let previous_finalized = old_finalized_slot;
    let justified_slot = state.latest_justified.slot;
    info!(
        finalized_slot,
        finalized_root = %ShortRoot(&source.root.0),
        previous_finalized,
        justified_slot,
        "Checkpoint finalized"
    );

    // Shift window to drop finalized slots from the front
    let delta = (state.latest_finalized.slot - old_finalized_slot) as usize;
    justified_slots_ops::shift_window(&mut state.justified_slots, delta);

    // Prune justifications whose roots are at or below the finalized slot.
    // The spec asserts all roots must be in root_to_slot (state.py L560).
    // A missing root means its slot <= finalized_slot, so prune it.
    justifications.retain(|root, _| match root_to_slot.get(root) {
        Some(&slot) => slot > state.latest_finalized.slot,
        None => {
            warn!(
                root = %ShortRoot(&root.0),
                finalized_slot = state.latest_finalized.slot,
                "Justification root missing from root_to_slot, pruning"
            );
            false
        }
    });
}

/// Convert the in-memory vote HashMap back into SSZ-compatible state fields.
///
/// Sorts roots for deterministic output, then flattens vote bitfields
/// into `state.justifications_roots` and `state.justifications_validators`.
fn serialize_justifications(
    state: &mut State,
    justifications: HashMap<H256, Vec<bool>>,
    validator_count: usize,
) {
    // Sorting ensures that every node produces identical state representation.
    let justification_roots = {
        let mut roots: Vec<H256> = justifications.keys().cloned().collect();
        roots.sort();
        roots
    };
    let mut justifications_validators =
        JustificationValidators::with_length(justification_roots.len() * validator_count)
            .expect("maximum validator justifications reached");
    justification_roots
        .iter()
        .flat_map(|root| justifications[root].iter())
        .enumerate()
        .filter(|(_, voted)| **voted)
        .for_each(|(i, _)| {
            justifications_validators
                .set(i, true)
                .expect("we just updated the capacity");
        });
    state.justifications_roots = justification_roots
        .try_into()
        .expect("justifications_roots limit exceeded");
    state.justifications_validators = justifications_validators;
}

/// Whether the source, target, and head checkpoints in `data` match the chain
/// at their slots.
///
/// Callers pass a chain view as it would appear after `process_block_header`
/// on the consuming block: covering `[0, block.slot - 1]` with `parent_root`
/// at the parent slot and `H256::ZERO` for empty slots between parent and the
/// candidate.
///
/// Checking `head` against the canonical view keeps counted votes internally
/// consistent: justification is keyed on `target.root`, so a sibling head must
/// not pair a canonical FFG vote with an LMD head on a non-canonical fork.
pub fn attestation_data_matches_chain(
    historical_block_hashes: &[H256],
    data: &AttestationData,
) -> bool {
    if data.source.root == H256::ZERO
        || data.target.root == H256::ZERO
        || data.head.root == H256::ZERO
    {
        return false;
    }
    let source_slot = data.source.slot as usize;
    let target_slot = data.target.slot as usize;
    let head_slot = data.head.slot as usize;
    if source_slot >= historical_block_hashes.len()
        || target_slot >= historical_block_hashes.len()
        || head_slot >= historical_block_hashes.len()
    {
        return false;
    }
    historical_block_hashes[source_slot] == data.source.root
        && historical_block_hashes[target_slot] == data.target.root
        && historical_block_hashes[head_slot] == data.head.root
}

/// Checks if the slot is a valid candidate for justification after a given finalized slot.
///
/// According to the 3SF-mini specification, a slot is justifiable if its
/// distance (`delta`) from the last finalized slot is:
///     1. Less than or equal to 5.
///     2. A perfect square (e.g., 9, 16, 25...).
///     3. A pronic number (of the form x^2 + x, e.g., 6, 12, 20...).
///
/// See https://github.com/ethereum/research/blob/c003fe1c1a785797e7b53e3cbf9569b989be6e93/3sf-mini/consensus.py#L52-L54
/// for the 3SF-mini reference.
///
/// For why we have unjustifiable slots, consider that in high-latency
/// scenarios, validators may vote for many different slots, making none of them
/// reach the supermajority threshold. By having unjustifiable slots, we can
/// funnel votes towards only some slots, increasing finalization chances.
pub fn slot_is_justifiable_after(slot: u64, finalized_slot: u64) -> bool {
    let Some(delta) = slot.checked_sub(finalized_slot) else {
        // Candidate slot must not be before finalized slot
        return false;
    };
    // Rule 1: The first 5 slots after finalization are always justifiable.
    //
    // Examples: delta = 0, 1, 2, 3, 4, 5
    delta <= 5
        // Rule 2: Slots at perfect square distances are justifiable.
        //
        // Examples: delta = 1, 4, 9, 16, 25, 36, 49, 64, ...
        // Check: integer square root squared equals delta
        || delta.isqrt().pow(2) == delta
        // Rule 3: Slots at pronic number distances are justifiable.
        //
        // Pronic numbers have the form n(n+1): 2, 6, 12, 20, 30, 42, 56, ...
        // Mathematical insight: For pronic delta = n(n+1), we have:
        //   4*delta + 1 = 4n(n+1) + 1 = (2n+1)^2
        // Check: 4*delta+1 is an odd perfect square
        || delta
            .checked_mul(4)
            .and_then(|v| v.checked_add(1))
            .is_some_and(|val| val.isqrt().pow(2) == val && val % 2 == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::{
        attestation::{AggregatedAttestation, AggregationBits, AttestationData},
        block::BlockBody,
        checkpoint::Checkpoint,
        primitives::H256,
        state::{ChainConfig, JustifiedSlots, State, Validator},
    };
    use libssz_types::SszList;

    fn make_validators(n: usize) -> Vec<Validator> {
        (0..n)
            .map(|i| Validator {
                attestation_pubkey: [i as u8; 52],
                proposal_pubkey: [i as u8; 52],
                index: i as u64,
            })
            .collect()
    }

    fn make_bits(set: &[usize], len: usize) -> AggregationBits {
        let mut b = AggregationBits::with_length(len).unwrap();
        for &i in set {
            b.set(i, true).unwrap();
        }
        b
    }

    fn make_attestation(
        att_slot: u64,
        src: (u64, H256),
        tgt: (u64, H256),
        head: (u64, H256),
        bits_set: &[usize],
        bits_len: usize,
    ) -> AggregatedAttestation {
        AggregatedAttestation {
            aggregation_bits: make_bits(bits_set, bits_len),
            data: AttestationData {
                slot: att_slot,
                source: Checkpoint {
                    slot: src.0,
                    root: src.1,
                },
                target: Checkpoint {
                    slot: tgt.0,
                    root: tgt.1,
                },
                head: Checkpoint {
                    slot: head.0,
                    root: head.1,
                },
            },
        }
    }

    /// leanSpec #833: `attestation_data_matches_chain` must reject a vote whose
    /// head sits off the canonical chain, even when source and target are both
    /// canonical. Justification is keyed on `target.root`, so accepting a
    /// canonical FFG vote paired with a sibling LMD head would decouple the two.
    #[test]
    fn matches_chain_rejects_off_canonical_head() {
        let r1 = H256([1u8; 32]);
        let r2 = H256([2u8; 32]);
        let sibling = H256([0x99u8; 32]);

        // Canonical chain: slot 0 genesis (ZERO is fine for source here only if
        // non-zero; use explicit roots), slot 1 -> r1, slot 2 -> r2.
        let g = H256([7u8; 32]);
        let hashes: Vec<H256> = vec![g, r1, r2];

        // source=(0,g), target=(1,r1) both canonical; head=(2, sibling) is not.
        let off_head = AttestationData {
            slot: 2,
            source: Checkpoint { slot: 0, root: g },
            target: Checkpoint { slot: 1, root: r1 },
            head: Checkpoint {
                slot: 2,
                root: sibling,
            },
        };
        assert!(
            !attestation_data_matches_chain(&hashes, &off_head),
            "off-canonical head must be rejected"
        );

        // Control: the same vote with the canonical head=(2, r2) is accepted.
        let canonical_head = AttestationData {
            head: Checkpoint { slot: 2, root: r2 },
            ..off_head
        };
        assert!(
            attestation_data_matches_chain(&hashes, &canonical_head),
            "fully canonical vote must be accepted"
        );

        // A zero-hash head is also rejected up front.
        let zero_head = AttestationData {
            head: Checkpoint {
                slot: 2,
                root: H256::ZERO,
            },
            ..off_head
        };
        assert!(
            !attestation_data_matches_chain(&hashes, &zero_head),
            "zero-hash head must be rejected"
        );

        // A head slot beyond the chain view is rejected.
        let out_of_range_head = AttestationData {
            head: Checkpoint { slot: 99, root: r2 },
            ..off_head
        };
        assert!(
            !attestation_data_matches_chain(&hashes, &out_of_range_head),
            "out-of-range head slot must be rejected"
        );
    }

    /// Regression: `process_attestations` must not let `state.latest_justified`
    /// regress within a single block when attestations appear in body order
    /// whose target slots are not monotonically increasing.
    ///
    /// Observed on devnet at canonical slot 27984: a block carried three
    /// supermajority attestations targeting slots 27978, 27981, and 27974 (in
    /// that order). Each reached the supermajority threshold and the
    /// unconditional `state.latest_justified = target` assignment caused the
    /// post-state to end at `latest_justified.slot = 27974`. Because the
    /// store had already latched `latest_justified = 27978` from importing a
    /// fork block, every subsequent proposal failed
    /// `JustifiedDivergenceNotClosed` and the chain froze.
    ///
    /// Compressed setup: finalized=0, source=3 (justified), targets in body
    /// order 4 / 9 / 6 — all justifiable from finalized=0 (Δ=4 ≤ 5, Δ=9=3²,
    /// Δ=6=2·3). With 4 validators, three votes is supermajority, so each
    /// attestation crosses the threshold.
    #[test]
    fn latest_justified_does_not_regress_within_block() {
        const NUM_VALIDATORS: usize = 4;
        let r3 = H256([3u8; 32]);
        let r4 = H256([4u8; 32]);
        let r6 = H256([6u8; 32]);
        let r9 = H256([9u8; 32]);

        // historical_block_hashes indexed by slot. Genesis at slot 0 is ZERO
        // (matches the default finalized checkpoint), then we place the
        // canonical roots at slots 3 / 4 / 6 / 9. Other slots are empty and
        // are not referenced by any attestation in the test.
        let mut hashes: Vec<H256> = vec![H256::ZERO; 10];
        hashes[3] = r3;
        hashes[4] = r4;
        hashes[6] = r6;
        hashes[9] = r9;

        let validators = make_validators(NUM_VALIDATORS);
        let mut justified_slots = JustifiedSlots::new();
        justified_slots_ops::extend_to_slot(&mut justified_slots, 0, 9);
        // Mark slot 3 as justified so source=(3, r3) passes is_valid_vote.
        justified_slots_ops::set_justified(&mut justified_slots, 0, 3);

        let mut state = State {
            config: ChainConfig { genesis_time: 0 },
            slot: 10,
            latest_block_header: BlockHeader {
                slot: 9,
                proposer_index: 0,
                parent_root: H256::ZERO,
                state_root: H256::ZERO,
                body_root: BlockBody::default().hash_tree_root(),
            },
            latest_justified: Checkpoint { slot: 3, root: r3 },
            latest_finalized: Checkpoint {
                slot: 0,
                root: H256::ZERO,
            },
            historical_block_hashes: SszList::try_from(hashes).unwrap(),
            justified_slots,
            validators: SszList::try_from(validators).unwrap(),
            justifications_roots: Default::default(),
            justifications_validators: JustificationValidators::new(),
            latest_execution_payload_header: Default::default(),
        };

        // Three supermajority attestations (3 of 4 validators each), all from
        // source=(3, r3), in body order targeting slots 4 → 9 → 6.
        let atts: Vec<AggregatedAttestation> = vec![
            make_attestation(3, (3, r3), (4, r4), (4, r4), &[0, 1, 3], NUM_VALIDATORS),
            make_attestation(3, (3, r3), (9, r9), (9, r9), &[0, 1, 2], NUM_VALIDATORS),
            make_attestation(3, (3, r3), (6, r6), (6, r6), &[0, 2, 3], NUM_VALIDATORS),
        ];
        let atts: AggregatedAttestations = atts.try_into().unwrap();

        process_attestations(&mut state, &atts).expect("process_attestations should succeed");

        // After processing, the chain's view of "latest justified" must be the
        // highest justified target (slot 9), not the last-processed one
        // (slot 6). Pre-fix this assertion fails with slot=6.
        assert_eq!(
            state.latest_justified.slot,
            9,
            "latest_justified regressed: got slot={}, root={}; expected slot=9",
            state.latest_justified.slot,
            ShortRoot(&state.latest_justified.root.0)
        );
        assert_eq!(state.latest_justified.root, r9);
    }

    /// Regression (leanSpec #802): a supermajority attestation whose source sits
    /// at or behind the finalized boundary may justify a newer target, but must
    /// never advance (rewind) finalization below that boundary.
    ///
    /// Setup: finalized = justified = slot 4. A supermajority votes from a stale
    /// source at slot 1 to a fresh target at slot 6 (Δ=2 is pronic, so the target
    /// is justifiable). The target should become justified while the finalized
    /// checkpoint stays pinned at slot 4.
    #[test]
    fn stale_finalized_source_justifies_without_rewinding_finalization() {
        const NUM_VALIDATORS: usize = 4;
        let r1 = H256([1u8; 32]);
        let r4 = H256([4u8; 32]);
        let r6 = H256([6u8; 32]);

        let mut hashes: Vec<H256> = vec![H256::ZERO; 7];
        hashes[1] = r1;
        hashes[4] = r4;
        hashes[6] = r6;

        let validators = make_validators(NUM_VALIDATORS);
        // Window is relative to finalized=4; cover up to slot 6 (slots 5 and 6).
        let mut justified_slots = JustifiedSlots::new();
        justified_slots_ops::extend_to_slot(&mut justified_slots, 4, 6);

        let mut state = State {
            config: ChainConfig { genesis_time: 0 },
            slot: 7,
            latest_block_header: BlockHeader {
                slot: 6,
                proposer_index: 0,
                parent_root: H256::ZERO,
                state_root: H256::ZERO,
                body_root: BlockBody::default().hash_tree_root(),
            },
            latest_justified: Checkpoint { slot: 4, root: r4 },
            latest_finalized: Checkpoint { slot: 4, root: r4 },
            historical_block_hashes: SszList::try_from(hashes).unwrap(),
            justified_slots,
            validators: SszList::try_from(validators).unwrap(),
            justifications_roots: Default::default(),
            justifications_validators: JustificationValidators::new(),
            latest_execution_payload_header: Default::default(),
        };

        // Supermajority (3 of 4) attesting from the stale source (slot 1) to the
        // fresh target (slot 6). Source slot 1 <= finalized 4, so it is implicitly
        // justified and passes is_valid_vote.
        let atts: Vec<AggregatedAttestation> = vec![make_attestation(
            7,
            (1, r1),
            (6, r6),
            (6, r6),
            &[0, 1, 2],
            NUM_VALIDATORS,
        )];
        let atts: AggregatedAttestations = atts.try_into().unwrap();

        process_attestations(&mut state, &atts).expect("process_attestations should succeed");

        // The target is justified.
        assert_eq!(state.latest_justified.slot, 6);
        assert_eq!(state.latest_justified.root, r6);
        // Finalization stays pinned at the boundary: the stale source must not
        // rewind or re-finalize.
        assert_eq!(state.latest_finalized.slot, 4);
        assert_eq!(state.latest_finalized.root, r4);
    }
}
