//! Block building: select attestations, compact, and seal state root.
//!
//! The selection algorithm is a tiered greedy modeled on Prysm's
//! `sortByProfitability`. Each round scores remaining candidates against a
//! projected post-state and picks the best per `EntryScore`: tier 1
//! (finalizes source) beats tier 2 (justifies target) beats tier 3 (adds
//! marginal new voters). Justification and finalization are projected
//! incrementally so dependent attestations become eligible on the next round
//! without re-running the STF. The final STF runs once after selection to
//! seal `state_root`.

use std::collections::{HashMap, HashSet};

use ethlambda_crypto::aggregate_proofs;
use ethlambda_state_transition::{
    attestation_data_matches_chain, justified_slots_ops, process_block, process_slots,
    slot_is_justifiable_after,
};
use ethlambda_types::{
    ShortRoot,
    attestation::{AggregatedAttestation, AggregationBits, AttestationData},
    block::{AggregatedAttestations, AggregatedSignatureProof, Block, BlockBody},
    checkpoint::Checkpoint,
    primitives::{H256, HashTreeRoot as _},
    state::{JustifiedSlots, State},
};
use tracing::{info, trace};

use crate::{MAX_ATTESTATIONS_DATA, metrics, store::StoreError};

/// Post-block checkpoints extracted from the state transition in `build_block`.
///
/// When building a block, the state transition processes attestations that may
/// advance justification/finalization. These checkpoints reflect the post-state
/// values, which the proposer needs for its attestation (since the block hasn't
/// been imported into the store yet).
pub struct PostBlockCheckpoints {
    pub justified: Checkpoint,
    pub finalized: Checkpoint,
}

/// Build a valid block on top of this state.
///
/// Selects attestations via `select_attestations`, compacts duplicate
/// `AttestationData` entries, and runs the STF once to seal the state root.
/// The proposer signature is NOT included; it is appended by the caller.
pub(crate) fn build_block(
    head_state: &State,
    slot: u64,
    proposer_index: u64,
    parent_root: H256,
    known_block_roots: &HashSet<H256>,
    aggregated_payloads: &HashMap<H256, (AttestationData, Vec<AggregatedSignatureProof>)>,
) -> Result<(Block, Vec<AggregatedSignatureProof>, PostBlockCheckpoints), StoreError> {
    info!(slot, proposer_index, "Building block");

    let selected = select_attestations(
        head_state,
        slot,
        parent_root,
        known_block_roots,
        aggregated_payloads,
    );

    // Compact: merge proofs sharing the same AttestationData via recursive
    // aggregation so each AttestationData appears at most once (leanSpec #510).
    let compacted = compact_attestations(selected, head_state)?;

    let (aggregated_attestations, aggregated_signatures): (Vec<_>, Vec<_>) =
        compacted.into_iter().unzip();

    let attestations: AggregatedAttestations = aggregated_attestations
        .try_into()
        .expect("attestation count exceeds limit");
    let mut final_block = Block {
        slot,
        proposer_index,
        parent_root,
        state_root: H256::ZERO,
        body: BlockBody { attestations },
    };
    let mut post_state = head_state.clone();
    process_slots(&mut post_state, slot)?;
    process_block(&mut post_state, &final_block)?;
    final_block.state_root = post_state.hash_tree_root();

    let post_checkpoints = PostBlockCheckpoints {
        justified: post_state.latest_justified,
        finalized: post_state.latest_finalized,
    };

    Ok((final_block, aggregated_signatures, post_checkpoints))
}

/// Tiered greedy attestation selection for block proposal.
///
/// Each round scores remaining candidates against a projected post-state and
/// picks the best per `EntryScore`: tier 1 (finalizes source) beats tier 2
/// (justifies target) beats tier 3 (adds new voters). Justification and
/// finalization are projected incrementally so dependent attestations become
/// eligible on the next round without re-running the STF.
///
/// Stops at `MAX_ATTESTATIONS_DATA` distinct data entries or when no
/// remaining candidate has a positive score. Within-entry proof selection is
/// delegated to `extend_proofs_greedily`.
fn select_attestations(
    head_state: &State,
    slot: u64,
    parent_root: H256,
    known_block_roots: &HashSet<H256>,
    aggregated_payloads: &HashMap<H256, (AttestationData, Vec<AggregatedSignatureProof>)>,
) -> Vec<(AggregatedAttestation, AggregatedSignatureProof)> {
    let mut selected: Vec<(AggregatedAttestation, AggregatedSignatureProof)> = Vec::new();
    if aggregated_payloads.is_empty() {
        return selected;
    }

    // Chain view that `process_block_header` would produce on the candidate
    // block: covering [0, slot - 1] with parent_root at parent.slot and
    // ZERO_HASH for empty slots in between. Lets us validate source/target
    // roots without waiting for the STF to drop mismatches.
    let parent_slot = head_state.latest_block_header.slot;
    let num_empty_slots = slot.saturating_sub(parent_slot).saturating_sub(1) as usize;
    let mut extended_historical_block_hashes: Vec<H256> =
        head_state.historical_block_hashes.iter().copied().collect();
    extended_historical_block_hashes.push(parent_root);
    extended_historical_block_hashes.extend(std::iter::repeat_n(H256::ZERO, num_empty_slots));

    let chain = ChainContext {
        aggregated_payloads,
        known_block_roots,
        extended_historical_block_hashes: &extended_historical_block_hashes,
        validator_count: head_state.validators.len(),
    };

    // Running per-target-root voter set, seeded from state and updated
    // incrementally as entries are selected. Mirrors the role of Eth2
    // participation flags in Prysm/Lighthouse-style packing.
    let mut projected = ProjectedState {
        justified_slots: head_state.justified_slots.clone(),
        finalized_slot: head_state.latest_finalized.slot,
        current_votes: build_running_votes(head_state),
    };
    let mut processed_data_roots: HashSet<H256> = HashSet::new();

    for _round in 0..MAX_ATTESTATIONS_DATA {
        let Some((data_root, score, new_voters)) =
            pick_best_candidate(&chain, &processed_data_roots, &projected)
        else {
            trace!(
                selected_total = processed_data_roots.len(),
                "converged: no scoring candidates"
            );
            break;
        };
        let (att_data, proofs) = &chain.aggregated_payloads[&data_root];

        processed_data_roots.insert(data_root);

        let before = selected.len();
        extend_proofs_greedily(proofs, &mut selected, att_data);

        let target_root = att_data.target.root;
        projected
            .current_votes
            .entry(target_root)
            .or_default()
            .extend(new_voters);

        trace!(
            tier = ?score.tier,
            new_voters = score.new_voters,
            target_slot = score.target_slot,
            target_root = %ShortRoot(&target_root.0),
            data_root = %ShortRoot(&data_root.0),
            selected_proofs = selected.len() - before,
            "selected"
        );

        // Project justification / finalization. Finalize implies Justify
        // (target is justified, AND source is finalized).
        if score.tier <= Tier::Justify {
            justified_slots_ops::extend_to_slot(
                &mut projected.justified_slots,
                projected.finalized_slot,
                att_data.target.slot,
            );
            justified_slots_ops::set_justified(
                &mut projected.justified_slots,
                projected.finalized_slot,
                att_data.target.slot,
            );
            // Justified target's voter bucket is no longer relevant for
            // scoring (no further entry can target it: filter rejects).
            projected.current_votes.remove(&target_root);
        }
        if score.tier == Tier::Finalize {
            let new_finalized = att_data.source.slot;
            let delta = new_finalized.saturating_sub(projected.finalized_slot) as usize;
            justified_slots_ops::shift_window(&mut projected.justified_slots, delta);
            projected.finalized_slot = new_finalized;
        }
    }

    selected
}

/// Scan candidate attestation entries and pick the highest-scoring one.
///
/// Skips entries already processed, those failing `entry_passes_filters`
/// (logging the reason), and those with zero new voters. Among remaining
/// entries, returns `(data_root, score, new_voters)` for the entry with the
/// best `EntryScore::ordering_key` (lower is better). Caller re-indexes
/// `chain.aggregated_payloads[&data_root]` for `att_data` and `proofs`.
fn pick_best_candidate(
    chain: &ChainContext<'_>,
    processed_data_roots: &HashSet<H256>,
    projected: &ProjectedState,
) -> Option<(H256, EntryScore, HashSet<u64>)> {
    let mut best: Option<(H256, EntryScore, HashSet<u64>)> = None;
    let mut best_key: Option<(Tier, std::cmp::Reverse<usize>, u64, u64, H256)> = None;

    for (data_root, (att_data, proofs)) in chain.aggregated_payloads {
        if processed_data_roots.contains(data_root) {
            continue;
        }
        if let Err(reason) = entry_passes_filters(
            att_data,
            chain.known_block_roots,
            chain.extended_historical_block_hashes,
            &projected.justified_slots,
            projected.finalized_slot,
        ) {
            trace_skipped_attestation(reason, att_data, data_root);
            continue;
        }

        let Some((score, new_voters)) = score_entry(
            att_data,
            proofs,
            &projected.current_votes,
            projected.finalized_slot,
            chain.validator_count,
        ) else {
            trace_skipped_attestation("zero_new_voters", att_data, data_root);
            continue;
        };

        let candidate_key = score.ordering_key(*data_root);
        if best_key.as_ref().is_none_or(|k| candidate_key < *k) {
            best = Some((*data_root, score, new_voters));
            best_key = Some(candidate_key);
        }
    }

    best
}

/// Static inputs to the attestation selection scan: the candidate pool and
/// the chain-level facts used to filter and score entries. Built once before
/// the round loop in `select_attestations`.
struct ChainContext<'a> {
    aggregated_payloads: &'a HashMap<H256, (AttestationData, Vec<AggregatedSignatureProof>)>,
    known_block_roots: &'a HashSet<H256>,
    extended_historical_block_hashes: &'a [H256],
    validator_count: usize,
}

/// Mutable projection of the post-state that `select_attestations` maintains
/// across rounds: which slots are justified, which slot is finalized, and the
/// running per-target-root voter set.
struct ProjectedState {
    justified_slots: JustifiedSlots,
    finalized_slot: u64,
    current_votes: HashMap<H256, HashSet<u64>>,
}

/// Validate a candidate entry against the projected chain view.
///
/// Mirrors `state_transition::is_valid_vote`: the entry's head must be known,
/// its source must be justified, its (source, target) must match the
/// candidate-block chain view, `target.slot > source.slot`, target must not
/// already be justified, and target must be a justifiable slot relative to
/// the projected finalized slot. The genesis self-vote (source == target ==
/// slot 0) is exempt from the `target.slot > source.slot` and
/// `target_already_justified` checks since fork-choice bootstrapping needs
/// it; STF will silently drop it, but it carries fork-choice signal.
fn entry_passes_filters(
    att_data: &AttestationData,
    known_block_roots: &HashSet<H256>,
    extended_historical_block_hashes: &[H256],
    projected_justified_slots: &JustifiedSlots,
    projected_finalized_slot: u64,
) -> Result<(), &'static str> {
    if !known_block_roots.contains(&att_data.head.root) {
        return Err("head_root_unknown");
    }
    if !justified_slots_ops::is_slot_justified(
        projected_justified_slots,
        projected_finalized_slot,
        att_data.source.slot,
    ) {
        return Err("source_not_justified");
    }
    if !attestation_data_matches_chain(extended_historical_block_hashes, att_data) {
        return Err("chain_mismatch");
    }
    let is_genesis_self_vote = is_genesis_self_vote(att_data);
    if !is_genesis_self_vote && att_data.target.slot <= att_data.source.slot {
        return Err("target_not_after_source");
    }
    if !is_genesis_self_vote
        && justified_slots_ops::is_slot_justified(
            projected_justified_slots,
            projected_finalized_slot,
            att_data.target.slot,
        )
    {
        return Err("target_already_justified");
    }
    if !is_genesis_self_vote
        && !slot_is_justifiable_after(att_data.target.slot, projected_finalized_slot)
    {
        return Err("target_not_justifiable");
    }
    Ok(())
}

/// Score a single candidate entry under the current projected state.
///
/// Returns `None` if the entry has zero new validators relative to the
/// running voter set for its `target.root` (no marginal value, drop). On
/// `Some`, the returned `HashSet` is the set of new voters contributed by
/// this entry (caller uses it to update the running voter map without
/// re-scanning aggregation bits). A genesis self-vote cannot justify or
/// finalize and is always scored as tier 3.
fn score_entry(
    att_data: &AttestationData,
    proofs: &[AggregatedSignatureProof],
    current_votes: &HashMap<H256, HashSet<u64>>,
    projected_finalized_slot: u64,
    validator_count: usize,
) -> Option<(EntryScore, HashSet<u64>)> {
    let prior_voters = current_votes.get(&att_data.target.root);
    let prior_count = prior_voters.map_or(0, HashSet::len);

    // Collect voters that this entry adds on top of prior_voters. Avoids
    // cloning prior_voters; the inner contains() makes this O(participants)
    // per candidate per round. `extend_proofs_greedily` selects proofs until
    // none contribute new voters, so its final coverage equals this set
    // unioned with prior_voters.
    let mut new_voters: HashSet<u64> = HashSet::new();
    for proof in proofs {
        for vid in proof.participant_indices() {
            if prior_voters.is_none_or(|prior| !prior.contains(&vid)) {
                new_voters.insert(vid);
            }
        }
    }
    if new_voters.is_empty() {
        return None;
    }

    let total = prior_count + new_voters.len();
    let crosses_2_3 = 3 * total >= 2 * validator_count;

    // 3SF-mini finalization requires no slot strictly between source.slot
    // and target.slot to still be justifiable (so source and target are
    // consecutive justified checkpoints in the projected post-state).
    let finalizes = crosses_2_3
        && (att_data.source.slot + 1..att_data.target.slot)
            .all(|s| !slot_is_justifiable_after(s, projected_finalized_slot));

    let tier = if is_genesis_self_vote(att_data) || !crosses_2_3 {
        Tier::Build
    } else if finalizes {
        Tier::Finalize
    } else {
        Tier::Justify
    };

    Some((
        EntryScore {
            tier,
            new_voters: new_voters.len(),
            target_slot: att_data.target.slot,
            att_slot: att_data.slot,
        },
        new_voters,
    ))
}

/// Selection tier for a candidate `AttestationData` entry.
///
/// Declared in priority order: lower variant beats higher under derived
/// `Ord`. `#[repr(u8)]` pins the discriminant for self-describing trace
/// output (`tier = Finalize` is clearer than `tier = 1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
enum Tier {
    /// Applying the entry crosses 2/3 on target AND finalizes the source
    /// (no slot strictly between source.slot and target.slot is still
    /// justifiable given projected finalized_slot).
    Finalize = 1,
    /// Applying the entry crosses 2/3 on target but does not finalize.
    Justify = 2,
    /// Adds marginal new voters toward target's 2/3 supermajority.
    Build = 3,
}

/// Tiered score for a candidate `AttestationData` entry during block building.
///
/// Lower `tier` wins. Entries with zero new voters relative to the running
/// per-target-root voter set are dropped (returned as `None`).
///
/// Within a tier, ordering prefers more `new_voters` (descending), then
/// smaller `target_slot` (older chain progress first), then smaller
/// `att_slot`, then the entry's `data_root` for determinism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EntryScore {
    tier: Tier,
    new_voters: usize,
    target_slot: u64,
    att_slot: u64,
}

impl EntryScore {
    fn ordering_key(&self, data_root: H256) -> (Tier, std::cmp::Reverse<usize>, u64, u64, H256) {
        (
            self.tier,
            std::cmp::Reverse(self.new_voters),
            self.target_slot,
            self.att_slot,
            data_root,
        )
    }
}

/// Deserialize `state.justifications_validators` into a per-target-root voter
/// map for fast lookup and incremental update during proposer scoring.
///
/// The state's flattened layout is `bit[i * N + j] = validator j voted for
/// justifications_roots[i]` (see `serialize_justifications`).
fn build_running_votes(state: &State) -> HashMap<H256, HashSet<u64>> {
    let validator_count = state.validators.len();
    let mut votes: HashMap<H256, HashSet<u64>> = HashMap::new();
    for (i, root) in state.justifications_roots.iter().enumerate() {
        let mut voters = HashSet::new();
        for j in 0..validator_count {
            if state.justifications_validators.get(i * validator_count + j) == Some(true) {
                voters.insert(j as u64);
            }
        }
        votes.insert(*root, voters);
    }
    votes
}

/// Compact attestations so each AttestationData appears at most once.
///
/// For each group of entries sharing the same AttestationData:
/// - Single entry: kept as-is.
/// - Multiple entries: merged into one using recursive proof aggregation
///   (leanSpec PR #510).
fn compact_attestations(
    entries: Vec<(AggregatedAttestation, AggregatedSignatureProof)>,
    head_state: &State,
) -> Result<Vec<(AggregatedAttestation, AggregatedSignatureProof)>, StoreError> {
    if entries.len() <= 1 {
        return Ok(entries);
    }

    // Group indices by AttestationData, preserving first-occurrence order
    let mut order: Vec<AttestationData> = Vec::new();
    let mut groups: HashMap<AttestationData, Vec<usize>> = HashMap::new();
    for (i, (att, _)) in entries.iter().enumerate() {
        match groups.entry(att.data.clone()) {
            std::collections::hash_map::Entry::Vacant(e) => {
                order.push(e.key().clone());
                e.insert(vec![i]);
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                e.get_mut().push(i);
            }
        }
    }

    // Fast path: no duplicates
    if order.len() == entries.len() {
        return Ok(entries);
    }

    // Wrap in Option so we can .take() items by index without cloning
    let mut items: Vec<Option<(AggregatedAttestation, AggregatedSignatureProof)>> =
        entries.into_iter().map(Some).collect();

    let mut compacted = Vec::with_capacity(order.len());

    for data in order {
        let indices = &groups[&data];
        if indices.len() == 1 {
            let item = items[indices[0]].take().expect("index used once");
            compacted.push(item);
            continue;
        }

        // Collect all entries for this AttestationData
        let group_items: Vec<(AggregatedAttestation, AggregatedSignatureProof)> = indices
            .iter()
            .map(|&idx| items[idx].take().expect("index used once"))
            .collect();

        // Union participant bitfields
        let merged_bits = group_items.iter().skip(1).fold(
            group_items[0].0.aggregation_bits.clone(),
            |acc, (att, _)| union_aggregation_bits(&acc, &att.aggregation_bits),
        );

        // Recursively aggregate child proofs into one (leanSpec #510).
        let data_root = data.hash_tree_root();
        let children: Vec<(Vec<_>, _)> = group_items
            .iter()
            .map(|(_, proof)| {
                let pubkeys = proof
                    .participant_indices()
                    .map(|vid| {
                        head_state
                            .validators
                            .get(vid as usize)
                            .ok_or(StoreError::InvalidValidatorIndex)?
                            .get_attestation_pubkey()
                            .map_err(|_| StoreError::PubkeyDecodingFailed(vid))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok((pubkeys, proof.proof_data.clone()))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;

        let slot: u32 = data.slot.try_into().expect("slot exceeds u32");
        let merged_proof_data = aggregate_proofs(children, &data_root, slot)
            .map_err(StoreError::SignatureAggregationFailed)?;

        let merged_proof = AggregatedSignatureProof::new(merged_bits.clone(), merged_proof_data);
        let merged_att = AggregatedAttestation {
            aggregation_bits: merged_bits,
            data,
        };
        compacted.push((merged_att, merged_proof));
    }

    Ok(compacted)
}

/// Greedily select proofs maximizing new validator coverage.
///
/// For a single attestation data entry, picks proofs that cover the most
/// uncovered validators. A proof is selected as long as it adds at least
/// one previously-uncovered validator; partially-overlapping participants
/// between selected proofs are allowed. `compact_attestations` later feeds
/// these proofs as children to `aggregate_proofs`, which delegates to
/// `xmss_aggregate` — that function tracks duplicate pubkeys across
/// children via its `dup_pub_keys` machinery, so overlap is supported by
/// the underlying aggregation scheme.
///
/// Each selected proof is appended to `selected` paired with its
/// corresponding AggregatedAttestation.
fn extend_proofs_greedily(
    proofs: &[AggregatedSignatureProof],
    selected: &mut Vec<(AggregatedAttestation, AggregatedSignatureProof)>,
    att_data: &AttestationData,
) {
    if proofs.is_empty() {
        return;
    }

    let mut covered: HashSet<u64> = HashSet::new();
    let mut remaining_indices: HashSet<usize> = (0..proofs.len()).collect();

    while !remaining_indices.is_empty() {
        // Pick proof covering the most uncovered validators (count only, no allocation)
        let best = remaining_indices
            .iter()
            .map(|&idx| {
                let count = proofs[idx]
                    .participant_indices()
                    .filter(|vid| !covered.contains(vid))
                    .count();
                (idx, count)
            })
            .max_by_key(|&(_, count)| count);

        let Some((best_idx, best_count)) = best else {
            break;
        };
        if best_count == 0 {
            break;
        }

        let proof = &proofs[best_idx];

        // Collect coverage only for the winning proof
        let new_covered: Vec<u64> = proof
            .participant_indices()
            .filter(|vid| !covered.contains(vid))
            .collect();

        let att = AggregatedAttestation {
            aggregation_bits: proof.participants.clone(),
            data: att_data.clone(),
        };

        metrics::inc_pq_sig_aggregated_signatures();
        metrics::inc_pq_sig_attestations_in_aggregated_signatures(new_covered.len() as u64);

        covered.extend(new_covered);
        selected.push((att, proof.clone()));
        remaining_indices.remove(&best_idx);
    }
}

/// Compute the bitwise union (OR) of two AggregationBits bitfields.
fn union_aggregation_bits(a: &AggregationBits, b: &AggregationBits) -> AggregationBits {
    let max_len = a.len().max(b.len());
    if max_len == 0 {
        return AggregationBits::with_length(0).expect("zero-length bitlist");
    }
    let mut result = AggregationBits::with_length(max_len).expect("union exceeds bitlist capacity");
    for i in 0..max_len {
        if a.get(i).unwrap_or(false) || b.get(i).unwrap_or(false) {
            result.set(i, true).expect("index within capacity");
        }
    }
    result
}

/// Genesis self-votes (source == target == slot 0) are allowed in blocks for
/// fork-choice bootstrapping even though their target is already justified
/// and they can never justify or finalize.
fn is_genesis_self_vote(att: &AttestationData) -> bool {
    att.source.slot == 0 && att.target.slot == 0
}

fn trace_skipped_attestation(reason: &'static str, att: &AttestationData, data_root: &H256) {
    trace!(
        reason,
        attestation_slot = att.slot,
        source_slot = att.source.slot,
        source_root = %ShortRoot(&att.source.root.0),
        target_slot = att.target.slot,
        target_root = %ShortRoot(&att.target.root.0),
        head_slot = att.head.slot,
        head_root = %ShortRoot(&att.head.root.0),
        data_root = %ShortRoot(&data_root.0),
        "skipped"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::{
        attestation::{
            AggregatedAttestation, AggregationBits, AttestationData, blank_xmss_signature,
        },
        block::{
            AggregatedSignatureProof, AttestationSignatures, BlockBody, BlockSignatures,
            SignedBlock,
        },
        checkpoint::Checkpoint,
        state::State,
    };

    fn make_att_data(slot: u64) -> AttestationData {
        AttestationData {
            slot,
            head: Checkpoint::default(),
            target: Checkpoint::default(),
            source: Checkpoint::default(),
        }
    }

    fn make_bits(indices: &[usize]) -> AggregationBits {
        let max = indices.iter().copied().max().unwrap_or(0);
        let mut bits = AggregationBits::with_length(max + 1).unwrap();
        for &i in indices {
            bits.set(i, true).unwrap();
        }
        bits
    }

    /// Regression test for https://github.com/lambdaclass/ethlambda/issues/259
    ///
    /// Simulates a stall scenario by populating the payload pool with 50
    /// distinct attestation entries, each carrying a ~253 KB proof (realistic
    /// XMSS aggregated proof size). Without the byte budget cap this would
    /// produce a block with all 50 entries. Verifies that build_block caps
    /// at MAX_ATTESTATIONS_DATA (16) and stays under the gossip size limit.
    #[test]
    fn build_block_caps_attestation_data_entries() {
        use ethlambda_types::{
            block::BlockHeader,
            state::{ChainConfig, JustificationValidators, JustifiedSlots},
        };
        use libssz::SszEncode;
        use libssz_types::SszList;

        const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024; // 10 MiB (spec limit)
        const PROOF_SIZE: usize = 253 * 1024; // ~253 KB realistic XMSS proof
        const NUM_VALIDATORS: usize = 50;
        const NUM_PAYLOAD_ENTRIES: usize = 50;

        const HEAD_SLOT: u64 = 51;
        const TARGET_SLOT: u64 = 5;

        let validators: Vec<_> = (0..NUM_VALIDATORS)
            .map(|i| ethlambda_types::state::Validator {
                attestation_pubkey: [i as u8; 52],
                proposal_pubkey: [i as u8; 52],
                index: i as u64,
            })
            .collect();

        // Build a head state at slot HEAD_SLOT with valid historical_block_hashes
        // so attestations referencing in-range slots match the chain (the
        // chain-match check in build_block now rejects mismatches).
        let hashes: Vec<H256> = (0..HEAD_SLOT).map(|i| H256([(i + 1) as u8; 32])).collect();
        let historical_block_hashes = SszList::try_from(hashes.clone()).unwrap();

        let head_header = BlockHeader {
            slot: HEAD_SLOT,
            proposer_index: 0,
            parent_root: H256::ZERO,
            state_root: H256::ZERO,
            body_root: BlockBody::default().hash_tree_root(),
        };

        let head_state = State {
            config: ChainConfig { genesis_time: 1000 },
            slot: HEAD_SLOT,
            latest_block_header: head_header,
            latest_justified: Checkpoint::default(),
            latest_finalized: Checkpoint::default(),
            historical_block_hashes,
            justified_slots: JustifiedSlots::new(),
            validators: SszList::try_from(validators).unwrap(),
            justifications_roots: Default::default(),
            justifications_validators: JustificationValidators::new(),
        };

        // process_slots fills in the parent header's state_root before
        // process_block_header computes the parent hash. Simulate that here.
        let mut header_for_root = head_state.latest_block_header.clone();
        header_for_root.state_root = head_state.hash_tree_root();
        let parent_root = header_for_root.hash_tree_root();

        let slot = HEAD_SLOT + 1;
        let proposer_index = slot % NUM_VALIDATORS as u64;

        // Common source / target / head referencing valid chain entries so the
        // chain-match check passes for every payload. We vary AttestationData.slot
        // alone to produce 50 distinct data_roots.
        let source = Checkpoint {
            root: hashes[0],
            slot: 0,
        };
        let target = Checkpoint {
            root: hashes[TARGET_SLOT as usize],
            slot: TARGET_SLOT,
        };
        let head = Checkpoint {
            root: hashes[0],
            slot: 0,
        };

        let mut known_block_roots = HashSet::new();
        known_block_roots.insert(parent_root);
        known_block_roots.insert(hashes[0]);

        // Simulate a stall: populate the payload pool with many distinct entries.
        // Each has a unique attestation slot and a large proof payload.
        let mut aggregated_payloads: HashMap<
            H256,
            (AttestationData, Vec<AggregatedSignatureProof>),
        > = HashMap::new();

        for i in 0..NUM_PAYLOAD_ENTRIES {
            let att_data = AttestationData {
                slot: (i + 1) as u64,
                head,
                target,
                source,
            };

            // Use the real hash_tree_root as the data_root key
            let data_root = att_data.hash_tree_root();

            // Create a single large proof per entry (one validator per proof)
            let validator_id = i % NUM_VALIDATORS;
            let mut bits = AggregationBits::with_length(NUM_VALIDATORS).unwrap();
            bits.set(validator_id, true).unwrap();

            let proof_bytes: Vec<u8> = vec![0xAB; PROOF_SIZE];
            let proof_data = SszList::try_from(proof_bytes).expect("proof fits in ByteListMiB");
            let proof = AggregatedSignatureProof::new(bits, proof_data);

            aggregated_payloads.insert(data_root, (att_data, vec![proof]));
        }

        // Build the block; this should succeed (the bug: no size guard)
        let (block, signatures, _post_checkpoints) = build_block(
            &head_state,
            slot,
            proposer_index,
            parent_root,
            &known_block_roots,
            &aggregated_payloads,
        )
        .expect("build_block should succeed");

        // MAX_ATTESTATIONS_DATA should have been enforced: fewer than 50 entries included
        let attestation_count = block.body.attestations.len();
        assert!(attestation_count > 0, "block should contain attestations");
        assert!(
            attestation_count <= MAX_ATTESTATIONS_DATA,
            "MAX_ATTESTATIONS_DATA should cap attestations: got {attestation_count}"
        );

        // Construct the full signed block as it would be sent over gossip
        let attestation_sigs: Vec<AggregatedSignatureProof> = signatures;
        let signed_block = SignedBlock {
            message: block,
            signature: BlockSignatures {
                attestation_signatures: AttestationSignatures::try_from(attestation_sigs).unwrap(),
                proposer_signature: blank_xmss_signature(),
            },
        };

        // SSZ-encode: this is exactly what publish_block does before compression
        let ssz_bytes = signed_block.to_ssz();

        // With MAX_ATTESTATIONS_DATA = 16, blocks should fit within gossip limits.
        assert!(
            ssz_bytes.len() <= MAX_PAYLOAD_SIZE,
            "block with {} attestations is {} bytes SSZ, exceeds MAX_PAYLOAD_SIZE ({} bytes)",
            signed_block.message.body.attestations.len(),
            ssz_bytes.len(),
            MAX_PAYLOAD_SIZE,
        );
    }

    /// Regression test for leanSpec PR #716: build_block must absorb
    /// gap-closing attestations whose source is justified on the head
    /// chain but older than `latest_justified` (e.g., a sibling fork
    /// advanced the store's justified past what the canonical head has
    /// proven). Without the relaxed `is_slot_justified(source.slot)`
    /// filter, the exact-equality check would drop the attestation and
    /// justification would never converge on this chain.
    #[test]
    fn build_block_absorbs_older_but_justified_source() {
        use ethlambda_state_transition::justified_slots_ops;
        use ethlambda_types::{
            block::BlockHeader,
            state::{ChainConfig, JustificationValidators, JustifiedSlots},
        };
        use libssz_types::SszList;

        const NUM_VALIDATORS: usize = 50;
        const SUPERMAJORITY: usize = 34; // ceil(2 * 50 / 3)
        const HEAD_SLOT: u64 = 5;
        const JUSTIFIED_SLOT: u64 = 1;
        const GAP_TARGET_SLOT: u64 = 2;

        let validators: Vec<_> = (0..NUM_VALIDATORS)
            .map(|i| ethlambda_types::state::Validator {
                attestation_pubkey: [i as u8; 52],
                proposal_pubkey: [i as u8; 52],
                index: i as u64,
            })
            .collect();

        let hashes: Vec<H256> = (0..HEAD_SLOT).map(|i| H256([(i + 1) as u8; 32])).collect();

        let mut justified_slots = JustifiedSlots::new();
        justified_slots_ops::extend_to_slot(&mut justified_slots, 0, JUSTIFIED_SLOT);
        justified_slots_ops::set_justified(&mut justified_slots, 0, JUSTIFIED_SLOT);

        let head_header = BlockHeader {
            slot: HEAD_SLOT,
            proposer_index: 0,
            parent_root: H256::ZERO,
            state_root: H256::ZERO,
            body_root: BlockBody::default().hash_tree_root(),
        };

        let head_state = State {
            config: ChainConfig { genesis_time: 1000 },
            slot: HEAD_SLOT,
            latest_block_header: head_header,
            latest_justified: Checkpoint {
                root: hashes[JUSTIFIED_SLOT as usize],
                slot: JUSTIFIED_SLOT,
            },
            latest_finalized: Checkpoint::default(),
            historical_block_hashes: SszList::try_from(hashes.clone()).unwrap(),
            justified_slots,
            validators: SszList::try_from(validators).unwrap(),
            justifications_roots: Default::default(),
            justifications_validators: JustificationValidators::new(),
        };

        let mut header_for_root = head_state.latest_block_header.clone();
        header_for_root.state_root = head_state.hash_tree_root();
        let parent_root = header_for_root.hash_tree_root();

        let slot = HEAD_SLOT + 1;
        let proposer_index = slot % NUM_VALIDATORS as u64;

        // source = genesis (slot 0): older than head.latest_justified at
        // slot 1. Pre-PR exact-equality filter would drop this; post-PR
        // it's absorbed and the candidate justifies GAP_TARGET_SLOT.
        let att_data = AttestationData {
            slot,
            head: Checkpoint {
                root: hashes[0],
                slot: 0,
            },
            target: Checkpoint {
                root: hashes[GAP_TARGET_SLOT as usize],
                slot: GAP_TARGET_SLOT,
            },
            source: Checkpoint {
                root: hashes[0],
                slot: 0,
            },
        };
        let data_root = att_data.hash_tree_root();

        let mut bits = AggregationBits::with_length(NUM_VALIDATORS).unwrap();
        for i in 0..SUPERMAJORITY {
            bits.set(i, true).unwrap();
        }
        let proof = AggregatedSignatureProof::new(bits, SszList::try_from(vec![0xAB; 64]).unwrap());

        let mut aggregated_payloads = HashMap::new();
        aggregated_payloads.insert(data_root, (att_data.clone(), vec![proof]));

        let mut known_block_roots = HashSet::new();
        known_block_roots.insert(parent_root);
        known_block_roots.insert(hashes[0]);

        let (block, _signatures, post_checkpoints) = build_block(
            &head_state,
            slot,
            proposer_index,
            parent_root,
            &known_block_roots,
            &aggregated_payloads,
        )
        .expect("build_block should succeed");

        let targets: Vec<_> = block
            .body
            .attestations
            .iter()
            .map(|att| att.data.target)
            .collect();
        assert!(
            targets.contains(&att_data.target),
            "produced block missing gap-closing attestation: {targets:?}"
        );

        assert_eq!(post_checkpoints.justified.slot, GAP_TARGET_SLOT);
        assert_eq!(
            post_checkpoints.justified.root,
            hashes[GAP_TARGET_SLOT as usize]
        );
    }

    /// Verifies the in-round projection of justified_slots. Round 1 selects
    /// attestation A (source=0, target=1), which projects slot 1 as justified.
    /// Attestation B has source=1 and would have been filtered as
    /// `source_not_justified` against the initial state; with the projection,
    /// round 2 admits it and the proposer packs both attestations.
    #[test]
    fn build_block_cascades_projected_justification_across_rounds() {
        use ethlambda_types::{
            block::BlockHeader,
            state::{ChainConfig, JustificationValidators, JustifiedSlots},
        };
        use libssz_types::SszList;

        const NUM_VALIDATORS: usize = 50;
        const SUPERMAJORITY: usize = 34; // ceil(2 * 50 / 3)
        const HEAD_SLOT: u64 = 10;

        let validators: Vec<_> = (0..NUM_VALIDATORS)
            .map(|i| ethlambda_types::state::Validator {
                attestation_pubkey: [i as u8; 52],
                proposal_pubkey: [i as u8; 52],
                index: i as u64,
            })
            .collect();

        let hashes: Vec<H256> = (0..HEAD_SLOT).map(|i| H256([(i + 1) as u8; 32])).collect();

        let head_header = BlockHeader {
            slot: HEAD_SLOT,
            proposer_index: 0,
            parent_root: H256::ZERO,
            state_root: H256::ZERO,
            body_root: BlockBody::default().hash_tree_root(),
        };
        let head_state = State {
            config: ChainConfig { genesis_time: 1000 },
            slot: HEAD_SLOT,
            latest_block_header: head_header,
            latest_justified: Checkpoint::default(),
            latest_finalized: Checkpoint::default(),
            historical_block_hashes: SszList::try_from(hashes.clone()).unwrap(),
            justified_slots: JustifiedSlots::new(),
            validators: SszList::try_from(validators).unwrap(),
            justifications_roots: Default::default(),
            justifications_validators: JustificationValidators::new(),
        };

        let mut header_for_root = head_state.latest_block_header.clone();
        header_for_root.state_root = head_state.hash_tree_root();
        let parent_root = header_for_root.hash_tree_root();

        let slot = HEAD_SLOT + 1;
        let proposer_index = slot % NUM_VALIDATORS as u64;

        // A: source = slot 0 (implicitly justified), target = slot 1.
        // B: source = slot 1 (NOT yet justified at block-build start),
        //    target = slot 2.
        let att_a = AttestationData {
            slot,
            head: Checkpoint {
                root: hashes[0],
                slot: 0,
            },
            target: Checkpoint {
                root: hashes[1],
                slot: 1,
            },
            source: Checkpoint {
                root: hashes[0],
                slot: 0,
            },
        };
        let att_b = AttestationData {
            slot,
            head: Checkpoint {
                root: hashes[0],
                slot: 0,
            },
            target: Checkpoint {
                root: hashes[2],
                slot: 2,
            },
            source: Checkpoint {
                root: hashes[1],
                slot: 1,
            },
        };

        let mut bits = AggregationBits::with_length(NUM_VALIDATORS).unwrap();
        for i in 0..SUPERMAJORITY {
            bits.set(i, true).unwrap();
        }
        let proof_a =
            AggregatedSignatureProof::new(bits.clone(), SszList::try_from(vec![0xAB; 64]).unwrap());
        let proof_b =
            AggregatedSignatureProof::new(bits, SszList::try_from(vec![0xCD; 64]).unwrap());

        let mut aggregated_payloads = HashMap::new();
        aggregated_payloads.insert(att_a.hash_tree_root(), (att_a.clone(), vec![proof_a]));
        aggregated_payloads.insert(att_b.hash_tree_root(), (att_b.clone(), vec![proof_b]));

        let mut known_block_roots = HashSet::new();
        known_block_roots.insert(parent_root);
        known_block_roots.insert(hashes[0]);

        let (block, _signatures, post_checkpoints) = build_block(
            &head_state,
            slot,
            proposer_index,
            parent_root,
            &known_block_roots,
            &aggregated_payloads,
        )
        .expect("build_block should succeed");

        let target_slots: Vec<u64> = block
            .body
            .attestations
            .iter()
            .map(|a| a.data.target.slot)
            .collect();
        assert!(
            target_slots.contains(&1),
            "A (target slot 1) missing: {target_slots:?}"
        );
        assert!(
            target_slots.contains(&2),
            "B (target slot 2) missing despite cascading projection: {target_slots:?}"
        );

        // Both attestations justify their targets; STF lands on slot 2.
        assert_eq!(post_checkpoints.justified.slot, 2);
    }

    #[test]
    fn compact_attestations_no_duplicates() {
        let data_a = make_att_data(1);
        let data_b = make_att_data(2);
        let bits_a = make_bits(&[0]);
        let bits_b = make_bits(&[1]);

        let entries = vec![
            (
                AggregatedAttestation {
                    aggregation_bits: bits_a.clone(),
                    data: data_a.clone(),
                },
                AggregatedSignatureProof::empty(bits_a),
            ),
            (
                AggregatedAttestation {
                    aggregation_bits: bits_b.clone(),
                    data: data_b.clone(),
                },
                AggregatedSignatureProof::empty(bits_b),
            ),
        ];

        let state = State::from_genesis(1000, vec![]);
        let out = compact_attestations(entries, &state).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0.data, data_a);
        assert_eq!(out[1].0.data, data_b);
    }

    #[test]
    fn compact_attestations_preserves_order_no_duplicates() {
        let data_a = make_att_data(1);
        let data_b = make_att_data(2);
        let data_c = make_att_data(3);

        let bits_0 = make_bits(&[0]);
        let bits_1 = make_bits(&[1]);
        let bits_2 = make_bits(&[2]);

        let entries = vec![
            (
                AggregatedAttestation {
                    aggregation_bits: bits_0.clone(),
                    data: data_a.clone(),
                },
                AggregatedSignatureProof::empty(bits_0),
            ),
            (
                AggregatedAttestation {
                    aggregation_bits: bits_1.clone(),
                    data: data_b.clone(),
                },
                AggregatedSignatureProof::empty(bits_1),
            ),
            (
                AggregatedAttestation {
                    aggregation_bits: bits_2.clone(),
                    data: data_c.clone(),
                },
                AggregatedSignatureProof::empty(bits_2),
            ),
        ];

        let state = State::from_genesis(1000, vec![]);
        let out = compact_attestations(entries, &state).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].0.data, data_a);
        assert_eq!(out[1].0.data, data_b);
        assert_eq!(out[2].0.data, data_c);
    }

    /// A partially-overlapping proof is still selected as long as it adds at
    /// least one previously-uncovered validator. The greedy prefers the
    /// largest proof first, then picks additional proofs whose coverage
    /// extends `covered`. The resulting overlap is handled downstream by
    /// `aggregate_proofs` → `xmss_aggregate` (which tracks duplicate pubkeys
    /// across children via its `dup_pub_keys` machinery).
    #[test]
    fn extend_proofs_greedily_allows_overlap_when_it_adds_coverage() {
        let data = make_att_data(1);

        // Distinct sizes to avoid tie-breaking ambiguity (HashSet iteration
        // order differs between debug/release):
        //   A = {0, 1, 2, 3}  (4 validators — largest, picked first)
        //   B = {2, 3, 4}     (overlaps A on {2,3} but adds validator 4)
        //   C = {1, 2}        (subset of A — adds nothing, must be skipped)
        let proof_a = AggregatedSignatureProof::empty(make_bits(&[0, 1, 2, 3]));
        let proof_b = AggregatedSignatureProof::empty(make_bits(&[2, 3, 4]));
        let proof_c = AggregatedSignatureProof::empty(make_bits(&[1, 2]));

        let mut selected = Vec::new();
        extend_proofs_greedily(&[proof_a, proof_b, proof_c], &mut selected, &data);

        assert_eq!(
            selected.len(),
            2,
            "A and B selected (B adds validator 4); C adds nothing and is skipped"
        );

        let covered: HashSet<u64> = selected
            .iter()
            .flat_map(|(_, p)| p.participant_indices())
            .collect();
        assert_eq!(covered, HashSet::from([0, 1, 2, 3, 4]));

        // Attestation bits mirror the proof's participants for each entry.
        for (att, proof) in &selected {
            assert_eq!(att.aggregation_bits, proof.participants);
            assert_eq!(att.data, data);
        }
    }

    /// When no proof contributes new coverage (subset of a previously selected
    /// proof), greedy terminates without selecting it.
    #[test]
    fn extend_proofs_greedily_stops_when_no_new_coverage() {
        let data = make_att_data(1);

        // B's participants are a subset of A's. After picking A, B offers zero
        // new coverage and must not be selected (its inclusion would also
        // violate the disjoint invariant).
        let proof_a = AggregatedSignatureProof::empty(make_bits(&[0, 1, 2, 3]));
        let proof_b = AggregatedSignatureProof::empty(make_bits(&[1, 2]));

        let mut selected = Vec::new();
        extend_proofs_greedily(&[proof_a, proof_b], &mut selected, &data);

        assert_eq!(selected.len(), 1);
        let covered: HashSet<u64> = selected[0].1.participant_indices().collect();
        assert_eq!(covered, HashSet::from([0, 1, 2, 3]));
    }
}
