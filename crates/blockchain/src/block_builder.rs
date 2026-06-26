//! Block building: select attestations and seal state root.
//!
//! The selection algorithm is a tiered greedy modeled on Prysm's
//! `sortByProfitability`. Each round scores remaining candidates against a
//! projected post-state and picks the best per `EntryScore`: tier 1
//! (finalizes source) beats tier 2 (justifies target) beats tier 3 (adds
//! marginal new voters). Justification and finalization are projected
//! incrementally so dependent attestations become eligible on the next round
//! without re-running the STF. The final STF runs once after selection to
//! seal `state_root`.
//!
//! Compaction is disabled: each `AttestationData` is packed with a single
//! proof (the best one, see `select_best_proof`), so no recursive proof merge
//! runs during block building.

use std::{
    cmp::Reverse,
    collections::{HashMap, HashSet},
    time::Instant,
};

use ethlambda_state_transition::{
    attestation_data_matches_chain, justified_slots_ops, process_block, process_slots,
    slot_is_justifiable_after,
};
use ethlambda_types::{
    ShortRoot,
    attestation::{AggregatedAttestation, AttestationData},
    block::{AggregatedAttestations, Block, BlockBody, TypeOneMultiSignature},
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
/// Selects attestations via `select_attestations` (one proof per
/// `AttestationData`, no compaction) and runs the STF once to seal the state
/// root. The proposer signature is NOT included; it is appended by the caller.
pub(crate) fn build_block(
    head_state: &State,
    slot: u64,
    proposer_index: u64,
    parent_root: H256,
    known_block_roots: &HashSet<H256>,
    aggregated_payloads: &HashMap<H256, (AttestationData, Vec<TypeOneMultiSignature>)>,
) -> Result<(Block, Vec<TypeOneMultiSignature>, PostBlockCheckpoints), StoreError> {
    info!(slot, proposer_index, "Building block");

    let select_start = Instant::now();
    let selected = select_attestations(
        head_state,
        slot,
        parent_root,
        known_block_roots,
        aggregated_payloads,
    );
    metrics::observe_block_proposal_phase("select_payloads", select_start.elapsed());

    let child_payloads_consumed = selected.len();

    // Compaction disabled: `select_attestations` packs exactly one proof per
    // AttestationData, so each appears at most once and no recursive proof
    // merge (`aggregate_proofs`) is needed.
    let (aggregated_attestations, aggregated_signatures): (Vec<_>, Vec<_>) =
        selected.into_iter().unzip();

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
    // ethlambda runs the STF once after selection (it projects justification
    // incrementally instead of re-running the STF per loop round), so this is
    // a single `stf_simulate` observation per build.
    let stf_start = Instant::now();
    process_slots(&mut post_state, slot)?;
    process_block(&mut post_state, &final_block)?;
    metrics::observe_block_proposal_phase("stf_simulate", stf_start.elapsed());
    final_block.state_root = post_state.hash_tree_root();

    metrics::inc_block_proposal_child_payloads_consumed(child_payloads_consumed as u64);
    metrics::observe_block_proposal_attestation_data_selected(final_block.body.attestations.len());
    metrics::observe_block_proposal_aggregates_selected(aggregated_signatures.len());

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
/// delegated to `select_best_proof` (one proof per entry, no compaction).
fn select_attestations(
    head_state: &State,
    slot: u64,
    parent_root: H256,
    known_block_roots: &HashSet<H256>,
    aggregated_payloads: &HashMap<H256, (AttestationData, Vec<TypeOneMultiSignature>)>,
) -> Vec<(AggregatedAttestation, TypeOneMultiSignature)> {
    let mut selected: Vec<(AggregatedAttestation, TypeOneMultiSignature)> = Vec::new();
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
        let Some((data_root, score)) =
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
        metrics::inc_block_proposal_attestation_builds();

        let before = selected.len();
        let target_root = att_data.target.root;
        let prior_voters = projected.current_votes.get(&target_root);
        // Compaction disabled: pack only the single best proof for this data.
        // `covered` is exactly what landed in the block, so the projection below
        // stays consistent with the STF.
        let covered = select_best_proof(proofs, &mut selected, att_data, prior_voters);

        let packed_voters = covered.len();
        projected
            .current_votes
            .entry(target_root)
            .or_default()
            .extend(covered);

        trace!(
            tier = ?score.tier,
            candidate_new_voters = score.new_voters,
            packed_voters,
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
/// entries, returns `(data_root, score)` for the entry with the best
/// `EntryScore::ordering_key` (lower is better). Caller re-indexes
/// `chain.aggregated_payloads[&data_root]` for `att_data` and `proofs`.
fn pick_best_candidate(
    chain: &ChainContext<'_>,
    processed_data_roots: &HashSet<H256>,
    projected: &ProjectedState,
) -> Option<(H256, EntryScore)> {
    let mut best: Option<(H256, EntryScore)> = None;
    let mut best_key: Option<OrderingKey> = None;

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

        let Some(score) = score_entry(
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
            best = Some((*data_root, score));
            best_key = Some(candidate_key);
        }
    }

    best
}

/// Static inputs to the attestation selection scan: the candidate pool and
/// the chain-level facts used to filter and score entries. Built once before
/// the round loop in `select_attestations`.
struct ChainContext<'a> {
    aggregated_payloads: &'a HashMap<H256, (AttestationData, Vec<TypeOneMultiSignature>)>,
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
/// running voter set for its `target.root` (no marginal value, drop). A
/// genesis self-vote cannot justify or finalize and is always scored as tier 3.
///
/// Only the score is returned; the voters packed into the block are chosen
/// later by `select_best_proof` (a single proof), so the caller updates its
/// projection from that function's return value rather than from this scan.
fn score_entry(
    att_data: &AttestationData,
    proofs: &[TypeOneMultiSignature],
    current_votes: &HashMap<H256, HashSet<u64>>,
    projected_finalized_slot: u64,
    validator_count: usize,
) -> Option<EntryScore> {
    let prior_voters = current_votes.get(&att_data.target.root);
    let prior_count = prior_voters.map_or(0, HashSet::len);

    // Collect voters that this entry adds on top of prior_voters. Avoids
    // cloning prior_voters; the inner contains() makes this O(participants)
    // per candidate per round.
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

    // 3SF-mini finalization requires the source to lie past the finalized
    // boundary (a source at or behind it is already final and must not
    // re-finalize) and no slot strictly between source.slot and target.slot to
    // still be justifiable (so source and target are consecutive justified
    // checkpoints in the projected post-state). Mirrors `try_finalize` in the
    // state transition.
    let finalizes = crosses_2_3
        && att_data.source.slot > projected_finalized_slot
        && (att_data.source.slot + 1..att_data.target.slot)
            .all(|s| !slot_is_justifiable_after(s, projected_finalized_slot));

    let tier = if is_genesis_self_vote(att_data) || !crosses_2_3 {
        Tier::Build
    } else if finalizes {
        Tier::Finalize
    } else {
        Tier::Justify
    };

    Some(EntryScore {
        tier,
        new_voters: new_voters.len(),
        target_slot: att_data.target.slot,
        att_slot: att_data.slot,
    })
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
/// The within-tier ordering is tier-dependent (leanSpec PR #1149):
///
/// - **Finalize / Justify**: the entry already crosses 2/3 on its target, so
///   newer chain progress leads: larger `target_slot`, then larger `att_slot`,
///   then more `new_voters`. Pushing the justified slot as far forward as
///   possible shortens recovery from a justification or finalization stall.
/// - **Build**: the entry only adds marginal voters toward the threshold, so
///   coverage leads: more `new_voters`, then larger `target_slot`, then larger
///   `att_slot`.
///
/// In both tiers `data_root` (ascending) is the final deterministic tiebreak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EntryScore {
    tier: Tier,
    new_voters: usize,
    target_slot: u64,
    att_slot: u64,
}

/// Total order over candidate entries; the smallest value is the best pick.
/// `tier` leads, then three tier-dependent `Reverse`-encoded priorities, then
/// `data_root` as the deterministic tiebreak. See [`EntryScore::ordering_key`].
type OrderingKey = (Tier, Reverse<u64>, Reverse<u64>, Reverse<u64>, H256);

impl EntryScore {
    /// Sort key where the smallest tuple is the best candidate. `tier` always
    /// leads; the remaining three slots carry tier-dependent priorities (see
    /// the type-level docs), all encoded as `Reverse` so "larger is better".
    fn ordering_key(&self, data_root: H256) -> OrderingKey {
        let more_new_voters = Reverse(self.new_voters as u64);
        let newer_target = Reverse(self.target_slot);
        let newer_att = Reverse(self.att_slot);
        match self.tier {
            Tier::Build => (
                self.tier,
                more_new_voters,
                newer_target,
                newer_att,
                data_root,
            ),
            Tier::Finalize | Tier::Justify => (
                self.tier,
                newer_target,
                newer_att,
                more_new_voters,
                data_root,
            ),
        }
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

/// Select the single best proof for an attestation data entry.
///
/// Compaction is disabled, so each AttestationData is packed with exactly one
/// proof and block building never runs a recursive proof merge. The "best"
/// proof is the one adding the most validators not already counted for this
/// target (`prior_voters`): that maximizes the union toward the 2/3
/// justification threshold and the votes recorded for future blocks.
///
/// Candidates are ranked over `proofs` in slice order, so ties resolve
/// deterministically (last max wins). The chosen proof is appended to
/// `selected` with its AggregatedAttestation. Returns the validators it newly
/// covers (excluding `prior_voters`) so the caller keeps its vote projection
/// consistent with the block; returns an empty set, packing nothing, if no
/// proof adds a new voter.
fn select_best_proof(
    proofs: &[TypeOneMultiSignature],
    selected: &mut Vec<(AggregatedAttestation, TypeOneMultiSignature)>,
    att_data: &AttestationData,
    prior_voters: Option<&HashSet<u64>>,
) -> HashSet<u64> {
    let Some(proof) = proofs.iter().max_by_key(|proof| {
        proof
            .participant_indices()
            .filter(|vid| prior_voters.is_none_or(|prior| !prior.contains(vid)))
            .count()
    }) else {
        return HashSet::new();
    };

    let covered_new: HashSet<u64> = proof
        .participant_indices()
        .filter(|vid| prior_voters.is_none_or(|prior| !prior.contains(vid)))
        .collect();

    // `score_entry` guarantees the entry has at least one new voter, so the best
    // proof adds at least one; guard defensively against packing a useless proof.
    if covered_new.is_empty() {
        return covered_new;
    }

    let att = AggregatedAttestation {
        aggregation_bits: proof.participants.clone(),
        data: att_data.clone(),
    };

    metrics::inc_pq_sig_aggregated_signatures();
    metrics::inc_pq_sig_attestations_in_aggregated_signatures(covered_new.len() as u64);
    selected.push((att, proof.clone()));

    covered_new
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
        attestation::{AggregationBits, AttestationData},
        block::{ByteList512KiB, MultiMessageAggregate, SignedBlock, TypeOneMultiSignature},
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

    /// Regression (leanSpec #802): a supermajority entry whose source sits at
    /// the finalized boundary must be scored `Justify`, not `Finalize`. Such a
    /// source is already final, so it advances nothing; the empty scan range
    /// `(source.slot + 1..target.slot)` would otherwise make `.all(...)`
    /// vacuously true and mis-tier the entry as a finalizer.
    #[test]
    fn score_entry_does_not_finalize_source_at_boundary() {
        const NUM_VALIDATORS: usize = 4;
        const FINALIZED_SLOT: u64 = 4;

        // Source at the finalized boundary, target one slot ahead (empty scan).
        let att_data = AttestationData {
            slot: 7,
            head: Checkpoint {
                slot: 5,
                root: H256([5u8; 32]),
            },
            target: Checkpoint {
                slot: 5,
                root: H256([5u8; 32]),
            },
            source: Checkpoint {
                slot: FINALIZED_SLOT,
                root: H256([4u8; 32]),
            },
        };

        // Supermajority (3 of 4) so the entry crosses 2/3.
        let proofs = vec![TypeOneMultiSignature::empty(make_bits(&[0, 1, 2]))];

        let score = score_entry(
            &att_data,
            &proofs,
            &HashMap::new(),
            FINALIZED_SLOT,
            NUM_VALIDATORS,
        )
        .expect("entry contributes new voters");

        assert_eq!(
            score.tier,
            Tier::Justify,
            "source at the finalized boundary must justify, not finalize"
        );
    }

    /// Regression test for https://github.com/lambdaclass/ethlambda/issues/259
    ///
    /// Simulates a stall scenario by populating the payload pool with 50
    /// distinct attestation entries, each carrying a ~253 KB proof (realistic
    /// XMSS aggregated proof size). Without the byte budget cap this would
    /// produce a block with all 50 entries. Verifies that build_block caps
    /// at MAX_ATTESTATIONS_DATA and stays under the gossip size limit.
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
        let mut aggregated_payloads: HashMap<H256, (AttestationData, Vec<TypeOneMultiSignature>)> =
            HashMap::new();

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
            let proof = TypeOneMultiSignature::new(bits, proof_data);

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

        // Substitute a worst-case-size proof to model what `propose_block`
        // would attach. The actual SNARK can't be built without lean-multisig,
        // but the size cap (`ByteList512KiB`) bounds the worst case.
        let _ = signatures;
        let proof = MultiMessageAggregate::new(
            ByteList512KiB::try_from(vec![0xAB; 512 * 1024]).expect("worst-case proof fits in cap"),
        );
        let signed_block = SignedBlock {
            message: block,
            proof,
        };

        // SSZ-encode: this is exactly what publish_block does before compression
        let ssz_bytes = signed_block.to_ssz();

        // With MAX_ATTESTATIONS_DATA enforced, blocks should fit within gossip limits.
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
        let proof = TypeOneMultiSignature::new(bits, SszList::try_from(vec![0xAB; 64]).unwrap());

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
            TypeOneMultiSignature::new(bits.clone(), SszList::try_from(vec![0xAB; 64]).unwrap());
        let proof_b = TypeOneMultiSignature::new(bits, SszList::try_from(vec![0xCD; 64]).unwrap());

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

    /// Compaction is disabled: exactly one proof is packed per AttestationData,
    /// the one covering the most validators. No proof is merged.
    #[test]
    fn select_best_proof_packs_single_largest() {
        let data = make_att_data(1);

        // Distinct sizes keep the choice unambiguous: B is the largest.
        let proof_a = TypeOneMultiSignature::empty(make_bits(&[0, 1, 2, 3]));
        let proof_b = TypeOneMultiSignature::empty(make_bits(&[2, 3, 4, 5, 6]));
        let proof_c = TypeOneMultiSignature::empty(make_bits(&[0]));

        let mut selected = Vec::new();
        let covered_new =
            select_best_proof(&[proof_a, proof_b, proof_c], &mut selected, &data, None);

        assert_eq!(selected.len(), 1, "exactly one proof packed, no merge");
        let packed: HashSet<u64> = selected[0].1.participant_indices().collect();
        assert_eq!(packed, HashSet::from([2, 3, 4, 5, 6]), "the largest proof");
        assert_eq!(covered_new, HashSet::from([2, 3, 4, 5, 6]));

        // Attestation bits mirror the packed proof's participants.
        assert_eq!(selected[0].0.aggregation_bits, selected[0].1.participants);
        assert_eq!(selected[0].0.data, data);
    }

    /// "Best" is measured by validators NOT already counted for the target
    /// (`prior_voters`), not by raw participant count: a proof that is mostly
    /// prior voters must lose to one that is all-new.
    #[test]
    fn select_best_proof_ranks_by_net_new_over_prior() {
        let data = make_att_data(1);

        // Prior voters {0,1,2,3}.
        //   A = {0,1,2,3,4}  (5 participants, only validator 4 is net-new)
        //   B = {5,6,7,8}    (4 participants, all net-new)
        // Raw count would pick A; net-new picks B.
        let prior: HashSet<u64> = HashSet::from([0, 1, 2, 3]);
        let proof_a = TypeOneMultiSignature::empty(make_bits(&[0, 1, 2, 3, 4]));
        let proof_b = TypeOneMultiSignature::empty(make_bits(&[5, 6, 7, 8]));

        let mut selected = Vec::new();
        let covered_new =
            select_best_proof(&[proof_a, proof_b], &mut selected, &data, Some(&prior));

        assert_eq!(selected.len(), 1);
        let packed: HashSet<u64> = selected[0].1.participant_indices().collect();
        assert_eq!(packed, HashSet::from([5, 6, 7, 8]), "the all-new proof B");
        // Returned set excludes prior voters.
        assert_eq!(covered_new, HashSet::from([5, 6, 7, 8]));
    }

    /// When every proof is entirely prior voters, nothing is packed (the entry
    /// adds no new votes). Defensive: `score_entry` already drops such entries.
    #[test]
    fn select_best_proof_packs_nothing_when_no_new_voters() {
        let data = make_att_data(1);

        let prior: HashSet<u64> = HashSet::from([0, 1]);
        let proof_a = TypeOneMultiSignature::empty(make_bits(&[0]));
        let proof_b = TypeOneMultiSignature::empty(make_bits(&[1]));

        let mut selected = Vec::new();
        let covered_new =
            select_best_proof(&[proof_a, proof_b], &mut selected, &data, Some(&prior));

        assert!(selected.is_empty(), "no proof adds a new voter");
        assert!(covered_new.is_empty());
    }

    /// End-to-end through `build_block`: an entry with several proofs is packed
    /// with only the single best one (no compaction), and the block still
    /// justifies the target through the real state transition.
    #[test]
    fn build_block_packs_single_best_proof_and_justifies() {
        use ethlambda_types::{
            block::BlockHeader,
            state::{ChainConfig, JustificationValidators, JustifiedSlots},
        };
        use libssz_types::SszList;

        const NUM_VALIDATORS: usize = 50;
        const SUPERMAJORITY: usize = 34; // ceil(2 * 50 / 3)
        const HEAD_SLOT: u64 = 5;
        const TARGET_SLOT: u64 = 1;

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

        let att_data = AttestationData {
            slot,
            head: Checkpoint {
                root: hashes[0],
                slot: 0,
            },
            target: Checkpoint {
                root: hashes[TARGET_SLOT as usize],
                slot: TARGET_SLOT,
            },
            source: Checkpoint {
                root: hashes[0],
                slot: 0,
            },
        };
        let data_root = att_data.hash_tree_root();

        // A supermajority proof (34/50) plus a smaller one. Only the best (the
        // supermajority proof) is packed; the small proof is dropped.
        let mut big_bits = AggregationBits::with_length(NUM_VALIDATORS).unwrap();
        for i in 0..SUPERMAJORITY {
            big_bits.set(i, true).unwrap();
        }
        let big = TypeOneMultiSignature::new(big_bits, SszList::try_from(vec![0xAB; 64]).unwrap());

        let mut small_bits = AggregationBits::with_length(NUM_VALIDATORS).unwrap();
        small_bits.set(SUPERMAJORITY, true).unwrap();
        small_bits.set(SUPERMAJORITY + 1, true).unwrap();
        let small =
            TypeOneMultiSignature::new(small_bits, SszList::try_from(vec![0xCD; 64]).unwrap());

        let mut aggregated_payloads = HashMap::new();
        aggregated_payloads.insert(data_root, (att_data.clone(), vec![big, small]));

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

        // One attestation carrying only the best proof's bits.
        assert_eq!(block.body.attestations.len(), 1);
        let packed = &block
            .body
            .attestations
            .iter()
            .next()
            .unwrap()
            .aggregation_bits;
        let packed_count = (0..NUM_VALIDATORS)
            .filter(|&i| packed.get(i).unwrap_or(false))
            .count();
        assert_eq!(
            packed_count, SUPERMAJORITY,
            "only the best (supermajority) proof is packed, not the extra voters"
        );

        // The single-proof block still justifies the target through the STF.
        assert_eq!(post_checkpoints.justified.slot, TARGET_SLOT);
        assert_eq!(
            post_checkpoints.justified.root,
            hashes[TARGET_SLOT as usize]
        );
    }
}
