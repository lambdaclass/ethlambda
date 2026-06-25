//! Reaggregate-from-block: recover per-attestation Type-1 proofs from a
//! freshly imported block's merged Type-2 proof and fold them into the local
//! aggregated-payload pool.
//!
//! Mirrors leanSpec PR #717 `SyncService._deconstruct_block_into_store`.
//! Required for catching-up nodes (and aggregators) to surface block-borne
//! votes to the rest of the network — without this, a validator that only
//! observed an attestation through a block can't republish it on gossip.
//!
//! ## Cost
//!
//! Each `split_type_2_by_message` runs a fresh SNARK. We bound the worst
//! case by:
//!
//! 1. Only deconstructing when the chain is in sync — backfilling nodes
//!    must not flood gossip with rederived aggregates.
//! 2. Skipping attestations whose target is at or behind the store's
//!    justified checkpoint — they carry no fork-choice value.
//! 3. Skipping attestations whose participants are already a subset of the
//!    local union for that data — nothing to recover.
//! 4. Capping the number of splits per imported block at
//!    [`MAX_REAGGREGATIONS_PER_BLOCK`] so an attacker-shaped block cannot
//!    blow past the slot budget.

use std::collections::HashSet;

use ethlambda_storage::Store;
use ethlambda_types::{
    attestation::{
        AggregatedAttestation, HashedAttestationData, SignedAggregatedAttestation,
        validator_indices,
    },
    block::{SignedBlock, TypeOneMultiSignature},
    primitives::{H256, HashTreeRoot as _},
    signature::ValidatorPublicKey,
};
use tracing::{debug, warn};

/// Maximum number of attestations whose Type-1 we will SNARK-split out of
/// any single imported block. Each split runs a fresh recursive SNARK
/// (~hundreds of ms) so the cap keeps block-import latency predictable.
pub const MAX_REAGGREGATIONS_PER_BLOCK: usize = 4;

/// Recover per-attestation Type-1 proofs from a freshly imported block.
///
/// Returns the combined aggregates that gained new validator coverage; the
/// caller publishes them on gossip when this node acts as an aggregator.
/// Always updates the store regardless of role so non-aggregator nodes
/// still get the fork-choice weight from block-imported votes.
pub fn reaggregate_from_block(
    store: &mut Store,
    signed_block: &SignedBlock,
) -> Vec<SignedAggregatedAttestation> {
    let block = &signed_block.message;
    let attestations: Vec<AggregatedAttestation> =
        block.body.attestations.iter().cloned().collect();
    if attestations.is_empty() {
        return Vec::new();
    }

    // The Type-2 proof was built against the parent state's validator set.
    // Without it we cannot resolve the pubkey layout the SNARK was bound to.
    let Some(parent_state) = store.get_state(&block.parent_root) else {
        debug!(
            block_root = %ethlambda_types::ShortRoot(&block.hash_tree_root().0),
            "Skipping reaggregation: parent state missing"
        );
        return Vec::new();
    };
    let validators = &parent_state.validators;
    let num_validators = validators.len() as u64;

    // Per-component pubkeys: one entry per body attestation in order, then
    // the proposer entry. Layout is invariant per block, so it's resolved
    // once and reused for every split call below.
    let mut pubkeys_per_component: Vec<Vec<ValidatorPublicKey>> =
        Vec::with_capacity(attestations.len() + 1);
    for att in &attestations {
        let mut pubkeys = Vec::new();
        for vid in validator_indices(&att.aggregation_bits) {
            if vid >= num_validators {
                warn!(vid, "Reaggregation aborted: participant out of range");
                return Vec::new();
            }
            let Ok(pk) = validators[vid as usize].get_attestation_pubkey() else {
                warn!(vid, "Reaggregation aborted: bad attestation pubkey");
                return Vec::new();
            };
            pubkeys.push(pk);
        }
        pubkeys_per_component.push(pubkeys);
    }
    if block.proposer_index >= num_validators {
        return Vec::new();
    }
    let Ok(proposer_pubkey) = validators[block.proposer_index as usize].get_proposal_pubkey()
    else {
        return Vec::new();
    };
    pubkeys_per_component.push(vec![proposer_pubkey]);

    let candidates = select_candidates(store, &attestations);
    if candidates.is_empty() {
        return Vec::new();
    }

    // Run the splits and merges. A failure on one attestation is logged
    // and skipped — partial progress still surfaces useful aggregates.
    let mut aggregates: Vec<SignedAggregatedAttestation> = Vec::with_capacity(candidates.len());
    let mut store_inserts: Vec<(HashedAttestationData, TypeOneMultiSignature)> =
        Vec::with_capacity(candidates.len());

    for candidate in candidates {
        let att = &attestations[candidate.idx];
        let data_root = candidate.data_root;
        let slot_u32: u32 = match att.data.slot.try_into() {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Step 1: SNARK-split this attestation's component out of the block's
        // merged Type-2 proof.
        let merged_bytes = signed_block.proof.proof_bytes();
        let split_bytes = match ethlambda_crypto::split_type_2_by_message(
            merged_bytes,
            pubkeys_per_component.clone(),
            &data_root,
        ) {
            Ok(bytes) => bytes,
            Err(err) => {
                debug!(%err, data_root = %ethlambda_types::ShortRoot(&data_root.0),
                    "Reaggregation split failed");
                continue;
            }
        };
        let block_t1 =
            TypeOneMultiSignature::new(att.aggregation_bits.clone(), split_bytes.clone());

        // Step 2: merge the split with local partials covering the same
        // AttestationData so the combined proof binds every known signer.
        // A child-only merge needs ≥ 2 children; if we only have the
        // block proof, use it as-is.
        let combined = if candidate.local_partials.is_empty() {
            block_t1
        } else {
            let mut children: Vec<(Vec<ValidatorPublicKey>, _)> =
                Vec::with_capacity(1 + candidate.local_partials.len());

            // First child: the split-from-block proof, paired with the
            // pubkeys derived from the block attestation's participant set.
            let block_att_pubkeys = pubkeys_per_component[candidate.idx].clone();
            children.push((block_att_pubkeys, split_bytes));

            // Remaining children: local partial Type-1s for the same data.
            let mut bad = false;
            for partial in &candidate.local_partials {
                let mut pubkeys = Vec::with_capacity(partial.participants.count_ones());
                for vid in partial.participant_indices() {
                    if vid >= num_validators {
                        bad = true;
                        break;
                    }
                    match validators[vid as usize].get_attestation_pubkey() {
                        Ok(pk) => pubkeys.push(pk),
                        Err(_) => {
                            bad = true;
                            break;
                        }
                    }
                }
                if bad {
                    break;
                }
                children.push((pubkeys, partial.proof.clone()));
            }
            if bad {
                continue;
            }

            let merged_bytes =
                match ethlambda_crypto::aggregate_proofs(children, &data_root, slot_u32) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        debug!(%err, data_root = %ethlambda_types::ShortRoot(&data_root.0),
                        "Reaggregation merge failed");
                        continue;
                    }
                };
            // Union the block participants with every local partial's
            // participants — the merged proof binds them all.
            let mut union_indices: HashSet<u64> =
                validator_indices(&att.aggregation_bits).collect();
            for partial in &candidate.local_partials {
                union_indices.extend(partial.participant_indices());
            }
            let max_vid = union_indices.iter().copied().max().unwrap_or(0);
            let mut union_bits =
                ethlambda_types::attestation::AggregationBits::with_length(max_vid as usize + 1)
                    .expect("union bitfield length within capacity");
            for vid in &union_indices {
                union_bits
                    .set(*vid as usize, true)
                    .expect("vid within union bitfield length");
            }
            TypeOneMultiSignature::new(union_bits, merged_bytes)
        };

        let hashed = HashedAttestationData::new(att.data.clone());
        store_inserts.push((hashed.clone(), combined.clone()));
        aggregates.push(SignedAggregatedAttestation {
            data: att.data.clone(),
            proof: combined,
        });
    }

    // Insert into the new pool. `PayloadBuffer::push` auto-prunes any local
    // partial whose participants are a strict subset of the combined proof,
    // so explicit supersede tracking isn't needed.
    if !store_inserts.is_empty() {
        store.insert_new_aggregated_payloads_batch(store_inserts);
    }

    aggregates
}

struct Candidate {
    idx: usize,
    data_root: H256,
    new_validators: usize,
    local_partials: Vec<TypeOneMultiSignature>,
}

/// Identify attestations from a freshly imported block worth SNARK-splitting.
///
/// A candidate is an attestation whose target outruns the store's justified
/// checkpoint and whose participants extend the local coverage for that
/// AttestationData. Candidates are sorted by uncovered-validator count and
/// capped at [`MAX_REAGGREGATIONS_PER_BLOCK`] so an attacker-shaped block
/// cannot blow past the slot budget.
fn select_candidates(store: &Store, attestations: &[AggregatedAttestation]) -> Vec<Candidate> {
    let justified_slot = store.latest_justified().slot;
    let mut candidates: Vec<Candidate> = Vec::new();
    for (idx, att) in attestations.iter().enumerate() {
        if att.data.target.slot <= justified_slot {
            continue;
        }
        let data_root = att.data.hash_tree_root();
        let (new, known) = store.existing_proofs_for_data(&data_root);
        let mut local_union: HashSet<u64> = HashSet::new();
        for proof in new.iter().chain(known.iter()) {
            local_union.extend(proof.participant_indices());
        }
        let block_participants: HashSet<u64> = validator_indices(&att.aggregation_bits).collect();
        if block_participants.is_subset(&local_union) {
            continue;
        }
        let mut local: Vec<TypeOneMultiSignature> = new;
        local.extend(known);
        candidates.push(Candidate {
            idx,
            data_root,
            new_validators: block_participants.difference(&local_union).count(),
            local_partials: local,
        });
    }
    candidates.sort_by_key(|c| std::cmp::Reverse(c.new_validators));
    candidates.truncate(MAX_REAGGREGATIONS_PER_BLOCK);
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_storage::{Store, backend::InMemoryBackend};
    use ethlambda_types::{
        attestation::{AggregatedAttestation, AggregationBits, AttestationData},
        checkpoint::Checkpoint,
        state::State,
    };
    use std::sync::Arc;

    fn bits(indices: &[usize]) -> AggregationBits {
        let max = indices.iter().copied().max().unwrap_or(0);
        let mut b = AggregationBits::with_length(max + 1).unwrap();
        for &i in indices {
            b.set(i, true).unwrap();
        }
        b
    }

    fn make_att(slot: u64, target_slot: u64, voters: &[usize]) -> AggregatedAttestation {
        AggregatedAttestation {
            aggregation_bits: bits(voters),
            data: AttestationData {
                slot,
                head: Checkpoint::default(),
                target: Checkpoint {
                    root: H256::ZERO,
                    slot: target_slot,
                },
                source: Checkpoint::default(),
            },
        }
    }

    fn empty_store() -> Store {
        let backend: Arc<dyn ethlambda_storage::StorageBackend> = Arc::new(InMemoryBackend::new());
        Store::from_anchor_state(backend, State::from_genesis(0, vec![]))
    }

    #[test]
    fn select_skips_target_at_or_below_justified() {
        let mut store = empty_store();
        // Justified at slot 5; an attestation with target.slot = 5 must be skipped.
        store
            .update_checkpoints(ethlambda_storage::ForkCheckpoints::new(
                store.head(),
                Some(Checkpoint {
                    root: H256::ZERO,
                    slot: 5,
                }),
                None,
            ))
            .expect("update_checkpoints should succeed");
        let candidates = select_candidates(&store, &[make_att(6, 5, &[0, 1])]);
        assert!(candidates.is_empty());
    }

    #[test]
    fn select_skips_when_block_participants_already_covered() {
        let mut store = empty_store();
        let att = make_att(2, 2, &[0, 1]);
        let hashed = HashedAttestationData::new(att.data.clone());
        // Seed the new-payload pool with a Type-1 covering validators {0, 1}.
        store.insert_new_aggregated_payload(hashed, TypeOneMultiSignature::empty(bits(&[0, 1])));
        let candidates = select_candidates(&store, &[att]);
        assert!(candidates.is_empty());
    }

    #[test]
    fn select_keeps_attestation_with_new_voters() {
        let mut store = empty_store();
        let att = make_att(2, 2, &[0, 1, 2]);
        let hashed = HashedAttestationData::new(att.data.clone());
        // Local pool only covers validator 0.
        store.insert_new_aggregated_payload(hashed, TypeOneMultiSignature::empty(bits(&[0])));
        let candidates = select_candidates(&store, &[att]);
        assert_eq!(candidates.len(), 1);
        // 1 and 2 are uncovered, so new_validators = 2.
        assert_eq!(candidates[0].new_validators, 2);
        assert_eq!(candidates[0].idx, 0);
    }

    #[test]
    fn select_caps_at_max_reaggregations_per_block() {
        let store = empty_store();
        // Synthesize MAX + 5 attestations, each carrying a unique data root and
        // distinct voters so none of the de-dup filters short-circuit.
        let attestations: Vec<AggregatedAttestation> = (0..MAX_REAGGREGATIONS_PER_BLOCK + 5)
            .map(|i| make_att((i + 1) as u64, (i + 2) as u64, &[i * 2, i * 2 + 1]))
            .collect();
        let candidates = select_candidates(&store, &attestations);
        assert_eq!(candidates.len(), MAX_REAGGREGATIONS_PER_BLOCK);
    }

    #[test]
    fn select_prioritises_attestations_with_most_uncovered_voters() {
        let store = empty_store();
        // Two attestations; one covers 1 new voter, the other covers 3.
        let high = make_att(1, 2, &[0, 1, 2]);
        let low = make_att(3, 4, &[5]);
        let candidates = select_candidates(&store, &[low.clone(), high.clone()]);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].new_validators, 3);
        assert_eq!(candidates[0].idx, 1);
    }
}
