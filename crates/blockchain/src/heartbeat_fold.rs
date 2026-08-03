//! Heartbeat fold: the next-slot proposer's job source for the interval-2
//! aggregation pipeline.
//!
//! Turns the raw committee signatures collected on the global heartbeat topic
//! into one type-1 aggregate, so the proposer can pack the committee's votes
//! without waiting for subnet aggregation to build and propagate one.
//!
//! This is a *job source*, not a second session: the produced job runs through
//! the same [`crate::aggregation`] worker, deadline, and `AggregateProduced`
//! machinery as a subnet job. That is what makes the result reach the builder
//! through the ordinary payload pool — inserted into `new_payloads` at the
//! interval-2 boundary, promoted to `known_payloads` at interval 3, and scored by
//! `select_attestations` like any other candidate — with no special path into the
//! block builder.
//!
//! Only the next slot's proposer runs it. Every other node's copy of these votes
//! reaches fork choice directly from the gossip topic, so folding them would be
//! prover work with no consumer.
//!
//! The common case is free. Honest committee members with the same view produce
//! byte-identical `AttestationData`, and their subnet aggregate usually already
//! covers them, so `B \ A` is empty and no job is emitted at all.

use std::collections::{BTreeMap, HashMap, HashSet};

use ethlambda_crypto::signature::{ValidatorPublicKey, ValidatorSignature};
use ethlambda_storage::Store;
use ethlambda_types::{
    ShortRoot,
    attestation::{AttestationData, HashedAttestationData},
    block::{ByteList512KiB, SingleMessageAggregate},
    primitives::H256,
    state::Validator,
};
use tracing::trace;

use crate::aggregation::{AggregationJob, AggregationSnapshot, JobSource};
use crate::metrics;

/// Upper bound on existing type-1s recursed into per fold, mirroring the
/// committee session's child cap.
const MAX_FOLD_CHILDREN: usize = 4;

/// Build the next-slot proposer's single aggregation job over `slot`'s heartbeat
/// committee votes. Runs on the actor thread; touches the store, does no heavy
/// cryptography.
///
/// A committee split can leave several distinct `AttestationData` among the
/// buffered signatures. Exactly one job is emitted, choosing the data with the
/// most buffered committee signers — the same coverage-led preference
/// `Tier::Heartbeat` applies when packing, so the job produced is the entry the
/// block most wants. Ties break on `data_root` ascending for determinism.
///
/// Returns `None` when nothing is foldable, either because no heartbeat signature
/// is buffered or because every buffered signer is already covered by an existing
/// type-1. The caller falls back to an ordinary subnet job in that case.
pub fn heartbeat_aggregation_snapshot(store: &Store, slot: u64) -> Option<AggregationSnapshot> {
    let buffered = store.heartbeat_signatures_at(slot);
    if buffered.is_empty() {
        return None;
    }

    let validators = store.head_state().validators;

    // `AttestationData` per buffered data_root, recovered from the vote store:
    // both are written together in `on_gossip_heartbeat_attestation`.
    let data_by_root: HashMap<H256, AttestationData> = store
        .heartbeat_votes_at(slot)
        .into_values()
        .map(|data| (HashedAttestationData::new(data.clone()).root(), data))
        .collect();

    // Descending buffered-signer count, then ascending data_root.
    let mut by_coverage: Vec<(&H256, &BTreeMap<u64, ValidatorSignature>)> =
        buffered.iter().collect();
    by_coverage.sort_by_key(|(root, sigs)| (std::cmp::Reverse(sigs.len()), **root));

    let groups_considered = by_coverage.len();
    for (data_root, sigs_by_validator) in by_coverage {
        let Some(data) = data_by_root.get(data_root) else {
            // The vote was pruned out from under the signature buffer; a
            // signature is unusable without its data.
            continue;
        };
        let (new_proofs, known_proofs) = store.existing_proofs_for_data(data_root);
        if let Some(job) = resolve_fold_job(
            HashedAttestationData::new(data.clone()),
            sigs_by_validator,
            &new_proofs,
            &known_proofs,
            &validators,
        ) {
            trace!(
                %slot,
                data_root = %ShortRoot(&data_root.0),
                raw_count = job.raw_ids.len(),
                children = job.children.len(),
                "Heartbeat fold job selected"
            );
            return Some(AggregationSnapshot {
                jobs: vec![job],
                groups_considered,
            });
        }
    }

    None
}

/// Build one fold job, or `None` when there is nothing uncovered to fold.
///
/// `A` = participants of the greedily chosen existing type-1s. `B` = the
/// buffered heartbeat signers. **`B` must be reduced to `B \ A` before the
/// `aggregate_mixed` call**: lean-multisig's aggregator tracks duplicate
/// pubkeys, and a validator present both in a child aggregate and in the raw list
/// is a duplicate.
///
/// `aggregate_mixed`'s "at least one raw signature OR at least two children"
/// precondition is satisfied by construction: a job is only emitted when
/// `B \ A` is non-empty.
fn resolve_fold_job(
    hashed: HashedAttestationData,
    sigs_by_validator: &BTreeMap<u64, ValidatorSignature>,
    new_proofs: &[SingleMessageAggregate],
    known_proofs: &[SingleMessageAggregate],
    validators: &[Validator],
) -> Option<AggregationJob> {
    let (children, accepted_child_ids) =
        select_fold_children(new_proofs, known_proofs, HashSet::new(), validators);
    let covered: HashSet<u64> = accepted_child_ids.iter().copied().collect();

    // B \ A, in ascending validator order (XMSS aggregation requires it, which
    // the BTreeMap iteration order already gives us).
    let mut raw_pubkeys = Vec::new();
    let mut raw_sigs = Vec::new();
    let mut raw_ids = Vec::new();
    for (validator_id, signature) in sigs_by_validator {
        if covered.contains(validator_id) {
            continue;
        }
        let Some(validator) = validators.get(*validator_id as usize) else {
            continue;
        };
        let Ok(pubkey) = ValidatorPublicKey::from_bytes(&validator.attestation_pubkey) else {
            continue;
        };
        raw_pubkeys.push(pubkey);
        raw_sigs.push(signature.clone());
        raw_ids.push(*validator_id);
    }

    // Every buffered signer is already covered: reuse the existing type-1
    // unchanged. This is the common case and it costs nothing.
    if raw_ids.is_empty() {
        metrics::inc_heartbeat_fold_skipped();
        trace!(
            data_root = %ShortRoot(&hashed.root().0),
            "Heartbeat fold skipped: no uncovered signers"
        );
        return None;
    }

    let slot = hashed.data().slot;
    Some(AggregationJob {
        hashed,
        slot,
        children,
        accepted_child_ids,
        raw_pubkeys,
        raw_sigs,
        raw_ids,
        // Heartbeat signatures live in their own slot-keyed buffer, pruned by the
        // RLMD window rather than consumed on aggregation, so there is nothing to
        // delete from the gossip pool here.
        keys_to_delete: Vec::new(),
        source: JobSource::Heartbeat,
    })
}

/// Greedily pick existing type-1s to recurse into, resolving their pubkeys.
///
/// Greedy rather than "take them all" so children never overlap each other,
/// which would feed lean-multisig the same duplicate pubkeys the `B \ A`
/// reduction exists to avoid. Drops any child whose pubkeys cannot be fully
/// resolved: passing fewer pubkeys than the proof expects yields an invalid
/// aggregate.
fn select_fold_children(
    new_proofs: &[SingleMessageAggregate],
    known_proofs: &[SingleMessageAggregate],
    seed_covered: HashSet<u64>,
    validators: &[Validator],
) -> (Vec<(Vec<ValidatorPublicKey>, ByteList512KiB)>, Vec<u64>) {
    let mut covered = seed_covered;
    let mut children = Vec::new();
    let mut child_ids: Vec<u64> = Vec::new();

    for proof_set in [new_proofs, known_proofs] {
        let mut remaining: Vec<&SingleMessageAggregate> = proof_set.iter().collect();

        while children.len() < MAX_FOLD_CHILDREN && !remaining.is_empty() {
            let best_idx = remaining
                .iter()
                .enumerate()
                .max_by_key(|(_, p)| {
                    p.participant_indices()
                        .filter(|vid| !covered.contains(vid))
                        .count()
                })
                .map(|(i, _)| i)
                .expect("remaining is non-empty");

            let participant_ids: Vec<u64> = remaining[best_idx].participant_indices().collect();
            if participant_ids.iter().all(|vid| covered.contains(vid)) {
                break;
            }

            let proof = remaining.swap_remove(best_idx);
            let pubkeys: Vec<ValidatorPublicKey> = participant_ids
                .iter()
                .filter_map(|&vid| {
                    let validator = validators.get(vid as usize)?;
                    ValidatorPublicKey::from_bytes(&validator.attestation_pubkey).ok()
                })
                .collect();
            if pubkeys.len() != participant_ids.len() {
                trace!(
                    expected = participant_ids.len(),
                    resolved = pubkeys.len(),
                    "Skipping heartbeat fold child: could not resolve all participant pubkeys"
                );
                continue;
            }

            covered.extend(&participant_ids);
            child_ids.extend(&participant_ids);
            children.push((pubkeys, proof.proof.clone()));
        }

        if children.len() >= MAX_FOLD_CHILDREN {
            break;
        }
    }

    (children, child_ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::checkpoint::Checkpoint;
    use libssz_types::SszList;

    fn validators(n: usize) -> Vec<Validator> {
        (0..n)
            .map(|i| Validator {
                attestation_pubkey: [i as u8; 52],
                proposal_pubkey: [i as u8; 52],
                index: i as u64,
            })
            .collect()
    }

    fn hashed(slot: u64) -> HashedAttestationData {
        HashedAttestationData::new(AttestationData {
            slot,
            head: Checkpoint::default(),
            target: Checkpoint::default(),
            source: Checkpoint::default(),
        })
    }

    /// A type-1 covering exactly `signers`.
    fn child_proof(signers: &[usize]) -> SingleMessageAggregate {
        let max = signers.iter().copied().max().unwrap_or(0);
        let mut bits = ethlambda_types::attestation::AggregationBits::with_length(max + 1).unwrap();
        for &i in signers {
            bits.set(i, true).unwrap();
        }
        let proof = SszList::try_from(vec![0xABu8; 8]).expect("proof fits");
        SingleMessageAggregate::new(bits, proof)
    }

    /// A cheap-but-real XMSS signature (tiny lifetime, cached) for tests that only
    /// need `ValidatorSignature::from_bytes` to succeed. `resolve_fold_job` never
    /// checks validity, only that the signature clones and carries a resolvable
    /// id — mirrors `aggregation::tests::dummy_sig`.
    fn dummy_sig() -> ValidatorSignature {
        use ethlambda_crypto::signature::LeanSignatureScheme;
        use leansig::{serialization::Serializable, signature::SignatureScheme};
        use rand::{SeedableRng, rngs::StdRng};

        static CACHED_SIG: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
            let mut rng = StdRng::seed_from_u64(42);
            let lifetime = 1 << 5; // small for speed
            let (_pk, sk) = LeanSignatureScheme::key_gen(&mut rng, 0, lifetime);
            let sig = LeanSignatureScheme::sign(&sk, 0, &[0u8; 32]).unwrap();
            sig.to_bytes()
        });

        ValidatorSignature::from_bytes(&CACHED_SIG).expect("cached test signature")
    }

    /// Buffered raw heartbeat signatures for `signers`.
    fn buffered(signers: &[u64]) -> BTreeMap<u64, ValidatorSignature> {
        signers.iter().map(|vid| (*vid, dummy_sig())).collect()
    }

    #[test]
    fn fold_reduces_raw_signers_to_b_minus_a() {
        // A child already covers {0, 1}; the buffer holds {0, 1, 2}. Only 2 may
        // reach `aggregate_mixed` as a raw signature — lean-multisig's aggregator
        // tracks duplicate pubkeys, and a validator present both in a child and in
        // the raw list is a duplicate.
        let job = resolve_fold_job(
            hashed(7),
            &buffered(&[0, 1, 2]),
            &[child_proof(&[0, 1])],
            &[],
            &validators(4),
        )
        .expect("an uncovered signer remains");

        assert_eq!(job.raw_ids, vec![2], "covered signers must be dropped");
        assert_eq!(job.children.len(), 1);
        let mut child_ids = job.accepted_child_ids.clone();
        child_ids.sort_unstable();
        assert_eq!(child_ids, vec![0, 1]);
        // The pubkey and signature lists stay aligned with raw_ids; a mismatch is
        // an `aggregate_mixed` CountMismatch error.
        assert_eq!(job.raw_pubkeys.len(), job.raw_ids.len());
        assert_eq!(job.raw_sigs.len(), job.raw_ids.len());
        assert_eq!(job.source, JobSource::Heartbeat);
        assert!(
            job.keys_to_delete.is_empty(),
            "heartbeat signatures are window-pruned, not consumed from the gossip pool"
        );
    }

    #[test]
    fn fold_is_skipped_when_every_signer_is_already_covered() {
        // The common case: the subnet aggregate already covers the whole
        // committee, so there is nothing to fold and the existing type-1 is reused
        // unchanged.
        let job = resolve_fold_job(
            hashed(7),
            &buffered(&[0, 1]),
            &[child_proof(&[0, 1, 2])],
            &[],
            &validators(4),
        );
        assert!(job.is_none(), "B \\ A empty means no work");
    }

    #[test]
    fn fold_with_no_children_uses_raw_signatures_alone() {
        // A committee member whose data no aggregate covers still folds: raw-only
        // satisfies `aggregate_mixed`'s "at least one raw signature" precondition,
        // and the resulting entry is a real finality vote.
        let job = resolve_fold_job(hashed(7), &buffered(&[3]), &[], &[], &validators(4))
            .expect("raw-only fold is valid");
        assert!(job.children.is_empty());
        assert_eq!(job.raw_ids, vec![3]);
    }

    #[test]
    fn fold_skips_signers_outside_the_registry() {
        // A signature from an index the registry does not have cannot be resolved
        // to a pubkey; dropping it beats passing a short pubkey list to the prover.
        let job = resolve_fold_job(hashed(7), &buffered(&[1, 99]), &[], &[], &validators(4))
            .expect("validator 1 is resolvable");
        assert_eq!(job.raw_ids, vec![1]);
    }

    /// Distinguishable data for the same slot, so a committee split produces
    /// several buffered `data_root`s.
    fn split_data(slot: u64, target_marker: u8) -> AttestationData {
        AttestationData {
            slot,
            head: Checkpoint::default(),
            target: Checkpoint {
                root: H256([target_marker; 32]),
                slot,
            },
            source: Checkpoint::default(),
        }
    }

    #[test]
    fn snapshot_emits_one_job_for_the_thickest_committee_split() {
        use ethlambda_storage::backend::InMemoryBackend;
        use ethlambda_types::state::State;
        use std::sync::Arc;

        let state = State::from_genesis(1000, validators(8));
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), state);

        // A committee split: two signers on one data, three on another.
        let thin = split_data(7, 0xAA);
        let thick = split_data(7, 0xBB);
        for (vid, data) in [(0u64, &thin), (1, &thin)] {
            store.insert_heartbeat_vote(vid, data.clone());
            store.insert_heartbeat_signature(
                7,
                HashedAttestationData::new(data.clone()).root(),
                vid,
                dummy_sig(),
            );
        }
        for (vid, data) in [(2u64, &thick), (3, &thick), (4, &thick)] {
            store.insert_heartbeat_vote(vid, data.clone());
            store.insert_heartbeat_signature(
                7,
                HashedAttestationData::new(data.clone()).root(),
                vid,
                dummy_sig(),
            );
        }

        let snapshot = heartbeat_aggregation_snapshot(&store, 7).expect("a job is foldable");
        assert_eq!(snapshot.jobs.len(), 1, "exactly one job, always");
        assert_eq!(
            snapshot.jobs[0].raw_ids,
            vec![2, 3, 4],
            "the thickest committee coverage wins, matching Tier::Heartbeat's ordering"
        );
        assert_eq!(snapshot.groups_considered, 2);
    }

    #[test]
    fn snapshot_is_none_when_nothing_is_buffered() {
        use ethlambda_storage::backend::InMemoryBackend;
        use ethlambda_types::state::State;
        use std::sync::Arc;

        let state = State::from_genesis(1000, validators(8));
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), state);

        // No heartbeat signatures at all: the caller falls back to a subnet job.
        assert!(heartbeat_aggregation_snapshot(&store, 7).is_none());

        // A vote whose signature buffer entry is for a different slot is not
        // foldable at this slot either.
        store.insert_heartbeat_vote(0, split_data(6, 0xAA));
        assert!(heartbeat_aggregation_snapshot(&store, 7).is_none());
    }
}
