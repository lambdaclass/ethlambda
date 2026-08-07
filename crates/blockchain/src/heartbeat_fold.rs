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
//! **Raw signatures only: the fold never recurses into an existing type-1.** The
//! job it emits carries an empty `children` list, which degenerates the shared
//! `aggregate_mixed` call to a plain single-message aggregation over raw XMSS, and
//! its coverage is exactly the buffered signers it was handed. The cost is that
//! the fold cannot union its buffer with a partially-overlapping existing proof:
//! both become separate candidates for the same `AttestationData`, and the
//! builder's per-data pick (`keep_best_proof_per_data`) keeps whichever covers
//! more.
//!
//! The common case is still free. Honest committee members with the same view
//! produce byte-identical `AttestationData`, so when a single existing type-1
//! already covers every buffered signer the fold would only reproduce coverage the
//! block can already pack, and no job is emitted at all.

use std::collections::{BTreeMap, HashMap, HashSet};

use ethlambda_crypto::signature::{ValidatorPublicKey, ValidatorSignature};
use ethlambda_storage::Store;
use ethlambda_types::{
    ShortRoot,
    attestation::{AttestationData, HashedAttestationData},
    block::SingleMessageAggregate,
    primitives::H256,
    state::Validator,
};
use tracing::trace;

use crate::aggregation::{AggregationJob, AggregationSnapshot, JobSource};
use crate::metrics;

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
/// is buffered or because a single existing type-1 already covers every buffered
/// signer. The caller falls back to an ordinary subnet job in that case.
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
        // Cheap pre-check: with no existing proof for this data there is nothing
        // the fold could be dominated by, so skip the clone of every proof blob.
        let existing_proofs = if store.proof_count_for_data(data_root) == 0 {
            Vec::new()
        } else {
            let (new_proofs, known_proofs) = store.existing_proofs_for_data(data_root);
            new_proofs.into_iter().chain(known_proofs).collect()
        };
        if let Some(job) = resolve_fold_job(
            HashedAttestationData::new(data.clone()),
            sigs_by_validator,
            &existing_proofs,
            &validators,
        ) {
            trace!(
                %slot,
                data_root = %ShortRoot(&data_root.0),
                raw_count = job.raw_ids.len(),
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

/// Build one raw-only fold job, or `None` when there is nothing worth proving.
///
/// Every buffered signature the validator registry can resolve to a pubkey goes in
/// raw, in ascending validator order (XMSS aggregation requires it, which the
/// `BTreeMap` iteration order already gives us). `children` stays empty by
/// construction, so `aggregate_mixed`'s "at least one raw signature OR at least two
/// children" precondition reduces to "at least one resolvable signature" — the
/// exact condition under which a job is emitted.
///
/// A lone raw signature is still a job, unlike on the subnet path: a committee
/// vote can only enter a block as a type-1, so a 1-of-1 aggregate is the cheapest
/// form in which the proposer can pack it.
fn resolve_fold_job(
    hashed: HashedAttestationData,
    sigs_by_validator: &BTreeMap<u64, ValidatorSignature>,
    existing_proofs: &[SingleMessageAggregate],
    validators: &[Validator],
) -> Option<AggregationJob> {
    let mut raw_pubkeys = Vec::new();
    let mut raw_sigs = Vec::new();
    let mut raw_ids = Vec::new();
    for (validator_id, signature) in sigs_by_validator {
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

    if raw_ids.is_empty() {
        return None;
    }

    // A single existing type-1 covering every buffered signer already carries
    // everything a raw-only fold could produce, so proving it again buys the block
    // nothing. Dominance has to come from *one* proof: with proposer aggregation
    // off (the default) the builder keeps the single best-coverage proof per data
    // rather than merging them, so coverage spread across two proofs is not
    // coverage the block can pack.
    if is_dominated(&raw_ids, existing_proofs) {
        metrics::inc_heartbeat_fold_skipped();
        trace!(
            data_root = %ShortRoot(&hashed.root().0),
            raw_count = raw_ids.len(),
            "Heartbeat fold skipped: an existing type-1 already covers every buffered signer"
        );
        return None;
    }

    let slot = hashed.data().slot;
    Some(AggregationJob {
        hashed,
        slot,
        // Raw signatures only — see the module docs. Empty children make the
        // shared `aggregate_mixed` call a plain single-message aggregation.
        children: Vec::new(),
        accepted_child_ids: Vec::new(),
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

/// Whether some single existing type-1's participants are a superset of `raw_ids`.
fn is_dominated(raw_ids: &[u64], existing_proofs: &[SingleMessageAggregate]) -> bool {
    existing_proofs.iter().any(|proof| {
        let participants: HashSet<u64> = proof.participant_indices().collect();
        raw_ids.iter().all(|vid| participants.contains(vid))
    })
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

    /// An existing type-1 covering exactly `signers`.
    fn existing_proof(signers: &[usize]) -> SingleMessageAggregate {
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
    fn fold_keeps_every_buffered_signer_raw() {
        // An existing type-1 covers {0, 1} and the buffer holds {0, 1, 2}. The fold
        // does not recurse into it, so all three signatures go in raw and the
        // resulting aggregate covers exactly the buffer.
        let job = resolve_fold_job(
            hashed(7),
            &buffered(&[0, 1, 2]),
            &[existing_proof(&[0, 1])],
            &validators(4),
        )
        .expect("the existing proof does not cover 2, so the fold runs");

        assert_eq!(job.raw_ids, vec![0, 1, 2], "no signer is dropped");
        assert!(
            job.children.is_empty() && job.accepted_child_ids.is_empty(),
            "raw signatures only: no existing type-1 is recursed into"
        );
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
    fn fold_is_skipped_when_one_proof_covers_every_signer() {
        // The common case: a subnet aggregate for the same data already covers the
        // whole buffer, so a raw-only fold would only reproduce coverage the block
        // can already pack.
        let job = resolve_fold_job(
            hashed(7),
            &buffered(&[0, 1]),
            &[existing_proof(&[0, 1, 2])],
            &validators(4),
        );
        assert!(job.is_none(), "a dominating type-1 means no work");
    }

    #[test]
    fn fold_runs_when_coverage_is_split_across_proofs() {
        // Two proofs jointly cover {0, 1, 2}, but neither covers it alone. Their
        // union is only reachable by recursion, which the fold does not do, and the
        // builder keeps one proof per data rather than merging them — so the raw
        // fold is what gets the whole buffer into a single packable entry.
        let job = resolve_fold_job(
            hashed(7),
            &buffered(&[0, 1, 2]),
            &[existing_proof(&[0, 1]), existing_proof(&[2])],
            &validators(4),
        )
        .expect("no single proof dominates the buffer");
        assert_eq!(job.raw_ids, vec![0, 1, 2]);
        assert!(job.children.is_empty());
    }

    #[test]
    fn fold_with_no_existing_proof_aggregates_raw_signatures() {
        // A committee member whose data no aggregate covers still folds: a lone raw
        // signature satisfies `aggregate_mixed`'s "at least one raw signature"
        // precondition, and the resulting entry is a real finality vote.
        let job = resolve_fold_job(hashed(7), &buffered(&[3]), &[], &validators(4))
            .expect("raw-only fold is valid");
        assert!(job.children.is_empty());
        assert_eq!(job.raw_ids, vec![3]);
    }

    #[test]
    fn fold_skips_signers_outside_the_registry() {
        // A signature from an index the registry does not have cannot be resolved
        // to a pubkey; dropping it beats passing a short pubkey list to the prover.
        let job = resolve_fold_job(hashed(7), &buffered(&[1, 99]), &[], &validators(4))
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
