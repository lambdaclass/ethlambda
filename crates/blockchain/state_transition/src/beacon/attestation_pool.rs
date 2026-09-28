//! Unaggregated attestations, held until an aggregator asks for them.
//!
//! What `GET /eth/v2/validator/aggregate_attestation` answers from: phase0's
//! `validator.md` ("Aggregation selection" onward) has an aggregator collect
//! the attestations its committee gossiped for the slot and combine every one
//! sharing its own `AttestationData` into a single `Attestation`.
//!
//! Only attestations that already passed gossip validation go in (the Beacon
//! API's pool endpoint, or `beacon_attestation_{subnet_id}`'s verdict), since
//! that is what makes combining their signatures safe: one bad share would
//! make the whole aggregate fail verification for every peer that receives it.
//! The caller also supplies the attester's committee position and the
//! committee's length, which it has from the same validation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ethlambda_types::{
    beacon::{
        containers::{
            electra::{AggregationBits, Attestation, CommitteeBits, SingleAttestation},
            shared::AttestationData,
        },
        preset,
        primitives::{BlsSignature, CommitteeIndex, Root, Slot},
    },
    primitives::HashTreeRoot as _,
};

use super::bls;

/// The pool, shared between whatever fills it (the Beacon API's pool endpoint,
/// the attestation subnet handler) and the aggregate endpoint that reads it.
pub type SharedAttestationPool = Arc<Mutex<AttestationPool>>;

/// One committee's votes on one `AttestationData`.
#[derive(Debug)]
struct Votes {
    data: AttestationData,
    /// One slot per committee member, by committee position.
    signatures: Vec<Option<BlsSignature>>,
}

#[derive(Debug, Default)]
pub struct AttestationPool {
    /// Keyed by the data's root and the committee, which is exactly what an
    /// aggregate request names.
    votes: HashMap<(Root, CommitteeIndex), Votes>,
    /// Single-committee aggregates this node has validated (the ones its
    /// validator clients published through it), the best-covered per data
    /// and committee. Block production packs from these as well as from
    /// `votes`.
    aggregates: HashMap<(Root, CommitteeIndex), Attestation>,
}

impl AttestationPool {
    /// Record a validated attestation, and drop everything more than an epoch
    /// older than it: an aggregate is requested in the slot its votes were
    /// cast, so older votes can no longer be asked for.
    ///
    /// A second attestation from the same committee position keeps the first,
    /// the same way gossip keeps the first valid attestation per validator.
    pub fn insert(
        &mut self,
        attestation: &SingleAttestation,
        committee_position: usize,
        committee_len: usize,
    ) {
        self.prune_before(attestation.data.slot);

        let key = (
            attestation.data.hash_tree_root(),
            attestation.committee_index,
        );
        let votes = self.votes.entry(key).or_insert_with(|| Votes {
            data: attestation.data,
            signatures: vec![None; committee_len],
        });
        if let Some(position @ None) = votes.signatures.get_mut(committee_position) {
            *position = Some(attestation.signature);
        }
    }

    /// Record a validated single-committee aggregate, keeping whichever of it
    /// and the one already held for its data and committee covers more
    /// members. An aggregate naming other than exactly one committee is
    /// ignored: this pool's unit is one committee.
    pub fn insert_aggregate(&mut self, aggregate: Attestation) {
        let Some(committee_index) = single_committee(&aggregate) else {
            return;
        };
        self.prune_before(aggregate.data.slot);
        let key = (aggregate.data.hash_tree_root(), committee_index);
        let better = self
            .aggregates
            .get(&key)
            .is_none_or(|held| set_bits(&aggregate) > set_bits(held));
        if better {
            self.aggregates.insert(key, aggregate);
        }
    }

    /// The best single-committee aggregate held for every data and
    /// committee, for block production to pack: whichever of the aggregate
    /// built from the pooled votes and a recorded aggregate covers more.
    pub fn block_candidates(&self) -> Vec<Attestation> {
        let keys: std::collections::HashSet<_> = self
            .votes
            .keys()
            .chain(self.aggregates.keys())
            .copied()
            .collect();
        keys.into_iter()
            .filter_map(|(data_root, committee_index)| {
                let from_votes = self
                    .votes
                    .get(&(data_root, committee_index))
                    .and_then(|votes| self.aggregate(data_root, votes.data.slot, committee_index));
                let recorded = self.aggregates.get(&(data_root, committee_index)).cloned();
                match (from_votes, recorded) {
                    (Some(a), Some(b)) => Some(if set_bits(&a) >= set_bits(&b) { a } else { b }),
                    (a, b) => a.or(b),
                }
            })
            .collect()
    }

    /// Drop everything more than an epoch older than `slot`.
    fn prune_before(&mut self, slot: Slot) {
        self.votes
            .retain(|_, votes| votes.data.slot + preset::SLOTS_PER_EPOCH > slot);
        self.aggregates
            .retain(|_, aggregate| aggregate.data.slot + preset::SLOTS_PER_EPOCH > slot);
    }

    /// Every vote held for `data_root` from `committee_index`'s committee,
    /// aggregated into electra's `Attestation`: one bit per committee member,
    /// the one committee named in `committee_bits`, and the BLS aggregate of
    /// the members' signatures.
    ///
    /// `None` if nothing is held for that data and committee, or if the data
    /// is not for `slot`, which the endpoint also names.
    pub fn aggregate(
        &self,
        data_root: Root,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Option<Attestation> {
        let votes = self.votes.get(&(data_root, committee_index))?;
        if votes.data.slot != slot {
            return None;
        }

        let mut aggregation_bits = AggregationBits::with_length(votes.signatures.len()).ok()?;
        let mut signatures = Vec::new();
        for (position, signature) in votes.signatures.iter().enumerate() {
            if let Some(signature) = signature {
                aggregation_bits.set(position, true).ok()?;
                signatures.push(*signature);
            }
        }
        let mut committee_bits = CommitteeBits::default();
        committee_bits.set(committee_index as usize, true).ok()?;

        Some(Attestation {
            aggregation_bits,
            data: votes.data,
            signature: bls::aggregate(&signatures).ok()?,
            committee_bits,
        })
    }
}

/// The one committee a single-committee attestation names, `None` if it names
/// none or several.
pub(crate) fn single_committee(attestation: &Attestation) -> Option<CommitteeIndex> {
    let mut named = (0..preset::MAX_COMMITTEES_PER_SLOT)
        .filter(|&index| attestation.committee_bits.get(index).unwrap_or(false));
    let first = named.next()?;
    named.next().is_none().then_some(first as CommitteeIndex)
}

fn set_bits(attestation: &Attestation) -> usize {
    (0..attestation.aggregation_bits.len())
        .filter(|&i| attestation.aggregation_bits.get(i).unwrap_or(false))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::helpers::test_state::sign_for;
    use ethlambda_types::beacon::containers::shared::Checkpoint;

    fn data(slot: Slot) -> AttestationData {
        AttestationData {
            slot,
            index: 0,
            beacon_block_root: Root::repeat_byte(1),
            source: Checkpoint::default(),
            target: Checkpoint {
                epoch: 0,
                root: Root::repeat_byte(2),
            },
        }
    }

    fn vote(slot: Slot, committee_index: u64, validator: u64) -> SingleAttestation {
        let data = data(slot);
        SingleAttestation {
            committee_index,
            attester_index: validator,
            signature: sign_for(validator as usize, data.hash_tree_root()),
            data,
        }
    }

    #[test]
    fn the_aggregate_carries_every_member_seen_and_their_combined_signature() {
        let mut pool = AttestationPool::default();
        let (first, second) = (vote(5, 2, 10), vote(5, 2, 11));
        pool.insert(&first, 0, 4);
        pool.insert(&second, 3, 4);

        let aggregate = pool.aggregate(data(5).hash_tree_root(), 5, 2).unwrap();
        let bits: Vec<bool> = (0..4)
            .map(|i| aggregate.aggregation_bits.get(i).unwrap())
            .collect();
        assert_eq!(bits, [true, false, false, true]);
        assert!(aggregate.committee_bits.get(2).unwrap());
        assert!(!aggregate.committee_bits.get(0).unwrap());
        let expected = bls::aggregate(&[first.signature, second.signature]).unwrap();
        assert_eq!(aggregate.signature, expected);
    }

    #[test]
    fn a_repeated_position_keeps_the_first_signature() {
        let mut pool = AttestationPool::default();
        let first = vote(5, 0, 10);
        let mut repeat = vote(5, 0, 10);
        repeat.signature = vote(5, 0, 11).signature;
        pool.insert(&first, 1, 2);
        pool.insert(&repeat, 1, 2);

        let aggregate = pool.aggregate(data(5).hash_tree_root(), 5, 0).unwrap();
        assert_eq!(
            aggregate.signature,
            bls::aggregate(&[first.signature]).unwrap()
        );
    }

    #[test]
    fn nothing_is_answered_for_another_committee_slot_or_data() {
        let mut pool = AttestationPool::default();
        pool.insert(&vote(5, 0, 10), 0, 2);
        assert!(pool.aggregate(data(5).hash_tree_root(), 5, 1).is_none());
        assert!(pool.aggregate(data(5).hash_tree_root(), 6, 0).is_none());
        assert!(pool.aggregate(data(6).hash_tree_root(), 5, 0).is_none());
    }

    #[test]
    fn block_candidates_take_the_better_of_votes_and_a_recorded_aggregate() {
        let mut pool = AttestationPool::default();
        pool.insert(&vote(5, 0, 10), 0, 3);
        // A recorded aggregate for the same committee covering two members
        // beats the one pooled vote.
        let mut recorded = pool.aggregate(data(5).hash_tree_root(), 5, 0).unwrap();
        recorded.aggregation_bits.set(1, true).unwrap();
        pool.insert_aggregate(recorded.clone());
        // A second committee has only votes.
        pool.insert(&vote(5, 1, 11), 0, 2);

        let mut candidates = pool.block_candidates();
        candidates.sort_by_key(single_committee);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0], recorded);
        assert_eq!(single_committee(&candidates[1]), Some(1));
    }

    #[test]
    fn votes_an_epoch_old_are_dropped() {
        let mut pool = AttestationPool::default();
        pool.insert(&vote(5, 0, 10), 0, 2);
        pool.insert(&vote(5 + preset::SLOTS_PER_EPOCH, 0, 11), 0, 2);
        assert!(pool.aggregate(data(5).hash_tree_root(), 5, 0).is_none());
    }
}
