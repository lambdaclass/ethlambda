//! Folding a committee's votes into one aggregate and publishing it.
//!
//! # What this client does and does not build
//!
//! It does not build the aggregate. The beacon node does, out of the votes it
//! collected on the subnet this client subscribed to, and hands back the best
//! one it has. What this client contributes is the wrapper: which of its
//! validators is publishing, the proof that validator was selected, and a
//! signature over both.
//!
//! That division matters for electra. A gossiped aggregate must cover exactly
//! one committee, even though the container widened to allow more; the
//! multi-committee form exists only on chain, assembled by a block proposer out
//! of several single-committee aggregates. Since this client never constructs
//! an aggregate, it cannot get that wrong.
//!
//! # Why the attestation data comes from the caller
//!
//! The aggregate asked for is the one covering the votes *this client's
//! validators cast*, which means the attestation data they actually signed.
//! Re-fetching it here would ask the beacon node again, and if the head moved
//! in between the answer would be different data, whose aggregate contains none
//! of this client's votes. So the attestation duty hands its data forward, and
//! a slot whose attestation failed is a slot with nothing to aggregate.
//!
//! # None of this is slashable
//!
//! Unlike every other duty here, aggregation signs nothing that can cost stake.
//! The aggregate's own signature belongs to the attesters and was produced by
//! somebody else; the selection proof commits to a slot, not a chain position;
//! and the wrapper signature says only "I collected these". Publishing two
//! different aggregates for one slot is wasteful, not punishable, which is why
//! there is no guard in this module.

use std::collections::BTreeMap;
use std::sync::Arc;

use ethlambda_types::beacon::containers::electra::{AggregateAndProof, SignedAggregateAndProof};
use ethlambda_types::beacon::containers::shared::AttestationData;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{HashTreeRoot as _, Slot};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::aggregation_selection::selection_for;
use crate::beacon_node::BeaconNodeApi;
use crate::beacon_node::dto::{AttesterDutyDto, parse_pubkey};
use crate::error::{Error, Result};
use crate::keys::ValidatorStore;
use crate::signing::SigningContext;

pub struct AggregationService<B> {
    beacon_node: Arc<B>,
    context: Arc<SigningContext>,
}

impl<B: BeaconNodeApi> AggregationService<B> {
    pub fn new(beacon_node: Arc<B>, context: Arc<SigningContext>) -> Self {
        Self {
            beacon_node,
            context,
        }
    }

    /// Publish an aggregate for every duty at `slot` this client was selected
    /// for.
    ///
    /// `data` must be what this slot's attestations were signed over. See the
    /// module doc for why it is not re-fetched.
    ///
    /// Returns how many aggregates were published, which is zero whenever none
    /// of this client's validators was selected. That is the ordinary case: a
    /// validator aggregates a few times a day.
    pub async fn aggregate(
        &self,
        slot: Slot,
        data: &AttestationData,
        duties: &[AttesterDutyDto],
        store: &RwLock<ValidatorStore>,
    ) -> Result<usize> {
        if duties.is_empty() {
            return Ok(0);
        }

        // Which of this client's validators aggregates, and with what proof.
        //
        // The read guard covers the whole selection pass and no await, the way
        // the attestation path's does: `selection_for` signs, and the lock is
        // write-preferring, so holding this across the fetches below would put
        // every later duty behind any keymanager writer that queued meanwhile.
        let selected: Vec<(AttesterDutyDto, _)> = {
            let store = store.read().await;
            duties
                .iter()
                .filter_map(|duty| match selection_for(&self.context, &store, duty) {
                    Ok(Some(proof)) => Some((duty.clone(), proof)),
                    Ok(None) => None,
                    Err(err) => {
                        warn!(
                            %slot,
                            validator = duty.validator_index,
                            %err,
                            "Could not compute aggregator selection; skipping this duty"
                        );
                        None
                    }
                })
                .collect()
        };

        if selected.is_empty() {
            return Ok(0);
        }

        // One fetch per committee, not per validator. Two of this client's
        // validators can be selected for the same committee, and they publish
        // one wrapper each around the identical aggregate; asking the node
        // twice for it would be the same answer at twice the cost.
        let data_root = data.hash_tree_root();
        let mut aggregates = BTreeMap::new();
        for (duty, _) in &selected {
            if aggregates.contains_key(&duty.committee_index) {
                continue;
            }
            match self
                .beacon_node
                .aggregate_attestation(slot, data_root, duty.committee_index)
                .await
            {
                Ok(aggregate) => {
                    aggregates.insert(duty.committee_index, aggregate);
                }
                // Not an error for the slot. A node with nothing to fold
                // answers 404, which the specification treats as an ordinary
                // outcome, and one committee's missing aggregate must not stop
                // another committee's from going out.
                Err(err) => warn!(
                    %slot,
                    committee = duty.committee_index,
                    %err,
                    "No aggregate available for this committee"
                ),
            }
        }

        if aggregates.is_empty() {
            return Ok(0);
        }

        // Every aggregate in this batch must share one fork, since the batch
        // goes out under a single header. They came from one slot, so a
        // disagreement means the nodes behind failover disagree about where a
        // fork boundary sits.
        let fork = self.batch_fork(&aggregates, slot)?;

        let signed = {
            let store = store.read().await;
            let mut signed = Vec::with_capacity(selected.len());
            for (duty, selection_proof) in &selected {
                let Some(aggregate) = aggregates.get(&duty.committee_index) else {
                    continue;
                };
                let pubkey = match parse_pubkey(&duty.pubkey) {
                    Ok(pubkey) => pubkey,
                    Err(err) => {
                        warn!(%slot, validator = duty.validator_index, %err, "Duty carried an unreadable pubkey");
                        continue;
                    }
                };

                let message = AggregateAndProof {
                    aggregator_index: duty.validator_index,
                    aggregate: aggregate.attestation.clone(),
                    selection_proof: *selection_proof,
                };
                // Signed over the whole wrapper, not over the aggregate: that
                // is what binds this validator's index and its selection proof
                // to the votes it is republishing.
                let root = message.hash_tree_root();
                let signature = match self
                    .context
                    .sign_aggregate_and_proof(&store, &pubkey, root, slot)
                {
                    Ok(signature) => signature,
                    Err(err) => {
                        warn!(%slot, validator = duty.validator_index, %err, "Failed to sign aggregate");
                        continue;
                    }
                };
                signed.push(SignedAggregateAndProof { message, signature });
            }
            signed
        };

        if signed.is_empty() {
            return Ok(0);
        }

        let count = signed.len();
        self.beacon_node.publish_aggregates(fork, &signed).await?;
        info!(%slot, count, fork = fork.as_str(), "Published aggregates");
        crate::metrics::inc_aggregates_published(count as u64);
        Ok(count)
    }

    /// The one fork every aggregate in this batch was produced under.
    ///
    /// Split out so the disagreement case has somewhere to be explained. The
    /// batch is published under a single `Eth-Consensus-Version`, so a batch
    /// spanning two forks could not be announced truthfully; with failover in
    /// play the aggregates can come from different nodes, which is the only way
    /// that happens.
    fn batch_fork(
        &self,
        aggregates: &BTreeMap<u64, crate::beacon_node::AggregateAttestation>,
        slot: Slot,
    ) -> Result<ForkName> {
        let mut forks = aggregates.values().map(|aggregate| aggregate.fork);
        let first = forks.next().expect("the caller checked for emptiness");
        if let Some(other) = forks.find(|fork| *fork != first) {
            return Err(Error::InconsistentResponse(format!(
                "aggregates for slot {slot} came back as both {} and {}; they cannot be \
                 published under one consensus version",
                first.as_str(),
                other.as_str()
            )));
        }
        Ok(first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregation_selection::is_aggregator;
    use crate::beacon_node::dto::encode_hex;
    use crate::beacon_node::mock::MockBeaconNode;
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::shared::Checkpoint;
    use ethlambda_types::beacon::primitives::{BlsPubkey, Root};

    fn secret() -> [u8; 32] {
        hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("valid hex")
            .try_into()
            .expect("32 bytes")
    }

    fn context() -> Arc<SigningContext> {
        Arc::new(SigningContext {
            config: Config::mainnet(),
            genesis_validators_root: Root::ZERO,
        })
    }

    fn store() -> (RwLock<ValidatorStore>, BlsPubkey) {
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        (RwLock::new(store), pubkey)
    }

    fn data(slot: Slot) -> AttestationData {
        AttestationData {
            slot,
            index: 0,
            beacon_block_root: Root::repeat_byte(7),
            source: Checkpoint {
                epoch: slot / 32 - 1,
                root: Root::ZERO,
            },
            target: Checkpoint {
                epoch: slot / 32,
                root: Root::ZERO,
            },
        }
    }

    fn duty(
        pubkey: &BlsPubkey,
        validator_index: u64,
        slot: Slot,
        committee_index: u64,
    ) -> AttesterDutyDto {
        AttesterDutyDto {
            pubkey: encode_hex(&pubkey.0),
            validator_index,
            committee_index,
            committee_length: 128,
            committees_at_slot: 64,
            validator_committee_index: 7,
            slot,
        }
    }

    /// A slot this key is selected to aggregate at, and one it is not. Which
    /// slots those are is a property of SHA-256, so they are found rather than
    /// written down.
    fn slots(pubkey: &BlsPubkey, store: &ValidatorStore) -> (Slot, Slot) {
        let context = context();
        let mut selected = None;
        let mut rejected = None;
        for slot in 3_200..3_400 {
            let proof = context
                .sign_selection_proof(store, pubkey, slot)
                .expect("signs");
            if is_aggregator(128, &proof) {
                selected.get_or_insert(slot);
            } else {
                rejected.get_or_insert(slot);
            }
            if selected.is_some() && rejected.is_some() {
                break;
            }
        }
        (
            selected.expect("some slot selects this key"),
            rejected.expect("some slot does not"),
        )
    }

    async fn fixture() -> (RwLock<ValidatorStore>, BlsPubkey, Slot, Slot) {
        let (store, pubkey) = store();
        let (selected, rejected) = {
            let guard = store.read().await;
            slots(&pubkey, &guard)
        };
        (store, pubkey, selected, rejected)
    }

    #[tokio::test]
    async fn a_selected_validator_publishes_one_aggregate() {
        let (store, pubkey, slot, _) = fixture().await;
        let node = Arc::new(MockBeaconNode::new().with_aggregate(data(slot)));
        let service = AggregationService::new(node.clone(), context());

        let published = service
            .aggregate(slot, &data(slot), &[duty(&pubkey, 1, slot, 2)], &store)
            .await
            .expect("aggregates");

        assert_eq!(published, 1);
        assert_eq!(node.published_aggregates().len(), 1);
    }

    /// Nothing is asked of the beacon node when this client was not selected.
    /// That is the ordinary case, and it must cost nothing.
    #[tokio::test]
    async fn an_unselected_validator_asks_the_node_for_nothing() {
        let (store, pubkey, _, slot) = fixture().await;
        let node = Arc::new(MockBeaconNode::new().with_aggregate(data(slot)));
        let service = AggregationService::new(node.clone(), context());

        let published = service
            .aggregate(slot, &data(slot), &[duty(&pubkey, 1, slot, 2)], &store)
            .await
            .expect("no-op");

        assert_eq!(published, 0);
        assert!(node.aggregate_requests().is_empty());
        assert!(node.published_aggregates().is_empty());
    }

    /// The aggregate asked for must be keyed on the data this client's
    /// validators actually signed. Asking for anything else fetches an
    /// aggregate containing none of their votes.
    #[tokio::test]
    async fn the_aggregate_is_requested_for_the_signed_datas_root() {
        let (store, pubkey, slot, _) = fixture().await;
        let node = Arc::new(MockBeaconNode::new().with_aggregate(data(slot)));

        AggregationService::new(node.clone(), context())
            .aggregate(slot, &data(slot), &[duty(&pubkey, 1, slot, 5)], &store)
            .await
            .expect("aggregates");

        let asked = node.aggregate_requests();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].0, slot);
        assert_eq!(asked[0].1, data(slot).hash_tree_root());
        assert_eq!(asked[0].2, 5, "the committee index must be passed through");
    }

    /// Two validators selected for one committee share a fetch and publish one
    /// wrapper each.
    #[tokio::test]
    async fn two_validators_in_one_committee_share_a_single_fetch() {
        let (store, pubkey, slot, _) = fixture().await;
        let node = Arc::new(MockBeaconNode::new().with_aggregate(data(slot)));
        let duties = vec![duty(&pubkey, 1, slot, 2), duty(&pubkey, 2, slot, 2)];

        let published = AggregationService::new(node.clone(), context())
            .aggregate(slot, &data(slot), &duties, &store)
            .await
            .expect("aggregates");

        assert_eq!(published, 2, "one wrapper per selected validator");
        assert_eq!(
            node.aggregate_requests().len(),
            1,
            "but only one fetch, since it is the same aggregate"
        );
    }

    /// The signature covers the whole wrapper, which is what binds the
    /// aggregator's index and its selection proof to the votes it republishes.
    #[tokio::test]
    async fn the_published_signature_covers_the_whole_wrapper() {
        use blst::min_pk::{PublicKey, Signature};

        let (store, pubkey, slot, _) = fixture().await;
        let node = Arc::new(MockBeaconNode::new().with_aggregate(data(slot)));

        AggregationService::new(node.clone(), context())
            .aggregate(slot, &data(slot), &[duty(&pubkey, 1, slot, 2)], &store)
            .await
            .expect("aggregates");

        let (fork, list) = node.published_aggregates().remove(0);
        assert_eq!(fork, ForkName::Electra);
        let entry = &list[0];
        assert_eq!(entry.message.aggregator_index, 1);

        let root = context().aggregate_and_proof_signing_root(entry.message.hash_tree_root(), slot);
        let pk = PublicKey::from_bytes(&pubkey.0).expect("valid pubkey");
        let sig = Signature::from_bytes(&entry.signature.0).expect("valid signature");
        assert_eq!(
            sig.verify(
                true,
                root.as_slice(),
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
                &[],
                &pk,
                true
            ),
            blst::BLST_ERROR::BLST_SUCCESS
        );
    }

    /// The selection proof published must be the same signature the selection
    /// was decided by. A beacon node re-derives the decision from it, so a
    /// different one would be rejected.
    #[tokio::test]
    async fn the_published_proof_is_the_one_selection_was_decided_by() {
        let (store, pubkey, slot, _) = fixture().await;
        let node = Arc::new(MockBeaconNode::new().with_aggregate(data(slot)));

        AggregationService::new(node.clone(), context())
            .aggregate(slot, &data(slot), &[duty(&pubkey, 1, slot, 2)], &store)
            .await
            .expect("aggregates");

        let (_, list) = node.published_aggregates().remove(0);

        let guard = store.read().await;
        let expected = context()
            .sign_selection_proof(&guard, &pubkey, slot)
            .expect("signs");
        assert_eq!(list[0].message.selection_proof, expected);
        assert!(
            is_aggregator(128, &list[0].message.selection_proof),
            "the published proof must be one that actually selects"
        );
    }

    /// A node with nothing to fold answers 404, which the specification treats
    /// as ordinary. One committee's missing aggregate must not stop another's.
    #[tokio::test]
    async fn a_committee_with_no_aggregate_does_not_stop_the_others() {
        let (store, pubkey, slot, _) = fixture().await;
        let node = Arc::new(MockBeaconNode::new()); // no aggregate set: every fetch 404s
        let service = AggregationService::new(node.clone(), context());

        let published = service
            .aggregate(slot, &data(slot), &[duty(&pubkey, 1, slot, 2)], &store)
            .await
            .expect("a missing aggregate is not an error for the slot");

        assert_eq!(published, 0);
        assert!(node.published_aggregates().is_empty());
    }

    #[tokio::test]
    async fn no_duties_means_no_work() {
        let (store, _, slot, _) = fixture().await;
        let node = Arc::new(MockBeaconNode::new().with_aggregate(data(slot)));

        let published = AggregationService::new(node.clone(), context())
            .aggregate(slot, &data(slot), &[], &store)
            .await
            .expect("no-op");
        assert_eq!(published, 0);
        assert!(node.aggregate_requests().is_empty());
    }
}
