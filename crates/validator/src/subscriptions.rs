//! Telling the beacon node which attestation subnets to find peers on.
//!
//! Without this the beacon node has no reason to be on the subnet an
//! attestation is published to, and the attestation reaches nobody. The
//! specification also makes this the signal by which a node learns which
//! validators are attached to it, which is why one entry is sent per validator
//! per duty even when several share a committee.

use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::aggregation_selection::selection_for;
use crate::beacon_node::BeaconNodeApi;
use crate::beacon_node::dto::{AttesterDutyDto, CommitteeSubscriptionDto};
use crate::error::Result;
use crate::keys::ValidatorStore;
use crate::signing::SigningContext;

/// Send one subscription per held duty, claiming the aggregator role for the
/// duties this client was selected for.
///
/// `is_aggregator` is not a preference. It is the answer
/// [`crate::aggregation_selection`] computes from a signature over the slot,
/// and the beacon node checks the same thing when the aggregate arrives, so
/// there is nothing here to decide. What the flag does is tell the node to keep
/// the subnet subscribed for the whole slot and collect the votes this client
/// will ask it to fold, which is why it has to be sent ahead of time rather
/// than discovered when the aggregation duty runs.
///
/// A duty whose selection cannot be computed is sent with the flag clear rather
/// than dropped. The subscription is what puts the beacon node on the subnet at
/// all, so losing it would cost that validator its plain attestation as well as
/// its aggregate.
pub async fn subscribe<B: BeaconNodeApi>(
    beacon_node: &Arc<B>,
    duties: &[AttesterDutyDto],
    store: &RwLock<ValidatorStore>,
    context: &SigningContext,
) -> Result<()> {
    if duties.is_empty() {
        return Ok(());
    }

    // The read guard is scoped to this block and never held across the await
    // below, for the reason spelled out in `crate::attestation`: the lock is
    // write-preferring, so one queued keymanager writer blocks every reader
    // behind it.
    let subscriptions: Vec<CommitteeSubscriptionDto> = {
        let store = store.read().await;
        duties
            .iter()
            .map(|duty| {
                let is_aggregator = match selection_for(context, &store, duty) {
                    Ok(selection) => selection.is_some(),
                    Err(err) => {
                        warn!(
                            slot = duty.slot,
                            validator = duty.validator_index,
                            %err,
                            "Could not compute aggregator selection; subscribing without the role"
                        );
                        false
                    }
                };
                CommitteeSubscriptionDto {
                    validator_index: duty.validator_index,
                    committee_index: duty.committee_index,
                    committees_at_slot: duty.committees_at_slot,
                    slot: duty.slot,
                    is_aggregator,
                }
            })
            .collect()
    };

    let aggregating = subscriptions
        .iter()
        .filter(|entry| entry.is_aggregator)
        .count();
    info!(
        count = subscriptions.len(),
        aggregating, "Subscribing to attestation subnets"
    );
    beacon_node.subscribe_committees(&subscriptions).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregation_selection::is_aggregator;
    use crate::beacon_node::dto::encode_hex;
    use crate::beacon_node::mock::MockBeaconNode;
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::primitives::{BlsPubkey, Root};

    fn secret() -> [u8; 32] {
        hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("valid hex")
            .try_into()
            .expect("32 bytes")
    }

    fn context() -> SigningContext {
        SigningContext {
            config: Config::mainnet(),
            genesis_validators_root: Root::ZERO,
        }
    }

    fn store() -> (RwLock<ValidatorStore>, BlsPubkey) {
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        (RwLock::new(store), pubkey)
    }

    fn duty(
        pubkey: &BlsPubkey,
        validator_index: u64,
        slot: u64,
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

    #[tokio::test]
    async fn one_subscription_is_sent_per_duty() {
        let node = Arc::new(MockBeaconNode::new());
        let (store, pubkey) = store();
        let duties = vec![
            duty(&pubkey, 1, 96, 2),
            duty(&pubkey, 2, 96, 2),
            duty(&pubkey, 3, 97, 5),
        ];
        subscribe(&node, &duties, &store, &context())
            .await
            .expect("subscribes");

        let sent = node.subscriptions();
        assert_eq!(
            sent.len(),
            3,
            "validators sharing a committee must not be deduplicated"
        );
        assert_eq!(sent[0].validator_index, 1);
        assert_eq!(sent[2].slot, 97);
    }

    #[tokio::test]
    async fn nothing_is_sent_when_there_are_no_duties() {
        let node = Arc::new(MockBeaconNode::new());
        let (store, _) = store();
        subscribe(&node, &[], &store, &context())
            .await
            .expect("no-op");
        assert!(node.subscriptions().is_empty());
    }

    /// The flag must be the selection rule's answer, not a constant either way.
    /// Asserted against the rule itself rather than against a hardcoded
    /// expectation, since which slots select this key is a property of SHA-256
    /// that would be meaningless to write down.
    #[tokio::test]
    async fn the_aggregator_flag_is_the_selection_rules_answer() {
        let node = Arc::new(MockBeaconNode::new());
        let (store, pubkey) = store();
        let context = context();

        let duties: Vec<AttesterDutyDto> =
            (96..128).map(|slot| duty(&pubkey, 1, slot, 2)).collect();
        subscribe(&node, &duties, &store, &context)
            .await
            .expect("subscribes");

        let guard = store.read().await;
        for (duty, sent) in duties.iter().zip(node.subscriptions()) {
            let proof = context
                .sign_selection_proof(&guard, &pubkey, duty.slot)
                .expect("signs");
            assert_eq!(
                sent.is_aggregator,
                is_aggregator(duty.committee_length, &proof),
                "slot {} disagreed with the selection rule",
                duty.slot
            );
        }
    }

    /// Over a full epoch of slots the flag must be set for some and clear for
    /// others. Without this, a bug that always answered one way would satisfy
    /// the test above, which only checks agreement with the same computation.
    #[tokio::test]
    async fn the_role_is_claimed_for_some_slots_and_not_others() {
        let node = Arc::new(MockBeaconNode::new());
        let (store, pubkey) = store();

        let duties: Vec<AttesterDutyDto> = (0..64).map(|slot| duty(&pubkey, 1, slot, 2)).collect();
        subscribe(&node, &duties, &store, &context())
            .await
            .expect("subscribes");

        let claimed = node
            .subscriptions()
            .iter()
            .filter(|entry| entry.is_aggregator)
            .count();
        assert!(
            claimed > 0 && claimed < duties.len(),
            "expected a mix over 64 slots, got {claimed}"
        );
    }

    /// A duty this client cannot sign for still has to be subscribed. The
    /// subscription is what puts the beacon node on the subnet, so dropping it
    /// would cost that validator its plain attestation too.
    #[tokio::test]
    async fn a_duty_for_an_unknown_validator_is_still_subscribed_without_the_role() {
        let node = Arc::new(MockBeaconNode::new());
        let (store, _) = store();
        let stranger = BlsPubkey([9; 48]);

        subscribe(&node, &[duty(&stranger, 1, 96, 2)], &store, &context())
            .await
            .expect("subscribes");

        let sent = node.subscriptions();
        assert_eq!(sent.len(), 1, "the subscription must still be sent");
        assert!(!sent[0].is_aggregator);
    }
}
