//! Voting on whether a slot's payload arrived: the payload timeliness
//! committee (PTC) duty that gloas adds.
//!
//! A small committee is drawn each slot, and its members attest to two facts
//! about the block they saw: whether the builder revealed the payload on time
//! (`payload_present`) and whether the blob data was available
//! (`blob_data_available`). The beacon node assembles those facts from its own
//! view, so this client does not judge them: it asks for the data, checks it is
//! about the right slot, signs it and submits it, which is the same division of
//! labour the attestation duty has.
//!
//! # Timing
//!
//! Due at `PAYLOAD_ATTESTATION_DUE_BPS` of the slot, three quarters of the way
//! in, which is when the node's view of the payload is as complete as it will
//! be. See [`crate::slot_clock::SlotClock::until_payload_attestation`].
//!
//! # No block, no vote
//!
//! A node that knows no block for the slot answers 204. That is not an error
//! and not a vote against the payload: there is nothing to attest to, so
//! nothing is signed. Voting `payload_present = false` for a block this client
//! never saw would be a claim about a block it cannot name.
//!
//! # Duplicates
//!
//! The specification attaches no slashing condition to a PTC vote, but a second,
//! different vote from one member for one slot is equivocation the network
//! penalises in gossip. So the slot is recorded per validator at signing time,
//! the way the attestation guard records, and a duty abandoned between signing
//! and submission is lost rather than re-signed. In memory only: this is not
//! slashing protection, and does not pretend to be.

use std::collections::HashSet;
use std::sync::Arc;

use ethlambda_types::beacon::containers::gloas::PayloadAttestationMessage;
use ethlambda_types::beacon::primitives::{Slot, ValidatorIndex};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::beacon_node::BeaconNodeApi;
use crate::beacon_node::dto::{PtcDutyDto, parse_pubkey};
use crate::error::Result;
use crate::keys::ValidatorStore;
use crate::signing::SigningContext;

/// How many slots of dedup history are kept. Far more than the one slot a duty
/// is ever owed for; the margin only absorbs a clock that steps back a little.
const HISTORY_SLOTS: u64 = 64;

pub struct PayloadAttestationService<B> {
    beacon_node: Arc<B>,
    context: Arc<SigningContext>,
    /// Which (validator, slot) pairs already produced a signature.
    ///
    /// A `std::sync::Mutex` for the reason the attestation service's guard is:
    /// the critical section is a lookup and an insert with no await inside it.
    done: std::sync::Mutex<HashSet<(ValidatorIndex, Slot)>>,
}

impl<B: BeaconNodeApi> PayloadAttestationService<B> {
    pub fn new(beacon_node: Arc<B>, context: Arc<SigningContext>) -> Self {
        Self {
            beacon_node,
            context,
            done: std::sync::Mutex::new(HashSet::new()),
        }
    }

    /// Sign and submit this client's committee votes for `slot`.
    ///
    /// Returns how many votes the node accepted: zero when the node has no
    /// block for the slot, or when every member was already served.
    ///
    /// # Do not retry this call within a slot
    ///
    /// For the reason the attestation duty's is not retried: a second call
    /// fetches the data again, and a head that moved in between would give a
    /// different vote from the same member. The dedup refuses it, so a retry is
    /// merely useless, but callers should not rely on it.
    pub async fn attest(
        &self,
        slot: Slot,
        duties: &[PtcDutyDto],
        store: &RwLock<ValidatorStore>,
    ) -> Result<usize> {
        if duties.is_empty() {
            return Ok(0);
        }

        // Cheap pre-check, so a slot already served costs the node no request.
        let pending: Vec<&PtcDutyDto> = {
            let done = self.lock();
            duties
                .iter()
                .filter(|duty| !done.contains(&(duty.validator_index, slot)))
                .collect()
        };
        if pending.is_empty() {
            return Ok(0);
        }

        let Some(data) = self.beacon_node.payload_attestation_data(slot).await? else {
            info!(%slot, "No block known for this slot; not voting on its payload");
            return Ok(0);
        };

        // Checked again here, having already been checked by the
        // implementation (see `BeaconNodeApi::payload_attestation_data`), for
        // the reason the attestation duty does: the trait is public, and this
        // is the last point before the data becomes a signature.
        if data.slot != slot {
            return Err(crate::error::Error::InconsistentResponse(format!(
                "requested payload attestation data for slot {slot}, node answered for slot {}",
                data.slot
            )));
        }

        let mut messages = Vec::with_capacity(pending.len());
        {
            let _timing = crate::metrics::time_signing();
            let store = store.read().await;
            for duty in pending {
                let pubkey = match parse_pubkey(&duty.pubkey) {
                    Ok(pubkey) => pubkey,
                    Err(err) => {
                        error!(%slot, validator = duty.validator_index, %err, "Duty carried an unreadable pubkey");
                        continue;
                    }
                };

                // Recorded before signing, so a signature that exists is one
                // the record already knows about.
                if !self.record(duty.validator_index, slot) {
                    continue;
                }

                match self
                    .context
                    .sign_payload_attestation(&store, &pubkey, &data)
                {
                    Ok(signature) => messages.push(PayloadAttestationMessage {
                        validator_index: duty.validator_index,
                        data,
                        signature,
                    }),
                    Err(err) => {
                        error!(%slot, validator = duty.validator_index, %err, "Failed to sign payload attestation");
                        crate::metrics::inc_signing_failures();
                    }
                }
            }
        }

        if messages.is_empty() {
            return Ok(0);
        }

        let submitted = messages.len();
        let published = self
            .beacon_node
            .submit_payload_attestations(&messages)
            .await?;
        if published < submitted {
            warn!(
                %slot,
                published,
                submitted,
                "Some payload attestations in this slot's batch were rejected by the beacon node"
            );
        }
        info!(
            %slot,
            count = published,
            payload_present = data.payload_present,
            blob_data_available = data.blob_data_available,
            "Published payload attestations"
        );
        crate::metrics::inc_payload_attestations_published(published as u64);
        Ok(published)
    }

    /// Record that `validator` is being served for `slot`. `false` when it
    /// already was, or when the record is unusable, which is treated as a
    /// refusal for the reason the other guards' poisoned locks are.
    fn record(&self, validator: ValidatorIndex, slot: Slot) -> bool {
        let Ok(mut done) = self.done.lock() else {
            error!(%slot, "Payload attestation record is poisoned; refusing to sign");
            return false;
        };
        done.retain(|(_, held)| held + HISTORY_SLOTS > slot);
        done.insert((validator, slot))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashSet<(ValidatorIndex, Slot)>> {
        // A poisoned set is still a set: the worst a panic mid-insert could
        // leave is a missing entry, and the signing path re-checks through
        // `record`, which refuses on poison.
        self.done
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_node::dto::encode_hex;
    use crate::beacon_node::mock::MockBeaconNode;
    use crate::error::Error;
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::gloas::PayloadAttestationData;
    use ethlambda_types::beacon::fork::ForkName;
    use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
    use ethlambda_types::beacon::primitives::{BlsPubkey, Root};

    const GLOAS_EPOCH: u64 = 10;

    fn secret() -> [u8; 32] {
        hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("valid hex")
            .try_into()
            .expect("32 bytes")
    }

    fn context() -> Arc<SigningContext> {
        Arc::new(SigningContext {
            config: Config::mainnet().with_fork_epoch(ForkName::Gloas, GLOAS_EPOCH),
            genesis_validators_root: Root::ZERO,
        })
    }

    fn store() -> (RwLock<ValidatorStore>, BlsPubkey) {
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        (RwLock::new(store), pubkey)
    }

    fn slot() -> Slot {
        GLOAS_EPOCH * SLOTS_PER_EPOCH + 4
    }

    fn data(slot: Slot) -> PayloadAttestationData {
        PayloadAttestationData {
            beacon_block_root: Root::repeat_byte(5),
            slot,
            payload_present: true,
            blob_data_available: false,
        }
    }

    fn duty(pubkey: &BlsPubkey, validator_index: u64, slot: Slot) -> PtcDutyDto {
        PtcDutyDto {
            pubkey: encode_hex(&pubkey.0),
            validator_index,
            slot,
        }
    }

    #[tokio::test]
    async fn a_committee_member_signs_and_submits_the_nodes_data() {
        use blst::min_pk::{PublicKey, Signature};

        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_payload_attestation_data(data(slot())));
        let service = PayloadAttestationService::new(node.clone(), context());

        let published = service
            .attest(slot(), &[duty(&pubkey, 9, slot())], &store)
            .await
            .expect("attests");
        assert_eq!(published, 1);

        let messages = node.submitted_payload_attestations();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].validator_index, 9);
        assert_eq!(messages[0].data, data(slot()));

        // Over the data's root alone, under the PTC domain at the data's epoch.
        let root = context().payload_attestation_signing_root(&messages[0].data);
        let pk = PublicKey::from_bytes(&pubkey.0).expect("valid pubkey");
        let sig = Signature::from_bytes(&messages[0].signature.0).expect("valid signature");
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

    /// A 204 is an ordinary answer: nothing is signed and nothing fails.
    #[tokio::test]
    async fn no_block_for_the_slot_means_no_vote() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new());
        let service = PayloadAttestationService::new(node.clone(), context());

        let published = service
            .attest(slot(), &[duty(&pubkey, 9, slot())], &store)
            .await
            .expect("a 204 is not an error");
        assert_eq!(published, 0);
        assert_eq!(node.payload_attestation_data_call_count(), 1);
        assert!(node.submitted_payload_attestations().is_empty());
    }

    /// One vote per (validator, slot): the second call neither asks the node
    /// nor signs again.
    #[tokio::test]
    async fn a_member_is_served_once_per_slot() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_payload_attestation_data(data(slot())));
        let service = PayloadAttestationService::new(node.clone(), context());
        let duties = [duty(&pubkey, 9, slot())];

        service
            .attest(slot(), &duties, &store)
            .await
            .expect("first");
        let again = service
            .attest(slot(), &duties, &store)
            .await
            .expect("second");

        assert_eq!(again, 0);
        assert_eq!(node.submitted_payload_attestations().len(), 1);
        assert_eq!(node.payload_attestation_data_call_count(), 1);
    }

    /// A new slot is a new vote, and a second member of the same slot is
    /// served even after the first.
    #[tokio::test]
    async fn dedup_is_per_validator_and_per_slot() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_payload_attestation_data(data(slot())));
        let service = PayloadAttestationService::new(node.clone(), context());

        service
            .attest(slot(), &[duty(&pubkey, 9, slot())], &store)
            .await
            .expect("first member");
        service
            .attest(slot(), &[duty(&pubkey, 10, slot())], &store)
            .await
            .expect("second member");
        assert_eq!(node.submitted_payload_attestations().len(), 2);
    }

    /// Data about another slot is never signed.
    #[tokio::test]
    async fn data_for_another_slot_is_rejected() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_payload_attestation_data(data(slot() - 1)));
        let service = PayloadAttestationService::new(node.clone(), context());

        let err = service
            .attest(slot(), &[duty(&pubkey, 9, slot())], &store)
            .await
            .expect_err("must reject");
        assert!(matches!(err, Error::InconsistentResponse(_)), "got {err:?}");
        assert!(node.submitted_payload_attestations().is_empty());
    }

    #[tokio::test]
    async fn no_duties_asks_the_node_for_nothing() {
        let (store, _) = store();
        let node = Arc::new(MockBeaconNode::new().with_payload_attestation_data(data(slot())));
        let service = PayloadAttestationService::new(node.clone(), context());

        assert_eq!(service.attest(slot(), &[], &store).await.expect("no-op"), 0);
        assert_eq!(node.payload_attestation_data_call_count(), 0);
    }
}
