//! EIP-8453's ("Decoupled Consensus") two voting duties, which replace the
//! attestation and its aggregation at EIP-8453 slots (validator.md, "Head
//! voting" and "Attesting").
//!
//! # Head votes
//!
//! A member of a slot's head vote committee asks the node for the slot's
//! `HeadVoteData` at `HEAD_VOTE_DUE_BPS` of the slot, the head vote deadline
//! the node's fork choice computed `get_ac_vote_head` at. It records the slot
//! and the data before signing, and never signs a different head for a slot it
//! already signed one for ("the validator must record the selected root before
//! signing and must not sign another head for the same slot"): re-signing the
//! identical data after a failed submission is allowed, since it is the same
//! message. A validator holding several seats in a slot's committee casts one
//! vote. The record is in memory: a head vote is not slashable, and a second
//! head for a slot only makes the validator an equivocator the fork choice
//! discounts.
//!
//! # FG attestations
//!
//! An attester asks the node for the finality attestation input of its
//! committee's slot at `SUPPORT_CUTOFF_BPS` of it, the first instant the
//! node's `get_ac_frame` answers in a slot (the specification leaves the
//! deadline a TODO; the support cutoff is where the node's engine takes the
//! AC-to-FG observation, see `Eip8453Node::finality_attestation_input`). The
//! node serves the inputs (target, justified, finalized height), or `204`
//! when there is no FG source. The selection is this client's: each key's
//! [`crate::finality_record::FinalitySigningRecords`] entry picks the data,
//! records it and writes it to disk before anything is signed. The signature
//! is under `DOMAIN_FINALITY_ATTESTER` at the epoch of the assigned slot.
//!
//! # Aggregation
//!
//! Neither duty has an aggregation half: the specification's aggregate topics
//! and aggregator selection are TODOs, and a node joins every attestation
//! subnet instead (see `docs/spec_deviations.md`).

use std::collections::HashMap;
use std::sync::Arc;

use ethlambda_decoupled::FinalityAttestationInput;
use ethlambda_types::beacon::containers::eip8453;
use ethlambda_types::beacon::primitives::{BlsPubkey, Slot};
use ethlambda_types::beacon::signing::compute_epoch_at_slot;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::beacon_node::BeaconNodeApi;
use crate::beacon_node::dto::{AttestationCommitteeDutyDto, HeadVoteDutyDto, parse_pubkey};
use crate::error::{Error, Result};
use crate::finality_record::FinalitySigningRecords;
use crate::keys::ValidatorStore;
use crate::signing::SigningContext;

/// How many slots of head vote history are kept per key. One slot is ever
/// owed; the margin absorbs a clock that steps back a little.
const HEAD_VOTE_HISTORY_SLOTS: Slot = 64;

/// Which head each key signed for each recent slot.
#[derive(Debug, Default)]
struct HeadVoteRecord {
    signed: HashMap<BlsPubkey, Vec<(Slot, eip8453::HeadVoteData)>>,
}

impl HeadVoteRecord {
    /// Record that `pubkey` signs `data` for its slot. `false` when it already
    /// signed another head for that slot.
    fn record(&mut self, pubkey: BlsPubkey, data: eip8453::HeadVoteData) -> bool {
        let slot = data.slot;
        let signed = self.signed.entry(pubkey).or_default();
        signed.retain(|(held, _)| held + HEAD_VOTE_HISTORY_SLOTS > slot);
        match signed.iter().find(|(held, _)| *held == slot) {
            Some((_, held)) => *held == data,
            None => {
                signed.push((slot, data));
                true
            }
        }
    }
}

/// The head vote duty.
pub struct HeadVoteService<B> {
    beacon_node: Arc<B>,
    context: Arc<SigningContext>,
    /// A `std::sync::Mutex` for the reason the other guards are: the
    /// critical section has no await in it.
    record: std::sync::Mutex<HeadVoteRecord>,
}

impl<B: BeaconNodeApi> HeadVoteService<B> {
    pub fn new(beacon_node: Arc<B>, context: Arc<SigningContext>) -> Self {
        Self {
            beacon_node,
            context,
            record: std::sync::Mutex::new(HeadVoteRecord::default()),
        }
    }

    /// Sign and submit one head vote for `slot` per validator whose duty
    /// names it. Returns how many the node accepted.
    pub async fn vote(
        &self,
        slot: Slot,
        duties: &[HeadVoteDutyDto],
        store: &RwLock<ValidatorStore>,
    ) -> Result<usize> {
        let voters: Vec<&HeadVoteDutyDto> = duties
            .iter()
            .filter(|duty| duty.slots.contains(&slot))
            .collect();
        if voters.is_empty() {
            return Ok(0);
        }
        let data = self.beacon_node.head_vote_data(slot).await?;
        // Checked again here, as every signable fetch is: the trait is public,
        // and this is the last point before the data becomes a signature.
        if data.slot != slot {
            return Err(Error::InconsistentResponse(format!(
                "requested head vote data for slot {slot}, node answered for slot {}",
                data.slot
            )));
        }

        let mut messages = Vec::with_capacity(voters.len());
        {
            let _timing = crate::metrics::time_signing();
            let store = store.read().await;
            for duty in voters {
                let pubkey = match parse_pubkey(&duty.pubkey) {
                    Ok(pubkey) => pubkey,
                    Err(err) => {
                        error!(%slot, validator = duty.validator_index, %err, "Duty carried an unreadable pubkey");
                        continue;
                    }
                };
                // Recorded before signing, so a signature that exists is one
                // the record knows about.
                let recorded = match self.record.lock() {
                    Ok(mut record) => record.record(pubkey, data),
                    Err(_) => {
                        error!(%slot, "Head vote record is poisoned; refusing to sign");
                        false
                    }
                };
                if !recorded {
                    warn!(
                        %slot,
                        validator = duty.validator_index,
                        "Refusing to sign a second head for a slot already voted in"
                    );
                    continue;
                }
                match self.context.sign_head_vote(&store, &pubkey, &data) {
                    Ok(signature) => messages.push(eip8453::HeadVoteMessage {
                        validator_index: duty.validator_index,
                        data,
                        signature,
                    }),
                    Err(err) => {
                        error!(%slot, validator = duty.validator_index, %err, "Failed to sign head vote");
                        crate::metrics::inc_signing_failures();
                    }
                }
            }
        }
        if messages.is_empty() {
            return Ok(0);
        }
        let submitted = messages.len();
        let published = self.beacon_node.submit_head_votes(&messages).await?;
        if published < submitted {
            warn!(
                %slot,
                published,
                submitted,
                "Some head votes in this slot's batch were rejected by the beacon node"
            );
        }
        info!(
            %slot,
            count = published,
            head = %hex::encode(&data.beacon_block_root.0[..4]),
            payload_status = data.payload_status,
            "Published head votes"
        );
        crate::metrics::inc_head_votes_published(published as u64);
        Ok(published)
    }
}

/// The FG attestation duty.
pub struct FgAttestationService<B> {
    beacon_node: Arc<B>,
    context: Arc<SigningContext>,
    records: Arc<FinalitySigningRecords>,
}

impl<B: BeaconNodeApi> FgAttestationService<B> {
    pub fn new(
        beacon_node: Arc<B>,
        context: Arc<SigningContext>,
        records: Arc<FinalitySigningRecords>,
    ) -> Self {
        Self {
            beacon_node,
            context,
            records,
        }
    }

    /// Select, record, sign and submit the FG attestations of the validators
    /// whose committee attests at `slot`. Returns how many the node accepted:
    /// zero when the node has no FG source or every record suppressed its
    /// vote.
    ///
    /// # Do not retry this call within a slot
    ///
    /// The records are written before signing, so a retry selects again from
    /// records that already name this slot's entry and is suppressed; the
    /// attestations of an abandoned call are lost rather than re-signed.
    pub async fn attest(
        &self,
        slot: Slot,
        duties: &[AttestationCommitteeDutyDto],
        store: &RwLock<ValidatorStore>,
    ) -> Result<usize> {
        let attesters: Vec<&AttestationCommitteeDutyDto> = duties
            .iter()
            .filter(|duty| duty.slots.contains(&slot))
            .collect();
        if attesters.is_empty() {
            return Ok(0);
        }
        let Some(input) = self.beacon_node.finality_attestation_input(slot).await? else {
            info!(%slot, "No FG source at the support cutoff; not attesting");
            return Ok(0);
        };
        let input = FinalityAttestationInput {
            target: input.target.into(),
            justified: input.justified.into(),
            finalized_height: input.finalized_height,
        };
        let epoch = compute_epoch_at_slot(slot);

        let mut attestations = Vec::with_capacity(attesters.len());
        for duty in attesters {
            let pubkey = match parse_pubkey(&duty.pubkey) {
                Ok(pubkey) => pubkey,
                Err(err) => {
                    error!(%slot, validator = duty.validator_index, %err, "Duty carried an unreadable pubkey");
                    continue;
                }
            };
            // A key the store no longer holds (removed through the
            // keymanager) must not touch its record.
            if !store.read().await.contains(&pubkey) {
                continue;
            }
            // Selected, recorded and on disk before anything is signed.
            let data = match self.records.attest(&pubkey, &input).await {
                Ok(Some(data)) => data,
                Ok(None) => {
                    info!(
                        %slot,
                        validator = duty.validator_index,
                        target_height = input.target.height,
                        "The finality signing record suppresses this attestation"
                    );
                    crate::metrics::inc_fg_attestations_suppressed();
                    continue;
                }
                Err(err) => {
                    error!(%slot, validator = duty.validator_index, %err, "Cannot record the FG attestation; not signing it");
                    crate::metrics::inc_signing_failures();
                    continue;
                }
            };
            let signed = {
                let _timing = crate::metrics::time_signing();
                let store = store.read().await;
                self.context
                    .sign_fg_attestation(&store, &pubkey, &data, epoch)
            };
            match signed {
                Ok(signature) => attestations.push(eip8453::SingleAttestation {
                    committee_index: duty.committee_index,
                    attester_index: duty.validator_index,
                    data,
                    signature,
                    epoch,
                }),
                Err(err) => {
                    error!(%slot, validator = duty.validator_index, %err, "Failed to sign FG attestation");
                    crate::metrics::inc_signing_failures();
                }
            }
        }
        if attestations.is_empty() {
            return Ok(0);
        }
        let submitted = attestations.len();
        let published = self
            .beacon_node
            .submit_fg_attestations(&attestations)
            .await?;
        if published < submitted {
            warn!(
                %slot,
                published,
                submitted,
                "Some FG attestations in this slot's batch were rejected by the beacon node"
            );
        }
        info!(
            %slot,
            count = published,
            target_height = input.target.height,
            "Published FG attestations"
        );
        crate::metrics::inc_fg_attestations_published(published as u64);
        Ok(published)
    }
}

#[cfg(test)]
mod tests;
