//! Sync committee duties: signing the head each slot, and aggregating.
//!
//! # What is owed
//!
//! A member of the current sync committee signs the head block root once per
//! slot (`SyncCommitteeMessage`), at the sync-message deadline. The 512 seats
//! are split into four subcommittees; within each, a few members are selected
//! by a hash of their selection proof to fold the subcommittee's messages into
//! a `SyncCommitteeContribution` and publish it, which is how the messages
//! reach a block cheaply.
//!
//! # Which slot, and which root
//!
//! The message carries the wall slot and the head root at the deadline, which
//! may be an older block when slots were skipped. A member assigned to wall
//! slot `S` signs for `S - 1`; the caller picks the duties accordingly (see
//! [`crate::duties::DutiesService::sync_at_slot`]).
//!
//! # Optimistic heads
//!
//! The optimistic-sync specification forbids signing `DOMAIN_SYNC_COMMITTEE`
//! over an optimistic head, so [`BeaconNodeApi::head_block_root`] fails with
//! `BeaconNodeSyncing` for one, and nothing is signed.
//!
//! # Duplicates
//!
//! Not slashable. The slot is recorded per validator at signing time only so a
//! retried call does not publish the same message twice. In memory only.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use ethlambda_types::beacon::constants::{
    SYNC_COMMITTEE_SUBNET_COUNT, TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE,
};
use ethlambda_types::beacon::containers::altair::{
    ContributionAndProof, SYNC_SUBCOMMITTEE_SIZE, SignedContributionAndProof,
    SyncCommitteeContribution, SyncCommitteeMessage,
};
use ethlambda_types::beacon::primitives::{BlsPubkey, BlsSignature, Root, Slot, ValidatorIndex};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::beacon_node::dto::{SyncDutyDto, parse_pubkey};
use crate::beacon_node::{BeaconNodeApi, validate_sync_contribution};
use crate::error::{Error, Result};
use crate::keys::ValidatorStore;
use crate::signing::SigningContext;

/// How many slots of dedup history are kept.
const HISTORY_SLOTS: u64 = 64;

/// The specification's `is_sync_committee_aggregator`: the first eight bytes of
/// the selection proof's SHA-256, little-endian, divide evenly by
/// `max(1, SYNC_SUBCOMMITTEE_SIZE / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE)`.
pub fn is_sync_committee_aggregator(selection_proof: &BlsSignature) -> bool {
    let modulo = (SYNC_SUBCOMMITTEE_SIZE as u64 / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE).max(1);
    let digest = Sha256::digest(selection_proof.0);
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(head) % modulo == 0
}

/// The subnets a duty's seats fall in: `seat / SYNC_SUBCOMMITTEE_SIZE`. A seat
/// beyond the committee is dropped with a warning, since no subnet carries it.
pub fn subnets_of(duty: &SyncDutyDto) -> BTreeSet<u64> {
    duty.validator_sync_committee_indices
        .iter()
        .filter_map(|seat| {
            let subnet = seat / SYNC_SUBCOMMITTEE_SIZE as u64;
            if subnet < SYNC_COMMITTEE_SUBNET_COUNT as u64 {
                Some(subnet)
            } else {
                warn!(
                    validator = duty.validator_index,
                    seat, "Sync committee seat is outside the committee; ignoring it"
                );
                None
            }
        })
        .collect()
}

pub struct SyncCommitteeService<B> {
    beacon_node: Arc<B>,
    context: Arc<SigningContext>,
    /// Which (validator, slot) pairs already produced a message signature.
    done: std::sync::Mutex<HashSet<(ValidatorIndex, Slot)>>,
}

impl<B: BeaconNodeApi> SyncCommitteeService<B> {
    pub fn new(beacon_node: Arc<B>, context: Arc<SigningContext>) -> Self {
        Self {
            beacon_node,
            context,
            done: std::sync::Mutex::new(HashSet::new()),
        }
    }

    /// Sign and submit this client's sync committee messages for `slot`.
    ///
    /// Returns the root signed over, so the aggregation that follows asks for
    /// contributions on the same one. `None` when there is nothing to do: no
    /// pending duty, or a head that is optimistic.
    pub async fn publish_messages(
        &self,
        slot: Slot,
        duties: &[SyncDutyDto],
        store: &RwLock<ValidatorStore>,
    ) -> Result<Option<Root>> {
        let pending: Vec<&SyncDutyDto> = {
            let done = self.lock();
            duties
                .iter()
                .filter(|duty| !done.contains(&(duty.validator_index, slot)))
                .collect()
        };
        if pending.is_empty() {
            return Ok(None);
        }

        let root = match self.beacon_node.head_block_root().await {
            Ok(root) => root,
            Err(Error::BeaconNodeSyncing) => {
                warn!(%slot, "Head is optimistic or the node is syncing; not signing sync committee messages");
                return Ok(None);
            }
            Err(err) => return Err(err),
        };

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
                if !self.record(duty.validator_index, slot) {
                    continue;
                }
                match self
                    .context
                    .sign_sync_committee_message(&store, &pubkey, slot, root)
                {
                    Ok(signature) => messages.push(SyncCommitteeMessage {
                        slot,
                        beacon_block_root: root,
                        validator_index: duty.validator_index,
                        signature,
                    }),
                    Err(err) => {
                        error!(%slot, validator = duty.validator_index, %err, "Failed to sign sync committee message");
                        crate::metrics::inc_signing_failures();
                    }
                }
            }
        }
        if messages.is_empty() {
            return Ok(None);
        }

        let submitted = messages.len();
        let published = self
            .beacon_node
            .submit_sync_committee_messages(&messages)
            .await?;
        if published < submitted {
            warn!(%slot, published, submitted, "Some sync committee messages in this slot's batch were rejected");
        }
        info!(%slot, count = published, "Published sync committee messages");
        crate::metrics::inc_sync_committee_messages_published(published as u64);
        Ok(Some(root))
    }

    /// Publish the contributions this client was selected to aggregate for
    /// `slot` over `beacon_block_root`. Returns how many were published.
    ///
    /// One request per subnet, shared by every selected validator in it. A
    /// subnet whose request fails is skipped with a warning so the others still
    /// go out.
    pub async fn aggregate(
        &self,
        slot: Slot,
        beacon_block_root: Root,
        duties: &[SyncDutyDto],
        store: &RwLock<ValidatorStore>,
    ) -> Result<usize> {
        // (validator, pubkey, subnet, selection proof) for each selected pair.
        let mut selected: Vec<(ValidatorIndex, BlsPubkey, u64, BlsSignature)> = Vec::new();
        {
            let store = store.read().await;
            for duty in duties {
                let pubkey = match parse_pubkey(&duty.pubkey) {
                    Ok(pubkey) => pubkey,
                    Err(err) => {
                        error!(%slot, validator = duty.validator_index, %err, "Duty carried an unreadable pubkey");
                        continue;
                    }
                };
                for subnet in subnets_of(duty) {
                    match self
                        .context
                        .sign_sync_selection_proof(&store, &pubkey, slot, subnet)
                    {
                        Ok(proof) if is_sync_committee_aggregator(&proof) => {
                            selected.push((duty.validator_index, pubkey, subnet, proof));
                        }
                        Ok(_) => {}
                        Err(err) => {
                            error!(%slot, validator = duty.validator_index, %err, "Failed to sign sync selection proof");
                            crate::metrics::inc_signing_failures();
                        }
                    }
                }
            }
        }
        if selected.is_empty() {
            return Ok(0);
        }

        let mut fetched: HashMap<u64, Option<SyncCommitteeContribution>> = HashMap::new();
        for (_, _, subnet, _) in &selected {
            if fetched.contains_key(subnet) {
                continue;
            }
            let answer = match self
                .beacon_node
                .sync_committee_contribution(slot, *subnet, beacon_block_root)
                .await
            {
                // Checked again, as the attestation duty does: the trait is
                // public and this is the last point before a signature.
                Ok(contribution) => {
                    match validate_sync_contribution(
                        slot,
                        *subnet,
                        beacon_block_root,
                        &contribution,
                    ) {
                        Ok(()) => Some(contribution),
                        Err(err) => {
                            warn!(%slot, subnet, %err, "Discarding a mismatched sync contribution");
                            None
                        }
                    }
                }
                Err(err) => {
                    warn!(%slot, subnet, %err, "No sync contribution for this subnet; skipping it");
                    None
                }
            };
            fetched.insert(*subnet, answer);
        }

        let mut signed = Vec::new();
        {
            let store = store.read().await;
            for (validator, pubkey, subnet, proof) in selected {
                let Some(Some(contribution)) = fetched.get(&subnet) else {
                    continue;
                };
                let message = ContributionAndProof {
                    aggregator_index: validator,
                    contribution: contribution.clone(),
                    selection_proof: proof,
                };
                match self
                    .context
                    .sign_contribution_and_proof(&store, &pubkey, &message)
                {
                    Ok(signature) => signed.push(SignedContributionAndProof { message, signature }),
                    Err(err) => {
                        error!(%slot, validator, %err, "Failed to sign contribution and proof");
                        crate::metrics::inc_signing_failures();
                    }
                }
            }
        }
        if signed.is_empty() {
            return Ok(0);
        }

        self.beacon_node
            .publish_contribution_and_proofs(&signed)
            .await?;
        info!(%slot, count = signed.len(), "Published sync committee contributions");
        crate::metrics::inc_sync_contributions_published(signed.len() as u64);
        Ok(signed.len())
    }

    fn record(&self, validator: ValidatorIndex, slot: Slot) -> bool {
        let Ok(mut done) = self.done.lock() else {
            error!(%slot, "Sync committee record is poisoned; refusing to sign");
            return false;
        };
        done.retain(|(_, held)| held + HISTORY_SLOTS > slot);
        done.insert((validator, slot))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashSet<(ValidatorIndex, Slot)>> {
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
    use ethlambda_types::beacon::config::Config;

    const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

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

    fn duty(pubkey: &BlsPubkey, validator_index: u64, seats: Vec<u64>) -> SyncDutyDto {
        SyncDutyDto {
            pubkey: encode_hex(&pubkey.0),
            validator_index,
            validator_sync_committee_indices: seats,
        }
    }

    fn verify(pubkey: &BlsPubkey, signature: &BlsSignature, root: Root) -> bool {
        use blst::min_pk::{PublicKey, Signature};
        let pk = PublicKey::from_bytes(&pubkey.0).expect("valid pubkey");
        let sig = Signature::from_bytes(&signature.0).expect("valid signature");
        sig.verify(true, root.as_slice(), DST, &[], &pk, true) == blst::BLST_ERROR::BLST_SUCCESS
    }

    fn contribution(slot: Slot, root: Root, subnet: u64) -> SyncCommitteeContribution {
        SyncCommitteeContribution {
            slot,
            beacon_block_root: root,
            subcommittee_index: subnet,
            aggregation_bits: Default::default(),
            signature: BlsSignature([1; 96]),
        }
    }

    /// A signature hashing to a multiple of the modulus, or to a non-multiple.
    fn found(selected: bool) -> BlsSignature {
        let modulo =
            (SYNC_SUBCOMMITTEE_SIZE as u64 / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE).max(1);
        for seed in 0u32..100_000 {
            let mut bytes = [0u8; 96];
            bytes[..4].copy_from_slice(&seed.to_le_bytes());
            let digest = Sha256::digest(bytes);
            let mut head = [0u8; 8];
            head.copy_from_slice(&digest[..8]);
            if (u64::from_le_bytes(head) % modulo == 0) == selected {
                return BlsSignature(bytes);
            }
        }
        panic!("no signature found");
    }

    #[test]
    fn selection_reads_the_digest_little_endian_with_the_specs_modulus() {
        assert!(is_sync_committee_aggregator(&found(true)));
        assert!(!is_sync_committee_aggregator(&found(false)));
    }

    #[test]
    fn seats_map_to_subnets_and_stray_ones_are_dropped() {
        let (_, pubkey) = store();
        let size = SYNC_SUBCOMMITTEE_SIZE as u64;
        let subnets = subnets_of(&duty(
            &pubkey,
            1,
            vec![0, 1, size, 3 * size + 5, 4 * size, 10_000],
        ));
        assert_eq!(subnets, BTreeSet::from([0, 1, 3]));
    }

    #[tokio::test]
    async fn one_message_per_duty_is_signed_over_the_head_root_and_deduplicated() {
        let root = Root::repeat_byte(7);
        let node = Arc::new(MockBeaconNode::new().with_head_root(root));
        let (store, pubkey) = store();
        let context = context();
        let service = SyncCommitteeService::new(node.clone(), context.clone());
        let duties = vec![duty(&pubkey, 1, vec![3, 130]), duty(&pubkey, 2, vec![9])];

        let signed_over = service
            .publish_messages(3200, &duties, &store)
            .await
            .expect("publishes");
        assert_eq!(signed_over, Some(root));

        let sent = node.submitted_sync_messages();
        assert_eq!(sent.len(), 2, "one per validator, however many seats");
        for message in &sent {
            assert_eq!(message.slot, 3200);
            assert_eq!(message.beacon_block_root, root);
            assert!(verify(
                &pubkey,
                &message.signature,
                context.sync_committee_message_signing_root(3200, root)
            ));
        }

        let again = service
            .publish_messages(3200, &duties, &store)
            .await
            .expect("second call");
        assert_eq!(again, None);
        assert_eq!(node.submitted_sync_messages().len(), 2, "no duplicates");
    }

    #[tokio::test]
    async fn an_optimistic_head_signs_nothing() {
        let mut node = MockBeaconNode::new().with_head_root(Root::repeat_byte(7));
        node.head_optimistic = true;
        let node = Arc::new(node);
        let (store, pubkey) = store();
        let service = SyncCommitteeService::new(node.clone(), context());

        let result = service
            .publish_messages(3200, &[duty(&pubkey, 1, vec![3])], &store)
            .await
            .expect("not an error");
        assert_eq!(result, None);
        assert!(node.submitted_sync_messages().is_empty());
    }

    /// Duty with a seat in every subnet, on the first slot where the selection
    /// is a mix, so "only selected pairs fetch" is not satisfied by all or none.
    fn mixed_slot(context: &SigningContext, store: &ValidatorStore, pubkey: &BlsPubkey) -> Slot {
        for slot in 3200..4200 {
            let picks = (0..4)
                .filter(|subnet| {
                    let proof = context
                        .sign_sync_selection_proof(store, pubkey, slot, *subnet)
                        .expect("signs");
                    is_sync_committee_aggregator(&proof)
                })
                .count();
            if picks > 0 && picks < 4 {
                return slot;
            }
        }
        panic!("no mixed slot found");
    }

    fn all_subnet_duty(pubkey: &BlsPubkey) -> SyncDutyDto {
        let size = SYNC_SUBCOMMITTEE_SIZE as u64;
        duty(pubkey, 9, vec![0, size, 2 * size, 3 * size])
    }

    #[tokio::test]
    async fn only_selected_pairs_fetch_and_a_published_contribution_verifies() {
        let (store, pubkey) = store();
        let context = context();
        let slot = {
            let guard = store.read().await;
            mixed_slot(&context, &guard, &pubkey)
        };
        let root = Root::repeat_byte(4);
        let mut node = MockBeaconNode::new();
        for subnet in 0..4 {
            node = node.with_contribution(contribution(slot, root, subnet));
        }
        let node = Arc::new(node);
        let service = SyncCommitteeService::new(node.clone(), context.clone());

        let published = service
            .aggregate(slot, root, &[all_subnet_duty(&pubkey)], &store)
            .await
            .expect("aggregates");

        let guard = store.read().await;
        let expected: Vec<u64> = (0..4)
            .filter(|subnet| {
                let proof = context
                    .sign_sync_selection_proof(&guard, &pubkey, slot, *subnet)
                    .expect("signs");
                is_sync_committee_aggregator(&proof)
            })
            .collect();
        let requested: Vec<u64> = node
            .contribution_requests()
            .iter()
            .map(|(_, subnet, _)| *subnet)
            .collect();
        assert_eq!(requested, expected, "only selected subnets are asked");
        assert_eq!(published, expected.len());

        let sent = node.published_contributions();
        assert_eq!(sent.len(), expected.len());
        for signed in &sent {
            assert!(verify(
                &pubkey,
                &signed.signature,
                context.contribution_and_proof_signing_root(&signed.message)
            ));
            assert!(verify(
                &pubkey,
                &signed.message.selection_proof,
                context.sync_selection_proof_signing_root(
                    slot,
                    signed.message.contribution.subcommittee_index
                )
            ));
        }
    }

    #[tokio::test]
    async fn a_mismatched_contribution_is_not_published() {
        let (store, pubkey) = store();
        let context = context();
        let slot = {
            let guard = store.read().await;
            mixed_slot(&context, &guard, &pubkey)
        };
        let root = Root::repeat_byte(4);
        let mut node = MockBeaconNode::new();
        for subnet in 0..4 {
            // Every answer is about another root.
            node = node.with_contribution(contribution(slot, Root::repeat_byte(5), subnet));
        }
        let node = Arc::new(node);
        let service = SyncCommitteeService::new(node.clone(), context);

        let published = service
            .aggregate(slot, root, &[all_subnet_duty(&pubkey)], &store)
            .await
            .expect("not an error");
        assert_eq!(published, 0);
        assert!(node.published_contributions().is_empty());
    }

    #[tokio::test]
    async fn a_missing_contribution_on_one_subnet_does_not_stop_another() {
        let (store, pubkey) = store();
        let context = context();
        // A slot where at least two subnets are selected.
        let (slot, picked) = {
            let guard = store.read().await;
            (3200..6000)
                .find_map(|slot| {
                    let picked: Vec<u64> = (0..4)
                        .filter(|subnet| {
                            let proof = context
                                .sign_sync_selection_proof(&guard, &pubkey, slot, *subnet)
                                .expect("signs");
                            is_sync_committee_aggregator(&proof)
                        })
                        .collect();
                    (picked.len() >= 2).then_some((slot, picked))
                })
                .expect("a slot selecting two subnets")
        };
        let root = Root::repeat_byte(4);
        // Only the last picked subnet has a contribution; the first answers 404.
        let kept = *picked.last().expect("nonempty");
        let node =
            Arc::new(MockBeaconNode::new().with_contribution(contribution(slot, root, kept)));
        let service = SyncCommitteeService::new(node.clone(), context);

        let published = service
            .aggregate(slot, root, &[all_subnet_duty(&pubkey)], &store)
            .await
            .expect("aggregates");
        assert_eq!(published, 1);
        assert_eq!(
            node.published_contributions()[0]
                .message
                .contribution
                .subcommittee_index,
            kept
        );
    }
}
