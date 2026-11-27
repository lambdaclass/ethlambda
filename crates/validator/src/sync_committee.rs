//! Sync committee duties: signing the head each slot, and aggregating.
//!
//! # What is owed
//!
//! A member of the current sync committee signs the head block root once per
//! slot (`SyncCommitteeMessage`), when the slot's block arrives or at the
//! sync-message deadline, whichever comes first (see
//! [`crate::head_monitor`]). The 512 seats
//! are split into four subcommittees; within each, a few members are selected
//! by a hash of their selection proof to fold the subcommittee's messages into
//! a `SyncCommitteeContribution` and publish it, which is how the messages
//! reach a block cheaply.
//!
//! # Which slot, and which root
//!
//! The message carries the wall slot and the head root when it is signed (on
//! the slot's block, or at the deadline), which may be an older block when
//! slots were skipped. A member assigned to wall
//! slot `S` signs for `S - 1`; the caller picks the duties accordingly (see
//! [`crate::duties::DutiesService::sync_at_slot`]).
//!
//! # Optimistic heads
//!
//! The optimistic-sync specification forbids signing `DOMAIN_SYNC_COMMITTEE`
//! over an optimistic head, so [`BeaconNodeApi::head_block_root`] fails with
//! `BeaconNodeSyncing` for one, and nothing is signed.
//!
//! A node that is syncing but not optimistic answers its stale head with
//! `execution_optimistic: false`, and the Beacon API has no 503 for it. The
//! fallback therefore does not ask a node whose last sync probe reported
//! syncing or optimistic for the head (see [`crate::beacon_node::health`]):
//! with every node in that state, the fetch answers `BeaconNodeSyncing` too.
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
    ContributionAndProof, SignedContributionAndProof, SyncCommitteeContribution,
    SyncCommitteeMessage, sync_subcommittee_size,
};
use ethlambda_types::beacon::primitives::{BlsPubkey, BlsSignature, Root, Slot, ValidatorIndex};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::beacon_node::dto::{SyncDutyDto, parse_pubkey};
use crate::beacon_node::{BeaconNodeApi, validate_sync_contribution};
use crate::error::{Error, Result};
use crate::keys::ValidatorStore;
use crate::performance::{Batch, Duty, Performance};
use crate::signing::{SigningContext, sign_all};

/// How many slots of dedup history are kept.
const HISTORY_SLOTS: u64 = 64;

/// The specification's `is_sync_committee_aggregator`: the first eight bytes of
/// the selection proof's SHA-256, little-endian, divide evenly by
/// `max(1, SYNC_SUBCOMMITTEE_SIZE / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE)`.
pub fn is_sync_committee_aggregator(selection_proof: &BlsSignature) -> bool {
    let modulo =
        (sync_subcommittee_size() as u64 / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE).max(1);
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
            let subnet = seat / sync_subcommittee_size() as u64;
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

/// Every seat `duties` hold at `slot`: one (validator, key, subnet) for each
/// subnet of each duty ([`subnets_of`]). What the contribution step decides
/// for and, in distributed mode, what is exchanged with the middleware ahead
/// of it ([`crate::distributed`]): read from one place, so the exchange
/// cannot come to cover other seats than the step reads. A duty whose pubkey
/// cannot be read holds none, and is reported.
pub fn seats_of(slot: Slot, duties: &[SyncDutyDto]) -> Vec<(ValidatorIndex, BlsPubkey, u64)> {
    let mut seats = Vec::new();
    for duty in duties {
        let pubkey = match parse_pubkey(&duty.pubkey) {
            Ok(pubkey) => pubkey,
            Err(err) => {
                error!(%slot, validator = duty.validator_index, %err, "Duty carried an unreadable pubkey");
                continue;
            }
        };
        for subnet in subnets_of(duty) {
            seats.push((duty.validator_index, pubkey, subnet));
        }
    }
    seats
}

pub struct SyncCommitteeService<B> {
    beacon_node: Arc<B>,
    context: Arc<SigningContext>,
    /// Which (validator, slot) pairs already produced a message signature.
    done: std::sync::Mutex<HashSet<(ValidatorIndex, Slot)>>,
    /// Where each validator's message outcome is counted. `None` counts
    /// nothing.
    performance: Option<Arc<Performance>>,
}

impl<B: BeaconNodeApi> SyncCommitteeService<B> {
    pub fn new(beacon_node: Arc<B>, context: Arc<SigningContext>) -> Self {
        Self {
            beacon_node,
            context,
            done: std::sync::Mutex::new(HashSet::new()),
            performance: None,
        }
    }

    /// Count each message duty's outcome per validator in `performance`.
    pub fn with_performance(mut self, performance: Arc<Performance>) -> Self {
        self.performance = Some(performance);
        self
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
        let pending = self.pending(slot, duties);
        if pending.is_empty() {
            return Ok(None);
        }
        // Counted from before the root is fetched: a fetch that fails, or one
        // the duty loop drops at the end of the slot (a hung node), counts
        // every pending duty failed.
        let mut outcomes = self.batch(slot, &pending);

        let root = match self.head_block_root().await {
            Ok(root) => root,
            Err(Error::BeaconNodeSyncing) => {
                // Not a failure: nothing may be signed over this head, so
                // nothing is counted.
                outcomes.skip_all();
                warn!(%slot, "Head is optimistic or the node is syncing; not signing sync committee messages");
                return Ok(None);
            }
            Err(err) => return Err(err),
        };
        self.publish_counted(slot, pending, store, root, outcomes)
            .await
    }

    /// The head root a message would sign, with nothing recorded and nothing
    /// signed. `BeaconNodeSyncing` for a head the node reports optimistic.
    ///
    /// For a caller that must look at the root before committing to it: the
    /// duty loop's early trigger signs only the block a head event announced,
    /// and otherwise leaves the duty to its deadline (see
    /// [`crate::head_monitor`]).
    pub async fn head_block_root(&self) -> Result<Root> {
        self.beacon_node.head_block_root().await
    }

    /// [`Self::publish_messages`] over `root`, a head root already fetched
    /// with [`Self::head_block_root`], instead of fetching it here.
    pub async fn publish_messages_over(
        &self,
        slot: Slot,
        duties: &[SyncDutyDto],
        store: &RwLock<ValidatorStore>,
        root: Root,
    ) -> Result<Option<Root>> {
        let pending = self.pending(slot, duties);
        if pending.is_empty() {
            return Ok(None);
        }
        let outcomes = self.batch(slot, &pending);
        self.publish_counted(slot, pending, store, root, outcomes)
            .await
    }

    /// Where the `pending` duties' outcomes at `slot` are counted.
    fn batch(&self, slot: Slot, pending: &[&SyncDutyDto]) -> Batch {
        Batch::new(
            self.performance.as_ref(),
            Duty::SyncCommitteeMessage,
            slot,
            pending.iter().map(|duty| duty.validator_index),
        )
    }

    /// Sign and submit the `pending` duties' messages over `root`, counting
    /// into `outcomes`, which the caller created for exactly those duties
    /// before it fetched `root`. Each counts once, published or failed,
    /// however this call ends: an early `?` or the duty loop's deadline
    /// counts it failed.
    async fn publish_counted(
        &self,
        slot: Slot,
        pending: Vec<&SyncDutyDto>,
        store: &RwLock<ValidatorStore>,
        root: Root,
        mut outcomes: Batch,
    ) -> Result<Option<Root>> {
        // Recorded one by one, then signed all at once, each within the
        // signing budget: a hung remote signer costs only its own keys'
        // messages, not the whole batch's.
        let mut to_sign = Vec::with_capacity(pending.len());
        for duty in pending {
            let pubkey = match parse_pubkey(&duty.pubkey) {
                Ok(pubkey) => pubkey,
                Err(err) => {
                    error!(%slot, validator = duty.validator_index, %err, "Duty carried an unreadable pubkey");
                    continue;
                }
            };
            if self.record(duty.validator_index, slot) {
                to_sign.push((duty.validator_index, pubkey));
            }
        }
        let signatures = {
            let _timing = crate::metrics::time_signing();
            sign_all(to_sign.iter().map(|(_, pubkey)| {
                (
                    *pubkey,
                    self.context
                        .sign_sync_committee_message(store, pubkey, slot, root),
                )
            }))
            .await
        };
        let mut messages = Vec::with_capacity(to_sign.len());
        for ((validator_index, _), signature) in to_sign.into_iter().zip(signatures) {
            match signature {
                Ok(signature) => messages.push(SyncCommitteeMessage {
                    slot,
                    beacon_block_root: root,
                    validator_index,
                    signature,
                }),
                Err(err) => {
                    error!(%slot, validator = validator_index, %err, "Failed to sign sync committee message");
                    crate::metrics::inc_signing_failures();
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
        let sent: Vec<_> = messages.iter().map(|m| m.validator_index).collect();
        outcomes.submitted(&sent, published);
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
        // Every (validator, subnet) pair's selection proof, asked for at once
        // and each within the signing budget. With distributed mode on, the
        // combined proofs fetched at the start of the slot instead, and a
        // pair with none is not selected (see `crate::distributed`).
        let seats = seats_of(slot, duties);
        let proofs = sign_all(seats.iter().map(|(_, pubkey, subnet)| {
            (
                *pubkey,
                self.context
                    .sync_selection_proof(store, pubkey, slot, *subnet),
            )
        }))
        .await;
        // (validator, pubkey, subnet, selection proof) for each selected pair.
        let mut selected: Vec<(ValidatorIndex, BlsPubkey, u64, BlsSignature)> = Vec::new();
        for ((validator, pubkey, subnet), proof) in seats.into_iter().zip(proofs) {
            match proof {
                Ok(Some(proof)) if is_sync_committee_aggregator(&proof) => {
                    selected.push((validator, pubkey, subnet, proof));
                }
                Ok(_) => {}
                Err(err) => {
                    error!(%slot, validator, %err, "Failed to sign sync selection proof");
                    crate::metrics::inc_signing_failures();
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

        let mut to_sign = Vec::new();
        for (validator, pubkey, subnet, proof) in selected {
            let Some(Some(contribution)) = fetched.get(&subnet) else {
                continue;
            };
            let message = ContributionAndProof {
                aggregator_index: validator,
                contribution: contribution.clone(),
                selection_proof: proof,
            };
            to_sign.push((pubkey, message));
        }
        let signatures = sign_all(to_sign.iter().map(|(pubkey, message)| {
            (
                *pubkey,
                self.context
                    .sign_contribution_and_proof(store, pubkey, message),
            )
        }))
        .await;
        let mut signed = Vec::with_capacity(to_sign.len());
        for ((_, message), signature) in to_sign.into_iter().zip(signatures) {
            match signature {
                Ok(signature) => signed.push(SignedContributionAndProof { message, signature }),
                Err(err) => {
                    error!(%slot, validator = message.aggregator_index, %err, "Failed to sign contribution and proof");
                    crate::metrics::inc_signing_failures();
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

    /// The duties not yet served for `slot`.
    fn pending<'d>(&self, slot: Slot, duties: &'d [SyncDutyDto]) -> Vec<&'d SyncDutyDto> {
        let done = self.lock();
        duties
            .iter()
            .filter(|duty| !done.contains(&(duty.validator_index, slot)))
            .collect()
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
        Arc::new(SigningContext::new(Config::mainnet(), Root::ZERO))
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
            (sync_subcommittee_size() as u64 / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE).max(1);
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
        let size = sync_subcommittee_size() as u64;
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
    async fn mixed_slot(
        context: &SigningContext,
        store: &RwLock<ValidatorStore>,
        pubkey: &BlsPubkey,
    ) -> Slot {
        for slot in 3200..4200 {
            let picks = picked_subnets(context, store, pubkey, slot).await.len();
            if picks > 0 && picks < 4 {
                return slot;
            }
        }
        panic!("no mixed slot found");
    }

    /// The subnets whose selection proof selects this key at `slot`.
    async fn picked_subnets(
        context: &SigningContext,
        store: &RwLock<ValidatorStore>,
        pubkey: &BlsPubkey,
        slot: Slot,
    ) -> Vec<u64> {
        let mut picked = Vec::new();
        for subnet in 0..4 {
            let proof = context
                .sign_sync_selection_proof(store, pubkey, slot, subnet)
                .await
                .expect("signs");
            if is_sync_committee_aggregator(&proof) {
                picked.push(subnet);
            }
        }
        picked
    }

    fn all_subnet_duty(pubkey: &BlsPubkey) -> SyncDutyDto {
        let size = sync_subcommittee_size() as u64;
        duty(pubkey, 9, vec![0, size, 2 * size, 3 * size])
    }

    #[tokio::test]
    async fn only_selected_pairs_fetch_and_a_published_contribution_verifies() {
        let (store, pubkey) = store();
        let context = context();
        let slot = mixed_slot(&context, &store, &pubkey).await;
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

        let expected = picked_subnets(&context, &store, &pubkey, slot).await;
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
        let slot = mixed_slot(&context, &store, &pubkey).await;
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
        let mut found = None;
        for slot in 3200..6000 {
            let picked = picked_subnets(&context, &store, &pubkey, slot).await;
            if picked.len() >= 2 {
                found = Some((slot, picked));
                break;
            }
        }
        let (slot, picked) = found.expect("a slot selecting two subnets");
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
