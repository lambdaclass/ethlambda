//! Signed proposer preferences: how a validator tells builders, and from
//! gloas its own beacon node, where its proposals should pay and which gas
//! limit to target.
//!
//! # Why it exists
//!
//! From gloas, beacon-APIs makes a signed `ProposerPreferences` the source of a
//! proposer's fee recipient and gas limit, superseding `prepare_beacon_proposer`.
//! It is also the trustless-bid channel: a node ignores p2p builder bids for a
//! slot whose proposer published no preferences, so a validator that stays
//! silent self-builds every gloas proposal.
//!
//! # Why v2 proposer duties
//!
//! A preference names the `dependent_root` its duty was computed from, and the
//! gossip rule compares it with the node's own shuffling dependent root. Fulu's
//! proposer lookahead fixes an epoch's proposers one epoch earlier than v1's
//! definition says, so only v2's `dependent_root` is the one a preference must
//! carry. The duty loop keeps its own v1 schedule; this service fetches v2 for
//! itself.
//!
//! # The signing domain
//!
//! See [`SigningContext::sign_proposer_preferences`]: the gossip rule's domain,
//! at the fork of the epoch before the proposal's, which is not the validator
//! guide's head-state one in the first epoch of a fork.
//!
//! # Why every slot
//!
//! [`PreferencesService::poll`] runs each slot rather than each epoch. A reorg
//! changes a dependent root, which makes the old preference unusable and needs
//! a new one; a validator can become active, or be given a fee recipient,
//! mid-epoch; and a node that refused a send must be tried again. What was
//! already accepted is remembered per `(slot, dependent_root)`, so a quiet
//! slot costs the two duty fetches and no signing.
//!
//! # Why every node gets them
//!
//! Each node gossips what it accepts, so the fallback client sends to all of
//! them: a preference only one node heard reaches builders through that node's
//! mesh alone.
//!
//! # No replacement
//!
//! A node deduplicates on `(slot, dependent_root)`, so a preference cannot be
//! replaced for the same slot and root. A fee recipient changed after a
//! preference went out applies from the next dependent root onward only.
//!
//! # Failures are never propagated
//!
//! A missed preference costs a builder bid and, from gloas, possibly the
//! node's knowledge of the fee recipient, never a duty. A failed send is logged
//! and counted, and the next slot retries.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ethlambda_types::beacon::containers::gloas::{ProposerPreferences, SignedProposerPreferences};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::preset;
use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch, Root, Slot};
use ethlambda_types::beacon::signing::compute_epoch_at_slot;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::beacon_node::BeaconNodeApi;
use crate::beacon_node::dto::{encode_hex, parse_pubkey};
use crate::keys::ValidatorStore;
use crate::proposer_settings::ProposerSettings;
use crate::signing::SigningContext;

/// Clears [`PreferencesService`]'s `in_flight` flag on every exit from a poll,
/// a panic included, so one failed poll cannot stop every later one.
struct InFlightGuard<'a>(&'a AtomicBool);

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Signs and publishes proposer preferences.
pub struct PreferencesService<B> {
    beacon_node: Arc<B>,
    context: Arc<SigningContext>,
    settings: Arc<ProposerSettings>,
    /// `(proposal_slot, dependent_root)` pairs a node accepted, so a
    /// preference is signed and sent once per dependent root. A reorg that
    /// moves the root sends the slot again; pruned below the current epoch.
    published: std::sync::Mutex<HashSet<(Slot, Root)>>,
    /// Epochs whose missing fee recipients were already warned about, so the
    /// warning is once per epoch rather than once per slot. Pruned like
    /// `published`.
    warned_epochs: std::sync::Mutex<HashSet<Epoch>>,
    /// One poll at a time: a slow node must not stack polls up.
    in_flight: AtomicBool,
}

impl<B: BeaconNodeApi + 'static> PreferencesService<B> {
    pub fn new(
        beacon_node: Arc<B>,
        context: Arc<SigningContext>,
        settings: Arc<ProposerSettings>,
    ) -> Self {
        Self {
            beacon_node,
            context,
            settings,
            published: std::sync::Mutex::new(HashSet::new()),
            warned_epochs: std::sync::Mutex::new(HashSet::new()),
            in_flight: AtomicBool::new(false),
        }
    }

    /// Publish what this client's validators still owe for the current and the
    /// next epoch, as of `current_slot`. Called once per slot, off the slot
    /// loop, so a slow node cannot delay the next slot's duties.
    ///
    /// Returns at once when the previous poll is still running.
    pub async fn poll(self: Arc<Self>, current_slot: Slot, store: Arc<RwLock<ValidatorStore>>) {
        if self.in_flight.swap(true, Ordering::AcqRel) {
            return;
        }
        let _guard = InFlightGuard(&self.in_flight);

        let epoch = compute_epoch_at_slot(current_slot);
        // Snapshotted with the guard dropped at once: nothing below awaits a
        // node while holding the store.
        let pubkeys: HashSet<BlsPubkey> = store.read().await.pubkeys().into_iter().collect();
        let fork = self.context.config.fork_at_epoch(epoch);

        for target in [epoch, epoch + 1] {
            if self.context.config.fork_at_epoch(target) < ForkName::Gloas {
                continue;
            }
            self.publish_epoch(fork, current_slot, target, &pubkeys, &store)
                .await;
        }

        let epoch_start = epoch * preset::SLOTS_PER_EPOCH;
        self.published
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(slot, _)| *slot >= epoch_start);
        self.warned_epochs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|warned| *warned >= epoch);
    }

    /// One target epoch: fetch its v2 duties, sign what is still owed and send it.
    async fn publish_epoch(
        &self,
        fork: ForkName,
        current_slot: Slot,
        target: Epoch,
        pubkeys: &HashSet<BlsPubkey>,
        store: &Arc<RwLock<ValidatorStore>>,
    ) {
        let duties = match self.beacon_node.proposer_duties_v2(target).await {
            Ok(duties) => duties,
            Err(err) => {
                debug!(epoch = target, %err, "Could not fetch proposer duties for preferences");
                return;
            }
        };

        let mut owed = Vec::new();
        let mut no_fee_recipient = 0usize;
        for duty in &duties.duties {
            // Started slots are skipped: gossip would IGNORE them.
            if duty.slot <= current_slot {
                continue;
            }
            let Ok(pubkey) = parse_pubkey(&duty.pubkey) else {
                continue;
            };
            if !pubkeys.contains(&pubkey) {
                continue;
            }
            let already = self
                .published
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(&(duty.slot, duties.dependent_root));
            if already {
                continue;
            }
            let Some(fee_recipient) = self.settings.fee_recipient(&pubkey) else {
                no_fee_recipient += 1;
                continue;
            };
            owed.push((
                pubkey,
                ProposerPreferences {
                    dependent_root: duties.dependent_root,
                    proposal_slot: duty.slot,
                    validator_index: duty.validator_index,
                    fee_recipient,
                    target_gas_limit: self.settings.gas_limit(&pubkey),
                },
            ));
        }

        if no_fee_recipient > 0 {
            let first_warning = self
                .warned_epochs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(target);
            if first_warning {
                warn!(
                    epoch = target,
                    skipped = no_fee_recipient,
                    "Validators without a fee recipient publish no proposer preferences"
                );
            }
        }
        if owed.is_empty() {
            return;
        }

        // At most a few per epoch, so signing inline is cheap; the read guard
        // is released before the submit.
        let mut signed = Vec::with_capacity(owed.len());
        {
            let store = store.read().await;
            for (pubkey, message) in owed {
                match self
                    .context
                    .sign_proposer_preferences(&store, &pubkey, &message)
                {
                    Ok(signature) => signed.push(SignedProposerPreferences { message, signature }),
                    Err(err) => {
                        warn!(
                            pubkey = %encode_hex(&pubkey.0),
                            slot = message.proposal_slot,
                            %err,
                            "Could not sign proposer preferences; skipping them"
                        );
                    }
                }
            }
        }
        if signed.is_empty() {
            return;
        }

        match self
            .beacon_node
            .submit_proposer_preferences(fork, &signed)
            .await
        {
            Ok(()) => {
                let count = signed.len();
                self.published
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .extend(
                        signed.iter().map(|entry| {
                            (entry.message.proposal_slot, entry.message.dependent_root)
                        }),
                    );
                crate::metrics::inc_proposer_preferences_published(count);
                info!(epoch = target, count, "Proposer preferences published");
            }
            Err(err) => {
                warn!(epoch = target, count = signed.len(), %err, "No beacon node accepted the proposer preferences");
                crate::metrics::inc_proposer_preferences_failures();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_node::dto::ProposerDutyDto;
    use crate::beacon_node::mock::MockBeaconNode;
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::constants::DOMAIN_PROPOSER_PREFERENCES;
    use ethlambda_types::beacon::primitives::{Bytes32, H160, HashTreeRoot as _};
    use ethlambda_types::beacon::signing::{compute_domain, compute_signing_root};

    const GLOAS_EPOCH: Epoch = 500_000;
    const FEE_RECIPIENT: H160 = H160([0xab; 20]);

    fn context() -> Arc<SigningContext> {
        let mut config = Config::mainnet();
        config.gloas_fork_epoch = GLOAS_EPOCH;
        Arc::new(SigningContext {
            config,
            genesis_validators_root: Root::repeat_byte(0x42),
        })
    }

    /// `count` distinct keys. The secrets are small integers, which are valid
    /// BLS scalars, so no keystore is needed.
    fn store_with_keys(count: usize) -> (ValidatorStore, Vec<BlsPubkey>) {
        let mut store = ValidatorStore::new();
        let pubkeys = (0..count)
            .map(|index| {
                let mut secret = [0u8; 32];
                secret[24..].copy_from_slice(&(index as u64 + 1).to_be_bytes());
                store.insert_secret("test", &secret).expect("inserts")
            })
            .collect();
        (store, pubkeys)
    }

    fn duty(pubkey: &BlsPubkey, validator_index: u64, slot: Slot) -> ProposerDutyDto {
        ProposerDutyDto {
            pubkey: encode_hex(&pubkey.0),
            validator_index,
            slot,
        }
    }

    fn settings(fee_recipient: Option<H160>) -> Arc<ProposerSettings> {
        Arc::new(ProposerSettings::new(Bytes32::ZERO, fee_recipient))
    }

    fn service(
        node: MockBeaconNode,
        settings: Arc<ProposerSettings>,
    ) -> (Arc<PreferencesService<MockBeaconNode>>, Arc<MockBeaconNode>) {
        let node = Arc::new(node);
        (
            Arc::new(PreferencesService::new(node.clone(), context(), settings)),
            node,
        )
    }

    fn slot_in(epoch: Epoch, offset: Slot) -> Slot {
        epoch * preset::SLOTS_PER_EPOCH + offset
    }

    fn submitted(node: &MockBeaconNode) -> Vec<(ForkName, Vec<SignedProposerPreferences>)> {
        node.submitted_preferences.lock().expect("lock").clone()
    }

    fn verifies(pubkey: &BlsPubkey, entry: &SignedProposerPreferences) -> bool {
        use blst::min_pk::{PublicKey, Signature};

        let context = context();
        let proposal_epoch = compute_epoch_at_slot(entry.message.proposal_slot);
        let domain = context.domain(DOMAIN_PROPOSER_PREFERENCES, proposal_epoch - 1);
        assert_eq!(
            domain,
            compute_domain(
                DOMAIN_PROPOSER_PREFERENCES,
                context
                    .config
                    .fork_version(context.config.fork_at_epoch(proposal_epoch - 1)),
                context.genesis_validators_root,
            )
        );
        let root = compute_signing_root(entry.message.hash_tree_root(), domain);
        let pk = PublicKey::from_bytes(&pubkey.0).expect("valid pubkey");
        let sig = Signature::from_bytes(&entry.signature.0).expect("valid signature");
        sig.verify(
            true,
            root.as_slice(),
            b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
            &[],
            &pk,
            true,
        ) == blst::BLST_ERROR::BLST_SUCCESS
    }

    #[tokio::test]
    async fn publishes_for_this_clients_gloas_duties_in_the_current_and_next_epoch() {
        let (store, pubkeys) = store_with_keys(1);
        let store = Arc::new(RwLock::new(store));
        let settings = settings(Some(FEE_RECIPIENT));
        settings.set_gas_limit(&pubkeys[0], 31_000_000);
        let current = slot_in(GLOAS_EPOCH, 1);
        let node = MockBeaconNode::new()
            .with_proposers_v2(
                GLOAS_EPOCH,
                Root::repeat_byte(0x11),
                vec![duty(&pubkeys[0], 3, slot_in(GLOAS_EPOCH, 10))],
            )
            .with_proposers_v2(
                GLOAS_EPOCH + 1,
                Root::repeat_byte(0x22),
                vec![duty(&pubkeys[0], 3, slot_in(GLOAS_EPOCH + 1, 4))],
            );
        let (service, node) = service(node, settings);

        service.poll(current, store).await;

        let sent = submitted(&node);
        assert_eq!(sent.len(), 2, "one send per target epoch");
        let mut entries: Vec<_> = sent
            .iter()
            .inspect(|(fork, _)| assert_eq!(*fork, ForkName::Gloas))
            .flat_map(|(_, entries)| entries.clone())
            .collect();
        entries.sort_by_key(|entry| entry.message.proposal_slot);
        assert_eq!(entries.len(), 2);
        let expected = [
            (slot_in(GLOAS_EPOCH, 10), Root::repeat_byte(0x11)),
            (slot_in(GLOAS_EPOCH + 1, 4), Root::repeat_byte(0x22)),
        ];
        for (entry, (slot, root)) in entries.iter().zip(expected) {
            assert_eq!(entry.message.proposal_slot, slot);
            assert_eq!(entry.message.dependent_root, root);
            assert_eq!(entry.message.validator_index, 3);
            assert_eq!(entry.message.fee_recipient, FEE_RECIPIENT);
            assert_eq!(entry.message.target_gas_limit, 31_000_000);
            assert!(verifies(&pubkeys[0], entry), "slot {slot}");
        }
    }

    #[tokio::test]
    async fn a_second_poll_does_not_resubmit() {
        let (store, pubkeys) = store_with_keys(1);
        let store = Arc::new(RwLock::new(store));
        let node = MockBeaconNode::new().with_proposers_v2(
            GLOAS_EPOCH,
            Root::repeat_byte(0x11),
            vec![duty(&pubkeys[0], 3, slot_in(GLOAS_EPOCH, 10))],
        );
        let (service, node) = service(node, settings(Some(FEE_RECIPIENT)));
        let current = slot_in(GLOAS_EPOCH, 1);

        service.clone().poll(current, store.clone()).await;
        service.poll(current + 1, store).await;

        assert_eq!(submitted(&node).len(), 1);
    }

    #[tokio::test]
    async fn a_changed_dependent_root_resubmits() {
        let (store, pubkeys) = store_with_keys(1);
        let store = Arc::new(RwLock::new(store));
        let slot = slot_in(GLOAS_EPOCH, 10);
        let node = MockBeaconNode::new().with_proposers_v2(
            GLOAS_EPOCH,
            Root::repeat_byte(0x11),
            vec![duty(&pubkeys[0], 3, slot)],
        );
        let (service, node) = service(node, settings(Some(FEE_RECIPIENT)));
        let current = slot_in(GLOAS_EPOCH, 1);

        service.clone().poll(current, store.clone()).await;
        node.set_proposers_v2(
            GLOAS_EPOCH,
            Root::repeat_byte(0x33),
            vec![duty(&pubkeys[0], 3, slot)],
        );
        service.poll(current + 1, store).await;

        let sent = submitted(&node);
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1].1[0].message.dependent_root, Root::repeat_byte(0x33));
        assert!(verifies(&pubkeys[0], &sent[1].1[0]));
    }

    #[tokio::test]
    async fn pre_gloas_epochs_are_skipped() {
        let (store, pubkeys) = store_with_keys(1);
        let store = Arc::new(RwLock::new(store));
        let node = MockBeaconNode::new().with_proposers_v2(
            GLOAS_EPOCH,
            Root::repeat_byte(0x11),
            vec![duty(&pubkeys[0], 3, slot_in(GLOAS_EPOCH, 10))],
        );
        let (service, node) = service(node, settings(Some(FEE_RECIPIENT)));

        // The epoch before gloas: only the next, gloas, epoch is owed.
        service
            .clone()
            .poll(slot_in(GLOAS_EPOCH - 1, 1), store.clone())
            .await;
        let sent = submitted(&node);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, ForkName::Fulu, "the current epoch's fork");
        assert_eq!(sent[0].1[0].message.proposal_slot, slot_in(GLOAS_EPOCH, 10));
        assert_eq!(node.proposer_duties_v2_call_count(), 1);

        // Two epochs before: nothing is submitted and no v2 call is made.
        let (service, node) = service_for_two_epochs_before(&pubkeys);
        service.poll(slot_in(GLOAS_EPOCH - 2, 1), store).await;
        assert!(submitted(&node).is_empty());
        assert_eq!(node.proposer_duties_v2_call_count(), 0);
    }

    fn service_for_two_epochs_before(
        pubkeys: &[BlsPubkey],
    ) -> (Arc<PreferencesService<MockBeaconNode>>, Arc<MockBeaconNode>) {
        let node = MockBeaconNode::new().with_proposers_v2(
            GLOAS_EPOCH - 1,
            Root::repeat_byte(0x11),
            vec![duty(&pubkeys[0], 3, slot_in(GLOAS_EPOCH - 1, 10))],
        );
        service(node, settings(Some(FEE_RECIPIENT)))
    }

    #[tokio::test]
    async fn started_slots_and_other_validators_are_skipped() {
        let (store, pubkeys) = store_with_keys(2);
        // The store holds only the first key; the second is another client's.
        let (held, _) = store_with_keys(1);
        let held = Arc::new(RwLock::new(held));
        let current = slot_in(GLOAS_EPOCH, 5);
        let node = MockBeaconNode::new().with_proposers_v2(
            GLOAS_EPOCH,
            Root::repeat_byte(0x11),
            vec![
                duty(&pubkeys[0], 3, current),
                duty(&pubkeys[0], 3, current - 1),
                duty(&pubkeys[1], 4, slot_in(GLOAS_EPOCH, 10)),
                duty(&pubkeys[0], 3, slot_in(GLOAS_EPOCH, 12)),
            ],
        );
        drop(store);
        let (service, node) = service(node, settings(Some(FEE_RECIPIENT)));

        service.poll(current, held).await;

        let sent = submitted(&node);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1.len(), 1);
        assert_eq!(sent[0].1[0].message.proposal_slot, slot_in(GLOAS_EPOCH, 12));
        assert_eq!(sent[0].1[0].message.validator_index, 3);
    }

    #[tokio::test]
    async fn a_validator_without_a_fee_recipient_is_skipped() {
        let (store, pubkeys) = store_with_keys(2);
        let store = Arc::new(RwLock::new(store));
        let settings = settings(None);
        settings.set_fee_recipient(&pubkeys[1], FEE_RECIPIENT);
        let node = MockBeaconNode::new().with_proposers_v2(
            GLOAS_EPOCH,
            Root::repeat_byte(0x11),
            vec![
                duty(&pubkeys[0], 3, slot_in(GLOAS_EPOCH, 10)),
                duty(&pubkeys[1], 4, slot_in(GLOAS_EPOCH, 11)),
            ],
        );
        let (service, node) = service(node, settings);

        service.poll(slot_in(GLOAS_EPOCH, 1), store).await;

        let sent = submitted(&node);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1.len(), 1);
        assert_eq!(sent[0].1[0].message.validator_index, 4);
    }

    #[tokio::test]
    async fn a_failed_submit_is_retried_next_poll() {
        let (store, pubkeys) = store_with_keys(1);
        let store = Arc::new(RwLock::new(store));
        let node = MockBeaconNode::new().with_proposers_v2(
            GLOAS_EPOCH,
            Root::repeat_byte(0x11),
            vec![duty(&pubkeys[0], 3, slot_in(GLOAS_EPOCH, 10))],
        );
        node.failures
            .lock()
            .expect("lock")
            .insert("submit_proposer_preferences", "node refused".to_string());
        let (service, node) = service(node, settings(Some(FEE_RECIPIENT)));
        let current = slot_in(GLOAS_EPOCH, 1);

        service.clone().poll(current, store.clone()).await;
        assert!(submitted(&node).is_empty());

        node.failures.lock().expect("lock").clear();
        service.poll(current + 1, store).await;
        assert_eq!(submitted(&node).len(), 1, "sent once the node recovered");
    }

    #[tokio::test]
    async fn overlapping_polls_do_not_run_twice() {
        let (store, pubkeys) = store_with_keys(1);
        let store = Arc::new(RwLock::new(store));
        let node = MockBeaconNode::new().with_proposers_v2(
            GLOAS_EPOCH,
            Root::repeat_byte(0x11),
            vec![duty(&pubkeys[0], 3, slot_in(GLOAS_EPOCH, 10))],
        );
        let (service, node) = service(node, settings(Some(FEE_RECIPIENT)));

        service.in_flight.store(true, Ordering::Release);
        service
            .clone()
            .poll(slot_in(GLOAS_EPOCH, 1), store.clone())
            .await;
        assert!(submitted(&node).is_empty());
        assert_eq!(node.proposer_duties_v2_call_count(), 0);
        assert!(
            service.in_flight.load(Ordering::Acquire),
            "the running poll's flag is not cleared by the one that bounced"
        );

        service.in_flight.store(false, Ordering::Release);
        service.clone().poll(slot_in(GLOAS_EPOCH, 1), store).await;
        assert_eq!(submitted(&node).len(), 1);
        assert!(
            !service.in_flight.load(Ordering::Acquire),
            "cleared after a poll"
        );
    }
}
