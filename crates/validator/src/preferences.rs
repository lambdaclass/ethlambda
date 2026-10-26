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
//! at the fork of the epoch before the proposal's. The validator guide's
//! head-state signer differs from it only for a proposal in the first epoch of
//! a fork, signed during that epoch.
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
//! # One preference per request
//!
//! A node answers 400 for a whole call when any entry in it fails, and one it
//! holds for the same `(slot, dependent_root)` with other content is such a
//! failure (a restart after a fee recipient change, say). Batching would then
//! fail every entry every slot until that slot passed, so each preference is
//! sent alone, and each success is remembered on its own. There are only a
//! handful per epoch.
//!
//! # Failures are never propagated
//!
//! A missed preference costs a builder bid and, from gloas, possibly the
//! node's knowledge of the fee recipient, never a duty. A failed send, or a
//! failed duties fetch, is logged (the fetch once per epoch) and counted, and
//! the next slot retries.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

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
    published: Mutex<HashSet<(Slot, Root)>>,
    /// Epochs whose missing fee recipients were already warned about, so the
    /// warning is once per epoch rather than once per slot. Pruned like
    /// `published`.
    no_fee_warned: Mutex<HashSet<Epoch>>,
    /// `(proposal_slot, dependent_root)` entries whose refusal was already
    /// warned about, so a persistently refused one warns once rather than every
    /// slot until its slot passes. Pruned with `published`.
    refusal_warned: Mutex<HashSet<(Slot, Root)>>,
    /// Epochs whose failed duties fetch was already warned about, for the same
    /// reason: a syncing node, or one without v2, fails every slot.
    fetch_warned: Mutex<HashSet<Epoch>>,
    /// One poll at a time: a slow node must not stack polls up.
    in_flight: AtomicBool,
}

/// Lock `mutex`, recovering a poisoned one: every write here is one set
/// operation, so the data behind it is never half-changed.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
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
            published: Mutex::new(HashSet::new()),
            no_fee_warned: Mutex::new(HashSet::new()),
            refusal_warned: Mutex::new(HashSet::new()),
            fetch_warned: Mutex::new(HashSet::new()),
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

        for target in [epoch, epoch + 1] {
            if self.context.config.fork_at_epoch(target) < ForkName::Gloas {
                continue;
            }
            self.publish_epoch(current_slot, target, &pubkeys, &store)
                .await;
        }

        let epoch_start = epoch * preset::SLOTS_PER_EPOCH;
        lock(&self.published).retain(|(slot, _)| *slot >= epoch_start);
        lock(&self.refusal_warned).retain(|(slot, _)| *slot >= epoch_start);
        lock(&self.no_fee_warned).retain(|warned| *warned >= epoch);
        lock(&self.fetch_warned).retain(|warned| *warned >= epoch);
    }

    /// One target epoch: fetch its v2 duties, sign what is still owed and send it.
    async fn publish_epoch(
        &self,
        current_slot: Slot,
        target: Epoch,
        pubkeys: &HashSet<BlsPubkey>,
        store: &Arc<RwLock<ValidatorStore>>,
    ) {
        let duties = match self.beacon_node.proposer_duties_v2(target).await {
            Ok(duties) => duties,
            Err(err) => {
                debug!(epoch = target, %err, "Could not fetch proposer duties for preferences");
                crate::metrics::inc_proposer_preferences_failures();
                if lock(&self.fetch_warned).insert(target) {
                    warn!(
                        epoch = target,
                        %err,
                        "No beacon node answered the v2 proposer duties; proposer preferences \
                         for this epoch wait for a node that does"
                    );
                }
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
            if lock(&self.published).contains(&(duty.slot, duties.dependent_root)) {
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

        if no_fee_recipient > 0 && lock(&self.no_fee_warned).insert(target) {
            warn!(
                epoch = target,
                skipped = no_fee_recipient,
                "Validators without a fee recipient publish no proposer preferences"
            );
        }
        if owed.is_empty() {
            return;
        }

        // At most a few per epoch, so signing inline is cheap; the read guard
        // is released before the submits.
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

        // The target epoch's fork, which is what the submitted objects belong
        // to (always gloas here).
        let fork = self.context.config.fork_at_epoch(target);
        let mut published = 0usize;
        for entry in signed {
            // One request per preference: a node answers 400 for the whole
            // call when any entry fails, and the one it refuses (for a
            // `(slot, root)` it holds with other content, say) would
            // otherwise keep the others from ever being marked published.
            let key = (entry.message.proposal_slot, entry.message.dependent_root);
            match self
                .beacon_node
                .submit_proposer_preferences(fork, std::slice::from_ref(&entry))
                .await
            {
                Ok(()) => {
                    lock(&self.published).insert(key);
                    published += 1;
                }
                Err(err) => {
                    // A refused entry is tried again every slot until its slot
                    // passes, so only its first refusal is a warning.
                    if lock(&self.refusal_warned).insert(key) {
                        warn!(
                            epoch = target,
                            slot = key.0,
                            validator = entry.message.validator_index,
                            %err,
                            "No beacon node accepted a proposer preference; builders' bids for \
                             that slot are ignored, and from gloas a node may not know the fee \
                             recipient"
                        );
                    } else {
                        debug!(
                            epoch = target,
                            slot = key.0,
                            validator = entry.message.validator_index,
                            %err,
                            "A proposer preference was refused again"
                        );
                    }
                    crate::metrics::inc_proposer_preferences_failures();
                }
            }
        }
        if published > 0 {
            crate::metrics::inc_proposer_preferences_published(published);
            info!(
                epoch = target,
                count = published,
                "Proposer preferences published"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_node::dto::ProposerDutyDto;
    use crate::beacon_node::mock::MockBeaconNode;
    use crate::test_support::{settings, store_with_keys};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::constants::DOMAIN_PROPOSER_PREFERENCES;
    use ethlambda_types::beacon::primitives::{H160, HashTreeRoot as _};
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

    fn duty(pubkey: &BlsPubkey, validator_index: u64, slot: Slot) -> ProposerDutyDto {
        ProposerDutyDto {
            pubkey: encode_hex(&pubkey.0),
            validator_index,
            slot,
        }
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
        // Spelled out rather than asked of `SigningContext::domain`: the
        // first gloas epoch's preference verifies under fulu's version (the
        // fork of the epoch before it), every later one under gloas's.
        let version = if proposal_epoch == GLOAS_EPOCH {
            context.config.fulu_fork_version
        } else {
            assert!(proposal_epoch > GLOAS_EPOCH);
            context.config.gloas_fork_version
        };
        let domain = compute_domain(
            DOMAIN_PROPOSER_PREFERENCES,
            version,
            context.genesis_validators_root,
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
        assert_eq!(sent.len(), 2, "one request per preference");
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
        assert_eq!(sent[0].0, ForkName::Gloas, "the target epoch's fork");
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

    /// A node that refuses one preference (it holds another for that slot and
    /// root) must not keep the others from going out and being remembered, nor
    /// make them re-sent every slot.
    #[tokio::test]
    async fn a_refused_preference_does_not_block_the_others() {
        let (store, pubkeys) = store_with_keys(2);
        let store = Arc::new(RwLock::new(store));
        let refused = slot_in(GLOAS_EPOCH, 10);
        let accepted = slot_in(GLOAS_EPOCH, 11);
        let node = MockBeaconNode::new().with_proposers_v2(
            GLOAS_EPOCH,
            Root::repeat_byte(0x11),
            vec![
                duty(&pubkeys[0], 3, refused),
                duty(&pubkeys[1], 4, accepted),
            ],
        );
        node.refused_preference_slots
            .lock()
            .expect("lock")
            .push(refused);
        let (service, node) = service(node, settings(Some(FEE_RECIPIENT)));
        let current = slot_in(GLOAS_EPOCH, 1);

        service.clone().poll(current, store.clone()).await;
        let sent = submitted(&node);
        assert_eq!(sent.len(), 1, "only the accepted one was recorded");
        assert_eq!(sent[0].1[0].message.proposal_slot, accepted);

        // Next poll: the accepted one is not re-sent, the refused one is
        // tried again (and refused again).
        service.clone().poll(current + 1, store.clone()).await;
        assert_eq!(submitted(&node).len(), 1);
        assert_eq!(
            *lock(&service.refusal_warned),
            HashSet::from([(refused, Root::repeat_byte(0x11))]),
            "two refusals of one entry leave one warn-path record"
        );

        node.refused_preference_slots.lock().expect("lock").clear();
        service.poll(current + 2, store).await;
        let sent = submitted(&node);
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1].1[0].message.proposal_slot, refused);
    }

    /// A failed duties fetch is warned about once per target epoch, and the
    /// next poll that gets an answer publishes.
    #[tokio::test]
    async fn a_failed_duties_fetch_is_retried_and_warned_once_per_epoch() {
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
            .insert("proposer_duties_v2", "syncing".to_string());
        let (service, node) = service(node, settings(Some(FEE_RECIPIENT)));
        let current = slot_in(GLOAS_EPOCH, 1);

        service.clone().poll(current, store.clone()).await;
        service.clone().poll(current + 1, store.clone()).await;
        assert!(submitted(&node).is_empty());
        let warned: Vec<Epoch> = lock(&service.fetch_warned).iter().copied().collect();
        assert_eq!(warned.len(), 2, "one entry per target epoch, not per poll");

        node.failures.lock().expect("lock").clear();
        service.poll(current + 2, store).await;
        assert_eq!(submitted(&node).len(), 1);
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
