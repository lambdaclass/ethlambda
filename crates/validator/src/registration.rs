//! Builder registrations: what tells a beacon node's builder where to pay each
//! validator and which gas limit to target.
//!
//! A registration is a `ValidatorRegistrationV1` the validator signs, so a
//! relay can trust that the fee recipient and gas limit it builds for were
//! chosen by the key that will sign the block. The beacon node forwards them to
//! its builder, which keeps the newest per validator.
//!
//! # Why a signature is reused until the settings change
//!
//! Builders order a validator's registrations by `timestamp` and keep the
//! latest, so re-sending an unchanged registration with the same timestamp is
//! harmless, and re-signing it with a fresh one every epoch would cost a BLS
//! signature per validator for a message that says nothing new. The signed
//! registration is therefore cached per validator and re-signed, with a new
//! timestamp, only when the fee recipient or gas limit changes. The full set is
//! still re-sent every epoch: a beacon node forgets its registrations when it
//! restarts, and a relay may expire them, so repeating them is what keeps the
//! validators registered without any state beyond this cache.
//!
//! # Why it stops at gloas
//!
//! From gloas the builder market works through proposer preferences, which the
//! beacon node serves itself, so there is nothing for this client to register.
//! Both entry points return at the gloas fork epoch.
//!
//! # Why every node gets them
//!
//! A registration installs state on a node's builder, so the fallback client
//! sends to every node rather than the first that answers: a node that never
//! heard them cannot serve a bid for these validators after a failover.
//!
//! # Failures are never propagated
//!
//! A missed registration costs at most a builder block, never a duty, so a
//! failed send is logged and counted and the caller moves on. A changed
//! registration whose send fails is cached anyway, so it is not re-sent at the
//! next slot: it waits for the next epoch's full send.
//!
//! # Signing stays off the async runtime
//!
//! The first epoch signs one BLS signature per validator. That runs on the
//! blocking pool in chunks of [`SIGN_CHUNK`], taking the store's read lock
//! afresh for each chunk, so neither the runtime's threads nor a queued
//! keymanager writer wait on thousands of signatures.
//!
//! # The per-slot check is one atomic read
//!
//! Only a keymanager write changes what a registration says, so
//! [`RegistrationService::register_changed`] compares
//! [`ProposerSettings::generation`] with the one it last signed against and
//! returns before touching the store when it has not moved.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ethlambda_types::beacon::builder::{SignedValidatorRegistrationV1, ValidatorRegistrationV1};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::beacon_node::BeaconNodeApi;
use crate::beacon_node::dto::encode_hex;
use crate::keys::ValidatorStore;
use crate::proposer_settings::ProposerSettings;
use crate::signing::SigningContext;

/// Registrations per request. Lighthouse's batch size: large enough that a few
/// thousand validators take a handful of requests, small enough that one
/// request stays well under a node's body limit.
pub const REGISTRATION_BATCH: usize = 500;

/// Keys signed per blocking task, and so per hold of the store's read lock.
const SIGN_CHUNK: usize = 64;

/// What [`RegistrationService::current`] found for a set of validators.
struct Current {
    /// Every validator's registration, cached or newly signed.
    all: Vec<SignedValidatorRegistrationV1>,
    /// The subset signed in this call, because it had no registration yet or
    /// its fee recipient or gas limit changed.
    changed: Vec<SignedValidatorRegistrationV1>,
    /// Validators skipped because no fee recipient is configured for them.
    no_fee_recipient: usize,
}

impl Current {
    fn extend(&mut self, other: Current) {
        self.all.extend(other.all);
        self.changed.extend(other.changed);
        self.no_fee_recipient += other.no_fee_recipient;
    }
}

/// Signs and sends builder registrations.
pub struct RegistrationService<B> {
    beacon_node: Arc<B>,
    context: Arc<SigningContext>,
    settings: Arc<ProposerSettings>,
    /// The validators the beacon node resolved at the last epoch refresh.
    known: std::sync::Mutex<Vec<BlsPubkey>>,
    /// The latest signed registration per validator.
    signed: std::sync::Mutex<HashMap<BlsPubkey, SignedValidatorRegistrationV1>>,
    /// The [`ProposerSettings::generation`] the cache was last brought up to
    /// date against.
    signed_generation: AtomicU64,
}

impl<B: BeaconNodeApi + 'static> RegistrationService<B> {
    pub fn new(
        beacon_node: Arc<B>,
        context: Arc<SigningContext>,
        settings: Arc<ProposerSettings>,
    ) -> Self {
        Self {
            beacon_node,
            context,
            settings,
            known: std::sync::Mutex::new(Vec::new()),
            signed: std::sync::Mutex::new(HashMap::new()),
            signed_generation: AtomicU64::new(0),
        }
    }

    /// The registration for each of `pubkeys` as of `now_secs`, signing only
    /// the ones whose `(fee_recipient, gas_limit)` differs from the cached one.
    ///
    /// `now_secs` is a parameter so a test can fix the timestamp.
    fn current(&self, store: &ValidatorStore, pubkeys: &[BlsPubkey], now_secs: u64) -> Current {
        // A poisoned lock is recovered: every write is one map operation, so
        // the data behind it is never half-changed.
        let mut signed = self
            .signed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut current = Current {
            all: Vec::with_capacity(pubkeys.len()),
            changed: Vec::new(),
            no_fee_recipient: 0,
        };
        for pubkey in pubkeys {
            let Some(fee_recipient) = self.settings.fee_recipient(pubkey) else {
                current.no_fee_recipient += 1;
                continue;
            };
            let gas_limit = self.settings.gas_limit(pubkey);

            if let Some(held) = signed.get(pubkey)
                && held.message.fee_recipient == fee_recipient
                && held.message.gas_limit == gas_limit
            {
                current.all.push(held.clone());
                continue;
            }

            let message = ValidatorRegistrationV1 {
                fee_recipient,
                gas_limit,
                timestamp: now_secs,
                pubkey: *pubkey,
            };
            // A key the keymanager removed since the epoch refresh is the one
            // way this fails; the next refresh no longer lists it.
            let signature = match self.context.sign_validator_registration(store, &message) {
                Ok(signature) => signature,
                Err(err) => {
                    warn!(pubkey = %encode_hex(&pubkey.0), %err, "Could not sign a builder registration; skipping it");
                    continue;
                }
            };
            let registration = SignedValidatorRegistrationV1 { message, signature };
            signed.insert(*pubkey, registration.clone());
            current.all.push(registration.clone());
            current.changed.push(registration);
        }
        current
    }

    /// Whether `epoch` is at or after gloas, where there is nothing to register.
    fn is_gloas(&self, epoch: Epoch) -> bool {
        self.context.config.fork_at_epoch(epoch) >= ForkName::Gloas
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    }

    /// [`Self::current`] over `pubkeys`, off the async runtime, [`SIGN_CHUNK`]
    /// keys per blocking task with the store's read lock taken per chunk.
    async fn current_blocking(
        self: &Arc<Self>,
        store: &Arc<RwLock<ValidatorStore>>,
        pubkeys: &[BlsPubkey],
    ) -> Current {
        let now_secs = Self::now_secs();
        let mut current = Current {
            all: Vec::with_capacity(pubkeys.len()),
            changed: Vec::new(),
            no_fee_recipient: 0,
        };
        for chunk in pubkeys.chunks(SIGN_CHUNK) {
            let (service, store, chunk) = (self.clone(), store.clone(), chunk.to_vec());
            let part = tokio::task::spawn_blocking(move || {
                let store = store.blocking_read();
                service.current(&store, &chunk, now_secs)
            })
            .await;
            match part {
                Ok(part) => current.extend(part),
                Err(err) => warn!(%err, "Signing builder registrations failed; skipping a chunk"),
            }
        }
        current
    }

    /// Register every validator in `pubkeys`, the ones the beacon node resolved
    /// at this epoch's refresh. Called once per epoch.
    ///
    /// Also forgets any validator no longer in `pubkeys`, so a key the
    /// keymanager removed stops being re-signed (and warned about) every slot.
    pub async fn register_all(
        self: Arc<Self>,
        epoch: Epoch,
        pubkeys: Vec<BlsPubkey>,
        store: Arc<RwLock<ValidatorStore>>,
    ) {
        if self.is_gloas(epoch) {
            return;
        }
        // Read before signing, so a change that lands while this runs is seen
        // by the next `register_changed` rather than lost.
        let generation = self.settings.generation();
        let current_keys: HashSet<BlsPubkey> = pubkeys.iter().copied().collect();
        self.signed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|pubkey, _| current_keys.contains(pubkey));
        *self
            .known
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = pubkeys.clone();

        let current = self.current_blocking(&store, &pubkeys).await;
        self.signed_generation.store(generation, Ordering::Release);
        if current.no_fee_recipient > 0 {
            warn!(
                skipped = current.no_fee_recipient,
                "Validators without a fee recipient are not registered with the builder"
            );
        }
        self.send(current.all, REGISTRATION_BATCH).await;
    }

    /// Send only the registrations whose fee recipient or gas limit changed
    /// since they were last signed, over the validators the last
    /// [`Self::register_all`] was given. Called every slot, so a keymanager
    /// change reaches the builder within a slot rather than an epoch.
    ///
    /// Returns before touching the store when no setting was written since the
    /// last signing: see the module doc.
    ///
    /// Silent about validators with no fee recipient: that is reported once
    /// per epoch by [`Self::register_all`], not repeated every slot.
    pub async fn register_changed(
        self: Arc<Self>,
        epoch: Epoch,
        store: Arc<RwLock<ValidatorStore>>,
    ) {
        if self.is_gloas(epoch) {
            return;
        }
        let generation = self.settings.generation();
        if generation == self.signed_generation.load(Ordering::Acquire) {
            return;
        }
        let known = self
            .known
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if known.is_empty() {
            return;
        }
        let current = self.current_blocking(&store, &known).await;
        self.signed_generation.store(generation, Ordering::Release);
        if current.changed.is_empty() {
            return;
        }
        self.send(current.changed, REGISTRATION_BATCH).await;
    }

    /// Send `registrations` to the beacon node in chunks of `batch_size`.
    ///
    /// The size is a parameter so a test can see the chunking without signing
    /// hundreds of keys.
    async fn send(&self, registrations: Vec<SignedValidatorRegistrationV1>, batch_size: usize) {
        for chunk in registrations.chunks(batch_size) {
            match self.beacon_node.register_validators(chunk).await {
                Ok(()) => {
                    debug!(count = chunk.len(), "Builder registrations sent");
                    crate::metrics::inc_builder_registrations_sent(chunk.len());
                }
                Err(err) => {
                    warn!(count = chunk.len(), %err, "No beacon node accepted the builder registrations");
                    crate::metrics::inc_builder_registration_failures();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_node::mock::MockBeaconNode;
    use crate::test_support::{settings, store_with_keys};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::primitives::{H160, Root};

    fn context(config: Config) -> Arc<SigningContext> {
        Arc::new(SigningContext {
            config,
            genesis_validators_root: Root::ZERO,
        })
    }

    fn service(
        config: Config,
        settings: Arc<ProposerSettings>,
    ) -> (
        Arc<RegistrationService<MockBeaconNode>>,
        Arc<MockBeaconNode>,
    ) {
        let node = Arc::new(MockBeaconNode::new());
        (
            Arc::new(RegistrationService::new(
                node.clone(),
                context(config),
                settings,
            )),
            node,
        )
    }

    #[test]
    fn registrations_are_signed_once_and_reused() {
        let (store, pubkeys) = store_with_keys(2);
        let (service, _) = service(Config::mainnet(), settings(Some(H160([0xab; 20]))));

        let first = service.current(&store, &pubkeys, 1_000);
        assert_eq!(first.all.len(), 2);
        assert_eq!(first.changed.len(), 2);

        let second = service.current(&store, &pubkeys, 2_000);
        assert_eq!(second.all, first.all, "same timestamp and signature");
        assert!(second.changed.is_empty());
        assert_eq!(second.all[0].message.timestamp, 1_000);
    }

    #[test]
    fn a_new_fee_recipient_or_gas_limit_re_signs() {
        let (store, pubkeys) = store_with_keys(3);
        let settings = settings(Some(H160([0xab; 20])));
        let (service, _) = service(Config::mainnet(), settings.clone());
        let first = service.current(&store, &pubkeys, 1_000);

        settings.set_fee_recipient(&pubkeys[0], H160([0xcd; 20]));
        settings.set_gas_limit(&pubkeys[1], 30_000_000);
        let second = service.current(&store, &pubkeys, 2_000);

        let changed: Vec<_> = second.changed.iter().map(|r| r.message.pubkey).collect();
        assert_eq!(changed, vec![pubkeys[0], pubkeys[1]]);
        assert_eq!(second.all[0].message.fee_recipient, H160([0xcd; 20]));
        assert_eq!(second.all[0].message.timestamp, 2_000);
        assert_eq!(second.all[1].message.gas_limit, 30_000_000);
        assert_eq!(second.all[1].message.timestamp, 2_000);
        assert_ne!(second.all[0].signature, first.all[0].signature);
        assert_eq!(second.all[2], first.all[2], "the third is untouched");
    }

    #[test]
    fn a_validator_without_a_fee_recipient_is_not_registered() {
        let (store, pubkeys) = store_with_keys(2);
        let settings = settings(None);
        settings.set_fee_recipient(&pubkeys[1], H160([0xcd; 20]));
        let (service, _) = service(Config::mainnet(), settings);

        let current = service.current(&store, &pubkeys, 1_000);

        assert_eq!(current.no_fee_recipient, 1);
        assert_eq!(current.all.len(), 1);
        assert_eq!(current.all[0].message.pubkey, pubkeys[1]);
    }

    #[test]
    fn a_removed_key_is_skipped_rather_than_failing_the_rest() {
        let (mut store, pubkeys) = store_with_keys(2);
        let (service, _) = service(Config::mainnet(), settings(Some(H160([0xab; 20]))));
        store.remove(&pubkeys[0]);

        let current = service.current(&store, &pubkeys, 1_000);

        assert_eq!(current.all.len(), 1);
        assert_eq!(current.all[0].message.pubkey, pubkeys[1]);
    }

    /// 501 keys is one more than a batch; signing them is a millisecond each.
    #[tokio::test]
    async fn register_all_sends_in_batches_of_500() {
        assert_eq!(REGISTRATION_BATCH, 500);
        let (store, pubkeys) = store_with_keys(REGISTRATION_BATCH + 1);
        let (service, node) = service(Config::mainnet(), settings(Some(H160([0xab; 20]))));
        let store = Arc::new(RwLock::new(store));

        service.register_all(0, pubkeys, store).await;

        assert_eq!(
            *node.registration_batches.lock().expect("lock"),
            vec![REGISTRATION_BATCH, 1]
        );
    }

    #[tokio::test]
    async fn send_chunks_by_the_size_it_is_given() {
        let (store, pubkeys) = store_with_keys(5);
        let (service, node) = service(Config::mainnet(), settings(Some(H160([0xab; 20]))));
        let current = service.current(&store, &pubkeys, 1_000);

        service.send(current.all, 2).await;

        assert_eq!(
            *node.registration_batches.lock().expect("lock"),
            vec![2, 2, 1]
        );
    }

    /// Both entry points stop at gloas, and `register_changed` is checked with
    /// something to send: a service that was filled before the fork and then
    /// had a setting changed.
    #[tokio::test]
    async fn nothing_is_sent_at_or_after_gloas() {
        let (store, pubkeys) = store_with_keys(2);
        let config = Config {
            gloas_fork_epoch: 4,
            ..Config::mainnet()
        };
        let settings = settings(Some(H160([0xab; 20])));
        let (service, node) = service(config, settings.clone());
        let store = Arc::new(RwLock::new(store));

        // Before the fork the service registers, and holds the keys.
        service
            .clone()
            .register_all(3, pubkeys.clone(), store.clone())
            .await;
        assert_eq!(*node.registration_batches.lock().expect("lock"), vec![2]);

        settings.set_gas_limit(&pubkeys[0], 30_000_000);
        service
            .clone()
            .register_all(4, pubkeys, store.clone())
            .await;
        service.clone().register_changed(5, store.clone()).await;
        assert_eq!(
            *node.registration_batches.lock().expect("lock"),
            vec![2],
            "a changed key is still not sent at or after the fork"
        );

        // The same change is sent when the epoch is before the fork.
        service.register_changed(3, store).await;
        assert_eq!(*node.registration_batches.lock().expect("lock"), vec![2, 1]);
    }

    #[tokio::test]
    async fn register_changed_sends_only_the_changed_keys() {
        let (store, pubkeys) = store_with_keys(3);
        let settings = settings(Some(H160([0xab; 20])));
        let (service, node) = service(Config::mainnet(), settings.clone());
        let store = Arc::new(RwLock::new(store));

        service
            .clone()
            .register_all(0, pubkeys.clone(), store.clone())
            .await;
        service.clone().register_changed(0, store.clone()).await;
        assert_eq!(
            *node.registration_batches.lock().expect("lock"),
            vec![3],
            "nothing changed, so nothing more is sent"
        );

        settings.set_gas_limit(&pubkeys[2], 30_000_000);
        service.register_changed(0, store).await;

        let registrations = node.registrations.lock().expect("lock");
        assert_eq!(registrations.len(), 4);
        assert_eq!(registrations[3].message.pubkey, pubkeys[2]);
        assert_eq!(registrations[3].message.gas_limit, 30_000_000);
    }

    /// The per-slot call is one atomic read when no setting moved: with the
    /// store write-locked, so any read of it would wait forever, it still
    /// returns at once, and sends nothing.
    #[tokio::test]
    async fn a_slot_with_no_change_makes_no_store_read_and_no_send() {
        let (store, pubkeys) = store_with_keys(2);
        let (service, node) = service(Config::mainnet(), settings(Some(H160([0xab; 20]))));
        let store = Arc::new(RwLock::new(store));
        service
            .clone()
            .register_all(0, pubkeys, store.clone())
            .await;
        let signed_before = service.signed.lock().expect("lock").clone();

        let _writer = store.write().await;
        tokio::time::timeout(
            std::time::Duration::from_millis(200),
            service.clone().register_changed(0, store.clone()),
        )
        .await
        .expect("returns without waiting on the store");

        assert_eq!(*node.registration_batches.lock().expect("lock"), vec![2]);
        assert_eq!(*service.signed.lock().expect("lock"), signed_before);
    }

    /// A key that left the resolved set is dropped from the cache, so it is not
    /// re-signed (and warned about) at every change.
    #[tokio::test]
    async fn a_key_no_longer_resolved_is_forgotten() {
        let (store, pubkeys) = store_with_keys(2);
        let (service, _node) = service(Config::mainnet(), settings(Some(H160([0xab; 20]))));
        let store = Arc::new(RwLock::new(store));

        service
            .clone()
            .register_all(0, pubkeys.clone(), store.clone())
            .await;
        service
            .clone()
            .register_all(0, vec![pubkeys[1]], store)
            .await;

        let signed = service.signed.lock().expect("lock");
        assert_eq!(signed.keys().copied().collect::<Vec<_>>(), vec![pubkeys[1]]);
        assert_eq!(*service.known.lock().expect("lock"), vec![pubkeys[1]]);
    }
}
