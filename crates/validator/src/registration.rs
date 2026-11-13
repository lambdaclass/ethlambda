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
//! failed send is logged and counted and the caller moves on.
//!
//! A per-slot send that no node accepts is sent again at every slot until one
//! does: it carries a keymanager change, and until a node takes it the builder
//! keeps paying the old fee recipient. The registrations are re-sent as they
//! were signed, so nothing is re-signed and their timestamps stay put, and
//! [`RegistrationService::signed_generation`] stays behind meanwhile, which
//! keeps the per-slot check below one atomic read. A full send that fails
//! waits for the next epoch's instead: re-sending every key each slot would
//! load a node that is already failing, and the next full send carries them
//! all anyway. A full send ends every per-slot retry, delivered or not, so a
//! node that keeps refusing costs a warning a slot for an epoch at most.
//!
//! A batch a node refuses with a 400 is not split to find the entry it
//! objects to: every entry is signed here by keys this client holds, so a
//! refusal says more about the node or the relay than about one entry, and no
//! other client splits either.
//!
//! # Each node works through the batches on its own
//!
//! The full set goes out in batches of [`REGISTRATION_BATCH`], and each node
//! is sent its batches in turn beside the other nodes rather than in step with
//! them (see [`BeaconNodeApi::register_validators_in_batches`]). A node that
//! hangs costs only its own batches, and only one timeout: what it has not
//! been sent by then is dropped until the next epoch.
//!
//! # One send at a time, and the newest registration last
//!
//! An ethlambda beacon node keeps the fee recipient of every registration it
//! is sent, newest timestamp or not, so the order sends reach a node in is the
//! order its fee recipients end up in. Every send therefore takes one lock,
//! [`RegistrationService::sending`], before it reads the cache and holds it
//! until the last batch is answered. A per-slot send can then never be
//! overtaken by an older registration from a full send that read the cache
//! before the change, and no batch of either is still in flight when the next
//! begins. The one window left is a request this client gave up on at its
//! timeout that the node still processes afterwards; the next epoch's full
//! send, which carries the newest registration, closes it.
//!
//! A per-slot send that finds the lock taken skips: it has not marked its
//! change as sent, so a later slot picks it up. While a full send runs, that
//! is the first slot after it ends, and a full send lasts as long as its
//! slowest node takes over every batch. A node has 12 s to answer each one
//! (one that takes longer is treated as unreachable and sent no more), so the
//! wait is at most 12 s per [`REGISTRATION_BATCH`] validators. An ethlambda
//! node whose relay does not answer comes close: it replies to each batch
//! with a 500 once its own 10 s wait on the relay runs out, and is still sent
//! the rest. With 5,000 validators, ten batches, a keymanager change then
//! waits about 100 s, eight slots, and two minutes at most.
//!
//! A full send waits for a running per-slot send instead, since that send is
//! short and skipping would cost an epoch. A full send that finds the
//! previous full send still running, or waiting, skips to the next epoch (see
//! [`crate::in_flight`]), so a hung node cannot queue up one waiting send per
//! epoch.
//!
//! # Signing stays off the async runtime
//!
//! The first epoch signs one BLS signature per validator. That runs on the
//! blocking pool in chunks of [`SIGN_CHUNK`], taking the store's read lock
//! afresh for each chunk, so neither the runtime's threads nor a queued
//! keymanager writer wait on thousands of signatures. The cache's own lock is
//! only ever taken under [`RegistrationService::sending`], so nothing on the
//! runtime waits on a chunk that holds it.
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
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, warn};

use crate::beacon_node::dto::encode_hex;
use crate::beacon_node::{BeaconNodeApi, REGISTRATION_BATCH};
use crate::in_flight::InFlight;
use crate::keys::ValidatorStore;
use crate::proposer_settings::ProposerSettings;
use crate::signing::SigningContext;

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
    /// Chunks whose signing task failed, so whose validators are in neither
    /// list.
    failed_chunks: usize,
}

impl Current {
    fn extend(&mut self, other: Current) {
        self.all.extend(other.all);
        self.changed.extend(other.changed);
        self.no_fee_recipient += other.no_fee_recipient;
        self.failed_chunks += other.failed_chunks;
    }
}

/// The timestamp for a registration replacing `held`: `now_secs`, or one
/// second past `held`'s when the clock does not say later.
///
/// A relay keeps a validator's registration with the latest timestamp and
/// drops one that is not newer. Two settings changes within one second, or a
/// wall clock stepped back between them, would otherwise sign the new settings
/// under a timestamp the relay ignores. The cached registration is then re-sent
/// every epoch while the builder keeps the old fee recipient or gas limit.
///
/// Two changes within a second put it one second ahead of the clock, which no
/// relay refuses as being in the future. After a larger backward step it is
/// further ahead: a relay may refuse it until its own clock catches up, and the
/// epoch's full re-send then delivers it. With the clock's own reading
/// instead, the relay would drop it as older on every re-send, since the
/// cached signature keeps that timestamp until the settings change again.
fn newer_than(held: Option<&SignedValidatorRegistrationV1>, now_secs: u64) -> u64 {
    held.map_or(now_secs, |held| {
        now_secs.max(held.message.timestamp.saturating_add(1))
    })
}

/// Signs and sends builder registrations.
pub struct RegistrationService<B> {
    beacon_node: Arc<B>,
    context: Arc<SigningContext>,
    settings: Arc<ProposerSettings>,
    /// The validators the beacon node resolved at the last epoch refresh.
    /// Taken under [`Self::sending`] only.
    known: std::sync::Mutex<Vec<BlsPubkey>>,
    /// The latest signed registration per validator. Taken under
    /// [`Self::sending`] only, so it is never contended: a `std` mutex is
    /// enough, and a signing chunk holding it keeps no one else waiting.
    signed: std::sync::Mutex<HashMap<BlsPubkey, SignedValidatorRegistrationV1>>,
    /// The [`ProposerSettings::generation`] the cache was last brought up to
    /// date against. Held behind while [`Self::unsent`] is not empty, so the
    /// next per-slot call retries it.
    signed_generation: AtomicU64,
    /// Validators whose newest registration a per-slot send could not get any
    /// node to accept: sent again, as signed, at every slot until one does or
    /// the next full send, which carries them anyway, ends the retry. Taken
    /// under [`Self::sending`] only.
    unsent: std::sync::Mutex<HashSet<BlsPubkey>>,
    /// Held by a send from before it reads the cache until its last batch is
    /// answered, so sends reach every node in the order they read the cache.
    /// See the module doc.
    sending: Mutex<()>,
    /// The epoch's full send, while it runs or waits for [`Self::sending`].
    full_send: InFlight,
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
            unsent: std::sync::Mutex::new(HashSet::new()),
            sending: Mutex::new(()),
            full_send: InFlight::default(),
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
            failed_chunks: 0,
        };
        for pubkey in pubkeys {
            let Some((fee_recipient, gas_limit)) =
                self.settings.fee_recipient_and_gas_limit(pubkey)
            else {
                current.no_fee_recipient += 1;
                continue;
            };

            let held = signed.get(pubkey);
            if let Some(held) = held
                && held.message.fee_recipient == fee_recipient
                && held.message.gas_limit == gas_limit
            {
                current.all.push(held.clone());
                continue;
            }

            let message = ValidatorRegistrationV1 {
                fee_recipient,
                gas_limit,
                timestamp: newer_than(held, now_secs),
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
            failed_chunks: 0,
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
                Err(err) => {
                    warn!(%err, "Signing builder registrations failed; skipping a chunk");
                    current.failed_chunks += 1;
                }
            }
        }
        current
    }

    /// Record that every setting up to `generation` is signed and sent,
    /// unless a chunk of the signing failed (`failed_chunks`) or a registration
    /// is waiting to be sent again ([`Self::unsent`]). Then the generation
    /// stays behind, so the next slot's [`Self::register_changed`] signs what
    /// that chunk held, or re-sends what no node took, rather than leaving a
    /// keymanager change unsent for an epoch.
    fn mark_signed(&self, generation: u64, failed_chunks: usize) {
        if failed_chunks == 0 && self.unsent().is_empty() {
            self.signed_generation.store(generation, Ordering::Release);
        }
    }

    /// [`Self::unsent`], locked. A poisoned lock is recovered: every write is
    /// one set operation.
    fn unsent(&self) -> std::sync::MutexGuard<'_, HashSet<BlsPubkey>> {
        self.unsent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
        let Some(_running) = self.full_send.enter() else {
            warn!(
                epoch,
                "The previous builder registration send is still running; skipping this epoch's"
            );
            return;
        };
        // Waits out a per-slot send rather than skipping: that one is short,
        // and the full set is sent once an epoch.
        let _sending = self.sending.lock().await;
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
        if current.no_fee_recipient > 0 {
            warn!(
                skipped = current.no_fee_recipient,
                "Validators without a fee recipient are not registered with the builder"
            );
        }
        self.send(&current.all).await;
        // This send carried every key, so it ends each per-slot retry: a key it
        // delivered needs no more, and one it did not waits for the next
        // epoch's full send with the rest of its batch.
        self.unsent().clear();
        self.mark_signed(generation, current.failed_chunks);
    }

    /// Send only the registrations whose fee recipient or gas limit changed
    /// since they were last signed, over the validators the last
    /// [`Self::register_all`] was given, plus any an earlier slot could not
    /// get a node to accept ([`Self::unsent`]). Called every slot, so a
    /// keymanager change reaches the builder within a slot rather than an
    /// epoch.
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
        if self.settings.generation() == self.signed_generation.load(Ordering::Acquire) {
            return;
        }
        // Silently: another send is running, and the change stays unsent, so
        // the next slot picks it up.
        let Ok(_sending) = self.sending.try_lock() else {
            return;
        };
        // Again, under the lock: a full send that just ended may have signed
        // this change already.
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
        // What changed, and what an earlier slot could not get any node to
        // take. Both are read off `all`, the newest registration per key, so a
        // key that changed again since its failed send goes out once, as now.
        let retry = std::mem::take(&mut *self.unsent());
        let changed: HashSet<BlsPubkey> = current
            .changed
            .iter()
            .map(|registration| registration.message.pubkey)
            .collect();
        let outgoing: Vec<SignedValidatorRegistrationV1> = current
            .all
            .into_iter()
            .filter(|registration| {
                let pubkey = &registration.message.pubkey;
                changed.contains(pubkey) || retry.contains(pubkey)
            })
            .collect();
        if !outgoing.is_empty() {
            let failed = self.send(&outgoing).await;
            self.unsent().extend(failed);
        }
        self.mark_signed(generation, current.failed_chunks);
    }

    /// Send `registrations` to the beacon node in batches, counting each batch
    /// as sent when a node accepted it and as a failure when none did.
    ///
    /// Returns the validators in the batches no node accepted.
    async fn send(&self, registrations: &[SignedValidatorRegistrationV1]) -> HashSet<BlsPubkey> {
        let outcomes = self
            .beacon_node
            .register_validators_in_batches(registrations)
            .await;
        let mut failed = HashSet::new();
        for (batch, outcome) in registrations.chunks(REGISTRATION_BATCH).zip(outcomes) {
            let count = batch.len();
            // Only logged and counted: see "Failures are never propagated".
            let refused = outcome
                .inspect(|()| {
                    debug!(count, "Builder registrations sent");
                    crate::metrics::inc_builder_registrations_sent(count);
                })
                .inspect_err(|err| {
                    warn!(count, %err, "No beacon node accepted the builder registrations");
                    crate::metrics::inc_builder_registration_failures();
                })
                .is_err();
            if refused {
                failed.extend(batch.iter().map(|registration| registration.message.pubkey));
            }
        }
        failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_node::mock::MockBeaconNode;
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::primitives::{Bytes32, H160, Root};
    use tokio::sync::Semaphore;

    fn context(config: Config) -> Arc<SigningContext> {
        Arc::new(SigningContext {
            config,
            genesis_validators_root: Root::ZERO,
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

    fn settings(fee_recipient: Option<H160>) -> Arc<ProposerSettings> {
        Arc::new(ProposerSettings::new(Bytes32::ZERO, fee_recipient))
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

    /// A relay drops a registration that is not newer than the one it holds,
    /// so a change signed within the same second, or after the clock stepped
    /// back, still gets a later timestamp than the registration it replaces.
    #[test]
    fn a_re_signed_registration_is_always_newer_than_the_last() {
        let (store, pubkeys) = store_with_keys(1);
        let settings = settings(Some(H160([0xab; 20])));
        let (service, _) = service(Config::mainnet(), settings.clone());
        let first = service.current(&store, &pubkeys, 2_000);
        assert_eq!(first.all[0].message.timestamp, 2_000);

        settings.set_gas_limit(&pubkeys[0], 30_000_000);
        let same_second = service.current(&store, &pubkeys, 2_000);
        assert_eq!(same_second.changed[0].message.timestamp, 2_001);

        settings.set_gas_limit(&pubkeys[0], 31_000_000);
        let stepped_back = service.current(&store, &pubkeys, 1_000);
        assert_eq!(stepped_back.changed[0].message.timestamp, 2_002);

        // Once the clock is ahead again, its reading is used.
        settings.set_gas_limit(&pubkeys[0], 32_000_000);
        let caught_up = service.current(&store, &pubkeys, 5_000);
        assert_eq!(caught_up.changed[0].message.timestamp, 5_000);
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

    /// A service over a node whose `register_validators` calls each wait for
    /// a permit from the returned gate, which starts with `permits`.
    fn gated_service(
        settings: Arc<ProposerSettings>,
        permits: usize,
    ) -> (
        Arc<RegistrationService<MockBeaconNode>>,
        Arc<MockBeaconNode>,
        Arc<Semaphore>,
    ) {
        let gate = Arc::new(Semaphore::new(permits));
        let node = Arc::new(MockBeaconNode::new().with_registration_gate(gate.clone()));
        let service = Arc::new(RegistrationService::new(
            node.clone(),
            context(Config::mainnet()),
            settings,
        ));
        (service, node, gate)
    }

    /// Bounds a call that must return on its own, so a regression fails the
    /// test rather than hanging it.
    async fn promptly<F: std::future::Future>(what: &str, call: F) -> F::Output {
        tokio::time::timeout(std::time::Duration::from_secs(5), call)
            .await
            .unwrap_or_else(|_| panic!("{what}"))
    }

    /// A full send that is still waiting on a slow node makes the next one
    /// skip, rather than both holding the set and sending it again; once it
    /// ends, the next one runs.
    #[tokio::test]
    async fn an_epoch_send_still_running_makes_the_next_one_skip() {
        let (store, pubkeys) = store_with_keys(2);
        let (service, node, gate) = gated_service(settings(Some(H160([0xab; 20]))), 0);
        let store = Arc::new(RwLock::new(store));

        let slow = tokio::spawn(
            service
                .clone()
                .register_all(0, pubkeys.clone(), store.clone()),
        );
        node.wait_for_registration_calls(1).await;
        promptly(
            "skips rather than waiting on the node",
            service
                .clone()
                .register_all(1, pubkeys.clone(), store.clone()),
        )
        .await;
        gate.add_permits(1);
        slow.await.expect("the first send ends");
        assert_eq!(
            *node.registration_batches.lock().expect("lock"),
            vec![2],
            "only the first send reached the node"
        );

        gate.add_permits(1);
        service.register_all(2, pubkeys, store).await;
        assert_eq!(*node.registration_batches.lock().expect("lock"), vec![2, 2]);
    }

    /// The reviewer's race: a full send holds the registrations it read
    /// before a change, and a per-slot send must not deliver the change while
    /// that older copy is still to reach the node, or the older one lands last
    /// and the node keeps its fee recipient. The per-slot send skips instead,
    /// and the next slot's delivers the change after the full send.
    #[tokio::test]
    async fn a_change_is_never_overtaken_by_a_full_send_that_read_before_it() {
        let (store, pubkeys) = store_with_keys(2);
        let settings = settings(Some(H160([0xab; 20])));
        let (service, node, gate) = gated_service(settings.clone(), 0);
        let store = Arc::new(RwLock::new(store));

        // The full send has read the cache and is at the node.
        let full = tokio::spawn(
            service
                .clone()
                .register_all(0, pubkeys.clone(), store.clone()),
        );
        node.wait_for_registration_calls(1).await;

        settings.set_fee_recipient(&pubkeys[0], H160([0xcd; 20]));
        promptly(
            "the per-slot send skips rather than waiting on the node",
            service.clone().register_changed(0, store.clone()),
        )
        .await;
        assert_eq!(
            node.registration_attempts
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "nothing reached the node beside the full send"
        );

        gate.add_permits(1);
        full.await.expect("the full send ends");
        gate.add_permits(1);
        service.register_changed(0, store).await;

        let registrations = node.registrations.lock().expect("lock");
        let latest_for_first = registrations
            .iter()
            .rfind(|registration| registration.message.pubkey == pubkeys[0])
            .expect("registered");
        assert_eq!(
            latest_for_first.message.fee_recipient,
            H160([0xcd; 20]),
            "the change reaches the node last"
        );
        assert_eq!(*node.registration_batches.lock().expect("lock"), vec![2, 1]);
    }

    /// The other way round, the full send waits for a running per-slot send
    /// rather than skipping its epoch, and then sends the change too, since it
    /// reads the cache only once the per-slot send is done.
    #[tokio::test]
    async fn a_full_send_waits_for_a_running_per_slot_send() {
        let (store, pubkeys) = store_with_keys(2);
        let settings = settings(Some(H160([0xab; 20])));
        let (service, node, gate) = gated_service(settings.clone(), 1);
        let store = Arc::new(RwLock::new(store));
        service
            .clone()
            .register_all(0, pubkeys.clone(), store.clone())
            .await;

        settings.set_gas_limit(&pubkeys[1], 30_000_000);
        let changed = tokio::spawn(service.clone().register_changed(0, store.clone()));
        node.wait_for_registration_calls(2).await;
        let full = tokio::spawn(
            service
                .clone()
                .register_all(1, pubkeys.clone(), store.clone()),
        );
        // Long enough for a full send that skipped to have returned.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !full.is_finished(),
            "the full send waits rather than skipping"
        );

        gate.add_permits(2);
        changed.await.expect("the per-slot send ends");
        full.await.expect("the full send ends");

        assert_eq!(
            *node.registration_batches.lock().expect("lock"),
            vec![2, 1, 2]
        );
        let registrations = node.registrations.lock().expect("lock");
        assert_eq!(registrations[2].message.gas_limit, 30_000_000);
        assert_eq!(
            registrations[4], registrations[2],
            "the full send carries the change it waited for"
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

    fn refuse_registrations(node: &MockBeaconNode) {
        node.failures
            .lock()
            .expect("lock")
            .insert("register_validators", "relay down".to_string());
    }

    fn registration_calls(node: &MockBeaconNode) -> usize {
        node.registration_attempts
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// A change no node accepted goes out again at every slot, as it was
    /// signed, until a node takes it; the slot after that sends nothing.
    #[tokio::test]
    async fn a_change_no_node_accepted_is_sent_again_until_one_does() {
        let (store, pubkeys) = store_with_keys(2);
        let settings = settings(Some(H160([0xab; 20])));
        let (service, node) = service(Config::mainnet(), settings.clone());
        let store = Arc::new(RwLock::new(store));
        service
            .clone()
            .register_all(0, pubkeys.clone(), store.clone())
            .await;

        refuse_registrations(&node);
        settings.set_gas_limit(&pubkeys[1], 30_000_000);
        service.clone().register_changed(0, store.clone()).await;
        service.clone().register_changed(0, store.clone()).await;
        assert_eq!(registration_calls(&node), 3, "refused, then tried again");

        node.stop_failing("register_validators");
        service.clone().register_changed(0, store.clone()).await;
        let signed = service.signed.lock().expect("lock")[&pubkeys[1]].clone();
        {
            let registrations = node.registrations.lock().expect("lock");
            assert_eq!(
                registrations.len(),
                3,
                "the full send's two, then the change"
            );
            assert_eq!(registrations[2].message.gas_limit, 30_000_000);
            assert_eq!(
                registrations[2], signed,
                "re-sent as signed, not signed again"
            );
        }

        service.clone().register_changed(0, store.clone()).await;
        assert_eq!(registration_calls(&node), 4, "delivered, so nothing more");
    }

    /// A full send that delivers a key waiting for its retry ends the retry,
    /// and the slots after it go back to sending nothing.
    #[tokio::test]
    async fn a_full_send_that_delivers_a_waiting_change_ends_its_retry() {
        let (store, pubkeys) = store_with_keys(2);
        let settings = settings(Some(H160([0xab; 20])));
        let (service, node) = service(Config::mainnet(), settings.clone());
        let store = Arc::new(RwLock::new(store));
        service
            .clone()
            .register_all(0, pubkeys.clone(), store.clone())
            .await;

        refuse_registrations(&node);
        settings.set_gas_limit(&pubkeys[1], 30_000_000);
        service.clone().register_changed(0, store.clone()).await;

        node.stop_failing("register_validators");
        service
            .clone()
            .register_all(1, pubkeys.clone(), store.clone())
            .await;
        service.clone().register_changed(1, store.clone()).await;
        assert_eq!(
            *node.registration_batches.lock().expect("lock"),
            vec![2, 2],
            "the two full sends, and no retry after the second"
        );
    }

    /// A full send ends the retry even when it is refused too: the change then
    /// waits for the next epoch's full send with the rest of the set, rather
    /// than costing a refused send at every slot for as long as the node
    /// refuses.
    #[tokio::test]
    async fn a_refused_full_send_ends_the_retry_too() {
        let (store, pubkeys) = store_with_keys(2);
        let settings = settings(Some(H160([0xab; 20])));
        let (service, node) = service(Config::mainnet(), settings.clone());
        let store = Arc::new(RwLock::new(store));
        service
            .clone()
            .register_all(0, pubkeys.clone(), store.clone())
            .await;

        refuse_registrations(&node);
        settings.set_gas_limit(&pubkeys[1], 30_000_000);
        service.clone().register_changed(0, store.clone()).await;
        service
            .clone()
            .register_all(1, pubkeys.clone(), store.clone())
            .await;
        assert_eq!(registration_calls(&node), 3, "full, per-slot, full");

        service.clone().register_changed(1, store.clone()).await;
        assert_eq!(registration_calls(&node), 3, "no retry after the full send");
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
