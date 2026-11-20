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
//! all anyway. A full send ends every per-slot retry it carries, delivered or
//! not, so a node that keeps refusing costs a warning a slot until the next
//! epoch's full send, which runs once that epoch's duty refresh succeeds. A
//! full send's own chunk whose signing failed is the exception: it carried
//! none of that chunk's keys, so the next slot sends them.
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
//! blocking pool in chunks of [`SIGN_CHUNK`], so the runtime's threads do not
//! compute thousands of local signatures. The store's read lock is taken per
//! signature and released before it is produced, so a queued keymanager
//! writer waits on no signature, remote or local. A remote key's signature is
//! a request to its signer, which the chunk waits on, bounded by
//! [`crate::signing::SIGNING_BUDGET`]; one that fails or runs out of budget
//! costs that key's registration, as a key the keymanager removed does. The
//! cache's own locks are only ever taken under
//! [`RegistrationService::sending`], and never held across a signature.
//!
//! # The per-slot check is one atomic read
//!
//! Only a keymanager write changes what a registration says, so
//! [`RegistrationService::register_changed`] compares
//! [`ProposerSettings::generation`] with the one it last signed against and
//! returns before touching the store when it has not moved. While something
//! is left to send (a retry, or a chunk whose signing failed) it holds
//! [`BEHIND`] instead, so each slot rescans until that is sent.

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
use crate::signing::{SigningContext, sign_all};

/// Keys signed per blocking task. No more than one remote signer is sent at
/// once ([`crate::keys::web3signer::MAX_CONCURRENT_REQUESTS`]), so a chunk's
/// requests all go out together and none waits on another for its turn
/// within the signing budget.
const SIGN_CHUNK: usize = 64;
const _: () = assert!(SIGN_CHUNK <= crate::keys::web3signer::MAX_CONCURRENT_REQUESTS);

/// What [`RegistrationService::signed_generation`] holds while something is
/// still to send. No [`ProposerSettings::generation`] reaches it, so the next
/// per-slot call runs whether or not a setting moved since.
const BEHIND: u64 = u64::MAX;

/// What [`RegistrationService::current`] found for a set of validators.
struct Current {
    /// Every validator's registration, cached or newly signed.
    all: Vec<SignedValidatorRegistrationV1>,
    /// The subset signed in this call, because it had no registration yet,
    /// its fee recipient or gas limit changed, or it lapsed (see
    /// [`RegistrationService::lapsed`]).
    changed: Vec<SignedValidatorRegistrationV1>,
    /// Validators skipped because no fee recipient is configured for them.
    no_fee_recipient: usize,
    /// Validators in a chunk whose signing task failed, so in neither list.
    /// The chunk cached nothing, so a change among them is still to be signed.
    in_failed_chunks: HashSet<BlsPubkey>,
}

impl Current {
    fn extend(&mut self, other: Current) {
        self.all.extend(other.all);
        self.changed.extend(other.changed);
        self.no_fee_recipient += other.no_fee_recipient;
        self.in_failed_chunks.extend(other.in_failed_chunks);
    }
}

/// How far ahead of its own clock the flashbots relay takes a registration's
/// timestamp: one further ahead fails its whole request.
const RELAY_FUTURE_TOLERANCE_SECS: u64 = 10;

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
/// epoch's full re-send then delivers it. Meanwhile it costs its whole batch:
/// the flashbots relay refuses a request over one timestamp more than ten
/// seconds ahead, as it does over one unknown key. With the clock's own
/// reading instead, the relay would drop it as older on every re-send, since
/// the cached signature keeps that timestamp until the settings change again.
/// Capping it near the clock would do the same.
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
    /// enough, and it is never held across a signature.
    /// Written only once a chunk is signed in full, so a key is cached only
    /// when its registration reaches the send.
    signed: std::sync::Mutex<HashMap<BlsPubkey, SignedValidatorRegistrationV1>>,
    /// The [`ProposerSettings::generation`] the cache was last brought up to
    /// date against, or [`BEHIND`] while [`Self::unsent`] is not empty or a
    /// chunk's signing failed, so the next per-slot call sends what is left.
    signed_generation: AtomicU64,
    /// Validators whose newest registration a per-slot send could not get any
    /// node to accept, or that a full send left out because their chunk's
    /// signing failed: sent at every slot until a node accepts them or a full
    /// send carries them, which ends the retry. Taken under [`Self::sending`]
    /// only.
    unsent: std::sync::Mutex<HashSet<BlsPubkey>>,
    /// Validators that could not be registered (no fee recipient, or a key
    /// that would not sign) while a registration of theirs was cached. A retry
    /// ends with such a key, so that registration may never have reached a
    /// node: once the key can be registered again it is signed afresh rather
    /// than found unchanged. Taken under [`Self::sending`] only.
    lapsed: std::sync::Mutex<HashSet<BlsPubkey>>,
    /// Held by a send from before it reads the cache until its last batch is
    /// answered, so sends reach every node in the order they read the cache.
    /// See the module doc.
    sending: Mutex<()>,
    /// The epoch's full send, while it runs or waits for [`Self::sending`].
    full_send: InFlight,
    /// A key whose signing panics, so a test can fail a chunk: nothing else
    /// can.
    #[cfg(test)]
    panic_signing: std::sync::Mutex<Option<BlsPubkey>>,
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
            lapsed: std::sync::Mutex::new(HashSet::new()),
            sending: Mutex::new(()),
            full_send: InFlight::default(),
            #[cfg(test)]
            panic_signing: std::sync::Mutex::new(None),
        }
    }

    /// [`Self::signed`], locked. A poisoned lock is recovered: every write is
    /// one map operation, so the data behind it is never half-changed.
    fn signed(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<BlsPubkey, SignedValidatorRegistrationV1>> {
        self.signed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// [`Self::lapsed`], locked, and recovered from poisoning like
    /// [`Self::signed`].
    fn lapsed(&self) -> std::sync::MutexGuard<'_, HashSet<BlsPubkey>> {
        self.lapsed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The registration for each of `pubkeys` as of `now_secs`, signing only
    /// the ones whose `(fee_recipient, gas_limit)` differs from the cached one.
    ///
    /// Three steps, so no lock is held across a signature, which for a remote
    /// key is a round trip: what to reuse and what to sign is decided under
    /// the cache's locks, the signatures are asked for together through
    /// [`sign_all`] with the locks released (the store's read guard is taken
    /// per lookup, inside the signer), and the cache is written last, so a key
    /// is cached only once its chunk is signed in full.
    ///
    /// `now_secs` is a parameter so a test can fix the timestamp.
    async fn current(
        &self,
        store: &RwLock<ValidatorStore>,
        pubkeys: &[BlsPubkey],
        now_secs: u64,
    ) -> Current {
        /// Where a validator's registration comes from, in `pubkeys`' order.
        enum Source {
            Held(SignedValidatorRegistrationV1),
            /// An index into `owed`.
            Owed(usize),
        }

        let mut newly_lapsed = Vec::new();
        let mut no_fee_recipient = 0;
        let mut order = Vec::with_capacity(pubkeys.len());
        // Each message to sign, and whether a registration of its key was
        // cached before it.
        let mut owed: Vec<(ValidatorRegistrationV1, bool)> = Vec::new();
        {
            let signed = self.signed();
            let lapsed = self.lapsed();
            for pubkey in pubkeys {
                #[cfg(test)]
                if self.panic_signing.lock().expect("lock").as_ref() == Some(pubkey) {
                    panic!("signing panicked, as the test asked");
                }

                let Some((fee_recipient, gas_limit)) =
                    self.settings.fee_recipient_and_gas_limit(pubkey)
                else {
                    no_fee_recipient += 1;
                    if signed.contains_key(pubkey) {
                        newly_lapsed.push(*pubkey);
                    }
                    continue;
                };

                let held = signed.get(pubkey);
                if let Some(held) = held
                    && !lapsed.contains(pubkey)
                    && held.message.fee_recipient == fee_recipient
                    && held.message.gas_limit == gas_limit
                {
                    order.push(Source::Held(held.clone()));
                    continue;
                }

                let timestamp = newer_than(held, now_secs);
                if timestamp > now_secs + RELAY_FUTURE_TOLERANCE_SECS {
                    warn!(
                        pubkey = %encode_hex(&pubkey.0),
                        timestamp,
                        now = now_secs,
                        "A builder registration is signed ahead of the clock, which stepped back; \
                         the relay refuses its batch until the clock catches up"
                    );
                }
                let message = ValidatorRegistrationV1 {
                    fee_recipient,
                    gas_limit,
                    timestamp,
                    pubkey: *pubkey,
                };
                order.push(Source::Owed(owed.len()));
                owed.push((message, held.is_some()));
            }
        }

        let requests = owed.iter().map(|(message, _)| {
            let signature = self.context.sign_validator_registration(store, message);
            (message.pubkey, signature)
        });
        let signatures = sign_all(requests).await;

        // A key the keymanager removed since the epoch refresh, a remote
        // signer that refused or did not answer within the signing budget:
        // each costs that key's registration, never the chunk's.
        let mut signed_now: Vec<Option<SignedValidatorRegistrationV1>> = owed
            .into_iter()
            .zip(signatures)
            .map(|((message, was_held), signature)| match signature {
                Ok(signature) => Some(SignedValidatorRegistrationV1 { message, signature }),
                Err(err) => {
                    warn!(
                        pubkey = %encode_hex(&message.pubkey.0),
                        %err,
                        "Could not sign a builder registration; skipping it"
                    );
                    if was_held {
                        newly_lapsed.push(message.pubkey);
                    }
                    None
                }
            })
            .collect();

        let mut current = Current {
            all: Vec::with_capacity(order.len()),
            changed: Vec::new(),
            no_fee_recipient,
            in_failed_chunks: HashSet::new(),
        };
        for source in order {
            match source {
                Source::Held(registration) => current.all.push(registration),
                Source::Owed(index) => {
                    if let Some(registration) = signed_now[index].take() {
                        current.all.push(registration.clone());
                        current.changed.push(registration);
                    }
                }
            }
        }

        // Cached only now that the chunk is signed in full: a key cached by a
        // chunk that then panicked would never reach the send, and the next
        // call would find it unchanged and not send it either.
        let changed = current.changed.iter();
        self.signed().extend(
            changed.map(|registration| (registration.message.pubkey, registration.clone())),
        );
        let mut lapsed = self.lapsed();
        for registration in &current.changed {
            lapsed.remove(&registration.message.pubkey);
        }
        lapsed.extend(newly_lapsed);
        current
    }

    /// Whether `epoch` is at or after gloas, where there is nothing to register.
    fn is_gloas(&self, epoch: Epoch) -> bool {
        self.context.config().fork_at_epoch(epoch) >= ForkName::Gloas
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    }

    /// [`Self::current`] over `pubkeys`, [`SIGN_CHUNK`] keys per blocking
    /// task.
    ///
    /// Each chunk runs on the blocking pool and drives its signing there, so
    /// a local key's signature is computed off the runtime's threads, and a
    /// chunk that panics costs its own keys only. A remote key's signature is
    /// a request the chunk waits on, bounded by
    /// [`crate::signing::SIGNING_BUDGET`]; a chunk is no larger than the
    /// requests one signer is sent at once, so its keys go out together.
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
            in_failed_chunks: HashSet::new(),
        };
        for keys in pubkeys.chunks(SIGN_CHUNK) {
            let (service, store, chunk) = (self.clone(), store.clone(), keys.to_vec());
            // The runtime the chunk's requests and timers run on: a blocking
            // thread is outside it, so it enters it to wait on them.
            let runtime = tokio::runtime::Handle::current();
            let part = tokio::task::spawn_blocking(move || {
                runtime.block_on(service.current(&store, &chunk, now_secs))
            })
            .await;
            match part {
                Ok(part) => current.extend(part),
                Err(err) => {
                    warn!(%err, "Signing builder registrations failed; skipping a chunk");
                    current.in_failed_chunks.extend(keys);
                }
            }
        }
        current
    }

    /// Record that every setting up to `generation` is signed and sent,
    /// unless a chunk of the signing failed (`in_failed_chunks` is not empty)
    /// or a registration is waiting to be sent again ([`Self::unsent`]). Then
    /// it records [`BEHIND`], so the next slot's [`Self::register_changed`]
    /// signs what that chunk held, or re-sends what no node took, even when no
    /// setting moved, rather than leaving it for the next epoch.
    fn mark_signed(&self, generation: u64, in_failed_chunks: &HashSet<BlsPubkey>) {
        let done = in_failed_chunks.is_empty() && self.unsent().is_empty();
        let marked = if done { generation } else { BEHIND };
        self.signed_generation.store(marked, Ordering::Release);
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
        self.lapsed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|pubkey| current_keys.contains(pubkey));
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
        // This send carried every key it could register, so it ends their
        // per-slot retries: a key it delivered needs no more, and one it did
        // not waits for the next epoch's full send with the rest of its batch.
        // A key in a failed chunk was not carried, so the next slot sends it,
        // changed or not. One it could not register lapsed instead.
        *self.unsent() = current.in_failed_chunks.clone();
        self.mark_signed(generation, &current.in_failed_chunks);
    }

    /// Send only the registrations whose fee recipient or gas limit changed
    /// since they were last signed, over the validators the last
    /// [`Self::register_all`] was given, plus any an earlier slot could not
    /// get a node to accept ([`Self::unsent`]). Called every slot, so a
    /// keymanager change reaches the builder within a slot rather than an
    /// epoch.
    ///
    /// Returns before touching the store when no setting was written since the
    /// last signing and nothing is left to send: see the module doc.
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
        // A key waiting for its retry whose chunk failed is in neither list,
        // so not in `outgoing` either: it waits for the next slot again.
        let in_failed_chunk = retry.intersection(&current.in_failed_chunks);
        self.unsent().extend(in_failed_chunk);
        if !outgoing.is_empty() {
            let failed = self.send(&outgoing).await;
            self.unsent().extend(failed);
        }
        self.mark_signed(generation, &current.in_failed_chunks);
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
        // A batch with no outcome counts as refused rather than delivered.
        let mut outcomes = outcomes.into_iter();
        for batch in registrations.chunks(REGISTRATION_BATCH) {
            let outcome = outcomes.next().unwrap_or_else(|| {
                let detail = "the beacon node gave no outcome for this batch";
                Err(crate::error::Error::InconsistentResponse(
                    detail.to_string(),
                ))
            });
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
    use crate::test_support::{settings, store_with_keys};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::primitives::{H160, Root};
    use tokio::sync::Semaphore;

    fn context(config: Config) -> Arc<SigningContext> {
        Arc::new(SigningContext::new(config, Root::ZERO))
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

    #[tokio::test]
    async fn registrations_are_signed_once_and_reused() {
        let (store, pubkeys) = store_with_keys(2);
        let store = RwLock::new(store);
        let (service, _) = service(Config::mainnet(), settings(Some(H160([0xab; 20]))));

        let first = service.current(&store, &pubkeys, 1_000).await;
        assert_eq!(first.all.len(), 2);
        assert_eq!(first.changed.len(), 2);

        let second = service.current(&store, &pubkeys, 2_000).await;
        assert_eq!(second.all, first.all, "same timestamp and signature");
        assert!(second.changed.is_empty());
        assert_eq!(second.all[0].message.timestamp, 1_000);
    }

    #[tokio::test]
    async fn a_new_fee_recipient_or_gas_limit_re_signs() {
        let (store, pubkeys) = store_with_keys(3);
        let store = RwLock::new(store);
        let settings = settings(Some(H160([0xab; 20])));
        let (service, _) = service(Config::mainnet(), settings.clone());
        let first = service.current(&store, &pubkeys, 1_000).await;

        settings.set_fee_recipient(&pubkeys[0], H160([0xcd; 20]));
        settings.set_gas_limit(&pubkeys[1], 30_000_000);
        let second = service.current(&store, &pubkeys, 2_000).await;

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
    #[tokio::test]
    async fn a_re_signed_registration_is_always_newer_than_the_last() {
        let (store, pubkeys) = store_with_keys(1);
        let store = RwLock::new(store);
        let settings = settings(Some(H160([0xab; 20])));
        let (service, _) = service(Config::mainnet(), settings.clone());
        let first = service.current(&store, &pubkeys, 2_000).await;
        assert_eq!(first.all[0].message.timestamp, 2_000);

        settings.set_gas_limit(&pubkeys[0], 30_000_000);
        let same_second = service.current(&store, &pubkeys, 2_000).await;
        assert_eq!(same_second.changed[0].message.timestamp, 2_001);

        settings.set_gas_limit(&pubkeys[0], 31_000_000);
        let stepped_back = service.current(&store, &pubkeys, 1_000).await;
        assert_eq!(stepped_back.changed[0].message.timestamp, 2_002);

        // Once the clock is ahead again, its reading is used.
        settings.set_gas_limit(&pubkeys[0], 32_000_000);
        let caught_up = service.current(&store, &pubkeys, 5_000).await;
        assert_eq!(caught_up.changed[0].message.timestamp, 5_000);
    }

    #[tokio::test]
    async fn a_validator_without_a_fee_recipient_is_not_registered() {
        let (store, pubkeys) = store_with_keys(2);
        let store = RwLock::new(store);
        let settings = settings(None);
        settings.set_fee_recipient(&pubkeys[1], H160([0xcd; 20]));
        let (service, _) = service(Config::mainnet(), settings);

        let current = service.current(&store, &pubkeys, 1_000).await;

        assert_eq!(current.no_fee_recipient, 1);
        assert_eq!(current.all.len(), 1);
        assert_eq!(current.all[0].message.pubkey, pubkeys[1]);
    }

    #[tokio::test]
    async fn a_removed_key_is_skipped_rather_than_failing_the_rest() {
        let (mut store, pubkeys) = store_with_keys(2);
        let (service, _) = service(Config::mainnet(), settings(Some(H160([0xab; 20]))));
        store.remove(&pubkeys[0]);
        let store = RwLock::new(store);

        let current = service.current(&store, &pubkeys, 1_000).await;

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

    /// Makes signing `pubkey` panic, failing its chunk, or stops doing so.
    fn panic_signing(service: &RegistrationService<MockBeaconNode>, pubkey: Option<BlsPubkey>) {
        *service.panic_signing.lock().expect("lock") = pubkey;
    }

    /// The last registration `node` accepted for `pubkey`.
    fn latest(node: &MockBeaconNode, pubkey: &BlsPubkey) -> SignedValidatorRegistrationV1 {
        let registrations = node.registrations.lock().expect("lock");
        registrations
            .iter()
            .rfind(|registration| registration.message.pubkey == *pubkey)
            .expect("registered")
            .clone()
    }

    /// A chunk that panics part way through caches nothing, so a key it signed
    /// before the panic is signed again and sent at the next slot, rather than
    /// found unchanged there and left for the next epoch's full send.
    #[tokio::test]
    async fn a_failed_chunk_leaves_nothing_cached_unsent() {
        let (store, pubkeys) = store_with_keys(2);
        let settings = settings(Some(H160([0xab; 20])));
        let (service, node) = service(Config::mainnet(), settings.clone());
        let store = Arc::new(RwLock::new(store));
        service
            .clone()
            .register_all(0, pubkeys.clone(), store.clone())
            .await;

        settings.set_fee_recipient(&pubkeys[0], H160([0xcd; 20]));
        settings.set_fee_recipient(&pubkeys[1], H160([0xcd; 20]));
        // The first key is signed, then the second panics.
        panic_signing(&service, Some(pubkeys[1]));
        service.clone().register_changed(0, store.clone()).await;
        assert_eq!(
            registration_calls(&node),
            1,
            "the failed chunk sent nothing"
        );

        panic_signing(&service, None);
        service.clone().register_changed(0, store.clone()).await;
        assert_eq!(*node.registration_batches.lock().expect("lock"), vec![2, 2]);
        assert_eq!(
            latest(&node, &pubkeys[0]).message.fee_recipient,
            H160([0xcd; 20])
        );
        assert_eq!(
            latest(&node, &pubkeys[1]).message.fee_recipient,
            H160([0xcd; 20])
        );
    }

    /// A key waiting for its retry keeps waiting when its chunk fails at the
    /// next slot, rather than leaving the retry set with the failed chunk.
    #[tokio::test]
    async fn a_retry_survives_a_failed_chunk() {
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

        panic_signing(&service, Some(pubkeys[0]));
        service.clone().register_changed(0, store.clone()).await;
        assert_eq!(
            registration_calls(&node),
            2,
            "the failed chunk sent nothing"
        );

        panic_signing(&service, None);
        service.clone().register_changed(0, store.clone()).await;
        assert_eq!(registration_calls(&node), 3, "the retry goes out");
        assert_eq!(latest(&node, &pubkeys[1]).message.gas_limit, 30_000_000);
    }

    /// A full send whose chunk fails with no setting changed since the last
    /// one still sends that chunk's keys at the next slot: the per-slot check
    /// is held behind whether or not the generation moved.
    #[tokio::test]
    async fn a_failed_chunk_of_a_full_send_goes_out_at_the_next_slot() {
        let (store, pubkeys) = store_with_keys(2);
        let (service, node) = service(Config::mainnet(), settings(Some(H160([0xab; 20]))));
        let store = Arc::new(RwLock::new(store));

        panic_signing(&service, Some(pubkeys[1]));
        service
            .clone()
            .register_all(0, pubkeys.clone(), store.clone())
            .await;
        assert_eq!(registration_calls(&node), 0, "the only chunk failed");

        panic_signing(&service, None);
        service.clone().register_changed(0, store.clone()).await;
        assert_eq!(*node.registration_batches.lock().expect("lock"), vec![2]);
        service.clone().register_changed(0, store.clone()).await;
        assert_eq!(registration_calls(&node), 1, "delivered, so nothing more");
    }

    /// A retry ends when its key loses its fee recipient, so the registration
    /// it was retrying may never have reached a node. Setting the same address
    /// again signs and sends it, rather than finding it unchanged in the cache.
    #[tokio::test]
    async fn a_fee_recipient_set_again_after_a_lapse_is_sent() {
        let (store, pubkeys) = store_with_keys(1);
        let settings = settings(None);
        settings.set_fee_recipient(&pubkeys[0], H160([0xab; 20]));
        let (service, node) = service(Config::mainnet(), settings.clone());
        let store = Arc::new(RwLock::new(store));
        service
            .clone()
            .register_all(0, pubkeys.clone(), store.clone())
            .await;

        refuse_registrations(&node);
        settings.set_fee_recipient(&pubkeys[0], H160([0xcd; 20]));
        service.clone().register_changed(0, store.clone()).await;
        let refused = service.signed.lock().expect("lock")[&pubkeys[0]].clone();
        node.stop_failing("register_validators");
        settings.clear_fee_recipient(&pubkeys[0]);
        service.clone().register_changed(0, store.clone()).await;
        assert_eq!(
            registration_calls(&node),
            2,
            "nothing to send without an address"
        );

        settings.set_fee_recipient(&pubkeys[0], H160([0xcd; 20]));
        service.clone().register_changed(0, store.clone()).await;
        let latest = latest(&node, &pubkeys[0]);
        assert_eq!(latest.message.fee_recipient, H160([0xcd; 20]));
        assert!(
            latest.message.timestamp > refused.message.timestamp,
            "signed afresh, later than the registration it replaces"
        );
        assert_eq!(registration_calls(&node), 3);
    }

    /// The same for a key that would not sign (the keymanager removed it)
    /// while it waited for its retry: imported again with the same address,
    /// it is signed and sent rather than found unchanged.
    #[tokio::test]
    async fn a_key_imported_again_after_its_retry_ended_is_sent() {
        let (store, pubkeys) = store_with_keys(1);
        let settings = settings(Some(H160([0xab; 20])));
        let (service, node) = service(Config::mainnet(), settings.clone());
        let store = Arc::new(RwLock::new(store));
        service
            .clone()
            .register_all(0, pubkeys.clone(), store.clone())
            .await;

        refuse_registrations(&node);
        settings.set_fee_recipient(&pubkeys[0], H160([0xcd; 20]));
        service.clone().register_changed(0, store.clone()).await;
        node.stop_failing("register_validators");
        store.write().await.remove(&pubkeys[0]);
        settings.forget(&pubkeys[0]);
        service.clone().register_changed(0, store.clone()).await;
        assert_eq!(
            registration_calls(&node),
            2,
            "nothing signs for a removed key"
        );

        // `store_with_keys`' first secret.
        let mut secret = [0u8; 32];
        secret[24..].copy_from_slice(&1u64.to_be_bytes());
        let imported = store.write().await.insert_secret("test", &secret);
        assert_eq!(imported.expect("inserts"), pubkeys[0]);
        settings.set_fee_recipient(&pubkeys[0], H160([0xcd; 20]));
        service.clone().register_changed(0, store.clone()).await;
        let latest = latest(&node, &pubkeys[0]);
        assert_eq!(latest.message.fee_recipient, H160([0xcd; 20]));
        assert_eq!(registration_calls(&node), 3);
    }

    /// A full send does not carry the keys of a chunk that failed, so it does
    /// not end their retries.
    #[tokio::test]
    async fn a_full_send_keeps_the_retries_of_a_failed_chunk() {
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

        panic_signing(&service, Some(pubkeys[0]));
        service
            .clone()
            .register_all(1, pubkeys.clone(), store.clone())
            .await;
        assert_eq!(
            registration_calls(&node),
            2,
            "the failed chunk sent nothing"
        );

        panic_signing(&service, None);
        service.clone().register_changed(1, store.clone()).await;
        assert_eq!(registration_calls(&node), 3, "the retry goes out");
        assert_eq!(latest(&node, &pubkeys[1]).message.gas_limit, 30_000_000);
        assert_eq!(
            *node.registration_batches.lock().expect("lock"),
            vec![2, 2],
            "the unchanged key the full send left out goes out with it"
        );
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
