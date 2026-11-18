//! Doppelganger protection: a key starts signing attestations and blocks only
//! once its beacon node has watched it stay silent for a full epoch.
//!
//! A doppelganger is a second validator client running the same key, the
//! usual cause being a key moved to a new machine while the old one still
//! runs. Slashing protection cannot see it: each client's record holds only
//! what that client signed, so the two go on signing conflicting votes until
//! one of them is slashed. This module asks the beacon network instead,
//! through the standard `POST /eth/v1/validator/liveness/{epoch}`, whether
//! anyone has been seen acting for the key, and keeps the key's slashable
//! duties withheld until the answer is a full epoch of "no".
//!
//! # The rule, which is Lighthouse's
//!
//! A key registered in epoch `E` (at startup, or by a keymanager import) is
//! watched from epoch `E + 1`. Activity in `E` itself is never held against
//! it: that is very likely this same client's previous process, restarted
//! within the epoch, and counting it would stop every restart.
//!
//! The check runs three quarters into every slot and asks about the previous
//! epoch and the current one. A key found live in any epoch it is watched for
//! is a doppelganger, and the client stops (see [`Doppelganger::detected`]).
//! An epoch counts as clean only from the last slot of the epoch after it:
//! an attestation can be included up to the end of the following epoch, and
//! the node's answer reads the chain's participation as well as what it saw
//! on gossip, so asking any earlier would let a vote still on its way into a
//! block go unseen. Once [`DETECTION_EPOCHS`] epochs are clean the key signs.
//!
//! So a key registered in epoch `E` signs from `E + 3`: it misses two to three
//! epochs of attestations, which is the price of the protection and why it is
//! off unless asked for. At genesis the price would be every validator missing
//! those epochs together, which a new chain may not survive, so a key
//! registered in epoch 0 signs at once, as Lighthouse's do.
//!
//! # What is withheld, and what is not
//!
//! Only what a doppelganger makes slashable, and what the node counts towards
//! liveness: attestations, blocks (with their RANDAO reveal) and aggregates.
//! An aggregate is not slashable, but the node marks its aggregator live, so
//! one published by this client during the check would be read back as a
//! doppelganger of itself. Everything else goes on for a key under the check,
//! as it does in Lighthouse: its duties are fetched and its subnets
//! subscribed (selection proofs included), so the key is ready the moment it
//! is cleared, and it signs sync committee messages and contributions,
//! payload timeliness votes, builder registrations, proposer preferences and
//! voluntary exits. None of those is slashable, and an ethlambda beacon node
//! does not count any of them as liveness (it counts attestations, aggregates
//! and block proposers).
//!
//! The duty loop drops a withheld key's attester and proposer duties before
//! anything is recorded or asked of the beacon node, and
//! [`crate::signing::SigningContext`] refuses those four signatures for it on
//! its own as well, so a path that skipped the duty loop's filter still could
//! not sign one.
//!
//! # Failing towards silence
//!
//! Every gap leaves a key unable to sign rather than able to:
//! - A key the check does not know signs nothing (a key reaching the store by
//!   some path that did not register it is registered at the next check).
//! - A key with no validator index yet is not asked about, and stays withheld:
//!   with no index it has no duties to withhold either.
//! - Only an explicit `is_live: false` counts towards a clean epoch, and only
//!   when both of the tick's questions were answered. A failed query, or a
//!   node that is syncing (see [`BeaconNodeApi::liveness`]), makes no
//!   progress. The epoch it was deciding is not asked about again, since a
//!   node answers only for the previous, current and next epoch; the key
//!   waits for the next epoch to be seen clean instead, so a failure costs
//!   an epoch of signing, never an epoch of checking.
//!
//! # What it cannot do
//!
//! Detection is not prevention, and the check is not foolproof. Two clients
//! with the same key started together both see silence, since each withholds
//! while the other does, and both start signing. A doppelganger that is down
//! for the epochs this client checks goes unseen until it comes back, and by
//! then this client is no longer checking. It is a guard against the common
//! mistake, not a substitute for running a key in one place.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch, Slot, ValidatorIndex};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::beacon_node::dto::encode_hex;
use crate::beacon_node::{BeaconNodeApi, Liveness};
use crate::keys::ValidatorStore;
use crate::slot_clock::SlotClock;

/// How many clean epochs a key needs before it signs. Lighthouse's.
pub const DETECTION_EPOCHS: u64 = 1;

/// How far into each slot the check runs, as a fraction of the slot.
///
/// Late enough that the slot's attestations have been gossiped and the
/// node's view of them is settled, early enough that a check cleared in the
/// last slot of an epoch is done before the next epoch's first duties.
const CHECK_NUMERATOR: u32 = 3;
const CHECK_DENOMINATOR: u32 = 4;

/// One key's progress through the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Watch {
    /// The first epoch whose activity counts against the key; also the next
    /// epoch that can count as clean, so one epoch is never counted twice.
    first_checked_epoch: Epoch,
    /// Clean epochs still owed. Zero is a key that may sign.
    remaining_epochs: u64,
    /// The key's validator index, once the beacon node has one for it. An
    /// index never changes once assigned, so it is asked for only once.
    index: Option<ValidatorIndex>,
}

impl Watch {
    fn registered_in(epoch: Epoch) -> Self {
        Self {
            first_checked_epoch: epoch + 1,
            // See the module doc: a key registered at genesis has nobody else
            // to have been, and holding every key back at once could stall a
            // new chain.
            remaining_epochs: if epoch == 0 { 0 } else { DETECTION_EPOCHS },
            index: None,
        }
    }

    fn cleared(&self) -> bool {
        self.remaining_epochs == 0
    }
}

/// A validator the check found live in an epoch it was watched for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sighting {
    pub index: ValidatorIndex,
    pub pubkey: BlsPubkey,
    pub epoch: Epoch,
}

/// What one tick's answers did.
#[derive(Debug, Default, PartialEq, Eq)]
struct Applied {
    /// Keys found live in an epoch they are watched for.
    sightings: Vec<Sighting>,
    /// Keys whose last owed epoch was clean, and which may now sign.
    cleared: Vec<ValidatorIndex>,
    /// Whether the tick could count an epoch as clean, or had to give up on
    /// it for want of an answer.
    progressed: bool,
}

/// Which keys may sign, and the signal that stops the client when one may not
/// ever. Shared by the check's task, the duty loop, [`crate::signing`] and the
/// keymanager.
#[derive(Default)]
pub struct Doppelganger {
    watched: Mutex<HashMap<BlsPubkey, Watch>>,
    detected: CancellationToken,
    /// What was seen, for the error the client stops with.
    sightings: Mutex<Vec<Sighting>>,
    /// The epoch the beacon node was last asked for the indices of keys that
    /// have none. Once an epoch is enough: a key gets an index at an epoch
    /// boundary, and its check cannot start before the epoch after the one it
    /// was registered in anyway.
    resolved_in: Mutex<Option<Epoch>>,
}

/// The epoch `clock` is in now; epoch 0 before genesis.
pub fn current_epoch(clock: &SlotClock) -> Epoch {
    clock.now().map_or(0, |slot| clock.epoch_of(slot))
}

impl Doppelganger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start watching `pubkey`, registered in `epoch`, the epoch the
    /// client's clock is in. A key already watched starts again from here:
    /// a key imported again may have been anywhere since it was last held.
    pub fn register(&self, pubkey: BlsPubkey, epoch: Epoch) {
        self.watched().insert(pubkey, Watch::registered_in(epoch));
        crate::metrics::set_doppelganger_detecting(self.detecting() as u64);
    }

    /// [`Self::register`] in the epoch `clock` is in now: what a keymanager
    /// import does for each key it adds.
    pub fn register_now(&self, pubkey: BlsPubkey, clock: &SlotClock) {
        self.register(pubkey, current_epoch(clock));
    }

    /// Stop checking `pubkey`: what a keymanager delete does for each key it
    /// takes out of the store, so a check already in flight cannot read the
    /// copy the operator now runs elsewhere as a doppelganger. The next check
    /// would forget it anyway (see [`Self::reconcile`]); this closes the gap
    /// before it.
    pub fn forget(&self, pubkey: &BlsPubkey) {
        self.watched().remove(pubkey);
        crate::metrics::set_doppelganger_detecting(self.detecting() as u64);
    }

    /// [`Self::register`] for every key, under one lock.
    pub fn register_all(&self, pubkeys: &[BlsPubkey], epoch: Epoch) {
        let mut watched = self.watched();
        for pubkey in pubkeys {
            watched.insert(*pubkey, Watch::registered_in(epoch));
        }
        drop(watched);
        crate::metrics::set_doppelganger_detecting(self.detecting() as u64);
    }

    /// Whether `pubkey` may sign an attestation, a block, a RANDAO reveal or
    /// an aggregate: it is known, it has passed the check, and no key of this
    /// client has been seen elsewhere.
    ///
    /// Once anything is detected no key signs those again: the client is
    /// stopping, and what is left of the process until it does is no time to
    /// be signing.
    pub fn allows_signing(&self, pubkey: &BlsPubkey) -> bool {
        !self.is_detected() && self.watched().get(pubkey).is_some_and(Watch::cleared)
    }

    /// How many keys are still withheld.
    pub fn detecting(&self) -> usize {
        self.watched()
            .values()
            .filter(|watch| !watch.cleared())
            .count()
    }

    /// Whether a doppelganger has been seen.
    pub fn is_detected(&self) -> bool {
        self.detected.is_cancelled()
    }

    /// Resolves once a doppelganger has been seen. The duty loop races this,
    /// and stops the client when it wins: a key signing elsewhere means the
    /// deployment is not what the operator thinks it is, which takes an
    /// operator, not a retry.
    pub async fn detected(&self) {
        self.detected.cancelled().await;
    }

    /// What was seen: empty until [`Self::detected`] resolves.
    pub fn sightings(&self) -> Vec<Sighting> {
        self.sightings
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The map, whatever a panicking holder left it as: every write to it
    /// replaces a whole entry, so a poisoned map is still a consistent one.
    fn watched(&self) -> MutexGuard<'_, HashMap<BlsPubkey, Watch>> {
        self.watched.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Make the watched set the keys the store holds: forget a key no longer
    /// held, and watch from `epoch` one that is held but was never
    /// registered.
    ///
    /// Forgetting matters. A key the operator deleted, possibly because they
    /// moved it elsewhere, would otherwise go on being checked, and the copy
    /// they now run deliberately would stop this client. It also makes a key
    /// imported again start the check again, whoever imported it.
    fn reconcile(&self, held: &[BlsPubkey], epoch: Epoch) {
        let held: HashSet<&BlsPubkey> = held.iter().collect();
        let mut watched = self.watched();
        watched.retain(|pubkey, _| held.contains(pubkey));
        for pubkey in held {
            if !watched.contains_key(pubkey) {
                warn!(
                    pubkey = %encode_hex(&pubkey.0),
                    epoch,
                    "A held key was never registered for doppelganger protection; checking it \
                     from now, and it signs no attestation or block until it passes"
                );
                watched.insert(*pubkey, Watch::registered_in(epoch));
            }
        }
    }

    /// The keys still under the check that have no validator index yet.
    fn unresolved(&self) -> Vec<BlsPubkey> {
        self.watched()
            .iter()
            .filter(|(_, watch)| !watch.cleared() && watch.index.is_none())
            .map(|(pubkey, _)| *pubkey)
            .collect()
    }

    /// Record the indices the beacon node resolved, for keys that asked for
    /// one; an answer about any other key is ignored.
    fn set_indices(&self, resolved: impl IntoIterator<Item = (BlsPubkey, ValidatorIndex)>) {
        let mut watched = self.watched();
        for (pubkey, index) in resolved {
            if let Some(watch) = watched.get_mut(&pubkey)
                && watch.index.is_none()
            {
                watch.index = Some(index);
            }
        }
    }

    /// The keys still under the check that have an index, by index.
    fn checked_indices(&self) -> HashMap<ValidatorIndex, BlsPubkey> {
        self.watched()
            .iter()
            .filter(|(_, watch)| !watch.cleared())
            .filter_map(|(pubkey, watch)| Some((watch.index?, *pubkey)))
            .collect()
    }

    /// Apply one tick's answers, asked at `slot` about `asked`: the previous
    /// epoch's (`None` in epoch 0, where there is none, or when the query
    /// failed) and the current one's (`None` when the query failed).
    ///
    /// A key answered live in an epoch it is watched for is a sighting,
    /// whichever question it came from. An epoch counts as clean only for an
    /// explicit `false` in the previous epoch's answer, at the last slot of
    /// the current epoch (see the module doc), and only when the current
    /// epoch's question was answered too.
    fn apply(
        &self,
        slot: Slot,
        asked: &HashMap<ValidatorIndex, BlsPubkey>,
        previous: Option<&[Liveness]>,
        current: Option<&[Liveness]>,
    ) -> Applied {
        let epoch = slot / SLOTS_PER_EPOCH;
        let mut applied = Applied::default();
        let mut watched = self.watched();

        let answers = [
            epoch.checked_sub(1).zip(previous),
            current.map(|current| (epoch, current)),
        ];
        for (answered_epoch, answers) in answers.into_iter().flatten() {
            for answer in answers.iter().filter(|answer| answer.is_live) {
                let Some(pubkey) = asked.get(&answer.index) else {
                    continue;
                };
                let Some(watch) = watched.get(pubkey) else {
                    continue;
                };
                // Once per validator, at the earlier epoch it was seen in.
                let seen = applied.sightings.iter().any(|s| s.index == answer.index);
                if answered_epoch >= watch.first_checked_epoch && !seen {
                    applied.sightings.push(Sighting {
                        index: answer.index,
                        pubkey: *pubkey,
                        epoch: answered_epoch,
                    });
                }
            }
        }
        if !applied.sightings.is_empty() {
            self.sightings
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend(applied.sightings.iter().copied());
            self.detected.cancel();
            return applied;
        }

        let (Some(previous_epoch), Some(previous), Some(_)) =
            (epoch.checked_sub(1), previous, current)
        else {
            return applied;
        };
        applied.progressed = true;
        if !(slot + 1).is_multiple_of(SLOTS_PER_EPOCH) {
            return applied;
        }
        for answer in previous.iter().filter(|answer| !answer.is_live) {
            let Some(watch) = asked
                .get(&answer.index)
                .and_then(|pubkey| watched.get_mut(pubkey))
            else {
                continue;
            };
            if watch.cleared() || previous_epoch < watch.first_checked_epoch {
                continue;
            }
            watch.remaining_epochs -= 1;
            watch.first_checked_epoch = previous_epoch + 1;
            if watch.cleared() {
                applied.cleared.push(answer.index);
            }
        }
        applied
    }

    /// One tick of the check, for `slot`.
    ///
    /// Asks nothing once every key has passed, or when the keys left have no
    /// index yet: an empty index list is never sent, since some nodes refuse
    /// one and none has anything to say about it.
    pub async fn check<B: BeaconNodeApi>(
        &self,
        beacon_node: &B,
        store: &RwLock<ValidatorStore>,
        slot: Slot,
    ) {
        if self.is_detected() {
            return;
        }
        let epoch = slot / SLOTS_PER_EPOCH;
        {
            // Under the store's read guard, so a keymanager import (which
            // registers and inserts under the write guard) cannot land
            // between the snapshot and the forgetting.
            let held = store.read().await;
            self.reconcile(&held.pubkeys(), epoch);
        }

        let unresolved = self.unresolved();
        let resolved_in = *self
            .resolved_in
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !unresolved.is_empty() && resolved_in != Some(epoch) {
            match beacon_node.validator_indices(&unresolved).await {
                // Marked only on an answer: a node that failed is asked again
                // next slot, a key the node has no index for next epoch.
                Ok(entries) => {
                    self.set_indices(entries.into_iter().map(|entry| (entry.pubkey, entry.index)));
                    *self
                        .resolved_in
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner) = Some(epoch);
                }
                Err(err) => warn!(
                    %slot,
                    %err,
                    "Could not resolve the indices of validators under doppelganger protection"
                ),
            }
        }

        let asked = self.checked_indices();
        let detecting = self.detecting();
        crate::metrics::set_doppelganger_detecting(detecting as u64);
        if detecting > 0 && slot.is_multiple_of(SLOTS_PER_EPOCH) {
            info!(
                %epoch,
                validators = detecting,
                unresolved = detecting.saturating_sub(asked.len()),
                "Listening for doppelgangers; these validators sign no attestation or block yet"
            );
        }
        if asked.is_empty() {
            return;
        }
        let mut indices: Vec<ValidatorIndex> = asked.keys().copied().collect();
        indices.sort_unstable();

        // Both at once: through `HttpBeaconNode` each is a syncing check and
        // then the query, and the tick at an epoch's last slot, the only one
        // that can clear a key, should be done well before the next epoch's
        // first duties.
        let previous_epoch = epoch.checked_sub(1);
        let ask_previous = async {
            match previous_epoch {
                Some(previous) => Some(beacon_node.liveness(previous, &indices).await),
                None => None,
            }
        };
        let (previous, current) = tokio::join!(ask_previous, beacon_node.liveness(epoch, &indices));
        let failures: Vec<String> = previous_epoch
            .zip(previous.as_ref())
            .into_iter()
            .chain([(epoch, &current)])
            .filter_map(|(asked_epoch, answer)| {
                let err = answer.as_ref().err()?;
                Some(format!("epoch {asked_epoch}: {err}"))
            })
            .collect();
        if !failures.is_empty() {
            warn!(
                %slot,
                ?failures,
                "Doppelganger liveness query failed; this tick counts no epoch as clean"
            );
        }
        let previous = previous.and_then(Result::ok);
        let current = current.ok();
        let applied = self.apply(slot, &asked, previous.as_deref(), current.as_deref());
        crate::metrics::set_doppelganger_detecting(self.detecting() as u64);

        if !applied.sightings.is_empty() {
            let indices: Vec<ValidatorIndex> = applied.sightings.iter().map(|s| s.index).collect();
            let pubkeys: Vec<String> = applied
                .sightings
                .iter()
                .map(|sighting| encode_hex(&sighting.pubkey.0))
                .collect();
            let epochs: Vec<Epoch> = applied.sightings.iter().map(|s| s.epoch).collect();
            error!(
                %slot,
                validators = ?indices,
                ?pubkeys,
                ?epochs,
                "Doppelganger detected: the beacon network saw these validators act while this \
                 client was not signing for them, so another client is running their keys. \
                 Stopping. Do not restart until the other client is found and stopped: a key \
                 signing in two places is slashed"
            );
            return;
        }
        if !applied.progressed {
            crate::metrics::inc_doppelganger_check_failures();
            // Said at error once an epoch, at the one tick whose failure
            // costs something: an operator whose node never answers (one
            // without the endpoint, say) otherwise sees only missed
            // attestations and a warning among many.
            if (slot + 1).is_multiple_of(SLOTS_PER_EPOCH) {
                error!(
                    %slot,
                    epoch = previous_epoch,
                    validators = self.detecting(),
                    "Doppelganger protection could not count this epoch as clean, for want of a \
                     liveness answer: the validators under the check stay withheld at least \
                     another epoch. A beacon node without /eth/v1/validator/liveness never \
                     clears them"
                );
            }
        }
        if !applied.cleared.is_empty() {
            info!(
                %slot,
                validators = ?applied.cleared,
                still_checking = self.detecting(),
                "Doppelganger protection passed; these validators now sign"
            );
        }
    }
}

/// When the check for `slot` runs.
fn check_time(clock: &SlotClock, slot: Slot) -> SystemTime {
    clock.start_of(slot) + clock.slot_duration() * CHECK_NUMERATOR / CHECK_DENOMINATOR
}

/// The slot the check runs for next, given the last one checked, and how long
/// from `now` until it is due; `None` before genesis.
///
/// The current slot, unless it was already checked, in which case the next
/// one. A tick that starts past its slot's three-quarter mark runs at once,
/// still inside its slot, and one that overslept by whole slots skips them
/// rather than running late for each: the last slot of an epoch, the only
/// tick that can clear a key, is never run from a later slot as if it were
/// still that one.
fn next_check(clock: &SlotClock, last: Option<Slot>, now: SystemTime) -> Option<(Slot, Duration)> {
    let current = clock.slot_at(now)?;
    let slot = match last {
        Some(last) if last >= current => last + 1,
        _ => current,
    };
    let wait = check_time(clock, slot)
        .duration_since(now)
        .unwrap_or_default();
    Some((slot, wait))
}

/// Run the check every slot, for the life of the client.
///
/// It never ends on its own: a key the keymanager imports later is checked
/// the same way, and with nothing to check a tick asks nothing.
pub async fn run<B: BeaconNodeApi>(
    doppelganger: Arc<Doppelganger>,
    beacon_node: Arc<B>,
    store: Arc<RwLock<ValidatorStore>>,
    clock: SlotClock,
) {
    let mut last: Option<Slot> = None;
    loop {
        let now = SystemTime::now();
        let Some((slot, wait)) = next_check(&clock, last, now) else {
            // Before genesis: nothing is live, and keys registered now were
            // registered in epoch 0, so there is nothing to check yet.
            let until_genesis = clock.start_of(0).duration_since(now).unwrap_or_default();
            tokio::time::sleep(until_genesis.max(Duration::from_millis(100))).await;
            continue;
        };
        tokio::time::sleep(wait).await;
        doppelganger.check(&*beacon_node, &store, slot).await;
        last = Some(slot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_node::ValidatorEntry;
    use crate::beacon_node::mock::MockBeaconNode;

    const E: Epoch = 10;

    fn pubkey(byte: u8) -> BlsPubkey {
        BlsPubkey([byte; 48])
    }

    fn first_slot(epoch: Epoch) -> Slot {
        epoch * SLOTS_PER_EPOCH
    }

    fn last_slot(epoch: Epoch) -> Slot {
        first_slot(epoch + 1) - 1
    }

    fn answers(live: &[(ValidatorIndex, bool)]) -> Vec<Liveness> {
        live.iter()
            .map(|&(index, is_live)| Liveness { index, is_live })
            .collect()
    }

    /// One key, registered in `E` with index 7.
    fn watching_one() -> (Doppelganger, HashMap<ValidatorIndex, BlsPubkey>) {
        let doppelganger = Doppelganger::new();
        doppelganger.register(pubkey(1), E);
        doppelganger.set_indices([(pubkey(1), 7)]);
        let asked = doppelganger.checked_indices();
        (doppelganger, asked)
    }

    #[test]
    fn a_key_registered_after_genesis_is_withheld_and_one_at_genesis_is_not() {
        let doppelganger = Doppelganger::new();
        doppelganger.register(pubkey(1), E);
        doppelganger.register(pubkey(2), 0);
        assert!(!doppelganger.allows_signing(&pubkey(1)));
        assert!(doppelganger.allows_signing(&pubkey(2)));
        assert_eq!(doppelganger.detecting(), 1);
    }

    #[test]
    fn an_unknown_key_signs_nothing() {
        let doppelganger = Doppelganger::new();
        assert!(!doppelganger.allows_signing(&pubkey(9)));
    }

    /// The restart case: this client's previous process attested in the
    /// epoch it was registered in, and that must not stop it.
    #[test]
    fn activity_in_the_registration_epoch_is_not_a_doppelganger() {
        let (doppelganger, asked) = watching_one();
        let live = answers(&[(7, true)]);
        let applied = doppelganger.apply(first_slot(E + 1), &asked, Some(&live), Some(&[]));
        assert!(applied.sightings.is_empty(), "{applied:?}");
        assert!(!doppelganger.is_detected());
    }

    #[test]
    fn activity_in_a_watched_epoch_is_a_doppelganger_and_stops_all_signing() {
        let (doppelganger, asked) = watching_one();
        doppelganger.register(pubkey(2), 0);
        assert!(doppelganger.allows_signing(&pubkey(2)));

        let live = answers(&[(7, true)]);
        let applied = doppelganger.apply(first_slot(E + 1) + 3, &asked, None, Some(&live));
        assert_eq!(
            applied.sightings,
            vec![Sighting {
                index: 7,
                pubkey: pubkey(1),
                epoch: E + 1
            }]
        );
        assert!(doppelganger.is_detected());
        assert!(
            !doppelganger.allows_signing(&pubkey(2)),
            "nothing signs once the client is stopping"
        );
    }

    /// A clean epoch counts only from the last slot of the epoch after it,
    /// so the key signs from `E + 3`.
    #[test]
    fn a_key_signs_once_its_first_watched_epoch_is_clean_at_the_end_of_the_next() {
        let (doppelganger, asked) = watching_one();
        let quiet = answers(&[(7, false)]);

        // E + 1 is the first watched epoch; asked about from within E + 2.
        for slot in first_slot(E + 2)..last_slot(E + 2) {
            let applied = doppelganger.apply(slot, &asked, Some(&quiet), Some(&quiet));
            assert!(
                applied.progressed && applied.cleared.is_empty(),
                "slot {slot}"
            );
            assert!(!doppelganger.allows_signing(&pubkey(1)), "slot {slot}");
        }
        let applied = doppelganger.apply(last_slot(E + 2), &asked, Some(&quiet), Some(&quiet));
        assert_eq!(applied.cleared, vec![7]);
        assert!(doppelganger.allows_signing(&pubkey(1)));
        assert_eq!(doppelganger.detecting(), 0);
    }

    /// At the end of `E + 1` the previous epoch is `E`, the registration
    /// epoch, which never counts as clean.
    #[test]
    fn the_registration_epoch_never_counts_as_clean() {
        let (doppelganger, asked) = watching_one();
        let quiet = answers(&[(7, false)]);
        let applied = doppelganger.apply(last_slot(E + 1), &asked, Some(&quiet), Some(&quiet));
        assert!(applied.cleared.is_empty());
        assert!(!doppelganger.allows_signing(&pubkey(1)));
    }

    /// A failed question makes no progress, whichever of the two failed, and
    /// the epoch is counted at its next chance instead.
    #[test]
    fn an_unanswered_question_makes_no_progress() {
        let (doppelganger, asked) = watching_one();
        let quiet = answers(&[(7, false)]);
        for (previous, current) in [(None, Some(&quiet[..])), (Some(&quiet[..]), None)] {
            let applied = doppelganger.apply(last_slot(E + 2), &asked, previous, current);
            assert!(!applied.progressed);
            assert!(!doppelganger.allows_signing(&pubkey(1)));
        }

        // Missed at the end of E + 2, so E + 2 itself is counted at the end of
        // E + 3.
        let applied = doppelganger.apply(last_slot(E + 3), &asked, Some(&quiet), Some(&quiet));
        assert_eq!(applied.cleared, vec![7]);
    }

    /// Only an explicit "not live" counts: a key the answer leaves out has
    /// not been shown silent.
    #[test]
    fn a_key_missing_from_the_answer_is_not_cleared() {
        let (doppelganger, asked) = watching_one();
        let applied = doppelganger.apply(last_slot(E + 2), &asked, Some(&[]), Some(&[]));
        assert!(applied.cleared.is_empty());
        assert!(!doppelganger.allows_signing(&pubkey(1)));
    }

    /// A sighting is acted on even when the other question failed.
    #[test]
    fn a_sighting_in_one_answer_is_enough() {
        let (doppelganger, asked) = watching_one();
        let live = answers(&[(7, true)]);
        let applied = doppelganger.apply(first_slot(E + 3), &asked, Some(&live), None);
        assert_eq!(applied.sightings.len(), 1);
        assert!(doppelganger.is_detected());
    }

    /// Live in both epochs asked about is one sighting, at the earlier.
    #[test]
    fn a_key_live_in_both_epochs_is_sighted_once() {
        let (doppelganger, asked) = watching_one();
        let live = answers(&[(7, true)]);
        let applied = doppelganger.apply(first_slot(E + 2), &asked, Some(&live), Some(&live));
        assert_eq!(
            applied.sightings,
            vec![Sighting {
                index: 7,
                pubkey: pubkey(1),
                epoch: E + 1
            }]
        );
        assert_eq!(doppelganger.sightings(), applied.sightings);
    }

    /// A key imported again starts over, as Lighthouse's does.
    #[test]
    fn registering_again_restarts_the_check() {
        let (doppelganger, asked) = watching_one();
        let quiet = answers(&[(7, false)]);
        doppelganger.apply(last_slot(E + 2), &asked, Some(&quiet), Some(&quiet));
        assert!(doppelganger.allows_signing(&pubkey(1)));

        doppelganger.register(pubkey(1), E + 5);
        assert!(!doppelganger.allows_signing(&pubkey(1)));
    }

    #[test]
    fn reconciling_forgets_deleted_keys_and_watches_unregistered_ones() {
        let doppelganger = Doppelganger::new();
        doppelganger.register_all(&[pubkey(1), pubkey(2)], 0);
        doppelganger.reconcile(&[pubkey(2), pubkey(3)], E);

        assert!(
            !doppelganger.allows_signing(&pubkey(1)),
            "deleted: forgotten"
        );
        assert!(doppelganger.allows_signing(&pubkey(2)), "kept as it was");
        assert!(
            !doppelganger.allows_signing(&pubkey(3)),
            "never registered: checked from now"
        );
        assert_eq!(doppelganger.detecting(), 1);
    }

    fn node_with(validators: &[(u8, ValidatorIndex)]) -> MockBeaconNode {
        let mut node = MockBeaconNode::new();
        node.validators = validators
            .iter()
            .map(|&(byte, index)| ValidatorEntry {
                index,
                pubkey: pubkey(byte),
                status: "active_ongoing".to_string(),
            })
            .collect();
        node
    }

    fn store_holding(keys: &[u8]) -> RwLock<ValidatorStore> {
        let mut store = ValidatorStore::new();
        for &byte in keys {
            store
                .insert_remote(pubkey(byte), "http://signer:9000")
                .expect("inserts");
        }
        RwLock::new(store)
    }

    /// The whole loop against a node, one tick per slot: resolved once,
    /// asked about both epochs with the indices quoted, and cleared at the
    /// end of `E + 2`.
    #[tokio::test]
    async fn checks_against_a_quiet_node_clear_the_key_at_the_end_of_the_second_epoch() {
        let node = node_with(&[(1, 7)]);
        let store = store_holding(&[1]);
        let doppelganger = Doppelganger::new();
        doppelganger.register(pubkey(1), E);

        for slot in first_slot(E)..last_slot(E + 2) {
            doppelganger.check(&node, &store, slot).await;
            assert!(!doppelganger.allows_signing(&pubkey(1)), "slot {slot}");
        }
        doppelganger.check(&node, &store, last_slot(E + 2)).await;
        assert!(doppelganger.allows_signing(&pubkey(1)));
        assert_eq!(node.validator_indices_call_count(), 1, "resolved once");

        let asked = node.liveness_requests();
        let ticks = (last_slot(E + 2) - first_slot(E) + 1) as usize;
        assert_eq!(asked.len(), 2 * ticks, "previous and current, every slot");
        assert_eq!(asked[0], (E - 1, vec![7]));
        assert_eq!(asked[1], (E, vec![7]));

        doppelganger.check(&node, &store, first_slot(E + 3)).await;
        assert_eq!(
            node.liveness_requests().len(),
            2 * ticks,
            "nothing is asked once every key has passed"
        );
    }

    #[tokio::test]
    async fn a_live_key_on_the_node_stops_the_client() {
        let node = node_with(&[(1, 7)]);
        node.live.lock().expect("lock").push((E + 1, 7));
        let store = store_holding(&[1]);
        let doppelganger = Doppelganger::new();
        doppelganger.register(pubkey(1), E);

        doppelganger
            .check(&node, &store, first_slot(E + 1) + 5)
            .await;
        assert!(doppelganger.is_detected());
        tokio::time::timeout(Duration::from_secs(1), doppelganger.detected())
            .await
            .expect("the signal fires");
    }

    /// A syncing node's "nobody is live" is not believed: the check makes
    /// no progress until a node that has the chain answers.
    #[tokio::test]
    async fn a_syncing_node_clears_nothing() {
        let mut node = node_with(&[(1, 7)]);
        node.syncing = true;
        let store = store_holding(&[1]);
        let doppelganger = Doppelganger::new();
        doppelganger.register(pubkey(1), E);

        for slot in first_slot(E)..=last_slot(E + 3) {
            doppelganger.check(&node, &store, slot).await;
        }
        assert!(!doppelganger.allows_signing(&pubkey(1)));
    }

    /// A key not yet on chain is not asked about, and stays withheld.
    #[tokio::test]
    async fn a_key_without_an_index_is_not_asked_about() {
        let node = node_with(&[]);
        let store = store_holding(&[1]);
        let doppelganger = Doppelganger::new();
        doppelganger.register(pubkey(1), E);

        doppelganger.check(&node, &store, last_slot(E + 2)).await;
        assert!(node.liveness_requests().is_empty(), "no empty index list");
        assert!(!doppelganger.allows_signing(&pubkey(1)));
    }

    /// A key the node has no index for is asked about once an epoch, not
    /// every slot; a node that failed to answer is asked again next slot.
    #[tokio::test]
    async fn a_missing_index_is_asked_for_once_an_epoch() {
        let node = node_with(&[]).failing_call("validator_indices", "down");
        let store = store_holding(&[1]);
        let doppelganger = Doppelganger::new();
        doppelganger.register(pubkey(1), E);

        doppelganger.check(&node, &store, first_slot(E)).await;
        doppelganger.check(&node, &store, first_slot(E) + 1).await;
        node.stop_failing("validator_indices");
        doppelganger.check(&node, &store, first_slot(E) + 2).await;
        assert_eq!(node.validator_indices_call_count(), 1, "the first answer");

        for slot in first_slot(E) + 3..=last_slot(E) {
            doppelganger.check(&node, &store, slot).await;
        }
        assert_eq!(
            node.validator_indices_call_count(),
            1,
            "not again this epoch"
        );
        doppelganger.check(&node, &store, first_slot(E + 1)).await;
        assert_eq!(node.validator_indices_call_count(), 2, "again the next");
    }

    fn clock() -> SlotClock {
        SlotClock::new(1_000, 12_000, 3_333, 6_667)
    }

    fn at(clock: &SlotClock, slot: Slot, millis: u64) -> SystemTime {
        clock.start_of(slot) + Duration::from_millis(millis)
    }

    #[test]
    fn the_check_runs_three_quarters_into_the_current_slot() {
        let clock = clock();
        assert_eq!(
            next_check(&clock, None, at(&clock, 5, 1_000)),
            Some((5, Duration::from_millis(8_000)))
        );
    }

    #[test]
    fn a_start_past_the_mark_checks_at_once() {
        let clock = clock();
        assert_eq!(
            next_check(&clock, None, at(&clock, 5, 10_000)),
            Some((5, Duration::ZERO))
        );
    }

    #[test]
    fn a_checked_slot_is_not_checked_again() {
        let clock = clock();
        assert_eq!(
            next_check(&clock, Some(5), at(&clock, 5, 10_000)),
            Some((6, Duration::from_millis(11_000)))
        );
    }

    /// A tick that overran into later slots moves to the current one rather
    /// than running each missed slot late as if it were still that slot.
    #[test]
    fn an_overslept_tick_skips_to_the_current_slot() {
        let clock = clock();
        assert_eq!(
            next_check(&clock, Some(5), at(&clock, 8, 2_000)),
            Some((8, Duration::from_millis(7_000)))
        );
    }

    #[test]
    fn nothing_is_checked_before_genesis() {
        let clock = clock();
        let before = clock.start_of(0) - Duration::from_secs(5);
        assert_eq!(next_check(&clock, None, before), None);
    }

    /// A deleted key is not checked: the copy the operator now runs
    /// elsewhere on purpose must not stop this client.
    #[tokio::test]
    async fn a_deleted_key_is_no_longer_checked() {
        let node = node_with(&[(1, 7)]);
        node.live.lock().expect("lock").push((E + 1, 7));
        let store = store_holding(&[]);
        let doppelganger = Doppelganger::new();
        doppelganger.register(pubkey(1), E);

        doppelganger
            .check(&node, &store, first_slot(E + 1) + 5)
            .await;
        assert!(!doppelganger.is_detected());
        assert!(node.liveness_requests().is_empty());
    }
}
