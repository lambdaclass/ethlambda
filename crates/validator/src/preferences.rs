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
//! See [`SigningContext::sign_proposer_preferences`]: the fork version of the
//! proposal epoch itself, as consensus-specs v1.7.0-beta.4 signs and verifies
//! and as every other client does. Beta.2's gossip rule took the fork of the
//! epoch before the proposal's, which differs only for a proposal in the first
//! epoch of a fork, and Lighthouse refuses a preference signed that way.
//!
//! # Why every slot
//!
//! [`PreferencesService::poll`] runs each slot rather than each epoch. A reorg
//! changes a dependent root, which makes the old preference unusable and needs
//! a new one; a validator can become active, or be given a fee recipient,
//! mid-epoch; and a node that refused a send must be tried again. What a node
//! accepted is kept per `(slot, dependent_root)`, as signed, so a quiet slot
//! costs the two duty fetches and no signing.
//!
//! # Why every node gets them
//!
//! Each node gossips what it accepts, so the fallback client sends to all of
//! them: a preference only one node heard reaches builders through that node's
//! mesh alone.
//!
//! So a preference is done only once every node accepted it. A node that was
//! syncing, or lacked the dependent block, when it was first sent never gets
//! it from gossip, which does not replay it; until every node has it, each
//! slot sends it again to all of them. That is safe for the nodes that already
//! hold it: ethlambda's answers 200 for an entry identical to the one it holds,
//! and Lighthouse's treats it as already seen. It is identical because it is
//! the message as first signed, kept rather than signed again: a fee recipient
//! changed in between would otherwise give the late node a second preference
//! for the slot, which the nodes holding the first refuse. The published count
//! takes a preference once, when the first node accepts it.
//!
//! # Again once an epoch
//!
//! A node keeps the preferences it accepted in memory only, so one that
//! restarts has lost them, and gossip does not give them back. Every kept
//! preference whose slot is still ahead is therefore sent again, as signed,
//! once an epoch, as the duty loop re-sends `prepare_beacon_proposer`, which a
//! restart loses too. The round runs at the poll of an epoch's last slot,
//! after which every slot of the next epoch is still ahead, so a node
//! restarted mid-epoch lacks the rest of that epoch's preferences and holds
//! every later one, the next epoch's first slot included. Each node answers
//! the re-send as it does any other: one still holding the preference with a
//! 200 and no republish, one that lost it by taking it again, and one not
//! ready yet by making it a preference only some nodes hold, sent each slot
//! from then on.
//!
//! # No replacement
//!
//! A node deduplicates on `(slot, dependent_root)`, so a preference cannot be
//! replaced for the same slot and root. A fee recipient changed after a
//! preference went out applies from the next dependent root onward only.
//!
//! A restart with other settings (another `--suggested-fee-recipient` or
//! `--gas-limit`, or the keymanager's overrides gone) is the same case seen
//! from a client that no longer remembers what it signed: it signs a
//! preference that differs from the one the nodes hold, and they refuse it
//! each slot until its slot starts, while building with the one they hold.
//!
//! # One preference per request, all at once
//!
//! A call has one status for all its entries: a node answers 400 when any
//! entry fails, and one it holds for the same `(slot, dependent_root)` with
//! other content is such a failure (a restart after a fee recipient change,
//! say). Which entries passed is then only as good as the 400's per-entry
//! list. Sent alone, each preference's own status says whether it was
//! accepted, with no body to trust, and each success is remembered on its own.
//!
//! The requests go out together, both target epochs' fetches and sends too, so
//! a node that does not answer costs a poll one duties fetch and one request
//! timeout rather than one timeout per preference. A poll sends at most one
//! preference per slot of the two epochs.
//!
//! # Failures are never propagated
//!
//! A missed preference costs a builder bid and, from gloas, possibly the
//! node's knowledge of the fee recipient, never a duty. A failed send, or a
//! failed duties fetch, is logged and counted, and the next slot retries. The
//! fetch warns once per epoch, a preference no node took once, and the
//! preferences some node did not take once per poll that finds new ones. A
//! preference whose slot started before the nodes answered is neither: gossip
//! ignores a started slot, and the poll was late, not refused.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use ethlambda_types::beacon::containers::gloas::{ProposerPreferences, SignedProposerPreferences};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch, ExecutionAddress, Root, Slot};
use ethlambda_types::beacon::signing::{compute_epoch_at_slot, compute_start_slot_at_epoch};
use futures_util::future::join_all;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::beacon_node::dto::{ProposerDutyDto, encode_hex, parse_pubkey};
use crate::beacon_node::{BeaconNodeApi, Delivery};
use crate::in_flight::InFlight;
use crate::keys::ValidatorStore;
use crate::proposer_settings::ProposerSettings;
use crate::signing::SigningContext;
use crate::slot_clock::SlotClock;

/// Where one `(proposal_slot, dependent_root)`'s preference stands.
#[derive(Debug, Clone)]
enum Sent {
    /// No node has accepted one, and that was warned about. Signed afresh
    /// each poll, so an address set in between is the one that goes out.
    Refused,
    /// A node accepted this message and another may not hold it: one refused
    /// or did not answer, or none took the epoch's re-send. Sent again, as
    /// signed, each poll until every node accepts it.
    Partly(SignedProposerPreferences),
    /// Every node accepted this message, last in the re-send round `round`
    /// (see [`round_of`]). Sent again, as signed, in each later round, for a
    /// node that restarted since and lost it.
    Everywhere {
        signed: SignedProposerPreferences,
        round: Epoch,
    },
}

/// The re-send round a poll at `current_slot` belongs to: the epoch of the
/// slot after it. An epoch's round thus starts at the poll of the last slot
/// before it, while every one of its slots is still ahead.
fn round_of(current_slot: Slot) -> Epoch {
    compute_epoch_at_slot(current_slot + 1)
}

impl Sent {
    /// The message some node accepted, if one did.
    fn accepted(&self) -> Option<&SignedProposerPreferences> {
        match self {
            Sent::Refused => None,
            Sent::Partly(signed) | Sent::Everywhere { signed, .. } => Some(signed),
        }
    }
}

/// Where a preference stood before this poll sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Before {
    /// Never sent: signed this poll.
    Unsent,
    /// Sent, and no node accepted it: signed again this poll.
    Refused,
    /// Some node accepted it, and not every node is known to hold it.
    Partly,
    /// Every node accepted it in an earlier round: this is this round's
    /// re-send (see [`round_of`]).
    Everywhere,
}

/// What one send came to, summed over a target epoch's sends.
#[derive(Debug, Default, Clone, Copy)]
struct Tally {
    /// A node accepted it for the first time.
    published: bool,
    /// It went from every node or none to some: the poll warns once for all.
    newly_partial: bool,
}

/// Signs and publishes proposer preferences.
pub struct PreferencesService<B> {
    beacon_node: Arc<B>,
    context: Arc<SigningContext>,
    settings: Arc<ProposerSettings>,
    /// Where each `(proposal_slot, dependent_root)` stands, so a preference
    /// is signed once per dependent root, sent until every node holds it, and
    /// sent again once an epoch after. A reorg that moves the root starts a
    /// new entry. Pruned below the current epoch.
    sent: Mutex<HashMap<(Slot, Root), Sent>>,
    /// Epochs whose missing fee recipients were already warned about, so the
    /// warning is once per epoch rather than once per slot. Pruned like
    /// `sent`.
    no_fee_warned: Mutex<HashSet<Epoch>>,
    /// Epochs whose failed duties fetch was already warned about, for the same
    /// reason: a syncing node, or one without v2, fails every slot.
    fetch_warned: Mutex<HashSet<Epoch>>,
    /// One poll at a time: a slow node must not stack polls up.
    in_flight: InFlight,
    /// The wall clock, so a preference whose slot started while the poll
    /// waited on a node is not sent, nor reported as refused when its slot
    /// started in flight. `None` goes by the poll's slot alone.
    clock: Option<SlotClock>,
}

/// Lock `mutex`, recovering a poisoned one: every write here is one map or
/// set operation, so the data behind it is never half-changed.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl<B> PreferencesService<B> {
    /// The fee recipients of the preferences some node accepted for `slot`
    /// from `validator`, one per dependent root signed for.
    ///
    /// From gloas a node builds with the preference it holds for the slot, so
    /// a block at `slot` may rightly pay one of these rather than the
    /// validator's current address: the preference names the address in
    /// force when it was signed, and cannot be replaced for its root.
    ///
    /// Only `validator`'s own: a reorg can move the slot from one of this
    /// client's validators to another, and the first one's address is not one
    /// the second asked to be paid at.
    pub fn accepted_fee_recipients(&self, slot: Slot, validator: u64) -> Vec<ExecutionAddress> {
        lock(&self.sent)
            .iter()
            .filter(|((held, _), _)| *held == slot)
            .filter_map(|(_, sent)| sent.accepted())
            .filter(|signed| signed.message.validator_index == validator)
            .map(|signed| signed.message.fee_recipient)
            .collect()
    }
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
            sent: Mutex::new(HashMap::new()),
            no_fee_warned: Mutex::new(HashSet::new()),
            fetch_warned: Mutex::new(HashSet::new()),
            in_flight: InFlight::default(),
            clock: None,
        }
    }

    /// Give the service the slot clock, so a poll that waited on a node skips
    /// the slots that started meanwhile rather than having them refused.
    pub fn with_clock(mut self, clock: SlotClock) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Publish what this client's validators still owe for the current and the
    /// next epoch, as of `current_slot`. Called once per slot, off the slot
    /// loop, so a slow node cannot delay the next slot's duties.
    ///
    /// Returns at once when the previous poll is still running.
    pub async fn poll(self: Arc<Self>, current_slot: Slot, store: Arc<RwLock<ValidatorStore>>) {
        let Some(_running) = self.in_flight.enter() else {
            return;
        };
        self.publish(current_slot, &store).await;

        let epoch = compute_epoch_at_slot(current_slot);
        let epoch_start = compute_start_slot_at_epoch(epoch);
        lock(&self.sent).retain(|(slot, _), _| *slot >= epoch_start);
        lock(&self.no_fee_warned).retain(|warned| *warned >= epoch);
        lock(&self.fetch_warned).retain(|warned| *warned >= epoch);
    }

    /// Both target epochs, at once, so a node that does not answer costs the
    /// poll one wait rather than one per epoch.
    async fn publish(&self, current_slot: Slot, store: &Arc<RwLock<ValidatorStore>>) {
        let epoch = compute_epoch_at_slot(current_slot);
        // Before the store or any node is asked: until the epoch before
        // gloas, and with no keys loaded, nothing is owed.
        let targets: Vec<Epoch> = [epoch, epoch + 1]
            .into_iter()
            .filter(|target| self.context.config.fork_at_epoch(*target) >= ForkName::Gloas)
            .collect();
        if targets.is_empty() {
            return;
        }
        // Snapshotted with the guard dropped at once: nothing below awaits a
        // node while holding the store.
        let pubkeys: HashSet<BlsPubkey> = store.read().await.pubkeys().into_iter().collect();
        if pubkeys.is_empty() {
            return;
        }

        let sends = targets
            .iter()
            .map(|target| self.publish_epoch(current_slot, *target, &pubkeys, store));
        for (target, published) in targets.iter().zip(join_all(sends).await) {
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

    /// Whether `slot` has started: by the clock when there is one, which a
    /// poll that waited on a node needs, else by the poll's own slot.
    fn started(&self, slot: Slot, current_slot: Slot) -> bool {
        slot <= current_slot
            || self
                .clock
                .as_ref()
                .and_then(SlotClock::now)
                .is_some_and(|now| now >= slot)
    }

    /// One target epoch: fetch its v2 duties, sign what is still owed, and
    /// send it along with what some node may still lack. Returns how many
    /// preferences a node accepted for the first time, which is all the
    /// published count takes: a re-send is not counted again.
    async fn publish_epoch(
        &self,
        current_slot: Slot,
        target: Epoch,
        pubkeys: &HashSet<BlsPubkey>,
        store: &Arc<RwLock<ValidatorStore>>,
    ) -> usize {
        let duties = match self.beacon_node.proposer_duties_v2(target).await {
            Ok(duties) => duties,
            Err(err) => {
                debug!(epoch = target, %err, "Could not fetch proposer duties for preferences");
                crate::metrics::inc_proposer_preferences_duty_fetch_failures();
                if lock(&self.fetch_warned).insert(target) {
                    warn!(
                        epoch = target,
                        %err,
                        "No beacon node answered the v2 proposer duties; proposer preferences \
                         for this epoch wait for a node that does"
                    );
                }
                return 0;
            }
        };
        let dependent_root = duties.dependent_root;
        let round = round_of(current_slot);

        let mut owed = Vec::new();
        let mut resend = Vec::new();
        let mut no_fee_recipient = 0usize;
        for duty in within_epoch(target, duties.duties) {
            // Started slots are skipped: gossip would IGNORE them.
            if self.started(duty.slot, current_slot) {
                continue;
            }
            let Ok(pubkey) = parse_pubkey(&duty.pubkey) else {
                continue;
            };
            if !pubkeys.contains(&pubkey) {
                continue;
            }
            let key = (duty.slot, dependent_root);
            let held = lock(&self.sent).get(&key).cloned();
            let before = match held {
                Some(Sent::Partly(signed)) => {
                    resend.push((signed, Before::Partly));
                    continue;
                }
                Some(Sent::Everywhere {
                    signed,
                    round: held,
                }) => {
                    if held < round {
                        resend.push((signed, Before::Everywhere));
                    }
                    continue;
                }
                Some(Sent::Refused) => Before::Refused,
                None => Before::Unsent,
            };
            // One read for both, so a keymanager write between two reads
            // cannot pair an old address with a new gas limit.
            let Some((fee_recipient, target_gas_limit)) =
                self.settings.fee_recipient_and_gas_limit(&pubkey)
            else {
                no_fee_recipient += 1;
                continue;
            };
            let message = ProposerPreferences {
                dependent_root,
                proposal_slot: duty.slot,
                validator_index: duty.validator_index,
                fee_recipient,
                target_gas_limit,
            };
            owed.push((pubkey, message, before));
        }

        if no_fee_recipient > 0 && lock(&self.no_fee_warned).insert(target) {
            warn!(
                epoch = target,
                skipped = no_fee_recipient,
                "Validators without a fee recipient publish no proposer preferences"
            );
        }

        let signed = self.sign(store, owed).await;

        // The target epoch's fork, which is what the submitted objects belong
        // to (always gloas here).
        let fork = self.context.config.fork_at_epoch(target);
        let sends = resend
            .into_iter()
            .chain(signed)
            .map(|(entry, before)| self.submit(fork, target, current_slot, entry, before));
        let tallies = join_all(sends).await;

        let newly_partial = tallies.iter().filter(|tally| tally.newly_partial).count();
        if newly_partial > 0 {
            warn!(
                epoch = target,
                count = newly_partial,
                "Not every beacon node took these proposer preferences, and a node gossips only \
                 what it took; sending them to every node each slot until all of them do"
            );
        }
        tallies.iter().filter(|tally| tally.published).count()
    }

    /// Sign each of `owed`, skipping with a warning any it cannot sign, such as
    /// one whose key the store no longer holds: the keymanager may have deleted
    /// it since the poll took its snapshot of the keys. The others are signed
    /// all the same.
    ///
    /// At most one per slot of the epoch (see [`within_epoch`]), so signing
    /// inline is cheap. The read guard is released before the submits, and is
    /// not taken at all when nothing is owed, so a quiet slot neither waits on
    /// nor holds up a keymanager write.
    async fn sign(
        &self,
        store: &Arc<RwLock<ValidatorStore>>,
        owed: Vec<(BlsPubkey, ProposerPreferences, Before)>,
    ) -> Vec<(SignedProposerPreferences, Before)> {
        if owed.is_empty() {
            return Vec::new();
        }
        let store = store.read().await;
        let mut signed = Vec::with_capacity(owed.len());
        for (pubkey, message, before) in owed {
            match self
                .context
                .sign_proposer_preferences(&store, &pubkey, &message)
            {
                Ok(signature) => {
                    signed.push((SignedProposerPreferences { message, signature }, before));
                }
                Err(err) => {
                    warn!(
                        slot = message.proposal_slot,
                        pubkey = %encode_hex(&pubkey.0),
                        %err,
                        "Could not sign proposer preferences; skipping them"
                    );
                }
            }
        }
        signed
    }

    /// Send one preference to every node and record what came of it.
    /// `before` is where it stood before this poll.
    ///
    /// The failures counter takes every send some node did not take, re-sends
    /// included, unless the slot started before the answer came.
    async fn submit(
        &self,
        fork: ForkName,
        target: Epoch,
        current_slot: Slot,
        entry: SignedProposerPreferences,
        before: Before,
    ) -> Tally {
        // One request per preference: see the module doc.
        let key = (entry.message.proposal_slot, entry.message.dependent_root);
        let validator = entry.message.validator_index;
        let answer = self
            .beacon_node
            .submit_proposer_preferences(fork, std::slice::from_ref(&entry))
            .await;
        let first = matches!(before, Before::Unsent | Before::Refused);
        let late = self.started(key.0, current_slot);
        match answer {
            Ok(Delivery::Everywhere) => {
                let held = Sent::Everywhere {
                    signed: entry,
                    round: round_of(current_slot),
                };
                lock(&self.sent).insert(key, held);
                Tally {
                    published: first,
                    newly_partial: false,
                }
            }
            Ok(Delivery::Partly) => {
                // Kept as signed, so the nodes that missed it get this very
                // message next slot. The fallback logged each refusal at debug.
                lock(&self.sent).insert(key, Sent::Partly(entry));
                if !late {
                    crate::metrics::inc_proposer_preferences_failures();
                }
                Tally {
                    published: first,
                    newly_partial: !late && before != Before::Partly,
                }
            }
            Err(err) if late => {
                debug!(
                    epoch = target,
                    slot = key.0,
                    validator,
                    %err,
                    "A proposer preference's slot started before a beacon node took it"
                );
                Tally::default()
            }
            Err(err) => {
                crate::metrics::inc_proposer_preferences_failures();
                match before {
                    Before::Unsent => {
                        // A refused entry is tried again every slot until its
                        // slot passes, so only its first refusal is a warning.
                        //
                        // A node that already holds a different preference
                        // for the slot and root refuses this one too. That is
                        // what a restart with another fee recipient or gas
                        // limit (or without the keymanager's overrides) looks
                        // like, and then the node does have a preference: the
                        // one signed before the restart.
                        warn!(
                            epoch = target,
                            slot = key.0,
                            validator,
                            %err,
                            "No beacon node accepted a proposer preference. Unless the nodes \
                             already hold one for this slot and dependent root (signed before a \
                             restart with other settings, which they keep), builders' bids for \
                             that slot are ignored, and from gloas a node may not know the fee \
                             recipient"
                        );
                        lock(&self.sent).insert(key, Sent::Refused);
                        Tally::default()
                    }
                    Before::Refused => {
                        debug!(
                            epoch = target,
                            slot = key.0,
                            validator,
                            %err,
                            "A proposer preference was refused again"
                        );
                        Tally::default()
                    }
                    Before::Partly => {
                        // A node already took it; kept for the next slot.
                        debug!(
                            epoch = target,
                            slot = key.0,
                            validator,
                            %err,
                            "No beacon node took a proposer preference sent again"
                        );
                        Tally::default()
                    }
                    Before::Everywhere => {
                        // Every node took it before, and none takes the
                        // epoch's re-send: restarted, and not ready yet. Sent
                        // each slot from now on, as one only some hold.
                        debug!(
                            epoch = target,
                            slot = key.0,
                            validator,
                            %err,
                            "No beacon node took this epoch's re-send of a proposer preference"
                        );
                        lock(&self.sent).insert(key, Sent::Partly(entry));
                        Tally {
                            published: false,
                            newly_partial: true,
                        }
                    }
                }
            }
        }
    }
}

/// `duties` cut to what one epoch can hold: those whose slot is in `target`,
/// and of those only the first listed for each slot.
///
/// The duties are a node's answer, so a buggy or hostile node chooses how
/// many there are and which slots they name. Every one left that names this
/// client's key is signed under the store's read guard, sent in a request of
/// its own, and remembered under a `(slot, dependent_root)` key the prune
/// keeps for as long as its slot lies ahead. Cut here, a target epoch costs at
/// most `SLOTS_PER_EPOCH` of each, whatever the node answered.
fn within_epoch(target: Epoch, duties: Vec<ProposerDutyDto>) -> Vec<ProposerDutyDto> {
    let slots = compute_start_slot_at_epoch(target)..compute_start_slot_at_epoch(target + 1);
    let listed = duties.len();
    let mut seen = HashSet::new();
    let kept: Vec<ProposerDutyDto> = duties
        .into_iter()
        .filter(|duty| slots.contains(&duty.slot) && seen.insert(duty.slot))
        .collect();
    let dropped = listed - kept.len();
    if dropped > 0 {
        debug!(
            epoch = target,
            dropped, "Dropped out-of-epoch or repeated-slot proposer duties"
        );
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_node::dto::ProposerDutyDto;
    use crate::beacon_node::mock::MockBeaconNode;
    use crate::test_support::{settings, store_with_keys};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::constants::DOMAIN_PROPOSER_PREFERENCES;
    use ethlambda_types::beacon::preset;
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

    /// Where each kept `(slot, dependent_root)` stands, by name.
    fn stages<B>(service: &PreferencesService<B>) -> HashMap<(Slot, Root), &'static str> {
        lock(&service.sent)
            .iter()
            .map(|(key, sent)| {
                let stage = match sent {
                    Sent::Refused => "refused",
                    Sent::Partly(_) => "partly",
                    Sent::Everywhere { .. } => "everywhere",
                };
                (*key, stage)
            })
            .collect()
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
        // Spelled out rather than asked of `SigningContext::domain`: every
        // preference, the first gloas epoch's included, verifies under the
        // proposal epoch's version, which for every slot here is gloas's.
        assert!(proposal_epoch >= GLOAS_EPOCH);
        let domain = compute_domain(
            DOMAIN_PROPOSER_PREFERENCES,
            context.config.gloas_fork_version,
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

    /// A reorg that moves a slot from one of this client's validators to
    /// another leaves both preferences kept, and each validator's block may
    /// pay only the address it signed for itself.
    #[tokio::test]
    async fn accepted_fee_recipients_are_the_proposers_own() {
        let (store, pubkeys) = store_with_keys(2);
        let store = Arc::new(RwLock::new(store));
        let slot = slot_in(GLOAS_EPOCH, 10);
        let node = MockBeaconNode::new().with_proposers_v2(
            GLOAS_EPOCH,
            Root::repeat_byte(0x11),
            vec![duty(&pubkeys[0], 3, slot)],
        );
        let settings = settings(Some(FEE_RECIPIENT));
        let other_recipient = H160([0xcd; 20]);
        settings.set_fee_recipient(&pubkeys[1], other_recipient);
        let (service, node) = service(node, settings);
        let current = slot_in(GLOAS_EPOCH, 1);

        service.clone().poll(current, store.clone()).await;
        node.set_proposers_v2(
            GLOAS_EPOCH,
            Root::repeat_byte(0x33),
            vec![duty(&pubkeys[1], 5, slot)],
        );
        service.clone().poll(current + 1, store).await;

        assert_eq!(submitted(&node).len(), 2);
        assert_eq!(
            service.accepted_fee_recipients(slot, 3),
            vec![FEE_RECIPIENT]
        );
        assert_eq!(
            service.accepted_fee_recipients(slot, 5),
            vec![other_recipient]
        );
        assert!(service.accepted_fee_recipients(slot, 4).is_empty());
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
            stages(&service),
            HashMap::from([
                ((refused, Root::repeat_byte(0x11)), "refused"),
                ((accepted, Root::repeat_byte(0x11)), "everywhere"),
            ]),
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
        // Both target epochs have duties, and the failure is injected on the
        // call itself, so neither fetch fails for want of data.
        node.set_proposers_v2(
            GLOAS_EPOCH + 1,
            Root::repeat_byte(0x22),
            vec![duty(&pubkeys[0], 3, slot_in(GLOAS_EPOCH + 1, 4))],
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
        assert_eq!(
            *lock(&service.fetch_warned),
            HashSet::from([GLOAS_EPOCH, GLOAS_EPOCH + 1]),
            "one entry per target epoch, not per poll"
        );

        node.failures.lock().expect("lock").clear();
        service.poll(current + 2, store).await;
        let mut slots: Vec<Slot> = submitted(&node)
            .iter()
            .flat_map(|(_, entries)| entries.iter().map(|entry| entry.message.proposal_slot))
            .collect();
        slots.sort();
        assert_eq!(
            slots,
            vec![slot_in(GLOAS_EPOCH, 10), slot_in(GLOAS_EPOCH + 1, 4)]
        );
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

        let running = service.in_flight.enter().expect("nothing is running");
        service
            .clone()
            .poll(slot_in(GLOAS_EPOCH, 1), store.clone())
            .await;
        assert!(submitted(&node).is_empty());
        assert_eq!(node.proposer_duties_v2_call_count(), 0);
        assert!(
            service.in_flight.enter().is_none(),
            "the running poll's flag is not cleared by the one that bounced"
        );

        drop(running);
        service.clone().poll(slot_in(GLOAS_EPOCH, 1), store).await;
        assert_eq!(submitted(&node).len(), 1);
        assert!(service.in_flight.enter().is_some(), "cleared after a poll");
    }

    /// A duty is signed for only under the epoch it belongs to: one a node
    /// lists under another epoch, or far in the future, is dropped, and leaves
    /// nothing behind for the prune to miss.
    #[tokio::test]
    async fn duties_outside_the_target_epoch_are_dropped() {
        let (store, pubkeys) = store_with_keys(1);
        let store = Arc::new(RwLock::new(store));
        let this_epoch = slot_in(GLOAS_EPOCH, 10);
        let next_epoch = slot_in(GLOAS_EPOCH + 1, 4);
        let node = MockBeaconNode::new()
            .with_proposers_v2(
                GLOAS_EPOCH,
                Root::repeat_byte(0x11),
                vec![
                    duty(&pubkeys[0], 3, this_epoch),
                    duty(&pubkeys[0], 3, slot_in(GLOAS_EPOCH + 1, 5)),
                    duty(&pubkeys[0], 3, slot_in(GLOAS_EPOCH + 1_000, 0)),
                ],
            )
            .with_proposers_v2(
                GLOAS_EPOCH + 1,
                Root::repeat_byte(0x22),
                vec![
                    // Unstarted, but the epoch before the one asked for.
                    duty(&pubkeys[0], 3, slot_in(GLOAS_EPOCH, 20)),
                    duty(&pubkeys[0], 3, next_epoch),
                ],
            );
        let (service, node) = service(node, settings(Some(FEE_RECIPIENT)));

        service.clone().poll(slot_in(GLOAS_EPOCH, 1), store).await;

        let mut sent: Vec<(Slot, Root)> = submitted(&node)
            .iter()
            .flat_map(|(_, entries)| entries.iter())
            .map(|entry| (entry.message.proposal_slot, entry.message.dependent_root))
            .collect();
        sent.sort();
        let expected = vec![
            (this_epoch, Root::repeat_byte(0x11)),
            (next_epoch, Root::repeat_byte(0x22)),
        ];
        assert_eq!(sent, expected);
        assert_eq!(
            stages(&service),
            expected
                .into_iter()
                .map(|key| (key, "everywhere"))
                .collect::<HashMap<_, _>>()
        );
    }

    /// However many duties a node lists, an epoch signs at most one preference
    /// per slot, for the duty listed first.
    #[tokio::test]
    async fn hundreds_of_duties_sign_at_most_one_preference_per_slot() {
        let (store, pubkeys) = store_with_keys(1);
        let store = Arc::new(RwLock::new(store));
        // Every even entry names a slot of the gloas epoch, cycling through
        // it; every odd one a slot epochs ahead.
        let duties = (0..400)
            .map(|position| {
                let slot = if position % 2 == 0 {
                    slot_in(GLOAS_EPOCH, (position / 2) % preset::SLOTS_PER_EPOCH)
                } else {
                    slot_in(GLOAS_EPOCH + 1 + position, 0)
                };
                duty(&pubkeys[0], position, slot)
            })
            .collect();
        let node =
            MockBeaconNode::new().with_proposers_v2(GLOAS_EPOCH, Root::repeat_byte(0x11), duties);
        let (service, node) = service(node, settings(Some(FEE_RECIPIENT)));

        // The last slot before gloas: the current epoch is skipped, and every
        // slot of the gloas epoch is still ahead.
        let current = slot_in(GLOAS_EPOCH - 1, preset::SLOTS_PER_EPOCH - 1);
        service.poll(current, store).await;

        let mut sent: Vec<(Slot, u64)> = submitted(&node)
            .iter()
            .inspect(|(_, entries)| assert_eq!(entries.len(), 1, "one per request"))
            .map(|(_, entries)| {
                let message = &entries[0].message;
                (message.proposal_slot, message.validator_index)
            })
            .collect();
        sent.sort();
        let first_listed: Vec<(Slot, u64)> = (0..preset::SLOTS_PER_EPOCH)
            .map(|offset| (slot_in(GLOAS_EPOCH, offset), 2 * offset))
            .collect();
        assert_eq!(sent, first_listed);
    }

    /// A node that refused a preference a peer accepted gets the same signed
    /// message on a later poll, once it accepts; the preference is counted as
    /// published once, at the first acceptance, and is not sent again after
    /// every node holds it.
    #[tokio::test]
    async fn a_node_that_refused_gets_the_preference_once_it_accepts() {
        use crate::beacon_node::fallback::FallbackBeaconNode;

        let (store, pubkeys) = store_with_keys(1);
        let snapshot: HashSet<BlsPubkey> = pubkeys.iter().copied().collect();
        let store = Arc::new(RwLock::new(store));
        let slot = slot_in(GLOAS_EPOCH, 10);
        let root = Root::repeat_byte(0x11);
        let node = || {
            MockBeaconNode::new().with_proposers_v2(
                GLOAS_EPOCH,
                root,
                vec![duty(&pubkeys[0], 3, slot)],
            )
        };
        let refusing = node();
        refusing
            .refused_preference_slots
            .lock()
            .expect("lock")
            .push(slot);
        let fallback = Arc::new(FallbackBeaconNode::new(vec![node(), refusing]));
        let service =
            PreferencesService::new(fallback.clone(), context(), settings(Some(FEE_RECIPIENT)));
        let held = |position: usize| {
            fallback.nodes()[position]
                .submitted_preferences
                .lock()
                .expect("lock")
                .clone()
        };
        let current = slot_in(GLOAS_EPOCH, 1);

        let counted = service
            .publish_epoch(current, GLOAS_EPOCH, &snapshot, &store)
            .await;
        assert_eq!(counted, 1, "published once a node took it");
        assert_eq!(held(0).len(), 1);
        assert!(held(1).is_empty());
        let partly = HashMap::from([((slot, root), "partly")]);
        assert_eq!(stages(&service), partly, "not every node has it");

        // Still refused: sent to both again, not counted again, and not a
        // refusal, since a node holds it.
        let counted = service
            .publish_epoch(current + 1, GLOAS_EPOCH, &snapshot, &store)
            .await;
        assert_eq!(counted, 0);
        assert_eq!(held(0).len(), 2);
        assert!(held(1).is_empty());
        assert_eq!(stages(&service), partly);

        fallback.nodes()[1]
            .refused_preference_slots
            .lock()
            .expect("lock")
            .clear();
        let counted = service
            .publish_epoch(current + 2, GLOAS_EPOCH, &snapshot, &store)
            .await;
        assert_eq!(counted, 0, "the accepting node's copy is not counted twice");
        let first = held(0)[0].clone();
        assert_eq!(held(1), vec![first], "the message as first signed");
        assert_eq!(
            stages(&service),
            HashMap::from([((slot, root), "everywhere")])
        );

        // Every node has it: nothing more is sent.
        service
            .publish_epoch(current + 3, GLOAS_EPOCH, &snapshot, &store)
            .await;
        assert_eq!(held(0).len(), 3);
        assert_eq!(held(1).len(), 1);
    }

    /// A key the keymanager deletes while the poll waits on the duties (after
    /// the poll's snapshot of the keys, before its signing) is skipped, and
    /// the other validators' preferences still go out.
    #[tokio::test]
    async fn a_key_removed_before_signing_is_skipped_without_losing_the_others() {
        let (store, pubkeys) = store_with_keys(2);
        let store = Arc::new(RwLock::new(store));
        let kept = slot_in(GLOAS_EPOCH, 11);
        let mut node = MockBeaconNode::new().with_proposers_v2(
            GLOAS_EPOCH,
            Root::repeat_byte(0x11),
            vec![
                duty(&pubkeys[0], 3, slot_in(GLOAS_EPOCH, 10)),
                duty(&pubkeys[1], 4, kept),
            ],
        );
        let deleted_from = store.clone();
        let deleted = pubkeys[0];
        node.on_proposer_duties_v2 = Some(Box::new(move || {
            deleted_from
                .try_write()
                .expect("the poll holds no guard while it waits on the node")
                .remove(&deleted);
        }));
        let (service, node) = service(node, settings(Some(FEE_RECIPIENT)));

        service
            .clone()
            .poll(slot_in(GLOAS_EPOCH, 1), store.clone())
            .await;

        assert!(
            !store.read().await.contains(&pubkeys[0]),
            "deleted mid-poll"
        );
        let sent = submitted(&node);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1[0].message.validator_index, 4);
        assert_eq!(
            stages(&service),
            HashMap::from([((kept, Root::repeat_byte(0x11)), "everywhere")])
        );
    }

    /// A node that restarts loses what it accepted. Each preference every node
    /// took is sent again, as first signed, once a round: at the poll of an
    /// epoch's last slot, so the next epoch's first slot is covered too. A
    /// re-send is not counted as published again.
    #[tokio::test]
    async fn every_kept_preference_is_sent_again_once_an_epoch() {
        let (store, pubkeys) = store_with_keys(1);
        let snapshot: HashSet<BlsPubkey> = pubkeys.iter().copied().collect();
        let store = Arc::new(RwLock::new(store));
        let first_slot = slot_in(GLOAS_EPOCH + 1, 0);
        let later_slot = slot_in(GLOAS_EPOCH + 1, 4);
        let root = Root::repeat_byte(0x22);
        let node = MockBeaconNode::new().with_proposers_v2(
            GLOAS_EPOCH + 1,
            root,
            vec![
                duty(&pubkeys[0], 3, first_slot),
                duty(&pubkeys[0], 3, later_slot),
            ],
        );
        let settings = settings(Some(FEE_RECIPIENT));
        let (service, node) = service(node, settings.clone());
        let publish = |current: Slot| {
            let service = service.clone();
            let snapshot = snapshot.clone();
            let store = store.clone();
            async move {
                service
                    .publish_epoch(current, GLOAS_EPOCH + 1, &snapshot, &store)
                    .await
            }
        };
        let last_of_epoch = slot_in(GLOAS_EPOCH, preset::SLOTS_PER_EPOCH - 1);
        let sent_slots = |from: usize| -> Vec<Slot> {
            let mut slots: Vec<Slot> = submitted(&node)[from..]
                .iter()
                .map(|(_, entries)| entries[0].message.proposal_slot)
                .collect();
            slots.sort();
            slots
        };

        // Published the epoch before their own, and not again before its end.
        assert_eq!(publish(slot_in(GLOAS_EPOCH, 1)).await, 2);
        publish(last_of_epoch - 1).await;
        assert_eq!(submitted(&node).len(), 2);
        assert_eq!(
            service.accepted_fee_recipients(later_slot, 3),
            vec![FEE_RECIPIENT]
        );

        // The address changes; the round's re-send still carries the one
        // signed, for both slots, the next epoch's first included.
        settings.set_fee_recipient(&pubkeys[0], H160([0xcd; 20]));
        assert_eq!(
            publish(last_of_epoch).await,
            0,
            "a re-send is not published again"
        );
        assert_eq!(sent_slots(2), vec![first_slot, later_slot]);
        let sent = submitted(&node);
        let mut first: Vec<_> = sent[..2].iter().map(|(_, entries)| &entries[0]).collect();
        let mut again: Vec<_> = sent[2..].iter().map(|(_, entries)| &entries[0]).collect();
        first.sort_by_key(|entry| entry.message.proposal_slot);
        again.sort_by_key(|entry| entry.message.proposal_slot);
        assert_eq!(again, first, "the messages as first signed");
        assert_eq!(
            service.accepted_fee_recipients(later_slot, 3),
            vec![FEE_RECIPIENT]
        );

        // Once a round: the next epoch's polls send nothing more.
        publish(first_slot).await;
        publish(first_slot + 1).await;
        assert_eq!(submitted(&node).len(), 4);
    }

    /// A round's re-send no node takes (every node restarted and is not ready
    /// yet) is sent each slot from then on, until one does.
    #[tokio::test]
    async fn a_re_send_no_node_takes_is_sent_each_slot() {
        let (store, pubkeys) = store_with_keys(1);
        let snapshot: HashSet<BlsPubkey> = pubkeys.iter().copied().collect();
        let store = Arc::new(RwLock::new(store));
        let slot = slot_in(GLOAS_EPOCH + 1, 4);
        let root = Root::repeat_byte(0x22);
        let node = MockBeaconNode::new().with_proposers_v2(
            GLOAS_EPOCH + 1,
            root,
            vec![duty(&pubkeys[0], 3, slot)],
        );
        let (service, node) = service(node, settings(Some(FEE_RECIPIENT)));
        let publish = |current: Slot| {
            let service = service.clone();
            let snapshot = snapshot.clone();
            let store = store.clone();
            async move {
                service
                    .publish_epoch(current, GLOAS_EPOCH + 1, &snapshot, &store)
                    .await
            }
        };

        publish(slot_in(GLOAS_EPOCH, 1)).await;
        node.failures
            .lock()
            .expect("lock")
            .insert("submit_proposer_preferences", "syncing".to_string());
        publish(slot_in(GLOAS_EPOCH, preset::SLOTS_PER_EPOCH - 1)).await;
        let key = (slot, root);
        assert_eq!(stages(&service), HashMap::from([(key, "partly")]));
        assert_eq!(
            service.accepted_fee_recipients(slot, 3),
            vec![FEE_RECIPIENT]
        );

        node.failures.lock().expect("lock").clear();
        publish(slot_in(GLOAS_EPOCH + 1, 0)).await;
        assert_eq!(submitted(&node).len(), 2, "sent again the next slot");
        assert_eq!(stages(&service), HashMap::from([(key, "everywhere")]));
    }

    /// The case a restart makes with two nodes: both took a preference, and
    /// one refuses the round's re-send (restarted, not synced yet). It drops
    /// to one only some nodes hold, is not counted again, and goes to both
    /// nodes each slot until the refusing one takes it.
    #[tokio::test]
    async fn a_re_send_one_of_two_nodes_refuses_is_sent_each_slot() {
        use crate::beacon_node::fallback::FallbackBeaconNode;

        let (store, pubkeys) = store_with_keys(1);
        let snapshot: HashSet<BlsPubkey> = pubkeys.iter().copied().collect();
        let store = Arc::new(RwLock::new(store));
        let slot = slot_in(GLOAS_EPOCH + 1, 4);
        let root = Root::repeat_byte(0x22);
        let node = || {
            MockBeaconNode::new().with_proposers_v2(
                GLOAS_EPOCH + 1,
                root,
                vec![duty(&pubkeys[0], 3, slot)],
            )
        };
        let fallback = Arc::new(FallbackBeaconNode::new(vec![node(), node()]));
        let service =
            PreferencesService::new(fallback.clone(), context(), settings(Some(FEE_RECIPIENT)));
        let held = |position: usize| {
            fallback.nodes()[position]
                .submitted_preferences
                .lock()
                .expect("lock")
                .len()
        };
        let refusing = |refuse: bool| {
            let mut slots = fallback.nodes()[1]
                .refused_preference_slots
                .lock()
                .expect("lock");
            slots.clear();
            if refuse {
                slots.push(slot);
            }
        };
        let key = (slot, root);

        let counted = service
            .publish_epoch(slot_in(GLOAS_EPOCH, 1), GLOAS_EPOCH + 1, &snapshot, &store)
            .await;
        assert_eq!(counted, 1);
        assert_eq!(stages(&service), HashMap::from([(key, "everywhere")]));

        refusing(true);
        let last_of_epoch = slot_in(GLOAS_EPOCH, preset::SLOTS_PER_EPOCH - 1);
        let counted = service
            .publish_epoch(last_of_epoch, GLOAS_EPOCH + 1, &snapshot, &store)
            .await;
        assert_eq!(counted, 0, "a re-send is not published again");
        assert_eq!((held(0), held(1)), (2, 1));
        assert_eq!(stages(&service), HashMap::from([(key, "partly")]));

        refusing(false);
        let counted = service
            .publish_epoch(
                slot_in(GLOAS_EPOCH + 1, 0),
                GLOAS_EPOCH + 1,
                &snapshot,
                &store,
            )
            .await;
        assert_eq!(counted, 0);
        assert_eq!((held(0), held(1)), (3, 2), "sent to both the next slot");
        assert_eq!(stages(&service), HashMap::from([(key, "everywhere")]));
    }

    /// A poll that started late, its slot behind the clock's, does not send a
    /// preference whose slot has started since.
    #[tokio::test]
    async fn a_slot_the_clock_says_started_is_not_sent() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let (store, pubkeys) = store_with_keys(1);
        let store = Arc::new(RwLock::new(store));
        let started = slot_in(GLOAS_EPOCH, 3);
        let ahead = slot_in(GLOAS_EPOCH, 10);
        let node = MockBeaconNode::new().with_proposers_v2(
            GLOAS_EPOCH,
            Root::repeat_byte(0x11),
            vec![duty(&pubkeys[0], 3, started), duty(&pubkeys[0], 3, ahead)],
        );
        // One second into slot 5 of the gloas epoch.
        let config = context().config.clone();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("after 1970")
            .as_secs();
        let clock_slot = slot_in(GLOAS_EPOCH, 5);
        let genesis = now - clock_slot * config.slot_duration_ms / 1000 - 1;
        let clock = SlotClock::from_config(genesis, &config);
        let node = Arc::new(node);
        let service = Arc::new(
            PreferencesService::new(node.clone(), context(), settings(Some(FEE_RECIPIENT)))
                .with_clock(clock),
        );

        service.poll(slot_in(GLOAS_EPOCH, 1), store).await;

        let sent = submitted(&node);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1[0].message.proposal_slot, ahead);
    }

    /// No keys loaded: no duties are fetched and nothing is signed.
    #[tokio::test]
    async fn with_no_keys_loaded_no_duties_are_fetched() {
        let (_, pubkeys) = store_with_keys(1);
        let store = Arc::new(RwLock::new(ValidatorStore::new()));
        let node = MockBeaconNode::new().with_proposers_v2(
            GLOAS_EPOCH,
            Root::repeat_byte(0x11),
            vec![duty(&pubkeys[0], 3, slot_in(GLOAS_EPOCH, 10))],
        );
        let (service, node) = service(node, settings(Some(FEE_RECIPIENT)));

        service.poll(slot_in(GLOAS_EPOCH, 1), store).await;

        assert_eq!(node.proposer_duties_v2_call_count(), 0);
        assert!(submitted(&node).is_empty());
    }

    /// Every preference of a poll, both target epochs', is sent at once: a
    /// node that takes the whole request timeout to answer costs the poll one
    /// timeout, not one per preference.
    #[tokio::test(start_paused = true)]
    async fn a_slow_node_costs_a_poll_one_wait() {
        let (store, pubkeys) = store_with_keys(1);
        let store = Arc::new(RwLock::new(store));
        let wait = std::time::Duration::from_secs(8);
        let node = MockBeaconNode::new()
            .with_proposers_v2(
                GLOAS_EPOCH,
                Root::repeat_byte(0x11),
                (10..13)
                    .map(|offset| duty(&pubkeys[0], 3, slot_in(GLOAS_EPOCH, offset)))
                    .collect(),
            )
            .with_proposers_v2(
                GLOAS_EPOCH + 1,
                Root::repeat_byte(0x22),
                (4..6)
                    .map(|offset| duty(&pubkeys[0], 3, slot_in(GLOAS_EPOCH + 1, offset)))
                    .collect(),
            )
            .with_preference_delay(wait);
        let (service, node) = service(node, settings(Some(FEE_RECIPIENT)));

        let began = tokio::time::Instant::now();
        service.poll(slot_in(GLOAS_EPOCH, 1), store).await;

        assert_eq!(submitted(&node).len(), 5);
        assert_eq!(began.elapsed(), wait, "five sends, one wait");
    }
}
