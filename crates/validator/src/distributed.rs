//! Distributed validator mode (`--distributed`): aggregation decided by the
//! combined selection proofs a middleware returns.
//!
//! # Why the client cannot decide alone
//!
//! Behind distributed validator middleware (Obol Charon), a validator's key is
//! split into shares across several operators, and this client holds one
//! share. The middleware combines a threshold of the operators' partial
//! signatures into one under the validator's key, so attestations and blocks
//! need nothing from the client. Aggregation does: whether a validator
//! aggregates is the hash of its selection proof (see
//! [`crate::aggregation_selection`]), and a share's partial proof hashes to a
//! different value than the combined one. Each operator's client would reach
//! its own, wrong, verdict, and put a partial proof in the `AggregateAndProof`
//! that no node accepts.
//!
//! # What is exchanged, and when
//!
//! The middleware serves two Beacon API endpoints for this, which take the
//! partial proofs and answer the combined ones:
//!
//! - `beacon_committee_selections`, for attester duties. Each epoch, and
//!   whenever else the duty loop owes the subnet subscriptions again (a node
//!   let back in, a swapped schedule, a dependent root that moved), in the
//!   task the subscriptions are sent from, every duty whose slot has not
//!   passed is signed and sent, the current epoch's in one request and
//!   then the next epoch's in another, and each epoch's subscriptions go out
//!   once its answer is in. Two requests, as `ethereum/beacon-APIs` asks
//!   (its PR 573: a request with other slots than the other operators' makes
//!   aggregations fail, and a next-epoch request may go unanswered). Charon
//!   answers a request only once it has combined every entry in it (its
//!   `BeaconCommitteeSelections` awaits each in turn), so next-epoch entries
//!   the other operators' clients do not send would hold the current
//!   epoch's answer back with them. Leaving out the slots that have passed
//!   is a precaution of the same kind.
//! - `sync_committee_selections`, for sync committee contributions: every
//!   sync duty's subnets, at the start of each slot, read at the slot's
//!   contribution deadline.
//!
//! The combined proofs are remembered in the [`SigningContext`], which with
//! the mode on holds nothing else, and every decision reads them there:
//! [`SigningContext::selection_proof`] for the subscription's
//! `is_aggregator` and the aggregation tick, and
//! [`SigningContext::sync_selection_proof`] for the contribution. The
//! combined proof is the one published in the `AggregateAndProof` and the
//! `ContributionAndProof`.
//!
//! # Failure
//!
//! A duty with no combined proof aggregates for nobody. Its subscription
//! still goes out, with `is_aggregator: false`, since it is what puts the
//! beacon node on the subnet at all, and no aggregate or contribution is
//! asked for. Falling back to the partial proof would only add aggregates
//! nobody can combine. The current epoch's duties that are still missing a
//! proof are asked for again at the next slot, as Lighthouse does, one
//! request per slot, so an entry the middleware cannot combine holds back
//! only its own slot's duties. The subscriptions of those whose combined
//! proof then selects them are sent again, now with the role. The next
//! epoch's are asked for again at the next epoch, as that epoch's current
//! ones.
//!
//! Nothing here is slashable, and nothing changes on the beacon node: the
//! endpoints are the middleware's, and `ethlambda beacon` does not serve them.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::SystemTime;

use ethlambda_types::beacon::primitives::{BlsPubkey, BlsSignature, Slot, ValidatorIndex};
use ethlambda_types::beacon::signing::compute_epoch_at_slot;
use futures_util::future::join_all;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

use crate::aggregation_selection::selection_for;
use crate::beacon_node::dto::{AttesterDutyDto, SyncDutyDto, parse_pubkey};
use crate::beacon_node::{BeaconCommitteeSelection, BeaconNodeApi, SyncCommitteeSelection};
use crate::error::{Error, Result};
use crate::keys::ValidatorStore;
use crate::signing::{SigningContext, sign_all, sign_all_within};
use crate::slot_clock::SlotClock;
use crate::subscriptions::{self, SUBSCRIPTION_SIGNING_BUDGET};
use crate::sync_committee::subnets_of;

/// The selection proof exchanges of a client running with `--distributed`.
pub struct Distributed<B> {
    beacon_node: Arc<B>,
    context: Arc<SigningContext>,
    /// Held while the current epoch's attester selections are exchanged, so
    /// a retry never sends what an epoch's round or another retry is still
    /// waiting on. An epoch's round waits for it, since its subscriptions
    /// must go out; a retry that finds it held skips the slot. The round's
    /// next-epoch exchange runs without it: a retry never sends those
    /// duties, and that request may wait out its whole timeout unanswered.
    attester: Mutex<()>,
    /// The share's own partial attester selection proofs already signed, by
    /// key and slot, so a retry or the next epoch's round sends them again
    /// without asking the signer. A middleware that keeps failing would
    /// otherwise cost a signature per missing duty every slot, a round trip
    /// each for a remote key, queued with the slot's attestations at the
    /// same signer. Never read to decide a selection: that is the combined
    /// proof, held in the [`SigningContext`].
    partials: std::sync::Mutex<Partials>,
}

/// The share's partial attester selection proofs [`Distributed`] keeps, and
/// the schedule they were signed under.
#[derive(Default)]
struct Partials {
    /// [`SigningContext::schedule_generation`] when the proofs held were
    /// signed. A schedule the chain check swaps can move a proof's domain,
    /// and the middleware refuses a partial under the old one, so a kept
    /// proof is sent again only while the schedule has not moved.
    generation: u64,
    by_duty: HashMap<(BlsPubkey, Slot), BlsSignature>,
}

impl<B: BeaconNodeApi + 'static> Distributed<B> {
    /// `context` must have distributed mode on
    /// ([`SigningContext::with_distributed`]), or the combined proofs this
    /// fetches are dropped and every selection is this client's own.
    pub fn new(beacon_node: Arc<B>, context: Arc<SigningContext>) -> Self {
        info!(
            "Distributed mode on: aggregation is decided by the combined selection proofs the \
             middleware returns"
        );
        Self {
            beacon_node,
            context,
            attester: Mutex::new(()),
            partials: std::sync::Mutex::default(),
        }
    }

    /// The partial proofs signed so far. A poisoned map is still a map of
    /// signatures.
    fn partials(&self) -> std::sync::MutexGuard<'_, Partials> {
        self.partials
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Drop the partial proofs of duties before `slot`, which no exchange
    /// sends again.
    fn forget_partials_before(&self, slot: Slot) {
        self.partials().by_duty.retain(|(_, held), _| *held >= slot);
    }

    /// The epoch's round at `slot` for `attester_duties`, on a task of its
    /// own: exchange, then subscribe (see [`Self::subscribe_epoch`]). What
    /// the duty loop sends its subnet subscriptions through in this mode,
    /// whatever owes them: a refresh that moved the attester schedule, a node
    /// let back in, a swapped schedule, or a dependent root that moved.
    pub fn spawn_round(
        self: &Arc<Self>,
        slot: Slot,
        attester_duties: Vec<AttesterDutyDto>,
        store: &Arc<RwLock<ValidatorStore>>,
    ) {
        let (this, store) = (self.clone(), store.clone());
        tokio::spawn(async move { this.subscribe_epoch(slot, &attester_duties, &store).await });
    }

    /// What the duty loop starts each slot once the slot's block is out.
    ///
    /// A retry for the current epoch's duties still missing a combined
    /// proof, unless `round` says the loop has just started a round
    /// ([`Self::spawn_round`]), which covers them. And the slot's sync
    /// committee exchange for `sync_duties`, bounded by the slot's
    /// contribution deadline, where its proofs are read. Each runs on a task
    /// of its own, so a slow middleware never delays a duty.
    pub fn after_proposal(
        self: &Arc<Self>,
        slot: Slot,
        round: bool,
        attester_duties: Vec<AttesterDutyDto>,
        sync_duties: Vec<SyncDutyDto>,
        store: &Arc<RwLock<ValidatorStore>>,
        clock: &SlotClock,
    ) {
        if !round {
            let (this, store) = (self.clone(), store.clone());
            tokio::spawn(async move { this.retry(slot, &attester_duties, &store).await });
        }

        if sync_duties.is_empty() {
            return;
        }
        // Until the contribution deadline, where the proofs are read: one
        // that lands after it decides nothing, so it is reported as missed
        // rather than remembered for no one.
        let budget = clock.until_contribution(slot, SystemTime::now());
        // A proposal that ran past the deadline leaves nothing to exchange
        // for. Not started at all: a timeout of zero still polls the exchange
        // once, which would sign every seat's partial proof for nothing.
        if budget.is_zero() {
            warn!(
                %slot,
                "Contribution deadline passed before the sync committee selection exchange; no \
                 contribution this slot"
            );
            return;
        }
        let (this, store) = (self.clone(), store.clone());
        tokio::spawn(async move {
            let exchange = this.exchange_sync(slot, &sync_duties, &store);
            match tokio::time::timeout(budget, exchange).await {
                Ok(Ok(_)) => {}
                Ok(Err(err)) => warn!(
                    %slot,
                    %err,
                    "Middleware did not combine the sync committee selection proofs; no \
                     contribution this slot"
                ),
                Err(_) => warn!(
                    %slot,
                    "Middleware did not combine the sync committee selection proofs before the \
                     contribution deadline; no contribution this slot"
                ),
            }
        });
    }

    /// The epoch's round, run when the attester schedule moved: exchange the
    /// proofs of every duty in the epoch of `slot` that has not passed, then
    /// subscribe those duties, then the same for the next epoch's duties.
    ///
    /// Every proof is sent again, those already combined as last epoch's
    /// lookahead included, as the other operators' clients send them: the
    /// endpoint is asked at the start of every epoch for all of its duties.
    /// Each epoch's subscriptions go out whether or not its exchange worked,
    /// without the role for the duties it left without a proof.
    ///
    /// Only the current epoch's exchange holds the guard the retry tries.
    /// The next epoch's runs after it is released: a retry never sends
    /// those duties, and a request the middleware leaves unanswered until
    /// its timeout would otherwise skip the next slot's retry.
    pub async fn subscribe_epoch(
        &self,
        slot: Slot,
        duties: &[AttesterDutyDto],
        store: &RwLock<ValidatorStore>,
    ) {
        let epoch = compute_epoch_at_slot(slot);
        {
            let _exchanging = self.attester.lock().await;
            self.forget_partials_before(slot);
            self.round(slot, epoch, duties, store).await;
        }
        self.round(slot, epoch + 1, duties, store).await;
    }

    /// One epoch's part of [`Self::subscribe_epoch`] at `slot`: exchange the
    /// proofs of the duties in `round` that have not passed, then subscribe
    /// them.
    async fn round(
        &self,
        slot: Slot,
        round: u64,
        duties: &[AttesterDutyDto],
        store: &RwLock<ValidatorStore>,
    ) {
        let owed: Vec<AttesterDutyDto> = duties
            .iter()
            .filter(|duty| duty.slot >= slot && compute_epoch_at_slot(duty.slot) == round)
            .cloned()
            .collect();
        if owed.is_empty() {
            return;
        }
        // The next epoch's request is one the middleware may rightly leave
        // unanswered (see the module doc), so its failure is no warning:
        // those duties are asked for again as the next epoch's current ones.
        // Either way the duties already holding a combined proof (the
        // current epoch's, from last epoch's lookahead) keep their role.
        let lookahead = round != compute_epoch_at_slot(slot);
        let exchanged = self.exchange_attester(&owed, store, lookahead).await;
        let _ = exchanged.inspect_err(|err| {
            if lookahead {
                debug!(
                    %slot,
                    epoch = round,
                    %err,
                    "Middleware did not combine the next epoch's attester selection proofs; the \
                     duties without one are subscribed without the aggregator role until its round"
                );
            } else {
                warn!(
                    %slot,
                    epoch = round,
                    %err,
                    "Middleware did not combine the attester selection proofs; the duties without \
                     one are subscribed without the aggregator role"
                );
            }
        });
        self.subscribe(round, &owed, store).await;
    }

    /// The retry at `slot`: exchange the proofs of the current epoch's duties
    /// that have not passed and hold no combined proof yet, and send the
    /// subscriptions of those the combined proof then selects again, now
    /// with the role. The others were already subscribed without it.
    ///
    /// One request per slot, all sent at once. The middleware answers a
    /// request only once it has combined every entry in it (see the module
    /// doc), so an entry it cannot combine, one the other operators' clients
    /// never send, would otherwise hold back every other duty of the epoch
    /// with it, at every retry.
    ///
    /// Skipped while another exchange is in flight. The next epoch's duties
    /// are left to that epoch's round: whether they are answered now depends
    /// on whether the other operators' clients look an epoch ahead, and a
    /// request for them every slot could go unanswered every slot.
    pub async fn retry(
        &self,
        slot: Slot,
        duties: &[AttesterDutyDto],
        store: &RwLock<ValidatorStore>,
    ) {
        let Ok(_exchanging) = self.attester.try_lock() else {
            debug!(%slot, "Attester selection exchange still in flight; not retrying this slot");
            return;
        };
        self.forget_partials_before(slot);
        let epoch = compute_epoch_at_slot(slot);
        let mut missing: BTreeMap<Slot, Vec<AttesterDutyDto>> = BTreeMap::new();
        let still_missing = duties.iter().filter(|duty| {
            duty.slot >= slot
                && compute_epoch_at_slot(duty.slot) == epoch
                && parse_pubkey(&duty.pubkey).is_ok_and(|pubkey| {
                    !self
                        .context
                        .holds_combined_selection_proof(&pubkey, duty.slot)
                })
        });
        for duty in still_missing {
            missing.entry(duty.slot).or_default().push(duty.clone());
        }
        if missing.is_empty() {
            return;
        }

        let exchanges = missing
            .values()
            .map(|owed| self.exchange_attester(owed, store, false));
        let mut combined = 0;
        let (mut failed, mut first_error) = (0, None);
        for exchanged in join_all(exchanges).await {
            match exchanged {
                Ok(answered) => combined += answered,
                Err(err) => {
                    failed += 1;
                    first_error.get_or_insert(err);
                }
            }
        }
        if let Some(err) = first_error {
            warn!(
                %slot,
                failed_slots = failed,
                missing_slots = missing.len(),
                %err,
                "Middleware still did not combine some attester selection proofs; retrying next slot"
            );
        }
        if combined == 0 {
            return;
        }

        let mut selected = Vec::new();
        for duty in missing.into_values().flatten() {
            if let Ok(Some(_)) = selection_for(&self.context, store, &duty).await {
                selected.push(duty);
            }
        }
        self.subscribe(epoch, &selected, store).await;
    }

    /// Sign the partial selection proof of every duty in `duties`, send them
    /// in one `beacon_committee_selections` request, and remember the
    /// combined proofs the middleware answers. Returns how many it answered.
    ///
    /// A duty whose proof could not be signed is left out of the request, and
    /// one the middleware leaves out of its answer gets no combined proof:
    /// both aggregate for nothing until a later exchange covers them. A
    /// partial proof signed before is sent again as it was, while its key is
    /// still held, rather than signed anew.
    ///
    /// `lookahead` is for the next epoch's duties, which the middleware may
    /// rightly leave unanswered, so an answer short of them is logged at
    /// debug rather than warned about.
    pub async fn exchange_attester(
        &self,
        duties: &[AttesterDutyDto],
        store: &RwLock<ValidatorStore>,
        lookahead: bool,
    ) -> Result<usize> {
        // An unreadable pubkey is left out here, and warned about by the
        // epoch round's subscription, which still sends the duty. A retry
        // never asks for one.
        let keyed: Vec<(&AttesterDutyDto, BlsPubkey)> = duties
            .iter()
            .filter_map(|duty| Some((duty, parse_pubkey(&duty.pubkey).ok()?)))
            .collect();
        // The partial proofs signed before, for keys still held. Checked
        // here because reusing one skips `sign_selection_proof`, which is
        // where a deleted key is found. None survives a schedule swap that
        // moved a fork, since a proof may then be over the old domain.
        let generation = self.context.schedule_generation();
        let reused: Vec<Option<BlsSignature>> = {
            let held = store.read().await;
            let mut partials = self.partials();
            if partials.generation != generation {
                partials.by_duty.clear();
                partials.generation = generation;
            }
            keyed
                .iter()
                .map(|(duty, pubkey)| {
                    let partial = partials.by_duty.get(&(*pubkey, duty.slot)).copied()?;
                    held.contains(pubkey).then_some(partial)
                })
                .collect()
        };
        // The subscription's budget, for its reason: this runs off the slot
        // loop ahead of the subscriptions, with no slot deadline behind it.
        let signed = sign_all_within(
            SUBSCRIPTION_SIGNING_BUDGET,
            keyed
                .iter()
                .zip(&reused)
                .filter(|(_, reused)| reused.is_none())
                .map(|((duty, pubkey), _)| {
                    (
                        *pubkey,
                        self.context.sign_selection_proof(store, pubkey, duty.slot),
                    )
                }),
        )
        .await;
        let mut signed = signed.into_iter();
        let partials: Vec<Result<BlsSignature>> = reused
            .into_iter()
            .map(|reused| match reused {
                Some(partial) => Ok(partial),
                None => signed.next().unwrap_or_else(|| {
                    unreachable!("`sign_all_within` answers every request it is given")
                }),
            })
            .collect();
        // Kept only if the schedule did not move while they were signed:
        // one signed across a swap may be over either domain. Checked under
        // the lock that clears them, so a swap seen by a later exchange
        // cannot be followed by an insert from this one.
        {
            let mut held = self.partials();
            if self.context.schedule_generation() == generation {
                for ((duty, pubkey), partial) in keyed.iter().zip(&partials) {
                    if let Ok(partial) = partial {
                        held.by_duty.insert((*pubkey, duty.slot), *partial);
                    }
                }
            }
        }

        let mut asked = Vec::with_capacity(keyed.len());
        let mut pubkeys: HashMap<(ValidatorIndex, Slot), BlsPubkey> = HashMap::new();
        for ((duty, pubkey), partial) in keyed.into_iter().zip(partials) {
            match partial {
                Ok(selection_proof) => {
                    let selection = BeaconCommitteeSelection {
                        validator_index: duty.validator_index,
                        slot: duty.slot,
                        selection_proof,
                    };
                    pubkeys.insert(selection.key(), pubkey);
                    asked.push(selection);
                }
                // A key the keymanager deleted since the schedule was fetched.
                Err(Error::UnknownValidator(_)) => debug!(
                    slot = duty.slot,
                    validator = duty.validator_index,
                    "Duty names a key this client no longer holds; not asking the middleware"
                ),
                Err(err) => {
                    warn!(
                        slot = duty.slot,
                        validator = duty.validator_index,
                        %err,
                        "Could not sign the partial selection proof; this duty aggregates for nothing"
                    );
                    crate::metrics::inc_signing_failures();
                }
            }
        }
        if asked.is_empty() {
            return Ok(0);
        }

        let answers = self.beacon_node.beacon_committee_selections(&asked).await?;
        let mut combined = 0;
        for answer in answers {
            // The implementation refused any answer naming an entry not
            // asked, so every key is found.
            if let Some(pubkey) = pubkeys.get(&answer.key()) {
                self.context.remember_combined_selection_proof(
                    *pubkey,
                    answer.slot,
                    answer.selection_proof,
                );
                combined += 1;
            }
        }
        if combined < asked.len() && !lookahead {
            warn!(
                asked = asked.len(),
                combined, "Middleware left some duties without a combined selection proof"
            );
        }
        debug!(
            asked = asked.len(),
            combined, lookahead, "Exchanged attester selection proofs"
        );
        Ok(combined)
    }

    /// Sign the partial proof of every subnet of every duty in `duties` at
    /// `slot`, send them in one `sync_committee_selections` request, and
    /// remember the combined proofs the middleware answers. Returns how many
    /// it answered.
    pub async fn exchange_sync(
        &self,
        slot: Slot,
        duties: &[SyncDutyDto],
        store: &RwLock<ValidatorStore>,
    ) -> Result<usize> {
        let mut seats = Vec::new();
        for duty in duties {
            let Ok(pubkey) = parse_pubkey(&duty.pubkey) else {
                continue;
            };
            for subnet in subnets_of(duty) {
                seats.push((duty.validator_index, pubkey, subnet));
            }
        }
        // The duty budget: these are read at this slot's contribution
        // deadline.
        let partials = sign_all(seats.iter().map(|(_, pubkey, subnet)| {
            (
                *pubkey,
                self.context
                    .sign_sync_selection_proof(store, pubkey, slot, *subnet),
            )
        }))
        .await;

        let mut asked = Vec::with_capacity(seats.len());
        let mut pubkeys: HashMap<(ValidatorIndex, Slot, u64), BlsPubkey> = HashMap::new();
        for ((validator, pubkey, subnet), partial) in seats.into_iter().zip(partials) {
            match partial {
                Ok(selection_proof) => {
                    let selection = SyncCommitteeSelection {
                        validator_index: validator,
                        slot,
                        subcommittee_index: subnet,
                        selection_proof,
                    };
                    pubkeys.insert(selection.key(), pubkey);
                    asked.push(selection);
                }
                Err(Error::UnknownValidator(_)) => debug!(
                    %slot,
                    validator,
                    "Sync duty names a key this client no longer holds; not asking the middleware"
                ),
                Err(err) => {
                    warn!(
                        %slot,
                        validator,
                        subnet,
                        %err,
                        "Could not sign the partial sync selection proof; no contribution for it"
                    );
                    crate::metrics::inc_signing_failures();
                }
            }
        }
        if asked.is_empty() {
            return Ok(0);
        }

        let answers = self.beacon_node.sync_committee_selections(&asked).await?;
        let mut combined = 0;
        for answer in answers {
            if let Some(pubkey) = pubkeys.get(&answer.key()) {
                self.context.remember_combined_sync_selection_proof(
                    *pubkey,
                    answer.slot,
                    answer.subcommittee_index,
                    answer.selection_proof,
                );
                combined += 1;
            }
        }
        if combined < asked.len() {
            warn!(
                %slot,
                asked = asked.len(),
                combined,
                "Middleware left some sync committee seats without a combined selection proof"
            );
        }
        Ok(combined)
    }

    /// Send the subscriptions for `duties`, reporting a failure as the duty
    /// loop's subscription task does.
    async fn subscribe(
        &self,
        epoch: u64,
        duties: &[AttesterDutyDto],
        store: &RwLock<ValidatorStore>,
    ) {
        let subscribed = subscriptions::subscribe(&self.beacon_node, duties, store, &self.context);
        let _ = subscribed.await.inspect_err(|err| {
            warn!(%epoch, %err, "Failed to subscribe to attestation subnets");
            crate::metrics::set_beacon_node_available(false);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregation::AggregationService;
    use crate::aggregation_selection::is_aggregator;
    use crate::beacon_node::dto::encode_hex;
    use crate::beacon_node::mock::MockBeaconNode;
    use crate::sync_committee::{SyncCommitteeService, is_sync_committee_aggregator};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::constants::TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE;
    use ethlambda_types::beacon::containers::altair::{
        SyncCommitteeContribution, sync_subcommittee_size,
    };
    use ethlambda_types::beacon::containers::shared::{AttestationData, Checkpoint};
    use ethlambda_types::beacon::fork::ForkName;
    use ethlambda_types::beacon::preset::slots_per_epoch;
    use ethlambda_types::beacon::primitives::{BlsSignature, Root};
    use sha2::{Digest, Sha256};

    const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    /// The first slot of epoch 100, where every test's round runs.
    const EPOCH_START: Slot = 3200;

    fn secret() -> [u8; 32] {
        hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("valid hex")
            .try_into()
            .expect("32 bytes")
    }

    fn store() -> (RwLock<ValidatorStore>, BlsPubkey) {
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        (RwLock::new(store), pubkey)
    }

    /// The client behind the middleware.
    fn distributed_context() -> Arc<SigningContext> {
        Arc::new(SigningContext::new(Config::mainnet(), Root::ZERO).with_distributed())
    }

    /// The same key with the mode off, whose proofs are the share's own
    /// verdicts.
    fn local_context() -> Arc<SigningContext> {
        Arc::new(SigningContext::new(Config::mainnet(), Root::ZERO))
    }

    fn duty(pubkey: &BlsPubkey, validator_index: u64, slot: Slot) -> AttesterDutyDto {
        AttesterDutyDto {
            pubkey: encode_hex(&pubkey.0),
            validator_index,
            committee_index: 2,
            committee_length: 128,
            committees_at_slot: 64,
            validator_committee_index: 7,
            slot,
        }
    }

    fn data(slot: Slot) -> AttestationData {
        AttestationData {
            slot,
            index: 0,
            beacon_block_root: Root::repeat_byte(7),
            source: Checkpoint {
                epoch: slot / 32 - 1,
                root: Root::ZERO,
            },
            target: Checkpoint {
                epoch: slot / 32,
                root: Root::ZERO,
            },
        }
    }

    /// A 96-byte value whose SHA-256 does (or does not) select under
    /// `modulo`. Not a curve point: a combined proof is never verified here,
    /// only hashed and published.
    fn proof_that_selects(modulo: u64, selected: bool) -> BlsSignature {
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
        panic!("no proof found");
    }

    /// A combined attester proof that selects (or not) in a 128-member
    /// committee, whose modulus is 8.
    fn attester_proof(selected: bool) -> BlsSignature {
        let combined = proof_that_selects(8, selected);
        assert_eq!(is_aggregator(128, &combined), selected);
        combined
    }

    fn sync_proof(selected: bool) -> BlsSignature {
        let modulo =
            (sync_subcommittee_size() as u64 / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE).max(1);
        let combined = proof_that_selects(modulo, selected);
        assert_eq!(is_sync_committee_aggregator(&combined), selected);
        combined
    }

    fn verifies(pubkey: &BlsPubkey, signature: &BlsSignature, root: Root) -> bool {
        use blst::min_pk::{PublicKey, Signature};
        let pk = PublicKey::from_bytes(&pubkey.0).expect("valid pubkey");
        let Ok(sig) = Signature::from_bytes(&signature.0) else {
            return false;
        };
        sig.verify(true, root.as_slice(), DST, &[], &pk, true) == blst::BLST_ERROR::BLST_SUCCESS
    }

    /// The first slot from epoch 100 on at which this key's own proof does
    /// (`selected`) or does not select it. Found rather than written down:
    /// which slots those are is a property of SHA-256. The range is the one
    /// `aggregation`'s tests find both in, for the same key.
    async fn slot_whose_own_proof_selects(
        store: &RwLock<ValidatorStore>,
        pubkey: &BlsPubkey,
        selected: bool,
    ) -> Slot {
        let local = local_context();
        for slot in EPOCH_START..3_400 {
            let own = local
                .sign_selection_proof(store, pubkey, slot)
                .await
                .expect("signs");
            if is_aggregator(128, &own) == selected {
                return slot;
            }
        }
        panic!("no slot found");
    }

    /// The first slot of the epoch `slot` is in, where that epoch's round
    /// runs.
    fn epoch_start(slot: Slot) -> Slot {
        compute_epoch_at_slot(slot) * slots_per_epoch()
    }

    fn assert_partials_are_the_shares_own(
        node: &MockBeaconNode,
        pubkey: &BlsPubkey,
        context: &SigningContext,
    ) {
        for request in node.selection_requests() {
            for entry in request {
                assert!(
                    verifies(
                        pubkey,
                        &entry.selection_proof,
                        context.selection_proof_signing_root(entry.slot)
                    ),
                    "slot {}: the middleware must be sent the share's own proof",
                    entry.slot
                );
            }
        }
    }

    /// The combined proof decides, against the share's own verdict either
    /// way: the subscription's role, whether the aggregation tick asks for an
    /// aggregate, and the proof the `AggregateAndProof` carries.
    #[tokio::test]
    async fn the_subscription_aggregation_and_published_proof_follow_the_combined_proof() {
        let (store, pubkey) = store();
        // Selected by the middleware where its own proof would not, and the
        // other way round.
        let chosen = slot_whose_own_proof_selects(&store, &pubkey, false).await;
        let passed_over = slot_whose_own_proof_selects(&store, &pubkey, true).await;
        let node = Arc::new(
            MockBeaconNode::new()
                .with_combined_selection(1, chosen, attester_proof(true))
                .with_combined_selection(2, passed_over, attester_proof(false))
                .with_aggregate(data(chosen)),
        );
        let context = distributed_context();
        let distributed = Distributed::new(node.clone(), context.clone());

        // Each duty's round runs at the start of its own epoch.
        for (validator, slot) in [(1, chosen), (2, passed_over)] {
            distributed
                .subscribe_epoch(epoch_start(slot), &[duty(&pubkey, validator, slot)], &store)
                .await;
        }

        let asked: Vec<BeaconCommitteeSelection> =
            node.selection_requests().into_iter().flatten().collect();
        assert_eq!(asked.len(), 2, "both duties are sent to the middleware");
        assert_partials_are_the_shares_own(&node, &pubkey, &context);

        let subscriptions = node.subscriptions();
        let role = |validator| {
            subscriptions
                .iter()
                .find(|entry| entry.validator_index == validator)
                .expect("subscribed")
                .is_aggregator
        };
        assert!(role(1), "the combined proof selects validator 1");
        assert!(!role(2), "the combined proof passes validator 2 over");

        let aggregation = AggregationService::new(node.clone(), context.clone());
        let published = aggregation
            .aggregate(chosen, &data(chosen), &[duty(&pubkey, 1, chosen)], &store)
            .await
            .expect("aggregates");
        assert_eq!(published, 1);
        let (_, list) = node.published_aggregates().remove(0);
        assert_eq!(list[0].message.selection_proof, attester_proof(true));

        let published = aggregation
            .aggregate(
                passed_over,
                &data(passed_over),
                &[duty(&pubkey, 2, passed_over)],
                &store,
            )
            .await
            .expect("no-op");
        assert_eq!(published, 0);
        assert_eq!(
            node.aggregate_requests().len(),
            1,
            "nothing is asked for the duty the middleware passed over"
        );
    }

    /// The current epoch and the next go in separate requests, current
    /// first, and a duty whose slot has passed is not sent.
    #[tokio::test]
    async fn each_epoch_is_its_own_request_and_past_slots_are_left_out() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new());
        let distributed = Distributed::new(node.clone(), distributed_context());
        let now = EPOCH_START + 4;
        let duties = vec![
            duty(&pubkey, 1, EPOCH_START + 1),
            duty(&pubkey, 2, EPOCH_START + 10),
            duty(&pubkey, 3, EPOCH_START + 40),
        ];

        distributed.subscribe_epoch(now, &duties, &store).await;

        let requests = node.selection_requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].len(), 1);
        assert_eq!(requests[0][0].slot, EPOCH_START + 10);
        assert_eq!(requests[1].len(), 1);
        assert_eq!(requests[1][0].slot, EPOCH_START + 40);
        // Subscribed without the role, since the middleware answered
        // nothing, and only for the duties still ahead.
        let subscriptions = node.subscriptions();
        assert_eq!(subscriptions.len(), 2);
        assert!(subscriptions.iter().all(|entry| !entry.is_aggregator));
    }

    /// A combined proof held from last epoch's lookahead must not be sent
    /// as the share's own when the epoch's round asks for that slot again.
    #[tokio::test]
    async fn a_second_round_for_a_slot_still_sends_the_shares_own_proof() {
        let (store, pubkey) = store();
        let slot = EPOCH_START + 40;
        let node =
            Arc::new(MockBeaconNode::new().with_combined_selection(1, slot, attester_proof(true)));
        let context = distributed_context();
        let distributed = Distributed::new(node.clone(), context.clone());
        let duties = vec![duty(&pubkey, 1, slot)];

        // As the lookahead, then as the next epoch's current one.
        distributed
            .subscribe_epoch(EPOCH_START, &duties, &store)
            .await;
        distributed
            .subscribe_epoch(EPOCH_START + 32, &duties, &store)
            .await;

        assert_eq!(node.selection_requests().len(), 2);
        assert_partials_are_the_shares_own(&node, &pubkey, &context);
        assert_eq!(
            context
                .selection_proof(&store, &pubkey, slot)
                .await
                .expect("held"),
            Some(attester_proof(true))
        );
    }

    /// The middleware failing: every subscription still goes out, without
    /// the role even where the share's own proof would select, and the
    /// aggregation tick asks for nothing.
    #[tokio::test]
    async fn a_middleware_error_leaves_every_duty_without_the_role() {
        let (store, pubkey) = store();
        let own_selects = slot_whose_own_proof_selects(&store, &pubkey, true).await;
        let node = Arc::new(
            MockBeaconNode::new()
                .failing_call("beacon_committee_selections", "middleware down")
                .with_aggregate(data(own_selects)),
        );
        let context = distributed_context();
        let distributed = Distributed::new(node.clone(), context.clone());
        let duties = vec![duty(&pubkey, 1, own_selects)];

        distributed
            .subscribe_epoch(epoch_start(own_selects), &duties, &store)
            .await;

        let subscriptions = node.subscriptions();
        assert_eq!(subscriptions.len(), 1, "the subscription still goes out");
        assert!(!subscriptions[0].is_aggregator);

        let published = AggregationService::new(node.clone(), context)
            .aggregate(own_selects, &data(own_selects), &duties, &store)
            .await
            .expect("no-op");
        assert_eq!(published, 0);
        assert!(node.aggregate_requests().is_empty());
    }

    /// After a failed round, the next slot asks again for the current
    /// epoch's duties still ahead and missing a proof, and re-sends the
    /// subscription of one that now has it, with the role. The next epoch's
    /// duties wait for their own round.
    #[tokio::test]
    async fn a_failed_exchange_is_retried_next_slot_and_resubscribes_with_the_role() {
        let (store, pubkey) = store();
        let current = EPOCH_START + 5;
        let next_epoch = EPOCH_START + 40;
        let node = Arc::new(
            MockBeaconNode::new()
                .failing_call("beacon_committee_selections", "middleware down")
                .with_combined_selection(1, current, attester_proof(true))
                .with_combined_selection(2, next_epoch, attester_proof(true)),
        );
        let distributed = Distributed::new(node.clone(), distributed_context());
        let duties = vec![duty(&pubkey, 1, current), duty(&pubkey, 2, next_epoch)];

        distributed
            .subscribe_epoch(EPOCH_START, &duties, &store)
            .await;
        assert!(node.selection_requests().is_empty());
        assert!(
            node.subscriptions()
                .iter()
                .all(|entry| !entry.is_aggregator)
        );

        node.failures
            .lock()
            .expect("lock")
            .remove("beacon_committee_selections");
        distributed.retry(EPOCH_START + 1, &duties, &store).await;

        let requests = node.selection_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0]
                .iter()
                .map(|entry| entry.slot)
                .collect::<Vec<_>>(),
            vec![current],
            "only the current epoch's duty is asked again"
        );
        let resent: Vec<_> = node.subscriptions().into_iter().skip(2).collect();
        assert_eq!(resent.len(), 1);
        assert_eq!(resent[0].validator_index, 1);
        assert!(resent[0].is_aggregator);

        // Nothing is missing any more, so the slot after asks for nothing.
        distributed.retry(EPOCH_START + 2, &duties, &store).await;
        assert_eq!(node.selection_requests().len(), 1);
    }

    /// The retry asks for each slot in a request of its own, so an entry
    /// the middleware cannot combine holds back only its own slot's, and
    /// re-sends only the subscriptions a combined proof selects: the round
    /// already sent the others without the role.
    #[tokio::test]
    async fn a_retry_asks_per_slot_and_resubscribes_only_the_selected() {
        let (store, pubkey) = store();
        let (chosen, passed_over) = (EPOCH_START + 5, EPOCH_START + 9);
        let node = Arc::new(
            MockBeaconNode::new()
                .failing_call("beacon_committee_selections", "middleware down")
                .with_combined_selection(1, chosen, attester_proof(true))
                .with_combined_selection(2, passed_over, attester_proof(false)),
        );
        let distributed = Distributed::new(node.clone(), distributed_context());
        let duties = vec![duty(&pubkey, 1, chosen), duty(&pubkey, 2, passed_over)];

        distributed
            .subscribe_epoch(EPOCH_START, &duties, &store)
            .await;
        let subscribed = node.subscriptions().len();
        assert_eq!(subscribed, 2, "the round subscribes both, without the role");

        node.failures
            .lock()
            .expect("lock")
            .remove("beacon_committee_selections");
        distributed.retry(EPOCH_START + 1, &duties, &store).await;

        let mut asked: Vec<Vec<Slot>> = node
            .selection_requests()
            .iter()
            .map(|request| request.iter().map(|entry| entry.slot).collect())
            .collect();
        asked.sort();
        assert_eq!(
            asked,
            vec![vec![chosen], vec![passed_over]],
            "one request per slot"
        );
        let resent: Vec<_> = node.subscriptions().into_iter().skip(subscribed).collect();
        assert_eq!(resent.len(), 1, "only the selected duty is re-sent");
        assert_eq!(resent[0].validator_index, 1);
        assert!(resent[0].is_aggregator);
    }

    /// A partial proof signed for an exchange that failed is sent again as
    /// it was by the retry, not signed anew, and forgotten once its slot has
    /// passed.
    #[tokio::test]
    async fn a_retry_sends_the_partial_proof_signed_before() {
        let (store, pubkey) = store();
        let current = EPOCH_START + 5;
        let node = Arc::new(
            MockBeaconNode::new()
                .failing_call("beacon_committee_selections", "middleware down")
                .with_combined_selection(1, current, attester_proof(true)),
        );
        let distributed = Distributed::new(node.clone(), distributed_context());
        let duties = vec![duty(&pubkey, 1, current)];

        distributed
            .subscribe_epoch(EPOCH_START, &duties, &store)
            .await;
        assert!(
            distributed
                .partials()
                .by_duty
                .contains_key(&(pubkey, current)),
            "kept although the exchange failed"
        );

        // Stands in for the kept signature, so the request shows which one
        // went out.
        let kept = BlsSignature([9; 96]);
        distributed
            .partials()
            .by_duty
            .insert((pubkey, current), kept);
        node.failures
            .lock()
            .expect("lock")
            .remove("beacon_committee_selections");
        distributed.retry(EPOCH_START + 1, &duties, &store).await;

        let requests = node.selection_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0][0].selection_proof, kept, "sent as kept");

        distributed.retry(current + 1, &duties, &store).await;
        assert!(
            distributed.partials().by_duty.is_empty(),
            "its slot has passed"
        );
    }

    /// A schedule swap that moves a fork forgets the kept partial proofs,
    /// which may be over the old domain: the retry signs the share's proof
    /// anew, under the new schedule.
    #[tokio::test]
    async fn a_schedule_swap_forgets_the_kept_partial_proofs() {
        let (store, pubkey) = store();
        let current = EPOCH_START + 5;
        let node = Arc::new(
            MockBeaconNode::new()
                .failing_call("beacon_committee_selections", "middleware down")
                .with_combined_selection(1, current, attester_proof(true)),
        );
        let context = distributed_context();
        let distributed = Distributed::new(node.clone(), context.clone());
        let duties = vec![duty(&pubkey, 1, current)];
        distributed
            .subscribe_epoch(EPOCH_START, &duties, &store)
            .await;
        let kept = BlsSignature([9; 96]);
        distributed
            .partials()
            .by_duty
            .insert((pubkey, current), kept);

        context.replace_config(Config::mainnet().with_fork_version(ForkName::Phase0, [9, 9, 9, 9]));
        node.failures
            .lock()
            .expect("lock")
            .remove("beacon_committee_selections");
        distributed.retry(EPOCH_START + 1, &duties, &store).await;

        let requests = node.selection_requests();
        assert_eq!(requests.len(), 1);
        assert_ne!(requests[0][0].selection_proof, kept, "signed anew");
        assert_partials_are_the_shares_own(&node, &pubkey, &context);
    }

    /// A partial proof kept for a key the keymanager has since deleted is
    /// not sent: reusing it skips the signer, which is where a deleted key
    /// is otherwise found.
    #[tokio::test]
    async fn a_kept_partial_proof_is_not_sent_for_a_deleted_key() {
        let (store, pubkey) = store();
        let current = EPOCH_START + 5;
        let node = Arc::new(
            MockBeaconNode::new().failing_call("beacon_committee_selections", "middleware down"),
        );
        let distributed = Distributed::new(node.clone(), distributed_context());
        let duties = vec![duty(&pubkey, 1, current)];
        distributed
            .subscribe_epoch(EPOCH_START, &duties, &store)
            .await;
        assert!(
            distributed
                .partials()
                .by_duty
                .contains_key(&(pubkey, current))
        );

        assert!(store.write().await.remove(&pubkey));
        node.failures
            .lock()
            .expect("lock")
            .remove("beacon_committee_selections");
        distributed.retry(EPOCH_START + 1, &duties, &store).await;

        assert!(
            node.selection_requests().is_empty(),
            "nothing is asked for a key no longer held"
        );
    }

    /// The seat with no combined proof is never asked for a contribution,
    /// even where the share's own proof selects it; the seat the middleware
    /// selects is, and the published proof is the combined one.
    #[tokio::test]
    async fn sync_contributions_follow_the_combined_proof() {
        let (store, pubkey) = store();
        let size = sync_subcommittee_size() as u64;
        let sync_duty = SyncDutyDto {
            pubkey: encode_hex(&pubkey.0),
            validator_index: 9,
            validator_sync_committee_indices: vec![0, size, 2 * size, 3 * size],
        };
        // A slot at which the share's own proofs select one subnet and not
        // another.
        let local = local_context();
        let mut found = None;
        for slot in EPOCH_START..EPOCH_START + 1000 {
            let mut own = Vec::new();
            for subnet in 0..4 {
                let proof = local
                    .sign_sync_selection_proof(&store, &pubkey, slot, subnet)
                    .await
                    .expect("signs");
                own.push(is_sync_committee_aggregator(&proof));
            }
            let selected = own.iter().position(|selects| *selects);
            let not_selected = own.iter().position(|selects| !*selects);
            if let (Some(selected), Some(not_selected)) = (selected, not_selected) {
                found = Some((slot, selected as u64, not_selected as u64));
                break;
            }
        }
        let (slot, own_selects, own_passes) = found.expect("a mixed slot");

        let root = Root::repeat_byte(4);
        let mut node = MockBeaconNode::new();
        for subnet in 0..4 {
            node = node
                .with_contribution(SyncCommitteeContribution {
                    slot,
                    beacon_block_root: root,
                    subcommittee_index: subnet,
                    aggregation_bits: Default::default(),
                    signature: BlsSignature([1; 96]),
                })
                .with_combined_sync_selection(9, slot, subnet, sync_proof(subnet == own_passes));
        }
        let node = Arc::new(node);
        let context = distributed_context();
        let distributed = Distributed::new(node.clone(), context.clone());

        let combined = distributed
            .exchange_sync(slot, std::slice::from_ref(&sync_duty), &store)
            .await
            .expect("exchanges");
        assert_eq!(combined, 4);
        let asked = node.sync_selection_requests().remove(0);
        assert_eq!(asked.len(), 4, "one entry per subnet");
        for entry in &asked {
            assert!(verifies(
                &pubkey,
                &entry.selection_proof,
                context.sync_selection_proof_signing_root(slot, entry.subcommittee_index)
            ));
        }

        let published = SyncCommitteeService::new(node.clone(), context)
            .aggregate(slot, root, &[sync_duty], &store)
            .await
            .expect("aggregates");
        assert_eq!(published, 1);
        let requested: Vec<u64> = node
            .contribution_requests()
            .iter()
            .map(|(_, subnet, _)| *subnet)
            .collect();
        assert_eq!(requested, vec![own_passes]);
        assert!(!requested.contains(&own_selects));
        let sent = node.published_contributions();
        assert_eq!(sent[0].message.selection_proof, sync_proof(true));
    }

    /// No answer from the middleware, no contribution, whatever the share's
    /// own proofs say.
    #[tokio::test]
    async fn a_sync_middleware_error_publishes_no_contribution() {
        let (store, pubkey) = store();
        let size = sync_subcommittee_size() as u64;
        let sync_duty = SyncDutyDto {
            pubkey: encode_hex(&pubkey.0),
            validator_index: 9,
            validator_sync_committee_indices: vec![0, size, 2 * size, 3 * size],
        };
        let slot = EPOCH_START;
        let root = Root::repeat_byte(4);
        let mut node =
            MockBeaconNode::new().failing_call("sync_committee_selections", "middleware down");
        for subnet in 0..4 {
            node = node.with_contribution(SyncCommitteeContribution {
                slot,
                beacon_block_root: root,
                subcommittee_index: subnet,
                aggregation_bits: Default::default(),
                signature: BlsSignature([1; 96]),
            });
        }
        let node = Arc::new(node);
        let context = distributed_context();
        let distributed = Distributed::new(node.clone(), context.clone());

        assert!(
            distributed
                .exchange_sync(slot, std::slice::from_ref(&sync_duty), &store)
                .await
                .is_err()
        );
        let published = SyncCommitteeService::new(node.clone(), context)
            .aggregate(slot, root, &[sync_duty], &store)
            .await
            .expect("no-op");
        assert_eq!(published, 0);
        assert!(node.contribution_requests().is_empty());
    }

    /// With the mode off the duty services never ask the middleware: the
    /// subscription, the aggregation tick and the contribution decide on
    /// this client's own proofs, and a combined proof cannot override one.
    #[tokio::test]
    async fn with_the_mode_off_no_selections_request_is_made() {
        let (store, pubkey) = store();
        let own_selects = slot_whose_own_proof_selects(&store, &pubkey, true).await;
        let context = local_context();
        // Ignored with the mode off.
        context.remember_combined_selection_proof(pubkey, own_selects, attester_proof(false));
        let root = Root::repeat_byte(4);
        let node = Arc::new(MockBeaconNode::new().with_aggregate(data(own_selects)));
        let duties = vec![duty(&pubkey, 1, own_selects)];

        subscriptions::subscribe(&node, &duties, &store, &context)
            .await
            .expect("subscribes");
        assert!(node.subscriptions()[0].is_aggregator);
        let published = AggregationService::new(node.clone(), context.clone())
            .aggregate(own_selects, &data(own_selects), &duties, &store)
            .await
            .expect("aggregates");
        assert_eq!(published, 1, "decided on this client's own proof");
        let size = sync_subcommittee_size() as u64;
        let sync_duty = SyncDutyDto {
            pubkey: encode_hex(&pubkey.0),
            validator_index: 9,
            validator_sync_committee_indices: vec![0, size, 2 * size, 3 * size],
        };
        SyncCommitteeService::new(node.clone(), context)
            .aggregate(own_selects, root, &[sync_duty], &store)
            .await
            .expect("aggregates");

        assert!(node.selection_requests().is_empty());
        assert!(node.sync_selection_requests().is_empty());
        let (_, list) = node.published_aggregates().remove(0);
        let own = local_context()
            .sign_selection_proof(&store, &pubkey, own_selects)
            .await
            .expect("signs");
        assert_eq!(list[0].message.selection_proof, own);
    }
}
