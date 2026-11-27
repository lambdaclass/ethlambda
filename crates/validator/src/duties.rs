//! What this client's validators are scheduled to do, and when.
//!
//! Holds one epoch's attester duties at a time, plus a lookahead epoch, and
//! discards them when the beacon node reports a different `dependent_root`: a
//! reorg deeper than `MIN_SEED_LOOKAHEAD` changes the committee shuffling, and
//! acting on the old schedule would attest from the wrong committee. From
//! fulu those roots are checked every slot, not only at each epoch's refresh
//! (see [`DutiesService::follow_dependent_root`]).
//!
//! Proposer duties are held alongside them, in a separate map and on
//! deliberately different terms:
//!
//! - **A lookahead only from fulu.** Since fulu, the state's
//!   `proposer_lookahead` fixes an epoch's proposers by the end of the epoch
//!   before it, so the next epoch's are fetched as the attester ones are, with
//!   v2's `dependent_root` (see [`ProposerDutiesVersion`]). That is what lets
//!   the duty loop propose at an epoch's first slot without asking the node
//!   anything first. Before fulu the next epoch's proposers are not decided
//!   until this one ends, so an answer now would be a guess: the current
//!   epoch's are fetched at its first slot, with v1's root.
//! - **Filtered on arrival.** The endpoint answers for every proposer in the
//!   epoch, not for a submitted list, so all but this client's own entries are
//!   dropped as they come in rather than at every lookup.
//! - **A change here is not a change for subscriptions.** Subnet subscriptions
//!   follow committees, and a proposer has none.
//!
//! Payload timeliness committee (PTC) duties, which exist from gloas, are held
//! in a third map on the attester schedule's terms: the current epoch and the
//! next, replaced when the `dependent_root` changes. They are narrowed to this
//! client's indices on arrival, and are not part of subnet subscriptions
//! either. Whether an epoch is a gloas one is the caller's to decide, since
//! this service holds no fork schedule, and so is holding off the gloas fork
//! epoch's until the fork, before which a node cannot know them.
//!
//! A validator the chain reports slashed keeps its attester and proposer
//! duties in their maps, as fetched, and no accessor hands them out; its sync
//! committee and payload timeliness committee duties are handed out as usual,
//! since the chain still counts them (see [`DutiesService::set_slashed`] and
//! [`crate::slashed`]).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::constants::GENESIS_SLOT;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::preset::{epochs_per_sync_committee_period, slots_per_epoch};
use ethlambda_types::beacon::primitives::{Epoch, Root, Slot, ValidatorIndex};
use tracing::{info, warn};

use crate::beacon_node::BeaconNodeApi;
use crate::beacon_node::dto::{AttesterDutyDto, ProposerDutyDto, PtcDutyDto, SyncDutyDto};
use crate::error::Result;

/// The sync committee period `epoch` belongs to.
pub fn sync_committee_period(epoch: Epoch) -> u64 {
    epoch / epochs_per_sync_committee_period()
}

/// Which proposer duties endpoint an epoch's schedule is fetched from.
///
/// The two list the same proposers and differ in the `dependent_root` they
/// name: v1's is the last block before the epoch, v2's the last block before
/// the epoch before it, the block fulu's `proposer_lookahead` fixes the
/// epoch's proposers from. One epoch is always fetched from the same one, so
/// the roots held for it compare like with like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposerDutiesVersion {
    V1,
    V2,
}

impl ProposerDutiesVersion {
    /// v2 for an epoch whose proposers the epoch before it already fixed,
    /// that is one whose previous epoch is fulu or later; v1 otherwise. The
    /// fulu fork epoch itself is v1: its lookahead is computed at the fork,
    /// not during the epoch before it.
    pub fn for_epoch(config: &Config, epoch: Epoch) -> Self {
        match epoch.checked_sub(1) {
            Some(previous) if config.fork_at_epoch(previous) >= ForkName::Fulu => Self::V2,
            _ => Self::V1,
        }
    }

    /// Whether `epoch`'s proposers can be fetched during the epoch before it,
    /// because they are already fixed.
    pub fn fixed_ahead(config: &Config, epoch: Epoch) -> bool {
        Self::for_epoch(config, epoch) == Self::V2
    }
}

/// One epoch's schedule of some kind, and the block root it is derived from.
#[derive(Debug, Clone)]
struct EpochDuties<T> {
    dependent_root: Root,
    /// [`DutiesService::indices_grown`] when the schedule was fetched. A
    /// schedule narrowed to the indices held then lacks every validator added
    /// since, whatever its root says, so the proposer and payload committee
    /// schedules are replaced once this falls behind: from fulu an epoch's
    /// proposers are fetched an epoch ahead, before that epoch's refresh
    /// resolves a key imported meanwhile. The attester schedule is stamped
    /// too but still keyed on its root alone.
    indices_seen: u64,
    duties: Vec<T>,
}

/// The v2 root an epoch's attester and payload committee schedules were last
/// checked against (see [`DutiesService::follow_dependent_root`]).
#[derive(Debug, Clone, Copy)]
struct Followed {
    root: Root,
    /// Whether the checks are done with this root: the schedules hold it, or
    /// a second refetch for it answered off it too, as a node whose roots
    /// disagree for good does. Until then each check refetches, so a refetch
    /// answered from before the reorg (a fallback node that had not caught up,
    /// say) is made again rather than taken as the node's last word.
    settled: bool,
}

pub struct DutiesService<B> {
    beacon_node: Arc<B>,
    /// Validator indices this client signs for, resolved from public keys.
    indices: Vec<ValidatorIndex>,
    by_epoch: HashMap<Epoch, EpochDuties<AttesterDutyDto>>,
    /// Proposer duties, already narrowed to `indices`. See the module doc for
    /// why this is a second map rather than another field on the first.
    proposers: HashMap<Epoch, EpochDuties<ProposerDutyDto>>,
    /// Payload timeliness committee duties, already narrowed to `indices`.
    ptc: HashMap<Epoch, EpochDuties<PtcDutyDto>>,
    /// Sync committee duties by period, already narrowed to `indices`. Keyed
    /// by period, not epoch, because a committee serves a whole period; and
    /// with no `dependent_root` because the endpoint sends none: the committee
    /// is fixed a period ahead, so each refresh simply replaces what is held.
    sync: HashMap<u64, Vec<SyncDutyDto>>,
    /// Validators the chain reports slashed, whose attester and proposer
    /// duties no accessor hands out. See [`Self::set_slashed`].
    slashed: HashSet<ValidatorIndex>,
    /// How many times `indices` has gained a validator it did not hold
    /// before. Stamped on each schedule fetched (see
    /// [`EpochDuties::indices_seen`]). A set that only shrank does not count:
    /// a key that failed to resolve for a moment must not cost a good
    /// schedule, and the duties of one removed for good find no key to sign.
    indices_grown: u64,
    /// Whether the attester schedule changed since
    /// [`Self::take_attesters_moved`] last asked. [`Self::refresh`] reports
    /// each change to its caller too, but a caller cut off before it acts on
    /// one (the duty loop abandons a refresh at the end of its slot) would
    /// lose it, since the next attempt fetches the same root and reports no
    /// change. Kept here, the move waits for whoever sends the subscriptions.
    attesters_moved: bool,
    /// The v2 proposer duties root each epoch's attester and payload
    /// committee schedules were last checked against by
    /// [`Self::follow_dependent_root`], recorded only once the refetches that
    /// check called for answered.
    followed: HashMap<Epoch, Followed>,
    /// Whether the "no validator indices resolved" warning has already fired.
    /// Without this, an idle client would repeat it every epoch forever; with
    /// it, the operator still gets exactly one signal that duties are not
    /// being fetched, rather than silent, permanent success.
    warned_no_indices: bool,
}

impl<B: BeaconNodeApi> DutiesService<B> {
    pub fn new(beacon_node: Arc<B>, indices: Vec<ValidatorIndex>) -> Self {
        Self {
            beacon_node,
            indices,
            by_epoch: HashMap::new(),
            proposers: HashMap::new(),
            ptc: HashMap::new(),
            sync: HashMap::new(),
            slashed: HashSet::new(),
            indices_grown: 0,
            attesters_moved: false,
            followed: HashMap::new(),
            warned_no_indices: false,
        }
    }

    /// Hand out no attester or proposer duty of the validators in `slashed`
    /// from now on, the schedules already held included, and every duty of
    /// any other. Their sync committee and payload timeliness committee
    /// duties are still handed out: the chain counts a slashed member's
    /// signature in both (see [`crate::slashed`]).
    ///
    /// Applied when the duties are read rather than when they are fetched:
    /// a schedule is kept until its dependent root moves, so the one held when
    /// a slashing is first seen (this epoch's, fetched as last epoch's
    /// lookahead) would otherwise keep the key attesting for the rest of the
    /// epoch. Each epoch refresh replaces the set.
    ///
    /// A held validator that leaves the set (a node that wrongly reported it
    /// slashed, answered otherwise by the next) gets its attester duties back,
    /// and with them the subnet subscriptions and aggregator selection proofs
    /// [`Self::all`] left out while it was in. Those are owed again although
    /// no schedule moved, so this records a move for
    /// [`Self::take_attesters_moved`]. Call it after [`Self::set_indices`], so
    /// a key deleted from the client does not count.
    pub fn set_slashed(&mut self, slashed: HashSet<ValidatorIndex>) {
        let readmitted = self
            .slashed
            .iter()
            .any(|index| !slashed.contains(index) && self.indices.contains(index));
        if readmitted {
            self.attesters_moved = true;
        }
        self.slashed = slashed;
    }

    /// Whether `index`'s duties are handed out: not when the chain reports
    /// its validator slashed.
    fn serves(&self, index: ValidatorIndex) -> bool {
        !self.slashed.contains(&index)
    }

    pub fn set_indices(&mut self, indices: Vec<ValidatorIndex>) {
        // Re-arm the warning: if indices are cleared again later, that is a
        // fresh regression worth reporting, not a continuation of the first.
        if !indices.is_empty() {
            self.warned_no_indices = false;
        }
        let held: HashSet<&ValidatorIndex> = self.indices.iter().collect();
        if indices.iter().any(|index| !held.contains(index)) {
            self.indices_grown += 1;
        }
        self.indices = indices;
    }

    /// Whether the attester schedule changed since this was last called,
    /// which owes the node this client's subnet subscriptions again.
    pub fn take_attesters_moved(&mut self) -> bool {
        std::mem::take(&mut self.attesters_moved)
    }

    pub fn indices(&self) -> &[ValidatorIndex] {
        &self.indices
    }

    /// Fetch `epoch`'s duties, replacing anything held for it if the beacon
    /// node's `dependent_root` has changed.
    ///
    /// Returns whether the schedule changed, which is what tells the caller to
    /// re-send subnet subscriptions.
    pub async fn refresh(&mut self, epoch: Epoch) -> Result<bool> {
        if self.indices.is_empty() {
            // Otherwise indistinguishable from a correctly idle node: without
            // this, a client that never resolved any validators attests
            // nothing, forever, and reports success the whole time.
            if !self.warned_no_indices {
                warn!("No validator indices resolved; attester duties will not be fetched");
                self.warned_no_indices = true;
            }
            return Ok(false);
        }

        let fetched = self
            .beacon_node
            .attester_duties(epoch, &self.indices)
            .await?;

        let changed = match self.by_epoch.get(&epoch) {
            Some(held) if held.dependent_root == fetched.dependent_root => false,
            Some(held) => {
                warn!(
                    %epoch,
                    held = %hex::encode(&held.dependent_root.0[..4]),
                    fetched = %hex::encode(&fetched.dependent_root.0[..4]),
                    "Attester duties invalidated by a reorg; replacing the schedule"
                );
                true
            }
            None => true,
        };

        if changed {
            info!(%epoch, count = fetched.duties.len(), "Attester duties updated");
            self.attesters_moved = true;
            self.by_epoch.insert(
                epoch,
                EpochDuties {
                    dependent_root: fetched.dependent_root,
                    indices_seen: self.indices_grown,
                    duties: fetched.duties,
                },
            );
        }

        Ok(changed)
    }

    /// Fetch `epoch`'s proposer duties and keep only this client's, replacing
    /// anything held for that epoch if the `dependent_root` has changed.
    ///
    /// Returns nothing a caller acts on, unlike [`Self::refresh`]: a proposer
    /// schedule changing has no subscription consequence, because subnet
    /// subscriptions follow committees and a proposer has none.
    ///
    /// The filter is the reason the fetched list is not stored as it arrives.
    /// A mainnet epoch names thirty-two proposers and this client typically
    /// holds none of them, so keeping the whole list would mean storing
    /// thirty-two entries an epoch to answer "not us" with, and re-deciding
    /// that at every slot lookup instead of once here.
    ///
    /// `version` must be the same every time one epoch is fetched (see
    /// [`ProposerDutiesVersion::for_epoch`]): the two name different roots.
    pub async fn refresh_proposers(
        &mut self,
        epoch: Epoch,
        version: ProposerDutiesVersion,
    ) -> Result<()> {
        if self.indices.is_empty() {
            // Silent, unlike the attester path's one-shot warning: that
            // warning already fired for the same cause, and saying it twice
            // per epoch would make the log read as two separate faults.
            return Ok(());
        }
        self.fetch_proposers(epoch, version).await.map(|_| ())
    }

    /// [`Self::refresh_proposers`] with indices resolved, returning the
    /// `dependent_root` the node answered with.
    async fn fetch_proposers(
        &mut self,
        epoch: Epoch,
        version: ProposerDutiesVersion,
    ) -> Result<Root> {
        let fetched = match version {
            ProposerDutiesVersion::V1 => self.beacon_node.proposer_duties(epoch).await?,
            ProposerDutiesVersion::V2 => self.beacon_node.proposer_duties_v2(epoch).await?,
        };
        let root = fetched.dependent_root;

        match self.proposers.get(&epoch) {
            Some(held) if held.dependent_root != root => warn!(
                %epoch,
                held = %hex::encode(&held.dependent_root.0[..4]),
                fetched = %hex::encode(&root.0[..4]),
                "Proposer duties invalidated by a reorg; replacing the schedule"
            ),
            // The same root: kept, unless a validator was added since.
            Some(held) if held.indices_seen == self.indices_grown => return Ok(root),
            _ => {}
        }

        // The genesis slot is dropped along with other validators' entries.
        // The endpoint lists a proposer for every slot of the epoch, slot 0
        // included, but slot 0 holds the genesis block and nobody proposes
        // there: asking a beacon node for a block at it is refused outright
        // (Lighthouse answers `SlotOutOfBounds`). It only ever comes up once in
        // a chain's life, which is exactly why it is easy to miss.
        let mine: Vec<ProposerDutyDto> = fetched
            .duties
            .into_iter()
            .filter(|duty| duty.slot != GENESIS_SLOT)
            .filter(|duty| self.indices.contains(&duty.validator_index))
            .collect();

        // Logged at info only when there is something to do, and at debug
        // otherwise. A client with a handful of validators proposes a few times
        // a day, so an info line every epoch saying "none of ours" would bury
        // the one that says otherwise.
        if mine.is_empty() {
            tracing::debug!(%epoch, "No proposer duties this epoch");
        } else {
            for duty in &mine {
                if !self.serves(duty.validator_index) {
                    warn!(
                        slot = duty.slot,
                        validator = duty.validator_index,
                        %epoch,
                        "Not proposing: the validator is slashed, and the chain refuses a block \
                         from a slashed proposer"
                    );
                    continue;
                }
                info!(
                    slot = duty.slot,
                    validator = duty.validator_index,
                    %epoch,
                    "Proposer duty scheduled"
                );
            }
        }

        self.proposers.insert(
            epoch,
            EpochDuties {
                dependent_root: root,
                indices_seen: self.indices_grown,
                duties: mine,
            },
        );
        Ok(root)
    }

    /// Check `epoch`'s held schedules against the node's v2 proposer duties,
    /// refetching the attester schedule, and the payload committee one when
    /// `ptc` is set, if a reorg moved the block they depend on. Returns
    /// whether the attester schedule moved, which owes the node this client's
    /// subnet subscriptions again.
    ///
    /// Only for an epoch whose proposers are fixed a whole epoch ahead (see
    /// [`ProposerDutiesVersion`]), and `ptc` only for a gloas epoch other than
    /// the fork's own, whose committee has a dependent root of its own.
    ///
    /// # One cheap request standing in for three
    ///
    /// v2's `dependent_root` for an epoch is the last block before the epoch
    /// before it, which is the attester and payload committee schedules'
    /// root too (beacon-APIs `attester.yaml`, `ptc.yaml`, `proposer.v2.yaml`).
    /// A node answers it from the state's `proposer_lookahead`, where the
    /// other two walk the epoch's committees. So the duty loop asks for this
    /// one every slot and fetches the others only when it says they moved,
    /// as Lighthouse asks for a few validators' attester duties first.
    ///
    /// # When a root counts as moved
    ///
    /// When it differs from the one the schedule is held with *and* from the
    /// v2 root the checks of this epoch settled on (`followed`). The second
    /// condition is what stops a node whose roots disagree for any other
    /// reason from costing a refetch, a full shuffle on some nodes, every
    /// slot: that node's v2 root does not move, so it is refetched twice at
    /// most. A real reorg is still caught: it moves the v2 root away from the
    /// one settled on.
    ///
    /// A root is settled on only once the refetches it called for answered,
    /// so one that failed or was cut off at the slot's end is made again at
    /// the next check, not dropped because the proposer schedule (replaced
    /// first) already holds the new root. And only once the schedules hold
    /// it, or a second refetch for it also answered off it: a refetch
    /// answered from before the reorg, by a fallback node that had not caught
    /// up, is made again at the next check.
    ///
    /// A schedule not held at all is fetched, so a lookahead fetch that failed
    /// at the epoch refresh is made good within a slot rather than an epoch.
    pub async fn follow_dependent_root(&mut self, epoch: Epoch, ptc: bool) -> Result<bool> {
        if self.indices.is_empty() {
            return Ok(false);
        }
        let followed = self.followed.get(&epoch).copied();
        let settled = followed.filter(|followed| followed.settled);
        let previous = settled.map(|followed| followed.root);
        let root = self
            .fetch_proposers(epoch, ProposerDutiesVersion::V2)
            .await?;
        let stale = |held: Option<Root>| match held {
            None => true,
            Some(held) => held != root && previous != Some(root),
        };

        let mut moved = false;
        if stale(self.by_epoch.get(&epoch).map(|held| held.dependent_root)) {
            moved = self.refresh(epoch).await?;
        }
        if ptc && stale(self.ptc.get(&epoch).map(|held| held.dependent_root)) {
            self.refresh_ptc(epoch).await?;
        }

        let holds = |held: Option<Root>| held == Some(root);
        let agrees = holds(self.by_epoch.get(&epoch).map(|held| held.dependent_root))
            && (!ptc || holds(self.ptc.get(&epoch).map(|held| held.dependent_root)));
        let second = followed.is_some_and(|followed| followed.root == root);
        let settled = agrees || second;
        self.followed.insert(epoch, Followed { root, settled });
        Ok(moved)
    }

    /// Fetch `epoch`'s payload timeliness committee duties for this client's
    /// indices, replacing anything held for it if the `dependent_root` has
    /// changed.
    ///
    /// Only to be called for a gloas epoch: an earlier one answers with no
    /// duties, which is harmless but a request wasted every epoch. Nor for the
    /// gloas fork epoch before it has begun, which a node refuses.
    pub async fn refresh_ptc(&mut self, epoch: Epoch) -> Result<()> {
        if self.indices.is_empty() {
            return Ok(());
        }

        let fetched = self.beacon_node.ptc_duties(epoch, &self.indices).await?;

        match self.ptc.get(&epoch) {
            Some(held) if held.dependent_root != fetched.dependent_root => warn!(
                %epoch,
                "Payload timeliness committee duties invalidated by a reorg; replacing the schedule"
            ),
            // The same root: kept, unless a validator was added since.
            Some(held) if held.indices_seen == self.indices_grown => return Ok(()),
            _ => {}
        }

        // The node was asked about these indices only, but a node that answers
        // for more must not make this client vote for validators it does not
        // hold.
        let mine: Vec<PtcDutyDto> = fetched
            .duties
            .into_iter()
            .filter(|duty| self.indices.contains(&duty.validator_index))
            .collect();
        if mine.is_empty() {
            tracing::debug!(%epoch, "No payload timeliness committee duties this epoch");
        } else {
            info!(%epoch, count = mine.len(), "Payload timeliness committee duties updated");
        }
        self.ptc.insert(
            epoch,
            EpochDuties {
                dependent_root: fetched.dependent_root,
                indices_seen: self.indices_grown,
                duties: mine,
            },
        );
        Ok(())
    }

    /// Fetch the sync committee duties of `period` for this client's indices,
    /// replacing whatever is held for it.
    ///
    /// Asked at the period's first epoch, which the node answers from the
    /// committee that serves the whole period. Narrowed to this client's
    /// indices on arrival, for the reason [`Self::refresh_ptc`] is.
    pub async fn refresh_sync(&mut self, period: u64) -> Result<()> {
        if self.indices.is_empty() {
            return Ok(());
        }
        let epoch = period * epochs_per_sync_committee_period();
        let fetched = self.beacon_node.sync_duties(epoch, &self.indices).await?;
        let mine: Vec<SyncDutyDto> = fetched
            .into_iter()
            .filter(|duty| self.indices.contains(&duty.validator_index))
            .filter(|duty| !duty.validator_sync_committee_indices.is_empty())
            .collect();
        if mine.is_empty() {
            tracing::debug!(period, "No sync committee duties this period");
        } else {
            info!(period, count = mine.len(), "Sync committee duties updated");
        }
        self.sync.insert(period, mine);
        Ok(())
    }

    /// The sync committee duties held for `period`.
    pub fn sync_for_period(&self, period: u64) -> Vec<SyncDutyDto> {
        self.sync.get(&period).cloned().unwrap_or_default()
    }

    /// The sync committee duties to perform at wall slot `slot`.
    ///
    /// Those of the period containing `slot + 1`: a member assigned to slot
    /// `S` signs for `S - 1` and the message is included at `S`, so at the
    /// last slot of a period the next committee is the one that signs.
    pub fn sync_at_slot(&self, slot: Slot) -> Vec<SyncDutyDto> {
        let period = sync_committee_period((slot + 1) / slots_per_epoch());
        self.sync_for_period(period)
    }

    /// Forget sync committee duties of periods before `period`.
    pub fn prune_sync_before(&mut self, period: u64) {
        self.sync.retain(|held, _| *held >= period);
    }

    /// Whether an attester schedule is held for `epoch`, an empty one
    /// included: a fetch that found no duties still answered.
    pub fn holds_attesters(&self, epoch: Epoch) -> bool {
        self.by_epoch.contains_key(&epoch)
    }

    /// Whether a payload timeliness committee schedule is held for `epoch`,
    /// an empty one included: a fetch that found no duties still answered.
    pub fn holds_ptc(&self, epoch: Epoch) -> bool {
        self.ptc.contains_key(&epoch)
    }

    /// Whether a proposer schedule is held for `epoch`, an empty one
    /// included: "none of ours" is an answer too.
    pub fn holds_proposers(&self, epoch: Epoch) -> bool {
        self.proposers.contains_key(&epoch)
    }

    /// Forget payload timeliness committee duties for epochs before `epoch`.
    pub fn prune_ptc_before(&mut self, epoch: Epoch) {
        self.ptc.retain(|held, _| *held >= epoch);
    }

    /// This client's committee duties at `slot`. More than one is ordinary: a
    /// client holding several validators can have several seats in one slot's
    /// committee.
    pub fn ptc_at_slot(&self, slot: Slot, epoch: Epoch) -> Vec<PtcDutyDto> {
        self.ptc
            .get(&epoch)
            .map(|held| {
                held.duties
                    .iter()
                    .filter(|duty| duty.slot == slot)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// This client's proposer duty for `slot`, if it has one and its
    /// validator is not slashed (see [`Self::set_slashed`]).
    ///
    /// At most one, and not because of that filter: a slot has exactly one
    /// proposer, so two entries would mean the beacon node contradicted
    /// itself.
    pub fn proposer_at_slot(&self, slot: Slot, epoch: Epoch) -> Option<&ProposerDutyDto> {
        self.proposers
            .get(&epoch)?
            .duties
            .iter()
            .find(|duty| duty.slot == slot && self.serves(duty.validator_index))
    }

    /// The proposer duty for `slot` that [`Self::proposer_at_slot`] holds
    /// back because its validator is slashed, so the duty loop can say why
    /// the slot gets no block. The schedule is usually fetched an epoch ahead,
    /// before the slashing is seen, so the warning at fetch time misses it.
    pub fn slashed_proposer_at_slot(&self, slot: Slot, epoch: Epoch) -> Option<&ProposerDutyDto> {
        self.proposers
            .get(&epoch)?
            .duties
            .iter()
            .find(|duty| duty.slot == slot && !self.serves(duty.validator_index))
    }

    /// Refresh the current epoch and the one after it, and forget anything
    /// older. The lookahead is what lets subnet subscriptions be sent before
    /// the duty slot arrives, and, from fulu, what lets the duty loop propose
    /// at the next epoch's first slot without asking the node anything first.
    ///
    /// A failed lookahead fetch is logged and shrugged off rather than
    /// propagated: it is speculative, so losing it must never mask a genuine
    /// change reported for the current epoch, which is the one that actually
    /// has a duty due. Pruning with `>= current_epoch` never evicts an epoch
    /// above the current one, so a clock stepping backwards costs at most a
    /// re-fetch, never the loss of an already-held future schedule. Each
    /// `refresh` call fetches fully before mutating `by_epoch`, so a failure
    /// never leaves a partial schedule behind either: this module is
    /// recoverable by construction, not by explicit retry logic, and the next
    /// call simply tries again.
    pub async fn refresh_around(&mut self, current_epoch: Epoch, config: &Config) -> Result<bool> {
        // Proposers first: the one schedule a block can be waiting on. The
        // next epoch's only once they are fixed (see the module doc).
        //
        // Shrugged off like the attester lookahead rather than propagated:
        // returning an error here would throw away the attester fetches below
        // and leave the caller holding the previous epoch's attester duties.
        // Losing the proposer schedule costs at most a block, and the duty
        // loop asks for it again before each slot's proposal while none is
        // held; losing the attester one costs every validator's vote, every
        // slot, until the next refresh succeeds.
        let next_epoch = current_epoch + 1;
        let current = ProposerDutiesVersion::for_epoch(config, current_epoch);
        let fetched = self.refresh_proposers(current_epoch, current).await;
        let _ = fetched.inspect_err(|err| {
            warn!(
                epoch = current_epoch,
                %err,
                "Proposer duties fetch failed; trying again before each slot's proposal"
            );
        });
        if ProposerDutiesVersion::fixed_ahead(config, next_epoch) {
            let fetched = self
                .refresh_proposers(next_epoch, ProposerDutiesVersion::V2)
                .await;
            let _ = fetched.inspect_err(|err| {
                warn!(
                    epoch = next_epoch,
                    %err,
                    "Lookahead proposer duties fetch failed; they are asked for again at that \
                     epoch's first slot, ahead of its block"
                );
            });
        }

        let mut changed = self.refresh(current_epoch).await?;

        match self.refresh(next_epoch).await {
            Ok(lookahead_changed) => changed |= lookahead_changed,
            Err(err) => warn!(
                epoch = next_epoch,
                %err,
                "Lookahead duties fetch failed; keeping the current epoch's result"
            ),
        }

        self.by_epoch.retain(|epoch, _| *epoch >= current_epoch);
        self.proposers.retain(|epoch, _| *epoch >= current_epoch);
        self.followed.retain(|epoch, _| *epoch >= current_epoch);
        Ok(changed)
    }

    /// The duties to perform at `slot`.
    pub fn at_slot(&self, slot: Slot, epoch: Epoch) -> Vec<AttesterDutyDto> {
        self.by_epoch
            .get(&epoch)
            .map(|held| {
                held.duties
                    .iter()
                    .filter(|duty| duty.slot == slot && self.serves(duty.validator_index))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The duties of `epoch` at `slot` or after it, slashed validators' left
    /// out as in [`Self::at_slot`].
    pub fn from_slot(&self, slot: Slot, epoch: Epoch) -> Vec<AttesterDutyDto> {
        self.by_epoch
            .get(&epoch)
            .map(|held| {
                held.duties
                    .iter()
                    .filter(|duty| duty.slot >= slot && self.serves(duty.validator_index))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Every duty held, across the epochs currently loaded.
    pub fn all(&self) -> Vec<AttesterDutyDto> {
        self.by_epoch
            .values()
            .flat_map(|held| held.duties.iter())
            .filter(|duty| self.serves(duty.validator_index))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_node::mock::MockBeaconNode;

    fn duty(validator_index: ValidatorIndex, slot: Slot, committee_index: u64) -> AttesterDutyDto {
        AttesterDutyDto {
            pubkey: "0x00".to_string(),
            validator_index,
            committee_index,
            committee_length: 128,
            committees_at_slot: 64,
            validator_committee_index: 7,
            slot,
        }
    }

    fn root(byte: u8) -> Root {
        Root::repeat_byte(byte)
    }

    fn proposer(validator_index: ValidatorIndex, slot: Slot) -> ProposerDutyDto {
        ProposerDutyDto {
            pubkey: "0x00".to_string(),
            validator_index,
            slot,
        }
    }

    #[tokio::test]
    async fn duties_are_fetched_and_indexed_by_slot() {
        let node = MockBeaconNode::new().with_duties(3, root(1), vec![duty(1337, 96, 2)]);
        let mut service = DutiesService::new(Arc::new(node), vec![1337]);

        assert!(service.refresh(3).await.expect("refreshes"));
        let at_96 = service.at_slot(96, 3);
        assert_eq!(at_96.len(), 1);
        assert_eq!(at_96[0].validator_index, 1337);
        assert!(service.at_slot(97, 3).is_empty());
    }

    #[tokio::test]
    async fn an_unchanged_dependent_root_is_not_a_change() {
        let node = MockBeaconNode::new().with_duties(3, root(1), vec![duty(1337, 96, 2)]);
        let mut service = DutiesService::new(Arc::new(node), vec![1337]);

        assert!(
            service.refresh(3).await.expect("first"),
            "first fetch is a change"
        );
        assert!(
            !service.refresh(3).await.expect("second"),
            "the same dependent_root must not count as a change"
        );
    }

    #[tokio::test]
    async fn a_changed_dependent_root_replaces_the_schedule() {
        let node = Arc::new(MockBeaconNode::new().with_duties(3, root(1), vec![duty(1337, 96, 2)]));
        let mut service = DutiesService::new(node.clone(), vec![1337]);
        service.refresh(3).await.expect("first");

        // The beacon node now reports a different dependent root and a
        // different committee, as it would after a deep reorg. `set_duties`
        // replaces rather than appends, which is what makes the same epoch
        // answer differently on the second call.
        node.set_duties(3, root(2), vec![duty(1337, 96, 55)]);

        assert!(
            service.refresh(3).await.expect("second"),
            "must report a change"
        );
        assert_eq!(service.at_slot(96, 3)[0].committee_index, 55);
    }

    #[tokio::test]
    async fn with_no_validators_nothing_is_fetched() {
        let node = Arc::new(MockBeaconNode::new());
        let mut service = DutiesService::new(node.clone(), vec![]);
        assert!(!service.refresh(3).await.expect("no-op"));
        assert_eq!(node.duties_call_count(), 0);
    }

    #[tokio::test]
    async fn refreshing_around_an_epoch_forgets_the_previous_one() {
        let node = MockBeaconNode::new()
            .with_duties(3, root(1), vec![duty(1337, 96, 2)])
            .with_duties(4, root(2), vec![duty(1337, 130, 2)])
            .with_duties(5, root(3), vec![duty(1337, 165, 2)]);
        let mut service = DutiesService::new(Arc::new(node), vec![1337]);

        service
            .refresh_around(3, &Config::mainnet())
            .await
            .expect("epoch 3");
        assert!(!service.at_slot(96, 3).is_empty());

        service
            .refresh_around(4, &Config::mainnet())
            .await
            .expect("epoch 4");
        assert!(
            service.at_slot(96, 3).is_empty(),
            "epoch 3 must have been dropped"
        );
        assert!(!service.at_slot(130, 4).is_empty());
    }

    #[tokio::test]
    async fn refresh_around_prefetches_the_lookahead_epoch() {
        let node = MockBeaconNode::new()
            .with_duties(3, root(1), vec![duty(1337, 96, 2)])
            .with_duties(4, root(2), vec![duty(1337, 130, 2)]);
        let mut service = DutiesService::new(Arc::new(node), vec![1337]);

        service
            .refresh_around(3, &Config::mainnet())
            .await
            .expect("epoch 3");

        // Epoch 4 must already be held before it is ever the current epoch:
        // that is the entire point of the lookahead, to have the schedule in
        // hand before the duty slot arrives.
        assert!(
            !service.at_slot(130, 4).is_empty(),
            "the lookahead epoch must have been fetched alongside the current one"
        );
    }

    #[tokio::test]
    async fn at_slot_is_scoped_to_the_requested_epoch() {
        // Two epochs holding a duty at the same slot number, for different
        // validators: `at_slot` must not blur the epoch argument away and
        // search every held epoch for a match.
        let node = MockBeaconNode::new()
            .with_duties(3, root(1), vec![duty(1337, 96, 2)])
            .with_duties(4, root(2), vec![duty(7, 96, 9)]);
        let mut service = DutiesService::new(Arc::new(node), vec![1337, 7]);

        service.refresh(3).await.expect("epoch 3");
        service.refresh(4).await.expect("epoch 4");

        let at_epoch_3 = service.at_slot(96, 3);
        assert_eq!(at_epoch_3.len(), 1);
        assert_eq!(at_epoch_3[0].validator_index, 1337);

        let at_epoch_4 = service.at_slot(96, 4);
        assert_eq!(at_epoch_4.len(), 1);
        assert_eq!(at_epoch_4[0].validator_index, 7);
    }

    /// The endpoint answers for every proposer in the epoch, so the filter is
    /// the whole point: a mainnet epoch names thirty-two and this client holds
    /// none of them on a typical day.
    #[tokio::test]
    async fn proposer_duties_are_narrowed_to_this_clients_validators() {
        let node = MockBeaconNode::new().with_proposers(
            3,
            root(1),
            vec![proposer(1337, 96), proposer(42, 97), proposer(1337, 98)],
        );
        let mut service = DutiesService::new(Arc::new(node), vec![1337]);
        service
            .refresh_proposers(3, ProposerDutiesVersion::V1)
            .await
            .expect("refreshes");

        assert_eq!(
            service.proposer_at_slot(96, 3).map(|d| d.validator_index),
            Some(1337)
        );
        assert!(
            service.proposer_at_slot(97, 3).is_none(),
            "another validator's slot must not be kept"
        );
        assert_eq!(
            service.proposer_at_slot(98, 3).map(|d| d.validator_index),
            Some(1337)
        );
    }

    #[tokio::test]
    async fn a_slot_with_no_proposer_duty_of_ours_answers_none() {
        let node = MockBeaconNode::new().with_proposers(3, root(1), vec![proposer(1337, 96)]);
        let mut service = DutiesService::new(Arc::new(node), vec![1337]);
        service
            .refresh_proposers(3, ProposerDutiesVersion::V1)
            .await
            .expect("refreshes");

        assert!(service.proposer_at_slot(97, 3).is_none());
        // Right slot, wrong epoch: the lookup must be scoped, not blurred.
        assert!(service.proposer_at_slot(96, 4).is_none());
    }

    #[tokio::test]
    async fn an_unchanged_proposer_dependent_root_keeps_the_held_schedule() {
        let node =
            Arc::new(MockBeaconNode::new().with_proposers(3, root(1), vec![proposer(1337, 96)]));
        let mut service = DutiesService::new(node.clone(), vec![1337]);
        service
            .refresh_proposers(3, ProposerDutiesVersion::V1)
            .await
            .expect("first");

        // Same dependent root, different content. A node that answers this way
        // is contradicting itself, and the held schedule must win: the root is
        // what the schedule is keyed on.
        node.set_proposers(3, root(1), vec![proposer(1337, 99)]);
        service
            .refresh_proposers(3, ProposerDutiesVersion::V1)
            .await
            .expect("second");

        assert!(service.proposer_at_slot(96, 3).is_some());
        assert!(service.proposer_at_slot(99, 3).is_none());
    }

    #[tokio::test]
    async fn a_changed_proposer_dependent_root_replaces_the_schedule() {
        let node =
            Arc::new(MockBeaconNode::new().with_proposers(3, root(1), vec![proposer(1337, 96)]));
        let mut service = DutiesService::new(node.clone(), vec![1337]);
        service
            .refresh_proposers(3, ProposerDutiesVersion::V1)
            .await
            .expect("first");

        // A reorg past the last slot of epoch 2 re-shuffles this epoch's
        // proposers, which is a far shallower reorg than the one that would
        // move an attester.
        node.set_proposers(3, root(2), vec![proposer(1337, 99)]);
        service
            .refresh_proposers(3, ProposerDutiesVersion::V1)
            .await
            .expect("second");

        assert!(
            service.proposer_at_slot(96, 3).is_none(),
            "the old slot must be gone"
        );
        assert!(service.proposer_at_slot(99, 3).is_some());
    }

    /// The reason the proposer fetch is shrugged off inside `refresh_around`
    /// rather than propagated. By the time it runs, this epoch's attester
    /// duties are already in hand; returning an error would discard them and
    /// leave the caller attesting on the previous epoch's schedule. A lost
    /// block is cheaper than every validator's vote, every slot, until the next
    /// refresh succeeds.
    #[tokio::test]
    async fn a_failed_proposer_fetch_does_not_cost_the_attester_schedule() {
        let node = MockBeaconNode::new()
            .with_duties(3, root(1), vec![duty(1337, 96, 2)])
            .with_duties(4, root(2), vec![duty(1337, 130, 2)])
            .failing_call("proposer_duties", "node is unhappy");
        let mut service = DutiesService::new(Arc::new(node), vec![1337]);

        service
            .refresh_around(3, &Config::mainnet())
            .await
            .expect("a failed proposer fetch must not fail the refresh");
        assert!(
            !service.at_slot(96, 3).is_empty(),
            "the attester schedule must have survived"
        );
        assert!(service.proposer_at_slot(96, 3).is_none());
    }

    /// Before fulu, proposer duties for the next epoch are not decided until
    /// this one ends, so prefetching them would hold a guess that the epoch
    /// boundary overwrites. Attester duties *are* prefetched, which is why this
    /// has to be asserted rather than assumed. (Mainnet's config puts epoch 3
    /// long before fulu.)
    #[tokio::test]
    async fn before_fulu_proposer_duties_are_not_prefetched_for_the_lookahead_epoch() {
        let node = Arc::new(
            MockBeaconNode::new()
                .with_duties(3, root(1), vec![duty(1337, 96, 2)])
                .with_duties(4, root(2), vec![duty(1337, 130, 2)])
                .with_proposers(3, root(1), vec![proposer(1337, 96)])
                .with_proposers(4, root(2), vec![proposer(1337, 130)]),
        );
        let mut service = DutiesService::new(node.clone(), vec![1337]);
        service
            .refresh_around(3, &Config::mainnet())
            .await
            .expect("epoch 3");

        assert_eq!(
            node.proposer_duties_call_count(),
            1,
            "exactly one proposer fetch, for the current epoch"
        );
        assert!(service.proposer_at_slot(96, 3).is_some());
        assert!(
            service.proposer_at_slot(130, 4).is_none(),
            "the lookahead epoch's proposers must not have been fetched"
        );
    }

    /// A config with fulu from genesis, so every epoch after the first has its
    /// proposers fixed an epoch ahead.
    fn fulu_config() -> Config {
        [
            ForkName::Altair,
            ForkName::Bellatrix,
            ForkName::Capella,
            ForkName::Deneb,
            ForkName::Electra,
            ForkName::Fulu,
        ]
        .into_iter()
        .fold(Config::mainnet(), |config, fork| {
            config.with_fork_epoch(fork, 0)
        })
    }

    #[test]
    fn proposer_duties_are_v2_once_the_epoch_before_is_fulu() {
        let mut config = fulu_config();
        config.fulu_fork_epoch = 10;
        let version = |epoch| ProposerDutiesVersion::for_epoch(&config, epoch);
        assert_eq!(version(0), ProposerDutiesVersion::V1, "no epoch before");
        assert_eq!(version(10), ProposerDutiesVersion::V1, "the fork epoch");
        assert_eq!(version(11), ProposerDutiesVersion::V2);
        assert!(!ProposerDutiesVersion::fixed_ahead(&config, 10));
        assert!(ProposerDutiesVersion::fixed_ahead(&config, 11));
    }

    /// From fulu the next epoch's proposers are fixed, so they are fetched
    /// with the lookahead, from v2, and the duty loop holds them before that
    /// epoch's first slot.
    #[tokio::test]
    async fn from_fulu_the_next_epochs_proposers_are_prefetched_from_v2() {
        let node = Arc::new(
            MockBeaconNode::new()
                .with_duties(3, root(1), vec![duty(1337, 96, 2)])
                .with_duties(4, root(2), vec![duty(1337, 130, 2)])
                .with_proposers_v2(3, root(1), vec![proposer(1337, 97)])
                .with_proposers_v2(4, root(2), vec![proposer(1337, 128)]),
        );
        let mut service = DutiesService::new(node.clone(), vec![1337]);
        service
            .refresh_around(3, &fulu_config())
            .await
            .expect("epoch 3");

        assert_eq!(node.proposer_duties_call_count(), 0, "no v1 request");
        assert_eq!(node.proposer_duties_v2_call_count(), 2);
        assert!(service.proposer_at_slot(97, 3).is_some());
        assert!(service.holds_proposers(4));
        assert!(
            service.proposer_at_slot(128, 4).is_some(),
            "the next epoch's first slot is known before it starts"
        );
    }

    /// A failed lookahead proposer fetch costs nothing else: the duty loop
    /// asks again at the epoch's first slot.
    #[tokio::test]
    async fn a_failed_proposer_prefetch_does_not_fail_the_refresh() {
        let node = Arc::new(
            MockBeaconNode::new()
                .with_duties(3, root(1), vec![duty(1337, 96, 2)])
                .with_duties(4, root(2), vec![duty(1337, 130, 2)])
                .with_proposers_v2(3, root(1), vec![proposer(1337, 97)]),
        );
        let mut service = DutiesService::new(node, vec![1337]);
        service
            .refresh_around(3, &fulu_config())
            .await
            .expect("refreshes");

        assert!(service.holds_attesters(4));
        assert!(!service.holds_proposers(4));
    }

    // ---- following dependent roots between refreshes (#827) -------------

    /// A service holding epoch 3 and its lookahead, refreshed on a fulu chain
    /// where every schedule of an epoch shares one root: `root(3)` for epoch 3
    /// and `root(4)` for epoch 4.
    async fn following(node: &Arc<MockBeaconNode>) -> DutiesService<MockBeaconNode> {
        for (epoch, slot) in [(3, 96), (4, 130)] {
            let epoch_root = root(epoch as u8);
            node.set_duties(epoch, epoch_root, vec![duty(1337, slot, 2)]);
            node.set_proposers_v2(epoch, epoch_root, vec![proposer(1337, slot + 1)]);
            node.set_ptc_duties(epoch, epoch_root, vec![ptc_duty(1337, slot + 2)]);
        }
        let mut service = DutiesService::new(node.clone(), vec![1337]);
        service
            .refresh_around(3, &fulu_config())
            .await
            .expect("refreshes");
        service.refresh_ptc(3).await.expect("ptc 3");
        service.refresh_ptc(4).await.expect("ptc 4");
        service
    }

    /// Roots that have not moved cost the one v2 request and nothing else.
    #[tokio::test]
    async fn unmoved_roots_cost_the_proposer_request_alone() {
        let node = Arc::new(MockBeaconNode::new());
        let mut service = following(&node).await;
        let (attesters, ptc, v2) = (
            node.duties_call_count(),
            node.ptc_call_count(),
            node.proposer_duties_v2_call_count(),
        );

        for epoch in [3, 4] {
            let moved = service
                .follow_dependent_root(epoch, true)
                .await
                .expect("checks");
            assert!(!moved);
        }

        assert_eq!(node.duties_call_count(), attesters);
        assert_eq!(node.ptc_call_count(), ptc);
        assert_eq!(node.proposer_duties_v2_call_count(), v2 + 2);
    }

    /// The lookahead's root moving between two slots of an epoch, as a
    /// one-slot reorg at the boundary moves it: the next check replaces the
    /// attester, payload committee and proposer schedules, and reports the
    /// attester move so the subscriptions are sent again.
    #[tokio::test]
    async fn a_moved_root_replaces_the_schedules_within_the_epoch() {
        let node = Arc::new(MockBeaconNode::new());
        let mut service = following(&node).await;

        node.set_duties(4, root(9), vec![duty(1337, 140, 5)]);
        node.set_proposers_v2(4, root(9), vec![proposer(1337, 141)]);
        node.set_ptc_duties(4, root(9), vec![ptc_duty(1337, 142)]);
        let moved = service
            .follow_dependent_root(4, true)
            .await
            .expect("checks");

        assert!(moved, "the attester schedule moved");
        assert!(service.at_slot(130, 4).is_empty(), "the old duty is gone");
        assert_eq!(service.at_slot(140, 4)[0].committee_index, 5);
        assert!(service.proposer_at_slot(131, 4).is_none());
        assert!(service.proposer_at_slot(141, 4).is_some());
        assert!(service.ptc_at_slot(132, 4).is_empty());
        assert_eq!(service.ptc_at_slot(142, 4).len(), 1);
    }

    /// The same for this epoch's schedules, which a reorg deeper than an epoch
    /// moves: the slot after the check attests from the new schedule.
    #[tokio::test]
    async fn a_deep_reorg_replaces_this_epochs_attester_schedule() {
        let node = Arc::new(MockBeaconNode::new());
        let mut service = following(&node).await;

        node.set_duties(3, root(8), vec![duty(1337, 100, 7)]);
        node.set_proposers_v2(3, root(8), Vec::new());
        assert!(
            service
                .follow_dependent_root(3, false)
                .await
                .expect("checks")
        );

        assert!(service.at_slot(96, 3).is_empty());
        assert_eq!(service.at_slot(100, 3)[0].committee_index, 7);
        assert!(
            service.proposer_at_slot(97, 3).is_none(),
            "this epoch's proposers follow the same root"
        );
    }

    /// A refetch a moved root called for that failed is made again by the
    /// next check. The proposer schedule already holds the new root by then,
    /// so only the root recorded after a check got through can tell the two
    /// apart.
    #[tokio::test]
    async fn a_refetch_that_failed_is_made_again_by_the_next_check() {
        let node = Arc::new(MockBeaconNode::new());
        let mut service = following(&node).await;
        node.set_duties(4, root(9), vec![duty(1337, 140, 5)]);
        node.set_proposers_v2(4, root(9), vec![proposer(1337, 141)]);

        node.start_failing("attester_duties", "down");
        assert!(service.follow_dependent_root(4, false).await.is_err());
        assert_eq!(service.at_slot(130, 4).len(), 1, "still the old schedule");

        node.stop_failing("attester_duties");
        let moved = service
            .follow_dependent_root(4, false)
            .await
            .expect("checks");
        assert!(moved);
        assert_eq!(service.at_slot(140, 4)[0].committee_index, 5);
    }

    /// A node whose attester root never matches its v2 root, for whatever
    /// reason, costs two attester refetches at most, not one every slot: on
    /// an ethlambda node each is a full shuffle.
    #[tokio::test]
    async fn roots_that_disagree_without_moving_are_not_refetched_every_slot() {
        let node = Arc::new(MockBeaconNode::new());
        let mut service = following(&node).await;
        node.set_proposers_v2(4, root(7), vec![proposer(1337, 131)]);
        let before = node.duties_call_count();

        for _ in 0..2 {
            service
                .follow_dependent_root(4, false)
                .await
                .expect("checks");
        }
        let after_second = node.duties_call_count();
        assert_eq!(after_second, before + 2, "the second settles it");
        for _ in 0..3 {
            service
                .follow_dependent_root(4, false)
                .await
                .expect("checks");
        }

        assert_eq!(node.duties_call_count(), after_second);
        assert_eq!(service.at_slot(130, 4).len(), 1, "the schedule is kept");
    }

    /// A refetch answered from before the reorg, as a fallback node that has
    /// not caught up answers it, is made again at the next check rather than
    /// taken as the node's last word.
    #[tokio::test]
    async fn a_refetch_answered_from_before_the_reorg_is_made_again() {
        let node = Arc::new(MockBeaconNode::new());
        let mut service = following(&node).await;
        node.set_proposers_v2(4, root(9), vec![proposer(1337, 141)]);

        let moved = service
            .follow_dependent_root(4, false)
            .await
            .expect("checks");
        assert!(!moved, "the attester answer is still the old one");

        node.set_duties(4, root(9), vec![duty(1337, 140, 5)]);
        let moved = service
            .follow_dependent_root(4, false)
            .await
            .expect("checks");
        assert!(moved);
        assert_eq!(service.at_slot(140, 4)[0].committee_index, 5);
    }

    /// A lookahead the epoch refresh failed to fetch is fetched by the next
    /// check, rather than by the next epoch's first slot ahead of its block.
    #[tokio::test]
    async fn a_lookahead_the_refresh_missed_is_fetched_by_the_next_check() {
        // No epoch 4 duties yet: the mock refuses the lookahead.
        let node = Arc::new(
            MockBeaconNode::new()
                .with_duties(3, root(3), vec![duty(1337, 96, 2)])
                .with_proposers_v2(3, root(3), Vec::new())
                .with_proposers_v2(4, root(4), Vec::new()),
        );
        let mut service = DutiesService::new(node.clone(), vec![1337]);
        service
            .refresh_around(3, &fulu_config())
            .await
            .expect("this epoch");
        assert!(!service.holds_attesters(4), "the lookahead failed");

        node.set_duties(4, root(4), vec![duty(1337, 130, 2)]);
        let moved = service
            .follow_dependent_root(4, false)
            .await
            .expect("checks");

        assert!(moved, "a first schedule is a move for the subscriptions");
        assert_eq!(service.at_slot(130, 4).len(), 1);
    }

    #[tokio::test]
    async fn with_no_validators_no_root_is_checked() {
        let node = Arc::new(MockBeaconNode::new());
        let mut service = DutiesService::new(node.clone(), Vec::new());
        assert!(!service.follow_dependent_root(4, true).await.expect("idles"));
        assert_eq!(node.proposer_duties_v2_call_count(), 0);
    }

    #[tokio::test]
    async fn refreshing_around_an_epoch_forgets_the_previous_ones_proposers() {
        let node = MockBeaconNode::new()
            .with_duties(3, root(1), vec![duty(1337, 96, 2)])
            .with_duties(4, root(2), vec![duty(1337, 130, 2)])
            .with_duties(5, root(3), vec![duty(1337, 165, 2)])
            .with_proposers(3, root(1), vec![proposer(1337, 96)])
            .with_proposers(4, root(2), vec![proposer(1337, 130)]);
        let mut service = DutiesService::new(Arc::new(node), vec![1337]);

        service
            .refresh_around(3, &Config::mainnet())
            .await
            .expect("epoch 3");
        assert!(service.proposer_at_slot(96, 3).is_some());

        service
            .refresh_around(4, &Config::mainnet())
            .await
            .expect("epoch 4");
        assert!(
            service.proposer_at_slot(96, 3).is_none(),
            "epoch 3's proposers must have been pruned"
        );
        assert!(service.proposer_at_slot(130, 4).is_some());
    }

    /// Found on a devnet where this client held every validator: the duties
    /// list named one of them for slot 0, the client asked for a block there,
    /// and the beacon node refused it. Slot 0 is the genesis block; there is
    /// no proposal to make.
    #[tokio::test]
    async fn a_duty_at_the_genesis_slot_is_not_scheduled() {
        let node = MockBeaconNode::new().with_proposers(
            0,
            root(1),
            vec![proposer(1337, 0), proposer(1337, 3)],
        );
        let mut service = DutiesService::new(Arc::new(node), vec![1337]);
        service
            .refresh_proposers(0, ProposerDutiesVersion::V1)
            .await
            .expect("refreshes");

        assert!(
            service.proposer_at_slot(0, 0).is_none(),
            "nobody proposes at the genesis slot"
        );
        assert!(
            service.proposer_at_slot(3, 0).is_some(),
            "the rest of epoch 0 is still scheduled"
        );
    }

    #[tokio::test]
    async fn with_no_validators_no_proposer_duties_are_fetched() {
        let node = Arc::new(MockBeaconNode::new());
        let mut service = DutiesService::new(node.clone(), vec![]);
        service
            .refresh_proposers(3, ProposerDutiesVersion::V1)
            .await
            .expect("no-op");
        assert_eq!(node.proposer_duties_call_count(), 0);
    }

    /// From fulu an epoch's proposers are fetched an epoch ahead, so a key
    /// imported meanwhile is resolved after its epoch's schedule was narrowed
    /// without it. The same root must not keep that schedule: the validator's
    /// slots would go unproposed for the whole epoch. Its payload committee
    /// seats likewise.
    #[tokio::test]
    async fn a_schedule_narrowed_before_an_index_was_added_is_replaced() {
        let node = Arc::new(
            MockBeaconNode::new()
                .with_proposers_v2(4, root(2), vec![proposer(1337, 128), proposer(42, 129)])
                .with_ptc_duties(4, root(2), vec![ptc_duty(1337, 130), ptc_duty(42, 131)]),
        );
        let mut service = DutiesService::new(node, vec![1337]);
        let v2 = ProposerDutiesVersion::V2;
        service.refresh_proposers(4, v2).await.expect("first");
        service.refresh_ptc(4).await.expect("first");
        assert!(service.proposer_at_slot(129, 4).is_none());

        service.set_indices(vec![1337, 42]);
        service.refresh_proposers(4, v2).await.expect("second");
        service.refresh_ptc(4).await.expect("second");

        assert_eq!(
            service.proposer_at_slot(129, 4).map(|d| d.validator_index),
            Some(42)
        );
        assert!(service.proposer_at_slot(128, 4).is_some());
        assert_eq!(service.ptc_at_slot(131, 4).len(), 1);
    }

    /// A set that only shrank, as one with a key that failed to resolve for a
    /// moment does, keeps the schedule held for the same root.
    #[tokio::test]
    async fn an_index_set_that_only_shrank_keeps_the_held_schedule() {
        let node =
            Arc::new(MockBeaconNode::new().with_proposers(3, root(1), vec![proposer(1337, 96)]));
        let mut service = DutiesService::new(node.clone(), vec![1337, 42]);
        let v1 = ProposerDutiesVersion::V1;
        service.refresh_proposers(3, v1).await.expect("first");

        service.set_indices(vec![1337]);
        node.set_proposers(3, root(1), vec![proposer(1337, 99)]);
        service.refresh_proposers(3, v1).await.expect("second");

        assert!(service.proposer_at_slot(96, 3).is_some());
        assert!(service.proposer_at_slot(99, 3).is_none());
    }

    fn ptc_duty(validator_index: ValidatorIndex, slot: Slot) -> PtcDutyDto {
        PtcDutyDto {
            pubkey: "0x00".to_string(),
            validator_index,
            slot,
        }
    }

    #[tokio::test]
    async fn payload_committee_duties_are_fetched_filtered_and_indexed_by_slot() {
        let node = Arc::new(MockBeaconNode::new().with_ptc_duties(
            12,
            Root::repeat_byte(1),
            // Validator 99 is not ours and must be dropped on arrival.
            vec![ptc_duty(7, 390), ptc_duty(99, 390), ptc_duty(7, 395)],
        ));
        let mut service = DutiesService::new(node.clone(), vec![7]);

        service.refresh_ptc(12).await.expect("refreshes");

        let at_390 = service.ptc_at_slot(390, 12);
        assert_eq!(at_390.len(), 1);
        assert_eq!(at_390[0].validator_index, 7);
        assert_eq!(service.ptc_at_slot(395, 12).len(), 1);
        assert!(service.ptc_at_slot(391, 12).is_empty());
        assert!(
            service.ptc_at_slot(390, 13).is_empty(),
            "scoped to the epoch"
        );
    }

    /// A reorg past the dependent root replaces the schedule; an unchanged
    /// root keeps it, which is what stops a refresh every epoch from churning.
    #[tokio::test]
    async fn a_changed_ptc_dependent_root_replaces_the_schedule() {
        let node = Arc::new(MockBeaconNode::new().with_ptc_duties(
            12,
            Root::repeat_byte(1),
            vec![ptc_duty(7, 390)],
        ));
        let mut service = DutiesService::new(node.clone(), vec![7]);
        service.refresh_ptc(12).await.expect("first");

        node.set_ptc_duties(12, Root::repeat_byte(1), vec![ptc_duty(7, 391)]);
        service.refresh_ptc(12).await.expect("same root");
        assert_eq!(
            service.ptc_at_slot(390, 12).len(),
            1,
            "unchanged root keeps it"
        );

        node.set_ptc_duties(12, Root::repeat_byte(2), vec![ptc_duty(7, 391)]);
        service.refresh_ptc(12).await.expect("new root");
        assert!(service.ptc_at_slot(390, 12).is_empty());
        assert_eq!(service.ptc_at_slot(391, 12).len(), 1);
    }

    #[tokio::test]
    async fn pruning_forgets_earlier_payload_committee_epochs() {
        let node = Arc::new(
            MockBeaconNode::new()
                .with_ptc_duties(12, Root::repeat_byte(1), vec![ptc_duty(7, 390)])
                .with_ptc_duties(13, Root::repeat_byte(1), vec![ptc_duty(7, 420)]),
        );
        let mut service = DutiesService::new(node, vec![7]);
        service.refresh_ptc(12).await.expect("12");
        service.refresh_ptc(13).await.expect("13");

        service.prune_ptc_before(13);
        assert!(service.ptc_at_slot(390, 12).is_empty());
        assert_eq!(service.ptc_at_slot(420, 13).len(), 1);
    }

    fn sync_duty(validator_index: ValidatorIndex, seats: Vec<u64>) -> SyncDutyDto {
        SyncDutyDto {
            pubkey: "0x00".to_string(),
            validator_index,
            validator_sync_committee_indices: seats,
        }
    }

    #[tokio::test]
    async fn sync_duties_are_fetched_at_the_periods_first_epoch_and_narrowed() {
        let node = Arc::new(MockBeaconNode::new().with_sync_duties(
            epochs_per_sync_committee_period(),
            vec![sync_duty(7, vec![3]), sync_duty(99, vec![4])],
        ));
        let mut service = DutiesService::new(node, vec![7]);

        service.refresh_sync(1).await.expect("refreshes");

        let held = service.sync_for_period(1);
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].validator_index, 7);
        assert!(service.sync_for_period(0).is_empty());
    }

    /// At a period's last slot the member signs for the slot after, which the
    /// next committee owns.
    #[tokio::test]
    async fn the_last_slot_of_a_period_uses_the_next_periods_duties() {
        let node = Arc::new(
            MockBeaconNode::new()
                .with_sync_duties(0, vec![sync_duty(7, vec![1])])
                .with_sync_duties(
                    epochs_per_sync_committee_period(),
                    vec![sync_duty(7, vec![200])],
                ),
        );
        let mut service = DutiesService::new(node, vec![7]);
        service.refresh_sync(0).await.expect("0");
        service.refresh_sync(1).await.expect("1");

        let period_slots = epochs_per_sync_committee_period() * slots_per_epoch();
        assert_eq!(
            service.sync_at_slot(period_slots - 2)[0].validator_sync_committee_indices,
            vec![1]
        );
        assert_eq!(
            service.sync_at_slot(period_slots - 1)[0].validator_sync_committee_indices,
            vec![200]
        );
    }

    #[tokio::test]
    async fn pruning_forgets_earlier_sync_periods() {
        let node = Arc::new(
            MockBeaconNode::new()
                .with_sync_duties(0, vec![sync_duty(7, vec![1])])
                .with_sync_duties(
                    epochs_per_sync_committee_period(),
                    vec![sync_duty(7, vec![2])],
                ),
        );
        let mut service = DutiesService::new(node, vec![7]);
        service.refresh_sync(0).await.expect("0");
        service.refresh_sync(1).await.expect("1");
        service.prune_sync_before(1);
        assert!(service.sync_for_period(0).is_empty());
        assert_eq!(service.sync_for_period(1).len(), 1);
    }

    #[tokio::test]
    async fn no_indices_means_no_sync_duties_request() {
        let node = Arc::new(MockBeaconNode::new());
        let mut service = DutiesService::new(node.clone(), Vec::new());
        service.refresh_sync(0).await.expect("idles");
        assert!(node.sync_duty_requests().is_empty());
    }

    #[tokio::test]
    async fn no_indices_means_no_payload_committee_request() {
        let node = Arc::new(MockBeaconNode::new());
        let mut service = DutiesService::new(node.clone(), Vec::new());
        service.refresh_ptc(12).await.expect("idles");
        assert_eq!(node.ptc_call_count(), 0);
    }

    /// The validator index of each duty, in order.
    fn indices<T>(duties: &[T], index: impl Fn(&T) -> ValidatorIndex) -> Vec<ValidatorIndex> {
        duties.iter().map(index).collect()
    }

    /// A validator found slashed after its schedules were fetched gets none of
    /// the attester and proposer duties already held, the lookahead epoch's
    /// included, and nothing is fetched again for it: a refresh whose
    /// dependent roots have not moved keeps what it holds, so this is the case
    /// a filter on arrival misses. Its sync committee and payload timeliness
    /// duties go on, every other validator keeps all of its duties, and the
    /// slashed one gets its back once the set no longer names it.
    #[tokio::test]
    async fn a_slashed_validators_held_attester_and_proposer_duties_are_not_handed_out() {
        let node = Arc::new(
            MockBeaconNode::new()
                .with_duties(3, root(1), vec![duty(11, 96, 2), duty(22, 96, 3)])
                .with_duties(4, root(2), vec![duty(11, 130, 2), duty(22, 131, 3)])
                .with_proposers(3, root(1), vec![proposer(11, 97), proposer(22, 98)])
                .with_ptc_duties(3, root(1), vec![ptc_duty(11, 99), ptc_duty(22, 99)])
                .with_sync_duties(0, vec![sync_duty(11, vec![1]), sync_duty(22, vec![2])]),
        );
        let mut service = DutiesService::new(node.clone(), vec![11, 22]);
        service
            .refresh_around(3, &Config::mainnet())
            .await
            .expect("refreshes");
        service.refresh_ptc(3).await.expect("refreshes");
        service.refresh_sync(0).await.expect("refreshes");
        let fetched = node.duties_call_count();

        service.set_slashed(HashSet::from([22]));

        let attester = |duty: &AttesterDutyDto| duty.validator_index;
        assert_eq!(indices(&service.at_slot(96, 3), attester), [11]);
        assert!(service.at_slot(131, 4).is_empty(), "the lookahead's too");
        assert_eq!(indices(&service.all(), attester), [11, 11]);
        assert_eq!(
            service
                .proposer_at_slot(97, 3)
                .map(|duty| duty.validator_index),
            Some(11)
        );
        assert!(service.proposer_at_slot(98, 3).is_none());
        let ptc = |duty: &PtcDutyDto| duty.validator_index;
        assert_eq!(indices(&service.ptc_at_slot(99, 3), ptc), [11, 22]);
        let sync = |duty: &SyncDutyDto| duty.validator_index;
        assert_eq!(indices(&service.sync_for_period(0), sync), [11, 22]);
        assert_eq!(
            node.duties_call_count(),
            fetched,
            "nothing is fetched again"
        );

        service.set_slashed(HashSet::new());
        assert_eq!(indices(&service.at_slot(96, 3), attester), [11, 22]);
        assert!(service.proposer_at_slot(98, 3).is_some());
    }

    /// The proposal held back from a slashed validator is still found, so the
    /// duty loop can say why its slot gets no block; an unslashed proposer's
    /// is not.
    #[tokio::test]
    async fn a_slashed_validators_held_proposal_is_reported() {
        let node = Arc::new(
            MockBeaconNode::new()
                .with_duties(3, root(1), Vec::new())
                .with_duties(4, root(2), Vec::new())
                .with_proposers(3, root(1), vec![proposer(11, 97), proposer(22, 98)]),
        );
        let mut service = DutiesService::new(node, vec![11, 22]);
        service
            .refresh_around(3, &Config::mainnet())
            .await
            .expect("refreshes");
        assert!(service.slashed_proposer_at_slot(98, 3).is_none());

        service.set_slashed(HashSet::from([22]));
        assert_eq!(
            service
                .slashed_proposer_at_slot(98, 3)
                .map(|duty| duty.validator_index),
            Some(22)
        );
        assert!(service.slashed_proposer_at_slot(97, 3).is_none());
    }

    /// A held validator that leaves the slashed set owes the node its subnet
    /// subscriptions again, which [`DutiesService::all`] left it out of,
    /// although no schedule moved. One that joins the set, or leaves it
    /// because its key was deleted, owes nothing.
    #[tokio::test]
    async fn a_validator_leaving_the_slashed_set_owes_its_subscriptions() {
        let node = Arc::new(
            MockBeaconNode::new()
                .with_duties(3, root(1), vec![duty(11, 96, 2), duty(22, 96, 3)])
                .with_duties(4, root(2), Vec::new()),
        );
        let mut service = DutiesService::new(node, vec![11, 22, 33]);
        service
            .refresh_around(3, &Config::mainnet())
            .await
            .expect("refreshes");
        service.take_attesters_moved();

        service.set_slashed(HashSet::from([22, 33]));
        assert!(!service.take_attesters_moved(), "joining owes nothing");

        service.set_indices(vec![11, 22]);
        service.set_slashed(HashSet::from([22]));
        assert!(
            !service.take_attesters_moved(),
            "a deleted key leaving owes nothing"
        );

        service.set_slashed(HashSet::new());
        assert!(service.take_attesters_moved());
        let attester = |duty: &AttesterDutyDto| duty.validator_index;
        assert_eq!(indices(&service.all(), attester), [11, 22]);
    }
}
