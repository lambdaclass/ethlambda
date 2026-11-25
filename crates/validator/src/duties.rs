//! What this client's validators are scheduled to do, and when.
//!
//! Holds one epoch's attester duties at a time, plus a lookahead epoch, and
//! discards them when the beacon node reports a different `dependent_root`: a
//! reorg deeper than `MIN_SEED_LOOKAHEAD` changes the committee shuffling, and
//! acting on the old schedule would attest from the wrong committee.
//!
//! Proposer duties are held alongside them, in a separate map and on
//! deliberately different terms. Three differences, all of them consequences of
//! the proposer shuffling being fixed a whole epoch later than the committee
//! shuffling:
//!
//! - **No lookahead.** Asking for the next epoch's proposers returns an answer
//!   that the end of this epoch will rewrite, so holding it would be holding a
//!   guess. Attester duties for the next epoch are already settled, which is
//!   why those *are* prefetched.
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

use ethlambda_types::beacon::constants::GENESIS_SLOT;
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

/// One epoch's schedule of some kind, and the block root it is derived from.
#[derive(Debug, Clone)]
struct EpochDuties<T> {
    dependent_root: Root,
    duties: Vec<T>,
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
    pub fn set_slashed(&mut self, slashed: HashSet<ValidatorIndex>) {
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
        self.indices = indices;
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
            self.by_epoch.insert(
                epoch,
                EpochDuties {
                    dependent_root: fetched.dependent_root,
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
    pub async fn refresh_proposers(&mut self, epoch: Epoch) -> Result<()> {
        if self.indices.is_empty() {
            // Silent, unlike the attester path's one-shot warning: that
            // warning already fired for the same cause, and saying it twice
            // per epoch would make the log read as two separate faults.
            return Ok(());
        }

        let fetched = self.beacon_node.proposer_duties(epoch).await?;

        let unchanged = self
            .proposers
            .get(&epoch)
            .is_some_and(|held| held.dependent_root == fetched.dependent_root);
        if unchanged {
            return Ok(());
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
                dependent_root: fetched.dependent_root,
                duties: mine,
            },
        );
        Ok(())
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

        let held = self.ptc.get(&epoch);
        if held.is_some_and(|held| held.dependent_root == fetched.dependent_root) {
            return Ok(());
        }
        if held.is_some() {
            warn!(
                %epoch,
                "Payload timeliness committee duties invalidated by a reorg; replacing the schedule"
            );
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

    /// Whether a payload timeliness committee schedule is held for `epoch`,
    /// an empty one included: a fetch that found no duties still answered.
    pub fn holds_ptc(&self, epoch: Epoch) -> bool {
        self.ptc.contains_key(&epoch)
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

    /// Refresh the current epoch and the one after it, and forget anything
    /// older. The lookahead is what lets subnet subscriptions be sent before
    /// the duty slot arrives.
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
    pub async fn refresh_around(&mut self, current_epoch: Epoch) -> Result<bool> {
        let mut changed = self.refresh(current_epoch).await?;

        match self.refresh(current_epoch + 1).await {
            Ok(lookahead_changed) => changed |= lookahead_changed,
            Err(err) => warn!(
                epoch = current_epoch + 1,
                %err,
                "Lookahead duties fetch failed; keeping the current epoch's result"
            ),
        }

        // The current epoch only, and never the lookahead: next epoch's
        // proposers are not decided until this one ends, so an answer now is a
        // guess that would be overwritten anyway.
        //
        // Shrugged off like the lookahead rather than propagated, and for a
        // sharper reason: the attester schedule for this epoch has already been
        // fetched successfully by the time this runs, and returning an error
        // here would throw that away and leave the caller holding the previous
        // epoch's attester duties. Losing the proposer schedule costs at most a
        // block; losing the attester one costs every validator's vote, every
        // slot, until the next refresh succeeds.
        if let Err(err) = self.refresh_proposers(current_epoch).await {
            warn!(
                epoch = current_epoch,
                %err,
                "Proposer duties fetch failed; this epoch's blocks will not be proposed"
            );
        }

        self.by_epoch.retain(|epoch, _| *epoch >= current_epoch);
        self.proposers.retain(|epoch, _| *epoch >= current_epoch);
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

        service.refresh_around(3).await.expect("epoch 3");
        assert!(!service.at_slot(96, 3).is_empty());

        service.refresh_around(4).await.expect("epoch 4");
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

        service.refresh_around(3).await.expect("epoch 3");

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
        service.refresh_proposers(3).await.expect("refreshes");

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
        service.refresh_proposers(3).await.expect("refreshes");

        assert!(service.proposer_at_slot(97, 3).is_none());
        // Right slot, wrong epoch: the lookup must be scoped, not blurred.
        assert!(service.proposer_at_slot(96, 4).is_none());
    }

    #[tokio::test]
    async fn an_unchanged_proposer_dependent_root_keeps_the_held_schedule() {
        let node =
            Arc::new(MockBeaconNode::new().with_proposers(3, root(1), vec![proposer(1337, 96)]));
        let mut service = DutiesService::new(node.clone(), vec![1337]);
        service.refresh_proposers(3).await.expect("first");

        // Same dependent root, different content. A node that answers this way
        // is contradicting itself, and the held schedule must win: the root is
        // what the schedule is keyed on.
        node.set_proposers(3, root(1), vec![proposer(1337, 99)]);
        service.refresh_proposers(3).await.expect("second");

        assert!(service.proposer_at_slot(96, 3).is_some());
        assert!(service.proposer_at_slot(99, 3).is_none());
    }

    #[tokio::test]
    async fn a_changed_proposer_dependent_root_replaces_the_schedule() {
        let node =
            Arc::new(MockBeaconNode::new().with_proposers(3, root(1), vec![proposer(1337, 96)]));
        let mut service = DutiesService::new(node.clone(), vec![1337]);
        service.refresh_proposers(3).await.expect("first");

        // A reorg past the last slot of epoch 2 re-shuffles this epoch's
        // proposers, which is a far shallower reorg than the one that would
        // move an attester.
        node.set_proposers(3, root(2), vec![proposer(1337, 99)]);
        service.refresh_proposers(3).await.expect("second");

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
            .refresh_around(3)
            .await
            .expect("a failed proposer fetch must not fail the refresh");
        assert!(
            !service.at_slot(96, 3).is_empty(),
            "the attester schedule must have survived"
        );
        assert!(service.proposer_at_slot(96, 3).is_none());
    }

    /// Proposer duties for the next epoch are not decided until this one ends,
    /// so prefetching them would hold a guess that the epoch boundary
    /// overwrites. Attester duties *are* prefetched, which is why this has to
    /// be asserted rather than assumed.
    #[tokio::test]
    async fn proposer_duties_are_not_prefetched_for_the_lookahead_epoch() {
        let node = Arc::new(
            MockBeaconNode::new()
                .with_duties(3, root(1), vec![duty(1337, 96, 2)])
                .with_duties(4, root(2), vec![duty(1337, 130, 2)])
                .with_proposers(3, root(1), vec![proposer(1337, 96)])
                .with_proposers(4, root(2), vec![proposer(1337, 130)]),
        );
        let mut service = DutiesService::new(node.clone(), vec![1337]);
        service.refresh_around(3).await.expect("epoch 3");

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

    #[tokio::test]
    async fn refreshing_around_an_epoch_forgets_the_previous_ones_proposers() {
        let node = MockBeaconNode::new()
            .with_duties(3, root(1), vec![duty(1337, 96, 2)])
            .with_duties(4, root(2), vec![duty(1337, 130, 2)])
            .with_duties(5, root(3), vec![duty(1337, 165, 2)])
            .with_proposers(3, root(1), vec![proposer(1337, 96)])
            .with_proposers(4, root(2), vec![proposer(1337, 130)]);
        let mut service = DutiesService::new(Arc::new(node), vec![1337]);

        service.refresh_around(3).await.expect("epoch 3");
        assert!(service.proposer_at_slot(96, 3).is_some());

        service.refresh_around(4).await.expect("epoch 4");
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
        service.refresh_proposers(0).await.expect("refreshes");

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
        service.refresh_proposers(3).await.expect("no-op");
        assert_eq!(node.proposer_duties_call_count(), 0);
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
        service.refresh_around(3).await.expect("refreshes");
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
}
