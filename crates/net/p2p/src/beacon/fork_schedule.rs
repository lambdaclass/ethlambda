//! Which fork digests the chain will use, and when a running node must move
//! between them.
//!
//! Every fork activation and every blob-schedule entry (a blob-parameter-only
//! fork, BPO) changes the fork digest, and the digest is in every gossip topic
//! name, the `Status` handshake and the ENR `eth2` entry. A node that computed
//! its digest once at startup is stranded on topics nobody publishes to the
//! moment a boundary passes, so the node follows this schedule instead.
//!
//! The transition rules are the spec's ("Transitioning the gossip" in altair's
//! `p2p-interface.md`): "In advance of the fork, a node SHOULD subscribe to the
//! post-fork variants of the topics", and the pre-fork topics are dropped "two
//! epochs after the fork". A digest is therefore held from
//! [`SUBSCRIBE_LEAD_EPOCHS`] before it activates until
//! [`UNSUBSCRIBE_LAG_EPOCHS`] after the next one does, and the node is
//! subscribed to whichever digests that window covers at the current epoch.
//! Everything here is a pure function of the epoch, so applying it is
//! idempotent and a node started inside a window lands in the same state as one
//! that crossed into it.
//!
//! Pure on purpose: the P2P actor owns the clock and the swarm; this owns only
//! the arithmetic, so it is testable without either.

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::constants::FAR_FUTURE_EPOCH;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::fork_digest::compute_fork_digest;
use ethlambda_types::beacon::primitives::{Epoch, ForkDigest, Root, Version};
use ethlambda_types::enr::EnrForkId;

/// Epochs before a digest activates at which its topics are joined.
pub const SUBSCRIBE_LEAD_EPOCHS: Epoch = 1;

/// Epochs after the *next* digest activates at which a digest's topics are
/// left.
pub const UNSUBSCRIBE_LAG_EPOCHS: Epoch = 2;

/// One digest and the epoch it becomes current.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduledDigest {
    /// The first epoch this digest is current at.
    pub activation_epoch: Epoch,
    pub digest: ForkDigest,
    /// The fork version in effect at `activation_epoch`, for the `eth2` entry's
    /// `next_fork_version` when this is the next boundary.
    pub version: Version,
    /// The fork in effect at `activation_epoch`, so the fork of everything
    /// published under `digest`.
    pub fork: ForkName,
}

/// Every digest a chain will use, in activation order.
#[derive(Debug, Clone)]
pub struct ForkSchedule {
    /// Never empty: the first entry is the genesis digest. Consecutive equal
    /// digests are merged, so each entry is a real change on the wire.
    entries: Vec<ScheduledDigest>,
}

impl ForkSchedule {
    /// Build the schedule from every fork epoch and blob-schedule epoch in
    /// `config`. Unscheduled forks carry [`FAR_FUTURE_EPOCH`] and are skipped.
    pub fn new(config: &Config, genesis_validators_root: Root) -> Self {
        let mut epochs: Vec<Epoch> = ForkName::ALL
            .into_iter()
            .map(|fork| config.fork_epoch(fork))
            .chain(config.blob_schedule.iter().map(|entry| entry.epoch))
            .chain([0])
            .filter(|&epoch| epoch != FAR_FUTURE_EPOCH)
            .collect();
        epochs.sort_unstable();
        epochs.dedup();

        let mut entries: Vec<ScheduledDigest> = Vec::with_capacity(epochs.len());
        for epoch in epochs {
            let digest = compute_fork_digest(config, genesis_validators_root, epoch);
            // Only a blob-schedule entry before fulu, or one landing on an
            // epoch another entry already covers, leaves the digest alone:
            // from fulu on the digest hashes the entry's own epoch as well as
            // its limit, so a later entry always moves it, even one restating
            // the limit already in force.
            if entries.last().is_some_and(|last| last.digest == digest) {
                continue;
            }
            entries.push(ScheduledDigest {
                activation_epoch: epoch,
                digest,
                version: config.fork_version(config.fork_at_epoch(epoch)),
                fork: config.fork_at_epoch(epoch),
            });
        }
        Self { entries }
    }

    /// Every scheduled digest, in activation order.
    pub fn entries(&self) -> &[ScheduledDigest] {
        &self.entries
    }

    fn index_at(&self, epoch: Epoch) -> usize {
        self.entries
            .partition_point(|entry| entry.activation_epoch <= epoch)
            .saturating_sub(1)
    }

    /// The digest (and its fork) that is current at `epoch`.
    pub fn current_at(&self, epoch: Epoch) -> ScheduledDigest {
        self.entries[self.index_at(epoch)]
    }

    /// The digest current at `epoch`.
    pub fn digest_at(&self, epoch: Epoch) -> ForkDigest {
        self.current_at(epoch).digest
    }

    /// The fork a message published under `digest` is in, if any scheduled
    /// digest is `digest`.
    ///
    /// This is how a gossip message's fork is taken from its own topic rather
    /// than from whichever digest the node currently advertises.
    pub fn fork_for_digest(&self, digest: ForkDigest) -> Option<ForkName> {
        self.entries
            .iter()
            .find(|entry| entry.digest == digest)
            .map(|entry| entry.fork)
    }

    /// The digests whose topics the node holds at `epoch`, in activation order.
    ///
    /// Entry `i` is held from [`SUBSCRIBE_LEAD_EPOCHS`] before it activates
    /// until [`UNSUBSCRIBE_LAG_EPOCHS`] after entry `i + 1` does; the first is
    /// held from genesis and the last forever. Always contains the current
    /// digest, since `epoch` lies inside its own window.
    pub fn held_at(&self, epoch: Epoch) -> Vec<ScheduledDigest> {
        self.entries
            .iter()
            .enumerate()
            .filter(|&(index, entry)| {
                let joined = index == 0
                    || epoch.saturating_add(SUBSCRIBE_LEAD_EPOCHS) >= entry.activation_epoch;
                let left = self.entries.get(index + 1).is_some_and(|next| {
                    epoch >= next.activation_epoch.saturating_add(UNSUBSCRIBE_LAG_EPOCHS)
                });
                joined && !left
            })
            .map(|(_, entry)| *entry)
            .collect()
    }

    /// The first epoch after `epoch` at which anything above changes: a join, a
    /// switch or a leave. `None` once the schedule has run out.
    pub fn next_change_after(&self, epoch: Epoch) -> Option<Epoch> {
        self.entries
            .iter()
            .enumerate()
            .flat_map(|(index, entry)| {
                let join = entry.activation_epoch.saturating_sub(SUBSCRIBE_LEAD_EPOCHS);
                let leave = self
                    .entries
                    .get(index + 1)
                    .map(|next| next.activation_epoch.saturating_add(UNSUBSCRIBE_LAG_EPOCHS));
                [Some(join), Some(entry.activation_epoch), leave]
            })
            .flatten()
            .filter(|&change| change > epoch)
            .min()
    }

    /// The next digest change after `epoch`, for the `eth2` entry's
    /// `next_fork_*` and for the startup log.
    pub fn next_boundary_after(&self, epoch: Epoch) -> Option<ScheduledDigest> {
        self.entries
            .iter()
            .find(|entry| entry.activation_epoch > epoch)
            .copied()
    }

    /// The `eth2` ENR entry at `epoch`.
    ///
    /// `next_fork_*` name the next entry of this schedule, so never an epoch at
    /// which the digest does not change. With none ahead, the spec says to
    /// repeat the current version and name the far-future epoch.
    pub fn enr_fork_id(&self, epoch: Epoch) -> EnrForkId {
        let current = self.current_at(epoch);
        match self.next_boundary_after(epoch) {
            Some(next) => EnrForkId {
                fork_digest: current.digest,
                next_fork_version: next.version,
                next_fork_epoch: next.activation_epoch,
            },
            None => EnrForkId {
                fork_digest: current.digest,
                next_fork_version: current.version,
                next_fork_epoch: FAR_FUTURE_EPOCH,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::config::BlobScheduleEntry;
    use libssz_types::SszList;

    const FULU: Epoch = 1_000;
    const GLOAS: Epoch = 5_000;

    fn gvr() -> Root {
        Root::repeat_byte(7)
    }

    /// Sepolia's shape: fulu, then gloas, with no blob-schedule entry between.
    fn fulu_then_gloas() -> Config {
        let mut config = Config::mainnet()
            .with_fork_epoch(ForkName::Altair, 1)
            .with_fork_epoch(ForkName::Bellatrix, 2)
            .with_fork_epoch(ForkName::Capella, 3)
            .with_fork_epoch(ForkName::Deneb, 4)
            .with_fork_epoch(ForkName::Electra, 5)
            .with_fork_epoch(ForkName::Fulu, FULU)
            .with_fork_epoch(ForkName::Gloas, GLOAS);
        config.blob_schedule = SszList::new();
        config
    }

    /// Fulu, two BPOs, then gloas.
    fn with_bpos() -> Config {
        let mut config = fulu_then_gloas();
        config.blob_schedule = SszList::try_from(vec![
            BlobScheduleEntry {
                epoch: 2_000,
                max_blobs_per_block: 15,
            },
            BlobScheduleEntry {
                epoch: 3_000,
                max_blobs_per_block: 21,
            },
        ])
        .expect("within capacity");
        config
    }

    fn digests_held(schedule: &ForkSchedule, epoch: Epoch) -> Vec<ForkDigest> {
        schedule
            .held_at(epoch)
            .into_iter()
            .map(|entry| entry.digest)
            .collect()
    }

    #[test]
    fn every_scheduled_digest_resolves_to_its_fork() {
        let config = with_bpos();
        let schedule = ForkSchedule::new(&config, gvr());
        // Genesis, each fork through fulu, two BPOs, gloas.
        let shape: Vec<(Epoch, ForkName)> = schedule
            .entries()
            .iter()
            .map(|entry| (entry.activation_epoch, entry.fork))
            .collect();
        assert_eq!(
            shape,
            vec![
                (0, ForkName::Phase0),
                (1, ForkName::Altair),
                (2, ForkName::Bellatrix),
                (3, ForkName::Capella),
                (4, ForkName::Deneb),
                (5, ForkName::Electra),
                (FULU, ForkName::Fulu),
                (2_000, ForkName::Fulu),
                (3_000, ForkName::Fulu),
                (GLOAS, ForkName::Gloas),
            ]
        );
        for entry in schedule.entries() {
            assert_eq!(schedule.fork_for_digest(entry.digest), Some(entry.fork));
            assert_eq!(
                entry.digest,
                compute_fork_digest(&config, gvr(), entry.activation_epoch)
            );
        }
        assert_eq!(schedule.fork_for_digest([0xde, 0xad, 0xbe, 0xef]), None);
    }

    #[test]
    fn a_bpo_moves_the_digest_but_not_the_fork() {
        let schedule = ForkSchedule::new(&with_bpos(), gvr());
        let before = schedule.current_at(1_999);
        let after = schedule.current_at(2_000);
        assert_ne!(before.digest, after.digest);
        assert_eq!(before.fork, ForkName::Fulu);
        assert_eq!(after.fork, ForkName::Fulu);
        assert_eq!(schedule.fork_for_digest(after.digest), Some(ForkName::Fulu));
    }

    #[test]
    fn the_gloas_boundary_resolves_both_sides() {
        let schedule = ForkSchedule::new(&fulu_then_gloas(), gvr());
        assert_eq!(schedule.current_at(GLOAS - 1).fork, ForkName::Fulu);
        assert_eq!(schedule.current_at(GLOAS).fork, ForkName::Gloas);
        assert_eq!(
            schedule.digest_at(GLOAS),
            compute_fork_digest(&fulu_then_gloas(), gvr(), GLOAS)
        );
    }

    #[test]
    fn a_blob_entry_before_fulu_is_not_a_boundary() {
        // The digest only hashes blob parameters from fulu on, so an entry
        // placed before it cannot move anything on the wire.
        let plain = ForkSchedule::new(&fulu_then_gloas(), gvr());
        let mut config = fulu_then_gloas();
        config.blob_schedule = SszList::try_from(vec![BlobScheduleEntry {
            // An epoch no fork uses, so the entry reaches the digest
            // comparison instead of being dropped as a duplicate epoch.
            epoch: 500,
            max_blobs_per_block: 9,
        }])
        .expect("within capacity");
        let with_entry = ForkSchedule::new(&config, gvr());
        assert_eq!(with_entry.entries().len(), plain.entries().len());
    }

    #[test]
    fn a_bpo_restating_the_previous_limit_is_still_a_boundary() {
        // `compute_fork_digest` hashes the entry's epoch as well as its limit,
        // so a later entry with the same limit moves the digest.
        let mut config = fulu_then_gloas();
        config.blob_schedule = SszList::try_from(vec![
            BlobScheduleEntry {
                epoch: 2_000,
                max_blobs_per_block: 15,
            },
            BlobScheduleEntry {
                epoch: 3_000,
                max_blobs_per_block: 15,
            },
        ])
        .expect("within capacity");
        let schedule = ForkSchedule::new(&config, gvr());
        assert_ne!(schedule.digest_at(2_999), schedule.digest_at(3_000));
        assert!(
            schedule
                .entries()
                .iter()
                .any(|entry| entry.activation_epoch == 3_000)
        );
    }

    #[test]
    fn the_next_digest_is_joined_one_epoch_early_and_the_old_left_two_late() {
        let schedule = ForkSchedule::new(&fulu_then_gloas(), gvr());
        let fulu = schedule.digest_at(GLOAS - 1);
        let gloas = schedule.digest_at(GLOAS);

        // Two epochs ahead: only the pre-boundary digest.
        assert_eq!(digests_held(&schedule, GLOAS - 2), vec![fulu]);
        // B-1: both, and the old one is still the current.
        assert_eq!(digests_held(&schedule, GLOAS - 1), vec![fulu, gloas]);
        assert_eq!(schedule.digest_at(GLOAS - 1), fulu);
        // B: both, and the new one is current.
        assert_eq!(digests_held(&schedule, GLOAS), vec![fulu, gloas]);
        assert_eq!(schedule.digest_at(GLOAS), gloas);
        // B+1: still both.
        assert_eq!(digests_held(&schedule, GLOAS + 1), vec![fulu, gloas]);
        // B+2: the old topics go.
        assert_eq!(digests_held(&schedule, GLOAS + 2), vec![gloas]);
    }

    #[test]
    fn a_node_started_inside_the_window_holds_both() {
        // Start at B+1: nothing crossed the boundary, yet the state is the one
        // a node that did cross it would be in.
        let schedule = ForkSchedule::new(&fulu_then_gloas(), gvr());
        let held = digests_held(&schedule, GLOAS + 1);
        assert_eq!(held.len(), 2);
        assert!(held.contains(&schedule.digest_at(GLOAS + 1)));
    }

    #[test]
    fn the_current_digest_is_always_held() {
        let schedule = ForkSchedule::new(&with_bpos(), gvr());
        for epoch in 0..6_000 {
            assert!(
                digests_held(&schedule, epoch).contains(&schedule.digest_at(epoch)),
                "epoch {epoch}"
            );
        }
    }

    #[test]
    fn changes_are_announced_at_every_join_switch_and_leave() {
        let schedule = ForkSchedule::new(&fulu_then_gloas(), gvr());
        assert_eq!(schedule.next_change_after(GLOAS - 10), Some(GLOAS - 1));
        assert_eq!(schedule.next_change_after(GLOAS - 1), Some(GLOAS));
        assert_eq!(schedule.next_change_after(GLOAS), Some(GLOAS + 2));
        assert_eq!(schedule.next_change_after(GLOAS + 2), None);
    }

    #[test]
    fn the_held_set_only_changes_at_announced_epochs() {
        let schedule = ForkSchedule::new(&with_bpos(), gvr());
        let mut previous = (digests_held(&schedule, 0), schedule.digest_at(0));
        let mut epoch = 0;
        while epoch < 6_000 {
            let next = schedule.next_change_after(epoch);
            let until = next.unwrap_or(6_000);
            for probe in epoch..until {
                assert_eq!(
                    (digests_held(&schedule, probe), schedule.digest_at(probe)),
                    previous,
                    "epoch {probe} changed without being announced"
                );
            }
            epoch = until;
            previous = (digests_held(&schedule, epoch), schedule.digest_at(epoch));
        }
    }

    #[test]
    fn the_next_boundary_names_the_digest_and_fork_ahead() {
        let schedule = ForkSchedule::new(&fulu_then_gloas(), gvr());
        let next = schedule.next_boundary_after(FULU + 1).expect("gloas ahead");
        assert_eq!(next.activation_epoch, GLOAS);
        assert_eq!(next.fork, ForkName::Gloas);
        assert_eq!(schedule.next_boundary_after(GLOAS), None);
    }

    #[test]
    fn the_enr_entry_points_at_the_next_boundary() {
        let schedule = ForkSchedule::new(&fulu_then_gloas(), gvr());
        let before = schedule.enr_fork_id(GLOAS - 1);
        assert_eq!(before.next_fork_epoch, GLOAS);
        let after = schedule.enr_fork_id(GLOAS);
        assert_eq!(after.fork_digest, schedule.digest_at(GLOAS));
        assert_eq!(after.next_fork_epoch, FAR_FUTURE_EPOCH);
    }

    #[test]
    fn closely_spaced_boundaries_hold_each_digest_in_its_own_window() {
        let mut config = fulu_then_gloas();
        config.blob_schedule = SszList::try_from(vec![
            BlobScheduleEntry {
                epoch: 2_000,
                max_blobs_per_block: 15,
            },
            BlobScheduleEntry {
                epoch: 2_001,
                max_blobs_per_block: 21,
            },
        ])
        .expect("within capacity");
        let schedule = ForkSchedule::new(&config, gvr());
        // Three digests are live at once around 2_001; none is dropped early.
        assert_eq!(schedule.held_at(2_001).len(), 3);
    }
}
