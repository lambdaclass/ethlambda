//! Subnet attestations and aggregates whose verdict waits for the block they
//! vote for.
//!
//! Validators vote as soon as the slot's block reaches them, so the first
//! votes for a block arrive while this node is still importing it: waiting
//! for its custody columns, or running its state transition. Their stateful
//! checks read the voted block's own post-state, so until the import finishes
//! they answer `Ignore(StateUnavailable)`, or `Ignore(UnknownBlock)` for a
//! block not stored at all. Reported at once, that verdict drops the vote:
//! gossipsub does not relay it, it never reaches the attestation pool an
//! aggregator here reads, and no other copy follows, since every peer sends
//! the same message id. On a devnet with ~130 ms imports this cost each node
//! 5 to 8% of the subnet votes it received.
//!
//! The specification lets a client hold these ("a client MAY queue
//! attestations for processing once block is retrieved"), and lighthouse
//! does: its reprocess queue withholds the verdict, and checks the message
//! again on the block's `BlockImported`. This is the same, keyed by the voted
//! block's root: the verdict channel parks the vote instead of reporting
//! it, gossipsub keeps holding the message meanwhile, and
//! [`BlockChainToP2P::block_state_ready`] releases every vote parked under
//! the root to its stateful checks again. Whatever they answer then is
//! reported and acted on exactly as a first answer would be, so an accepted
//! vote propagates as the original message.
//!
//! What bounds it:
//!
//! - **One retry.** A vote checked again is never parked a second time.
//! - **A deadline inside gossipsub's.** Gossipsub drops a message still
//!   waiting for its verdict after `history_length` (6) heartbeats of 700 ms,
//!   which is 3.5 to 4.2 s after it arrived, depending on where in a
//!   heartbeat it did. [`PARKED_VOTE_DEADLINE`] plus one
//!   [`PARKED_VOTE_SWEEP_INTERVAL`] stays under that, so a vote whose block
//!   never comes still gets its first verdict, as it would have before.
//! - **A cap.** Votes are parked before their signature is checked, so at
//!   [`MAX_PARKED_VOTES`] the next one is reported as it would have been
//!   before this queue existed. Aggregates have a smaller cap of their own,
//!   [`MAX_PARKED_AGGREGATES`], since one can be far larger than a subnet
//!   attestation.
//!
//! The import signal can win the race against the verdict it releases: the
//! check reads the store on a blocking thread, the import caches the state
//! and sends its signal, and only then does the verdict reach the actor. A
//! vote whose root was announced among the last [`RECENTLY_READY_ROOTS`] is
//! therefore checked again at once instead of being parked.
//!
//! [`BlockChainToP2P::block_state_ready`]: ethlambda_network_api::BlockChainToP2P::block_state_ready

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use ethlambda_state_transition::beacon::gossip::Outcome;
use ethlambda_types::beacon::primitives::Root;

use crate::beacon::verdict::{GossipId, Validated};

/// How many votes may be parked at once. Lighthouse's
/// `MAXIMUM_QUEUED_ATTESTATIONS`.
pub(crate) const MAX_PARKED_VOTES: usize = 16_384;

/// How many of the parked votes may be aggregates.
///
/// An electra aggregate's bits run to `MAX_VALIDATORS_PER_COMMITTEE *
/// MAX_COMMITTEES_PER_SLOT`, 16 KiB decoded and a few hundred bytes on the
/// wire, and it is parked before its signature is checked. Under
/// [`MAX_PARKED_VOTES`] alone a peer naming roots that never import could
/// keep about 256 MiB of them resident; this keeps it near 32 MiB. An honest
/// network sends about a thousand aggregates a slot, so this holds two slots'
/// worth.
pub(crate) const MAX_PARKED_AGGREGATES: usize = 2_048;

/// How long after its arrival a parked vote may still wait for its block.
/// See the module documentation for why it must stay under 3.5 s with
/// [`PARKED_VOTE_SWEEP_INTERVAL`] added.
pub(crate) const PARKED_VOTE_DEADLINE: Duration = Duration::from_millis(2_500);

/// How often parked votes past [`PARKED_VOTE_DEADLINE`] are swept while any
/// are parked.
pub(crate) const PARKED_VOTE_SWEEP_INTERVAL: Duration = Duration::from_millis(250);

/// How many recently announced roots are remembered, for the race the module
/// documentation describes. About one block a slot is announced, so this
/// covers the last few minutes, far longer than any check takes.
const RECENTLY_READY_ROOTS: usize = 64;

/// A vote whose verdict is withheld until its block's post-state is ready.
pub(crate) struct ParkedVote {
    pub(crate) id: GossipId,
    pub(crate) object: Validated,
    /// What its first check answered: the verdict it gets if it is never
    /// checked again.
    pub(crate) outcome: Outcome,
}

impl ParkedVote {
    /// Whether it is too late to check this vote again: gossipsub would drop
    /// it before a second verdict could reach it.
    pub(crate) fn expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.id.received_at) >= PARKED_VOTE_DEADLINE
    }

    /// Whether this is an aggregate, which [`MAX_PARKED_AGGREGATES`] caps.
    fn is_aggregate(&self) -> bool {
        matches!(self.object, Validated::Aggregate { .. })
    }
}

/// How many of `votes` are aggregates.
fn aggregates_in(votes: &[ParkedVote]) -> usize {
    votes.iter().filter(|vote| vote.is_aggregate()).count()
}

/// What [`ParkedVotes::park`] did with a vote.
pub(crate) enum Parking {
    /// Parked until its root is announced or its deadline passes.
    Parked,
    /// Its root was already announced: check it again now.
    Ready(ParkedVote),
    /// The queue is full: report its first verdict now.
    Full(ParkedVote),
}

/// The parked votes, by the root of the block they vote for.
#[derive(Default)]
pub(crate) struct ParkedVotes {
    by_root: HashMap<Root, Vec<ParkedVote>>,
    len: usize,
    /// How many of the `len` are aggregates.
    aggregates: usize,
    recently_ready: VecDeque<Root>,
    /// Whether an expiry sweep is already scheduled, so parking a vote never
    /// starts a second timer.
    sweep_scheduled: bool,
}

impl ParkedVotes {
    /// Park `vote` under `root`, the block it votes for.
    pub(crate) fn park(&mut self, root: Root, vote: ParkedVote) -> Parking {
        if self.recently_ready.contains(&root) {
            return Parking::Ready(vote);
        }
        let aggregate = vote.is_aggregate();
        if self.len >= MAX_PARKED_VOTES || (aggregate && self.aggregates >= MAX_PARKED_AGGREGATES) {
            return Parking::Full(vote);
        }
        self.by_root.entry(root).or_default().push(vote);
        self.len += 1;
        self.aggregates += usize::from(aggregate);
        Parking::Parked
    }

    /// `root` has a post-state now: take every vote parked under it, and
    /// remember the root for a verdict still on its way (see the module
    /// documentation).
    pub(crate) fn take_ready(&mut self, root: Root) -> Vec<ParkedVote> {
        if !self.recently_ready.contains(&root) {
            if self.recently_ready.len() == RECENTLY_READY_ROOTS {
                self.recently_ready.pop_front();
            }
            self.recently_ready.push_back(root);
        }
        let votes = self.by_root.remove(&root).unwrap_or_default();
        self.len -= votes.len();
        self.aggregates -= aggregates_in(&votes);
        votes
    }

    /// Take every vote past its deadline at `now`.
    pub(crate) fn take_expired(&mut self, now: Instant) -> Vec<ParkedVote> {
        let mut expired = Vec::new();
        self.by_root.retain(|_, votes| {
            let (late, waiting): (Vec<_>, Vec<_>) = std::mem::take(votes)
                .into_iter()
                .partition(|vote| vote.expired(now));
            expired.extend(late);
            *votes = waiting;
            !votes.is_empty()
        });
        self.len -= expired.len();
        self.aggregates -= aggregates_in(&expired);
        expired
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Mark a sweep as scheduled. `true` when none was, meaning the caller
    /// must schedule it.
    pub(crate) fn claim_sweep(&mut self) -> bool {
        !std::mem::replace(&mut self.sweep_scheduled, true)
    }

    /// The scheduled sweep is running: the next park schedules another.
    pub(crate) fn sweep_started(&mut self) {
        self.sweep_scheduled = false;
    }
}

#[cfg(test)]
mod tests {
    use ethlambda_state_transition::beacon::gossip::IgnoreReason;
    use ethlambda_types::beacon::containers::electra::SingleAttestation;
    use ethlambda_types::beacon::containers::{AttestationData, Checkpoint};
    use libp2p::PeerId;
    use libp2p::gossipsub::MessageId;

    use super::*;

    fn vote(attester: u64, received_at: Instant) -> ParkedVote {
        ParkedVote {
            id: GossipId {
                message_id: MessageId::new(&attester.to_le_bytes()),
                propagation_source: PeerId::random(),
                received_at,
                kind: "beacon_attestation",
                pq_vote: None,
            },
            object: Validated::Attestation {
                attestation: Box::new(SingleAttestation {
                    committee_index: 0,
                    attester_index: attester,
                    data: AttestationData {
                        slot: 1,
                        index: 0,
                        beacon_block_root: Root::repeat_byte(1),
                        source: Checkpoint::default(),
                        target: Checkpoint::default(),
                    },
                    signature: Default::default(),
                }),
                subnet_id: 0,
            },
            outcome: Outcome::Ignore(IgnoreReason::StateUnavailable),
        }
    }

    fn aggregate(aggregator: u64, received_at: Instant) -> ParkedVote {
        use ethlambda_types::beacon::containers::{SignedAggregateAndProof, phase0};

        let aggregate = SignedAggregateAndProof::Phase0(phase0::SignedAggregateAndProof {
            message: phase0::AggregateAndProof {
                aggregator_index: aggregator,
                aggregate: phase0::Attestation {
                    aggregation_bits: phase0::AggregationBits::with_length(1).unwrap(),
                    data: AttestationData {
                        slot: 1,
                        index: 0,
                        beacon_block_root: Root::repeat_byte(1),
                        source: Checkpoint::default(),
                        target: Checkpoint::default(),
                    },
                    signature: Default::default(),
                },
                selection_proof: Default::default(),
            },
            signature: Default::default(),
        });
        ParkedVote {
            id: GossipId {
                message_id: MessageId::new(&aggregator.to_be_bytes()),
                propagation_source: PeerId::random(),
                received_at,
                kind: "beacon_aggregate_and_proof",
                pq_vote: None,
            },
            object: Validated::Aggregate {
                aggregate: Box::new(aggregate),
                attesting_indices: Vec::new(),
            },
            outcome: Outcome::Ignore(IgnoreReason::UnknownBlock),
        }
    }

    fn attesters(votes: &[ParkedVote]) -> Vec<u64> {
        let mut attesters: Vec<u64> = votes
            .iter()
            .map(|vote| match &vote.object {
                Validated::Attestation { attestation, .. } => attestation.attester_index,
                _ => unreachable!("only attestations are parked here"),
            })
            .collect();
        attesters.sort_unstable();
        attesters
    }

    #[test]
    fn an_announced_root_releases_only_its_own_votes() {
        let now = Instant::now();
        let mut parked = ParkedVotes::default();
        let (a, b) = (Root::repeat_byte(1), Root::repeat_byte(2));
        assert!(matches!(parked.park(a, vote(1, now)), Parking::Parked));
        assert!(matches!(parked.park(a, vote(2, now)), Parking::Parked));
        assert!(matches!(parked.park(b, vote(3, now)), Parking::Parked));
        assert_eq!(parked.len(), 3);

        assert_eq!(attesters(&parked.take_ready(a)), vec![1, 2]);
        assert_eq!(parked.len(), 1);
        assert!(parked.take_ready(a).is_empty());
        assert_eq!(attesters(&parked.take_ready(b)), vec![3]);
        assert!(parked.is_empty());
    }

    #[test]
    fn a_vote_for_a_root_already_announced_is_checked_again_at_once() {
        let now = Instant::now();
        let mut parked = ParkedVotes::default();
        let root = Root::repeat_byte(1);
        assert!(parked.take_ready(root).is_empty());

        assert!(matches!(parked.park(root, vote(1, now)), Parking::Ready(_)));
        assert!(parked.is_empty());
    }

    #[test]
    fn only_the_latest_announced_roots_are_remembered() {
        let now = Instant::now();
        let mut parked = ParkedVotes::default();
        for byte in 0..=RECENTLY_READY_ROOTS as u8 {
            parked.take_ready(Root::repeat_byte(byte));
        }

        // The first one has been pushed out; the latest is still known.
        assert!(matches!(
            parked.park(Root::repeat_byte(0), vote(1, now)),
            Parking::Parked
        ));
        assert!(matches!(
            parked.park(Root::repeat_byte(RECENTLY_READY_ROOTS as u8), vote(2, now)),
            Parking::Ready(_)
        ));
    }

    #[test]
    fn a_full_queue_hands_the_vote_back() {
        let now = Instant::now();
        let mut parked = ParkedVotes::default();
        for attester in 0..MAX_PARKED_VOTES as u64 {
            let root = Root::repeat_byte((attester % 4) as u8);
            assert!(matches!(
                parked.park(root, vote(attester, now)),
                Parking::Parked
            ));
        }

        assert!(matches!(
            parked.park(Root::repeat_byte(9), vote(u64::MAX, now)),
            Parking::Full(_)
        ));
        assert_eq!(parked.len(), MAX_PARKED_VOTES);

        // Releasing a root makes room again.
        let released = parked.take_ready(Root::repeat_byte(0)).len();
        assert_eq!(parked.len(), MAX_PARKED_VOTES - released);
        assert!(matches!(
            parked.park(Root::repeat_byte(9), vote(u64::MAX, now)),
            Parking::Parked
        ));
    }

    /// Aggregates fill a cap of their own, well below the queue's: past it
    /// the next aggregate is handed back, while a subnet attestation still
    /// parks, and releasing or expiring aggregates makes room for more.
    #[test]
    fn aggregates_have_a_smaller_cap_of_their_own() {
        let now = Instant::now();
        let mut parked = ParkedVotes::default();
        let (a, b) = (Root::repeat_byte(1), Root::repeat_byte(2));
        for aggregator in 0..MAX_PARKED_AGGREGATES as u64 {
            let root = if aggregator % 2 == 0 { a } else { b };
            assert!(matches!(
                parked.park(root, aggregate(aggregator, now)),
                Parking::Parked
            ));
        }

        assert!(matches!(
            parked.park(a, aggregate(u64::MAX, now)),
            Parking::Full(_)
        ));
        assert!(matches!(parked.park(a, vote(1, now)), Parking::Parked));

        assert_eq!(parked.take_ready(a).len(), MAX_PARKED_AGGREGATES / 2 + 1);
        assert!(matches!(
            parked.park(Root::repeat_byte(3), aggregate(u64::MAX, now)),
            Parking::Parked
        ));
        let expired = parked.take_expired(now + PARKED_VOTE_DEADLINE).len();
        assert_eq!(expired, MAX_PARKED_AGGREGATES / 2 + 1);
        assert!(parked.is_empty());
        for aggregator in 0..MAX_PARKED_AGGREGATES as u64 {
            assert!(matches!(
                parked.park(b, aggregate(aggregator, now)),
                Parking::Parked
            ));
        }
    }

    #[test]
    fn only_votes_past_the_deadline_expire() {
        let early = Instant::now();
        let late = early + Duration::from_secs(1);
        let mut parked = ParkedVotes::default();
        let root = Root::repeat_byte(1);
        parked.park(root, vote(1, early));
        parked.park(root, vote(2, late));
        parked.park(Root::repeat_byte(2), vote(3, early));

        let sweep = early + PARKED_VOTE_DEADLINE;
        assert!(
            parked
                .take_expired(sweep - Duration::from_millis(1))
                .is_empty()
        );
        assert_eq!(attesters(&parked.take_expired(sweep)), vec![1, 3]);
        assert_eq!(parked.len(), 1);
        assert_eq!(attesters(&parked.take_ready(root)), vec![2]);
    }

    #[test]
    fn one_sweep_is_scheduled_at_a_time() {
        let mut parked = ParkedVotes::default();
        assert!(parked.claim_sweep());
        assert!(!parked.claim_sweep());
        parked.sweep_started();
        assert!(parked.claim_sweep());
    }

    #[test]
    fn the_deadline_leaves_room_for_a_sweep_inside_gossipsubs_window() {
        // Gossipsub drops a message awaiting its verdict as early as five
        // heartbeats of 700 ms after it arrived.
        let earliest_eviction = Duration::from_millis(5 * 700);
        assert!(PARKED_VOTE_DEADLINE + PARKED_VOTE_SWEEP_INTERVAL < earliest_eviction);
    }
}
