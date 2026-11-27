//! Disseminates PQ aggregates on the `beacon_aggregate_and_proof` waggle topic (leanVM proof
//! broadcast).
//!
//! The proof of an aggregate is split into chunks, which the signed `AggregateHeader` of the
//! aggregate commits to. Peers push chunks to each other, announce and request them until each
//! of them holds every chunk. The header travels with the first chunk a peer gets.
//!
//! This follows the dissemination of execution payload chunks over waggle (EIP-8411). What
//! differs comes from the commitment: the chunks of a payload are verified against the bid of a
//! block we know before we accept the first chunk, while nothing commits to a proof before it is
//! broadcast. So an aggregate is tracked from the first message about it, and its chunks are
//! only kept once a header arrived with one of them and was checked.
//!
//! Ported from Lighthouse's `beacon_node/network/src/waggle_handlers/aggregate.rs`
//! (`kamilsa/lighthouse`, branch `leanvm-proof-broadcast`, at `9ab5e2e7f`;
//! Apache-2.0, Copyright Sigma Prime Pty Ltd), so that this node disseminates
//! aggregates as the `pq-devnet-0-waggle` image does and interoperates with it.
//! The dissemination itself (what is pushed, announced, requested and served,
//! and when) is kept; what changed is how the service reaches the rest of the
//! node, which is [`Host`] here: Lighthouse's beacon processor, slot clock and
//! peer manager are this crate's blocking checks, wall clock and
//! [`PeerPenalties`]. A header is checked by
//! `gossip::pq::aggregate_header_checks` and a complete aggregate by the P2P
//! actor, which owns the seen cache.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::ops::RangeInclusive;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use bytes::Bytes;
use ethlambda_metrics::*;
use ethlambda_state_transition::beacon::gossip::pq::CheckedHeader;
use ethlambda_types::beacon::containers::pq::SignedAggregateHeader;
use ethlambda_types::beacon::containers::proof_chunks::{
    AggregateId, AggregatePiece, ProofChunk, ProofChunkBitmap, ProofChunkMetadata,
    TOTAL_PROOF_CHUNKS,
};
use ethlambda_types::beacon::preset::MIN_ATTESTATION_INCLUSION_DELAY_PQ;
use ethlambda_types::beacon::primitives::{Root, Slot, ValidatorIndex};
use ethlambda_types::primitives::HashTreeRoot as _;
use libp2p::PeerId;
use libp2p::swarm::ConnectionId;
use libssz::{SszDecode, SszEncode};
use rand::seq::SliceRandom;
use tokio::select;
use tokio::sync::{mpsc, oneshot};
use tokio::task::coop::consume_budget;
use tokio::time::{Instant, sleep_until};
use tracing::{debug, error, warn};

use crate::waggle::handler::{ObjectPieces, PieceSender, TopicEvent};

/// What the service needs from the rest of the node.
pub(crate) trait Host: Send + 'static {
    /// The fork digest of the epoch of `slot`.
    fn fork_digest_at(&self, slot: Slot) -> ForkDigest;

    /// The validators that can aggregate at `slot`, by the head state: the
    /// aggregation committees of every committee of the slot. `None` when the
    /// head state does not cover the slot, as while syncing.
    fn aggregators_at(&self, slot: Slot) -> Option<Vec<ValidatorIndex>>;

    /// The slots whose aggregates are in their tracking window, see
    /// [`tracked_slots`], if the clock is past genesis.
    fn tracked_slots(&self) -> Option<RangeInclusive<Slot>>;

    /// How long until the tracking window moves on, see
    /// [`time_to_next_tracking_window`].
    fn time_to_next_tracking_window(&self) -> Duration;

    /// Has the header of the aggregate `id` that `peer_id` sent checked. The
    /// result comes back as [`AggregateDisseminationMessage::HeaderVerified`].
    fn check_header(
        &self,
        id: AggregateId,
        peer_id: PeerId,
        signed_header: Arc<SignedAggregateHeader>,
    ) -> Result<(), HostError>;

    /// Has the aggregate of `header` checked, complete with its chunks, the
    /// last of which `peer_id` sent. The result comes back as
    /// [`AggregateDisseminationMessage::AggregateVerified`].
    fn check_aggregate(
        &self,
        header: Arc<CheckedHeader>,
        chunks: Vec<Arc<ProofChunk>>,
        peer_id: PeerId,
    ) -> Result<(), HostError>;

    /// Reports `peer_id` for misbehaving on the topic.
    fn report_peer(&self, peer_id: PeerId, penalty: Penalty, reason: &'static str);
}

/// Why the [`Host`] could not take a check.
#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum HostError {
    #[error("no permit left for the check")]
    Overloaded,
    #[error("the node is shutting down")]
    ShuttingDown,
}

/// How bad a peer's misbehaviour is, as Lighthouse's peer actions grade it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Penalty {
    /// Lighthouse's `LowToleranceError`: invalid data, a handful gets a peer
    /// dropped.
    LowTolerance,
    /// Lighthouse's `MidToleranceError`: protocol misuse that a buggy but
    /// honest peer could commit.
    MidTolerance,
}

/// Per-peer penalty scores, decaying over time, that drop a peer once its
/// score crosses [`PeerPenalties::DISCONNECT_AT`]. A stand-in for the peer
/// manager Lighthouse reports to: this node scores peers through gossipsub
/// only, which knows nothing of Waggle.
#[derive(Default)]
pub(crate) struct PeerPenalties {
    scores: HashMap<PeerId, (f64, Instant)>,
}

impl PeerPenalties {
    /// The score that gets a peer disconnected: five low-tolerance or ten
    /// mid-tolerance penalties in quick succession, as Lighthouse's.
    pub(crate) const DISCONNECT_AT: f64 = 50.0;
    /// How long a penalty takes to decay to half.
    const HALF_LIFE: Duration = Duration::from_secs(600);

    /// Adds `penalty` to `peer_id`'s score. Returns whether the peer is now to
    /// be disconnected, which forgets its score.
    pub(crate) fn add(&mut self, peer_id: PeerId, penalty: Penalty, now: Instant) -> bool {
        let points = match penalty {
            Penalty::LowTolerance => 10.0,
            Penalty::MidTolerance => 5.0,
        };
        let (score, at) = self.scores.entry(peer_id).or_insert((0.0, now));
        let halvings =
            now.saturating_duration_since(*at).as_secs_f64() / Self::HALF_LIFE.as_secs_f64();
        *score = *score * 0.5f64.powf(halvings) + points;
        *at = now;
        if *score >= Self::DISCONNECT_AT {
            self.scores.remove(&peer_id);
            return true;
        }
        false
    }
}

/// A set of chunk indices, below [`TOTAL_PROOF_CHUNKS`]: the 64 bits of a
/// [`ProofChunkBitmap`], whose SSZ bit `i` is bit `i` of this little-endian
/// word.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ChunkSet(u64);

const _: () = assert!(TOTAL_PROOF_CHUNKS == u64::BITS as usize);

impl ChunkSet {
    pub(crate) fn new() -> Self {
        Self(0)
    }

    /// Whether `index` is in the set, or `None` past the last chunk.
    pub(crate) fn get(&self, index: usize) -> Option<bool> {
        (index < TOTAL_PROOF_CHUNKS).then(|| self.0 >> index & 1 == 1)
    }

    pub(crate) fn set(&mut self, index: usize, value: bool) -> Result<(), ()> {
        if index >= TOTAL_PROOF_CHUNKS {
            return Err(());
        }
        if value {
            self.0 |= 1 << index;
        } else {
            self.0 &= !(1 << index);
        }
        Ok(())
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.0 == 0
    }

    pub(crate) fn union(&self, other: &Self) -> Self {
        Self(self.0 | other.0)
    }

    pub(crate) fn intersection(&self, other: &Self) -> Self {
        Self(self.0 & other.0)
    }

    pub(crate) fn difference(&self, other: &Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Every bit, in index order. Takes a copy, so iterating holds no
    /// borrow of where the set lives.
    pub(crate) fn iter(self) -> impl Iterator<Item = bool> {
        let bits = self.0;
        (0..TOTAL_PROOF_CHUNKS).map(move |index| bits >> index & 1 == 1)
    }
}

impl From<&ProofChunkBitmap> for ChunkSet {
    fn from(bitmap: &ProofChunkBitmap) -> Self {
        let bytes: [u8; 8] = bitmap
            .as_bytes()
            .try_into()
            .expect("a 64-bit bitvector is eight bytes");
        Self(u64::from_le_bytes(bytes))
    }
}

impl From<ChunkSet> for ProofChunkBitmap {
    fn from(set: ChunkSet) -> Self {
        let mut bitmap = ProofChunkBitmap::new();
        for index in 0..TOTAL_PROOF_CHUNKS {
            if set.get(index) == Some(true) {
                let _ = bitmap.set(index, true);
            }
        }
        bitmap
    }
}

/// The service's metrics, under Lighthouse's names with this node's
/// `lean_beacon_` prefix, so the two clients' dashboards line up.
mod metrics {
    use super::*;

    pub(super) static AGGREGATE_DISSEMINATION_AGGREGATES_TRACKED: LazyLock<IntCounter> =
        LazyLock::new(|| {
            register_int_counter!(
                "lean_beacon_aggregate_dissemination_aggregates_tracked_total",
                "Aggregates the Waggle dissemination started tracking"
            )
            .unwrap()
        });
    pub(super) static AGGREGATE_DISSEMINATION_HEADERS: LazyLock<IntCounterVec> =
        LazyLock::new(|| {
            register_int_counter_vec!(
                "lean_beacon_aggregate_dissemination_headers_total",
                "Aggregate headers received over Waggle, by result",
                &["result"]
            )
            .unwrap()
        });
    pub(super) static AGGREGATE_DISSEMINATION_AGGREGATES_COMPLETED: LazyLock<IntCounterVec> =
        LazyLock::new(|| {
            register_int_counter_vec!(
                "lean_beacon_aggregate_dissemination_aggregates_completed_total",
                "Aggregates whose every chunk is held, by how",
                &["source"]
            )
            .unwrap()
        });
    pub(super) static AGGREGATE_DISSEMINATION_AGGREGATES_INCOMPLETE: LazyLock<IntCounterVec> =
        LazyLock::new(|| {
            register_int_counter_vec!(
                "lean_beacon_aggregate_dissemination_aggregates_incomplete_total",
                "Aggregates dropped at the end of their tracking window while incomplete",
                &["header"]
            )
            .unwrap()
        });
    pub(super) static AGGREGATE_DISSEMINATION_AGGREGATES_VERIFIED: LazyLock<IntCounterVec> =
        LazyLock::new(|| {
            register_int_counter_vec!(
                "lean_beacon_aggregate_dissemination_aggregates_verified_total",
                "Reassembled aggregates checked, by result",
                &["result"]
            )
            .unwrap()
        });
    pub(super) static AGGREGATE_DISSEMINATION_REASSEMBLY_SECONDS: LazyLock<Histogram> =
        LazyLock::new(|| {
            register_histogram!(
                "lean_beacon_aggregate_dissemination_reassembly_seconds",
                "Time from tracking an aggregate to holding every chunk",
                vec![
                    0.05, 0.1, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 4.0, 6.0, 8.0, 12.0
                ]
            )
            .unwrap()
        });
    pub(super) static AGGREGATE_DISSEMINATION_CHUNKS_RECEIVED: LazyLock<IntCounterVec> =
        LazyLock::new(|| {
            register_int_counter_vec!(
                "lean_beacon_aggregate_dissemination_chunks_received_total",
                "Proof chunks received over Waggle, by what became of them",
                &["result"]
            )
            .unwrap()
        });
    pub(super) static AGGREGATE_DISSEMINATION_CHUNKS_SENT: LazyLock<IntCounterVec> =
        LazyLock::new(|| {
            register_int_counter_vec!(
                "lean_beacon_aggregate_dissemination_chunks_sent_total",
                "Proof chunks queued for peers, pushed or served",
                &["kind"]
            )
            .unwrap()
        });
    pub(super) static AGGREGATE_DISSEMINATION_HEADERS_SENT: LazyLock<IntCounter> =
        LazyLock::new(|| {
            register_int_counter!(
                "lean_beacon_aggregate_dissemination_headers_sent_total",
                "Chunks sent with the aggregate's header"
            )
            .unwrap()
        });
    pub(super) static AGGREGATE_DISSEMINATION_ANNOUNCEMENTS_SENT: LazyLock<IntCounter> =
        LazyLock::new(|| {
            register_int_counter!(
                "lean_beacon_aggregate_dissemination_announcements_sent_total",
                "Metadata-only announcements queued for peers"
            )
            .unwrap()
        });
    pub(super) static AGGREGATE_DISSEMINATION_CHUNKS_REQUESTED: LazyLock<IntCounter> =
        LazyLock::new(|| {
            register_int_counter!(
                "lean_beacon_aggregate_dissemination_chunks_requested_total",
                "Proof chunks requested from peers"
            )
            .unwrap()
        });
    pub(super) static AGGREGATE_DISSEMINATION_CHUNK_REQUESTS_RETRIED: LazyLock<IntCounter> =
        LazyLock::new(|| {
            register_int_counter!(
                "lean_beacon_aggregate_dissemination_chunk_requests_retried_total",
                "Chunk requests made again after the previous one timed out"
            )
            .unwrap()
        });
    pub(super) static AGGREGATE_DISSEMINATION_SEND_ERRORS: LazyLock<IntCounterVec> =
        LazyLock::new(|| {
            register_int_counter_vec!(
                "lean_beacon_aggregate_dissemination_send_errors_total",
                "Messages that could not be queued for a peer, by kind",
                &["kind"]
            )
            .unwrap()
        });
    pub(super) static AGGREGATE_DISSEMINATION_BYTES_SENT: LazyLock<IntCounter> =
        LazyLock::new(|| {
            register_int_counter!(
                "lean_beacon_aggregate_dissemination_bytes_sent_total",
                "Bytes of Waggle messages queued for peers"
            )
            .unwrap()
        });
    pub(super) static AGGREGATE_DISSEMINATION_BYTES_RECEIVED: LazyLock<IntCounter> =
        LazyLock::new(|| {
            register_int_counter!(
                "lean_beacon_aggregate_dissemination_bytes_received_total",
                "Bytes of Waggle messages received from peers"
            )
            .unwrap()
        });

    pub(super) fn inc_counter(counter: &IntCounter) {
        counter.inc();
    }

    pub(super) fn inc_counter_by(counter: &IntCounter, by: u64) {
        counter.inc_by(by);
    }

    pub(super) fn inc_counter_vec(counter: &IntCounterVec, labels: &[&str]) {
        counter.with_label_values(labels).inc();
    }

    pub(super) fn observe_duration(histogram: &Histogram, duration: Duration) {
        histogram.observe(duration.as_secs_f64());
    }
}

/// The number of peers each valid chunk is pushed to, if as many peers aren't known to have the
/// chunk. The other peers learn about the chunk from our metadata, and may request it.
///
/// A peer need not have announced the aggregate: the first chunk a peer gets brings the header.
const PUSH_PEERS: usize = 2;

/// How long after the first chunk of an aggregate arrived we push its chunks on. Later ones are
/// only announced, and peers request them. An aggregate we publish is pushed whenever.
const PUSH_PHASE: Duration = Duration::from_millis(250);

/// How many times its share of our pushes of an aggregate a peer may get at most, where its share
/// is what it would get if the pushes were spread evenly over our peers, see
/// `max_pushes_per_peer`.
///
/// Without a limit, the `PUSH_PEERS` peers with the shortest send queues would get all the
/// chunks of an aggregate we have every chunk of, as when we publish it, and the others none.
const MAX_PUSH_SHARE: usize = 2;

/// How long to wait after we start tracking an aggregate before requesting the chunks we lack.
/// Chunks are still being pushed to us in the meantime, and requesting them would waste the
/// bandwidth of our peers.
const REQUEST_DELAY: Duration = Duration::from_millis(100);

/// How long to wait for a requested chunk before requesting it again, from another peer if one
/// announced it, not counting the time it takes to send the chunk, see
/// `REQUEST_TIMEOUT_PER_BYTE`.
const REQUEST_TIMEOUT: Duration = Duration::from_millis(500);

/// The time added to `REQUEST_TIMEOUT` for every byte of the chunks of an aggregate, see
/// `request_timeout`: a peer needs longer to send a long chunk than a short one.
const REQUEST_TIMEOUT_PER_BYTE: Duration = Duration::from_micros(16);

/// The longest we wait after a chunk becomes valid before we announce it, so that one
/// announcement covers several chunks.
const ANNOUNCE_INTERVAL: Duration = Duration::from_millis(50);

/// How long to wait before trying again to request chunks from a peer whose send queue was full,
/// so that the request could not be queued.
const REQUEST_RETRY_DELAY: Duration = Duration::from_millis(100);

/// The number of slots after its own that an aggregate is tracked for, i.e. disseminated.
///
/// A block includes attestations from at least `MIN_ATTESTATION_INCLUSION_DELAY_PQ` slots before
/// it, so the aggregates of a slot are first included that many slots later. Nodes that didn't
/// get an aggregate during its own slot can so still get it from us in time for that block.
const TRACKED_SLOTS_AFTER_OWN: u64 = MIN_ATTESTATION_INCLUSION_DELAY_PQ;

/// The maximum number of chunks of an aggregate requested from a peer at a time.
const MAX_REQUESTS_PER_PEER: usize = 1;

/// The maximum number of pieces of an aggregate kept while its header is being checked. They are
/// handled once it is. Further ones are dropped, like chunks that arrive without a header while
/// we hold none.
const MAX_PENDING_PIECES: usize = TOTAL_PROOF_CHUNKS;

/// How long we wait for the beacon processor to check a header before we give up on it, and
/// have the next one checked that arrived with a chunk.
///
/// The beacon processor drops work when its queues are full, and does not tell. Without a
/// limit, the aggregate would wait for the result forever, and no chunk of it would be kept.
const HEADER_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(2);

/// The fork digest of a topic.
pub(crate) type ForkDigest = [u8; 4];

/// The peers on the topic.
type TopicPeers = HashMap<PeerId, Peer>;

/// A message to the aggregate dissemination service of a topic.
#[derive(Debug)]
pub(crate) enum AggregateDisseminationMessage {
    /// A peer subscribed to the topic on the connection `connection_id`. Pieces queued on `sender`
    /// are sent to it.
    PeerSubscribed {
        peer_id: PeerId,
        connection_id: ConnectionId,
        sender: PieceSender,
    },
    /// An aggregate of a local aggregator, to publish. Sent once local
    /// aggregates are published over Waggle.
    #[allow(dead_code)]
    NewAggregate(NewAggregate),
    /// The beacon processor checked the header of the aggregate `id`, which `peer_id` sent.
    HeaderVerified {
        id: AggregateId,
        peer_id: PeerId,
        result: Result<Arc<CheckedHeader>, HeaderRejection>,
    },
    /// The beacon processor checked the aggregate `id`, complete with its proof.
    AggregateVerified {
        id: AggregateId,
        outcome: AggregateOutcome,
    },
}

/// An aggregate to disseminate: one of a local aggregator, which was checked completely.
#[derive(Debug)]
pub(crate) struct NewAggregate {
    pub header: Arc<CheckedHeader>,
    /// Every chunk of the proof, in order.
    pub chunks: Vec<Arc<ProofChunk>>,
}

/// Why a header did not pass the checks of the beacon processor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderRejection {
    /// The header failed a check, and its sender is penalized.
    Invalid,
    /// The header could not be checked, or is not to be considered. Its sender is not penalized.
    Ignored,
}

/// What became of an aggregate the beacon processor checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AggregateOutcome {
    /// The aggregate passed every check and was imported.
    Valid,
    /// The proof does not match the header, or the aggregate failed a check. Peers are not
    /// penalized for it: every chunk was committed to by the aggregator.
    Invalid,
    /// The aggregate was not judged: an aggregate seen before covers it, or
    /// there was no capacity to check it. Its chunks are still served.
    Ignored,
}

/// Disseminates the aggregates of one topic, i.e. of one fork digest, for as long as we are
/// subscribed to the topic.
pub(crate) struct AggregateDisseminationService<H: Host> {
    /// The fork digest of the topic.
    fork_digest: ForkDigest,
    message_recv: mpsc::Receiver<AggregateDisseminationMessage>,
    /// The events of the topic. Dropping the receiver unsubscribes from the topic.
    topic_events: async_channel::Receiver<TopicEvent>,
    /// Resolves once we are to unsubscribe from the topic.
    unsubscribe: oneshot::Receiver<()>,
    host: H,
    /// When to next clean up: once the tracking window moved on, see `clean_up`.
    next_clean_up: Instant,
    /// Whether a peer may have made chunks requestable since we last requested any, see
    /// `request_missing_chunks`.
    requests_pending: bool,
    /// The peers on the topic.
    peers: TopicPeers,
    /// The aggregates we track.
    aggregates: HashMap<AggregateId, Aggregate>,
    /// The header root of the aggregate whose header we hold, by slot and aggregator. We hold the
    /// header of at most one aggregate per slot and aggregator, the first valid one we received,
    /// and track no other aggregate of that slot and aggregator.
    held: HashMap<(Slot, u64), Root>,
}

/// A peer on the topic, as of its newest connection.
///
/// The two subscriptions with a peer, ours to it and its to us, are reported on different channels,
/// so their events are not ordered relative to each other: those of a previous connection can
/// arrive after those of the current one. The connection tells them apart. A peer has one
/// connection at a time, and libp2p assigns connection IDs from a counter, so the higher ID is the
/// newer connection. Events of a newer connection replace what we know about the peer, and events
/// of an older one are ignored, see `peer_on_connection`.
struct Peer {
    /// The newest connection of the peer we heard of, which the fields below are about.
    connection_id: ConnectionId,
    /// Queues pieces for the peer, if it is subscribed to us.
    sender: Option<PieceSender>,
    /// Whether our subscription stream to the peer is open.
    subscribed: bool,
}

impl Peer {
    fn new(connection_id: ConnectionId) -> Self {
        Self {
            connection_id,
            sender: None,
            subscribed: false,
        }
    }

    /// Whether either subscription is alive. The other one may still be established, or again:
    /// the peer can subscribe to us again on the same connection.
    fn keep(&self) -> bool {
        self.subscribed
            || self
                .sender
                .as_ref()
                .is_some_and(|sender| !sender.is_closed())
    }

    fn sender(&self) -> Option<&PieceSender> {
        // Ignore peers with a closed sender or if the subscription isn't mutual.
        if self.subscribed
            && let Some(sender) = self.sender.as_ref()
            && !sender.is_closed()
        {
            Some(sender)
        } else {
            None
        }
    }
}

/// Returns what we know about `peer_id` on the connection `connection_id`, to apply an event of
/// that connection to. Returns `None` if the event is stale, as the peer has a newer connection.
///
/// If the connection is newer than the one we know, what we know is replaced, which drops the
/// sender of the previous connection.
fn peer_on_connection(
    peers: &mut TopicPeers,
    peer_id: PeerId,
    connection_id: ConnectionId,
) -> Option<&mut Peer> {
    match peers.entry(peer_id) {
        Entry::Vacant(entry) => Some(entry.insert(Peer::new(connection_id))),
        Entry::Occupied(entry) => {
            let peer = entry.into_mut();
            match connection_id.cmp(&peer.connection_id) {
                Ordering::Greater => {
                    *peer = Peer::new(connection_id);
                    Some(peer)
                }
                Ordering::Equal => Some(peer),
                Ordering::Less => None,
            }
        }
    }
}

/// Removes `peer_id`, as our subscription stream to it on the connection `connection_id` ended,
/// unless the peer has a newer connection.
///
/// Waggle does not subscribe again on the same connection, so the peer is of no use until it
/// connects again. Removing it drops its sender, which ends its subscription to us too.
fn remove_peer_on_connection(peers: &mut TopicPeers, peer_id: PeerId, connection_id: ConnectionId) {
    if peers
        .get(&peer_id)
        .is_some_and(|peer| peer.connection_id == connection_id)
    {
        peers.remove(&peer_id);
    }
}

/// An aggregate we track.
struct Aggregate {
    id: AggregateId,
    /// The ID as the object ID of our messages about the aggregate, which share it.
    object_id: Bytes,
    /// Our metadata without requests, encoded, for what we have: the messages that announce the
    /// same to several peers share it.
    announcement: Option<(ChunkSet, Bytes)>,
    header: HeaderState,
    /// The chunks of the proof. Only valid while we hold the header they were verified against.
    chunks: Vec<Chunk>,
    /// When we started to track the aggregate, see `REQUEST_DELAY`.
    tracked_since: Instant,
    peers: HashMap<PeerId, AggregatePeer>,
    /// Whether the application has the complete aggregate, either because it gave it to us or
    /// because we handed it over after collecting every chunk.
    complete: bool,
    /// Whether the aggregate was found invalid once it was complete. Its chunks are then neither
    /// pushed, announced, requested nor served anymore.
    invalid: bool,
    /// Whether the aggregate passed every check.
    valid: bool,
    /// Whether we hold a valid aggregate with the same attestation data and committee whose
    /// attesters include all of the attesters of this one, which would be ignored if we
    /// completed it. Its chunks are not requested anymore. The ones we hold are still served.
    covered: bool,
    /// Whether we have news for our peers, see
    /// `AggregateDisseminationService::flush_announcements`.
    announcement_pending: bool,
    /// When we last announced what we have to all peers, see `ANNOUNCE_INTERVAL`.
    last_announced: Option<Instant>,
    /// When the first chunk a peer sent us became valid, see `PUSH_PHASE`.
    first_chunk_at: Option<Instant>,
    /// When to try again to request chunks, if a request could not be queued for its peer, see
    /// `REQUEST_RETRY_DELAY`.
    request_retry_at: Option<Instant>,
}

/// What we have of the header of an aggregate.
enum HeaderState {
    /// None. Chunks that arrive without one are dropped, as they can't be verified.
    Unknown,
    /// A header that arrived with a valid chunk is being checked by the beacon processor.
    Verifying {
        /// The peer that sent the header.
        from: PeerId,
        /// When the header was sent to the beacon processor, see `HEADER_VERIFICATION_TIMEOUT`.
        since: Instant,
        /// The header, to verify the chunks that wait against once it passed.
        signed_header: Arc<SignedAggregateHeader>,
        /// The pieces that wait for the header to be checked, in the order they arrived, at most
        /// `MAX_PENDING_PIECES`. The first one is the piece the header arrived with.
        pending: Vec<PendingPiece>,
    },
    /// A header that passed the checks. The chunks we hold are verified against it.
    Held(HeldHeader),
}

/// A piece that waits for the header of its aggregate to be checked.
struct PendingPiece {
    peer_id: PeerId,
    /// The header the piece carried, if any, which is checked instead if the one being checked
    /// fails.
    signed_header: Option<Arc<SignedAggregateHeader>>,
    chunk: Arc<ProofChunk>,
}

struct HeldHeader {
    verified: Arc<CheckedHeader>,
    /// The header as we send it along with a chunk.
    signed_header: Arc<SignedAggregateHeader>,
}

/// A chunk of the proof of an aggregate. We only keep valid chunks, as each chunk is validated
/// on receipt.
#[derive(Clone)]
enum Chunk {
    Unknown {
        /// The peer we last requested the chunk from, and when.
        requested: Option<(PeerId, Instant)>,
    },
    Valid {
        chunk: Arc<ProofChunk>,
        /// The chunk as we send it without the header, encoded with `encode_piece`, once we sent
        /// it. Kept, as we send each chunk to several peers, whose messages share it: cloning it
        /// does not copy it.
        ///
        /// This is always our own encoding, also of the chunks we received: a peer may compress a
        /// chunk badly on purpose, and forwarding its bytes would pass them on to our peers.
        encoded: Option<Bytes>,
        /// The chunk as we send it with the header.
        encoded_with_header: Option<Bytes>,
        /// The number of peers we pushed the chunk to, see `PUSH_PEERS`.
        pushes: usize,
    },
}

impl Chunk {
    /// Returns a chunk we don't have and did not request yet.
    fn unknown() -> Self {
        Chunk::Unknown { requested: None }
    }

    /// Returns the valid `chunk`, which was not sent to any peer yet.
    fn valid(chunk: Arc<ProofChunk>) -> Self {
        Chunk::Valid {
            chunk,
            encoded: None,
            encoded_with_header: None,
            pushes: 0,
        }
    }
}

/// What we know about a peer regarding an aggregate.
#[derive(Default)]
struct AggregatePeer {
    /// The chunks the peer last told us it has, if it told us anything yet.
    has: Option<ChunkSet>,
    sent_to: ChunkSet,
    received_from: ChunkSet,
    /// The chunks we last told the peer we have, if we told it anything yet.
    announced: Option<ChunkSet>,
    /// The number of chunks we pushed to the peer, i.e. sent without it requesting them, which is
    /// limited, see `max_pushes_per_peer`.
    pushes: usize,
    banned: bool,
    /// Whether the peer is known to hold the header: it announced a `have` that is not empty,
    /// sent us a valid chunk, or we sent it the header. A chunk we send it carries the header
    /// unless it is.
    knows_header: bool,
}

impl AggregatePeer {
    /// Whether the peer is known to have the chunk at `index`: it told us it has it, we sent it
    /// the chunk, or it sent us the chunk.
    fn knows(&self, index: usize) -> bool {
        self.has
            .iter()
            .chain([&self.sent_to, &self.received_from])
            .any(|bitmap| bitmap.get(index).unwrap_or(true))
    }

    /// Returns the chunks the peer is known to have, see `knows`.
    fn known_chunks(&self) -> ChunkSet {
        let known = self.sent_to.union(&self.received_from);
        match &self.has {
            Some(has) => known.union(has),
            None => known,
        }
    }

    /// Whether the peer sent us the chunk at `index`, or the index is out of bounds.
    fn sent_us(&self, index: usize) -> bool {
        self.received_from.get(index).unwrap_or(true)
    }
}

/// A peer to push chunks of an aggregate to, see `Aggregate::push_chunks`.
struct PushCandidate<'a> {
    peer_id: PeerId,
    sender: &'a PieceSender,
    /// The length of the send queue of the peer when we looked, plus what we queued since. Kept
    /// here, as reading it from the queue for every chunk and candidate is slow.
    queued: usize,
    /// The number of chunks we may still push to the peer, see `max_pushes_per_peer`.
    remaining_pushes: usize,
    /// The chunks not to push to the peer: the ones it is known to have, and the ones we tried to
    /// push to it since.
    skip: ChunkSet,
}

/// A peer that may be asked for chunks of an aggregate, see `Aggregate::request_missing_chunks`.
///
/// What is looked at for every missing chunk and candidate is kept here, as looking it up by
/// peer ID each time is slow.
struct RequestCandidate<'a> {
    peer_id: PeerId,
    sender: &'a PieceSender,
    /// The chunks the peer told us it has.
    has: ChunkSet,
    /// The number of requests outstanding with the peer, including the ones of `request`.
    outstanding: usize,
    /// The chunks to request from the peer now.
    request: ChunkSet,
}

impl RequestCandidate<'_> {
    /// Whether the peer told us that it has the chunk at `index`.
    fn has_chunk(&self, index: usize) -> bool {
        self.has.get(index).unwrap_or(false)
    }
}

/// Whether to track an aggregate we received a message about, see
/// `AggregateDisseminationService::check_aggregate_id`.
#[derive(Debug, PartialEq, Eq)]
enum IdCheck {
    Track,
    /// The message is dropped.
    Ignore,
}

impl<H: Host> AggregateDisseminationService<H> {
    /// Spawns the service of the topic of `fork_digest`, which we subscribed to.
    ///
    /// The events of the topic arrive on `topic_events`. The service runs until `unsubscribe`
    /// resolves, and unsubscribes from the topic as it ends. `subscribed_peers` are the peers
    /// that subscribed to the topic before us, with the connections they did so on.
    pub(crate) fn spawn(
        fork_digest: ForkDigest,
        message_recv: mpsc::Receiver<AggregateDisseminationMessage>,
        topic_events: async_channel::Receiver<TopicEvent>,
        unsubscribe: oneshot::Receiver<()>,
        subscribed_peers: HashMap<PeerId, (ConnectionId, PieceSender)>,
        host: H,
    ) {
        let service = Self::new(fork_digest, message_recv, topic_events, unsubscribe, host);
        let mut service = service;
        for (peer_id, (connection_id, sender)) in subscribed_peers {
            let peer = Peer {
                sender: Some(sender),
                ..Peer::new(connection_id)
            };
            service.peers.insert(peer_id, peer);
        }
        tokio::spawn(service.start());
    }

    fn new(
        fork_digest: ForkDigest,
        message_recv: mpsc::Receiver<AggregateDisseminationMessage>,
        topic_events: async_channel::Receiver<TopicEvent>,
        unsubscribe: oneshot::Receiver<()>,
        host: H,
    ) -> Self {
        AggregateDisseminationService {
            fork_digest,
            message_recv,
            topic_events,
            unsubscribe,
            host,
            // Due right away, which sets the time of the next one.
            next_clean_up: Instant::now(),
            requests_pending: false,
            peers: HashMap::new(),
            aggregates: HashMap::new(),
            held: HashMap::new(),
        }
    }

    async fn start(mut self) {
        let fork_digest = hex::encode(self.fork_digest);
        debug!(fork_digest, "Aggregate dissemination service starting");

        loop {
            // Yield to the runtime once the budget of the task is used up. Otherwise the task
            // would keep its worker for as long as there are events: taking them uses none of
            // the budget, as `topic_events` is no Tokio channel.
            consume_budget().await;

            let wake_at = self.next_wake(Instant::now());
            let result = select! {
                // Biased, so that chunks are only requested and announcements only made once
                // there is nothing else to do.
                biased;
                // Also resolves if the sender is dropped, which is how we are told to unsubscribe.
                _ = &mut self.unsubscribe => break,
                message = self.message_recv.recv() => {
                    let Some(message) = message else {
                        // Shutting down.
                        break;
                    };
                    self.handle_application_message(message)
                },
                topic_event = self.topic_events.recv() => {
                    let Ok(topic_event) = topic_event else {
                        // Shutting down.
                        break;
                    };
                    self.handle_waggle_event(topic_event)
                },
                _ = sleep_until(wake_at) => {
                    self.on_wake();
                    Ok(())
                }
                _ = std::future::ready(()),
                    if self.requests_pending || self.announcements_pending() =>
                {
                    // Requests first: they carry our metadata, which saves announcing it to the
                    // peers we request from.
                    if std::mem::take(&mut self.requests_pending) {
                        self.request_missing_chunks();
                    }
                    self.flush_announcements();
                    Ok(())
                }
            };

            if let Err(err) = result {
                error!(%err, "Error in aggregate dissemination");
            }
        }
        // Dropping `self.topic_events` unsubscribes from the topic.
        debug!(fork_digest, "Aggregate dissemination service shutting down");
    }

    /// Returns when there is next something to do that no message or event makes us do, see
    /// `on_wake`: clean up, request chunks, or announce news that is held back.
    ///
    /// Of what is due already, only what `on_wake` gets done counts. The service would wake up
    /// for anything else over and over.
    fn next_wake(&self, now: Instant) -> Instant {
        self.aggregates
            .values()
            .filter_map(|aggregate| aggregate.next_wake(now))
            .fold(self.next_clean_up, Instant::min)
    }

    /// Does what is due, see `next_wake`. News that is no longer held back is announced by
    /// `flush_announcements`, once there is nothing else to do.
    fn on_wake(&mut self) {
        let now = Instant::now();
        if now >= self.next_clean_up {
            self.clean_up();
            let wait = self.host.time_to_next_tracking_window();
            self.next_clean_up = now.checked_add(wait).unwrap_or(now);
        }
        self.give_up_on_unchecked_headers(now);
        self.request_missing_chunks();
    }

    /// Gives up on the headers that the beacon processor did not check within
    /// `HEADER_VERIFICATION_TIMEOUT`, as if they could not be checked: their senders are not
    /// penalized, and the next header that arrived with a chunk is checked instead.
    fn give_up_on_unchecked_headers(&mut self, now: Instant) {
        let unchecked = self
            .aggregates
            .iter()
            .filter_map(|(id, aggregate)| match &aggregate.header {
                HeaderState::Verifying { from, since, .. }
                    if now.saturating_duration_since(*since) >= HEADER_VERIFICATION_TIMEOUT =>
                {
                    Some((*id, *from))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        for (id, from) in unchecked {
            debug!(
                slot = %id.slot,
                aggregator_index = id.aggregator_index,
                "Header of aggregate was not checked in time"
            );
            self.on_header_verified(id, from, Err(HeaderRejection::Ignored));
        }
    }

    fn handle_application_message(
        &mut self,
        message: AggregateDisseminationMessage,
    ) -> Result<(), Error> {
        match message {
            AggregateDisseminationMessage::PeerSubscribed {
                peer_id,
                connection_id,
                sender,
            } => {
                // If the subscription is of a previous connection, dropping `sender` ends it.
                if let Some(peer) = peer_on_connection(&mut self.peers, peer_id, connection_id) {
                    peer.sender = Some(sender);
                    self.try_inform_new_peer(peer_id);
                }
                Ok(())
            }
            AggregateDisseminationMessage::NewAggregate(new_aggregate) => {
                self.publish(new_aggregate)
            }
            AggregateDisseminationMessage::HeaderVerified {
                id,
                peer_id,
                result,
            } => {
                self.on_header_verified(id, peer_id, result);
                Ok(())
            }
            AggregateDisseminationMessage::AggregateVerified { id, outcome } => {
                self.on_aggregate_verified(id, outcome);
                Ok(())
            }
        }
    }

    /// Tracks an aggregate of a local aggregator with its header and all chunks valid, and
    /// disseminates the chunks.
    fn publish(&mut self, new_aggregate: NewAggregate) -> Result<(), Error> {
        let NewAggregate { header, chunks } = new_aggregate;
        let id = id_of(&header);
        // We only track aggregates during their tracking window.
        if !self.is_tracked_slot(id.slot) {
            return Ok(());
        }
        let signed_header = Arc::new(header.signed_header.clone());
        if chunks.len() != TOTAL_PROOF_CHUNKS {
            return Err(Error::UnexpectedPiecesLen(chunks.len()));
        }
        if chunks
            .iter()
            .enumerate()
            .any(|(index, chunk)| chunk.index as usize != index)
        {
            return Err(Error::ChunkIndexMismatch);
        }
        // We hold the header of one aggregate per slot and aggregator, the first one.
        if self
            .held
            .get(&(id.slot, id.aggregator_index))
            .is_some_and(|header_root| *header_root != id.header_root)
        {
            warn!(
                slot = %id.slot,
                aggregator_index = id.aggregator_index,
                "Not publishing aggregate, as we hold another one of its aggregator"
            );
            return Ok(());
        }

        let aggregate = self.aggregates.entry(id).or_insert_with(|| {
            metrics::inc_counter(&metrics::AGGREGATE_DISSEMINATION_AGGREGATES_TRACKED);
            Aggregate::new(id)
        });
        // Pieces that wait for a header to be checked are dropped: we have every chunk.
        aggregate.header = HeaderState::Held(HeldHeader {
            verified: header,
            signed_header,
        });
        let mut new_chunks = vec![];
        for (index, (chunk, new_chunk)) in aggregate.chunks.iter_mut().zip(chunks).enumerate() {
            if let Chunk::Valid { .. } = chunk {
                // We already have this chunk, nothing to do.
                continue;
            }
            *chunk = Chunk::valid(new_chunk);
            new_chunks.push(index);
        }
        // No need to hand the complete aggregate to the application, we got it from there, and
        // it checked the aggregate before.
        aggregate.valid = true;
        if !aggregate.complete {
            aggregate.complete = true;
            metrics::inc_counter_vec(
                &metrics::AGGREGATE_DISSEMINATION_AGGREGATES_COMPLETED,
                &["published"],
            );
        }
        aggregate.push_chunks(new_chunks, &self.peers);
        // Tell our peers what we have right away, so that they request what we don't push.
        aggregate.announce(&self.peers);

        self.on_header_held(id);
        self.mark_covered_by(id);
        Ok(())
    }

    fn handle_waggle_event(&mut self, event: TopicEvent) -> Result<(), Error> {
        match event {
            TopicEvent::Opened {
                peer_id,
                connection_id,
            } => {
                if let Some(peer) = peer_on_connection(&mut self.peers, peer_id, connection_id) {
                    peer.subscribed = true;
                    self.try_inform_new_peer(peer_id);
                }
            }
            TopicEvent::Pieces {
                peer_id,
                connection_id,
                pieces,
            } => {
                let received_bytes = [&pieces.metadata, &pieces.pieces]
                    .into_iter()
                    .flatten()
                    .fold(0usize, |bytes, data| bytes.saturating_add(data.len()));
                metrics::inc_counter_by(
                    &metrics::AGGREGATE_DISSEMINATION_BYTES_RECEIVED,
                    received_bytes as u64,
                );
                if self
                    .peers
                    .get(&peer_id)
                    .is_some_and(|peer| peer.connection_id > connection_id)
                {
                    // Sent on a previous connection of the peer, and delivered late. The peer
                    // starts over on its new connection, so this is no longer of use.
                    debug!(%peer_id, "Ignoring waggle message of a previous connection");
                    return Ok(());
                }
                let message = match Message::try_from(pieces) {
                    Ok(message) => message,
                    Err(err) => {
                        // The peer sent garbage, this is not an error on our side.
                        debug!(%err, %peer_id, "Malformed waggle message");
                        self.penalize_peer(
                            peer_id,
                            None,
                            Penalty::LowTolerance,
                            "waggle_malformed_message",
                        );
                        return Ok(());
                    }
                };
                // Whatever the peer tells us may make chunks requestable: it has more chunks, or
                // sent one we requested, so that it can be asked for another.
                self.requests_pending = true;
                self.handle_message(peer_id, message)?;
            }
            TopicEvent::Closed {
                peer_id,
                connection_id,
            } => {
                remove_peer_on_connection(&mut self.peers, peer_id, connection_id);
            }
        }
        Ok(())
    }

    /// Whether to start tracking the aggregate `id`, which a peer sent a message about and we
    /// don't track.
    ///
    /// Its slot and aggregator let us drop messages about aggregates that no eligible aggregator
    /// can have signed, before we hold a header. The header root can't be checked yet.
    ///
    /// The sender of an aggregate of an aggregator that is not eligible is not penalized, unlike
    /// the EIP's _[REJECT]_: the aggregation committees of an epoch depend on the RANDAO mix of
    /// two epochs before, so peers on another fork can see other aggregators, and announce their
    /// aggregates honestly. Penalizing them split a devnet whose forks crossed epoch boundaries.
    fn check_aggregate_id(&self, id: &AggregateId) -> IdCheck {
        // Not from a future slot, and the tracking window has not ended.
        if !self.is_tracked_slot(id.slot) {
            return IdCheck::Ignore;
        }
        // On the topic of the fork digest of the epoch of its slot.
        if self.host.fork_digest_at(id.slot) != self.fork_digest {
            return IdCheck::Ignore;
        }
        // The aggregator is in the aggregation committee of one of the committees of the slot.
        match self.host.aggregators_at(id.slot) {
            Some(aggregators) if aggregators.contains(&id.aggregator_index) => {}
            Some(_) => {
                debug!(
                    slot = %id.slot,
                    aggregator_index = id.aggregator_index,
                    "Ignoring aggregate of an aggregator not eligible at its slot"
                );
                return IdCheck::Ignore;
            }
            None => {
                // The head state doesn't cover the slot, as when we are syncing.
                debug!(slot = %id.slot, "Unable to tell the aggregators of slot");
                return IdCheck::Ignore;
            }
        }
        // We don't hold the header of another aggregate with the same slot and aggregator.
        if self.held.contains_key(&(id.slot, id.aggregator_index)) {
            return IdCheck::Ignore;
        }
        IdCheck::Track
    }

    fn handle_message(&mut self, peer_id: PeerId, message: Message) -> Result<(), Error> {
        let Message {
            id,
            metadata,
            piece,
        } = message;

        if !self.aggregates.contains_key(&id) {
            match self.check_aggregate_id(&id) {
                IdCheck::Track => {}
                IdCheck::Ignore => {
                    if piece.is_some() {
                        count_received_chunk("untracked");
                    }
                    return Ok(());
                }
            }
            metrics::inc_counter(&metrics::AGGREGATE_DISSEMINATION_AGGREGATES_TRACKED);
            self.aggregates.insert(id, Aggregate::new(id));
        }
        self.bound_headerless_aggregates(peer_id, id);

        let Some(aggregate) = self.aggregates.get_mut(&id) else {
            return Ok(());
        };
        if aggregate.peers.entry(peer_id).or_default().banned {
            debug!(%peer_id, "Message from banned peer");
            if piece.is_some() {
                count_received_chunk("ignored");
            }
            return Ok(());
        }

        let carried_chunk = piece.is_some();
        if let Some(piece) = piece
            && !self.handle_piece(peer_id, id, piece)
        {
            // The message is dropped, and nothing from it is used.
            return Ok(());
        }

        if let Some(metadata) = metadata {
            self.handle_metadata(peer_id, id, metadata, carried_chunk);
        }
        Ok(())
    }

    /// Keeps what we remember about aggregates whose header we don't hold bounded: of the
    /// aggregates with the slot and aggregator of `id`, `peer_id` only counts as a peer of the
    /// one it sent a message about last, which is `id`. Aggregates without a header that no
    /// peer is left of are not tracked anymore.
    ///
    /// Until we hold a header, peers can announce several aggregates of a slot and aggregator,
    /// of which an honest aggregator signed at most one, and we can't tell which.
    fn bound_headerless_aggregates(&mut self, peer_id: PeerId, id: AggregateId) {
        if self.held.contains_key(&(id.slot, id.aggregator_index)) {
            // We track no other aggregate of this slot and aggregator.
            return;
        }
        self.aggregates.retain(|other_id, other| {
            if *other_id == id
                || other_id.slot != id.slot
                || other_id.aggregator_index != id.aggregator_index
                || other.peers.remove(&peer_id).is_none()
            {
                return true;
            }
            other.forget_requests_to(peer_id);
            // An aggregate whose header is being checked is kept: the result refers to it.
            !other.peers.is_empty() || !matches!(other.header, HeaderState::Unknown)
        });
    }

    /// Handles the piece `peer_id` sent of the aggregate `id`, which we track. Returns whether
    /// the rest of the message is to be handled, i.e. whether the message is not dropped.
    fn handle_piece(&mut self, peer_id: PeerId, id: AggregateId, piece: AggregatePiece) -> bool {
        let AggregatePiece {
            signed_header,
            chunk,
        } = piece;
        let chunk = Arc::new(chunk);
        let index = chunk.index as usize;
        let signed_header = signed_header.into_iter().next().map(Arc::new);
        let Some(aggregate) = self.aggregates.get_mut(&id) else {
            return false;
        };

        // The index bound is load-bearing: the inclusion proof only covers its low bits.
        if index >= TOTAL_PROOF_CHUNKS {
            count_received_chunk("invalid");
            self.penalize_peer(
                peer_id,
                Some(id),
                Penalty::LowTolerance,
                "waggle_chunk_index_out_of_bounds",
            );
            return false;
        }

        match &mut aggregate.header {
            HeaderState::Held(_) => self.handle_chunk(peer_id, id, chunk, false),
            HeaderState::Unknown => {
                let Some(signed_header) = signed_header else {
                    // We can't verify the chunk without the header, and the peer isn't at fault:
                    // it had reason to believe that we hold it. We get the header with the first
                    // chunk of another peer.
                    count_received_chunk("no_header");
                    return false;
                };
                if aggregate.peers.entry(peer_id).or_default().sent_us(index) {
                    count_received_chunk("repeated");
                    self.penalize_peer(
                        peer_id,
                        Some(id),
                        Penalty::MidTolerance,
                        "waggle_duplicate_chunk",
                    );
                    return false;
                }
                if !header_matches_id(&signed_header, &id) {
                    metrics::inc_counter_vec(
                        &metrics::AGGREGATE_DISSEMINATION_HEADERS,
                        &["mismatch"],
                    );
                    self.penalize_peer(
                        peer_id,
                        Some(id),
                        Penalty::LowTolerance,
                        "waggle_header_mismatch",
                    );
                    return false;
                }
                // A header is only kept if the chunk it arrived with is valid, so check the
                // chunk first: it is cheap, unlike the signature of the header.
                if !chunk.verify_inclusion_proof(signed_header.message.proof_chunks_root) {
                    count_received_chunk("invalid");
                    self.penalize_peer(
                        peer_id,
                        Some(id),
                        Penalty::LowTolerance,
                        "waggle_invalid_chunk",
                    );
                    return false;
                }
                if let Err(error) = self.host.check_header(id, peer_id, signed_header.clone()) {
                    warn!(%error, "Unable to have an aggregate header checked");
                    count_received_chunk("ignored");
                    return false;
                }
                if aggregate.first_chunk_at.is_none() {
                    debug!(
                        slot = id.slot,
                        aggregator_index = id.aggregator_index,
                        %peer_id,
                        "First piece of an aggregate"
                    );
                }
                let aggregate_peer = aggregate.peers.entry(peer_id).or_default();
                let _ = aggregate_peer.received_from.set(index, true);
                aggregate.header = HeaderState::Verifying {
                    from: peer_id,
                    since: Instant::now(),
                    signed_header: signed_header.clone(),
                    pending: vec![PendingPiece {
                        peer_id,
                        signed_header: Some(signed_header),
                        chunk,
                    }],
                };
                true
            }
            HeaderState::Verifying { pending, .. } => {
                let aggregate_peer = aggregate.peers.entry(peer_id).or_default();
                if aggregate_peer.sent_us(index) {
                    count_received_chunk("repeated");
                    self.penalize_peer(
                        peer_id,
                        Some(id),
                        Penalty::MidTolerance,
                        "waggle_duplicate_chunk",
                    );
                    return false;
                }
                if let Some(signed_header) = &signed_header
                    && !header_matches_id(signed_header, &id)
                {
                    metrics::inc_counter_vec(
                        &metrics::AGGREGATE_DISSEMINATION_HEADERS,
                        &["mismatch"],
                    );
                    self.penalize_peer(
                        peer_id,
                        Some(id),
                        Penalty::LowTolerance,
                        "waggle_header_mismatch",
                    );
                    return false;
                }
                if pending.len() >= MAX_PENDING_PIECES {
                    count_received_chunk("ignored");
                    return false;
                }
                let _ = aggregate_peer.received_from.set(index, true);
                pending.push(PendingPiece {
                    peer_id,
                    signed_header,
                    chunk,
                });
                true
            }
        }
    }

    /// Handles the chunk `peer_id` sent of the aggregate `id`, whose header we hold. Returns
    /// whether the chunk is valid.
    ///
    /// `noted` is whether the chunk was noted as received from the peer already, as it waited
    /// for the header to be checked.
    fn handle_chunk(
        &mut self,
        peer_id: PeerId,
        id: AggregateId,
        chunk: Arc<ProofChunk>,
        noted: bool,
    ) -> bool {
        let index = chunk.index as usize;
        let Some(aggregate) = self.aggregates.get_mut(&id) else {
            return false;
        };
        let HeaderState::Held(header) = &aggregate.header else {
            return false;
        };
        let proof_chunks_root = header.verified.proof_chunks_root();
        let aggregate_peer = aggregate.peers.entry(peer_id).or_default();
        if aggregate_peer.banned {
            count_received_chunk("ignored");
            return false;
        }
        if !noted {
            if aggregate_peer.sent_us(index) {
                // This peer sent this chunk already.
                count_received_chunk("repeated");
                self.penalize_peer(
                    peer_id,
                    Some(id),
                    Penalty::MidTolerance,
                    "waggle_duplicate_chunk",
                );
                return false;
            }
            let _ = aggregate_peer.received_from.set(index, true);
        }
        let Some(local_chunk) = aggregate.chunks.get_mut(index) else {
            // The caller checked the index.
            return false;
        };

        let valid = match local_chunk {
            Chunk::Valid { chunk: local, .. } => **local == *chunk,
            // The index is in bounds, as `verify_inclusion_proof` requires.
            Chunk::Unknown { .. } => chunk.verify_inclusion_proof(proof_chunks_root),
        };
        if !valid {
            count_received_chunk("invalid");
            self.penalize_peer(
                peer_id,
                Some(id),
                Penalty::LowTolerance,
                "waggle_invalid_chunk",
            );
            return false;
        }
        // A peer that holds a chunk verified it against the header.
        aggregate_peer.knows_header = true;

        if let Chunk::Unknown { .. } = local_chunk {
            count_received_chunk("valid");
            *local_chunk = Chunk::valid(chunk);
            aggregate.on_chunk_valid(index, peer_id, &self.peers, &self.host);
        } else {
            count_received_chunk("duplicate");
        }
        true
    }

    /// Handles the metadata `peer_id` sent about the aggregate `id`, which we track.
    fn handle_metadata(
        &mut self,
        peer_id: PeerId,
        id: AggregateId,
        metadata: Metadata,
        carried_chunk: bool,
    ) {
        let Some(aggregate) = self.aggregates.get_mut(&id) else {
            return;
        };
        let aggregate_peer = aggregate.peers.entry(peer_id).or_default();
        if aggregate_peer.banned {
            return;
        }
        if let Some(has) = &aggregate_peer.has
            && !has.difference(&metadata.have).is_zero()
        {
            // The peer no longer has a chunk it announced.
            self.penalize_peer(
                peer_id,
                Some(id),
                Penalty::MidTolerance,
                "waggle_lost_chunk",
            );
            return;
        }
        aggregate_peer.has = Some(metadata.have);
        if !metadata.have.is_zero() {
            // A peer that holds a chunk verified it against the header.
            aggregate_peer.knows_header = true;
        }

        // Serve the requests right away.
        let mut send = Vec::new();
        for ((((requested, has), sent_to), received_from), chunk) in metadata
            .request
            .iter()
            .zip(metadata.have.iter())
            .zip(aggregate_peer.sent_to.iter())
            .zip(aggregate_peer.received_from.iter())
            .zip(aggregate.chunks.iter())
        {
            if requested {
                if has || received_from {
                    // The peer requests a chunk it has.
                    self.penalize_peer(
                        peer_id,
                        Some(id),
                        Penalty::MidTolerance,
                        "waggle_request_for_held_chunk",
                    );
                    return;
                }
                // We never send a peer a chunk twice.
                if let Chunk::Valid { chunk, .. } = chunk
                    && !sent_to
                {
                    send.push(chunk.index as usize);
                }
            }
        }

        // The chunks of an invalid aggregate are not served.
        if aggregate.invalid {
            return;
        }
        if !send.is_empty()
            && let Some(sender) = self.peers.get(&peer_id).and_then(Peer::sender)
        {
            let have = aggregate.have();
            for index in send {
                if !aggregate.send_chunk(index, peer_id, sender, &have) {
                    break;
                }
                metrics::inc_counter_vec(
                    &metrics::AGGREGATE_DISSEMINATION_CHUNKS_SENT,
                    &["served"],
                );
            }
        }

        // Tell the peer what we have if it doesn't know yet.
        if carried_chunk {
            // The peer is pushing chunks, each with its new metadata. Answering each of them
            // would defeat coalescing our announcements, so leave it to the next flush.
            aggregate.announcement_pending = true;
        } else if let Some(sender) = self.peers.get(&peer_id).and_then(Peer::sender) {
            let have = aggregate.have();
            aggregate.announce_to(peer_id, sender, &have);
        }
    }

    /// Handles the result of the checks of the header of the aggregate `id`, which `peer_id`
    /// sent.
    fn on_header_verified(
        &mut self,
        id: AggregateId,
        peer_id: PeerId,
        result: Result<Arc<CheckedHeader>, HeaderRejection>,
    ) {
        let Some(aggregate) = self.aggregates.get_mut(&id) else {
            // We stopped tracking the aggregate in the meantime.
            return;
        };
        let HeaderState::Verifying { from, .. } = &aggregate.header else {
            // We got the header otherwise in the meantime, as when we published the aggregate.
            return;
        };
        if *from != peer_id {
            // The result of a header we gave up on.
            return;
        }
        let HeaderState::Verifying {
            signed_header,
            mut pending,
            ..
        } = std::mem::replace(&mut aggregate.header, HeaderState::Unknown)
        else {
            return;
        };

        match result {
            Ok(verified) => {
                if self
                    .held
                    .get(&(id.slot, id.aggregator_index))
                    .is_some_and(|header_root| *header_root != id.header_root)
                {
                    // We hold the header of another aggregate of this slot and aggregator by now.
                    self.aggregates.remove(&id);
                    return;
                }
                metrics::inc_counter_vec(&metrics::AGGREGATE_DISSEMINATION_HEADERS, &["valid"]);
                aggregate.header = HeaderState::Held(HeldHeader {
                    verified,
                    signed_header,
                });
                // The peers whose chunks waited hold the header: they sent it, or sent a chunk
                // without it as they took us to hold it. So the chunks pushed on below don't
                // bring it to them again. A peer whose chunk turns out invalid is ignored anyway.
                for piece in &pending {
                    aggregate
                        .peers
                        .entry(piece.peer_id)
                        .or_default()
                        .knows_header = true;
                }
                self.on_header_held(id);
                // The chunks that waited for the header, which are verified against it now.
                for piece in pending {
                    self.handle_chunk(piece.peer_id, id, piece.chunk, true);
                }
                self.mark_covered(id);
                self.requests_pending = true;
            }
            Err(rejection) => {
                let result = match rejection {
                    HeaderRejection::Invalid => "invalid",
                    HeaderRejection::Ignored => "ignored",
                };
                metrics::inc_counter_vec(&metrics::AGGREGATE_DISSEMINATION_HEADERS, &[result]);
                // The pieces of the peer are dropped with its header.
                pending.retain(|piece| piece.peer_id != peer_id);
                if let Some(aggregate_peer) = aggregate.peers.get_mut(&peer_id) {
                    // It did not send us chunks we could use.
                    aggregate_peer.received_from = ChunkSet::new();
                }
                if rejection == HeaderRejection::Invalid {
                    self.penalize_peer(
                        peer_id,
                        Some(id),
                        Penalty::LowTolerance,
                        "waggle_invalid_header",
                    );
                }
                self.verify_next_pending_header(id, pending);
            }
        }
    }

    /// Has the next header among `pending` checked, the pieces that waited for a header of the
    /// aggregate `id` that did not pass. If none of them carries a header, they are dropped, as
    /// chunks that arrive without a header while we hold none are.
    fn verify_next_pending_header(&mut self, id: AggregateId, mut pending: Vec<PendingPiece>) {
        loop {
            let Some(aggregate) = self.aggregates.get_mut(&id) else {
                return;
            };
            let Some(position) = pending.iter().position(|piece| {
                piece.signed_header.is_some()
                    && !aggregate
                        .peers
                        .get(&piece.peer_id)
                        .is_some_and(|aggregate_peer| aggregate_peer.banned)
            }) else {
                // No header left. The peers whose pieces are dropped did not send us chunks we
                // could use.
                for piece in pending {
                    count_received_chunk("no_header");
                    if let Some(aggregate_peer) = aggregate.peers.get_mut(&piece.peer_id) {
                        let _ = aggregate_peer
                            .received_from
                            .set(piece.chunk.index as usize, false);
                    }
                }
                return;
            };
            let Some(piece) = pending.get(position) else {
                return;
            };
            let (from, chunk) = (piece.peer_id, piece.chunk.clone());
            let Some(signed_header) = piece.signed_header.clone() else {
                return;
            };

            // As for the first header: it is only checked if the chunk it arrived with is valid.
            if !chunk.verify_inclusion_proof(signed_header.message.proof_chunks_root) {
                count_received_chunk("invalid");
                pending.retain(|piece| piece.peer_id != from);
                self.penalize_peer(
                    from,
                    Some(id),
                    Penalty::LowTolerance,
                    "waggle_invalid_chunk",
                );
                continue;
            }
            if let Err(error) = self.host.check_header(id, from, signed_header.clone()) {
                warn!(%error, "Unable to have an aggregate header checked");
                for piece in pending {
                    count_received_chunk("ignored");
                    if let Some(aggregate_peer) = aggregate.peers.get_mut(&piece.peer_id) {
                        let _ = aggregate_peer
                            .received_from
                            .set(piece.chunk.index as usize, false);
                    }
                }
                return;
            }
            aggregate.header = HeaderState::Verifying {
                from,
                since: Instant::now(),
                signed_header,
                pending,
            };
            return;
        }
    }

    /// Notes that we hold the header of the aggregate `id` from now on, and stops tracking the
    /// other aggregates with its slot and aggregator.
    fn on_header_held(&mut self, id: AggregateId) {
        self.held
            .insert((id.slot, id.aggregator_index), id.header_root);
        self.aggregates.retain(|other_id, _| {
            *other_id == id
                || other_id.slot != id.slot
                || other_id.aggregator_index != id.aggregator_index
        });
    }

    /// Handles the result of the checks of the complete aggregate `id`.
    fn on_aggregate_verified(&mut self, id: AggregateId, outcome: AggregateOutcome) {
        let Some(aggregate) = self.aggregates.get_mut(&id) else {
            return;
        };
        match outcome {
            AggregateOutcome::Valid => {
                metrics::inc_counter_vec(
                    &metrics::AGGREGATE_DISSEMINATION_AGGREGATES_VERIFIED,
                    &["valid"],
                );
                aggregate.valid = true;
                self.mark_covered_by(id);
            }
            AggregateOutcome::Ignored => {
                metrics::inc_counter_vec(
                    &metrics::AGGREGATE_DISSEMINATION_AGGREGATES_VERIFIED,
                    &["ignored"],
                );
            }
            AggregateOutcome::Invalid => {
                metrics::inc_counter_vec(
                    &metrics::AGGREGATE_DISSEMINATION_AGGREGATES_VERIFIED,
                    &["invalid"],
                );
                debug!(
                    slot = %id.slot,
                    aggregator_index = id.aggregator_index,
                    header_root = ?id.header_root,
                    "Aggregate is invalid, its chunks are no longer disseminated"
                );
                aggregate.invalid = true;
                aggregate.announcement_pending = false;
            }
        }
    }

    /// Stops requesting the chunks of the aggregates that the valid aggregate `id` covers: the
    /// ones with the same attestation data and committee whose attesters are all among its
    /// attesters. They would be ignored once complete.
    fn mark_covered_by(&mut self, id: AggregateId) {
        let Some(valid) = self
            .aggregates
            .get(&id)
            .filter(|aggregate| aggregate.valid)
            .and_then(Aggregate::held_header)
            .cloned()
        else {
            return;
        };
        for (other_id, other) in &mut self.aggregates {
            if *other_id != id
                && !other.complete
                && other
                    .held_header()
                    .is_some_and(|header| covers(&valid, header))
            {
                other.covered = true;
            }
        }
    }

    /// Stops requesting the chunks of the aggregate `id`, whose header we now hold, if a valid
    /// aggregate we hold covers it, see `mark_covered_by`.
    fn mark_covered(&mut self, id: AggregateId) {
        let Some(header) = self.aggregates.get(&id).and_then(Aggregate::held_header) else {
            return;
        };
        let covered = self.aggregates.iter().any(|(other_id, other)| {
            *other_id != id
                && other.valid
                && other
                    .held_header()
                    .is_some_and(|valid| covers(valid, header))
        });
        if covered && let Some(aggregate) = self.aggregates.get_mut(&id) {
            aggregate.covered = !aggregate.complete;
        }
    }

    /// Returns the slots whose aggregates are in their tracking window, see `tracked_slots`.
    fn tracked_slots(&self) -> Option<RangeInclusive<Slot>> {
        self.host.tracked_slots()
    }

    /// Whether an aggregate of `slot` is in its tracking window.
    fn is_tracked_slot(&self, slot: Slot) -> bool {
        self.tracked_slots()
            .is_some_and(|tracked_slots| tracked_slots.contains(&slot))
    }

    /// Stops tracking aggregates once their tracking window is over, and drops the peers neither
    /// of whose subscriptions is alive anymore.
    ///
    /// This is done whenever the tracking window moved on, see `time_to_next_tracking_window`,
    /// as a window that is over is all there is to clean up for. The peers are dropped along
    /// with it: until then, they are of no harm, as nothing is sent to them.
    fn clean_up(&mut self) {
        let tracked_slots = self.tracked_slots();
        let is_tracked = |slot: &Slot| {
            tracked_slots
                .as_ref()
                .is_some_and(|tracked_slots| tracked_slots.contains(slot))
        };
        self.aggregates.retain(|id, aggregate| {
            let tracked = is_tracked(&id.slot);
            if !tracked && !aggregate.complete {
                let header = if aggregate.held_header().is_some() {
                    "held"
                } else {
                    "none"
                };
                metrics::inc_counter_vec(
                    &metrics::AGGREGATE_DISSEMINATION_AGGREGATES_INCOMPLETE,
                    &[header],
                );
            }
            tracked
        });
        self.held.retain(|(slot, _), _| is_tracked(slot));

        self.peers.retain(|_, peer| {
            // The subscription of the peer to us ended. It may subscribe again.
            if peer.sender.as_ref().is_some_and(PieceSender::is_closed) {
                peer.sender = None;
            }
            peer.keep()
        });
        let peers = &self.peers;
        for aggregate in self.aggregates.values_mut() {
            aggregate
                .peers
                .retain(|peer_id, _| peers.contains_key(peer_id));
        }
    }

    fn try_inform_new_peer(&mut self, peer_id: PeerId) {
        let Some(sender) = self.peers.get(&peer_id).and_then(Peer::sender) else {
            // This peer either has no sender yet or the sub isn't yet mutual.
            return;
        };
        for aggregate in self.aggregates.values_mut() {
            // The peer may have reconnected. What we queued for it on its previous connection
            // may not have reached it: what we announced, and the header.
            if let Some(aggregate_peer) = aggregate.peers.get_mut(&peer_id) {
                aggregate_peer.announced = None;
                aggregate_peer.knows_header = aggregate_peer
                    .has
                    .as_ref()
                    .is_some_and(|has| !has.is_zero())
                    || !aggregate_peer.received_from.is_zero();
            }
            let have = aggregate.have();
            aggregate.announce_to(peer_id, sender, &have);
            // The chunks that were not pushed to enough peers yet, as when we published an
            // aggregate with few peers.
            aggregate.push_chunks((0..TOTAL_PROOF_CHUNKS).collect(), &self.peers);
        }
        // The peer may have chunks we lack, as it told us before.
        self.requests_pending = true;
    }

    /// Whether any aggregate has news for our peers that is due to be announced.
    fn announcements_pending(&self) -> bool {
        let now = Instant::now();
        self.aggregates
            .values()
            .any(|aggregate| aggregate.announcement_pending && aggregate.announcement_due(now))
    }

    /// Announces the aggregates with news to our peers.
    ///
    /// Announcing as soon as a chunk becomes valid would send a message per chunk to every peer,
    /// filling their send queues. Instead, we wait until there is nothing else to do, which
    /// coalesces the announcements of chunks received in a burst.
    ///
    /// News that is not due yet, see `Aggregate::announcement_due`, is held back until it is. The
    /// service wakes up for it by then, see `next_wake`.
    fn flush_announcements(&mut self) {
        let now = Instant::now();
        for aggregate in self.aggregates.values_mut() {
            if aggregate.announcement_pending && aggregate.announcement_due(now) {
                aggregate.announcement_pending = false;
                aggregate.last_announced = Some(now);
                aggregate.announce(&self.peers);
            }
        }
    }

    /// Requests the chunks we lack of the aggregates we started to track at least
    /// `REQUEST_DELAY` ago, see `Aggregate::request_missing_chunks`.
    ///
    /// Chunks become requestable as time passes, which the service wakes up for, see
    /// `Aggregate::next_request_at`, or as peers tell us more, see `requests_pending`.
    fn request_missing_chunks(&mut self) {
        let now = Instant::now();
        for aggregate in self.aggregates.values_mut() {
            aggregate.request_missing_chunks(&self.peers, now);
        }
    }

    /// Reports `peer_id` to the peer manager, and ignores it for the rest of the aggregate `id`,
    /// if any.
    fn penalize_peer(
        &mut self,
        peer_id: PeerId,
        id: Option<AggregateId>,
        penalty: Penalty,
        msg: &'static str,
    ) {
        if let Some(id) = id
            && let Some(aggregate) = self.aggregates.get_mut(&id)
        {
            aggregate.peers.entry(peer_id).or_default().banned = true;
            // Request the chunks we requested from the peer elsewhere.
            aggregate.forget_requests_to(peer_id);
        };
        self.host.report_peer(peer_id, penalty, msg);
    }
}

/// Whether `signed_header` is the header of the aggregate `id`: its root is the header root of
/// the ID, and it is of the slot and the aggregator of the ID.
fn header_matches_id(signed_header: &SignedAggregateHeader, id: &AggregateId) -> bool {
    signed_header.message.aggregate.data.slot == id.slot
        && signed_header.message.aggregator_index == id.aggregator_index
        && signed_header.message.hash_tree_root() == id.header_root
}

/// Whether the aggregate of the header `valid` covers the one of `other`: they have the same
/// attestation data and committee, and the attesters of `other` are all attesters of `valid`.
fn covers(valid: &CheckedHeader, other: &CheckedHeader) -> bool {
    let (valid, other) = (valid.aggregate(), other.aggregate());
    valid.data == other.data
        && valid.committee_bits == other.committee_bits
        && valid.aggregation_bits.len() == other.aggregation_bits.len()
        && (0..valid.aggregation_bits.len()).all(|index| {
            valid.aggregation_bits.get(index).unwrap_or(false)
                || !other.aggregation_bits.get(index).unwrap_or(false)
        })
}

/// Returns how long to wait for a requested chunk of an aggregate whose chunks are `chunk_len`
/// bytes long: `REQUEST_TIMEOUT`, and `REQUEST_TIMEOUT_PER_BYTE` for every byte.
fn request_timeout(chunk_len: usize) -> Duration {
    let chunk_len = u32::try_from(chunk_len).unwrap_or(u32::MAX);
    REQUEST_TIMEOUT.saturating_add(REQUEST_TIMEOUT_PER_BYTE.saturating_mul(chunk_len))
}

/// Returns the maximum number of chunks of an aggregate to push to one peer, if we can push to
/// `peer_count` peers: `MAX_PUSH_SHARE` times what each of them would get if we spread our
/// pushes, `PUSH_PEERS` per chunk, evenly over them.
///
/// With few peers, this is more than a proof has chunks, and so no limit.
fn max_pushes_per_peer(peer_count: usize) -> usize {
    TOTAL_PROOF_CHUNKS
        .saturating_mul(PUSH_PEERS)
        .saturating_mul(MAX_PUSH_SHARE)
        .div_ceil(peer_count.max(1))
}

/// Returns the slots whose aggregates are in their tracking window at `now`,
/// the time since genesis, if the clock is past genesis: the current slot and
/// the `TRACKED_SLOTS_AFTER_OWN` slots before it, allowing for a clock
/// disparity of `disparity`.
pub(crate) fn tracked_slots(
    now: Duration,
    slot_duration: Duration,
    disparity: Duration,
) -> Option<RangeInclusive<Slot>> {
    let earliest_current_slot = slot_at(now.checked_sub(disparity)?, slot_duration);
    let latest_current_slot = slot_at(now.saturating_add(disparity), slot_duration);
    Some(earliest_current_slot.saturating_sub(TRACKED_SLOTS_AFTER_OWN)..=latest_current_slot)
}

/// Returns how long it takes from `now`, the time since genesis, until the
/// tracking window moves on, i.e. until the first of the `tracked_slots` is
/// over: until the next slot starts, allowing for a clock disparity of
/// `disparity`. A slot, if the clock is not past genesis.
pub(crate) fn time_to_next_tracking_window(
    now: Duration,
    slot_duration: Duration,
    disparity: Duration,
) -> Duration {
    let time_to_next_window = || {
        let earliest_current_slot = slot_at(now.checked_sub(disparity)?, slot_duration);
        let next_slot = u32::try_from(earliest_current_slot.saturating_add(1)).ok()?;
        slot_duration
            .checked_mul(next_slot)?
            .checked_add(disparity)?
            .checked_sub(now)
    };
    time_to_next_window().unwrap_or(slot_duration)
}

fn slot_at(since_genesis: Duration, slot_duration: Duration) -> Slot {
    let slot_ms = slot_duration.as_millis().max(1);
    (since_genesis.as_millis() / slot_ms) as Slot
}

impl Aggregate {
    fn new(id: AggregateId) -> Self {
        Aggregate {
            id,
            object_id: Bytes::from(id.to_ssz()),
            announcement: None,
            header: HeaderState::Unknown,
            chunks: vec![Chunk::unknown(); TOTAL_PROOF_CHUNKS],
            tracked_since: Instant::now(),
            peers: HashMap::new(),
            complete: false,
            invalid: false,
            valid: false,
            covered: false,
            announcement_pending: false,
            last_announced: None,
            first_chunk_at: None,
            request_retry_at: None,
        }
    }

    /// Returns the header of the aggregate, if we hold it.
    fn held_header(&self) -> Option<&Arc<CheckedHeader>> {
        match &self.header {
            HeaderState::Held(header) => Some(&header.verified),
            HeaderState::Unknown | HeaderState::Verifying { .. } => None,
        }
    }

    /// Whether what we have may be announced to all peers at `now`: `ANNOUNCE_INTERVAL` after
    /// the last time, or right away if we have every chunk, so that peers stop sending us any.
    fn announcement_due(&self, now: Instant) -> bool {
        self.complete
            || self
                .last_announced
                .is_none_or(|last| now.saturating_duration_since(last) >= ANNOUNCE_INTERVAL)
    }

    /// Returns when the service is to wake up for the aggregate after `now`, if nothing else
    /// happens, see `AggregateDisseminationService::next_wake`: to announce news that is held
    /// back, or to request chunks.
    fn next_wake(&self, now: Instant) -> Option<Instant> {
        let announce_at = self
            .last_announced
            .filter(|_| self.announcement_pending && !self.announcement_due(now))
            .and_then(|last| last.checked_add(ANNOUNCE_INTERVAL));
        // To give up on a header that is not checked in time.
        let header_timeout_at = match &self.header {
            HeaderState::Verifying { since, .. } => since.checked_add(HEADER_VERIFICATION_TIMEOUT),
            HeaderState::Unknown | HeaderState::Held(_) => None,
        };
        [announce_at, header_timeout_at, self.next_request_at(now)]
            .into_iter()
            .flatten()
            .min()
    }

    /// Whether the chunks we lack are to be requested: not once we have every chunk, nor if the
    /// aggregate is of no use, nor while its header is being checked.
    fn requests_chunks(&self) -> bool {
        !self.complete
            && !self.invalid
            && !self.covered
            && !matches!(self.header, HeaderState::Verifying { .. })
    }

    /// Returns when `request_missing_chunks` is next to be called after `now`, if no peer tells
    /// us anything until then: once `REQUEST_DELAY` passed, and from then on whenever a request
    /// times out, or is to be tried again as it could not be queued.
    ///
    /// A chunk whose request timed out and that no peer can be asked for is requested once a
    /// peer tells us more, so there is nothing to wake up for.
    fn next_request_at(&self, now: Instant) -> Option<Instant> {
        if !self.requests_chunks() {
            return None;
        }
        let request_at = self.tracked_since.checked_add(REQUEST_DELAY)?;
        if now < request_at {
            return Some(request_at);
        }
        let request_timeout = self.request_timeout();
        self.chunks
            .iter()
            .filter_map(|chunk| match chunk {
                Chunk::Unknown {
                    requested: Some((_, requested_at)),
                } => requested_at.checked_add(request_timeout),
                _ => None,
            })
            .chain(self.request_retry_at)
            .filter(|at| *at > now)
            .min()
    }

    /// Returns the chunks we have, i.e. the valid ones.
    fn have(&self) -> ChunkSet {
        let mut have = ChunkSet::new();
        for (index, chunk) in self.chunks.iter().enumerate() {
            // Can't fail, we have exactly as many chunks as bits.
            let _ = have.set(index, matches!(chunk, Chunk::Valid { .. }));
        }
        have
    }

    /// Returns all chunks if every one of them is valid.
    fn valid_chunks(&self) -> Option<Vec<Arc<ProofChunk>>> {
        self.chunks
            .iter()
            .map(|chunk| match chunk {
                Chunk::Valid { chunk, .. } => Some(chunk.clone()),
                Chunk::Unknown { .. } => None,
            })
            .collect()
    }

    /// Forgets the requests outstanding with `peer_id`, so that their chunks are requested from
    /// other peers.
    fn forget_requests_to(&mut self, peer_id: PeerId) {
        for chunk in &mut self.chunks {
            if let Chunk::Unknown { requested } = chunk
                && requested.is_some_and(|(requested_from, _)| requested_from == peer_id)
            {
                *requested = None;
            }
        }
    }

    /// Disseminates the chunk at `index`, which just became valid, and hands the aggregate to the
    /// beacon processor once every chunk is valid. `peer_id` is the peer that sent the chunk.
    fn on_chunk_valid(
        &mut self,
        index: usize,
        peer_id: PeerId,
        peers: &TopicPeers,
        host: &impl Host,
    ) {
        self.first_chunk_at.get_or_insert_with(Instant::now);
        self.push_chunk(index, peers);
        self.announcement_pending = !self.invalid;

        if !self.complete
            && let Some(chunks) = self.valid_chunks()
            && let Some(header) = self.held_header().cloned()
        {
            // We are complete, send to the beacon processor to reassemble and check the proof.
            self.complete = true;
            metrics::inc_counter_vec(
                &metrics::AGGREGATE_DISSEMINATION_AGGREGATES_COMPLETED,
                &["reassembled"],
            );
            metrics::observe_duration(
                &metrics::AGGREGATE_DISSEMINATION_REASSEMBLY_SECONDS,
                self.tracked_since.elapsed(),
            );
            if let Err(err) = host.check_aggregate(header, chunks, peer_id) {
                warn!(
                    %err,
                    slot = %self.id.slot,
                    aggregator_index = self.id.aggregator_index,
                    "Unable to have a reassembled aggregate checked"
                );
            }
        }
    }

    /// Returns the valid chunk at `index` as we send it, encoded with `encode_piece`, with the
    /// header of the aggregate if `with_header`.
    ///
    /// Each of the two is encoded when it is first sent, and the encoding kept with the chunk.
    fn encoded_chunk(&mut self, index: usize, with_header: bool) -> Option<Bytes> {
        let HeaderState::Held(header) = &self.header else {
            return None;
        };
        let Some(Chunk::Valid {
            chunk,
            encoded,
            encoded_with_header,
            ..
        }) = self.chunks.get_mut(index)
        else {
            return None;
        };
        let (encoded, signed_header) = if with_header {
            (encoded_with_header, Some(&*header.signed_header))
        } else {
            (encoded, None)
        };
        if encoded.is_none() {
            match encode_piece(signed_header, chunk) {
                Ok(encoded_piece) => *encoded = Some(encoded_piece.into()),
                Err(err) => {
                    error!(
                        ?err,
                        slot = %self.id.slot,
                        aggregator_index = self.id.aggregator_index,
                        index,
                        "Unable to encode proof chunk"
                    );
                    return None;
                }
            }
        }
        encoded.clone()
    }

    /// Queues a message about the aggregate for `peer_id`, and returns whether it was queued: the
    /// valid chunk at `chunk`, if any, and our metadata, i.e. that we have `have`, which is what
    /// we have now, and that we request the chunks of `request`, if any.
    ///
    /// The chunk carries the header unless the peer is known to hold it. The metadata is left
    /// out if it is no news to the peer: it knows that we have `have`, and we request nothing.
    /// `kind` is what the message is for, to tell the send errors apart.
    fn send(
        &mut self,
        peer_id: PeerId,
        sender: &PieceSender,
        have: &ChunkSet,
        request: Option<&ChunkSet>,
        chunk: Option<usize>,
        kind: &'static str,
    ) -> bool {
        let with_header = chunk.is_some()
            && !self
                .peers
                .get(&peer_id)
                .is_some_and(|aggregate_peer| aggregate_peer.knows_header);
        let encoded_chunk = match chunk {
            Some(index) => match self.encoded_chunk(index, with_header) {
                Some(encoded_chunk) => Some(encoded_chunk),
                None => return false,
            },
            None => None,
        };
        let aggregate_peer = self.peers.entry(peer_id).or_default();

        // A node that holds no chunk has nothing to announce, and only sends metadata to request.
        let announce = request.is_some()
            || (!have.is_zero() && aggregate_peer.announced.as_ref() != Some(have));
        // Like gossipsub control messages, the metadata is not compressed, as it is too small to
        // benefit.
        let metadata = announce.then(|| match (request, &self.announcement) {
            // What we announced to another peer already.
            (None, Some((announced, metadata))) if announced == have => metadata.clone(),
            _ => {
                let metadata = ProofChunkMetadata {
                    have: (*have).into(),
                    request: request.copied().unwrap_or_default().into(),
                };
                let metadata = Bytes::from(metadata.to_ssz());
                if request.is_none() {
                    self.announcement = Some((*have, metadata.clone()));
                }
                metadata
            }
        });
        if metadata.is_none() && encoded_chunk.is_none() {
            // Nothing to tell the peer.
            return false;
        }
        let sent_bytes = [&metadata, &encoded_chunk]
            .into_iter()
            .flatten()
            .fold(0usize, |bytes, data| bytes.saturating_add(data.len()));
        let message = ObjectPieces {
            object_id: self.object_id.clone(),
            metadata,
            pieces: encoded_chunk,
        };
        if let Err(err) = sender.try_send(message) {
            debug!(%err, %peer_id, kind, index = ?chunk, "Unable to send message");
            metrics::inc_counter_vec(&metrics::AGGREGATE_DISSEMINATION_SEND_ERRORS, &[kind]);
            return false;
        }
        count_sent_bytes(sent_bytes);

        if let Some(index) = chunk {
            let _ = aggregate_peer.sent_to.set(index, true);
            if with_header {
                // The stream delivers in order, so the peer has the header before anything we
                // send it next.
                aggregate_peer.knows_header = true;
                metrics::inc_counter(&metrics::AGGREGATE_DISSEMINATION_HEADERS_SENT);
            }
        }
        if announce {
            aggregate_peer.announced = Some(*have);
        }
        true
    }

    /// Sends the valid chunk at `index` to `peer_id`, and returns whether it was queued for
    /// sending.
    ///
    /// Our metadata is sent along if the peer doesn't know that we have `have`, which is what we
    /// have now. This saves announcing it in a message of its own. It carries no requests, those
    /// are made by `request_missing_chunks`.
    fn send_chunk(
        &mut self,
        index: usize,
        peer_id: PeerId,
        sender: &PieceSender,
        have: &ChunkSet,
    ) -> bool {
        self.send(peer_id, sender, have, None, Some(index), "chunk")
    }

    /// Pushes the valid chunk at `index` to peers that aren't known to have the chunk, until it
    /// was pushed to `PUSH_PEERS` peers, preferring peers with a short send queue. No peer gets
    /// more of the chunks of the aggregate pushed than `max_pushes_per_peer`.
    fn push_chunk(&mut self, index: usize, peers: &TopicPeers) {
        self.push_chunks(vec![index], peers);
    }

    /// Pushes the valid chunks at `indices` like `push_chunk`, one peer at a time: every chunk is
    /// pushed to a first peer before any is pushed to a second one. The chunks pushed to the
    /// fewest peers so far go first, in random order among them.
    ///
    /// The send queue of a peer is sent in order. Pushing one chunk to all of its peers before
    /// the next would queue the chunks in the same order for every peer, and the last one would
    /// leave us only after all the others did, to every peer. A proof is only of use with all
    /// of its chunks, so it would reach the network as late as possible. For the same reason, a
    /// peer that may only get some of the chunks gets the ones we pushed the least.
    fn push_chunks(&mut self, mut indices: Vec<usize>, peers: &TopicPeers) {
        if self.invalid {
            return;
        }
        // Past the time we push the chunks we received for, see `PUSH_PHASE`.
        if let Some(first_chunk_at) = self.first_chunk_at
            && first_chunk_at.elapsed() >= PUSH_PHASE
        {
            return;
        }
        indices.retain(|index| {
            matches!(
                self.chunks.get(*index),
                Some(Chunk::Valid { pushes, .. }) if *pushes < PUSH_PEERS
            )
        });
        if indices.is_empty() {
            return;
        }

        // The peers we can push to share our pushes.
        let peer_count = peers
            .values()
            .filter(|peer| peer.sender().is_some())
            .count();
        let max_pushes = max_pushes_per_peer(peer_count);

        // Look up what the peers know once, rather than for every push.
        let single_index = match indices.as_slice() {
            [index] => Some(*index),
            _ => None,
        };
        let unknown_peer = AggregatePeer::default();
        let mut candidates = peers
            .iter()
            .filter_map(|(peer_id, peer)| {
                let sender = peer.sender()?;
                // A peer need not have told us anything about the aggregate.
                let aggregate_peer = self.peers.get(peer_id).unwrap_or(&unknown_peer);
                if aggregate_peer.banned {
                    return None;
                }
                let remaining_pushes = max_pushes.saturating_sub(aggregate_peer.pushes);
                if remaining_pushes == 0 {
                    return None;
                }
                let skip = match single_index {
                    // A single chunk is checked right away, which spares collecting what the
                    // peer knows. This is the common case: a chunk we received.
                    Some(index) => {
                        if aggregate_peer.knows(index) {
                            return None;
                        }
                        ChunkSet::new()
                    }
                    None => aggregate_peer.known_chunks(),
                };
                Some(PushCandidate {
                    peer_id: *peer_id,
                    sender,
                    queued: sender.len(),
                    remaining_pushes,
                    skip,
                })
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return;
        }
        // Random order, so that ties between peers with equally long send queues are broken
        // randomly.
        let mut rng = rand::thread_rng();
        candidates.shuffle(&mut rng);

        let have = self.have();
        for _ in 0..PUSH_PEERS {
            // The chunks pushed to the fewest peers first, in random order among them.
            indices.shuffle(&mut rng);
            let chunks = &self.chunks;
            indices.sort_by_key(|index| match chunks.get(*index) {
                Some(Chunk::Valid { pushes, .. }) => *pushes,
                _ => usize::MAX,
            });
            // A chunk that can't be pushed to another peer now can't be later in this call.
            indices.retain(|index| self.push_chunk_to_one(*index, &mut candidates, &have));
            if indices.is_empty() {
                break;
            }
        }
    }

    /// Pushes the valid chunk at `index` to the candidate with the shortest send queue that may
    /// get another push, unless the chunk was pushed to `PUSH_PEERS` peers already. Returns
    /// whether it was pushed.
    fn push_chunk_to_one(
        &mut self,
        index: usize,
        candidates: &mut [PushCandidate<'_>],
        have: &ChunkSet,
    ) -> bool {
        if !matches!(
            self.chunks.get(index),
            Some(Chunk::Valid { pushes, .. }) if *pushes < PUSH_PEERS
        ) {
            return false;
        }

        loop {
            // The first of the candidates with the shortest queue, which are in random order.
            let Some(candidate) = candidates
                .iter_mut()
                .filter(|candidate| {
                    candidate.remaining_pushes > 0 && !candidate.skip.get(index).unwrap_or(true)
                })
                .min_by_key(|candidate| candidate.queued)
            else {
                return false;
            };
            let _ = candidate.skip.set(index, true);
            // If the chunk can't be sent to the peer, it is pushed to another one instead.
            if self.send_chunk(index, candidate.peer_id, candidate.sender, have) {
                metrics::inc_counter_vec(
                    &metrics::AGGREGATE_DISSEMINATION_CHUNKS_SENT,
                    &["pushed"],
                );
                candidate.queued = candidate.queued.saturating_add(1);
                candidate.remaining_pushes = candidate.remaining_pushes.saturating_sub(1);
                if let Some(aggregate_peer) = self.peers.get_mut(&candidate.peer_id) {
                    aggregate_peer.pushes = aggregate_peer.pushes.saturating_add(1);
                }
                if let Some(Chunk::Valid { pushes, .. }) = self.chunks.get_mut(index) {
                    *pushes = pushes.saturating_add(1);
                }
                return true;
            }
        }
    }

    /// Announces our metadata to every peer we are mutually subscribed with, see `announce_to`.
    fn announce(&mut self, peers: &TopicPeers) {
        let have = self.have();
        for (peer_id, peer) in peers {
            if let Some(sender) = peer.sender() {
                self.announce_to(*peer_id, sender, &have);
            }
        }
    }

    /// Sends our metadata to `peer_id`, unless it knows already that we have `have`, which is what
    /// we have now, or we have nothing. It carries no requests, those are made by
    /// `request_missing_chunks`.
    fn announce_to(&mut self, peer_id: PeerId, sender: &PieceSender, have: &ChunkSet) {
        if self.invalid || have.is_zero() {
            return;
        }
        if self.peers.get(&peer_id).is_some_and(|aggregate_peer| {
            aggregate_peer.banned || aggregate_peer.announced.as_ref() == Some(have)
        }) {
            return;
        }

        // Nothing to do on error: If closed, it will be cleaned up. If full, the peer is told
        // along with our next news.
        if self.send(peer_id, sender, have, None, None, "announcement") {
            metrics::inc_counter(&metrics::AGGREGATE_DISSEMINATION_ANNOUNCEMENTS_SENT);
        }
    }

    /// How long to wait for a requested chunk before requesting it again, see
    /// `request_timeout`. The chunks of a proof are equally long, but for the last ones, which
    /// can be shorter. Until we have one of them, the chunks count as empty.
    fn request_timeout(&self) -> Duration {
        let chunk_len = self
            .chunks
            .iter()
            .filter_map(|chunk| match chunk {
                Chunk::Valid { chunk, .. } => Some(chunk.chunk.len()),
                Chunk::Unknown { .. } => None,
            })
            .max()
            .unwrap_or_default();
        request_timeout(chunk_len)
    }

    /// Requests the chunks we lack from the peers that announced them, if we started to track
    /// the aggregate at least `REQUEST_DELAY` before `now`.
    ///
    /// Each chunk is requested from one peer, and again once it was not received within the
    /// timeout, see `request_timeout`, from another peer if one announced it. No peer is asked
    /// beyond `MAX_REQUESTS_PER_PEER` outstanding requests. Among the peers that have a chunk,
    /// the one with the fewest outstanding requests is asked, which spreads the requests. The
    /// chunks that the fewest peers have are requested first.
    ///
    /// While we hold no header, a single chunk is requested: it brings the header, and every
    /// further one would bring it again.
    ///
    /// A request is our metadata with the requested chunks set, so it tells the peer what we have
    /// as well. If it can't be queued for the peer, it is tried again after `REQUEST_RETRY_DELAY`.
    fn request_missing_chunks(&mut self, peers: &TopicPeers, now: Instant) {
        if !self.requests_chunks()
            || now.saturating_duration_since(self.tracked_since) < REQUEST_DELAY
        {
            return;
        }
        self.request_retry_at = None;
        let holds_header = matches!(self.header, HeaderState::Held(_));

        let request_timeout = self.request_timeout();
        // The chunks to request, and the number of requests outstanding with each peer.
        let mut missing = vec![];
        let mut outstanding = HashMap::<PeerId, usize>::new();
        for (index, chunk) in self.chunks.iter().enumerate() {
            let Chunk::Unknown { requested } = chunk else {
                continue;
            };
            match requested {
                Some((peer_id, requested_at))
                    if now.saturating_duration_since(*requested_at) < request_timeout =>
                {
                    let requests = outstanding.entry(*peer_id).or_default();
                    *requests = requests.saturating_add(1);
                }
                _ => missing.push(index),
            }
        }
        if missing.is_empty() || (!holds_header && !outstanding.is_empty()) {
            return;
        }
        let mut missing_chunks = ChunkSet::new();
        for index in &missing {
            let _ = missing_chunks.set(*index, true);
        }

        // Look up the peers that can be asked once, rather than for every chunk.
        let mut candidates = peers
            .iter()
            .filter_map(|(peer_id, peer)| {
                let sender = peer.sender()?;
                let aggregate_peer = self.peers.get(peer_id)?;
                if aggregate_peer.banned {
                    return None;
                }
                // A peer that told us nothing yet has no chunk to ask for.
                let has = aggregate_peer.has.as_ref()?;
                if has.intersection(&missing_chunks).is_zero() {
                    return None;
                }
                Some(RequestCandidate {
                    peer_id: *peer_id,
                    sender,
                    has: *has,
                    outstanding: outstanding.get(peer_id).copied().unwrap_or_default(),
                    request: ChunkSet::new(),
                })
            })
            .collect::<Vec<_>>();
        // Usually, every peer that has chunks we lack is busy with a request, as this is called
        // whenever a peer told us anything.
        if candidates
            .iter()
            .all(|candidate| candidate.outstanding >= MAX_REQUESTS_PER_PEER)
        {
            return;
        }
        // Random order, so that ties between peers and between chunks are broken randomly.
        candidates.shuffle(&mut rand::thread_rng());
        missing.shuffle(&mut rand::thread_rng());
        // Request the chunks first that the fewest peers have. Otherwise, a peer that has them
        // could be asked for chunks that other peers have too, and have no requests left.
        missing.sort_by_cached_key(|index| {
            candidates
                .iter()
                .filter(|candidate| candidate.has_chunk(*index))
                .count()
        });

        let mut requests = 0usize;
        for index in missing {
            if !holds_header && requests >= 1 {
                break;
            }
            // The peer that did not send the chunk in time, if we requested it before.
            let timed_out = match self.chunks.get(index) {
                Some(Chunk::Unknown {
                    requested: Some((peer_id, _)),
                }) => Some(*peer_id),
                _ => None,
            };
            let chosen = candidates
                .iter_mut()
                .filter(|candidate| {
                    candidate.outstanding < MAX_REQUESTS_PER_PEER && candidate.has_chunk(index)
                })
                .min_by_key(|candidate| {
                    (Some(candidate.peer_id) == timed_out, candidate.outstanding)
                });
            let Some(candidate) = chosen else {
                continue;
            };
            candidate.outstanding = candidate.outstanding.saturating_add(1);
            let _ = candidate.request.set(index, true);
            requests = requests.saturating_add(1);
        }

        let have = self.have();
        for candidate in &candidates {
            let (peer_id, request) = (candidate.peer_id, &candidate.request);
            if request.is_zero() {
                continue;
            }
            if !self.send(
                peer_id,
                candidate.sender,
                &have,
                Some(request),
                None,
                "request",
            ) {
                // No peer tells us once the queue has room again, so try again in a while.
                self.request_retry_at = now.checked_add(REQUEST_RETRY_DELAY);
                continue;
            }
            for (requested, chunk) in request.iter().zip(&mut self.chunks) {
                if requested
                    && let Chunk::Unknown {
                        requested: previous_request,
                    } = chunk
                {
                    metrics::inc_counter(&metrics::AGGREGATE_DISSEMINATION_CHUNKS_REQUESTED);
                    // A chunk is only requested again once its previous request timed out.
                    if previous_request.is_some() {
                        metrics::inc_counter(
                            &metrics::AGGREGATE_DISSEMINATION_CHUNK_REQUESTS_RETRIED,
                        );
                    }
                    *previous_request = Some((peer_id, now));
                }
            }
        }
    }
}

/// Counts a chunk received from a peer, by what became of it.
fn count_received_chunk(result: &str) {
    metrics::inc_counter_vec(&metrics::AGGREGATE_DISSEMINATION_CHUNKS_RECEIVED, &[result]);
}

/// Counts the bytes of a message queued for a peer.
fn count_sent_bytes(bytes: usize) {
    metrics::inc_counter_by(&metrics::AGGREGATE_DISSEMINATION_BYTES_SENT, bytes as u64);
}

/// This is just named error as it is private to this module.
#[derive(Debug, Clone, thiserror::Error)]
enum Error {
    #[error("unexpected number of pieces: {0}")]
    UnexpectedPiecesLen(usize),
    #[error("chunk index mismatch")]
    ChunkIndexMismatch,
    #[error("invalid object id size")]
    InvalidObjectIdSize,
    #[error("SSZ decode error: {0:?}")]
    SszDecode(libssz::DecodeError),
    #[error("a piece carries at most one header")]
    TooManyHeaders,
    #[error("snappy error: {0}")]
    Snappy(snap::Error),
    /// A piece decompresses to more bytes than the largest valid piece has.
    #[error("piece decompresses to {0} bytes, more than the largest valid piece")]
    DecompressedTooLarge(usize),
    /// A piece is longer than Snappy compresses its uncompressed length to, at worst.
    #[error("compressed piece of {0} bytes is longer than its worst case compression")]
    CompressedTooLarge(usize),
}

/// A waggle message about an aggregate, decoded.
struct Message {
    id: AggregateId,
    metadata: Option<Metadata>,
    piece: Option<AggregatePiece>,
}

/// A [`ProofChunkMetadata`], decoded into chunk sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Metadata {
    have: ChunkSet,
    request: ChunkSet,
}

impl From<ProofChunkMetadata> for Metadata {
    fn from(metadata: ProofChunkMetadata) -> Self {
        Self {
            have: (&metadata.have).into(),
            request: (&metadata.request).into(),
        }
    }
}

/// The network id of the aggregate `header` describes.
fn id_of(header: &CheckedHeader) -> AggregateId {
    AggregateId {
        slot: header.aggregate().data.slot,
        aggregator_index: header.aggregator_index(),
        header_root: header.header_root,
    }
}

/// The length of an SSZ serialized `AggregateId`.
const AGGREGATE_ID_LEN: usize = 48;

/// Encodes a piece for a waggle message: `chunk`, with the header `signed_header` if any, as
/// snappy compressed SSZ, like gossipsub message data.
fn encode_piece(
    signed_header: Option<&SignedAggregateHeader>,
    chunk: &ProofChunk,
) -> Result<Vec<u8>, Error> {
    let piece = AggregatePiece {
        signed_header: signed_header
            .cloned()
            .into_iter()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| Error::TooManyHeaders)?,
        chunk: chunk.clone(),
    };
    snap::raw::Encoder::new()
        .compress_vec(&piece.to_ssz())
        .map_err(Error::Snappy)
}

/// Decodes a piece encoded with `encode_piece`.
fn decode_piece(data: &[u8]) -> Result<AggregatePiece, Error> {
    // Check the length before decompressing, so that peers can't make us allocate more than the
    // largest piece takes.
    let len = snap::raw::decompress_len(data).map_err(Error::Snappy)?;
    if len > AggregatePiece::max_ssz_len() {
        return Err(Error::DecompressedTooLarge(len));
    }
    // Snappy never compresses this badly.
    if data.len() > snap::raw::max_compress_len(len) {
        return Err(Error::CompressedTooLarge(data.len()));
    }
    let ssz_bytes = snap::raw::Decoder::new()
        .decompress_vec(data)
        .map_err(Error::Snappy)?;
    AggregatePiece::from_ssz_bytes(&ssz_bytes).map_err(Error::SszDecode)
}

impl TryFrom<ObjectPieces> for Message {
    type Error = Error;

    fn try_from(value: ObjectPieces) -> Result<Self, Self::Error> {
        if value.object_id.len() != AGGREGATE_ID_LEN {
            return Err(Error::InvalidObjectIdSize);
        }
        Ok(Self {
            id: AggregateId::from_ssz_bytes(&value.object_id).map_err(Error::SszDecode)?,
            metadata: value
                .metadata
                .map(|metadata| ProofChunkMetadata::from_ssz_bytes(&metadata).map(Metadata::from))
                .transpose()
                .map_err(Error::SszDecode)?,
            piece: value.pieces.map(|piece| decode_piece(&piece)).transpose()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use ethlambda_types::beacon::containers::pq::{AggregateHeader, Attestation, AttestationProof};
    use ethlambda_types::beacon::containers::proof_chunks::{ProofChunkBytes, build_proof_chunks};
    use ethlambda_types::beacon::containers::shared::AttestationData;
    use libssz_types::ProgressiveBitlist;
    /// The slot of the aggregates of the tests.
    const SLOT: Slot = 3;

    /// An aggregate as its aggregator disseminates it.
    #[derive(Clone)]
    struct TestAggregate {
        id: AggregateId,
        signed_header: Arc<SignedAggregateHeader>,
        verified: Arc<CheckedHeader>,
        /// The chunks of the proof, with their inclusion proofs.
        chunks: Vec<Arc<ProofChunk>>,
    }

    /// Returns an aggregate of `aggregator_index` whose attesters are the committee members at
    /// `attesters`, of a committee of eight. The bytes of its proof depend on `seed`, so that
    /// aggregates differ, and vary, so that no two chunks are equal.
    fn test_aggregate(aggregator_index: u64, attesters: &[usize], seed: u8) -> TestAggregate {
        let proof = AttestationProof::try_from(
            (0..10_000usize)
                .map(|i| (i % 251) as u8 ^ seed)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let (chunks, proof_chunks_root) = build_proof_chunks(&proof).unwrap();
        let mut aggregation_bits = ProgressiveBitlist::with_length(8);
        for attester in attesters {
            aggregation_bits.set(*attester, true).unwrap();
        }
        let mut committee_bits = ethlambda_types::beacon::containers::pq::CommitteeBits::default();
        committee_bits.set(0, true).unwrap();
        let signed_header = SignedAggregateHeader {
            message: AggregateHeader {
                aggregator_index,
                aggregate: Attestation {
                    aggregation_bits,
                    data: AttestationData {
                        slot: SLOT,
                        ..Default::default()
                    },
                    committee_bits,
                },
                proof_chunks_root,
            },
            signature: Default::default(),
        };
        let header_root = signed_header.message.hash_tree_root();
        let verified = Arc::new(CheckedHeader {
            signed_header: signed_header.clone(),
            header_root,
            committee_index: 0,
            attesting_indices: attesters.iter().map(|attester| *attester as u64).collect(),
            statements: vec![],
        });
        TestAggregate {
            id: AggregateId {
                slot: SLOT,
                aggregator_index,
                header_root,
            },
            signed_header: Arc::new(signed_header),
            verified,
            chunks: chunks.into_iter().map(Arc::new).collect(),
        }
    }

    impl TestAggregate {
        /// Returns the piece carrying the chunk at `index`, with the header if `with_header`.
        fn piece(&self, index: usize, with_header: bool) -> AggregatePiece {
            AggregatePiece {
                signed_header: with_header
                    .then(|| (*self.signed_header).clone())
                    .into_iter()
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                chunk: (*self.chunks[index]).clone(),
            }
        }

        /// Returns the chunk at `index` with other content, which its inclusion proof doesn't
        /// fit.
        fn altered_piece(&self, index: usize, with_header: bool) -> AggregatePiece {
            let mut piece = self.piece(index, with_header);
            let len = piece.chunk.chunk.len();
            piece.chunk.chunk = ProofChunkBytes::try_from(vec![0xee; len]).unwrap();
            piece
        }

        /// Returns the aggregate as we track it once we hold its header and the chunks at
        /// `valid`, none of which was pushed yet.
        fn tracked(&self, valid: &[usize]) -> Aggregate {
            let mut aggregate = Aggregate::new(self.id);
            aggregate.header = HeaderState::Held(HeldHeader {
                verified: self.verified.clone(),
                signed_header: self.signed_header.clone(),
            });
            for index in valid {
                aggregate.chunks[*index] = Chunk::valid(self.chunks[*index].clone());
            }
            aggregate
        }
    }

    fn bitmap(indices: &[usize]) -> ChunkSet {
        let mut bitmap = ChunkSet::new();
        for index in indices {
            bitmap.set(*index, true).unwrap();
        }
        bitmap
    }

    /// Returns the indices set in `bitmap`.
    fn indices(bitmap: &ChunkSet) -> Vec<usize> {
        bitmap
            .iter()
            .enumerate()
            .filter_map(|(index, bit)| bit.then_some(index))
            .collect()
    }

    /// Returns metadata of a peer that has the chunks at `have`, and requests the ones at
    /// `request`.
    fn wire_metadata(metadata: &Metadata) -> ProofChunkMetadata {
        ProofChunkMetadata {
            have: metadata.have.into(),
            request: metadata.request.into(),
        }
    }

    fn metadata(have: &[usize], request: &[usize]) -> Metadata {
        Metadata {
            have: bitmap(have),
            request: bitmap(request),
        }
    }

    fn connection(id: usize) -> ConnectionId {
        ConnectionId::new_unchecked(id)
    }

    /// Adds a peer we are mutually subscribed with to `peers`, returning its ID and the receiver
    /// of the messages we send it.
    fn add_peer(peers: &mut TopicPeers) -> (PeerId, async_channel::Receiver<ObjectPieces>) {
        let (sender, receiver) = async_channel::unbounded();
        let peer_id = PeerId::random();
        peers.insert(
            peer_id,
            Peer {
                sender: Some(sender),
                subscribed: true,
                ..Peer::new(connection(0))
            },
        );
        (peer_id, receiver)
    }

    /// Notes that `peer_id` announced that it has the chunks at `have` of `aggregate`.
    fn announced(aggregate: &mut Aggregate, peer_id: PeerId, have: &[usize]) {
        let aggregate_peer = aggregate.peers.entry(peer_id).or_default();
        aggregate_peer.has = Some(bitmap(have));
        aggregate_peer.knows_header = !have.is_empty();
    }

    /// Returns the messages sent to a peer so far.
    fn sent(receiver: &async_channel::Receiver<ObjectPieces>) -> Vec<Message> {
        let mut messages = vec![];
        while let Ok(message) = receiver.try_recv() {
            messages.push(Message::try_from(message).unwrap());
        }
        messages
    }

    /// Returns the indices of the chunks sent to a peer so far, each with whether it carried the
    /// header.
    fn sent_chunks(receiver: &async_channel::Receiver<ObjectPieces>) -> Vec<(u8, bool)> {
        sent(receiver)
            .into_iter()
            .filter_map(|message| message.piece)
            .map(|piece| (piece.chunk.index, !piece.signed_header.is_empty()))
            .collect()
    }

    /// Returns the chunks requested from a peer so far.
    fn requested_chunks(receiver: &async_channel::Receiver<ObjectPieces>) -> Vec<usize> {
        sent(receiver)
            .into_iter()
            .filter_map(|message| message.metadata)
            .flat_map(|metadata| indices(&metadata.request))
            .collect()
    }

    /// The time `REQUEST_DELAY` after we started to track `aggregate`, from which on its chunks
    /// are requested.
    fn after_request_delay(aggregate: &Aggregate) -> Instant {
        aggregate.tracked_since + REQUEST_DELAY
    }

    #[test]
    fn encoded_messages_decode() {
        let aggregate = test_aggregate(7, &[0, 1], 0);
        let metadata = metadata(&[3], &[5]);
        for with_header in [true, false] {
            let piece = aggregate.piece(3, with_header);
            let encoded = encode_piece(
                with_header.then_some(&*aggregate.signed_header),
                &aggregate.chunks[3],
            )
            .unwrap();

            let message = Message::try_from(ObjectPieces {
                object_id: Bytes::from(aggregate.id.to_ssz()),
                metadata: Some(wire_metadata(&metadata).to_ssz().into()),
                pieces: Some(encoded.into()),
            })
            .unwrap();
            assert_eq!(message.id, aggregate.id);
            assert_eq!(message.metadata.unwrap(), metadata);
            assert_eq!(message.piece.unwrap(), piece);
        }
    }

    #[test]
    fn malformed_messages_dont_decode() {
        let aggregate = test_aggregate(7, &[0], 0);
        let object_id = Bytes::from(aggregate.id.to_ssz());
        let decode = |object_id: &Bytes, metadata: Option<Vec<u8>>, pieces: Option<Vec<u8>>| {
            Message::try_from(ObjectPieces {
                object_id: object_id.clone(),
                metadata: metadata.map(Bytes::from),
                pieces: pieces.map(Bytes::from),
            })
            .map(|_| ())
        };
        assert!(decode(&object_id, None, None).is_ok());

        // An object ID that is no `AggregateId`.
        assert!(matches!(
            decode(&object_id.slice(..32), None, None),
            Err(Error::InvalidObjectIdSize)
        ));
        // Metadata of the wrong length.
        assert!(matches!(
            decode(&object_id, Some(vec![0; 15]), None),
            Err(Error::SszDecode(_))
        ));
        // A piece that claims to decompress to more than the largest valid piece. The length is
        // checked before anything is decompressed.
        let too_long = snap::raw::Encoder::new()
            .compress_vec(&vec![0; AggregatePiece::max_ssz_len() + 1])
            .unwrap();
        assert!(matches!(
            decode(&object_id, None, Some(too_long)),
            Err(Error::DecompressedTooLarge(_))
        ));
        // A piece that is longer than snappy compresses its claimed length to.
        let mut padded = snap::raw::Encoder::new().compress_vec(&[1, 2, 3]).unwrap();
        padded.extend_from_slice(&[0; 1_000]);
        assert!(matches!(
            decode(&object_id, None, Some(padded)),
            Err(Error::CompressedTooLarge(_))
        ));
        // A piece that is no snappy, and one that is no `AggregatePiece`.
        assert!(decode(&object_id, None, Some(vec![0xff; 10])).is_err());
        let garbage = snap::raw::Encoder::new().compress_vec(&[1, 2, 3]).unwrap();
        assert!(matches!(
            decode(&object_id, None, Some(garbage)),
            Err(Error::SszDecode(_))
        ));
    }

    #[test]
    fn events_of_a_newer_connection_replace_the_peer() {
        let mut peers = TopicPeers::new();
        let peer_id = PeerId::random();

        // Both subscriptions are established on a connection.
        let (old_sender, old_receiver) = async_channel::unbounded::<ObjectPieces>();
        peer_on_connection(&mut peers, peer_id, connection(1))
            .unwrap()
            .subscribed = true;
        peer_on_connection(&mut peers, peer_id, connection(1))
            .unwrap()
            .sender = Some(old_sender);
        assert!(peers[&peer_id].sender().is_some());

        // The peer subscribes on a newer connection, which starts over and ends the subscription
        // on the previous one.
        let (new_sender, _new_receiver) = async_channel::unbounded::<ObjectPieces>();
        peer_on_connection(&mut peers, peer_id, connection(2))
            .unwrap()
            .sender = Some(new_sender);
        assert!(old_receiver.is_closed());
        assert_eq!(peers[&peer_id].connection_id, connection(2));
        assert!(!peers[&peer_id].subscribed);
        assert!(peers[&peer_id].sender().is_none());

        // The events of the previous connection are stale. Its `Closed` in particular, which can
        // be delivered late, does not remove the peer.
        assert!(peer_on_connection(&mut peers, peer_id, connection(1)).is_none());
        remove_peer_on_connection(&mut peers, peer_id, connection(1));
        assert_eq!(peers[&peer_id].connection_id, connection(2));

        // The `Closed` of the newest connection does.
        remove_peer_on_connection(&mut peers, peer_id, connection(2));
        assert!(peers.is_empty());
    }

    #[test]
    fn peers_are_kept_while_a_subscription_is_alive() {
        let (sender, receiver) = async_channel::unbounded::<ObjectPieces>();
        let mut peer = Peer {
            sender: Some(sender),
            ..Peer::new(connection(1))
        };
        // The peer is subscribed to us, and we may still subscribe to it.
        assert!(peer.keep());
        assert!(peer.sender().is_none());

        // Its subscription ended, and we never subscribed.
        drop(receiver);
        assert!(!peer.keep());

        // We are subscribed to the peer, and it may subscribe to us again.
        peer.subscribed = true;
        assert!(peer.keep());
        assert!(peer.sender().is_none());
    }

    /// A chunk set's bit `i` is the SSZ bitvector's bit `i`, both ways, so
    /// metadata means the same chunks on the wire as in the service.
    #[test]
    fn chunk_sets_and_bitvectors_name_the_same_chunks() {
        let indices = [0, 1, 9, 31, 32, 63];
        let set = bitmap(&indices);
        let wire = ProofChunkBitmap::from(set);
        for index in 0..TOTAL_PROOF_CHUNKS {
            assert_eq!(wire.get(index), Some(indices.contains(&index)), "{index}");
        }
        assert_eq!(ChunkSet::from(&wire), set);
        // Bit 9 is the second byte's second bit on the wire.
        assert_eq!(wire.as_bytes()[1], 0b10);
        assert_eq!(set.get(TOTAL_PROOF_CHUNKS), None);
        assert!(set.clone().set(TOTAL_PROOF_CHUNKS, true).is_err());
    }

    #[test]
    fn a_peer_is_dropped_once_its_penalties_add_up_and_forgiven_as_they_decay() {
        let mut penalties = PeerPenalties::default();
        let peer = PeerId::random();
        let start = Instant::now();
        for _ in 0..4 {
            assert!(!penalties.add(peer, Penalty::LowTolerance, start));
        }
        assert!(penalties.add(peer, Penalty::LowTolerance, start));

        // Nine mid-tolerance penalties are not enough; the score was forgotten
        // with the disconnect, so this starts over.
        for _ in 0..9 {
            assert!(!penalties.add(peer, Penalty::MidTolerance, start));
        }
        // An hour later most of it has decayed.
        let later = start + Duration::from_secs(3600);
        assert!(!penalties.add(peer, Penalty::MidTolerance, later));
    }

    #[test]
    fn aggregates_are_tracked_until_the_first_block_that_can_include_them() {
        let slot_duration = Duration::from_secs(12);
        let disparity = Duration::from_millis(500);
        let tracked_at = |time: Duration| tracked_slots(time, slot_duration, disparity).unwrap();
        let start_of = |slot: u64| slot_duration * slot as u32;

        // During its own slot and the two after it, as a block includes attestations from at
        // least two slots before it.
        for slot in [10, 11, 12] {
            assert!(tracked_at(start_of(slot)).contains(&10));
        }
        // Until the clock disparity after the end of that slot.
        assert!(tracked_at(start_of(13) + disparity - Duration::from_millis(1)).contains(&10));
        assert!(!tracked_at(start_of(13) + disparity).contains(&10));
        // Not from a future slot, but for the clock disparity.
        assert!(!tracked_at(start_of(10) - disparity - Duration::from_millis(1)).contains(&10));
        assert!(tracked_at(start_of(10) - disparity).contains(&10));
        // Nothing before genesis.
        assert!(tracked_slots(Duration::ZERO, slot_duration, disparity).is_none());

        // The service cleans up as the window moves on.
        assert_eq!(
            time_to_next_tracking_window(start_of(13), slot_duration, disparity),
            disparity
        );
    }

    #[test]
    fn the_header_matches_the_id_it_is_sent_under() {
        let aggregate = test_aggregate(7, &[0], 0);
        assert!(header_matches_id(&aggregate.signed_header, &aggregate.id));
        for id in [
            AggregateId {
                slot: SLOT + 1,
                ..aggregate.id
            },
            AggregateId {
                aggregator_index: 8,
                ..aggregate.id
            },
            AggregateId {
                header_root: Root::repeat_byte(1),
                ..aggregate.id
            },
        ] {
            assert!(!header_matches_id(&aggregate.signed_header, &id));
        }
    }

    #[test]
    fn an_aggregate_covers_the_ones_whose_attesters_it_includes() {
        let valid = test_aggregate(7, &[0, 1, 2], 0);
        // The same attesters count, as an identical aggregate would be ignored.
        for attesters in [&[0][..], &[1, 2], &[0, 1, 2]] {
            let other = test_aggregate(8, attesters, 1);
            assert!(covers(&valid.verified, &other.verified), "{attesters:?}");
        }
        for attesters in [&[3][..], &[0, 3], &[0, 1, 2, 3]] {
            let other = test_aggregate(8, attesters, 1);
            assert!(!covers(&valid.verified, &other.verified), "{attesters:?}");
        }
    }

    #[test]
    fn a_chunk_is_pushed_to_peers_that_are_not_known_to_have_it() {
        let test = test_aggregate(7, &[0], 0);
        let mut aggregate = test.tracked(&[3]);
        let mut peers = TopicPeers::new();
        // Peers need not have told us anything about the aggregate to be pushed to.
        let (_, silent_1) = add_peer(&mut peers);
        let (_, silent_2) = add_peer(&mut peers);
        let (holder, holder_receiver) = add_peer(&mut peers);
        announced(&mut aggregate, holder, &[3]);
        let (sender, sender_receiver) = add_peer(&mut peers);
        aggregate
            .peers
            .entry(sender)
            .or_default()
            .received_from
            .set(3, true)
            .unwrap();

        aggregate.push_chunk(3, &peers);

        // To `PUSH_PEERS` peers, with the header, as they are not known to hold it.
        assert_eq!(sent_chunks(&silent_1), vec![(3, true)]);
        assert_eq!(sent_chunks(&silent_2), vec![(3, true)]);
        // Not to the peer that announced it, nor to the one that sent it to us.
        assert!(sent(&holder_receiver).is_empty());
        assert!(sent(&sender_receiver).is_empty());

        // It was pushed to enough peers, so it is not pushed to another one.
        let (_, late_receiver) = add_peer(&mut peers);
        aggregate.push_chunk(3, &peers);
        assert!(sent(&late_receiver).is_empty());
    }

    #[test]
    fn the_header_is_sent_with_the_first_chunk_only() {
        let test = test_aggregate(7, &[0], 0);
        let mut aggregate = test.tracked(&[1, 2, 3]);
        let mut peers = TopicPeers::new();
        let (peer_id, receiver) = add_peer(&mut peers);
        let sender = peers[&peer_id].sender().unwrap();
        let have = aggregate.have();

        for index in [1, 2, 3] {
            assert!(aggregate.send_chunk(index, peer_id, sender, &have));
        }

        // The stream delivers in order, so the peer has the header before the later chunks.
        assert_eq!(
            sent_chunks(&receiver),
            vec![(1, true), (2, false), (3, false)]
        );
        assert!(aggregate.peers[&peer_id].knows_header);

        // A peer that is known to hold the header gets none: it announced a chunk, which it
        // verified against the header.
        let (announcer, announcer_receiver) = add_peer(&mut peers);
        announced(&mut aggregate, announcer, &[1]);
        let sender = peers[&announcer].sender().unwrap();
        assert!(aggregate.send_chunk(2, announcer, sender, &have));
        assert_eq!(sent_chunks(&announcer_receiver), vec![(2, false)]);

        // A peer that only requests, with an empty `have`, is not known to hold it.
        let (requester, requester_receiver) = add_peer(&mut peers);
        announced(&mut aggregate, requester, &[]);
        let sender = peers[&requester].sender().unwrap();
        assert!(aggregate.send_chunk(2, requester, sender, &have));
        assert_eq!(sent_chunks(&requester_receiver), vec![(2, true)]);
    }

    #[test]
    fn every_chunk_is_pushed_once_before_any_is_pushed_twice() {
        let test = test_aggregate(7, &[0], 0);
        let all = (0..TOTAL_PROOF_CHUNKS).collect::<Vec<_>>();
        let mut aggregate = test.tracked(&all);
        let mut peers = TopicPeers::new();
        let receivers = (0..4).map(|_| add_peer(&mut peers).1).collect::<Vec<_>>();

        aggregate.push_chunks(all.clone(), &peers);

        let pushed = receivers.iter().map(sent_chunks).collect::<Vec<_>>();
        // Every chunk was pushed to `PUSH_PEERS` peers, and never twice to the same one.
        let mut pushes = vec![0; TOTAL_PROOF_CHUNKS];
        for chunks in &pushed {
            let mut seen = std::collections::HashSet::new();
            for (index, _) in chunks {
                assert!(seen.insert(*index));
                pushes[*index as usize] += 1;
            }
            // No peer got more than its share.
            assert!(chunks.len() <= max_pushes_per_peer(4));
            // The header came with the first chunk each peer got.
            assert!(
                chunks
                    .iter()
                    .enumerate()
                    .all(|(position, (_, with_header))| { *with_header == (position == 0) })
            );
        }
        assert!(pushes.iter().all(|pushes| *pushes == PUSH_PEERS));
    }

    #[test]
    fn chunks_are_not_pushed_after_the_push_phase() {
        let test = test_aggregate(7, &[0], 0);
        let mut peers = TopicPeers::new();
        let (_, receiver) = add_peer(&mut peers);

        // A chunk a peer sent us long after the first one arrived is only announced.
        let mut aggregate = test.tracked(&[3]);
        aggregate.first_chunk_at = Instant::now().checked_sub(PUSH_PHASE);
        aggregate.push_chunk(3, &peers);
        assert!(sent(&receiver).is_empty());

        // The aggregate we publish received no chunk, and is pushed whenever.
        let mut aggregate = test.tracked(&[3]);
        aggregate.push_chunk(3, &peers);
        assert_eq!(sent_chunks(&receiver), vec![(3, true)]);
    }

    #[test]
    fn what_we_have_is_announced_once_it_changed() {
        let test = test_aggregate(7, &[0], 0);
        let mut peers = TopicPeers::new();
        let (_, receiver) = add_peer(&mut peers);

        // A node that holds no chunk has nothing to announce.
        let mut aggregate = test.tracked(&[]);
        aggregate.announce(&peers);
        assert!(sent(&receiver).is_empty());

        let mut aggregate = test.tracked(&[3]);
        aggregate.announce(&peers);
        let messages = sent(&receiver);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].piece.is_none());
        assert_eq!(messages[0].metadata, Some(metadata(&[3], &[])));

        // Not again while nothing changed.
        aggregate.announce(&peers);
        assert!(sent(&receiver).is_empty());

        aggregate.chunks[4] = Chunk::valid(test.chunks[4].clone());
        aggregate.announce(&peers);
        assert_eq!(sent(&receiver)[0].metadata, Some(metadata(&[3, 4], &[])));
    }

    #[test]
    fn a_chunk_carries_our_metadata_if_it_is_news_to_the_peer() {
        let test = test_aggregate(7, &[0], 0);
        let mut aggregate = test.tracked(&[3, 4]);
        let mut peers = TopicPeers::new();
        let (peer_id, receiver) = add_peer(&mut peers);
        let sender = peers[&peer_id].sender().unwrap();
        let have = aggregate.have();

        assert!(aggregate.send_chunk(3, peer_id, sender, &have));
        assert!(aggregate.send_chunk(4, peer_id, sender, &have));
        let messages = sent(&receiver);
        assert_eq!(messages[0].metadata, Some(metadata(&[3, 4], &[])));
        assert!(messages[1].metadata.is_none());
    }

    #[test]
    fn missing_chunks_are_requested_from_the_peers_that_announced_them() {
        let test = test_aggregate(7, &[0], 0);
        let mut aggregate = test.tracked(&[0]);
        let mut peers = TopicPeers::new();
        let (has_1, has_1_receiver) = add_peer(&mut peers);
        announced(&mut aggregate, has_1, &[0, 1]);
        let (has_1_2, has_1_2_receiver) = add_peer(&mut peers);
        announced(&mut aggregate, has_1_2, &[1, 2]);
        let (_, silent_receiver) = add_peer(&mut peers);

        // Not within `REQUEST_DELAY` after we start to track the aggregate.
        aggregate.request_missing_chunks(&peers, aggregate.tracked_since);
        assert!(sent(&has_1_receiver).is_empty());

        let now = after_request_delay(&aggregate);
        aggregate.request_missing_chunks(&peers, now);
        // The chunk that the fewest peers announced first, and one request per peer at a time.
        assert_eq!(requested_chunks(&has_1_2_receiver), vec![2]);
        assert_eq!(requested_chunks(&has_1_receiver), vec![1]);
        assert!(sent(&silent_receiver).is_empty());

        // Nothing more while the requests are outstanding.
        aggregate.request_missing_chunks(&peers, now);
        assert!(sent(&has_1_receiver).is_empty());
        assert!(sent(&has_1_2_receiver).is_empty());

        // A chunk that was not received in time is requested from another peer that announced
        // it.
        let timed_out = now + aggregate.request_timeout();
        aggregate.chunks[2] = Chunk::valid(test.chunks[2].clone());
        aggregate.request_missing_chunks(&peers, timed_out);
        assert_eq!(requested_chunks(&has_1_2_receiver), vec![1]);
        assert!(sent(&has_1_receiver).is_empty());
    }

    #[test]
    fn a_request_tells_the_peer_what_we_have() {
        let test = test_aggregate(7, &[0], 0);
        let mut aggregate = test.tracked(&[0]);
        let mut peers = TopicPeers::new();
        let (peer_id, receiver) = add_peer(&mut peers);
        announced(&mut aggregate, peer_id, &[1]);

        let now = after_request_delay(&aggregate);
        aggregate.request_missing_chunks(&peers, now);
        assert_eq!(sent(&receiver)[0].metadata, Some(metadata(&[0], &[1])));
        // So what we have is not announced to the peer again.
        aggregate.announce(&peers);
        assert!(sent(&receiver).is_empty());
    }

    #[test]
    fn a_single_chunk_is_requested_while_we_hold_no_header() {
        let test = test_aggregate(7, &[0], 0);
        let mut aggregate = Aggregate::new(test.id);
        let mut peers = TopicPeers::new();
        let receivers = (0..3)
            .map(|_| {
                let (peer_id, receiver) = add_peer(&mut peers);
                announced(&mut aggregate, peer_id, &[0, 1, 2, 3]);
                receiver
            })
            .collect::<Vec<_>>();

        let now = after_request_delay(&aggregate);
        aggregate.request_missing_chunks(&peers, now);
        aggregate.request_missing_chunks(&peers, now);

        // The chunk brings the header, and so would every further one. It is requested with an
        // empty `have`, so the peer knows to send the header along.
        let requests = receivers
            .iter()
            .flat_map(sent)
            .filter_map(|message| message.metadata)
            .collect::<Vec<_>>();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].have.is_zero());
        assert_eq!(indices(&requests[0].request).len(), 1);

        // No chunks are requested while a header is being checked: the ones that wait for it may
        // be all we lack.
        let mut aggregate = Aggregate::new(test.id);
        aggregate.header = HeaderState::Verifying {
            from: PeerId::random(),
            since: Instant::now(),
            signed_header: test.signed_header.clone(),
            pending: vec![],
        };
        for peer_id in peers.keys() {
            announced(&mut aggregate, *peer_id, &[0, 1, 2, 3]);
        }
        let now = after_request_delay(&aggregate);
        aggregate.request_missing_chunks(&peers, now);
        assert!(receivers.iter().all(|receiver| sent(receiver).is_empty()));
        assert!(aggregate.next_request_at(now).is_none());
        // The service wakes up to give up on the header if it is not checked in time.
        assert!(aggregate.next_wake(now).is_some());
    }

    #[test]
    fn chunks_of_aggregates_of_no_use_are_not_requested() {
        let test = test_aggregate(7, &[0], 0);
        let mut peers = TopicPeers::new();
        let (peer_id, receiver) = add_peer(&mut peers);

        for make_useless in [
            (|aggregate| aggregate.invalid = true) as fn(&mut Aggregate),
            |aggregate| aggregate.covered = true,
            |aggregate| aggregate.complete = true,
        ] {
            let mut aggregate = test.tracked(&[0]);
            announced(&mut aggregate, peer_id, &[1]);
            make_useless(&mut aggregate);
            let now = after_request_delay(&aggregate);
            aggregate.request_missing_chunks(&peers, now);
            assert!(sent(&receiver).is_empty());
            assert!(aggregate.next_request_at(now).is_none());
        }

        // An invalid aggregate is not pushed nor announced either.
        let mut aggregate = test.tracked(&[0]);
        aggregate.invalid = true;
        aggregate.push_chunk(0, &peers);
        aggregate.announce(&peers);
        assert!(sent(&receiver).is_empty());
    }

    /// The slot duration and clock disparity of the rigs' clocks.
    const SLOT_DURATION: Duration = Duration::from_secs(12);
    const DISPARITY: Duration = Duration::from_millis(500);
    /// The fork digest of the rigs' topic, and of every slot.
    const FORK_DIGEST: ForkDigest = [1, 2, 3, 4];

    /// What the service did through its host, and the clock it reads.
    #[derive(Default)]
    struct MockState {
        /// The time since genesis.
        now: Duration,
        /// The checks the service asked for, as `"header"` or `"aggregate"`.
        work: Vec<&'static str>,
        /// The peers the service reported, with the reasons.
        reports: Vec<(PeerId, &'static str)>,
    }

    /// A [`Host`] whose clock the test sets and that only records what the
    /// service asks of it.
    #[derive(Clone)]
    struct MockHost {
        state: Arc<Mutex<MockState>>,
        aggregators: Vec<ValidatorIndex>,
    }

    impl Host for MockHost {
        fn fork_digest_at(&self, _slot: Slot) -> ForkDigest {
            FORK_DIGEST
        }

        fn aggregators_at(&self, _slot: Slot) -> Option<Vec<ValidatorIndex>> {
            Some(self.aggregators.clone())
        }

        fn tracked_slots(&self) -> Option<RangeInclusive<Slot>> {
            let now = self.state.lock().unwrap().now;
            tracked_slots(now, SLOT_DURATION, DISPARITY)
        }

        fn time_to_next_tracking_window(&self) -> Duration {
            let now = self.state.lock().unwrap().now;
            time_to_next_tracking_window(now, SLOT_DURATION, DISPARITY)
        }

        fn check_header(
            &self,
            _id: AggregateId,
            _peer_id: PeerId,
            _signed_header: Arc<SignedAggregateHeader>,
        ) -> Result<(), HostError> {
            self.state.lock().unwrap().work.push("header");
            Ok(())
        }

        fn check_aggregate(
            &self,
            _header: Arc<CheckedHeader>,
            _chunks: Vec<Arc<ProofChunk>>,
            _peer_id: PeerId,
        ) -> Result<(), HostError> {
            self.state.lock().unwrap().work.push("aggregate");
            Ok(())
        }

        fn report_peer(&self, peer_id: PeerId, _penalty: Penalty, reason: &'static str) {
            self.state.lock().unwrap().reports.push((peer_id, reason));
        }
    }

    /// A dissemination service to pass the messages of peers to. It is not
    /// run, so nothing arrives on its channels.
    struct Rig {
        service: AggregateDisseminationService<MockHost>,
        state: Arc<Mutex<MockState>>,
        /// A validator that is an aggregator at `SLOT`, and one that is not.
        aggregator: u64,
        no_aggregator: u64,
    }

    /// Returns a new service, at the start of `SLOT`, that tracks no
    /// aggregate.
    fn rig() -> Rig {
        let state = Arc::new(Mutex::new(MockState {
            now: SLOT_DURATION * SLOT as u32,
            ..Default::default()
        }));
        let (aggregator, no_aggregator) = (5, 6);
        let host = MockHost {
            state: state.clone(),
            aggregators: vec![aggregator, 7, 8],
        };
        let service = AggregateDisseminationService::new(
            FORK_DIGEST,
            mpsc::channel(1).1,
            async_channel::unbounded().1,
            oneshot::channel().1,
            host,
        );
        Rig {
            service,
            state,
            aggregator,
            no_aggregator,
        }
    }

    impl Rig {
        /// Makes the service track `test`, as it does from the first message about it, without
        /// a header.
        fn track(&mut self, test: &TestAggregate) {
            self.service
                .aggregates
                .insert(test.id, Aggregate::new(test.id));
        }

        /// Makes the service track `test` and hold its header, and the chunks at `valid`.
        fn hold(&mut self, test: &TestAggregate, valid: &[usize]) {
            self.service.aggregates.insert(test.id, test.tracked(valid));
            self.service.on_header_held(test.id);
        }

        fn aggregate(&mut self, test: &TestAggregate) -> &mut Aggregate {
            self.service.aggregates.get_mut(&test.id).unwrap()
        }

        fn tracks(&self, test: &TestAggregate) -> bool {
            self.service.aggregates.contains_key(&test.id)
        }

        /// Whether we hold the chunk at `index` of `test`.
        fn holds_chunk(&mut self, test: &TestAggregate, index: usize) -> bool {
            matches!(self.aggregate(test).chunks[index], Chunk::Valid { .. })
        }

        fn add_peer(&mut self) -> (PeerId, async_channel::Receiver<ObjectPieces>) {
            add_peer(&mut self.service.peers)
        }

        /// Passes a message of `peer_id` about `test` to the service.
        fn receive(
            &mut self,
            test: &TestAggregate,
            peer_id: PeerId,
            metadata: Option<Metadata>,
            piece: Option<AggregatePiece>,
        ) {
            let message = Message {
                id: test.id,
                metadata,
                piece,
            };
            self.service.handle_message(peer_id, message).unwrap();
        }

        /// Returns the peers the service reported since the last call, with the reasons.
        fn reports(&mut self) -> Vec<(PeerId, &'static str)> {
            std::mem::take(&mut self.state.lock().unwrap().reports)
        }

        /// Returns the checks the service asked for since the last call.
        fn work(&mut self) -> Vec<&'static str> {
            std::mem::take(&mut self.state.lock().unwrap().work)
        }

        /// Sets the time since genesis.
        fn set_now(&mut self, now: Duration) {
            self.state.lock().unwrap().now = now;
        }

        /// Tells the service that the header of `test` that `peer_id` sent passed the checks.
        fn header_passes(&mut self, test: &TestAggregate, peer_id: PeerId) {
            self.service
                .on_header_verified(test.id, peer_id, Ok(test.verified.clone()));
        }
    }

    /// Runs the cases below, each on a service of its own. One test, as in
    /// Lighthouse, where a rig was slow to build.
    #[tokio::test]
    async fn handle_message() {
        a_header_is_checked_before_its_chunks_are_kept(rig());
        chunks_without_a_header_are_dropped_while_we_hold_none(rig());
        a_header_of_another_aggregate_is_rejected(rig());
        a_header_is_not_checked_if_its_chunk_is_invalid(rig());
        the_next_header_is_checked_if_one_is_invalid(rig());
        valid_chunks_are_kept_and_pushed_on(rig());
        invalid_chunks_are_rejected_and_their_sender_ignored(rig());
        a_chunk_sent_twice_is_penalized(rig());
        a_chunk_with_an_index_out_of_bounds_is_penalized(rig());
        the_aggregate_is_handed_over_once_every_chunk_is_valid(rig());
        a_peer_that_lost_a_chunk_is_penalized(rig());
        requested_chunks_are_served_once_with_the_header(rig());
        requests_for_held_chunks_are_penalized(rig());
        an_invalid_aggregate_is_no_longer_disseminated(rig());
        covered_aggregates_are_no_longer_requested(rig());
        one_header_is_held_per_slot_and_aggregator(rig());
        headerless_aggregates_are_bounded_per_peer(rig());
        untracked_aggregates_are_only_tracked_if_their_id_passes(rig());
        a_published_aggregate_is_pushed_and_announced(rig());
        aggregates_are_dropped_after_their_tracking_window(rig());
    }

    fn a_header_is_checked_before_its_chunks_are_kept(mut rig: Rig) {
        let test = test_aggregate(7, &[0], 0);
        rig.track(&test);
        let (sender, sender_receiver) = rig.add_peer();
        let (other, other_receiver) = rig.add_peer();

        // The first chunk brings the header, which the beacon processor checks.
        rig.receive(&test, sender, None, Some(test.piece(3, true)));
        assert_eq!(rig.work(), vec!["header"]);
        // Until it passes, the chunk is neither kept nor pushed on.
        assert!(!rig.holds_chunk(&test, 3));
        assert!(sent(&other_receiver).is_empty());
        // Chunks that arrive meanwhile wait, with or without a header, which is not checked
        // again.
        rig.receive(&test, other, None, Some(test.piece(4, true)));
        rig.receive(&test, sender, None, Some(test.piece(5, false)));
        assert!(rig.work().is_empty());
        assert!(!rig.holds_chunk(&test, 4));

        rig.header_passes(&test, sender);

        // The chunks are kept now, and pushed on: to each peer but the one that sent it.
        for index in [3, 4, 5] {
            assert!(rig.holds_chunk(&test, index));
        }
        assert_eq!(rig.service.held[&(SLOT, 7)], test.id.header_root);
        // Both peers sent us a valid chunk, so they hold the header, and get none.
        assert_eq!(sent_chunks(&other_receiver), vec![(3, false), (5, false)]);
        assert_eq!(sent_chunks(&sender_receiver), vec![(4, false)]);
        assert!(rig.reports().is_empty());

        // Further headers are ignored without being checked.
        rig.receive(&test, sender, None, Some(test.piece(6, true)));
        assert!(rig.work().is_empty());
        assert!(rig.holds_chunk(&test, 6));
    }

    fn chunks_without_a_header_are_dropped_while_we_hold_none(mut rig: Rig) {
        let test = test_aggregate(7, &[0], 0);
        rig.track(&test);
        let (sender, _sender_receiver) = rig.add_peer();

        // The whole message is dropped, and the peer is not penalized: it had reason to believe
        // that we hold the header.
        rig.receive(
            &test,
            sender,
            Some(metadata(&[3], &[])),
            Some(test.piece(3, false)),
        );
        assert!(rig.work().is_empty());
        assert!(rig.reports().is_empty());
        assert!(rig.aggregate(&test).peers[&sender].has.is_none());

        // It is not held against the peer if it sends the chunk with the header later.
        rig.receive(&test, sender, None, Some(test.piece(3, true)));
        assert_eq!(rig.work(), vec!["header"]);
        assert!(rig.reports().is_empty());
    }

    fn a_header_of_another_aggregate_is_rejected(mut rig: Rig) {
        let test = test_aggregate(7, &[0], 0);
        let other = test_aggregate(7, &[0], 1);
        rig.track(&test);
        let (sender, _sender_receiver) = rig.add_peer();

        // The header of another aggregate of the aggregator, under the ID of this one.
        rig.receive(&test, sender, None, Some(other.piece(3, true)));
        assert!(rig.work().is_empty());
        assert_eq!(rig.reports(), vec![(sender, "waggle_header_mismatch")]);
        assert!(rig.aggregate(&test).peers[&sender].banned);
    }

    fn a_header_is_not_checked_if_its_chunk_is_invalid(mut rig: Rig) {
        let test = test_aggregate(7, &[0], 0);
        rig.track(&test);
        let (sender, _sender_receiver) = rig.add_peer();

        // A header is only kept if the chunk it arrived with is valid, which is cheap to check.
        rig.receive(&test, sender, None, Some(test.altered_piece(3, true)));
        assert!(rig.work().is_empty());
        assert_eq!(rig.reports(), vec![(sender, "waggle_invalid_chunk")]);
        assert!(matches!(rig.aggregate(&test).header, HeaderState::Unknown));
    }

    fn the_next_header_is_checked_if_one_is_invalid(mut rig: Rig) {
        let test = test_aggregate(7, &[0], 0);
        rig.track(&test);
        let (forger, _forger_receiver) = rig.add_peer();
        let (honest, _honest_receiver) = rig.add_peer();
        let (bystander, _bystander_receiver) = rig.add_peer();

        rig.receive(&test, forger, None, Some(test.piece(3, true)));
        rig.receive(&test, bystander, None, Some(test.piece(4, false)));
        rig.receive(&test, honest, None, Some(test.piece(5, true)));
        assert_eq!(rig.work(), vec!["header"]);

        // The header of the first peer is not validly signed. The peer is penalized, and its
        // chunk dropped. The header that came with the chunk of another peer is checked next.
        rig.service
            .on_header_verified(test.id, forger, Err(HeaderRejection::Invalid));
        assert_eq!(rig.reports(), vec![(forger, "waggle_invalid_header")]);
        assert_eq!(rig.work(), vec!["header"]);
        assert!(matches!(
            &rig.aggregate(&test).header,
            HeaderState::Verifying { from, pending, .. } if *from == honest && pending.len() == 2
        ));

        // A late result for the header we gave up on changes nothing.
        rig.header_passes(&test, forger);
        assert!(!rig.holds_chunk(&test, 5));

        rig.header_passes(&test, honest);
        assert!(!rig.holds_chunk(&test, 3));
        assert!(rig.holds_chunk(&test, 4));
        assert!(rig.holds_chunk(&test, 5));
        assert!(rig.reports().is_empty());

        // A header that could not be checked is dropped without penalizing its sender. With no
        // other header at hand, we are back to holding none.
        let test = test_aggregate(8, &[0], 0);
        rig.track(&test);
        rig.receive(&test, honest, None, Some(test.piece(3, true)));
        rig.receive(&test, bystander, None, Some(test.piece(4, false)));
        assert_eq!(rig.work(), vec!["header"]);
        rig.service
            .on_header_verified(test.id, honest, Err(HeaderRejection::Ignored));
        assert!(rig.reports().is_empty());
        assert!(rig.work().is_empty());
        assert!(matches!(rig.aggregate(&test).header, HeaderState::Unknown));
        // The peers whose chunks were dropped did not send us chunks we could use, so they may
        // send them again.
        rig.receive(&test, bystander, None, Some(test.piece(4, true)));
        assert!(rig.reports().is_empty());
        assert_eq!(rig.work(), vec!["header"]);

        // The beacon processor may drop the header without telling. We give up on it after a
        // while, without penalizing its sender, so that the aggregate is not stuck.
        let now = Instant::now();
        rig.service.give_up_on_unchecked_headers(now);
        assert!(matches!(
            rig.aggregate(&test).header,
            HeaderState::Verifying { .. }
        ));
        rig.service
            .give_up_on_unchecked_headers(now + HEADER_VERIFICATION_TIMEOUT);
        assert!(matches!(rig.aggregate(&test).header, HeaderState::Unknown));
        assert!(rig.reports().is_empty());
    }

    fn valid_chunks_are_kept_and_pushed_on(mut rig: Rig) {
        let test = test_aggregate(7, &[0], 0);
        rig.hold(&test, &[]);
        let (sender, sender_receiver) = rig.add_peer();
        let (_, other_receiver) = rig.add_peer();

        rig.receive(&test, sender, None, Some(test.piece(3, false)));

        // The chunk is kept, and pushed to the other peer, which is not known to hold the
        // header.
        assert!(rig.holds_chunk(&test, 3));
        assert_eq!(sent_chunks(&other_receiver), vec![(3, true)]);
        // Its sender is not told that we have it right away, but with the next announcements.
        assert!(sent(&sender_receiver).is_empty());
        assert!(rig.aggregate(&test).announcement_pending);
        assert!(rig.aggregate(&test).peers[&sender].knows_header);
        assert!(rig.reports().is_empty());

        // Another peer may send the chunk as well, which changes nothing.
        rig.receive(&test, PeerId::random(), None, Some(test.piece(3, false)));
        assert!(sent(&other_receiver).is_empty());
        assert!(rig.reports().is_empty());

        rig.service.flush_announcements();
        assert_eq!(
            sent(&sender_receiver)[0].metadata,
            Some(metadata(&[3], &[]))
        );
    }

    fn invalid_chunks_are_rejected_and_their_sender_ignored(mut rig: Rig) {
        let test = test_aggregate(7, &[0], 0);
        rig.hold(&test, &[]);
        let (_, other_receiver) = rig.add_peer();

        // The inclusion proof doesn't fit the chunk.
        let peer_id = PeerId::random();
        rig.receive(&test, peer_id, None, Some(test.altered_piece(3, false)));
        assert!(!rig.holds_chunk(&test, 3));
        assert!(sent(&other_receiver).is_empty());
        assert_eq!(rig.reports(), vec![(peer_id, "waggle_invalid_chunk")]);

        // The peer is ignored for the rest of the aggregate, also if it sends a valid chunk.
        rig.receive(&test, peer_id, None, Some(test.piece(4, false)));
        assert!(!rig.holds_chunk(&test, 4));
        assert!(rig.reports().is_empty());

        // A chunk that differs from the one we hold is invalid as well.
        rig.hold(&test, &[5]);
        let peer_id = PeerId::random();
        rig.receive(&test, peer_id, None, Some(test.altered_piece(5, false)));
        assert_eq!(rig.reports(), vec![(peer_id, "waggle_invalid_chunk")]);
    }

    fn a_chunk_sent_twice_is_penalized(mut rig: Rig) {
        let test = test_aggregate(7, &[0], 0);
        rig.hold(&test, &[]);
        let peer_id = PeerId::random();

        rig.receive(&test, peer_id, None, Some(test.piece(3, false)));
        assert!(rig.reports().is_empty());
        rig.receive(&test, peer_id, None, Some(test.piece(3, false)));
        assert_eq!(rig.reports(), vec![(peer_id, "waggle_duplicate_chunk")]);
    }

    fn a_chunk_with_an_index_out_of_bounds_is_penalized(mut rig: Rig) {
        let test = test_aggregate(7, &[0], 0);
        rig.hold(&test, &[]);
        let peer_id = PeerId::random();

        // The inclusion proof only covers the low bits of the index, so this chunk would
        // verify as the one at index 3.
        let mut piece = test.piece(3, false);
        piece.chunk.index += TOTAL_PROOF_CHUNKS as u8;
        rig.receive(&test, peer_id, None, Some(piece));
        assert!(!rig.holds_chunk(&test, 3));
        assert_eq!(
            rig.reports(),
            vec![(peer_id, "waggle_chunk_index_out_of_bounds")]
        );
    }

    fn the_aggregate_is_handed_over_once_every_chunk_is_valid(mut rig: Rig) {
        let test = test_aggregate(7, &[0], 0);
        let all_but_last = (0..TOTAL_PROOF_CHUNKS - 1).collect::<Vec<_>>();
        rig.hold(&test, &all_but_last);
        assert!(rig.work().is_empty());

        rig.receive(
            &test,
            PeerId::random(),
            None,
            Some(test.piece(TOTAL_PROOF_CHUNKS - 1, false)),
        );
        assert_eq!(rig.work(), vec!["aggregate"]);
        assert!(rig.aggregate(&test).complete);
        // What we have is announced right away, so that peers stop sending us chunks.
        assert!(rig.service.announcements_pending());
    }

    fn a_peer_that_lost_a_chunk_is_penalized(mut rig: Rig) {
        let test = test_aggregate(7, &[0], 0);
        rig.hold(&test, &[]);
        let peer_id = PeerId::random();

        rig.receive(&test, peer_id, Some(metadata(&[1, 2], &[])), None);
        rig.receive(&test, peer_id, Some(metadata(&[1, 2, 3], &[])), None);
        assert!(rig.reports().is_empty());
        rig.receive(&test, peer_id, Some(metadata(&[2, 3], &[])), None);
        assert_eq!(rig.reports(), vec![(peer_id, "waggle_lost_chunk")]);
    }

    fn requested_chunks_are_served_once_with_the_header(mut rig: Rig) {
        let test = test_aggregate(7, &[0], 0);
        rig.hold(&test, &[1, 2]);
        let (peer_id, receiver) = rig.add_peer();

        // A peer that holds no chunk requests its first one with an empty `have`. It gets the
        // header along, and what we have.
        rig.receive(&test, peer_id, Some(metadata(&[], &[1])), None);
        let messages = sent(&receiver);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].metadata, Some(metadata(&[1, 2], &[])));
        let piece = messages[0].piece.as_ref().unwrap();
        assert_eq!(piece.chunk.index, 1);
        assert_eq!(piece.signed_header.len(), 1);

        // The next one comes without, and a chunk we lack is not served.
        rig.receive(&test, peer_id, Some(metadata(&[1], &[2, 3])), None);
        assert_eq!(sent_chunks(&receiver), vec![(2, false)]);

        // We never send a peer a chunk twice.
        let (pushed_to, pushed_to_receiver) = rig.add_peer();
        rig.aggregate(&test)
            .peers
            .entry(pushed_to)
            .or_default()
            .sent_to
            .set(1, true)
            .unwrap();
        rig.receive(&test, pushed_to, Some(metadata(&[], &[1])), None);
        assert!(sent_chunks(&pushed_to_receiver).is_empty());
        assert!(rig.reports().is_empty());
    }

    fn requests_for_held_chunks_are_penalized(mut rig: Rig) {
        let test = test_aggregate(7, &[0], 0);
        rig.hold(&test, &[1]);

        // A chunk the peer announced.
        let (peer_id, receiver) = rig.add_peer();
        rig.receive(&test, peer_id, Some(metadata(&[1], &[1])), None);
        assert_eq!(
            rig.reports(),
            vec![(peer_id, "waggle_request_for_held_chunk")]
        );
        assert!(sent_chunks(&receiver).is_empty());

        // A chunk the peer sent us.
        let (peer_id, receiver) = rig.add_peer();
        rig.receive(&test, peer_id, None, Some(test.piece(1, false)));
        rig.receive(&test, peer_id, Some(metadata(&[], &[1])), None);
        assert_eq!(
            rig.reports(),
            vec![(peer_id, "waggle_request_for_held_chunk")]
        );
        assert!(sent_chunks(&receiver).is_empty());
    }

    fn an_invalid_aggregate_is_no_longer_disseminated(mut rig: Rig) {
        let test = test_aggregate(7, &[0], 0);
        let all = (0..TOTAL_PROOF_CHUNKS).collect::<Vec<_>>();
        rig.hold(&test, &all);
        let (peer_id, receiver) = rig.add_peer();

        // The proof did not verify. No peer is penalized: every chunk was committed to by the
        // aggregator.
        rig.service
            .on_aggregate_verified(test.id, AggregateOutcome::Invalid);
        assert!(rig.reports().is_empty());

        // Its chunks are neither served, pushed nor announced anymore.
        rig.receive(&test, peer_id, Some(metadata(&[], &[1])), None);
        rig.service.try_inform_new_peer(peer_id);
        rig.service.flush_announcements();
        assert!(sent(&receiver).is_empty());
        // The header stays held: the aggregator signed no other one, unless it is faulty.
        assert_eq!(rig.service.held[&(SLOT, 7)], test.id.header_root);
    }

    fn covered_aggregates_are_no_longer_requested(mut rig: Rig) {
        // Two aggregates of the same committee by different aggregators, the attesters of one
        // among those of the other, and a third with another attester.
        let large = test_aggregate(7, &[0, 1], 0);
        let small = test_aggregate(8, &[0], 1);
        let other = test_aggregate(9, &[2], 2);
        rig.hold(&large, &[]);
        rig.hold(&small, &[1]);
        rig.hold(&other, &[]);
        let (peer_id, receiver) = rig.add_peer();

        // The large one passed every check. The small one would be ignored once complete.
        rig.service
            .on_aggregate_verified(large.id, AggregateOutcome::Valid);
        assert!(rig.aggregate(&small).covered);
        assert!(!rig.aggregate(&other).covered);
        assert!(!rig.aggregate(&large).covered);

        // We still serve the chunks of the small one that we hold.
        rig.receive(&small, peer_id, Some(metadata(&[], &[1])), None);
        assert_eq!(sent_chunks(&receiver), vec![(1, true)]);

        // An aggregate whose header we get later is covered as well.
        let late = test_aggregate(10, &[1], 3);
        rig.track(&late);
        rig.receive(&late, peer_id, None, Some(late.piece(3, true)));
        rig.header_passes(&late, peer_id);
        assert!(rig.aggregate(&late).covered);
    }

    fn one_header_is_held_per_slot_and_aggregator(mut rig: Rig) {
        // A faulty aggregator signed two headers for the slot.
        let first = test_aggregate(rig.aggregator, &[0], 0);
        let second = test_aggregate(rig.aggregator, &[0], 1);
        assert_ne!(first.id, second.id);
        rig.track(&first);
        rig.track(&second);
        let (peer_1, _receiver_1) = rig.add_peer();
        let (peer_2, _receiver_2) = rig.add_peer();

        rig.receive(&first, peer_1, None, Some(first.piece(3, true)));
        rig.receive(&second, peer_2, None, Some(second.piece(3, true)));
        assert_eq!(rig.work(), vec!["header", "header"]);

        // We keep the first valid header, and stop tracking the other aggregate.
        rig.header_passes(&first, peer_1);
        assert!(rig.tracks(&first));
        assert!(!rig.tracks(&second));
        rig.header_passes(&second, peer_2);
        assert!(!rig.tracks(&second));
        assert_eq!(
            rig.service.held[&(SLOT, rig.aggregator)],
            first.id.header_root
        );

        // Messages about the other one are ignored from now on, without penalty.
        assert_eq!(rig.service.check_aggregate_id(&second.id), IdCheck::Ignore);
        rig.receive(&second, peer_2, None, Some(second.piece(4, true)));
        assert!(!rig.tracks(&second));
        assert!(rig.work().is_empty());
        assert!(rig.reports().is_empty());
    }

    fn headerless_aggregates_are_bounded_per_peer(mut rig: Rig) {
        // Aggregates of the same slot and aggregator, of which we hold no header.
        let made_up = (0..4)
            .map(|seed| test_aggregate(7, &[0], seed))
            .collect::<Vec<_>>();
        let (peer_id, _receiver) = rig.add_peer();
        let (other, _other_receiver) = rig.add_peer();

        // A peer only counts for the one it announced last, so it can't make us remember more
        // than one per slot and aggregator.
        for test in &made_up {
            rig.track(test);
            rig.receive(test, peer_id, Some(metadata(&[1], &[])), None);
        }
        assert_eq!(rig.service.aggregates.len(), 1);
        assert!(rig.tracks(&made_up[3]));

        // An aggregate that another peer announced too stays tracked.
        rig.track(&made_up[0]);
        rig.receive(&made_up[0], other, Some(metadata(&[1], &[])), None);
        rig.receive(&made_up[0], peer_id, Some(metadata(&[1], &[])), None);
        assert!(!rig.tracks(&made_up[3]));
        rig.track(&made_up[1]);
        rig.receive(&made_up[1], peer_id, Some(metadata(&[1], &[])), None);
        assert!(rig.tracks(&made_up[0]));
        assert!(rig.tracks(&made_up[1]));
        assert!(!rig.aggregate(&made_up[0]).peers.contains_key(&peer_id));

        // Aggregates of other aggregators are not affected.
        let another = test_aggregate(8, &[0], 0);
        rig.track(&another);
        rig.receive(&another, peer_id, Some(metadata(&[1], &[])), None);
        assert!(rig.tracks(&made_up[1]));
        assert!(rig.reports().is_empty());
    }

    fn untracked_aggregates_are_only_tracked_if_their_id_passes(mut rig: Rig) {
        let (peer_id, _receiver) = rig.add_peer();

        // An aggregate of an aggregator of its slot is tracked from the first message about it,
        // which may be an announcement or bring a chunk.
        let test = test_aggregate(rig.aggregator, &[0], 0);
        assert_eq!(rig.service.check_aggregate_id(&test.id), IdCheck::Track);
        rig.receive(&test, peer_id, Some(metadata(&[1], &[])), None);
        assert!(rig.tracks(&test));
        assert!(rig.reports().is_empty());

        // No eligible aggregator can have signed the header of this one, as far as we can
        // tell, so it is not tracked. Its sender is not penalized: on another fork, its
        // aggregator can be eligible.
        let ineligible = test_aggregate(rig.no_aggregator, &[0], 0);
        assert_eq!(
            rig.service.check_aggregate_id(&ineligible.id),
            IdCheck::Ignore
        );
        rig.receive(&ineligible, peer_id, None, Some(ineligible.piece(3, true)));
        assert!(!rig.tracks(&ineligible));
        assert!(rig.work().is_empty());
        assert!(rig.reports().is_empty());

        // Nor is one of a future slot tracked. It is dropped without penalty, whoever its
        // aggregator is.
        for aggregator_index in [rig.aggregator, rig.no_aggregator] {
            let id = AggregateId {
                slot: SLOT + 1,
                aggregator_index,
                ..test.id
            };
            assert_eq!(rig.service.check_aggregate_id(&id), IdCheck::Ignore);
        }

        // Nor one on the topic of another fork digest than the one at its slot.
        let fork_digest = rig.service.fork_digest;
        rig.service.fork_digest = [0xff; 4];
        assert_eq!(rig.service.check_aggregate_id(&test.id), IdCheck::Ignore);
        rig.service.fork_digest = fork_digest;
        assert_eq!(rig.service.check_aggregate_id(&test.id), IdCheck::Track);

        // Nor one whose tracking window has ended.
        let after_window = SLOT + TRACKED_SLOTS_AFTER_OWN + 1;
        rig.set_now(SLOT_DURATION * after_window as u32 + DISPARITY);
        assert_eq!(rig.service.check_aggregate_id(&test.id), IdCheck::Ignore);
    }

    fn a_published_aggregate_is_pushed_and_announced(mut rig: Rig) {
        let test = test_aggregate(7, &[0], 0);
        let (_, receiver_1) = rig.add_peer();
        let (_, receiver_2) = rig.add_peer();

        rig.service
            .publish(NewAggregate {
                header: test.verified.clone(),
                chunks: test.chunks.clone(),
            })
            .unwrap();

        // We have every chunk, so nothing is handed to the beacon processor.
        assert!(rig.work().is_empty());
        assert!(rig.aggregate(&test).complete);
        assert_eq!(rig.service.held[&(SLOT, 7)], test.id.header_root);
        // With two peers, every chunk is pushed to both. The first one each gets brings the
        // header, and what we have.
        for receiver in [&receiver_1, &receiver_2] {
            let messages = sent(receiver);
            assert_eq!(messages.len(), TOTAL_PROOF_CHUNKS);
            for (position, message) in messages.iter().enumerate() {
                let piece = message.piece.as_ref().unwrap();
                assert_eq!(piece.signed_header.is_empty(), position != 0);
                assert_eq!(message.metadata.is_some(), position == 0);
            }
        }

        // A peer that subscribes later is told what we have.
        let (late, late_receiver) = rig.add_peer();
        rig.service.try_inform_new_peer(late);
        let messages = sent(&late_receiver);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].metadata.as_ref().unwrap().request.is_zero());
        assert_eq!(
            indices(&messages[0].metadata.as_ref().unwrap().have).len(),
            TOTAL_PROOF_CHUNKS
        );

        // Another aggregate of the aggregator for the slot is not published.
        let equivocation = test_aggregate(7, &[0], 1);
        rig.service
            .publish(NewAggregate {
                header: equivocation.verified.clone(),
                chunks: equivocation.chunks.clone(),
            })
            .unwrap();
        assert!(!rig.tracks(&equivocation));
    }

    fn aggregates_are_dropped_after_their_tracking_window(mut rig: Rig) {
        let test = test_aggregate(7, &[0], 0);
        rig.hold(&test, &[1]);
        let clean_up_at = |rig: &mut Rig, slot: Slot| {
            rig.set_now(SLOT_DURATION * slot as u32 + DISPARITY);
            rig.service.clean_up();
        };

        // Tracked through the slot of the first block that can include the aggregate.
        clean_up_at(&mut rig, SLOT + TRACKED_SLOTS_AFTER_OWN);
        assert!(rig.tracks(&test));
        assert!(rig.service.held.contains_key(&(SLOT, 7)));

        clean_up_at(&mut rig, SLOT + TRACKED_SLOTS_AFTER_OWN + 1);
        assert!(!rig.tracks(&test));
        assert!(rig.service.held.is_empty());
    }
}
