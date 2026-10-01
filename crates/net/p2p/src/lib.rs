pub mod muxers {
    //! Why the TCP transport offers mplex as well as yamux.
    //!
    //! Measured against live mainnet peers on 2026-08-13, dialing with a
    //! throwaway probe binary carrying nothing but `identify`, so that none of
    //! this crate's own protocols can be the cause:
    //!
    //! ```text
    //! yamux only      Proposed /yamux/1.0.0  ->  NotAvailable
    //!                 connection dies ~250ms in, no Goodbye, yamux frame
    //!                 decode error: multistream-select negotiates the muxer
    //!                 optimistically, so we are already writing yamux frames
    //!                 when the refusal arrives and we parse their reply as one
    //!
    //! yamux + mplex   Proposed /yamux/1.0.0, then /mplex/6.7.0
    //!                 Negotiated /mplex/6.7.0, identify completes both ways
    //! ```
    //!
    //! The same probe against a non-Ethereum libp2p node (an IPFS bootstrapper)
    //! completes identify with yamux alone, which is what rules out this crate's
    //! transport setup and points at the beacon network's own convention.
    //!
    //! mplex is deprecated in libp2p and the facade crate has already dropped
    //! its re-export, so `libp2p-mplex` is depended on directly. When mainnet
    //! peers accept yamux, this goes away; until then a yamux-only beacon node
    //! peers with nothing over TCP.
}

use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    fmt, io,
    net::{IpAddr, SocketAddr},
    num::{NonZeroU8, NonZeroUsize},
    ops::Range,
    sync::Arc,
    time::{Duration, Instant},
};

use either::Either;
use ethlambda_network_api::{
    FetchRequest, InitBlockChain, P2PToBlockChainRef,
    block_chain_to_p2p::{
        CheckDataColumnSidecars, FetchBlock, PublishAggregatedAttestation, PublishAttestation,
        PublishBlock,
    },
    rpc_to_p2p::{
        PublishBeaconAggregate, PublishBeaconAttestation, PublishBeaconBlock,
        PublishBeaconOperation, SubscribeAttestationSubnets,
    },
};
use ethlambda_state_transition::beacon::aggregate::MAX_AGGREGATES_PER_SLOT;
use ethlambda_state_transition::beacon::gossip::{
    SeenBlocks, SeenColumns, aggregate::SeenAggregates, attestation::SeenAttestations,
    operations::SeenOperations,
};
use ethlambda_storage::{Chain, Store};
use ethlambda_types::beacon::preset::{MAX_VALIDATORS_PER_COMMITTEE, SLOTS_PER_EPOCH};
use ethlambda_types::primitives::H256;
use ethrex_p2p::types::NodeRecord;
use ethrex_rlp::decode::RLPDecode;
use futures::StreamExt;
use libp2p::{
    Multiaddr,
    gossipsub::{MessageAuthenticity, ValidationMode},
    identity::{Keypair, PublicKey, secp256k1},
    multiaddr::Protocol,
    request_response::OutboundRequestId,
    swarm::{ConnectionError, NetworkBehaviour, SwarmEvent, dial_opts::DialOpts},
};
use sha2::Digest;
use spawned_concurrency::actor;
use spawned_concurrency::error::ActorError;
use spawned_concurrency::message::Message;
use spawned_concurrency::protocol;
use spawned_concurrency::tasks::{
    Actor, ActorRef, ActorStart, Context, Handler, send_after, spawn_listener,
};
use tracing::{debug, info, trace, warn};

use crate::{
    discovery::{
        DIAL_INTERVAL_AT_TARGET, DIAL_INTERVAL_AT_ZERO_PEERS, DiscoveryError, DiscoverySpawnConfig,
        dial::{DiscoveryState, dial_interval, dial_progress, dial_tick, forget_discovered_peer},
        enr::{dialable_port, read_ip, read_public_key, read_quic_port, read_tcp_port},
        spawn_discovery,
    },
    gossipsub::{
        aggregation_topic, attestation_subnet_topic, block_topic, publish_aggregated_attestation,
        publish_attestation, publish_beacon_aggregate, publish_beacon_attestation,
        publish_beacon_block, publish_beacon_operation, publish_block,
    },
    lean::protocols::MAX_REQUEST_BLOCKS,
    req_resp::{
        Codec, MAX_COMPRESSED_PAYLOAD_SIZE, ReqResp, ReqRespEvent, Request, build_status,
        fetch_block_from_peer, fetch_data_columns_from_peer,
        handlers::{columns_custodied_by, resume_range_batch_held_for_custody},
    },
    swarm_adapter::SwarmHandle,
};

pub mod beacon;
pub mod discovery;
mod gossipsub;
pub mod lean;
pub mod metrics;
mod req_resp;
pub(crate) mod swarm_adapter;

pub use libp2p::PeerId;

/// Asking a peer for beacon blocks, by range and by root.
///
/// Both are driven from inside this crate: `fetch_block_from_peer` sends the
/// by-root one, and `request_next_beacon_range_batch` the by-range one, off a
/// peer's `Status`. They stay public because the answer stops at this crate:
/// this node has no beacon `BlockChain` actor to import into, so a fetched
/// block is checked and dropped, and the importer that changes that is expected
/// to drive its own fetches from outside rather than through the range session.
pub use req_resp::{request_beacon_block_by_root, request_beacon_blocks_by_range};

/// `MAX_PAYLOAD_SIZE`, the ceiling on an uncompressed gossip or req/resp
/// payload. Public because a beacon `config.yaml` carries it too, and startup
/// refuses a network whose value differs from this one.
pub use req_resp::MAX_PAYLOAD_SIZE;

// 5ms, 10ms, 20ms, 40ms, 80ms, 160ms, 320ms, 640ms, 1280ms, 2560ms
//
// This ladder, not a separate wall-clock budget, is what actually bounds how
// long a lookup persists: `MAX_FETCH_RETRIES` attempts, each capped by the
// request-response layer's own per-request timeout, with a doubling backoff
// between them. A held block is evicted by finality on its own schedule
// regardless, so the ladder only needs to stay well inside that window, which
// it comfortably does. A `COLUMN_LOOKUP_MAX_DURATION` used to sit alongside
// this, copied from Lighthouse without checking it against these timings: it
// was long enough that the attempts ladder above always ran out first, so it
// could never fire, while its own doc claimed it was what stopped the asking.
const MAX_FETCH_RETRIES: u32 = 10;
const INITIAL_BACKOFF_MS: u64 = 5;
const BACKOFF_MULTIPLIER: u64 = 2;

/// How long an entry in `pending_column_requests` may go without a new request
/// before a fresh [`FetchRequest`] for that root starts its own lookup
/// instead of folding into it.
///
/// The entry exists to deduplicate: while a lookup is running, a second ask
/// for the same root merges its columns rather than opening a parallel ladder.
/// That is only correct while the lookup it defers to is actually alive. An
/// entry whose round never reported back leaves the root deduplicated against
/// a lookup that will never ask anything again, and the chain actor's
/// per-slot re-drive of a held block would then be swallowed silently, which
/// is precisely the case the re-drive exists for.
///
/// Comfortably longer than a full ladder (`MAX_FETCH_RETRIES` attempts whose
/// backoffs sum to a few seconds, plus each attempt's round trips) and shorter
/// than a mainnet slot, so a re-drive arriving on the next tick finds either a
/// live lookup or no entry at all.
const STALE_COLUMN_LOOKUP: Duration = Duration::from_secs(8);

/// How many peers of unknown custody one `DataColumnsByRange` prefetch may
/// speculatively ask for the columns no known custodian covers.
///
/// A peer's custody is only known once its `metadata/3` answer or its ENR
/// `cgc` has been recorded, and there is always a handful of connected peers
/// that have supplied neither. Those are worth asking; peers that *have* told
/// us what they keep, and do not keep this column, are not. Two rather than
/// all of them, because a range answer is megabytes when it lands.
const UNKNOWN_CUSTODY_RANGE_PEERS: usize = 2;

/// How long a beacon range batch may be held back waiting for every one of
/// this node's custody columns to have a known custodian among the connected
/// peers.
///
/// A batch sends its blocks and its `DataColumnsByRange` together, and the
/// column request can only be aimed at peers whose custody is already known.
/// Right after startup that is almost nobody: a peer's custody arrives with its
/// `metadata/3` answer, after it connects. A batch sent then aims its column
/// request at peers that may not keep the columns, a short or empty answer is
/// not retried, and every block it leaves uncovered is held and chased by root
/// one at a time. The wait is what gives the one range request a custodian to
/// go to.
///
/// Bounded rather than open-ended, unlike lighthouse's range sync, which waits
/// for custody peers as long as it takes. Nothing here goes looking for a
/// custodian of a specific column, so a column no connected peer keeps may stay
/// uncovered for a long time; past this deadline the batch goes anyway, and the
/// uncovered columns get the unknown-custody fallback and the by-root path, as
/// they did before the wait existed.
const RANGE_BATCH_CUSTODY_WAIT: Duration = Duration::from_secs(30);

const PEER_REDIAL_INTERVAL_SECS: u64 = 12;

/// How many of one peer's addresses a dial attempt starts at once.
///
/// One, so that libp2p walks [`dial_addrs`] in order rather than racing it, and
/// the QUIC address that list puts first is genuinely tried first. Under
/// libp2p's default factor both transports start together and TCP wins most of
/// the races, which is not a free choice between two equal wires: a TCP
/// connection to a mainnet beacon peer negotiates mplex (see [`muxers`]), and
/// `libp2p_mplex`'s waker bookkeeping was the single largest symbol in a
/// profile of the mainnet follower, ahead of the whole state transition. QUIC
/// carries its own multiplexing and reaches none of that code.
///
/// The cost is the one the race existed to avoid, now bounded rather than
/// removed: a peer advertising a `quic` port nothing answers waits out
/// `libp2p_quic`'s handshake timeout before its `tcp` address is tried. A peer
/// whose ENR carries no `quic` entry pays nothing, because TCP is then the only
/// address in the list, and neither does lean, whose records advertise `quic`
/// alone.
const DIAL_ADDRESS_CONCURRENCY: NonZeroU8 = NonZeroU8::new(1).expect("1 > 0");

const MAX_SYNC_RANGE: u64 = MAX_REQUEST_BLOCKS * 64; // 65,536 slots (~3 days)

/// How many beacon gossip messages may be in stateful validation at once. A
/// message arriving with none free is ignored rather than queued. Revisit once
/// `lean_beacon_gossip_validation_seconds` has data from a follower.
const GOSSIP_VALIDATION_PERMITS: usize = 128;

/// How many data column sidecars may be in the chain checks at once (see
/// [`beacon::column_checks`]). A separate pool from
/// [`GOSSIP_VALIDATION_PERMITS`], so a range batch's hundreds of sidecars
/// cannot take every permit and leave gossip reporting `Overloaded`. A sidecar
/// arriving with none free waits for one. Revisit with data, as for gossip.
const COLUMN_CHECK_PERMITS: usize = 16;

/// How many `beacon_aggregate_and_proof` and `beacon_attestation_{subnet_id}`
/// stateful checks may run at once.
///
/// A pool of its own, not [`GOSSIP_VALIDATION_PERMITS`]'s: a mainnet slot
/// carries up to `MAX_COMMITTEES_PER_SLOT * TARGET_AGGREGATORS_PER_COMMITTEE`
/// aggregates plus whatever this node's backbone subnets add, a burst that
/// arrives every slot rather than only during a range sync. Sharing the block
/// and column pool with that burst would let it take every permit and answer
/// `Ignore(Overloaded)` for a block or a column instead, which must never
/// happen: neither topic gates anything the way this one gates fork choice's
/// votes for the current head. Sized the same as [`GOSSIP_VALIDATION_PERMITS`]
/// for now, since both do comparable per-item work (one state read, one to
/// three BLS verifications); revisit once
/// `lean_beacon_gossip_validation_seconds{kind="beacon_aggregate_and_proof"}`
/// has data from a follower.
const ATTESTATION_VALIDATION_PERMITS: usize = 128;

/// Capacity of the first-valid-block cache, keyed by `(slot, proposer)`.
/// How often to leave aggregator subnets whose slot has passed. One slot's
/// worth: a subnet outlives its need by at most this, which costs a little
/// relayed traffic and nothing else.
const AGGREGATOR_SUBNET_SWEEP_INTERVAL: Duration = Duration::from_secs(12);

const SEEN_BLOCKS_CAPACITY: NonZeroUsize = NonZeroUsize::new(1024).expect("non-zero");

/// Capacity of the first-valid-sidecar cache, keyed by `(slot, proposer, index)`.
const SEEN_COLUMNS_CAPACITY: NonZeroUsize = NonZeroUsize::new(4096).expect("non-zero");

/// How many `(target_epoch, aggregator_index)` pairs the accepted-aggregate
/// cache remembers, and how many `(hash_tree_root(data), committee_index)`
/// bitfields alongside it (`SeenAggregates::new`'s two capacities, both sized
/// the same here).
///
/// [`MAX_AGGREGATES_PER_SLOT`] bounds how many aggregators one slot can select
/// at all, mainnet's largest number this topic ever has to hold coordinates
/// for. `is_current_or_previous_epoch` is the only gossip condition either
/// half of this cache backs, so a key from further back than two epochs is
/// never asked about again; sizing for two epochs of that per-slot bound is
/// generous headroom rather than a tight derivation, in the same spirit
/// [`SEEN_BLOCKS_CAPACITY`] and [`SEEN_COLUMNS_CAPACITY`] are sized in.
const SEEN_AGGREGATES_CAPACITY: NonZeroUsize =
    NonZeroUsize::new((MAX_AGGREGATES_PER_SLOT * SLOTS_PER_EPOCH * 2) as usize).expect("non-zero");

/// Capacity of the accepted-attestation cache, keyed by `(target_epoch,
/// attester_index)`, for a node relaying `backbone_subnets` attestation
/// subnets.
///
/// Unlike [`SEEN_AGGREGATES_CAPACITY`], there is no per-slot cap on how many
/// distinct attesters this topic can name: every validator attests once per
/// epoch, and on mainnet a single backbone subnet can carry on the order of a
/// thousand of them per slot. The real bound instead comes from
/// `compute_subnet_for_attestation` (see
/// `beacon::gossip::attestation::compute_subnet_for_attestation`), which is
/// `(committees_per_slot * slot_in_epoch + committee_index) %
/// attestation_subnet_count`. `committees_per_slot` never exceeds
/// `MAX_COMMITTEES_PER_SLOT`, which itself never exceeds
/// `attestation_subnet_count` (64 of 64 on both mainnet and minimal), so the
/// `committees_per_slot` committee indices of one slot are consecutive
/// integers spanning no more residues than there are subnets: they land on
/// distinct subnets without wrapping into a collision. One subnet therefore
/// carries at most one committee per slot, i.e. at most
/// [`MAX_VALIDATORS_PER_COMMITTEE`] attesters.
///
/// The capacity is two epochs (the only window `is_current_or_previous_epoch`
/// accepts) of `SLOTS_PER_EPOCH` slots, each contributing at most that many
/// attesters per subnet this node backbones. `backbone_subnets` is runtime
/// (`BeaconWire::attestation_subnets`), so this is computed at `P2PServer`
/// construction rather than as a const, and floored to one subnet so a lean
/// node, which backbones none, still gets a valid non-zero capacity. As with
/// [`SEEN_AGGREGATES_CAPACITY`], the LRU only grows to what actually arrives,
/// so this bound costs memory only under that load.
fn seen_attestations_capacity(backbone_subnets: usize) -> NonZeroUsize {
    let subnets = backbone_subnets.max(1);
    let capacity = 2 * SLOTS_PER_EPOCH as usize * MAX_VALIDATORS_PER_COMMITTEE * subnets;
    NonZeroUsize::new(capacity).expect("positive factors give a positive capacity")
}

pub(crate) struct PendingRequest {
    pub(crate) attempts: u32,
    pub(crate) failed_peers: HashSet<PeerId>,
}

/// A block-root fetch's counterpart for a column lookup: the same
/// attempt/failed-peer bookkeeping [`PendingRequest`] carries, plus what
/// [`PendingRequest`] never needed to. `columns` is the request body a retry
/// resends, since (unlike a block-root fetch, whose body is the root already
/// keying this map) a column request also names which columns.
pub(crate) struct PendingColumnRequest {
    pub(crate) columns: Vec<u64>,
    pub(crate) attempts: u32,
    pub(crate) failed_peers: HashSet<PeerId>,
    /// Requests sent for this root and not yet answered or failed.
    ///
    /// One attempt now fans out across the peers that custody the columns, so
    /// a single lookup can have several requests open at once. Without this
    /// count each of their failures would schedule its own retry, and each
    /// retry would fan out again: one unanswered lookup against eight
    /// custodians becomes eight retries, then sixty-four. A retry is scheduled
    /// only when the last outstanding request of the round reports back, so an
    /// attempt still costs exactly one retry however wide it was.
    pub(crate) in_flight: usize,
    /// When this lookup last put requests on the wire, for
    /// [`STALE_COLUMN_LOOKUP`] to measure against.
    pub(crate) last_asked: Instant,
}

pub(crate) enum PendingRequestKind {
    Root(H256),
    Range {
        start_slot: u64,
        end_slot: u64,
    },
    /// A `DataColumnsByRoot` lookup for this block's missing columns. Carries
    /// only the root: the columns, attempts and failed-peer set live in
    /// `pending_column_requests`, keyed the same way, so this is enough to
    /// route the response and nothing this map needs to duplicate.
    Columns(H256),
    /// A `DataColumnsByRange` sweep for a range sync batch, covering the same
    /// slots the matching `BlocksByRange` asked for.
    ///
    /// Carries no per-root bookkeeping, unlike [`Self::Columns`]: this is not
    /// a lookup for one block's missing columns but a bulk prefetch, so a
    /// short or empty answer is not a failure to retry. The blocks it is
    /// paired with arrive on their own request, and any column still missing
    /// when a block is held still gets the by-root path.
    ColumnRange {
        start_slot: u64,
        end_slot: u64,
    },
}

/// Which single-protocol field of [`ReqResp`] an outbound request travels
/// through.
///
/// Splitting one shared `request_response::Behaviour` into one per protocol
/// (see [`ReqResp`]'s doc comment) gives each field its own
/// `OutboundRequestId` sequence, starting at 1: two different protocols can
/// now legitimately mint the same numeric id for two unrelated requests. A
/// bare `OutboundRequestId` is therefore no longer a safe map key on its own,
/// and every place that names one names this alongside it instead, forming
/// [`ReqRespRequestId`].
///
/// One variant per field, sharing that field's name so the two stay easy to
/// line up by eye; [`crate::swarm_adapter::execute_command`] matches
/// exhaustively on this to choose which field actually sends, and
/// [`handle_behaviour_event`] matches exhaustively on the derived
/// `ReqRespEvent` to tag every inbound event with the variant that produced
/// it. Public because [`request_beacon_block_by_root`] and
/// [`request_beacon_blocks_by_range`] carry a [`ReqRespRequestId`] in their
/// return type and are themselves public, for the reason their own doc
/// comments give.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReqRespProtocol {
    LeanStatus,
    LeanBlocksByRoot,
    LeanBlocksByRange,
    BeaconStatusV1,
    BeaconStatusV2,
    BeaconPing,
    BeaconMetadataV1,
    BeaconMetadataV2,
    BeaconMetadataV3,
    BeaconGoodbye,
    BeaconBlocksByRange,
    BeaconBlocksByRoot,
    DataColumnSidecarsByRange,
    DataColumnSidecarsByRoot,
}

/// An outbound request id, namespaced by the protocol it was sent on.
///
/// See [`ReqRespProtocol`] for why the protocol has to be carried alongside
/// the id rather than trusted to be unique on its own now that each protocol
/// has its own `Behaviour` field and so its own id sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReqRespRequestId {
    pub protocol: ReqRespProtocol,
    pub id: OutboundRequestId,
}

pub(crate) struct RangeSyncState {
    /// Remaining slots to request, with an exclusive end.
    pub(crate) current_range: Range<u64>,
    /// Latest advertised head slot for each peer.
    pub(crate) peer_set: HashMap<PeerId, u64>,
    pub(crate) in_flight: bool,
    /// When the next batch was first held back for custody, while it still is.
    /// Beacon-only; see [`RANGE_BATCH_CUSTODY_WAIT`].
    pub(crate) custody_wait_since: Option<Instant>,
}

/// Where a beacon range batch held back for custody stands, as
/// [`RangeSyncState::wait_for_custody`] reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CustodyWait {
    /// The batch has only now started waiting, so its deadline still needs
    /// scheduling.
    Started,
    /// Still inside [`RANGE_BATCH_CUSTODY_WAIT`].
    Waiting,
    /// The deadline has passed: the batch goes with whatever custody is known.
    Expired,
}

impl RangeSyncState {
    pub(crate) fn new(current_range: Range<u64>, peer: PeerId, peer_head: u64) -> Self {
        Self {
            current_range,
            peer_set: HashMap::from([(peer, peer_head)]),
            in_flight: false,
            custody_wait_since: None,
        }
    }

    /// Hold the next batch back for custody, starting its wait on the first
    /// call, and say whether it may keep waiting at `now`.
    ///
    /// The wait belongs to the batch rather than the session: sending clears
    /// it (see [`Self::end_custody_wait`]), so a batch that finds custody
    /// uncovered later on, after a custodian disconnected, gets a wait of its
    /// own rather than inheriting an expired one.
    pub(crate) fn wait_for_custody(&mut self, now: Instant) -> CustodyWait {
        match self.custody_wait_since {
            None => {
                self.custody_wait_since = Some(now);
                CustodyWait::Started
            }
            Some(since) if now.duration_since(since) < RANGE_BATCH_CUSTODY_WAIT => {
                CustodyWait::Waiting
            }
            Some(_) => CustodyWait::Expired,
        }
    }

    /// End the custody wait of the batch being sent, returning how long it
    /// waited, or `None` if it never did.
    pub(crate) fn end_custody_wait(&mut self, now: Instant) -> Option<Duration> {
        self.custody_wait_since
            .take()
            .map(|since| now.duration_since(since))
    }

    /// Whether the next batch is currently held back for custody.
    pub(crate) fn is_waiting_for_custody(&self) -> bool {
        self.custody_wait_since.is_some()
    }

    pub(crate) fn merge_peer(&mut self, peer: PeerId, peer_head: u64, end_exclusive: u64) {
        self.peer_set.insert(peer, peer_head);
        self.current_range.end = self.current_range.end.max(end_exclusive);
        self.drop_stale_peers();
    }

    pub(crate) fn next_batch(&self) -> Option<(PeerId, Range<u64>)> {
        if self.in_flight || self.current_range.is_empty() {
            return None;
        }

        let (&peer, &peer_head) = self
            .peer_set
            .iter()
            .filter(|(_, head)| **head >= self.current_range.start)
            .max_by_key(|(_, head)| **head)?;
        let peer_end = peer_head.saturating_add(1);
        let batch_end = self
            .current_range
            .start
            .saturating_add(MAX_REQUEST_BLOCKS)
            .min(self.current_range.end)
            .min(peer_end);

        (batch_end > self.current_range.start)
            .then_some((peer, self.current_range.start..batch_end))
    }

    pub(crate) fn complete_batch(&mut self, end_slot: u64) {
        self.in_flight = false;
        self.current_range.start = self.current_range.start.max(end_slot.saturating_add(1));
        self.drop_stale_peers();
    }

    pub(crate) fn fail_peer(&mut self, peer: &PeerId) {
        self.in_flight = false;
        self.peer_set.remove(peer);
        self.drop_stale_peers();
    }

    fn drop_stale_peers(&mut self) {
        let start_slot = self.current_range.start;
        self.peer_set.retain(|_, head| *head >= start_slot);
    }
}

// --- Swarm construction ---

/// [libp2p Behaviour](libp2p::swarm::NetworkBehaviour) combining identify,
/// Gossipsub and the request/response protocols.
///
/// `identify` is registered purely for interop: go-libp2p (gean) gates gossipsub
/// GRAFT on the identify exchange completing, so a peer that doesn't respond to
/// `/ipfs/id/1.0.0` is silently excluded from the mesh. Events from this
/// behaviour are intentionally not handled: the registration alone is enough
/// to satisfy probing peers. ream and zeam follow the same pattern.
///
/// Not handling its events is *not* the same as it having no effect, which is
/// why it is built with the address cache off. See [`build_swarm`].
///
/// The request/response side is a nested [`ReqResp`]: one
/// `request_response::Behaviour` per protocol id rather than one shared
/// behaviour registering every id. Its doc comment has why, and
/// [`ReqRespProtocol`] names its fields for anything that has to pick one
/// at runtime.
#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour {
    identify: libp2p::identify::Behaviour,
    gossipsub: libp2p::gossipsub::Behaviour,
    req_resp: ReqResp,
    /// Refuses connections past the configured ceiling. A deny from any member
    /// behaviour denies the connection, so registering this is the whole
    /// mechanism; see [`beacon::swarm::connection_limits`] for the numbers and why the
    /// beacon network needs them while lean does not.
    connection_limits: libp2p::connection_limits::Behaviour,
}

/// No connection limits, which is what the lean network has always run with: a
/// devnet's peer count is bounded by the size of the devnet itself, so a cap
/// there would only ever cap the operator.
pub(crate) fn unlimited_connections() -> libp2p::connection_limits::Behaviour {
    libp2p::connection_limits::Behaviour::new(Default::default())
}

/// Configuration for building the libp2p swarm.
///
/// These are the parameters both networks take; [`WireConfig`] carries what only
/// one of them does. One config and one [`build_swarm`] rather than a pair per
/// network, because the transport, the two listeners and the static bootnode
/// dialing are identical and were duplicated line for line while there were two
/// builders.
pub struct SwarmConfig {
    pub node_key: Vec<u8>,
    pub bootnodes: Vec<Bootnode>,
    pub listening_socket: SocketAddr,
    /// How many peers this node is asking for, from
    /// `--discovery.target-peers`. The same number
    /// [`DiscoverySpawnConfig::target_peers`] carries to the dial loop, because
    /// the beacon connection limits are derived from it: what this node refuses
    /// and what it goes looking for have to be two readings of one number, or a
    /// reservation the swarm does not keep is one the dial loop chases forever.
    /// Ignored on lean, which runs [`unlimited_connections`].
    pub target_peers: usize,
    /// Which network's wire to build. Decides the gossip topics, the req/resp
    /// protocol set, the gossipsub `seen_ttl`, the identify protocol version and
    /// the connection limits, and so decides the [`Wire`] the built swarm
    /// carries.
    pub wire: WireConfig,
}

/// The half of [`SwarmConfig`] the two networks disagree about.
pub enum WireConfig {
    Lean(LeanWireConfig),
    /// Boxed for the reason [`Wire::Beacon`] is: it carries a whole `Config`,
    /// and every lean node would otherwise pay for it in each config it moves.
    Beacon(Box<beacon::swarm::BeaconWireConfig>),
}

/// The lean network's swarm parameters.
///
/// INVARIANT: `subscription_subnets` is the fixed set of attestation subnets
/// this node subscribes to. It is computed once by the caller via
/// [`attestation_subscription_subnets`] and shared with the blockchain actor,
/// so both agree on exactly which subnets feed this node's gossip groups. The
/// set is consumed during [`build_swarm`] and NOT stored on [`P2PServer`]:
/// runtime toggles of the aggregator role via the admin API (see
/// [`ethlambda_types::aggregator::AggregatorController`]) intentionally do not
/// resubscribe gossip subnets; this is the leanSpec PR #636 "hot-standby model"
/// scope limitation. A node that may aggregate at runtime must include those
/// subnets here at startup.
pub struct LeanWireConfig {
    pub validator_ids: Vec<u64>,
    pub attestation_committee_count: u64,
    /// Attestation subnets to subscribe to, precomputed via
    /// [`attestation_subscription_subnets`].
    pub subscription_subnets: HashSet<u64>,
    /// Slot duration from the network's config file. Gossipsub's duplicate
    /// cache is specified in slots, so it has to follow the network's cadence.
    pub milliseconds_per_slot: u64,
}

/// Width of gossipsub's duplicate cache, in slots: leanSpec sets
/// `seen_ttl = SECONDS_PER_SLOT * JUSTIFICATION_LOOKBACK_SLOTS * 2`.
const DUPLICATE_CACHE_SLOTS: u64 = 3 * 2;

/// The attestation subnets a node subscribes to: every validator subscribes
/// to its own committee subnet (`validator_id % attestation_committee_count`)
/// for mesh health, and an aggregator additionally subscribes to any explicit
/// `aggregate_subnet_ids`, falling back to subnet 0 when it would otherwise
/// subscribe to none.
pub fn attestation_subscription_subnets(
    validator_ids: &[u64],
    attestation_committee_count: u64,
    is_aggregator: bool,
    aggregate_subnet_ids: Option<&[u64]>,
) -> HashSet<u64> {
    let mut subnets: HashSet<u64> = validator_ids
        .iter()
        .map(|vid| vid % attestation_committee_count)
        .collect();
    if is_aggregator {
        if let Some(ids) = aggregate_subnet_ids {
            subnets.extend(ids.iter().copied());
        }
        // Fall back to subnet 0 only when the aggregator has no validators and
        // no explicit subnets; otherwise leave the set as configured.
        if subnets.is_empty() {
            subnets.insert(0);
        }
    }
    subnets
}

/// Which network's wire this node speaks.
///
/// One `P2PServer` serves both, dispatching on this once at the top of each
/// handler, exactly as `BlockChainServer` dispatches on the state variant.
/// Nothing is shared below the match: the topic names, the req/resp protocol
/// ids, the handshake and the decode are all different, and the parts that
/// genuinely coincide (the discv5 stack, the `ssz_snappy` framing,
/// `compute_message_id`) sit one layer down and are the beacon spec's anyway.
pub enum Wire {
    Lean(LeanWire),
    /// Boxed because a `BeaconWire` carries a whole `Config` and so is four
    /// times the size of a `LeanWire`; unboxed, every lean node would pay for
    /// it in each `Wire` it moves.
    Beacon(Box<beacon::BeaconWire>),
}

/// The lean network's gossip topics.
pub struct LeanWire {
    pub(crate) attestation_topics: HashMap<u64, libp2p::gossipsub::IdentTopic>,
    pub(crate) attestation_committee_count: u64,
    pub(crate) block_topic: libp2p::gossipsub::IdentTopic,
    pub(crate) aggregation_topic: libp2p::gossipsub::IdentTopic,
}

impl Wire {
    pub(crate) fn lean(&self) -> Option<&LeanWire> {
        match self {
            Wire::Lean(lean) => Some(lean),
            Wire::Beacon(_) => None,
        }
    }

    pub(crate) fn beacon(&self) -> Option<&beacon::BeaconWire> {
        match self {
            Wire::Beacon(beacon) => Some(beacon),
            Wire::Lean(_) => None,
        }
    }

    /// Which chain's handler a shared request belongs to.
    ///
    /// The two block requests are one `Request` variant for both wires, so the
    /// dispatch reads this instead of a tag on the message. A node speaks one
    /// wire for its whole life, so this is the same answer every time and is
    /// already recorded here; carrying it on the message would be a second copy
    /// of it.
    pub(crate) fn is_beacon(&self) -> bool {
        matches!(self, Wire::Beacon(_))
    }
}

/// Result of building the swarm — contains all pieces needed to start the P2P actor.
pub struct BuiltSwarm {
    /// This node's libp2p peer ID, derived from the node key. Exposed so the
    /// caller can report it (e.g. via the RPC `/lean/v0/node/identity` endpoint).
    pub local_peer_id: PeerId,
    pub(crate) swarm: libp2p::Swarm<Behaviour>,
    pub(crate) wire: Wire,
    /// Every dial target per bootnode; see [`dial_addrs`]. Empty entries are never
    /// inserted; see [`bootnode_dial_addrs`].
    pub(crate) bootnode_addrs: HashMap<PeerId, Vec<Multiaddr>>,
}

/// Why [`build_swarm`] could not produce a usable swarm.
///
/// Both listeners are fatal rather than best-effort. Carrying on after a failed
/// TCP bind would leave the node advertising a `tcp` entry nothing answers,
/// which is the failure this transport exists to remove, inverted. The
/// configuration cases are caught before anything binds (`validate_ports` in
/// the CLI), so reaching this means the port is genuinely taken.
#[derive(Debug, thiserror::Error)]
pub enum SwarmBuildError {
    #[error("failed to bind the gossipsub {transport} listener on {addr}: {source}")]
    Listen {
        transport: &'static str,
        addr: Multiaddr,
        #[source]
        source: libp2p::TransportError<std::io::Error>,
    },
    #[error("failed to subscribe to a gossipsub topic: {0}")]
    Subscription(#[from] libp2p::gossipsub::SubscriptionError),
}

/// The gossipsub parameters both wires share.
///
/// `mesh_n` 8, low 6, high 12, the 700ms heartbeat, and the 6/3 history already
/// match the beacon spec, so `seen_ttl` is the only value that differs between
/// the two networks: lean's is its slot duration times a 3-slot justification
/// lookback times two, mainnet's epoch is 32 slots of 12s.
///
/// `validate_messages` holds every received message until the application
/// reports a verdict for it. Beacon only: every beacon topic gets one from
/// `beacon::verdict`, while lean handlers produce none, so turning it on there
/// would stop lean gossip from propagating at all.
pub(crate) fn gossipsub_config(
    seen_ttl: Duration,
    validate_messages: bool,
) -> libp2p::gossipsub::Config {
    let mut builder = libp2p::gossipsub::ConfigBuilder::default();
    builder
        // d
        .mesh_n(8)
        // d_low
        .mesh_n_low(6)
        // d_high
        .mesh_n_high(12)
        // d_lazy
        .gossip_lazy(6)
        .heartbeat_interval(Duration::from_millis(700))
        .fanout_ttl(Duration::from_secs(60))
        .history_length(6)
        .history_gossip(3)
        .duplicate_cache_time(seen_ttl)
        .validation_mode(ValidationMode::Anonymous)
        .message_id_fn(compute_message_id)
        // Taken from ream
        .max_transmit_size(MAX_COMPRESSED_PAYLOAD_SIZE)
        .max_messages_per_rpc(Some(500))
        .allow_self_origin(true)
        .idontwant_message_size_threshold(1000);
    if validate_messages {
        builder.validate_messages();
    }
    builder.build().expect("invalid gossipsub config")
}

/// Build and configure the libp2p swarm, dial bootnodes, subscribe to topics.
///
/// One builder for both networks. Four things differ at the behaviour level and
/// are resolved in the first match below; the topic set differs and is resolved
/// in the last one. Everything in between, the transport, the QUIC and TCP
/// listeners and the static bootnode dialing, is the same on either wire.
pub fn build_swarm(config: SwarmConfig) -> Result<BuiltSwarm, SwarmBuildError> {
    let SwarmConfig {
        node_key,
        bootnodes,
        listening_socket,
        target_peers,
        wire,
    } = config;

    // The codec comes out of this match too, not from `Default`: the two beacon
    // block protocols frame their chunks against the fork schedule and the
    // chain, so whatever decides that the protocols are registered has to decide
    // that the context is there. See [`Codec`].
    let (seen_ttl, identify_version, connection_limits, codec) = match &wire {
        WireConfig::Lean(lean) => (
            Duration::from_millis(lean.milliseconds_per_slot * DUPLICATE_CACHE_SLOTS),
            // Use the same `protocol_version` string as zeam
            "/ipfs/0.1.0",
            unlimited_connections(),
            Codec::lean(),
        ),
        WireConfig::Beacon(beacon) => (
            beacon::swarm::seen_ttl(&beacon.config),
            beacon::swarm::IDENTIFY_PROTOCOL_VERSION,
            beacon::swarm::connection_limits(target_peers),
            Codec::beacon(beacon::BeaconContext {
                config: beacon.config.clone(),
                genesis_validators_root: beacon.genesis_validators_root,
            }),
        ),
    };

    let validate_messages = matches!(wire, WireConfig::Beacon(_));
    let gossipsub = libp2p::gossipsub::Behaviour::new(
        MessageAuthenticity::Anonymous,
        gossipsub_config(seen_ttl, validate_messages),
    )
    .expect("failed to initiate behaviour");

    let req_resp = ReqResp::new(codec, &wire);

    let secret_key = secp256k1::SecretKey::try_from_bytes(node_key).expect("invalid node key");
    let identity = libp2p::identity::Keypair::from(secp256k1::Keypair::from(secret_key));

    // Cache off, as lighthouse does: with it, identify pushes every `listenAddrs` a
    // peer reports into the address book, loopback included, and `req_resp` dials those.
    let identify = libp2p::identify::Behaviour::new(
        libp2p::identify::Config::new(identify_version.to_owned(), identity.public())
            .with_cache_size(0),
    );

    let behavior = Behaviour {
        identify,
        gossipsub,
        req_resp,
        connection_limits,
    };

    // TODO: set peer scoring params

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default().nodelay(true),
            libp2p::noise::Config::new,
            // mplex is not decoration: mainnet beacon peers answer `na` to a
            // yamux-only proposal. See [`muxers`] for the measurement. Lean
            // peers all speak yamux, so offering both costs that wire nothing
            // and keeps one transport stack rather than two.
            #[allow(deprecated)]
            (
                libp2p::yamux::Config::default,
                libp2p_mplex::MplexConfig::default,
            ),
        )
        .expect("failed to add TCP transport to swarm")
        .with_quic()
        .with_behaviour(|_| behavior)
        .expect("failed to add behaviour to swarm")
        .with_swarm_config(|c| {
            // Disable idle connection timeout
            c.with_idle_connection_timeout(Duration::from_secs(u64::MAX))
                // Address order is a preference, not a race. See
                // `DIAL_ADDRESS_CONCURRENCY`.
                .with_dial_concurrency_factor(DIAL_ADDRESS_CONCURRENCY)
        })
        .build();
    let local_peer_id = *swarm.local_peer_id();
    let (bootnode_addrs, undialable_bootnodes) =
        merge_bootnode_dial_addrs(bootnodes, local_peer_id);
    // The merged map is the dial input, so every address a duplicate entry
    // contributed is in the one attempt this peer gets. A refused dial is not
    // fatal: the entry stays in `bootnode_addrs`, so the redial path picks the
    // peer up. Unwrapping here would abort a node over a bootnode file that is
    // merely redundant.
    for (peer_id, addrs) in &bootnode_addrs {
        let opts = DialOpts::peer_id(*peer_id).addresses(addrs.clone()).build();
        let _ = swarm
            .dial(opts)
            .inspect_err(|err| warn!(%peer_id, %err, "Swarm refused the initial bootnode dial"));
    }
    // Every skip in the merge is individually unremarkable and logged at
    // `debug`, but a list that produces no dial target at all leaves the node
    // isolated unless discovery is on, which is worth one line at `warn`.
    if bootnode_addrs.is_empty() && undialable_bootnodes > 0 {
        warn!(
            undialable_bootnodes,
            "No bootnode advertises a quic or tcp port, so nothing will be dialed statically; \
             peering depends entirely on discv5 discovery"
        );
    }
    let quic_addr = Multiaddr::empty()
        .with(listening_socket.ip().into())
        .with(Protocol::Udp(listening_socket.port()))
        .with(Protocol::QuicV1);
    swarm
        .listen_on(quic_addr.clone())
        .map_err(|source| SwarmBuildError::Listen {
            transport: "QUIC",
            addr: quic_addr,
            source,
        })?;
    // Same port number as the QUIC listener above: TCP and UDP are separate
    // namespaces, so this cannot collide with it.
    let tcp_addr = Multiaddr::empty()
        .with(listening_socket.ip().into())
        .with(Protocol::Tcp(listening_socket.port()));
    swarm
        .listen_on(tcp_addr.clone())
        .map_err(|source| SwarmBuildError::Listen {
            transport: "TCP",
            addr: tcp_addr,
            source,
        })?;

    let wire = match wire {
        WireConfig::Lean(lean) => {
            // Subscribe to block topic (all nodes)
            let block_topic = block_topic();
            swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&block_topic)
                .unwrap();

            // Subscribe to aggregation topic (all validators)
            let aggregation_topic = aggregation_topic();
            swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&aggregation_topic)
                .unwrap();

            // The committee metric should reflect validator membership only, not
            // aggregator-only subscriptions.
            let metric_subnet = lean
                .validator_ids
                .iter()
                .map(|vid| vid % lean.attestation_committee_count)
                .min()
                .unwrap_or(0);
            metrics::set_attestation_committee_subnet(metric_subnet);

            let mut attestation_topics: HashMap<u64, libp2p::gossipsub::IdentTopic> =
                HashMap::new();
            for &subnet_id in &lean.subscription_subnets {
                let topic = attestation_subnet_topic(subnet_id);
                swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
                info!(subnet_id, "Subscribed to attestation subnet");
                attestation_topics.insert(subnet_id, topic);
            }

            info!(socket=%listening_socket, "P2P node started");

            Wire::Lean(LeanWire {
                attestation_topics,
                attestation_committee_count: lean.attestation_committee_count,
                block_topic,
                aggregation_topic,
            })
        }
        WireConfig::Beacon(beacon) => {
            // The custody set is columns, not subnets: a column's subnet is
            // `column % DATA_COLUMN_SIDECAR_SUBNET_COUNT`, computed rather than
            // assumed so a network that ever separates the two counts still
            // subscribes to the right topic.
            let column_subnets: Vec<u64> = beacon
                .custody_columns
                .iter()
                .map(|column| {
                    ethlambda_state_transition::beacon::das::compute_subnet_for_data_column_sidecar(
                        *column,
                    )
                })
                .collect();
            let topics = beacon::topics::BeaconTopics::new(
                beacon.fork_digest,
                &column_subnets,
                &beacon.attestation_subnets,
            );
            for topic in &topics.topics {
                swarm.behaviour_mut().gossipsub.subscribe(topic)?;
                info!(topic = %topic, "Subscribed to beacon topic");
            }

            info!(
                socket = %listening_socket,
                fork_digest = %hex::encode(beacon.fork_digest),
                topics = topics.topics.len(),
                columns = beacon.custody_columns.len(),
                attestation_subnets = ?beacon.attestation_subnets,
                "Beacon P2P node started"
            );

            Wire::Beacon(Box::new(beacon::BeaconWire {
                fork_digest: beacon.fork_digest,
                fork: beacon.fork,
                topics,
                config: beacon.config,
                genesis_time: beacon.genesis_time,
                genesis_validators_root: beacon.genesis_validators_root,
                metadata_seq_number: 0,
                custody_columns: beacon.custody_columns,
                attestation_subnets: beacon.attestation_subnets,
            }))
        }
    };

    Ok(BuiltSwarm {
        local_peer_id,
        swarm,
        wire,
        bootnode_addrs,
    })
}

// --- P2P Actor ---

/// Public handle to the P2P actor.
pub struct P2P {
    handle: ActorRef<P2PServer>,
}

impl P2P {
    /// Start discovery, start the I/O adapter, spawn the actor, and wire the
    /// swarm event stream.
    ///
    /// The discv5 server is started here, and its handle seeds the dial loop's
    /// state and schedules its first tick. It is started before the swarm
    /// adapter so a fatal discovery failure (a busy UDP port, say) surfaces
    /// before any actor is running.
    ///
    /// Discovery is not optional. It used to be, behind `--discovery.enable`,
    /// but neither chain has another way to reach a peer it was not handed
    /// statically, and mainnet never had the choice at all: published bootnode
    /// ENRs carry no `quic` entry, so none of them is statically dialable.
    pub async fn spawn(
        built: BuiltSwarm,
        store: Store,
        node_names: HashMap<PeerId, String>,
        discovery: DiscoverySpawnConfig,
    ) -> Result<P2P, DiscoveryError> {
        let discovery = spawn_discovery(discovery).await?;
        let (swarm_stream, swarm_handle) =
            swarm_adapter::start_swarm_adapter(built.swarm, node_names.clone());

        // Seeded from the anchor the store was bootstrapped at, so the first
        // range request starts where the chain does rather than at slot 0.
        let beacon_fetched_through = match store.chain() {
            Chain::Beacon => store.beacon_head().map_or(0, |(slot, _)| slot),
            Chain::Lean => 0,
        };
        // Read before `built.wire` moves into the server below; absent on a
        // lean wire, which `seen_attestations_capacity` floors for.
        let backbone_attestation_subnets = built
            .wire
            .beacon()
            .map_or(0, |beacon| beacon.attestation_subnets.len());

        let server = P2PServer {
            swarm_handle,
            store,
            blockchain: None,
            wire: built.wire,
            connected_peers: HashMap::new(),
            peer_custody: HashMap::new(),
            pending_root_requests: HashMap::new(),
            pending_column_requests: HashMap::new(),
            outbound_requests: HashMap::new(),
            range_sync_state: None,
            beacon_fetched_through,
            bootnode_addrs: built.bootnode_addrs,
            node_names,
            discovery: DiscoveryState::new(discovery, built.local_peer_id),
            seen_blocks: SeenBlocks::new(SEEN_BLOCKS_CAPACITY),
            seen_columns: SeenColumns::new(SEEN_COLUMNS_CAPACITY),
            seen_aggregates: SeenAggregates::new(
                SEEN_AGGREGATES_CAPACITY,
                SEEN_AGGREGATES_CAPACITY,
            ),
            seen_attestations: SeenAttestations::new(seen_attestations_capacity(
                backbone_attestation_subnets,
            )),
            seen_operations: SeenOperations::default(),
            gossip_validation_permits: Arc::new(tokio::sync::Semaphore::new(
                GOSSIP_VALIDATION_PERMITS,
            )),
            column_check_permits: Arc::new(tokio::sync::Semaphore::new(COLUMN_CHECK_PERMITS)),
            attestation_validation_permits: Arc::new(tokio::sync::Semaphore::new(
                ATTESTATION_VALIDATION_PERMITS,
            )),
            aggregator_subnets: HashMap::new(),
        };
        let handle = server.start();
        send_after(
            AGGREGATOR_SUBNET_SWEEP_INTERVAL,
            handle.context(),
            p2p_protocol::LeaveExpiredAggregatorSubnets,
        );
        send_after(
            DIAL_INTERVAL_AT_ZERO_PEERS,
            handle.context(),
            p2p_protocol::DiscoverPeers,
        );
        spawn_listener(handle.context(), swarm_stream.map(WrappedSwarmEvent));
        Ok(P2P { handle })
    }

    pub fn actor_ref(&self) -> &ActorRef<P2PServer> {
        &self.handle
    }
}

/// Message wrapper for swarm events. Not part of the protocol because
/// `SwarmEvent` contains non-Clone types (e.g. `ResponseChannel`).
pub(crate) struct WrappedSwarmEvent(SwarmEvent<BehaviourEvent>);
impl Message for WrappedSwarmEvent {
    type Result = ();
}

/// P2P actor state.
pub struct P2PServer {
    pub(crate) swarm_handle: SwarmHandle,
    pub(crate) store: Store,

    // BlockChain protocol ref (set via InitBlockChain message)
    pub(crate) blockchain: Option<P2PToBlockChainRef>,

    pub(crate) wire: Wire,

    /// Every peer holding at least one established connection, and which side
    /// opened the first one.
    ///
    /// Keyed by peer rather than connection: a peer may hold up to
    /// [`beacon::swarm::MAX_CONNECTIONS_PER_PEER`] of them, and every consumer
    /// here asks "can I talk to this peer", not "over how many sockets". The
    /// direction is the first connection's, which is the one that decides
    /// whether this peer was our choice or the network's.
    pub(crate) connected_peers: HashMap<PeerId, ConnectionDirection>,
    /// The columns each peer custodies, as computed from its own node id and
    /// its advertised custody group count.
    ///
    /// Deterministic on both sides, which is the whole point: the spec notes
    /// that "due to the deterministic custody functions, a node knows exactly
    /// what a peer should be able to respond to", so a column request can be
    /// aimed at a peer that actually holds it instead of scattered at random.
    /// At mainnet's `CUSTODY_REQUIREMENT` a peer holds 8 of 128 columns, so
    /// asking an arbitrary one for a specific column nearly always comes back
    /// empty.
    ///
    /// Absent for any peer that has not answered `metadata/3` and arrived with
    /// no usable `cgc`; [`columns_custodied_by`] treats absent as "no opinion",
    /// never as "custodies nothing".
    pub(crate) peer_custody: HashMap<PeerId, Vec<u64>>,
    pub(crate) pending_root_requests: HashMap<H256, PendingRequest>,
    /// One entry per block root with an in-flight or backed-off
    /// `DataColumnsByRoot` lookup. Mirrors `pending_root_requests`'s role for
    /// the block path: `fetch_missing_columns` dedupes against it, and
    /// `handle_column_fetch_failure` is the only place an entry is retired.
    pub(crate) pending_column_requests: HashMap<H256, PendingColumnRequest>,
    pub(crate) outbound_requests: HashMap<ReqRespRequestId, PendingRequestKind>,
    pub(crate) range_sync_state: Option<RangeSyncState>,

    /// Highest beacon slot handed to the chain actor, whether or not it has
    /// been imported yet.
    pub(crate) beacon_fetched_through: u64,
    bootnode_addrs: HashMap<PeerId, Vec<Multiaddr>>,
    node_names: HashMap<PeerId, String>,

    pub(crate) discovery: DiscoveryState,

    /// The first valid block per `(slot, proposer)` accepted from gossip.
    pub(crate) seen_blocks: SeenBlocks,
    /// The first valid sidecar per `(slot, proposer, index)` accepted from
    /// gossip. Bounded by capacity, so a fabricated slot cannot grow it.
    pub(crate) seen_columns: SeenColumns,
    /// Accepted `beacon_aggregate_and_proof`s, by `(target_epoch,
    /// aggregator_index)` and by `(hash_tree_root(data), committee_index)`.
    pub(crate) seen_aggregates: SeenAggregates,
    /// Accepted `beacon_attestation_{subnet_id}`s, by `(target_epoch,
    /// attester_index)`.
    pub(crate) seen_attestations: SeenAttestations,
    /// The first valid operation per validator (or per attesting index, for
    /// attester slashings) accepted from gossip on the four operation topics.
    /// Recorded only after the stateful check passes and never pruned: an
    /// entry needs a validator to really exit, be slashed or change
    /// credentials, so it is bounded by the registry.
    pub(crate) seen_operations: SeenOperations,
    /// Permits for block and column stateful gossip checks in flight on
    /// blocking threads.
    pub(crate) gossip_validation_permits: Arc<tokio::sync::Semaphore>,
    /// Permits for data column chain checks in flight on blocking threads.
    pub(crate) column_check_permits: Arc<tokio::sync::Semaphore>,
    /// Permits for aggregate and subnet-attestation stateful gossip checks in
    /// flight on blocking threads. Separate from
    /// [`Self::gossip_validation_permits`]; see
    /// [`ATTESTATION_VALIDATION_PERMITS`].
    pub(crate) attestation_validation_permits: Arc<tokio::sync::Semaphore>,

    /// The attestation subnets joined for a validator client's aggregators,
    /// each with the last slot it is needed for. Short-lived by design: never
    /// advertised in `attnets`, and left once the slot has passed. The
    /// backbone subnets are separate and never left.
    pub(crate) aggregator_subnets: HashMap<u64, u64>,
}

impl P2PServer {
    fn resolve_node_name(&self, peer_id: Option<&PeerId>) -> &str {
        peer_id
            .and_then(|p| self.node_names.get(p))
            .map(String::as_str)
            .unwrap_or("unknown")
    }

    /// Republish the peer gauges from the state that actually decides them.
    ///
    /// Set from a full re-count rather than incremented and decremented per
    /// event, because a gauge kept by arithmetic is only ever as right as the
    /// least reliable event that touches it: one missed decrement and it is
    /// wrong until restart, in the direction that hides a problem. These are
    /// the gauges used to tell whether connections leak, so they must not be
    /// able to leak themselves.
    ///
    /// Cheap enough to call on every connect and disconnect: the work is
    /// proportional to the peer count, which is bounded by
    /// [`beacon::swarm::max_connections`]. The swarm's own connection counters
    /// are the other half of the leak question, and the swarm lives in
    /// [`swarm_adapter`]'s task rather than here, so those are published from
    /// its metric tick instead.
    pub(crate) fn refresh_peer_metrics(&self) {
        let (mut inbound, mut outbound) = (0, 0);
        for direction in self.connected_peers.values() {
            match direction {
                ConnectionDirection::Inbound => inbound += 1,
                ConnectionDirection::Outbound => outbound += 1,
            }
        }
        metrics::set_peers_by_direction(inbound, outbound);
        self.refresh_custody_column_metrics();
    }

    /// Publish, per column this node samples, how many connected peers are
    /// known to custody it.
    ///
    /// This is the supply side of the data-availability gate: a block is held
    /// until every sampled column arrives, so a column sitting at zero peers is
    /// a stall waiting to happen, and it is invisible in a total peer count.
    ///
    /// Only the columns this node samples get a series. Publishing all 128
    /// would bury the eight that can actually block an import, and the custody
    /// set is fixed for the life of the node, so the label set is stable.
    ///
    /// Counted through [`columns_custodied_by`], the same answer the fetch path
    /// picks its peers with, so the gauge cannot say a column has custodians
    /// that a lookup for it would not find.
    ///
    /// Called from every writer of either input, which is both ends of a
    /// connection and [`req_resp::handlers::record_peer_custody`]. The last of
    /// those is the one that matters: a peer's custody arrives with its
    /// `metadata/3` answer, *after* it connects, so a gauge refreshed on
    /// connection events alone would read every column at the zero it had
    /// before the peer said anything — which is the exact reading this gauge
    /// was added to mean "a stall waiting to happen".
    pub(crate) fn refresh_custody_column_metrics(&self) {
        let Some(wire) = self.wire.beacon() else {
            return;
        };
        for column in wire.custody_columns.iter().copied() {
            metrics::set_custody_column_peers(column, columns_custodied_by(self, column).len());
        }
    }
}

// Protocol trait for internal messages only (retry scheduling).
// Network-api messages and swarm events are handled via manual Handler impls.
#[protocol]
pub(crate) trait P2PProtocol: Send + Sync {
    #[allow(dead_code)] // invoked via send_after, not called directly
    fn retry_block_fetch(&self, root: H256) -> Result<(), ActorError>;
    #[allow(dead_code)] // invoked via send_after, not called directly
    fn retry_data_column_fetch(&self, block_root: H256) -> Result<(), ActorError>;
    #[allow(dead_code)] // invoked via send_after, not called directly
    fn retry_peer_redial(&self, peer_id: PeerId) -> Result<(), ActorError>;
    #[allow(dead_code)] // invoked via send_after, not called directly
    fn discover_peers(&self) -> Result<(), ActorError>;
    #[allow(dead_code)] // invoked via send_after, not called directly
    fn leave_expired_aggregator_subnets(&self) -> Result<(), ActorError>;
    #[allow(dead_code)] // invoked via send_after, not called directly
    fn retry_beacon_range_batch(&self) -> Result<(), ActorError>;
}

#[actor(protocol = P2PProtocol)]
impl P2PServer {
    #[send_handler]
    async fn handle_retry_block_fetch(
        &mut self,
        msg: p2p_protocol::RetryBlockFetch,
        _ctx: &Context<Self>,
    ) {
        let root = msg.root;
        // Check if still pending (might have succeeded during backoff)
        if !self.pending_root_requests.contains_key(&root) {
            trace!(%root, "Block fetch completed during backoff, skipping retry");
            return;
        }

        trace!(%root, "Retrying block fetch after backoff");

        if !fetch_block_from_peer(self, root).await {
            tracing::error!(%root, "Failed to retry block fetch, giving up");
            self.pending_root_requests.remove(&root);
        }
    }

    #[send_handler]
    async fn handle_retry_data_column_fetch(
        &mut self,
        msg: p2p_protocol::RetryDataColumnFetch,
        _ctx: &Context<Self>,
    ) {
        let block_root = msg.block_root;
        // Same "might have completed during backoff" guard as
        // `handle_retry_block_fetch`, and the same reason for it: the reissued
        // request must ask for what is still missing, which
        // `pending_column_requests` is the only place that remembers.
        let Some(pending) = self.pending_column_requests.get(&block_root) else {
            trace!(%block_root, "Data column fetch completed during backoff, skipping retry");
            return;
        };
        let columns = pending.columns.clone();

        if !fetch_data_columns_from_peer(self, block_root, columns).await {
            tracing::error!(%block_root, "Failed to retry data column fetch, giving up");
            self.pending_column_requests.remove(&block_root);
        }
    }

    #[send_handler]
    async fn handle_retry_peer_redial(
        &mut self,
        msg: p2p_protocol::RetryPeerRedial,
        _ctx: &Context<Self>,
    ) {
        let peer_id = msg.peer_id;

        // Skip if already reconnected
        if self.connected_peers.contains_key(&peer_id) {
            trace!(%peer_id, "Bootnode reconnected during redial delay, skipping");
            return;
        }

        if let Some(addrs) = self.bootnode_addrs.get(&peer_id) {
            trace!(%peer_id, "Redialing disconnected bootnode");
            self.swarm_handle
                .dial(DialOpts::peer_id(peer_id).addresses(addrs.clone()).build());
        }
    }

    #[send_handler]
    async fn handle_leave_expired_aggregator_subnets(
        &mut self,
        _msg: p2p_protocol::LeaveExpiredAggregatorSubnets,
        ctx: &Context<Self>,
    ) {
        send_after(
            AGGREGATOR_SUBNET_SWEEP_INTERVAL,
            ctx.clone(),
            p2p_protocol::LeaveExpiredAggregatorSubnets,
        );
        gossipsub::leave_expired_aggregator_subnets(self);
        gossipsub::prune_attestation_pool(self);
        gossipsub::prune_operation_pool(self);
    }

    #[send_handler]
    async fn handle_discover_peers(
        &mut self,
        _msg: p2p_protocol::DiscoverPeers,
        ctx: &Context<Self>,
    ) {
        let dialed = dial_tick(self).await;
        // Rescheduled on every path out of the tick, so nothing above can stop
        // the loop. The gap is a function of how full the peer table is rather
        // than a flat heartbeat: near `MAX_DIAL_RATE_PER_SECOND` while short of
        // peers, easing off as they arrive. See `dial::dial_interval`.
        //
        // Unless the tick dialed nothing, which the curve cannot tell on its
        // own: it reads a shortfall against `target_peers`, and a network with
        // fewer peers than that to offer leaves that shortfall open forever.
        // Pacing on it alone would hold the loop at its floor for the life of
        // the process, re-drawing a candidate pool of peers it is already
        // connected to. One dial opened puts it straight back on the curve.
        let interval = if dialed {
            dial_interval(dial_progress(self))
        } else {
            DIAL_INTERVAL_AT_TARGET
        };
        send_after(interval, ctx.clone(), p2p_protocol::DiscoverPeers);
    }

    /// The deadline of a range batch held back for custody. Scheduled once,
    /// when the batch starts waiting; see [`RANGE_BATCH_CUSTODY_WAIT`].
    #[send_handler]
    async fn handle_retry_beacon_range_batch(
        &mut self,
        _msg: p2p_protocol::RetryBeaconRangeBatch,
        ctx: &Context<Self>,
    ) {
        resume_range_batch_held_for_custody(self, ctx).await;
    }
}

// --- Manual Handler impls for network-api messages ---

impl Handler<InitBlockChain> for P2PServer {
    async fn handle(&mut self, msg: InitBlockChain, _ctx: &Context<Self>) {
        self.blockchain = Some(msg.blockchain);
        info!("BlockChain protocol ref initialized");
    }
}

impl Handler<PublishBlock> for P2PServer {
    async fn handle(&mut self, msg: PublishBlock, _ctx: &Context<Self>) {
        publish_block(self, msg.block).await;
    }
}

impl Handler<PublishAttestation> for P2PServer {
    async fn handle(&mut self, msg: PublishAttestation, _ctx: &Context<Self>) {
        publish_attestation(self, msg.attestation).await;
    }
}

impl Handler<PublishAggregatedAttestation> for P2PServer {
    async fn handle(&mut self, msg: PublishAggregatedAttestation, _ctx: &Context<Self>) {
        publish_aggregated_attestation(self, msg.attestation).await;
    }
}

impl Handler<PublishBeaconAggregate> for P2PServer {
    async fn handle(&mut self, msg: PublishBeaconAggregate, _ctx: &Context<Self>) {
        publish_beacon_aggregate(self, msg.aggregate).await;
    }
}

impl Handler<PublishBeaconOperation> for P2PServer {
    async fn handle(&mut self, msg: PublishBeaconOperation, _ctx: &Context<Self>) {
        publish_beacon_operation(self, msg.operation).await;
    }
}

impl Handler<PublishBeaconBlock> for P2PServer {
    async fn handle(&mut self, msg: PublishBeaconBlock, _ctx: &Context<Self>) {
        publish_beacon_block(self, msg.block, msg.sidecars).await;
    }
}

impl Handler<SubscribeAttestationSubnets> for P2PServer {
    async fn handle(&mut self, msg: SubscribeAttestationSubnets, _ctx: &Context<Self>) {
        gossipsub::join_aggregator_subnets(self, msg.subnets);
    }
}

impl Handler<PublishBeaconAttestation> for P2PServer {
    async fn handle(&mut self, msg: PublishBeaconAttestation, _ctx: &Context<Self>) {
        publish_beacon_attestation(self, msg.subnet_id, msg.attestation).await;
    }
}

impl Handler<FetchBlock> for P2PServer {
    async fn handle(&mut self, msg: FetchBlock, _ctx: &Context<Self>) {
        fetch_missing(self, msg.request).await;
    }
}

impl Handler<CheckDataColumnSidecars> for P2PServer {
    async fn handle(&mut self, msg: CheckDataColumnSidecars, _ctx: &Context<Self>) {
        beacon::column_checks::check_and_forward(self, msg.sidecars);
    }
}

/// Ask for whatever a [`FetchRequest`] says is missing.
///
/// Both halves are by-root lookups with their own dedup and retry ladder, and
/// a request may name either or both. There is no by-range arm here: a caller
/// on the chain side has a root, not a span, and the span worth asking for is
/// the one this crate is already syncing, so
/// [`req_resp::request_beacon_data_columns_by_range`] rides every
/// `BeaconBlocksByRange` batch instead of waiting to be asked.
async fn fetch_missing(server: &mut P2PServer, request: FetchRequest) {
    let FetchRequest {
        block_root,
        needs_block,
        columns,
    } = request;
    if needs_block {
        fetch_missing_block(server, block_root).await;
    }
    if !columns.is_empty() {
        fetch_missing_columns(server, block_root, columns).await;
    }
}

/// The by-root block half of a [`FetchRequest`].
async fn fetch_missing_block(server: &mut P2PServer, root: H256) {
    // Deduplicate - if already pending, ignore
    if server.pending_root_requests.contains_key(&root) {
        trace!(%root, "Block fetch already in progress, ignoring duplicate");
        return;
    }
    fetch_block_from_peer(server, root).await;
}

/// The by-root column half of a [`FetchRequest`].
async fn fetch_missing_columns(server: &mut P2PServer, block_root: H256, columns: Vec<u64>) {
    // Same one-lookup-per-root rule as the block half, but merged rather
    // than dropped: the availability gate may re-ask for a root already
    // in flight with a wider column set than the first ask named, as
    // columns trickle in, and dropping the difference would rest on an
    // unenforced invariant that a re-ask is always a subset of what is
    // already pending. A column added this way misses the request
    // already on the wire, which cannot be widened after it was sent;
    // it rides the next event for this root instead — a retry of this
    // lookup, which resends whatever `columns` now holds, or, once this
    // lookup resolves and the entry is gone, a fresh `FetchRequest`
    // from a caller that rechecks what is still missing.
    //
    // "In flight" has to mean it, though: an entry whose round never
    // reported back would otherwise deduplicate this root against a lookup
    // that will never ask anything again. Past `STALE_COLUMN_LOOKUP` the
    // entry is dropped and this ask starts a lookup of its own.
    if let Some(pending) = server.pending_column_requests.get_mut(&block_root) {
        if pending.last_asked.elapsed() < STALE_COLUMN_LOOKUP {
            for column in columns {
                if !pending.columns.contains(&column) {
                    trace!(%block_root, column, "Merging a new column into an in-flight data column fetch");
                    pending.columns.push(column);
                }
            }
            return;
        }
        debug!(%block_root, "Replacing a data column lookup that stopped asking");
        server.pending_column_requests.remove(&block_root);
    }
    fetch_data_columns_from_peer(server, block_root, columns).await;
}

// --- Manual Handler for swarm events ---

impl Handler<WrappedSwarmEvent> for P2PServer {
    async fn handle(&mut self, msg: WrappedSwarmEvent, ctx: &Context<Self>) {
        handle_swarm_event(self, msg.0, ctx).await;
    }
}

async fn handle_swarm_event(
    server: &mut P2PServer,
    event: SwarmEvent<BehaviourEvent>,
    ctx: &Context<P2PServer>,
) {
    match event {
        SwarmEvent::Behaviour(behaviour_event) => {
            handle_behaviour_event(server, behaviour_event, ctx).await;
        }
        SwarmEvent::ConnectionEstablished {
            peer_id,
            endpoint,
            num_established,
            ..
        } => {
            let direction = ConnectionDirection::from(&endpoint);
            // Read off the connection's own address rather than which one we
            // dialed: with both QUIC and TCP offered, libp2p races every
            // address in a dial and may connect over either. This is what
            // answers "did the TCP fallback actually help", as a metric because
            // the trace field alone is invisible at default verbosity.
            let transport = transport_label(endpoint.get_remote_address());
            metrics::inc_peer_connection_transport(direction.as_str(), transport);
            if num_established.get() == 1 {
                server.connected_peers.insert(peer_id, direction);
                server.refresh_peer_metrics();
                let peer_count = server.connected_peers.len();
                metrics::notify_peer_connected(
                    server.resolve_node_name(Some(&peer_id)),
                    direction.as_str(),
                    "success",
                );
                // Compute the beacon status and its log fields first, so no
                // borrow of `server.wire` is alive across the send.
                let beacon_status = server.wire.beacon().map(|wire| {
                    (
                        beacon::handler::build_status(
                            &server.store,
                            wire,
                            beacon::handler::StatusVersion::V1,
                        ),
                        hex::encode(wire.fork_digest),
                    )
                });
                match beacon_status {
                    Some((status, digest)) => {
                        trace!(
                            %peer_id,
                            %direction,
                            %transport,
                            peer_count,
                            fork_digest = %digest,
                            "Peer connected"
                        );
                        beacon::handler::send_status(server, peer_id, status).await;
                        // Behind the handshake rather than in place of it: this
                        // is what tells us which columns the peer custodies, and
                        // an inbound peer has no ENR here to read a `cgc` from.
                        beacon::handler::request_metadata(server, peer_id).await;
                    }
                    None => {
                        let our_status = build_status(&server.store);
                        let our_finalized_slot = our_status.finalized.slot;
                        let our_head_slot = our_status.head.slot;
                        trace!(
                            %peer_id,
                            %direction,
                            %transport,
                            peer_count,
                            our_finalized_slot,
                            our_head_slot,
                            "Peer connected"
                        );
                        server
                            .swarm_handle
                            .send_request(
                                peer_id,
                                Request::LeanStatus(our_status),
                                ReqRespProtocol::LeanStatus,
                            )
                            .await;
                    }
                }
            } else {
                trace!(%peer_id, %direction, %transport, "Added peer connection");
            }
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            endpoint,
            num_established,
            cause,
            ..
        } => {
            let closed_direction = ConnectionDirection::from(&endpoint);
            let reason = match &cause {
                None => "remote_close",
                Some(err) => {
                    // Categorize disconnection reasons
                    let err_str = err.to_string().to_lowercase();
                    if err_str.contains("timeout")
                        || err_str.contains("timedout")
                        || err_str.contains("keepalive")
                    {
                        "timeout"
                    } else if err_str.contains("reset") || err_str.contains("connectionreset") {
                        "remote_close"
                    } else {
                        "error"
                    }
                }
            };
            let cause_label = disconnect_cause(cause.as_ref());
            if num_established == 0 {
                // Report the direction this peer was *counted* under, not the
                // one the last socket happened to carry. A peer may hold both
                // an inbound and an outbound connection, and whichever closes
                // last decides `closed_direction`; attributing the disconnect
                // to that would let the per-direction connect and disconnect
                // counters drift apart, and those counters are exactly what a
                // "peers held" figure gets derived from.
                let direction = server
                    .connected_peers
                    .remove(&peer_id)
                    .unwrap_or(closed_direction);
                forget_discovered_peer(server, &peer_id);
                server.refresh_peer_metrics();
                let peer_count = server.connected_peers.len();
                metrics::notify_peer_disconnected(
                    server.resolve_node_name(Some(&peer_id)),
                    direction.as_str(),
                    reason,
                );
                // Charged here rather than on every closed connection, so this
                // totals to the same count as the metric above and the two can
                // be read against each other directly.
                metrics::inc_peer_disconnect_cause(direction.as_str(), cause_label);

                // `debug!` rather than the `trace!` below, and carrying the
                // cause itself: `cause_label` deliberately cannot name what an
                // `io_other` was, so this is the only place that answer exists.
                debug!(
                    %peer_id,
                    %direction,
                    %cause_label,
                    cause = ?cause,
                    "Peer connection closed"
                );
                trace!(
                    %peer_id,
                    %direction,
                    %reason,
                    peer_count,
                    "Peer disconnected"
                );

                // Schedule redial if this is a bootnode
                if server.bootnode_addrs.contains_key(&peer_id) {
                    send_after(
                        Duration::from_secs(PEER_REDIAL_INTERVAL_SECS),
                        ctx.clone(),
                        p2p_protocol::RetryPeerRedial { peer_id },
                    );
                    trace!(%peer_id, "Scheduled bootnode redial in {}s", PEER_REDIAL_INTERVAL_SECS);
                }
            } else {
                trace!(%peer_id, direction = %closed_direction, %reason, "Peer connection closed but other connections remain");
            }
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            let result = if error.to_string().to_lowercase().contains("timed out") {
                "timeout"
            } else {
                "error"
            };
            metrics::notify_peer_connected(
                server.resolve_node_name(peer_id.as_ref()),
                "outbound",
                result,
            );
            debug!(?peer_id, %error, "Outgoing connection error");

            if let Some(pid) = peer_id {
                // A dial that never establishes ends up here rather than in
                // `ConnectionClosed`, so this is the only place a peer we dialed
                // but never connected to can be forgotten. Gated on the peer
                // being gone: a *second* dial to an already-connected peer can
                // fail here (the bootnode redial path is one way), and dropping
                // a live peer's `attnets` would make `covered_subnets`
                // under-count subnets we do in fact cover.
                if !server.connected_peers.contains_key(&pid) {
                    forget_discovered_peer(server, &pid);
                }

                // Schedule redial if this was a bootnode
                if server.bootnode_addrs.contains_key(&pid)
                    && !server.connected_peers.contains_key(&pid)
                {
                    send_after(
                        Duration::from_secs(PEER_REDIAL_INTERVAL_SECS),
                        ctx.clone(),
                        p2p_protocol::RetryPeerRedial { peer_id: pid },
                    );
                    trace!(%pid, "Scheduled bootnode redial after connection error");
                }
            }
        }
        SwarmEvent::IncomingConnectionError { peer_id, error, .. } => {
            // A connection our own limit refused is policy working, not a
            // fault. Once the cap is reached every further dial arrives here,
            // so counting these as errors would bury the real ones under the
            // steady rate of peers we are deliberately turning away, and warn
            // once per rejection while doing it. See `beacon::swarm::connection_limits`.
            let refused_at_capacity = matches!(
                &error,
                libp2p::swarm::ListenError::Denied { cause }
                    if cause
                        .downcast_ref::<libp2p::connection_limits::Exceeded>()
                        .is_some()
            );
            if refused_at_capacity {
                metrics::notify_peer_connected(
                    server.resolve_node_name(peer_id.as_ref()),
                    "inbound",
                    "refused_at_capacity",
                );
                let peer_count = server.connected_peers.len();
                debug!(peer_count, "Refused an inbound connection at capacity");
            } else {
                metrics::notify_peer_connected(
                    server.resolve_node_name(peer_id.as_ref()),
                    "inbound",
                    "error",
                );
                debug!(%error, "Incoming connection error");
            }
        }
        _ => {
            trace!(?event, "Ignored swarm event");
        }
    }
}

/// Dispatch one [`BehaviourEvent`], tagging every req/resp field's event with
/// the [`ReqRespProtocol`] variant that names it.
///
/// The tag is the whole of what each req/resp arm decides, so the match yields
/// it as a value and the one call that consumes it sits below, rather than
/// each arm repeating the call with a different constant.
///
/// Deliberately exhaustive, with no wildcard arm: `handle_swarm_event`'s own
/// catch-all would otherwise silently swallow a `BehaviourEvent` variant this
/// function forgot to name, for the same reason the fork's own `DialError`
/// conversion is matched exhaustively (see `DialOutcome`'s `From` impl in
/// `swarm_adapter.rs`). Adding a fifteenth [`ReqResp`] field forces this to
/// grow an arm rather than falling through unnoticed.
async fn handle_behaviour_event(
    server: &mut P2PServer,
    event: BehaviourEvent,
    ctx: &Context<P2PServer>,
) {
    let (protocol, event) = match event {
        // Registered for interop only; see `Behaviour`'s doc comment for why
        // its events are never read.
        BehaviourEvent::Identify(_) => return,
        // A deny from this behaviour already denied the connection at the
        // swarm level; nothing here needs to react to it a second time.
        BehaviourEvent::ConnectionLimits(_) => return,
        BehaviourEvent::Gossipsub(libp2p::gossipsub::Event::Message {
            propagation_source,
            message_id,
            message,
        }) => {
            return gossipsub::handle_gossip_message(
                server,
                ctx,
                propagation_source,
                message_id,
                message,
            )
            .await;
        }
        BehaviourEvent::Gossipsub(_) => return,
        BehaviourEvent::ReqResp(event) => match event {
            ReqRespEvent::LeanStatus(e) => (ReqRespProtocol::LeanStatus, e),
            ReqRespEvent::LeanBlocksByRoot(e) => (ReqRespProtocol::LeanBlocksByRoot, e),
            ReqRespEvent::LeanBlocksByRange(e) => (ReqRespProtocol::LeanBlocksByRange, e),
            ReqRespEvent::BeaconStatusV1(e) => (ReqRespProtocol::BeaconStatusV1, e),
            ReqRespEvent::BeaconStatusV2(e) => (ReqRespProtocol::BeaconStatusV2, e),
            ReqRespEvent::BeaconPing(e) => (ReqRespProtocol::BeaconPing, e),
            ReqRespEvent::BeaconMetadataV1(e) => (ReqRespProtocol::BeaconMetadataV1, e),
            ReqRespEvent::BeaconMetadataV2(e) => (ReqRespProtocol::BeaconMetadataV2, e),
            ReqRespEvent::BeaconMetadataV3(e) => (ReqRespProtocol::BeaconMetadataV3, e),
            ReqRespEvent::BeaconGoodbye(e) => (ReqRespProtocol::BeaconGoodbye, e),
            ReqRespEvent::BeaconBlocksByRange(e) => (ReqRespProtocol::BeaconBlocksByRange, e),
            ReqRespEvent::BeaconBlocksByRoot(e) => (ReqRespProtocol::BeaconBlocksByRoot, e),
            ReqRespEvent::DataColumnSidecarsByRange(e) => {
                (ReqRespProtocol::DataColumnSidecarsByRange, e)
            }
            ReqRespEvent::DataColumnSidecarsByRoot(e) => {
                (ReqRespProtocol::DataColumnSidecarsByRoot, e)
            }
        },
    };

    req_resp::handle_req_resp_message(server, protocol, event, ctx).await;
}

// --- Node identity helpers ---

/// Derive each entry's `PeerId` from its secp256k1 private key.
///
/// Drops entries whose key fails to parse, with a `warn!` per drop.
pub fn derive_peer_ids(names_and_privkeys: HashMap<String, H256>) -> HashMap<PeerId, String> {
    names_and_privkeys
        .into_iter()
        .filter_map(|(name, mut privkey)| {
            match secp256k1::SecretKey::try_from_bytes(&mut privkey.0) {
                Ok(privkey) => {
                    let pubkey = Keypair::from(secp256k1::Keypair::from(privkey)).public();
                    Some((PeerId::from_public_key(&pubkey), name))
                }
                Err(err) => {
                    warn!(%name, %err, "Skipping node-name registry entry: invalid secp256k1 privkey");
                    None
                }
            }
        })
        .collect()
}

// --- Bootnode parsing ---

/// [`Clone`] so one parse of the bootnode file can serve both `build_swarm` and
/// discovery: every field is plain data, and cloning beats reading the file twice.
#[derive(Clone)]
pub struct Bootnode {
    pub(crate) ip: IpAddr,
    /// The libp2p QUIC port, when the ENR advertises one.
    ///
    /// `None` for a record that does not advertise one. See
    /// [`Bootnode::tcp_port`] for the other transport that can still make such
    /// a record dialable: every beacon-chain bootnode published today is
    /// exactly that case, `tcp` and `udp` but no `quic`.
    pub(crate) quic_port: Option<u16>,
    /// The libp2p TCP port, when the ENR advertises one.
    ///
    /// `None` for the ENRs lean-quickstart generates today, which carry only
    /// `ip`/`quic`/`secp256k1`. Every published mainnet beacon-chain bootnode
    /// carries this instead of `quic`, which is what makes them statically
    /// dialable now that the swarm speaks both transports.
    pub(crate) tcp_port: Option<u16>,
    /// The discv5 UDP port, when the ENR advertises one.
    ///
    /// `None` for the ENRs lean-quickstart generates today, which carry only
    /// `ip`/`quic`/`secp256k1`. Such a bootnode is still dialed statically over
    /// QUIC or TCP; it just cannot seed the discv5 routing table.
    pub(crate) udp_port: Option<u16>,
    pub(crate) public_key: PublicKey,
}

impl Bootnode {
    /// This bootnode as a discv5 seed, or `None` when its ENR advertises no
    /// `udp` port and it therefore cannot be reached by discovery.
    ///
    /// `tcp_port` carries this bootnode's real advertised TCP port when it has
    /// one, now that ethlambda dials TCP too; it is `0` only when the ENR
    /// advertises none, which ethrex reads as "no TCP listener".
    pub(crate) fn as_discovery_node(&self) -> Option<ethrex_p2p::types::Node> {
        let udp_port = self.udp_port?;
        // libp2p and ethrex hold the same key in different representations:
        // ethrex wants the 65-byte uncompressed SEC1 form with its leading 0x04
        // tag stripped.
        let uncompressed = self
            .public_key
            .clone()
            .try_into_secp256k1()
            .ok()?
            .to_bytes_uncompressed();
        // `Node::from_enr` would compute the same identity from the record, but
        // it falls back to `tcp` when `udp` is absent, which would seed a
        // tcp-only bootnode under a port discv5 does not listen on.
        Some(ethrex_p2p::types::Node::new(
            self.ip,
            udp_port,
            self.tcp_port.unwrap_or(0),
            ethrex_common::H512::from_slice(&uncompressed[1..]),
        ))
    }
}

/// Decode `enr:`-prefixed records into usable bootnodes.
///
/// Records that cannot be decoded, or that lack an IP, a public key or any
/// dialable port at all, are skipped with a warning rather than aborting
/// startup: one malformed entry in the bootnode file should not stop the node
/// from booting. A record carrying only one of `quic`, `tcp` and `udp` is kept,
/// since each is useful on its own.
pub fn parse_enrs(enrs: Vec<String>) -> Vec<Bootnode> {
    let configured = enrs.len();
    let bootnodes: Vec<Bootnode> = enrs
        .into_iter()
        .filter_map(|enr_str| {
            parse_enr(&enr_str)
                .inspect_err(
                    |reason| warn!(%reason, enr = %enr_str, "Skipping unusable bootnode ENR"),
                )
                .ok()
        })
        .collect();
    // Each rejection above already warned, but a file where *every* entry is
    // unusable boots a node with an empty bootnode list, which otherwise looks
    // identical to having configured none at all.
    if bootnodes.is_empty() && configured > 0 {
        warn!(
            configured,
            "No bootnode ENR could be used; the node starts with no bootnodes"
        );
    }
    bootnodes
}

fn parse_enr(enr_str: &str) -> Result<Bootnode, String> {
    let stripped = enr_str
        .strip_prefix("enr:")
        .ok_or_else(|| "missing enr: prefix".to_string())?;
    let decoded = ethrex_common::base64::decode(stripped.as_bytes());
    let record = NodeRecord::decode(&decoded).map_err(|err| format!("RLP decode failed: {err}"))?;
    let pairs = record.pairs();

    // A record with no dialable `quic` entry is not an error: it may still
    // advertise `tcp`, and even a record with neither is worth keeping as a
    // discv5 seed. Keep it and let `build_swarm` skip it when it picks static
    // dial targets.
    let quic_port = read_quic_port(&record);

    // An explicit `udp: 0` is no more reachable than a `quic: 0`, which
    // `read_quic_port` already rejects. Reading it verbatim would seed discv5
    // with a contact on a port nothing listens on.
    let udp_port = pairs.udp_port.and_then(dialable_port);

    // Same rule for `tcp`, the transport every published beacon-chain bootnode
    // advertises and none of them pairs with a `quic` entry.
    let tcp_port = read_tcp_port(pairs);

    let public_key = read_public_key(pairs)
        .ok_or_else(|| "node record missing or malformed public key".to_string())?;

    let ip = read_ip(pairs).ok_or_else(|| "node record missing IP address".to_string())?;

    // `quic`, `tcp` and `udp` are independently optional, but a record with none
    // of them is reachable by nothing we speak: it can be neither dialed nor
    // seeded. Drop it here rather than carry a contact no code path can use.
    if quic_port.is_none() && tcp_port.is_none() && udp_port.is_none() {
        return Err("node advertises none of quic, tcp, or udp".to_string());
    }

    Ok(Bootnode {
        ip,
        quic_port,
        tcp_port,
        udp_port,
        public_key: public_key.into(),
    })
}

// --- Utility functions ---

/// Every address worth trying for one peer, from whichever of its two ports are
/// present.
///
/// Empty when neither is, which is a discv5-only seed: it can still answer
/// FINDNODE, but there is nothing for the swarm to dial.
///
/// The order *is* the preference, and `quic` leads it. libp2p starts
/// `dial_concurrency_factor` of these at a time, which
/// [`DIAL_ADDRESS_CONCURRENCY`] pins to one, so a peer's `tcp` address is
/// reached only once the QUIC attempt ahead of it has failed. Under the default
/// factor both went into one `FuturesUnordered` and the faster handshake won,
/// which sounds neutral and is not: TCP won most of those races and every win
/// was another mplex connection.
///
/// Shared by both dial paths, so a change to what counts as dialable cannot
/// apply to static bootnodes and discovered peers differently: static bootnodes
/// in [`build_swarm`] and discovered peers in
/// [`admission::admit`](discovery::admission).
pub(crate) fn dial_addrs(
    ip: IpAddr,
    quic_port: Option<u16>,
    tcp_port: Option<u16>,
    peer_id: PeerId,
) -> Vec<Multiaddr> {
    let mut addrs = Vec::with_capacity(2);
    if let Some(port) = quic_port {
        addrs.push(quic_multiaddr(ip, port, peer_id));
    }
    if let Some(port) = tcp_port {
        addrs.push(tcp_multiaddr(ip, port, peer_id));
    }
    addrs
}

/// Static dial targets, one entry per peer id, merged across duplicate bootnode
/// entries. Also reports how many entries named no dialable transport at all.
///
/// Two entries can name one peer: the same ENR pasted twice, or an old and a new
/// record for a single secp256k1 key. `parse_enrs` does not dedup, and
/// `DialOpts::peer_id` dials under the default `DisconnectedAndNotDialing`
/// condition, so a second dial to a peer already being dialed is refused
/// outright.
///
/// Merging before dialing rather than while dialing is what puts every address
/// into the one attempt the peer gets. Dialing per entry would take only the
/// first entry's addresses: with a stale QUIC-only record listed ahead of a
/// newer one carrying a live TCP port, startup would race a dead address alone,
/// burn the full connect timeout, and reach the live one only on the redial.
fn merge_bootnode_dial_addrs(
    bootnodes: Vec<Bootnode>,
    local_peer_id: PeerId,
) -> (HashMap<PeerId, Vec<Multiaddr>>, usize) {
    let mut merged: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
    let mut undialable = 0usize;
    for bootnode in bootnodes {
        let peer_id = PeerId::from_public_key(&bootnode.public_key);
        if peer_id == local_peer_id {
            continue;
        }
        let addrs = bootnode_dial_addrs(&bootnode, peer_id);
        if addrs.is_empty() {
            // Discovery-only seed: reachable over discv5, but with no QUIC or
            // TCP port there is nothing for the swarm to dial.
            undialable += 1;
            debug!(%peer_id, ip = %bootnode.ip, "Bootnode advertises no dialable transport, discv5 seed only");
            continue;
        }
        match merged.entry(peer_id) {
            Entry::Occupied(mut known) => {
                debug!(
                    %peer_id,
                    ip = %bootnode.ip,
                    "Bootnode list names this peer more than once, merging its addresses"
                );
                let known = known.get_mut();
                for addr in addrs {
                    if !known.contains(&addr) {
                        known.push(addr);
                    }
                }
            }
            Entry::Vacant(unknown) => {
                unknown.insert(addrs);
            }
        }
    }
    (merged, undialable)
}

/// Dial targets for a static bootnode. See [`dial_addrs`].
pub(crate) fn bootnode_dial_addrs(bootnode: &Bootnode, peer_id: PeerId) -> Vec<Multiaddr> {
    dial_addrs(bootnode.ip, bootnode.quic_port, bootnode.tcp_port, peer_id)
}

/// The address of a libp2p QUIC listener, as [`dial_addrs`] spells it.
///
/// Infallible: `with_p2p` only rejects a multiaddr that already carries a `p2p`
/// component, and this one is built fresh.
pub(crate) fn quic_multiaddr(ip: IpAddr, quic_port: u16, peer_id: PeerId) -> Multiaddr {
    Multiaddr::empty()
        .with(ip.into())
        .with(Protocol::Udp(quic_port))
        .with(Protocol::QuicV1)
        .with_p2p(peer_id)
        .expect("a freshly built multiaddr carries no p2p component")
}

/// The address of a libp2p TCP listener, the fallback path for a peer whose
/// advertised `quic` entry does not answer.
///
/// Infallible for the same reason [`quic_multiaddr`] is.
pub(crate) fn tcp_multiaddr(ip: IpAddr, tcp_port: u16, peer_id: PeerId) -> Multiaddr {
    Multiaddr::empty()
        .with(ip.into())
        .with(Protocol::Tcp(tcp_port))
        .with_p2p(peer_id)
        .expect("a freshly built multiaddr carries no p2p component")
}

/// Which side opened a connection.
///
/// Carried per peer rather than derived where needed, because the two are not
/// interchangeable and only one of them is ours to choose. Inbound supply on
/// mainnet is effectively unbounded and arrives with no say in who it is; an
/// outbound peer is one this node picked, which is the only lever it has on its
/// own custody-column coverage. Mixing the two into a single count is what lets
/// inbound demand quietly crowd the dial loop out of its own reservation, so the
/// direction is kept alongside the peer. See
/// [`beacon::swarm::connection_limits`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConnectionDirection {
    /// The remote dialed us.
    Inbound,
    /// We dialed the remote.
    Outbound,
}

impl ConnectionDirection {
    /// The label this direction carries in metrics and logs.
    ///
    /// The two strings are leanMetrics-specified label values on
    /// `lean_peer_connection_events_total`, so they are fixed, not cosmetic.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

impl fmt::Display for ConnectionDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&libp2p::core::ConnectedPoint> for ConnectionDirection {
    fn from(endpoint: &libp2p::core::ConnectedPoint) -> Self {
        if endpoint.is_dialer() {
            Self::Outbound
        } else {
            Self::Inbound
        }
    }
}

/// "quic" or "tcp", read off which protocol the connection's own multiaddr
/// carries. `"unknown"` is unreachable in practice: every address this swarm
/// ever connects over came from one of the two transports it was built with,
/// but a swarm event is not proof of that, so this stays total rather than
/// panicking on a shape it does not expect.
fn transport_label(addr: &Multiaddr) -> &'static str {
    for protocol in addr.iter() {
        match protocol {
            Protocol::Quic | Protocol::QuicV1 => return "quic",
            Protocol::Tcp(_) => return "tcp",
            _ => {}
        }
    }
    "unknown"
}

/// What ended a connection, as the label
/// [`metrics::inc_peer_disconnect_cause`] counts it under.
///
/// Read off the `ConnectionError` variant and the error types inside it,
/// rather than sniffed out of the whole `Display` string the way the
/// leanMetrics-specified `reason` beside it still has to be. That string test
/// is why nine closes in ten on a mainnet follower read only `error`: it looks
/// for "timeout" and "reset" and calls everything else a fault, and a peer
/// hanging up on us produces neither word.
///
/// `clean_close` is `None`, which libp2p reports when a connection ended with
/// no error at all. For a beacon peer that is the ordinary shape of a
/// deliberate disconnect, so it should be read against `lean_peer_goodbye_total`
/// rather than on its own.
///
/// An I/O close's kind is rarely the answer on its own. `StreamMuxerBox` wraps
/// every muxer error in `io::Error::other`, so almost every close arrives as
/// `ErrorKind::Other` with the muxer's own error behind it, and that inner
/// error is read by downcasting to the two muxers this node runs; see
/// [`io_disconnect_cause`].
///
/// `io_other` is the residue: an I/O error that is neither one of the kinds
/// below nor one of those two muxers' errors. It should stay near empty; a
/// rise means a close shape this function does not know yet, and the `debug!`
/// at the call site prints the full cause for exactly that case.
///
/// Matched exhaustively on purpose. `ConnectionError` is not `#[non_exhaustive]`,
/// so a new variant upstream should fail this build rather than quietly join
/// the residue.
fn disconnect_cause(cause: Option<&ConnectionError>) -> &'static str {
    match cause {
        None => "clean_close",
        Some(ConnectionError::KeepAliveTimeout) => "keep_alive_timeout",
        Some(ConnectionError::IO(err)) => io_disconnect_cause(err),
    }
}

/// The label for an I/O close: its kind when that names something, otherwise
/// whatever the muxer error inside it says.
///
/// Each transport is boxed on its own by the swarm builder, so the error
/// behind an `Other` is exactly one of two types: `libp2p::quic::Error` for a
/// QUIC connection, or the TCP stack's muxer selection,
/// `Either<libp2p::yamux::Error, io::Error>` (mplex reports plain I/O errors).
fn io_disconnect_cause(err: &io::Error) -> &'static str {
    if let Some(label) = io_kind_label(err.kind()) {
        return label;
    }
    let Some(inner) = err.get_ref() else {
        return "io_other";
    };
    if let Some(err) = inner.downcast_ref::<libp2p::quic::Error>() {
        return quic_disconnect_cause(err);
    }
    if let Some(err) = inner.downcast_ref::<Either<libp2p::yamux::Error, io::Error>>() {
        return tcp_muxer_disconnect_cause(err);
    }
    "io_other"
}

/// The I/O kinds worth a label of their own. `None` for the rest, `Other`
/// included, which is where the muxer's error has to be read instead.
fn io_kind_label(kind: io::ErrorKind) -> Option<&'static str> {
    match kind {
        io::ErrorKind::ConnectionReset => Some("connection_reset"),
        io::ErrorKind::ConnectionAborted => Some("connection_aborted"),
        io::ErrorKind::BrokenPipe => Some("broken_pipe"),
        io::ErrorKind::NotConnected => Some("not_connected"),
        io::ErrorKind::TimedOut => Some("timed_out"),
        io::ErrorKind::UnexpectedEof => Some("unexpected_eof"),
        // `io::ErrorKind` *is* `#[non_exhaustive]`, so this arm is required
        // rather than chosen.
        _ => None,
    }
}

/// A QUIC connection's close.
///
/// Matched exhaustively, like [`disconnect_cause`], so a new variant fails the
/// build. Only `Connection` and `Io` can end an established connection; the
/// rest are dial and listener errors, kept apart from the residue anyway so a
/// surprise shows up under its own transport.
fn quic_disconnect_cause(err: &libp2p::quic::Error) -> &'static str {
    use libp2p::quic::Error;
    match err {
        Error::Connection(err) => quic_close_label(&err.to_string()),
        Error::Io(err) => io_kind_label(err.kind()).unwrap_or("quic_other"),
        Error::Reach(_)
        | Error::HandshakeTimedOut
        | Error::NoActiveListenerForDialAsListener
        | Error::HolePunchInProgress(_) => "quic_other",
    }
}

/// Which `quinn::ConnectionError` a QUIC close was, read off its `Display`.
///
/// Read off the text because it is the only way in: `libp2p::quic`'s
/// `ConnectionError` keeps the quinn error in a private field and forwards
/// nothing but `Display`. What makes this safe to match is that each of
/// quinn-proto 0.11's messages opens with a fixed string of quinn's own, and
/// anything the peer supplies (the close reason and code) only follows the
/// colon. So the prefix is chosen by quinn, never by the remote.
///
/// `quic_application_close` is the peer's application closing the connection
/// (libp2p's normal close, and go-libp2p's connection gater); the reason is
/// in the `debug!` line, deliberately not in a label. `quic_transport_close`
/// is a transport-level `CONNECTION_CLOSE`.
fn quic_close_label(display: &str) -> &'static str {
    if display.starts_with("closed by peer: ") {
        "quic_application_close"
    } else if display.starts_with("aborted by peer: ") {
        "quic_transport_close"
    } else if display == "reset by peer" {
        "quic_reset"
    } else if display == "timed out" {
        "quic_timed_out"
    } else if display == "closed" {
        "quic_local_close"
    } else {
        // Version mismatch, a locally detected transport error, exhausted
        // connection ids: none of them a peer leaving.
        "quic_other"
    }
}

/// A TCP connection's close, through whichever muxer it negotiated.
///
/// yamux hides its variants too, but forwards `source` down to the I/O error
/// beneath an `Io` or a `Decode` failure, so the chain is walked for one
/// before falling back to the one variant worth naming, a clean `Closed`.
fn tcp_muxer_disconnect_cause(err: &Either<libp2p::yamux::Error, io::Error>) -> &'static str {
    match err {
        Either::Right(err) => io_kind_label(err.kind()).unwrap_or("mplex_other"),
        Either::Left(err) => {
            let mut source = std::error::Error::source(err);
            while let Some(err) = source {
                if let Some(label) = err
                    .downcast_ref::<io::Error>()
                    .and_then(|err| io_kind_label(err.kind()))
                {
                    return label;
                }
                source = err.source();
            }
            // yamux's own `Closed` message, in both versions libp2p carries.
            if err.to_string() == "connection is closed" {
                "yamux_closed"
            } else {
                "yamux_other"
            }
        }
    }
}

/// `MESSAGE_DOMAIN_INVALID_SNAPPY`: what [`compute_message_id`] prefixes a
/// message that does not decompress with.
///
/// Public, like [`MESSAGE_DOMAIN_VALID_SNAPPY`], because a beacon
/// `config.yaml` carries both: startup refuses a network that sets either to
/// something else, since this node would compute message ids its peers do not.
pub const MESSAGE_DOMAIN_INVALID_SNAPPY: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

/// `MESSAGE_DOMAIN_VALID_SNAPPY`: what [`compute_message_id`] prefixes a
/// message that decompresses with.
pub const MESSAGE_DOMAIN_VALID_SNAPPY: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

fn compute_message_id(message: &libp2p::gossipsub::Message) -> libp2p::gossipsub::MessageId {
    let mut hasher = sha2::Sha256::new();
    let decompressed = gossipsub::decompress_message(&message.data).ok();

    let (domain, data) = match decompressed.as_deref() {
        Some(data) => (MESSAGE_DOMAIN_VALID_SNAPPY, data),
        None => (MESSAGE_DOMAIN_INVALID_SNAPPY, message.data.as_slice()),
    };
    let topic = message.topic.as_str().as_bytes();
    let topic_len = (topic.len() as u64).to_le_bytes();
    hasher.update(domain);
    hasher.update(topic_len);
    hasher.update(topic);
    hasher.update(data);
    let hash = hasher.finalize();
    libp2p::gossipsub::MessageId(hash[..20].to_vec())
}

/// Test scaffolding shared by the beacon gossip handler's `triage_*` tests
/// (`gossipsub::handler`) and the verdict module's `settle` tests
/// (`beacon::verdict`): a real, unconnected beacon `P2PServer`, and a sidecar
/// shaped to clear structural validation. Lives here, rather than duplicated
/// in each of those two test modules, because both need the identical
/// beacon-shaped environment; `req_resp::handlers::tests::unconnected_server`
/// keeps its own lean-flavored copy, since that one builds a different wire.
#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::{HashMap, HashSet};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use ethlambda_storage::Store;
    use ethlambda_storage::backend::InMemoryBackend;
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::{fulu, shared};
    use ethlambda_types::beacon::preset;
    use ethlambda_types::beacon::primitives::{KzgCommitment, KzgProof, Root};
    use ethlambda_types::checkpoint::Checkpoint;
    use ethlambda_types::enr::EnrForkId;
    use ethlambda_types::primitives::H256;
    use libssz_types::SszVector;

    use crate::beacon::swarm::BeaconWireConfig;
    use crate::{P2PServer, SwarmConfig, WireConfig, build_swarm};

    /// A real, unconnected beacon `P2PServer`, built the same way
    /// `req_resp::handlers::tests::unconnected_server` builds a lean one:
    /// port `0` throughout, so this cannot collide with a running node or a
    /// sibling test, and no bootnodes or peers.
    ///
    /// Neither `triage_*` nor `settle` ever reads `swarm_handle` or
    /// `discovery`, but both are required fields, and building the real thing
    /// is no more expensive than faking one would be.
    pub(crate) async fn unconnected_beacon_server(
        config: Config,
        finalized_slot: u64,
    ) -> P2PServer {
        let built = build_swarm(SwarmConfig {
            node_key: vec![9u8; 32],
            bootnodes: Vec::new(),
            listening_socket: "127.0.0.1:0".parse().expect("valid socket"),
            target_peers: crate::discovery::DEFAULT_DISCOVERY_TARGET_PEERS,
            wire: WireConfig::Beacon(Box::new(BeaconWireConfig {
                fork_digest: [0u8; 4],
                fork: config.fork_at_epoch(0),
                config: config.clone(),
                genesis_time: config.genesis_time,
                genesis_validators_root: Root::ZERO,
                custody_columns: Vec::new(),
                attestation_subnets: Vec::new(),
            })),
        })
        .expect("swarm builds");

        let (_swarm_stream, swarm_handle) =
            crate::swarm_adapter::start_swarm_adapter(built.swarm, HashMap::new());

        let discovery = crate::discovery::spawn_discovery(crate::discovery::DiscoverySpawnConfig {
            node_key: secp256k1::SecretKey::new(&mut rand::rngs::OsRng)
                .secret_bytes()
                .to_vec(),
            bind_ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port: 0,
            p2p_port: 0,
            subscription_subnets: HashSet::new(),
            attestation_committee_count: 1,
            bootnodes: Vec::new(),
            advertise_ip: None,
            target_peers: 0,
            fork_id: EnrForkId::local(),
            custody_group_count: None,
        })
        .await
        .expect("discovery spawns");

        let backend = Arc::new(InMemoryBackend::new());
        let anchor_checkpoint = Checkpoint {
            root: H256::ZERO,
            slot: finalized_slot,
        };
        // The caller's own `config`, genesis time included, not a fresh
        // `Config::mainnet()`: a caller that builds a clock-sensitive `config`
        // (a recent `genesis_time`, say) needs the store's clock to agree with
        // it, since `cheap_checks`/`stateful_checks` read the store's own
        // config rather than the wire's.
        let store = Store::init_beacon(
            backend,
            config.genesis_time,
            config,
            H256::ZERO,
            anchor_checkpoint,
            finalized_slot,
        );
        // Read before `built.wire` moves into the server below, mirroring
        // `P2P::spawn`.
        let backbone_attestation_subnets = built
            .wire
            .beacon()
            .map_or(0, |beacon| beacon.attestation_subnets.len());

        P2PServer {
            swarm_handle,
            store,
            blockchain: None,
            wire: built.wire,
            connected_peers: HashMap::new(),
            peer_custody: HashMap::new(),
            pending_root_requests: HashMap::new(),
            pending_column_requests: HashMap::new(),
            outbound_requests: HashMap::new(),
            range_sync_state: None,
            beacon_fetched_through: 0,
            bootnode_addrs: HashMap::new(),
            node_names: HashMap::new(),
            discovery: crate::discovery::dial::DiscoveryState::new(discovery, built.local_peer_id),
            seen_blocks: ethlambda_state_transition::beacon::gossip::SeenBlocks::new(
                crate::SEEN_BLOCKS_CAPACITY,
            ),
            seen_columns: ethlambda_state_transition::beacon::gossip::SeenColumns::new(
                crate::SEEN_COLUMNS_CAPACITY,
            ),
            seen_aggregates:
                ethlambda_state_transition::beacon::gossip::aggregate::SeenAggregates::new(
                    crate::SEEN_AGGREGATES_CAPACITY,
                    crate::SEEN_AGGREGATES_CAPACITY,
                ),
            seen_attestations:
                ethlambda_state_transition::beacon::gossip::attestation::SeenAttestations::new(
                    crate::seen_attestations_capacity(backbone_attestation_subnets),
                ),
            seen_operations: Default::default(),
            gossip_validation_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::GOSSIP_VALIDATION_PERMITS,
            )),
            column_check_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::COLUMN_CHECK_PERMITS,
            )),
            attestation_validation_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::ATTESTATION_VALIDATION_PERMITS,
            )),
            aggregator_subnets: HashMap::new(),
        }
    }

    /// A sidecar that clears `verify_data_column_sidecar`'s structural checks
    /// (one commitment, one proof, one column cell, all the same length) but
    /// carries no real KZG material: nothing in `triage_data_column`'s reject
    /// path under test verifies the cryptography, only the shape and the
    /// header's slot.
    pub(crate) fn valid_shaped_sidecar(slot: u64, index: u64) -> fulu::DataColumnSidecar {
        let cell: fulu::Cell =
            SszVector::try_from(vec![0u8; preset::BYTES_PER_CELL]).expect("exact cell size");
        fulu::DataColumnSidecar {
            index,
            column: vec![cell].try_into().expect("within the per-block limit"),
            kzg_commitments: vec![KzgCommitment::default()]
                .try_into()
                .expect("within the per-block limit"),
            kzg_proofs: vec![KzgProof::default()]
                .try_into()
                .expect("within the per-block limit"),
            signed_block_header: shared::SignedBeaconBlockHeader {
                message: shared::BeaconBlockHeader {
                    slot,
                    proposer_index: 7,
                    ..Default::default()
                },
                signature: Default::default(),
            },
            kzg_commitments_inclusion_proof: vec![
                H256::ZERO;
                preset::KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH
            ]
            .try_into()
            .expect("exactly the required depth"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use ethlambda_types::constants::DEFAULT_MILLISECONDS_PER_SLOT;

    fn random_peer() -> PeerId {
        PeerId::from_public_key(&Keypair::generate_ed25519().public())
    }

    /// Zero backbone subnets (a lean node, or a beacon node that backbones
    /// none) must not shrink the cache to a useless zero capacity, and every
    /// additional subnet scales it by the same per-subnet, per-epoch bound.
    #[test]
    fn seen_attestations_capacity_floors_at_one_subnet_and_scales_with_more() {
        let per_subnet = 2 * SLOTS_PER_EPOCH as usize * MAX_VALIDATORS_PER_COMMITTEE;
        assert_eq!(seen_attestations_capacity(0).get(), per_subnet);
        assert_eq!(seen_attestations_capacity(1).get(), per_subnet);
        assert_eq!(seen_attestations_capacity(3).get(), per_subnet * 3);
    }

    /// The split the specified `reason` label cannot make. Each of these is a
    /// distinct answer to "who ended this and why", and all but the first two
    /// collapse into `error` next door.
    #[test]
    fn a_close_is_labelled_by_the_cause_libp2p_reported() {
        assert_eq!(disconnect_cause(None), "clean_close");
        assert_eq!(
            disconnect_cause(Some(&ConnectionError::KeepAliveTimeout)),
            "keep_alive_timeout"
        );
        for (kind, label) in [
            (io::ErrorKind::ConnectionReset, "connection_reset"),
            (io::ErrorKind::ConnectionAborted, "connection_aborted"),
            (io::ErrorKind::BrokenPipe, "broken_pipe"),
            (io::ErrorKind::NotConnected, "not_connected"),
            (io::ErrorKind::TimedOut, "timed_out"),
            (io::ErrorKind::UnexpectedEof, "unexpected_eof"),
        ] {
            let err = ConnectionError::IO(io::Error::new(kind, "test"));
            assert_eq!(disconnect_cause(Some(&err)), label, "{kind:?}");
        }
    }

    /// `io::ErrorKind` is `#[non_exhaustive]`, and an error that is neither a
    /// named kind nor one of the two muxers' errors has to land somewhere, so
    /// the residue is a real bucket rather than an unreachable arm.
    #[test]
    fn an_unclassified_io_error_falls_to_the_residue() {
        for kind in [io::ErrorKind::Other, io::ErrorKind::InvalidData] {
            let err = ConnectionError::IO(io::Error::new(kind, "some other close"));
            assert_eq!(disconnect_cause(Some(&err)), "io_other", "{kind:?}");
        }
    }

    /// The shape nine closes in ten actually take on mainnet: the muxer's
    /// error boxed inside an `io::Error` of kind `Other`, the way
    /// `StreamMuxerBox` wraps it. Reading only the outer kind put every one of
    /// these in `io_other`.
    #[test]
    fn a_muxer_error_inside_an_other_io_error_is_read_through() {
        let boxed = |err: Either<libp2p::yamux::Error, io::Error>| {
            ConnectionError::IO(io::Error::other(err))
        };
        for (kind, label) in [
            (io::ErrorKind::UnexpectedEof, "unexpected_eof"),
            (io::ErrorKind::ConnectionReset, "connection_reset"),
            (io::ErrorKind::Other, "mplex_other"),
        ] {
            let err = boxed(Either::Right(io::Error::new(kind, "mplex")));
            assert_eq!(disconnect_cause(Some(&err)), label, "mplex {kind:?}");
        }

        // `libp2p::quic::Error::Connection` cannot be built outside its crate
        // (the quinn error is a private field), so its reading is pinned
        // through `quic_close_label` below; these are the variants that can.
        let quic = |err: libp2p::quic::Error| ConnectionError::IO(io::Error::other(err));
        let reset = io::Error::new(io::ErrorKind::ConnectionReset, "quic socket");
        assert_eq!(
            disconnect_cause(Some(&quic(libp2p::quic::Error::Io(reset)))),
            "connection_reset"
        );
        assert_eq!(
            disconnect_cause(Some(&quic(libp2p::quic::Error::HandshakeTimedOut))),
            "quic_other"
        );
    }

    /// quinn-proto 0.11's `ConnectionError` messages, as a mainnet follower
    /// logs them. The last case is the one the prefix match exists for: the
    /// reason is the peer's to choose, so it must not be able to pass for
    /// another variant.
    #[test]
    fn a_quic_close_is_labelled_by_quinns_prefix_not_the_peers_reason() {
        for (display, label) in [
            (
                "closed by peer: connection gated (code 4103)",
                "quic_application_close",
            ),
            ("closed by peer: 0", "quic_application_close"),
            ("aborted by peer: NO_ERROR", "quic_transport_close"),
            ("reset by peer", "quic_reset"),
            ("timed out", "quic_timed_out"),
            ("closed", "quic_local_close"),
            ("CIDs exhausted", "quic_other"),
            (
                "closed by peer: reset by peer (code 1)",
                "quic_application_close",
            ),
        ] {
            assert_eq!(quic_close_label(display), label, "{display}");
        }
    }

    /// Proves the TCP transport `build_swarm` now adds actually completes a
    /// connection end to end, rather than only compiling. Builds two real
    /// swarms via the production entry point (port `0`, so this cannot
    /// collide with a running node or a sibling test), learns the first
    /// swarm's TCP listen address off its own `NewListenAddr` event, dials it
    /// from the second swarm, and polls both until each reports
    /// `ConnectionEstablished`. A regression to QUIC-only, or a
    /// misconfigured TCP transport, hangs here until the timeout rather than
    /// racing to a false positive.
    #[tokio::test]
    async fn two_lean_swarms_connect_over_tcp() {
        fn build(node_key_byte: u8) -> BuiltSwarm {
            build_swarm(SwarmConfig {
                node_key: vec![node_key_byte; 32],
                bootnodes: Vec::new(),
                listening_socket: "127.0.0.1:0".parse().expect("valid socket"),
                target_peers: crate::discovery::DEFAULT_DISCOVERY_TARGET_PEERS,
                wire: WireConfig::Lean(LeanWireConfig {
                    validator_ids: Vec::new(),
                    attestation_committee_count: 1,
                    subscription_subnets: HashSet::new(),
                    milliseconds_per_slot: DEFAULT_MILLISECONDS_PER_SLOT,
                }),
            })
            .expect("swarm builds")
        }

        let mut dialer = build(1);
        let mut listener = build(2);

        // Both a QUIC and a TCP `NewListenAddr` arrive for `listener`; only
        // the TCP one is wanted here.
        let listener_tcp_addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } =
                listener.swarm.select_next_some().await
                && address.iter().any(|p| matches!(p, Protocol::Tcp(_)))
            {
                break address
                    .with_p2p(listener.local_peer_id)
                    .expect("failed to add peer ID to multiaddr");
            }
        };

        dialer
            .swarm
            .dial(listener_tcp_addr)
            .expect("dial is accepted");

        let (mut dialer_connected, mut listener_connected) = (false, false);
        let both_connect = async {
            while !(dialer_connected && listener_connected) {
                tokio::select! {
                    event = dialer.swarm.select_next_some() => {
                        if let SwarmEvent::ConnectionEstablished { endpoint, .. } = event {
                            assert_eq!(transport_label(endpoint.get_remote_address()), "tcp");
                            dialer_connected = true;
                        }
                    }
                    event = listener.swarm.select_next_some() => {
                        if let SwarmEvent::ConnectionEstablished { endpoint, .. } = event {
                            assert_eq!(transport_label(endpoint.get_remote_address()), "tcp");
                            listener_connected = true;
                        }
                    }
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), both_connect)
            .await
            .expect("both swarms must connect over TCP within the timeout");
    }

    #[test]
    fn gossip_is_held_for_a_verdict_only_when_asked() {
        let ttl = Duration::from_secs(1);
        assert!(gossipsub_config(ttl, true).validate_messages());
        assert!(!gossipsub_config(ttl, false).validate_messages());
    }

    /// How many times [`concurrent_beacon_requests_on_different_protocols_never_cross`]
    /// repeats its connect-and-fire cycle.
    ///
    /// The crossing this proves against is timing-dependent: which of two
    /// substreams negotiates first depends on scheduling, not on send order
    /// (see `Behaviour`'s doc comment), so one repetition proves nothing on
    /// its own. A fresh connection per repetition, rather than reusing one
    /// connection for every pair, is what gives each repetition its own
    /// independent chance at the race.
    const CROSSING_TEST_REPETITIONS: usize = 64;

    /// Regression test for the defect this branch exists to fix: two
    /// outbound requests, on two different protocols, fired back to back on
    /// one connection — exactly [`beacon::handler::send_status`] then
    /// [`beacon::handler::request_metadata`]'s real call pattern from
    /// `ConnectionEstablished` below — must each reach the wire under their
    /// own protocol's framing, never swapped.
    ///
    /// Before the per-protocol split, both requests travelled through one
    /// shared `req_resp: request_response::Behaviour<Codec>` field via the fork's
    /// `send_request_with_protocol`, which only narrows the *offered*
    /// protocol per call; the outbound `Handler` still pairs a negotiated
    /// substream with the *next unpaired* queued request
    /// (`requested_outbound.pop_front()` in the pinned fork's
    /// `protocols/request-response/src/handler.rs`), which is the send
    /// order only when negotiation happens to complete in send order too.
    /// When it doesn't, `write_request` is handed the wrong (protocol,
    /// request) pair: a `Status` value written under the `metadata/3`
    /// protocol is refused by `beacon_encoding::encode_status` (wrong
    /// version), which fails the write locally, and a `MetaData` value
    /// written under `status/1` encodes to an empty payload regardless of
    /// protocol and reaches the peer, which then fails to decode it as a
    /// real `Status` body. Either way, this test's answering side never
    /// manages to echo the right payload back, and the `Some(true)`
    /// assertions below fail.
    ///
    /// Splitting the shared field into one per protocol (this branch's
    /// change) makes this structurally unreachable rather than merely less
    /// likely: each protocol's own `Handler` has its own queue, with never
    /// more than the one request this test ever puts on it, so there is no
    /// shared FIFO left to reorder.
    #[tokio::test]
    async fn concurrent_beacon_requests_on_different_protocols_never_cross() {
        use crate::beacon::messages::{BeaconMetaData, BeaconStatus, MetaDataV3, StatusV1};
        use crate::beacon::protocols;
        use crate::req_resp::{Response, ResponsePayload};
        use ethlambda_types::beacon::config::Config;
        use ethlambda_types::beacon::fork::ForkName;
        use ethlambda_types::beacon::primitives::Root;
        use libp2p::request_response::{self, ResponseChannel};

        fn build(node_key_byte: u8) -> BuiltSwarm {
            build_swarm(SwarmConfig {
                node_key: vec![node_key_byte; 32],
                bootnodes: Vec::new(),
                listening_socket: "127.0.0.1:0".parse().expect("valid socket"),
                target_peers: crate::discovery::DEFAULT_DISCOVERY_TARGET_PEERS,
                wire: WireConfig::Beacon(Box::new(beacon::swarm::BeaconWireConfig {
                    fork_digest: [0x11, 0x22, 0x33, 0x44],
                    fork: ForkName::Fulu,
                    config: Config::mainnet(),
                    genesis_time: 0,
                    genesis_validators_root: Root::ZERO,
                    custody_columns: Vec::new(),
                    attestation_subnets: Vec::new(),
                })),
            })
            .expect("swarm builds")
        }

        /// Every [`BehaviourEvent`] variant that carries a req/resp event,
        /// tagged with the [`ReqRespProtocol`] that names it. A test-local
        /// mirror of [`handle_behaviour_event`]'s own tagging match, kept
        /// separate because that one needs a live `P2PServer` and this test
        /// drives bare swarms.
        fn tag_req_resp_event(
            event: BehaviourEvent,
        ) -> Option<(ReqRespProtocol, request_response::Event<Request, Response>)> {
            let BehaviourEvent::ReqResp(event) = event else {
                return None;
            };
            Some(match event {
                ReqRespEvent::LeanStatus(e) => (ReqRespProtocol::LeanStatus, e),
                ReqRespEvent::LeanBlocksByRoot(e) => (ReqRespProtocol::LeanBlocksByRoot, e),
                ReqRespEvent::LeanBlocksByRange(e) => (ReqRespProtocol::LeanBlocksByRange, e),
                ReqRespEvent::BeaconStatusV1(e) => (ReqRespProtocol::BeaconStatusV1, e),
                ReqRespEvent::BeaconStatusV2(e) => (ReqRespProtocol::BeaconStatusV2, e),
                ReqRespEvent::BeaconPing(e) => (ReqRespProtocol::BeaconPing, e),
                ReqRespEvent::BeaconMetadataV1(e) => (ReqRespProtocol::BeaconMetadataV1, e),
                ReqRespEvent::BeaconMetadataV2(e) => (ReqRespProtocol::BeaconMetadataV2, e),
                ReqRespEvent::BeaconMetadataV3(e) => (ReqRespProtocol::BeaconMetadataV3, e),
                ReqRespEvent::BeaconGoodbye(e) => (ReqRespProtocol::BeaconGoodbye, e),
                ReqRespEvent::BeaconBlocksByRange(e) => (ReqRespProtocol::BeaconBlocksByRange, e),
                ReqRespEvent::BeaconBlocksByRoot(e) => (ReqRespProtocol::BeaconBlocksByRoot, e),
                ReqRespEvent::DataColumnSidecarsByRange(e) => {
                    (ReqRespProtocol::DataColumnSidecarsByRange, e)
                }
                ReqRespEvent::DataColumnSidecarsByRoot(e) => {
                    (ReqRespProtocol::DataColumnSidecarsByRoot, e)
                }
            })
        }

        /// Answer whatever the listener actually decoded, so even a garbled,
        /// crossed request gets *some* answer back rather than leaving the
        /// dialer to time out. `send_response` is a passthrough to the
        /// channel's own oneshot sender (see `execute_command`'s doc comment
        /// on its `SendResponse` arm), so any field answers it identically.
        fn answer(
            swarm: &mut libp2p::Swarm<Behaviour>,
            request: Request,
            channel: ResponseChannel<Response>,
        ) {
            let response = match request {
                Request::Status(status) => Response::success(ResponsePayload::Status(status)),
                Request::MetaData(_) => {
                    Response::success(ResponsePayload::MetaData(BeaconMetaData::V3(MetaDataV3 {
                        seq_number: 0,
                        attnets: Default::default(),
                        syncnets: Default::default(),
                        custody_group_count: 4,
                    })))
                }
                // Neither protocol this test sends is ever requested by the
                // peer here, so any other shape means the wire pairing has
                // already scrambled the request into a third variant
                // entirely; drop the channel rather than guess an answer.
                _ => return,
            };
            let _ = swarm
                .behaviour_mut()
                .req_resp
                .beacon_status_v1
                .send_response(channel, response);
        }

        let mut crossings = 0usize;

        for _ in 0..CROSSING_TEST_REPETITIONS {
            let mut dialer = build(1);
            let mut listener = build(2);

            let listener_addr = loop {
                if let SwarmEvent::NewListenAddr { address, .. } =
                    listener.swarm.select_next_some().await
                    && address.iter().any(|p| matches!(p, Protocol::Tcp(_)))
                {
                    break address
                        .with_p2p(listener.local_peer_id)
                        .expect("adds a peer id");
                }
            };
            dialer.swarm.dial(listener_addr).expect("dial is accepted");

            let (mut dialer_connected, mut listener_connected) = (false, false);
            while !(dialer_connected && listener_connected) {
                tokio::select! {
                    event = dialer.swarm.select_next_some() => {
                        if matches!(event, SwarmEvent::ConnectionEstablished { .. }) {
                            dialer_connected = true;
                        }
                    }
                    event = listener.swarm.select_next_some() => {
                        if matches!(event, SwarmEvent::ConnectionEstablished { .. }) {
                            listener_connected = true;
                        }
                    }
                }
            }

            // Fired back to back, with no `.await` of anything but the send
            // call itself in between: the same pattern `ConnectionEstablished`
            // uses for `send_status` then `request_metadata` in production.
            let status = Request::Status(BeaconStatus::V1(StatusV1 {
                fork_digest: [0x11, 0x22, 0x33, 0x44],
                finalized_root: Root::ZERO,
                finalized_epoch: 0,
                head_root: Root::ZERO,
                head_slot: 0,
            }));
            let status_id = ReqRespRequestId {
                protocol: ReqRespProtocol::BeaconStatusV1,
                id: dialer
                    .swarm
                    .behaviour_mut()
                    .req_resp
                    .beacon_status_v1
                    .send_request(&listener.local_peer_id, status),
            };
            let metadata_id = ReqRespRequestId {
                protocol: ReqRespProtocol::BeaconMetadataV3,
                id: dialer
                    .swarm
                    .behaviour_mut()
                    .req_resp
                    .beacon_metadata_v3
                    .send_request(
                        &listener.local_peer_id,
                        Request::MetaData(protocols::METADATA_V3),
                    ),
            };

            let (mut status_correct, mut metadata_correct) = (None, None);
            let drive = async {
                loop {
                    if status_correct.is_some() && metadata_correct.is_some() {
                        return;
                    }
                    tokio::select! {
                        event = dialer.swarm.select_next_some() => {
                            let SwarmEvent::Behaviour(event) = event else { continue };
                            let Some((protocol, event)) = tag_req_resp_event(event) else { continue };
                            match event {
                                request_response::Event::Message {
                                    message: request_response::Message::Response { request_id, response },
                                    ..
                                } => {
                                    let id = ReqRespRequestId { protocol, id: request_id };
                                    // Correct means both "answered" and
                                    // "answered with the payload shape this
                                    // id's own request expects": a response
                                    // that arrives but names the wrong
                                    // payload is exactly what a crossed
                                    // request looks like from here.
                                    if id == status_id {
                                        status_correct = Some(matches!(
                                            response,
                                            Response::Success {
                                                payload: ResponsePayload::Status(_)
                                            }
                                        ));
                                    } else if id == metadata_id {
                                        metadata_correct = Some(matches!(
                                            response,
                                            Response::Success {
                                                payload: ResponsePayload::MetaData(_)
                                            }
                                        ));
                                    }
                                }
                                request_response::Event::OutboundFailure { request_id, .. } => {
                                    let id = ReqRespRequestId { protocol, id: request_id };
                                    if id == status_id {
                                        status_correct = Some(false);
                                    } else if id == metadata_id {
                                        metadata_correct = Some(false);
                                    }
                                }
                                _ => {}
                            }
                        }
                        event = listener.swarm.select_next_some() => {
                            if let SwarmEvent::Behaviour(event) = event
                                && let Some((_, request_response::Event::Message {
                                    message: request_response::Message::Request { request, channel, .. },
                                    ..
                                })) = tag_req_resp_event(event)
                            {
                                answer(&mut listener.swarm, request, channel);
                            }
                        }
                    }
                }
            };
            tokio::time::timeout(Duration::from_secs(5), drive)
                .await
                .expect("both requests must resolve within the timeout");

            if status_correct != Some(true) || metadata_correct != Some(true) {
                crossings += 1;
            }
        }

        assert_eq!(
            crossings, 0,
            "{crossings}/{CROSSING_TEST_REPETITIONS} repetitions crossed protocols"
        );
    }

    #[test]
    fn a_lean_wire_reports_its_topics_and_no_beacon_wire() {
        // The enum is what makes "subscribed to lean topics and beacon topics
        // at once" unrepresentable. `P2PServer` dispatches on it once per
        // handler, the same way `BlockChainServer` dispatches on the state
        // variant.
        let wire = Wire::Lean(LeanWire {
            attestation_topics: HashMap::new(),
            attestation_committee_count: 4,
            block_topic: block_topic(),
            aggregation_topic: aggregation_topic(),
        });
        assert!(wire.beacon().is_none());
        let lean = wire.lean().expect("a lean wire");
        assert_eq!(lean.attestation_committee_count, 4);
        assert!(lean.block_topic.to_string().starts_with("/leanconsensus/"));
    }

    /// A bootnode file naming one peer twice must not abort the node.
    ///
    /// `DialOpts::peer_id` dials under the default `DisconnectedAndNotDialing`
    /// condition, so a second dial while the first is in flight comes back as
    /// `Err(DialPeerConditionFalse)` synchronously. Two file entries decode to
    /// one `PeerId` whenever they share a secp256k1 key: the same ENR pasted
    /// twice, or an old and a new record for one node. `parse_enrs` does not
    /// dedup, so `build_swarm` has to, and it merges the address lists rather
    /// than dropping whichever entry came second.
    ///
    /// Asserting the map is asserting the dial: `build_swarm` merges first and
    /// then dials one `DialOpts` per map entry, so what is checked here is the
    /// list the initial dial races. The pure merge itself is pinned separately
    /// by [`merging_bootnodes_keeps_every_address_for_the_initial_dial`].
    ///
    /// The QUIC-only condition (`From<Multiaddr>`) this replaced was `Always`,
    /// which is why the duplicate went unnoticed before.
    #[tokio::test]
    async fn a_bootnode_named_twice_is_dialed_once_with_both_addresses() {
        let key = secp256k1::Keypair::generate();
        let public_key: PublicKey = key.public().clone().into();
        let peer_id = PeerId::from_public_key(&public_key);
        let ip = IpAddr::from(Ipv4Addr::new(203, 0, 113, 1));
        // Two records for one key: the first advertising QUIC only, the second
        // having since added TCP. Neither port is listening, which is fine —
        // the dial only has to be *taken*.
        let bootnodes = vec![
            Bootnode {
                ip,
                quic_port: Some(9001),
                tcp_port: None,
                udp_port: Some(9000),
                public_key: public_key.clone(),
            },
            Bootnode {
                ip,
                quic_port: Some(9001),
                tcp_port: Some(9001),
                udp_port: Some(9000),
                public_key,
            },
        ];

        let built = build_swarm(SwarmConfig {
            node_key: vec![7u8; 32],
            bootnodes,
            listening_socket: "127.0.0.1:0".parse().expect("valid socket"),
            target_peers: crate::discovery::DEFAULT_DISCOVERY_TARGET_PEERS,
            wire: WireConfig::Lean(LeanWireConfig {
                validator_ids: Vec::new(),
                attestation_committee_count: 1,
                subscription_subnets: HashSet::new(),
                milliseconds_per_slot: DEFAULT_MILLISECONDS_PER_SLOT,
            }),
        })
        .expect("a duplicated bootnode entry must not fail the build");

        assert_eq!(
            built.bootnode_addrs.len(),
            1,
            "the two entries name one peer, so they must collapse to one dial target"
        );
        let addrs = built
            .bootnode_addrs
            .get(&peer_id)
            .expect("the bootnode is tracked under its peer id");
        let expected: HashSet<Multiaddr> = HashSet::from([
            quic_multiaddr(ip, 9001, peer_id),
            tcp_multiaddr(ip, 9001, peer_id),
        ]);
        assert_eq!(
            addrs.iter().cloned().collect::<HashSet<_>>(),
            expected,
            "the merged list must carry every address the duplicate entries offered"
        );
    }

    /// The merge has to happen before the dial, not during it.
    ///
    /// The case that distinguishes them: a stale QUIC-only record listed ahead
    /// of a newer one for the same key that has since added a live TCP port,
    /// with the QUIC port dead. Merging while dialing takes only the first
    /// entry's addresses, so startup races a dead address alone and reaches the
    /// live one a redial interval later; merging first puts both into the one
    /// attempt the peer gets.
    #[test]
    fn merging_bootnodes_keeps_every_address_for_the_initial_dial() {
        let key = secp256k1::Keypair::generate();
        let public_key: PublicKey = key.public().clone().into();
        let peer_id = PeerId::from_public_key(&public_key);
        let ip = IpAddr::from(Ipv4Addr::new(203, 0, 113, 1));
        let bootnodes = vec![
            Bootnode {
                ip,
                quic_port: Some(9001),
                tcp_port: None,
                udp_port: Some(9000),
                public_key: public_key.clone(),
            },
            Bootnode {
                ip,
                quic_port: None,
                tcp_port: Some(9002),
                udp_port: Some(9000),
                public_key,
            },
            // A discv5-only seed: nothing to dial, counted separately so the
            // caller can tell "no bootnode is dialable" from "no bootnodes".
            Bootnode {
                ip,
                quic_port: None,
                tcp_port: None,
                udp_port: Some(9000),
                public_key: secp256k1::Keypair::generate().public().clone().into(),
            },
        ];

        let (merged, undialable) = merge_bootnode_dial_addrs(bootnodes, random_peer());

        assert_eq!(undialable, 1, "the transport-less entry must be counted");
        assert_eq!(merged.len(), 1, "the two records name one peer");
        let addrs = merged
            .get(&peer_id)
            .expect("the peer is keyed by its peer id");
        let expected: HashSet<Multiaddr> = HashSet::from([
            quic_multiaddr(ip, 9001, peer_id),
            tcp_multiaddr(ip, 9002, peer_id),
        ]);
        assert_eq!(
            addrs.iter().cloned().collect::<HashSet<_>>(),
            expected,
            "the address only the second entry offered must reach the first dial"
        );
    }

    /// Our own key in a bootnode list is a dial to ourselves, which
    /// `Swarm::dial` refuses as `LocalPeerId`. Dropping it in the merge keeps it
    /// out of `bootnode_addrs`, so the redial path never retries it either.
    #[test]
    fn merging_bootnodes_drops_our_own_record() {
        let key = secp256k1::Keypair::generate();
        let public_key: PublicKey = key.public().clone().into();
        let local_peer_id = PeerId::from_public_key(&public_key);
        let bootnodes = vec![Bootnode {
            ip: IpAddr::from(Ipv4Addr::new(203, 0, 113, 1)),
            quic_port: Some(9001),
            tcp_port: Some(9001),
            udp_port: Some(9000),
            public_key,
        }];

        let (merged, undialable) = merge_bootnode_dial_addrs(bootnodes, local_peer_id);

        assert!(merged.is_empty(), "we must not be a dial target");
        assert_eq!(
            undialable, 0,
            "our own record is not an undialable bootnode, it is not a bootnode"
        );
    }

    #[test]
    fn range_sync_state_merges_new_peer_ranges() {
        let first_peer = random_peer();
        let second_peer = random_peer();
        let mut state = RangeSyncState::new(10..101, first_peer, 100);

        state.merge_peer(second_peer, 150, 151);

        assert_eq!(state.current_range, 10..151);
        assert_eq!(state.peer_set.get(&first_peer), Some(&100));
        assert_eq!(state.peer_set.get(&second_peer), Some(&150));
    }

    #[test]
    fn range_sync_state_allows_only_one_batch_in_flight() {
        let first_peer = random_peer();
        let second_peer = random_peer();
        let mut state = RangeSyncState::new(10..3000, first_peer, 500);
        state.merge_peer(second_peer, 2000, 3000);

        let (selected_peer, batch) = state.next_batch().expect("batch available");
        assert_eq!(selected_peer, second_peer);
        assert_eq!(batch, 10..(10 + MAX_REQUEST_BLOCKS));

        state.in_flight = true;
        assert!(state.next_batch().is_none());
    }

    #[test]
    fn range_sync_state_advances_and_drops_stale_peers() {
        let stale_peer = random_peer();
        let current_peer = random_peer();
        let mut state = RangeSyncState::new(10..3000, stale_peer, 100);
        state.merge_peer(current_peer, 2999, 3000);
        state.in_flight = true;

        state.complete_batch(1033);

        assert_eq!(state.current_range, 1034..3000);
        assert!(!state.in_flight);
        assert!(!state.peer_set.contains_key(&stale_peer));
        assert_eq!(state.peer_set.get(&current_peer), Some(&2999));
    }

    #[test]
    fn a_batch_held_for_custody_waits_until_its_deadline_and_no_longer() {
        let mut state = RangeSyncState::new(10..3000, random_peer(), 500);
        let start = Instant::now();

        // Only the first hold starts the wait, which is what schedules the
        // deadline once rather than on every re-check.
        assert_eq!(state.wait_for_custody(start), CustodyWait::Started);
        assert!(state.is_waiting_for_custody());
        let halfway = start + RANGE_BATCH_CUSTODY_WAIT / 2;
        assert_eq!(state.wait_for_custody(halfway), CustodyWait::Waiting);
        let deadline = start + RANGE_BATCH_CUSTODY_WAIT;
        assert_eq!(state.wait_for_custody(deadline), CustodyWait::Expired);

        assert_eq!(
            state.end_custody_wait(deadline),
            Some(RANGE_BATCH_CUSTODY_WAIT)
        );
        assert!(!state.is_waiting_for_custody());
        assert_eq!(state.end_custody_wait(deadline), None);
    }

    #[test]
    fn each_batch_gets_a_custody_wait_of_its_own() {
        let mut state = RangeSyncState::new(10..3000, random_peer(), 500);
        let start = Instant::now();
        state.wait_for_custody(start);
        let sent_at = start + 2 * RANGE_BATCH_CUSTODY_WAIT;
        assert_eq!(state.wait_for_custody(sent_at), CustodyWait::Expired);
        state.end_custody_wait(sent_at);

        // A later batch that finds custody uncovered again waits in full,
        // rather than inheriting the expired wait of the batch before it.
        assert_eq!(state.wait_for_custody(sent_at), CustodyWait::Started);
    }

    #[test]
    fn parse_enrs_extracts_ip_port_and_public_key() {
        // Values taken from a local devnet run with lean-quickstart
        let enrs = vec![
            "enr:-IW4QGGifTt9ypyMtChDISUNX3z4z5iPdiEPOmBoILvnDuWIKbWVmKXxZERPnw0piQyaBNCENFEPoIi-vxsnsrBig9MBgmlkgnY0gmlwhH8AAAGEcXVpY4IjKYlzZWNwMjU2azGhAhMMnGF1rmIPQ9tWgqfkNmvsG-aIyc9EJU5JFo3Tegys".to_string(),
            "enr:-IW4QPjoNZjNpzdjOqAR2rGguVAWmqpNCUCfbr-pp3rr6Dk6YO2KK5VWARr7BGr8BdmGmG75cBeVC2buzvtQ_nEWLKEBgmlkgnY0gmlwhH8AAAGEcXVpY4IjKolzZWNwMjU2azGhA5_HplOwUZ8wpF4O3g4CBsjRMI6kQYT7ph5LkeKzLgTS".to_string(),
            "enr:-IW4QNQN_PFdTfuYLGmdAWNivEJLT2tSZtn5jdBOImvh0QlLAJ1p8wHvvfD7aOa1lH88oJ8ddGK_a_FWqAQT_QY4qdMBgmlkgnY0gmlwhH8AAAGEcXVpY4IjK4lzZWNwMjU2azGhA7NTxgfOmGE2EQa4HhsXxFOeHdTLYIc2MEBczymm9IUN".to_string(),
            "enr:-IW4QI9EXVDvUIxTrCV51Gs2RtpmZu71S7ZP7RRg1OoSBVvGFeXkc5WleBffXwTcWX1Qa9F_N6MhH28TsGFhXkMCGvUBgmlkgnY0gmlwhH8AAAGEcXVpY4IjL4lzZWNwMjU2azGhA6Dm1X9PyyCNAm3RUGcZtG5U3imbj_MDPU5CtPnpeaKS".to_string(),
        ];

        let bootnodes = parse_enrs(enrs);

        assert_eq!(bootnodes.len(), 4);

        // All ENRs encode 127.0.0.1 as the IPv4 address
        for bootnode in &bootnodes {
            assert_eq!(bootnode.ip, IpAddr::from(Ipv4Addr::LOCALHOST));
        }

        // Each ENR encodes a distinct QUIC port
        assert_eq!(bootnodes[0].quic_port, Some(9001));
        assert_eq!(bootnodes[1].quic_port, Some(9002));
        assert_eq!(bootnodes[2].quic_port, Some(9003));
        assert_eq!(bootnodes[3].quic_port, Some(9007));

        // Verify the secp256k1 public keys (33-byte compressed format)
        let expected_pubkeys: Vec<[u8; 33]> = vec![
            hex::decode("02130c9c6175ae620f43db5682a7e4366bec1be688c9cf44254e49168dd37a0cac")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("039fc7a653b0519f30a45e0ede0e0206c8d1308ea44184fba61e4b91e2b32e04d2")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("03b353c607ce9861361106b81e1b17c4539e1dd4cb60873630405ccf29a6f4850d")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("03a0e6d57f4fcb208d026dd1506719b46e54de299b8ff3033d4e42b4f9e979a292")
                .unwrap()
                .try_into()
                .unwrap(),
        ];

        for (bootnode, expected) in bootnodes.iter().zip(expected_pubkeys.iter()) {
            let secp_key = secp256k1::PublicKey::try_from_bytes(expected).unwrap();
            let expected_key: PublicKey = secp_key.into();
            assert_eq!(bootnode.public_key, expected_key);
        }

        // Devnet ENRs from lean-quickstart carry no `udp` entry, so they cannot
        // seed discv5 even though they remain dialable over QUIC.
        for bootnode in &bootnodes {
            assert_eq!(bootnode.udp_port, None);
        }
    }

    #[test]
    fn parse_enrs_extracts_the_udp_port_when_present() {
        // `secp256k1` is already bound in this module to `libp2p::identity::secp256k1`
        // (see the top-of-file `use`), so reach the raw `secp256k1` crate that
        // `ethrex_p2p::types::NodeRecord::from_pairs` expects via an explicit
        // crate-root path instead of the shadowed name.
        use ::secp256k1 as raw_secp256k1;

        // Build an ENR the way ethlambda does once discovery is enabled: udp for
        // discv5, quic for libp2p, no tcp.
        let signer = raw_secp256k1::SecretKey::new(&mut rand::rngs::OsRng);
        let mut pairs = ethrex_p2p::types::NodeRecordPairs {
            ip: Some(Ipv4Addr::LOCALHOST),
            udp_port: Some(9010),
            tcp_port: None,
            ..Default::default()
        };
        pairs.set_extra_int(b"quic", 9001);
        let record = NodeRecord::from_pairs(1, &signer, pairs).unwrap();

        let bootnodes = parse_enrs(vec![record.enr_url().unwrap()]);

        assert_eq!(bootnodes.len(), 1);
        assert_eq!(bootnodes[0].ip, IpAddr::from(Ipv4Addr::LOCALHOST));
        assert_eq!(bootnodes[0].quic_port, Some(9001));
        assert_eq!(bootnodes[0].udp_port, Some(9010));
    }

    #[test]
    fn parse_enrs_treats_a_zero_udp_port_as_absent() {
        use ::secp256k1 as raw_secp256k1;

        // `udp: 0` names no listener, exactly as `quic: 0` does not. Reading it
        // verbatim would seed discv5 with an undialable contact, so the record
        // survives only as a static dial target.
        let signer = raw_secp256k1::SecretKey::new(&mut rand::rngs::OsRng);
        let mut pairs = ethrex_p2p::types::NodeRecordPairs {
            ip: Some(Ipv4Addr::LOCALHOST),
            udp_port: Some(0),
            tcp_port: None,
            ..Default::default()
        };
        pairs.set_extra_int(b"quic", 9001);
        let record = NodeRecord::from_pairs(1, &signer, pairs).unwrap();

        let bootnodes = parse_enrs(vec![record.enr_url().unwrap()]);

        assert_eq!(bootnodes.len(), 1);
        assert_eq!(bootnodes[0].quic_port, Some(9001));
        assert_eq!(bootnodes[0].udp_port, None);
        assert!(
            bootnodes[0].as_discovery_node().is_none(),
            "a zero udp port must not become a discv5 seed"
        );
    }

    #[test]
    fn parse_enrs_drops_a_record_whose_only_ports_are_zero() {
        use ::secp256k1 as raw_secp256k1;

        // Neither port is dialable, so nothing downstream can ever use this
        // record: the same outcome as a record carrying no ports at all.
        let signer = raw_secp256k1::SecretKey::new(&mut rand::rngs::OsRng);
        let mut pairs = ethrex_p2p::types::NodeRecordPairs {
            ip: Some(Ipv4Addr::LOCALHOST),
            udp_port: Some(0),
            tcp_port: None,
            ..Default::default()
        };
        pairs.set_extra_int(b"quic", 0);
        let record = NodeRecord::from_pairs(1, &signer, pairs).unwrap();

        assert!(parse_enrs(vec![record.enr_url().unwrap()]).is_empty());
    }

    #[test]
    fn parse_enrs_keeps_a_quic_less_record_and_dials_it_over_tcp() {
        // Some nodes advertise `tcp` and `udp` but no `quic`, so requiring
        // `quic` here would drop the entire mainnet bootstrap list and leave
        // discv5 with nothing to seed from. Now that TCP is a transport we
        // speak, such a record is not merely kept as a seed: the one that
        // carries `tcp` becomes a static dial target too, over that port alone.
        //
        // The two ENRs are from eth-clients/mainnet's `bootstrap_nodes.yaml`,
        // and they differ in exactly the way that matters here: the first
        // advertises `tcp` and the second does not.
        let enrs = vec![
            "enr:-Iu4QLm7bZGdAt9NSeJG0cEnJohWcQTQaI9wFLu3Q7eHIDfrI4cwtzvEW3F3VbG9XdFXlrHyFGeXPn9snTCQJ9bnMRABgmlkgnY0gmlwhAOTJQCJc2VjcDI1NmsxoQIZdZD6tDYpkpEfVo5bgiU8MGRjhcOmHGD2nErK0UKRrIN0Y3CCIyiDdWRwgiMo".to_string(),
            "enr:-Le4QPUXJS2BTORXxyx2Ia-9ae4YqA_JWX3ssj4E_J-3z1A-HmFGrU8BpvpqhNabayXeOZ2Nq_sbeDgtzMJpLLnXFgAChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISsaa0Zg2lwNpAkAIkHAAAAAPA8kv_-awoTiXNlY3AyNTZrMaEDHAD2JKYevx89W0CcFJFiskdcEzkH_Wdv9iW42qLK79ODdWRwgiMohHVkcDaCI4I".to_string(),
        ];

        let bootnodes = parse_enrs(enrs);

        assert_eq!(bootnodes.len(), 2, "a quic-less ENR is still a valid seed");
        for bootnode in &bootnodes {
            assert_eq!(bootnode.quic_port, None);
            // The whole point of keeping them: a `udp` port means discv5 can
            // use them, which is what `as_discovery_node` reports.
            assert_eq!(bootnode.udp_port, Some(9000));
            assert!(bootnode.as_discovery_node().is_some());
        }

        // What the TCP transport changed: the first record's `tcp` entry is now
        // a dial target, where before it produced no address and the bootnode
        // was a discv5 seed and nothing more.
        assert_eq!(bootnodes[0].tcp_port, Some(9000));
        let peer_id = PeerId::from_public_key(&bootnodes[0].public_key);
        assert_eq!(
            bootnode_dial_addrs(&bootnodes[0], peer_id),
            vec![
                format!("/ip4/3.147.37.0/tcp/9000/p2p/{peer_id}")
                    .parse::<Multiaddr>()
                    .unwrap()
            ],
            "a tcp-only bootnode is dialed over tcp alone"
        );

        // The second advertises neither, so it stays a seed with nothing to
        // dial: this is the case the `warn` in `build_swarm` counts.
        assert_eq!(bootnodes[1].tcp_port, None);
        let seed_only = PeerId::from_public_key(&bootnodes[1].public_key);
        assert!(bootnode_dial_addrs(&bootnodes[1], seed_only).is_empty());
    }

    #[test]
    fn a_peer_advertising_both_transports_is_dialed_over_quic_first() {
        // Position in this list used to decide nothing, because libp2p raced
        // every address at once. `DIAL_ADDRESS_CONCURRENCY` made it decide
        // which transport the peer is reached over whenever it answers on
        // both, so the order is asserted rather than left to read like
        // incidental construction order.
        let peer_id = random_peer();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

        let addrs = dial_addrs(ip, Some(9000), Some(9001), peer_id);

        assert_eq!(
            addrs,
            vec![
                quic_multiaddr(ip, 9000, peer_id),
                tcp_multiaddr(ip, 9001, peer_id),
            ],
            "quic has to come first, or the reservation is the wrong way round"
        );
    }

    #[test]
    fn parse_enrs_skips_malformed_records_but_keeps_the_valid_one() {
        // The rewrite's whole point is that one bad line in the bootnode file
        // must not take the others down with it. Feed it a mix of the ways an
        // entry can be malformed, plus one genuinely valid ENR (reused from
        // `parse_enrs_extracts_ip_port_and_public_key`), and check the valid
        // one survives and nothing panics along the way.
        let enrs = vec![
            "not-an-enr-at-all".to_string(), // missing "enr:" prefix
            "enr:not valid base64!!!".to_string(), // non-base64 garbage
            "enr:AAAAAAAAAAAAAAAA".to_string(), // valid base64, not valid RLP
            "enr:-IW4QGGifTt9ypyMtChDISUNX3z4z5iPdiEPOmBoILvnDuWIKbWVmKXxZERPnw0piQyaBNCENFEPoIi-vxsnsrBig9MBgmlkgnY0gmlwhH8AAAGEcXVpY4IjKYlzZWNwMjU2azGhAhMMnGF1rmIPQ9tWgqfkNmvsG-aIyc9EJU5JFo3Tegys".to_string(),
        ];

        let bootnodes = parse_enrs(enrs);

        assert_eq!(bootnodes.len(), 1, "exactly the one valid ENR must survive");
        assert_eq!(bootnodes[0].ip, IpAddr::from(Ipv4Addr::LOCALHOST));
        assert_eq!(bootnodes[0].quic_port, Some(9001));
    }
}
