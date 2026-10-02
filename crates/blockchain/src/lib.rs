use ethlambda_engine::{EngineClient, ForkchoiceStateV1, PayloadStatusV1 as EnginePayloadStatus};
use ethlambda_network_api::{
    AggregateArrival, BlockArrival, BlockChainToP2PRef, BlockSource, DeferredFrom, FetchRequest,
    InitP2P,
};
use ethlambda_state_transition::beacon::error::Error as BeaconError;
use ethlambda_state_transition::beacon::fork_choice;
use ethlambda_state_transition::beacon::helpers::accessors::CommitteeCacheExt;
use ethlambda_state_transition::is_proposer;
use ethlambda_storage::{ALL_TABLES, CacheKey, Chain, Store};
use ethlambda_types::{
    ShortRoot,
    aggregator::AggregatorController,
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    beacon::{
        config::Config,
        constants,
        containers::{SignedAggregateAndProof, SignedBeaconBlock, fulu},
        preset,
        primitives::ValidatorIndex,
    },
    block::SignedBlock,
    chain_config::ChainConfig,
    primitives::{H256, HashTreeRoot as _},
    time::unix_now_ms,
};
use libssz::{SszDecode as _, SszEncode as _};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant, SystemTime};

use crate::aggregation::{
    AggregateProduced, AggregationDeadline, AggregationDone, AggregationSession,
    EARLY_AGGREGATION_WINDOW, EarlyAggregationCheck, MAX_AGGREGATION_JOBS,
    PRIOR_WORKER_JOIN_TIMEOUT, aggregation_deadline, run_aggregation_worker,
};
use crate::key_manager::ValidatorKeyPair;
use crate::sync_status::SyncStatusTracker;
use spawned_concurrency::actor;
use spawned_concurrency::error::ActorError;
use spawned_concurrency::protocol;
use spawned_concurrency::tasks::{
    Actor, ActorRef, ActorStart, Backend, Context, Handler, send_after,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::block_builder::ProposerConfig;
use crate::events::ChainEventSnapshot;
use crate::import_timing::{BlockImportReport, CascadeTimings, HeadTimings, ImportTimings};
use crate::store::StoreError;

pub use events::{ChainEvent, EventBus, Topic, UnknownTopic};

pub mod aggregation;
mod beacon_aggregates;
pub mod beacon_engine;
pub mod block_builder;
pub(crate) mod coverage;
pub mod events;
pub(crate) mod fork_choice_tree;
pub mod import_timing;
pub mod key_manager;
pub mod metrics;
pub mod reaggregate;
pub mod spec_test_runner;
pub mod store;
mod sync_status;

pub struct BlockChain {
    handle: ActorRef<BlockChainServer>,
}

/// Startup configuration for the [`BlockChain`] actor: the distinct
/// dependencies wired in once at spawn, grouped to keep the constructor's
/// signature small.
pub struct BlockChainConfig {
    /// Committee-aggregator role, toggleable at runtime via the admin API.
    pub aggregator: AggregatorController,
    /// Runtime-readable sync status: written by the actor each tick and read
    /// by the RPC `/lean/v0/node/syncing` endpoint.
    pub sync_status_controller: SyncStatusController,
    /// Number of attestation committees (= subnet count).
    pub attestation_committee_count: u64,
    /// Whether the sync-gate suppresses validator duties (vs observe-only).
    pub gate_duties: bool,
    /// Attestation subnets this node subscribes to.
    pub subscribed_subnets: HashSet<u64>,
    /// The subnet this aggregator is responsible for when scoring recursive
    /// aggregation. Aggregators on different duty subnets merge different
    /// children, which is what stops them all producing the same proof.
    pub aggregation_duty_subnet: u64,
    /// Whether the aggregator sits out candidates whose level another duty
    /// subnet owns in the slot, trading window overlap for less duplicated prover
    /// work.
    pub skip_redundant_aggregation: bool,
    /// Proposer-side block-building policy.
    pub proposer_config: ProposerConfig,
}

// The interval grid lives in `ethlambda-types` because `ethlambda-storage` also
// derives slots from the store clock and must not carry a second copy of a
// consensus-critical constant.
pub use ethlambda_types::block::MAX_ATTESTATIONS_DATA;
pub use ethlambda_types::constants::{DEFAULT_MILLISECONDS_PER_SLOT, INTERVALS_PER_SLOT};
pub use sync_status::SyncStatusController;
/// Future-slot tolerance for gossip attestations, expressed in intervals.
///
/// Bounds the clock skew the time check is willing to absorb when admitting a
/// vote whose slot has not yet started locally. One interval is a fifth of the
/// configured slot, the lean analogue of mainnet's
/// [`MAXIMUM_GOSSIP_CLOCK_DISPARITY`].
///
/// See: leanSpec PR #682.
pub const GOSSIP_DISPARITY_INTERVALS: u64 = 1;

/// How far ahead of the wall clock a beacon block may sit and still be held
/// for its slot rather than rejected.
///
/// The phase0 p2p-interface constant of the same name, which is what
/// [`GOSSIP_DISPARITY_INTERVALS`] is lean's analogue of. Mainnet clients
/// admit a block this far early and queue it to its slot; past it the block
/// is not early, it is wrong.
///
/// It is also what keeps [`BlockChainServer::defer_early_block`] from being a
/// flood target: a hold keeps the whole block in memory until its slot
/// starts, so holding anything merely "in the future" would let one peer
/// spend this node's memory on blocks for slots years away.
///
/// Wraps [`ethlambda_types::beacon::constants::MAXIMUM_GOSSIP_CLOCK_DISPARITY`]
/// as a `Duration`, rather than defining the number here: the p2p crate's own
/// data-column gossip check needs the same value, and a `Duration` is no more
/// use to it than a bare millisecond count is to anything in this module that
/// converts one to the other anyway.
pub const MAXIMUM_GOSSIP_CLOCK_DISPARITY: Duration =
    Duration::from_millis(ethlambda_types::beacon::constants::MAXIMUM_GOSSIP_CLOCK_DISPARITY);

/// Where a parked data column sidecar was put.
///
/// The three fields are exactly `Table::PendingDataColumns`'s key, so reading
/// the sidecar back needs nothing else. `slot` is also what the finality sweep
/// compares against.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ParkedColumn {
    slot: u64,
    block_root: H256,
    index: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SlotInterval {
    BlockPublication,
    AttestationProduction,
    Aggregation,
    SafeTargetUpdate,
    EndOfSlot,
}

impl SlotInterval {
    pub(crate) fn from_ms_since_genesis(ms_since_genesis: u64, config: &ChainConfig) -> Self {
        Self::from_intervals_since_genesis(ms_since_genesis / config.milliseconds_per_interval())
    }

    pub(crate) fn from_intervals_since_genesis(intervals_since_genesis: u64) -> Self {
        match intervals_since_genesis % INTERVALS_PER_SLOT {
            0 => Self::BlockPublication,
            1 => Self::AttestationProduction,
            2 => Self::Aggregation,
            3 => Self::SafeTargetUpdate,
            4 => Self::EndOfSlot,
            _ => unreachable!("slots only have {INTERVALS_PER_SLOT} intervals"),
        }
    }

    /// Milliseconds from genesis to the start of this interval in `slot`.
    ///
    /// Inverse of [`Self::from_ms_since_genesis`].
    pub(crate) fn to_ms_since_genesis(self, slot: u64, config: &ChainConfig) -> u64 {
        let interval = match self {
            Self::BlockPublication => 0,
            Self::AttestationProduction => 1,
            Self::Aggregation => 2,
            Self::SafeTargetUpdate => 3,
            Self::EndOfSlot => 4,
        };
        // Saturating so a caller that has not yet bounded `slot` (arrival
        // metrics see gossip slots before validation) cannot panic the actor in
        // a debug build or wrap into a small timestamp in a release one. The
        // clamped value is still meaningless: callers wanting a usable delta
        // must bound the slot themselves.
        slot.saturating_mul(config.milliseconds_per_slot)
            .saturating_add(interval * config.milliseconds_per_interval())
    }
}

/// Milliseconds until the next `cadence_ms` boundary, measured relative to
/// genesis. Before genesis, milliseconds until genesis itself.
///
/// Both tick cadences run through this: lean's is one fifth of a slot
/// ([`ms_until_next_interval`]), beacon's a whole slot
/// ([`ms_until_next_beacon_slot`]). One body, so the pre-genesis case and the
/// "a sample exactly on a boundary waits a whole cadence rather than zero"
/// property cannot hold on one grid and not the other.
fn ms_until_next_boundary(now_ms: u64, genesis_time_ms: u64, cadence_ms: u64) -> u64 {
    let Some(ms_since_genesis) = now_ms.checked_sub(genesis_time_ms) else {
        return genesis_time_ms - now_ms;
    };
    cadence_ms - (ms_since_genesis % cadence_ms)
}

/// Milliseconds until the next interval boundary: lean's tick cadence, one
/// fifth of a slot.
fn ms_until_next_interval(now_ms: u64, config: &ChainConfig) -> u64 {
    ms_until_next_boundary(
        now_ms,
        config.genesis_time_ms(),
        config.milliseconds_per_interval(),
    )
}

/// Milliseconds until the next slot boundary: beacon's tick cadence.
///
/// A beacon follower has no sub-slot duties (see [`ChainDuties::Beacon`]'s
/// documentation), so it ticks once per slot rather than once per lean
/// interval.
fn ms_until_next_beacon_slot(now_ms: u64, genesis_time_ms: u64, slot_duration_ms: u64) -> u64 {
    ms_until_next_boundary(now_ms, genesis_time_ms, slot_duration_ms)
}

impl BlockChain {
    /// Spawn the blockchain actor for the lean chain.
    ///
    /// `events` is the chain-event publication bus: the spawned actor is its
    /// sole publisher; consumers subscribe read-only receivers.
    ///
    /// Asserts `store.chain() == Chain::Lean`: pairing a lean-shaped
    /// `BlockChainConfig` (validator keys, aggregator role, proposer policy)
    /// with a beacon store would corrupt the directory the moment any duty
    /// touched it, so this is a programming error to catch here rather than
    /// a runtime condition to branch on. Use [`Self::spawn_beacon`] for a
    /// beacon store.
    pub fn spawn(
        store: Store,
        validator_keys: HashMap<u64, ValidatorKeyPair>,
        config: BlockChainConfig,
        events: EventBus,
    ) -> BlockChain {
        assert_eq!(
            store.chain(),
            Chain::Lean,
            "BlockChain::spawn requires a lean store; use BlockChain::spawn_beacon for a beacon one"
        );

        let BlockChainConfig {
            aggregator,
            sync_status_controller,
            attestation_committee_count,
            gate_duties,
            subscribed_subnets,
            aggregation_duty_subnet,
            skip_redundant_aggregation,
            proposer_config,
        } = config;

        metrics::set_is_aggregator(aggregator.is_enabled());
        metrics::set_node_sync_status(metrics::SyncStatus::Idle);
        let time_config = store.config().time_grid();
        let key_manager = key_manager::KeyManager::new(validator_keys);

        let lean = LeanDuties {
            key_manager,
            aggregator,
            current_aggregation: None,
            attestation_committee_count,
            subscribed_subnets,
            aggregation_duty_subnet,
            skip_redundant_aggregation,
            proposer_config,
            pre_merge_coverage: None,
        };

        // Warm the XMSS signing caches for the next duties before the first
        // tick, which fires right away and runs the current interval's duty.
        // The store clock doesn't work here: after an offline gap it lags
        // wall-clock by exactly the gap the first duty will be at.
        let ms_since_genesis = unix_now_ms().saturating_sub(time_config.genesis_time_ms());
        let current_slot = ms_since_genesis / time_config.milliseconds_per_slot;
        match SlotInterval::from_ms_since_genesis(ms_since_genesis, &time_config) {
            // The first tick still attests at the current slot. No proposal
            // key: the current slot's block was due at the previous slot's
            // interval 4, before we started, and the interval-1 tick warms the
            // next slot's.
            SlotInterval::BlockPublication | SlotInterval::AttestationProduction => {
                lean.key_manager.prepare_keys_for(current_slot as u32, None);
            }
            // This slot's attestations are behind us, so the next signatures
            // are the next slot's block, built at this slot's interval 4, and
            // that slot's attestations.
            SlotInterval::Aggregation
            | SlotInterval::SafeTargetUpdate
            | SlotInterval::EndOfSlot => {
                let num_validators = store.head_state().validators.len() as u64;
                let next_slot = current_slot + 1;
                let proposer = lean.our_proposer(next_slot, num_validators);
                lean.key_manager
                    .prepare_keys_for(next_slot as u32, proposer);
            }
        }

        Self::start_actor(
            store,
            SyncStatusTracker::new(gate_duties),
            sync_status_controller,
            events,
            ChainDuties::Lean(Box::new(lean)),
            Vec::new(),
            None,
            constants::SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY,
        )
    }

    /// Spawn the blockchain actor for the beacon chain, as a follower with no
    /// validator duties.
    ///
    /// No validator keys, no key advance, no aggregator role: a beacon
    /// follower only imports blocks and runs fork choice (see
    /// [`ChainDuties::Beacon`]). Feeding it gossip and calling this from
    /// `run_node` are later slices; this constructor only builds the actor.
    ///
    /// Uses [`SyncStatusTracker::new`]`(false)`: the tracker still drives the
    /// `lean_node_sync_status` metric (the name predates beacon support), but
    /// there are no duties on this arm for it to gate.
    ///
    /// Asserts `store.chain() == Chain::Beacon`, the mirror image of
    /// [`Self::spawn`]'s assertion, for the same reason: a mismatch here is a
    /// programming error, not a condition to recover from.
    ///
    /// `custody_columns` feeds the data-availability gate in `process_block`.
    /// It is computed once at startup from this node's id (see
    /// `das::custody_columns`).
    ///
    /// `engine` is the execution client to validate payloads against, `None`
    /// when `--execution-endpoint` was not given, and
    /// `safe_slots_to_import_optimistically` is
    /// `--safe-slots-to-import-optimistically`.
    pub fn spawn_beacon(
        store: Store,
        sync_status_controller: SyncStatusController,
        events: EventBus,
        custody_columns: Vec<u64>,
        engine: Option<EngineClient>,
        safe_slots_to_import_optimistically: u64,
    ) -> BlockChain {
        assert_eq!(
            store.chain(),
            Chain::Beacon,
            "BlockChain::spawn_beacon requires a beacon store; use BlockChain::spawn for a lean one"
        );

        metrics::set_node_sync_status(metrics::SyncStatus::Idle);

        Self::start_actor(
            store,
            SyncStatusTracker::new(false),
            sync_status_controller,
            events,
            ChainDuties::Beacon,
            custody_columns,
            engine,
            safe_slots_to_import_optimistically,
        )
    }

    /// Start the actor and arm its first tick: everything the two public
    /// constructors above do identically, once.
    ///
    /// The first `Tick` is armed for genesis, or immediately when genesis is
    /// already past (`unwrap_or_default` on a negative duration). That is the
    /// contract both chains' tick loops are entered through, which is why it
    /// is stated in one place rather than per chain.
    ///
    /// `custody_columns` and `engine` are both meaningless on
    /// [`ChainDuties::Lean`]: lean carries no
    /// `DataAvailability::Columns` evidence to gate on and has no execution
    /// layer, so [`BlockChain::spawn`] passes an empty vector and `None`. It
    /// passes the specification's own default for
    /// `safe_slots_to_import_optimistically`, which nothing on that arm reads.
    #[allow(clippy::too_many_arguments)]
    fn start_actor(
        store: Store,
        sync_status: SyncStatusTracker,
        sync_status_controller: SyncStatusController,
        events: EventBus,
        duties: ChainDuties,
        custody_columns: Vec<u64>,
        engine: Option<EngineClient>,
        safe_slots_to_import_optimistically: u64,
    ) -> BlockChain {
        let genesis_time = store.config().genesis_time;

        // `sidecars_awaiting_parent` starts empty below, and it is the only
        // index into `Table::PendingDataColumns`. Anything a previous run
        // parked there is unreachable from here on, so it goes now rather than
        // sitting unverified and unread until the directory is deleted.
        let _ = store
            .clear_pending_data_column_sidecars()
            .inspect_err(|err| error!(%err, "Failed to clear parked data column sidecars"));

        let handle = BlockChainServer {
            store,
            p2p: None,
            pending_blocks: HashMap::new(),
            pending_block_parents: HashMap::new(),
            blocks_awaiting_columns: HashMap::new(),
            held_timings: HashMap::new(),
            sidecars_awaiting_parent: HashMap::new(),
            beacon_aggregates: Default::default(),
            custody_columns,
            engine,
            safe_slots_to_import_optimistically,
            last_tick_instant: None,
            sync_status,
            sync_status_controller,
            events,
            duties,
        }
        // Own thread: these handlers are long synchronous CPU that starves a shared runtime.
        .start_with_backend(Backend::Thread);
        let time_until_genesis = (SystemTime::UNIX_EPOCH + Duration::from_secs(genesis_time))
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        send_after(
            time_until_genesis,
            handle.context(),
            block_chain_protocol::Tick,
        );
        BlockChain { handle }
    }

    pub fn actor_ref(&self) -> &ActorRef<BlockChainServer> {
        &self.handle
    }
}

/// GenServer that sequences all blockchain updates.
///
/// Any head or finalization updates are done by this server.
/// Right now it also handles block processing, but in the future
/// those updates might be done in parallel with only writes being
/// processed by this server.
pub struct BlockChainServer {
    store: Store,

    // P2P protocol ref (set via InitP2P message)
    p2p: Option<BlockChainToP2PRef>,

    // Pending block roots waiting for their parent (block data stored in DB)
    pending_blocks: HashMap<H256, HashSet<H256>>,
    // Maps pending block_root → its cached missing ancestor. Resolved by walking the
    // chain at lookup time, since a cached ancestor may itself have become pending with
    // a deeper missing parent after the entry was created.
    pending_block_parents: HashMap<H256, H256>,

    /// Beacon blocks admitted past the parent check (see
    /// [`Self::process_or_pend_block`]) but held from fork choice because a
    /// column this node custodies for them had not yet arrived, keyed by root
    /// with the block's own slot cached alongside so
    /// [`Self::release_block_if_columns_complete`] can re-check presence
    /// without decoding the block back out of storage first. A separate map
    /// from `pending_blocks` above: a held block already has a known parent,
    /// which is the one thing that map tracks the absence of. Always empty on
    /// lean, which carries no `DataAvailability::Columns` evidence to gate on.
    blocks_awaiting_columns: HashMap<H256, u64>,

    /// Timing timings for every block currently held, keyed by root.
    ///
    /// One map for all three hold kinds rather than a field widening each of
    /// the hold maps, because what has to survive a hold is the same thing
    /// whichever hold it is: the block's original arrival, so that its
    /// end-to-end time still starts where it really started. Entries are taken
    /// on release and removed by [`Self::discard_pending_subtree`], the funnel
    /// both eviction paths already use for `pending_blocks` and
    /// `blocks_awaiting_columns`, so a block nobody ever redelivers cannot
    /// leave one behind.
    held_timings: HashMap<H256, ImportTimings>,

    /// Sidecars whose block's parent this node cannot yet transition from,
    /// keyed by that parent's root and replayed when it gains a post-state.
    ///
    /// The specification's gossip rule for a sidecar whose parent is not
    /// usable is `[IGNORE]`, and it says so with an explicit licence to come
    /// back to it: "MAY be queued for processing once the parent block is
    /// retrieved". Dropping instead is what deadlocks a follower running the
    /// availability gate, because the gate manufactures exactly this
    /// condition: a held block never reaches `on_block`, so it never writes a
    /// post-state, so every sidecar of every *child* of it fails the parent
    /// lookup. Held block and un-arrived parent are indistinguishable here and
    /// both are temporary, so both queue.
    ///
    /// Only the keys live here. The sidecar's own bytes go straight into
    /// `Table::PendingDataColumns` and are read back on replay, because a
    /// sidecar carries a cell per blob and a queue of them is the one
    /// structure on this actor whose size a peer gets to choose.
    ///
    /// Uncapped, and swept only by
    /// [`Self::evict_sidecars_awaiting_parent_at_or_below_finality`], on the
    /// same schedule held blocks are. A peer naming parents this node will
    /// never have can therefore grow it until finality reclaims the slots;
    /// see [`Self::queue_sidecar_awaiting_parent`]. Always empty on lean.
    ///
    /// A set per parent, so "the same column is never parked twice" is the
    /// container's own rule rather than a scan every arrival pays for. Order
    /// is not one: a replay checks and stores each sidecar on its own, and a
    /// held block is released by its last column arriving, whichever that is.
    sidecars_awaiting_parent: HashMap<H256, HashSet<ParkedColumn>>,

    /// The columns this node samples, computed once at startup from its node
    /// id (see `das::custody_columns`). Empty on lean.
    custody_columns: Vec<u64>,

    /// The execution client this follower validates payloads against, when one
    /// is configured. `None` is `--execution-endpoint` absent, in which case
    /// every block gets [`fork_choice::PayloadValidity::NotRequired`] and the
    /// follower behaves exactly as it did before any engine existed.
    ///
    /// Always `None` on lean, which has no execution layer.
    engine: Option<EngineClient>,

    /// `--safe-slots-to-import-optimistically`. Bounds
    /// [`fork_choice::is_optimistic_candidate_block`]'s age condition; the
    /// specification requires the value to be operator-configurable.
    safe_slots_to_import_optimistically: u64,

    /// Last tick instant for measuring interval duration.
    last_tick_instant: Option<Instant>,

    /// Stateful sync heuristic used by `lean_node_sync_status`. Also gates
    /// validator duties while syncing, unless that gating was disabled at
    /// startup via `--disable-duty-sync-gate` (then it is metric-only). On a
    /// beacon follower ([`BlockChain::spawn_beacon`]) there are no duties to
    /// gate, so it is always constructed observe-only there.
    sync_status: SyncStatusTracker,

    /// Shared, read-only mirror of `sync_status` for readers outside the actor
    /// (the RPC `/lean/v0/node/syncing` endpoint). Written from
    /// `update_sync_status` with the same `SyncStatus` fed to the metric.
    sync_status_controller: SyncStatusController,

    /// Chain-event publication bus. The actor is the sole publisher; consumers
    /// only subscribe, preserving the one-directional write flow.
    events: EventBus,

    /// The `beacon_aggregate_and_proof` seen-sets and deferral queue. Always
    /// empty on lean, which subscribes to no such topic. See
    /// [`crate::beacon_aggregates`] for why all three live on the actor rather
    /// than in the p2p layer that first sees an aggregate.
    beacon_aggregates: crate::beacon_aggregates::AggregateGossip,

    /// The lean-only or beacon-only half of this actor's state. See
    /// [`ChainDuties`].
    duties: ChainDuties,
}

/// The lean-only or beacon-only half of [`BlockChainServer`]'s state.
///
/// Every field a lean validator needs (key material, aggregator role, the
/// in-flight aggregation session, proposer policy, ...) means nothing on a
/// beacon follower: it has no validator keys, casts no votes, and builds no
/// blocks of its own. Splitting them behind this enum, rather than leaving
/// them on [`BlockChainServer`] directly and trusting every call site to
/// check the chain before touching one, turns "beacon has no validator
/// duties" into a compile-time fact instead of a convention: the field
/// simply is not there to read on that arm.
///
/// A lean-only *message handler* opens with
/// `let ChainDuties::Lean(_) = &self.duties else { return };`: dropping a
/// message that does not apply to this chain is a legitimate runtime outcome,
/// and the handler is the actor's outer boundary where that decision belongs.
///
/// Everything below that boundary reads the payload through
/// [`BlockChainServer::lean`]/[`BlockChainServer::lean_mut`], which panic
/// rather than return. Since [`BlockChain::spawn`] and
/// [`BlockChain::spawn_beacon`] each assert their store's chain tag matches
/// the duties they build, reaching one from a beacon follower is a
/// programming error, not a condition to absorb: a silent `return` in the
/// middle of a duty would leave it half-done and look exactly like a real
/// early exit.
///
/// Boxes the `Lean` payload: `LeanDuties` carries a key manager, a subnet
/// set and an aggregation session, and clippy's `large_enum_variant` flags
/// the gap against a `Beacon` arm that carries nothing at all.
enum ChainDuties {
    /// Validator duties: signing, committee aggregation, proposing. See
    /// [`LeanDuties`].
    Lean(Box<LeanDuties>),
    /// Chain-following only: import blocks, run fork choice, tick once per
    /// slot boundary. A follower holds no state of its own beyond the store:
    /// even a block that arrives before its slot waits in a timer rather than
    /// in a field here (see [`BlockChainServer::defer_early_block`]).
    Beacon,
}

/// Panics, naming the validator duty a beacon follower reached.
///
/// The same shape as `state_transition`'s `lean_boundary` helpers, and for
/// the mirror-image reason: `ChainDuties::Beacon` carries no validator state,
/// so a duty asking for it means the caller dispatched on the wrong chain.
/// `#[cold]` and `#[track_caller]` so the panic still reports the duty's own
/// file and line, the way an `unreachable!` written inline there would have.
#[cold]
#[track_caller]
fn beacon_has_no_duties() -> ! {
    unreachable!(
        "a beacon follower reached a lean validator duty; \
         BlockChain::spawn_beacon builds ChainDuties::Beacon, so the caller \
         must dispatch on the chain before this point"
    )
}

/// Validator-duty state, live only on [`ChainDuties::Lean`].
struct LeanDuties {
    key_manager: key_manager::KeyManager,

    /// Whether this node acts as a committee aggregator.
    ///
    /// Read fresh on every tick and gossip event so runtime toggles via the
    /// admin API take effect without a restart. Seeded from the CLI
    /// `--is-aggregator` flag at spawn.
    aggregator: AggregatorController,

    /// The slot's one committee-signature aggregation session (started at
    /// interval 2, or early via the 2/3 trigger). Deliberately persists after
    /// the worker finishes (that persistence is the once-per-slot latch the
    /// early trigger and the interval-2 skip both check) until the next
    /// session start replaces it.
    current_aggregation: Option<AggregationSession>,

    /// Number of attestation committees (= subnet count). Used by the
    /// attestation aggregate coverage emission and the early-aggregation
    /// threshold.
    attestation_committee_count: u64,

    /// Attestation subnets this node subscribes to (its validators' own
    /// subnets plus any aggregator-only subnets), computed once at startup and
    /// shared with the P2P swarm via [`ethlambda_p2p::attestation_subscription_subnets`].
    /// Used to scale the early-aggregation threshold.
    subscribed_subnets: HashSet<u64>,

    /// The subnet this aggregator is responsible for. Scores which children
    /// recursive aggregation merges, so aggregators on different duty subnets
    /// build different proofs.
    aggregation_duty_subnet: u64,

    /// Whether to sit out aggregation candidates whose level another duty
    /// subnet owns this slot, trading window overlap for less duplicated
    /// prover work. See [`aggregation::owns_width`] for the rotation.
    skip_redundant_aggregation: bool,

    /// Proposer-side block-building policy
    proposer_config: ProposerConfig,

    /// Pre-merge `new_payloads` snapshot for the attestation aggregate coverage
    /// report. Captured at the end-of-slot promote (interval 4), read at the
    /// next slot boundary. Owned solely by the actor and only touched from the
    /// single-threaded message loop, so no synchronization is needed.
    /// Observability-only.
    pre_merge_coverage: Option<coverage::CoverageSnapshot>,
}

impl LeanDuties {
    /// Returns the validator ID if any of our validators is the proposer for
    /// this slot.
    fn our_proposer(&self, slot: u64, num_validators: u64) -> Option<u64> {
        self.key_manager
            .validator_ids()
            .into_iter()
            .find(|&vid| is_proposer(vid, slot, num_validators))
    }
}

/// Error from importing a block, whichever chain it belongs to.
///
/// [`BlockChainServer::process_block`] runs one of two import calls
/// depending on the block's variant: lean's [`store::on_block`] returns
/// [`StoreError`], beacon's [`fork_choice::on_block`] returns
/// [`BeaconError`]. Wrapping both here, rather than picking one chain's
/// error type to stand in for both, keeps each chain's own error type
/// exactly as its own module defines it.
#[derive(Debug, thiserror::Error)]
enum ImportError {
    #[error(transparent)]
    Lean(#[from] StoreError),
    #[error(transparent)]
    Beacon(#[from] BeaconError),
}

/// What [`BlockChainServer::process_block`] did with the block it was given.
///
/// The distinction exists for [`BlockChainServer::process_or_pend_block`]:
/// only [`ImportOutcome::Imported`] means a post-state now exists under
/// `block_root`, so only it may unblock anything pending on that root.
/// `process_block` used to return a bare `Ok(())` for a held block too, which
/// made its caller call `collect_pending_children` as if the hold had
/// produced a state to build on. A child block naming a held block as parent
/// would then have its ancestor walk find the held block's row in
/// `BlockHeaders` (written by `hold_block_for_columns`'s own
/// `insert_pending_block`) and re-enqueue it into the very cascade the child
/// arrived on; reprocessing re-held it, which called
/// `collect_pending_children` again, which re-enqueued the same child again —
/// forever, inside `run_import_cascade`'s synchronous loop, with no yield
/// point and a duplicate column fetch to peers on every turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportOutcome {
    /// A post-state now exists under the block's root, whether this call
    /// wrote it or it already had one. Safe to unblock anything pending on
    /// this root.
    Imported,
    /// The block left the cascade without a post-state under its root, so
    /// nothing pending on that root may be unblocked.
    ///
    /// Two reasons reach this, and they differ in what happens next:
    ///
    /// - A fulu block whose custody columns have not all arrived. The block is
    ///   persisted and readable back by root, and
    ///   [`BlockChainServer::release_block_if_columns_complete`] eventually
    ///   re-imports it and reaches `collect_pending_children` for real.
    /// - No verdict from the execution client, or a `NOT_VALIDATED` verdict on
    ///   a block that is not an optimistic candidate. Nothing is recorded and
    ///   the block is simply dropped: unlike a column hold, nothing re-drives
    ///   it, which is what the terminal retry policy on the engine ladder
    ///   means. See `EngineClient::call`'s own documentation.
    ///
    /// The name reads as "held for columns" for historical reasons; it is the
    /// general "produced no post-state" outcome.
    Held,
}

/// The availability evidence for `block`, or `None` if a column this node
/// custodies has not arrived yet.
///
/// `None` is not "unavailable": it means the question cannot be answered yet,
/// which is why the caller holds the block rather than rejecting it. A partial
/// set must never be passed on as evidence, because
/// `is_data_available_columns` is vacuously true over an empty list and would
/// import a block whose data nobody has.
///
/// Only fulu blocks reach the column shape. A deneb or electra block carrying
/// blobs would need the blob-and-proof shape, which this node has no source
/// for, so it is admitted with a log rather than held forever against a
/// pipeline that does not exist.
///
/// `ethlambda_storage::Table::DataColumns` is never pruned today (see its own
/// doc comment), which is what lets the sidecar-collecting `.expect()`s below
/// assume a column confirmed present a moment ago by `custody_columns_present`
/// is still there to decode; a future pruner has to keep that window safe too.
/// Whether a block at `block_slot` still falls inside the window this node may
/// insist on data availability for.
///
/// The boundary is the specification's own
/// `max(current_epoch - MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS,
/// FULU_FORK_EPOCH)`: the epoch range peers "MUST support serving requests of
/// data columns on". Below it a peer "MAY respond with error code
/// `3: ResourceUnavailable` or not include the data column sidecar in the
/// response", so a block there can be unavailable through no fault of anyone,
/// and holding it would stall the chain against data the network is entitled to
/// have dropped. Above it, refusing to import without the columns is the point.
///
/// Pre-fulu blocks are never gated: the column matrix does not exist for them,
/// and their own blob shape has no pipeline here (see [`data_availability_for`]).
///
/// Mirrors lighthouse's `da_check_required_for_epoch`, which asks the same
/// question of the same boundary.
fn da_check_required_for_slot(block_slot: u64, current_slot: u64, config: &Config) -> bool {
    let block_epoch = block_slot / preset::SLOTS_PER_EPOCH;
    let current_epoch = current_slot / preset::SLOTS_PER_EPOCH;
    let boundary = current_epoch
        .saturating_sub(constants::MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS)
        .max(config.fulu_fork_epoch);
    block_epoch >= boundary
}

fn data_availability_for(
    store: &Store,
    block: &SignedBeaconBlock,
    custody_columns: &[u64],
) -> Option<fork_choice::DataAvailability> {
    match block {
        SignedBeaconBlock::Deneb(inner) => {
            if !inner.message.body.blob_kzg_commitments.is_empty() {
                warn_no_blob_pipeline(block);
            }
            Some(fork_choice::DataAvailability::NotRequired)
        }
        SignedBeaconBlock::Electra(inner) => {
            if !inner.message.body.blob_kzg_commitments.is_empty() {
                warn_no_blob_pipeline(block);
            }
            Some(fork_choice::DataAvailability::NotRequired)
        }
        SignedBeaconBlock::Fulu(inner) => {
            if inner.message.body.blob_kzg_commitments.is_empty() {
                return Some(fork_choice::DataAvailability::NotRequired);
            }

            // An empty custody set means there is nothing outstanding, not
            // that the question is unanswerable: `custody_columns_present`
            // below is vacuously true and the resulting `Columns(vec![])` is
            // vacuously available, which is the right answer for a caller
            // that supplied every block itself. Only the replay harness
            // (`BlockChainServer::for_replay`) is in that position. A node
            // cannot be: `run_node` asserts a non-empty set before spawning,
            // `MainnetOptions::custody_group_count` floors at
            // `CUSTODY_REQUIREMENT`, and `das::custody_columns` never returns
            // an empty set.
            let slot = block.slot();
            let block_root = block.message_hash_tree_root();

            // Presence first, over the full set: a column this node has not
            // yet verified must not even be looked up, since silently
            // dropping the missing ones would hand back a shorter-but-still-
            // non-empty list that reads as complete evidence to the caller.
            if !custody_columns_present(store, slot, &block_root, custody_columns) {
                return None;
            }

            let sidecars = custody_columns
                .iter()
                .map(|&index| {
                    let encoded = store
                        .get_data_column_sidecar(slot, &block_root, index)
                        .expect("DB read should succeed")
                        .expect("presence just confirmed above");
                    fulu::DataColumnSidecar::from_ssz_bytes(&encoded)
                        .expect("a sidecar this node verified before storing decodes")
                })
                .collect();

            Some(fork_choice::DataAvailability::Columns(sidecars))
        }
        _ => Some(fork_choice::DataAvailability::NotRequired),
    }
}

/// Whether every column in `custody_columns` is present for `block_root` at
/// `slot`, without reading any of them back.
///
/// Shared by [`data_availability_for`] and
/// [`BlockChainServer::release_block_if_columns_complete`], which both need
/// the same "is the set complete" question answered before paying for a read:
/// the former before collecting evidence, the latter before deciding whether
/// a held block is worth fetching back out of storage at all.
fn custody_columns_present(
    store: &Store,
    slot: u64,
    block_root: &H256,
    custody_columns: &[u64],
) -> bool {
    let present = store
        .data_column_indices_for(slot, block_root)
        .expect("DB read should succeed");
    custody_columns.iter().all(|index| present.contains(index))
}

/// Warns that `block` is being admitted with no availability check: this node
/// has no blob-and-proof pipeline to source `DataAvailability::Blobs`
/// evidence from for a deneb or electra block, and holding such a block
/// forever against a source that will never fill in would be worse than
/// admitting it unchecked.
///
/// Logged on every occurrence, with the fork and the block root, rather than
/// on the first one only: the held side of this gate is fully observable
/// (`lean_blocks_held_for_columns` plus `hold_block_for_columns`'s own log
/// line), and this is the admitted-without-checking side of the same gate, so
/// an operator needs to be able to tell how often it fires and for which block
/// just as much.
fn warn_no_blob_pipeline(block: &SignedBeaconBlock) {
    let fork = block.fork_name().as_str();
    let block_root = block.message_hash_tree_root();
    warn!(
        fork,
        block_root = %ShortRoot(&block_root.0),
        "Admitting a block carrying blobs with no availability check: this node \
         has no blob-and-proof pipeline"
    );
}

impl BlockChainServer {
    async fn on_tick(&mut self, timestamp_ms: u64, ctx: &Context<Self>) {
        let time_config = self.store.config().time_grid();

        // Calculate current slot and interval from milliseconds
        let time_since_genesis_ms = timestamp_ms.saturating_sub(time_config.genesis_time_ms());
        let slot = time_since_genesis_ms / time_config.milliseconds_per_slot;
        let interval = SlotInterval::from_ms_since_genesis(time_since_genesis_ms, &time_config);

        // Idempotency guard
        //
        // `slot`/`interval` come from the wall clock, but the tick cadence is driven
        // by the monotonic clock (`tokio::sleep`). The wall clock can drift behind it
        // inside VMs, so a tick scheduled for the next interval boundary can fire
        // while the wall clock still reads the previous interval.
        //
        // The store clock is one Unix millisecond row on either chain, but the
        // grids differ: lean counts intervals since genesis, beacon Unix
        // seconds. This tick's own position and the store's own reading are
        // both derived in whichever unit that chain keeps, so the comparison
        // below has one unit per arm rather than one across both.
        let (tick_time, store_time) = match self.store.chain() {
            Chain::Lean => (
                time_since_genesis_ms / time_config.milliseconds_per_interval(),
                self.store.intervals_since_genesis(),
            ),
            Chain::Beacon => (
                timestamp_ms / 1000,
                self.store.time_ms().expect("store time exists") / 1_000,
            ),
        };

        if store_time > 0 && tick_time <= store_time {
            debug!(
                %slot,
                ?interval,
                tick_time,
                store_time,
                "Skipping already-processed tick"
            );
            return;
        }

        // Fail fast: a state with zero validators is invalid and would cause
        // panics in proposer selection and attestation processing. Lean-only:
        // `head_state` peels a lean `State` and panics on a beacon store, which
        // has no validator set of its own to check. Read once per tick, since
        // `head_state` clones the whole state. Zero on a beacon follower, where
        // nothing reads it: `get_our_proposer` answers `None` there first.
        let num_validators = match self.store.chain() {
            Chain::Lean => self.store.head_state().validators.len() as u64,
            Chain::Beacon => 0,
        };
        if self.store.chain() == Chain::Lean && num_validators == 0 {
            error!("Head state has no validators, skipping tick");
            return;
        }

        // Update current slot metric
        metrics::update_current_slot(slot);
        self.update_sync_status(slot);

        // Snapshot the aggregator flag once per tick so all read sites within
        // the tick see a consistent value even if the admin API toggles it
        // mid-tick. Mirror it to the gauge from the actor side so
        // `lean_is_aggregator` reflects the value the actor is acting on.
        // Always false on a beacon follower, which holds no such role.
        let is_aggregator = self.is_aggregator();
        metrics::set_is_aggregator(is_aggregator);

        // ==== interval 4 (pre-tick) ====

        // Snapshot the pre-merge `new_payloads` set at the end-of-slot promote
        // (interval 4), so the post-block report for this round sees its
        // "timely" cohort just before it is promoted out of `new_payloads`.
        //
        // Only interval 4 — not the proposer's interval-0 promote. By interval 0
        // the round's votes have already been promoted at the previous slot's
        // interval 4; `new_payloads` then holds only stragglers, and snapshotting
        // them here would overwrite the good interval-4 snapshot the report still
        // needs (those stragglers surface in the `late` section instead). Skip
        // empty snapshots so a missed round keeps the last set we saw. Pure
        // observability.
        if interval == SlotInterval::EndOfSlot
            && let Some(snapshot) = coverage::snapshot_new_payloads(&self.store)
            && let ChainDuties::Lean(lean) = &mut self.duties
        {
            lean.pre_merge_coverage = Some(snapshot);
        }

        // Whether one of our validators proposes this slot. Drives the store's
        // interval-0 attestation acceptance. `get_our_proposer` answers `None`
        // on a beacon follower, which carries no validator keys.
        let is_proposer = (interval == SlotInterval::BlockPublication && slot > 0)
            .then(|| self.get_our_proposer(slot, num_validators))
            .flatten()
            .is_some();

        // Tick the store first - this accepts attestations at interval 0 if we have a proposal.
        // Snapshot/diff around the call so attestation-driven head or
        // finalization moves surface as chain events.
        //
        // Which call that is depends on the chain. Lean's `store::on_tick`
        // carries its own fork-choice work; beacon's clock advance does not, so
        // the head recompute follows it here. It is still needed for a slot in
        // which nothing arrived, the block path having one of its own (see
        // [`Self::recompute_beacon_head`], which both share).
        let pre_tick = ChainEventSnapshot::capture(&self.store);
        match self.store.chain() {
            Chain::Lean => store::on_tick(&mut self.store, timestamp_ms, is_proposer),
            Chain::Beacon => {
                let config = self.store.config();
                // Loops `on_tick_per_slot` over every boundary crossed since the
                // last call, so a tick delayed by a long import still resets
                // proposer boost and pulls up unrealized checkpoints for each
                // slot it skipped, not just the latest one.
                fork_choice::on_tick(&mut self.store, timestamp_ms / 1000, &config);
                // Between the clock and the head: an aggregate for the slot
                // that just ended becomes applicable exactly now, and its
                // votes have to be in fork choice before the head this tick
                // reports is chosen.
                self.drain_deferred_aggregates();
                self.recompute_beacon_head().await;
            }
        }
        // `slot` above is already derived from `timestamp_ms` (the wall clock
        // at tick time), so it doubles as the wall-clock slot for the gate.
        pre_tick.diff_and_emit(&self.store, &self.events, slot);

        // The other of the two places (with a genuine `process_block` import)
        // beacon finality can move; see the method's own documentation for
        // why nothing else evicts a held block nobody redelivers.
        self.evict_held_blocks_at_or_below_finality();
        self.evict_sidecars_awaiting_parent_at_or_below_finality();
        self.redrive_held_blocks().await;

        // Per-interval duties for this tick. Lean-only, so this is where a
        // beacon follower's tick ends: it has no validator duties (see
        // [`ChainDuties::Beacon`]), and everything a tick owes it happened
        // above.
        self.run_interval_duties(interval, slot, num_validators, is_aggregator, ctx)
            .await;

        // Update safe target slot metric (updated by store.on_tick at interval 3).
        // Lean-only: a beacon store keeps no safe target.
        if self.store.chain() == Chain::Lean {
            metrics::update_safe_target_slot(self.store.safe_target_slot());
        }

        // Head may change when attestations are promoted at intervals 0/4.
        // Beacon moves the justified and finalized pair without importing
        // anything, when the clock advance above crosses an epoch boundary and
        // pulls up unrealized checkpoints.
        self.refresh_chain_metrics();
    }

    /// Push the head, justified and finalized slots to their gauges.
    ///
    /// The two places a tick or an import can move any of the three
    /// ([`Self::on_tick`] and [`Self::process_block`]) refresh all three, so
    /// they read the chain the same way: head through [`Self::head_slot`],
    /// which is the only spelling of that dispatch.
    fn refresh_chain_metrics(&self) {
        metrics::update_head_slot(self.head_slot());
        let latest_justified_slot = self
            .store
            .latest_justified()
            .expect("Error: Latest justified checkpoint does not exist")
            .slot;
        metrics::update_latest_justified_slot(latest_justified_slot);
        let latest_finalized_slot = self
            .store
            .latest_finalized()
            .expect("Error: Latest finalized checkpoint does not exist")
            .slot;
        metrics::update_latest_finalized_slot(latest_finalized_slot);
    }

    /// Run this tick's validator duties, the interval grid `on_tick` sits on.
    ///
    /// Lean-only, and it says so itself rather than making the caller ask:
    /// [`ChainDuties::Beacon`] carries no validator state for any of these to
    /// read, and a beacon follower ticks once per slot, which lands it on
    /// [`SlotInterval::BlockPublication`] where there is nothing to do anyway.
    ///
    /// `is_aggregator` is passed in rather than read here so every duty in the
    /// tick acts on the one value the tick started with, even if the admin API
    /// toggles the role underneath it. `num_validators` is the head state's,
    /// read once by `on_tick` since `head_state` clones the whole state.
    async fn run_interval_duties(
        &mut self,
        interval: SlotInterval,
        slot: u64,
        num_validators: u64,
        is_aggregator: bool,
        ctx: &Context<Self>,
    ) {
        if !matches!(self.duties, ChainDuties::Lean(_)) {
            return;
        }
        let time_config = self.store.config().time_grid();

        // Per-interval duties for this tick. Intervals 0 (block publish) and 3
        // (safe-target update) are driven inside `store::on_tick` above, so they
        // carry only a note below.
        match interval {
            // ==== interval 0 ====
            //
            // No actor work at interval 0. The block is published here
            // conceptually (at the slot boundary), but the build+publish code
            // path runs at interval 4 of the previous slot — where it also
            // advances the store to this slot's interval 0 before building (see
            // `propose_block`). The real interval-0 tick is then skipped by the
            // idempotency guard above, since the store clock is already here.
            SlotInterval::BlockPublication => {}

            // ==== interval 1 ====
            //
            // Produce attestations at interval 1 (all validators including
            // proposer). Reuse the same snapshot so self-delivery decisions
            // match the rest of the tick.
            SlotInterval::AttestationProduction => {
                // Emit the post-block coverage report for the previous slot.
                // Fired at interval 1 (not 0) so the block carrying `slot - 1`'s
                // votes — proposed at interval 0 of this slot — has typically
                // been received and processed, letting the `block` section see
                // the same round.
                if slot > 0 {
                    coverage::emit_post_block_coverage(
                        &self.store,
                        self.lean().pre_merge_coverage.as_ref(),
                        self.lean().attestation_committee_count,
                        slot - 1,
                    );
                }
                if self.sync_status.duties_allowed() {
                    self.produce_attestations(slot, is_aggregator);
                } else if !self.lean().key_manager.validator_ids().is_empty() {
                    info!(%slot, "Skipping attestations while syncing");
                }

                // Schedule the early-aggregation window check. This tick is
                // one interval before T2, so the timer fires right as the
                // window opens at T2 - EARLY_AGGREGATION_WINDOW.
                if is_aggregator {
                    send_after(
                        Duration::from_millis(time_config.milliseconds_per_interval())
                            - EARLY_AGGREGATION_WINDOW,
                        ctx.clone(),
                        EarlyAggregationCheck,
                    );
                }

                // Warm the XMSS signing caches for the next slot so the signing
                // paths don't have to, now that this slot's attestations are
                // signed: a key caches one bottom subtree, so warming any earlier
                // evicts the subtree this slot's attestation signs with whenever
                // the two slots straddle a subtree boundary. This lands before
                // interval 4 signs the next slot's block. A skipped interval-1
                // tick costs only latency, since `sign` rebuilds the subtree
                // itself on a miss. Runs off the actor so a subtree boundary
                // doesn't stall the tick.
                let next_slot = slot + 1;
                let proposer = self.get_our_proposer(next_slot, num_validators);
                self.lean_mut()
                    .key_manager
                    .prepare_keys_in_background(next_slot as u32, proposer);
            }

            // ==== interval 2 ====
            SlotInterval::Aggregation => {
                if is_aggregator {
                    // The early trigger may have already started this slot's
                    // session (running or finished) — it IS the slot's session,
                    // so don't start a second one.
                    let already_started = self
                        .lean()
                        .current_aggregation
                        .as_ref()
                        .is_some_and(|session| session.session_id == slot);
                    if !already_started {
                        self.start_aggregation_session(slot, ctx).await;
                    }
                } else {
                    metrics::inc_aggregator_skipped_not_aggregator();
                }
            }

            // ==== interval 3 ====
            //
            // Safe-target update is handled inside `store::on_tick`.
            SlotInterval::SafeTargetUpdate => {}

            // ==== interval 4 ====
            //
            // Build and publish the NEXT slot's block here, one interval early,
            // so the heavy leanVM work happens during this otherwise-idle
            // interval. `propose_block` blocks the actor for the build and aligns
            // publication to the slot boundary. Doing the whole proposal here —
            // rather than stashing it for the interval-0 tick — keeps it robust:
            // `on_tick` skips the interval-0 tick whenever this build overruns
            // its interval.
            SlotInterval::EndOfSlot => {
                let next_slot = slot + 1;
                let next_proposer = self
                    .get_our_proposer(next_slot, num_validators)
                    .filter(|_| self.sync_status.duties_allowed());

                if let Some(validator_id) = next_proposer {
                    self.propose_block(next_slot, validator_id).await;
                }
            }
        }
    }

    /// This chain's head slot: `Store::head_slot` on lean,
    /// `Store::beacon_head` on beacon, which decode different tables. Zero on
    /// a beacon store with no head recorded yet.
    fn head_slot(&self) -> u64 {
        match self.store.chain() {
            Chain::Lean => self.store.head_slot(),
            Chain::Beacon => self.store.beacon_head().map_or(0, |(slot, _)| slot),
        }
    }

    /// Whether this node acts as a committee aggregator, read fresh so a
    /// runtime toggle takes effect without a restart. Always false on a beacon
    /// follower: the role is a lean validator duty.
    fn is_aggregator(&self) -> bool {
        matches!(&self.duties, ChainDuties::Lean(lean) if lean.aggregator.is_enabled())
    }

    /// This node's validator-duty state, for a caller that has already
    /// established it is running the lean chain.
    ///
    /// Panics on a beacon follower, through the same reasoning as
    /// `state_transition`'s `lean_boundary` pair: the two spawn constructors
    /// assert the store's chain tag against the duties they build, so a
    /// beacon follower reaching a validator duty is a dispatch bug above this
    /// method. `#[track_caller]` so the panic names the duty that asked
    /// rather than this accessor. A lean-only *message* is dropped at its
    /// handler instead, which is the boundary where that is a real outcome;
    /// see [`ChainDuties`].
    #[track_caller]
    fn lean(&self) -> &LeanDuties {
        match &self.duties {
            ChainDuties::Lean(lean) => lean,
            ChainDuties::Beacon => beacon_has_no_duties(),
        }
    }

    /// [`Self::lean`] for a duty that mutates its own state (the key manager,
    /// the aggregation session). Same panic, same reason.
    #[track_caller]
    fn lean_mut(&mut self) -> &mut LeanDuties {
        match &mut self.duties {
            ChainDuties::Lean(lean) => lean,
            ChainDuties::Beacon => beacon_has_no_duties(),
        }
    }

    /// Kick off a committee-signature aggregation session:
    /// 1. If a prior session is still running (pathological), warn and join it.
    /// 2. Snapshot the aggregation inputs from the store, capped at a single job
    ///    when we propose next slot.
    /// 3. Spawn a `spawn_blocking` worker that streams results back as messages.
    /// 4. Schedule the `AggregationDeadline` self-message at one interval out.
    ///
    /// Both entry points land here — the interval-2 tick and the early
    /// 2/3-threshold trigger — so the proposer cap applies to whichever one
    /// starts the slot's session. Lean-only.
    async fn start_aggregation_session(&mut self, slot: u64, ctx: &Context<Self>) {
        if let Some(prior) = self.lean_mut().current_aggregation.take() {
            prior.cancel.cancel();
            if !prior.worker.is_finished() {
                warn!(
                    prior_session_id = prior.session_id,
                    new_session_id = slot,
                    "Prior aggregation worker still running at next session start; joining before proceeding"
                );
            }
            match tokio::time::timeout(PRIOR_WORKER_JOIN_TIMEOUT, prior.worker).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => warn!(?err, "Prior aggregation worker task ended abnormally"),
                Err(_) => warn!(
                    timeout_secs = PRIOR_WORKER_JOIN_TIMEOUT.as_secs(),
                    "Timed out joining prior aggregation worker"
                ),
            }
        }

        let attestation_committee_count = self.lean().attestation_committee_count;
        coverage::emit_agg_start_new_coverage(&self.store, attestation_committee_count);

        // Limit ourselves to a single round of aggregation if we propose next round.
        // This buys us time to build the block before the next slot's interval-0 tick.
        let num_validators = self.store.head_state().validators.len() as u64;
        let next_proposer = self
            .get_our_proposer(slot + 1, num_validators)
            .filter(|_| self.sync_status.duties_allowed());
        let max_jobs = if next_proposer.is_some() {
            1
        } else {
            MAX_AGGREGATION_JOBS
        };

        let lean = self.lean();
        let window_config = aggregation::AggregationWindowConfig {
            duty_subnet: lean.aggregation_duty_subnet,
            committee_count: attestation_committee_count,
            skip_redundant: lean.skip_redundant_aggregation,
        };
        let Some(snapshot) =
            aggregation::snapshot_aggregation_inputs(&self.store, slot, max_jobs, window_config)
        else {
            // No current-slot gossip sigs — nothing to aggregate this slot.
            return;
        };

        let session_id = slot;
        let time_config = self.store.config().time_grid();
        let t2_ms = time_config.genesis_time_ms()
            + SlotInterval::Aggregation.to_ms_since_genesis(slot, &time_config);
        // Interval-2 boundary as a wall-clock instant; the worker holds each
        // produced aggregate until this before sending it back, so nothing
        // reaches gossip early.
        let publish_at = SystemTime::UNIX_EPOCH + Duration::from_millis(t2_ms);
        let now_ms = unix_now_ms();
        let early = now_ms < t2_ms;
        if early {
            let lead = Duration::from_millis(t2_ms - now_ms);
            metrics::inc_aggregation_early_starts();
            metrics::observe_aggregation_early_start_lead(lead);
            info!(
                %slot,
                lead_ms = lead.as_millis() as u64,
                "Starting aggregation session early"
            );
        }

        // Independent token per session. Shutdown propagates via our
        // #[stopped] hook which cancels any current session; the deadline
        // timer cancels this specific session at +`aggregation_deadline`.
        let cancel = CancellationToken::new();
        let actor_ref = ctx.actor_ref();

        let worker_cancel = cancel.clone();
        let worker_actor = actor_ref.clone();
        let worker = tokio::task::spawn_blocking(move || {
            run_aggregation_worker(
                snapshot,
                worker_actor,
                worker_cancel,
                session_id,
                publish_at,
            );
        });

        let _deadline_timer = send_after(
            aggregation_deadline(time_config.milliseconds_per_interval()),
            ctx.clone(),
            AggregationDeadline { session_id },
        );

        self.lean_mut().current_aggregation = Some(AggregationSession {
            session_id,
            early,
            cancel,
            worker,
        });
    }

    /// Early-aggregation trigger: start the slot's session ahead of the
    /// interval-2 tick when, inside the window `[T2 - EARLY_AGGREGATION_WINDOW, T2)`,
    /// a single attestation-data group already holds 2/3 of the signatures
    /// expected from this node's aggregation subnets. Called after every
    /// stored current-slot gossip signature and once at the window opening via
    /// [`EarlyAggregationCheck`]. Fires at most once per slot: the started
    /// session stays in `current_aggregation` (running or finished) until the
    /// next session replaces it. The latch has one hole: if the snapshot
    /// yields no jobs (possible only when no signer's pubkey resolves, i.e. a
    /// corrupted validator registry), no session is installed and the check
    /// retries on later inserts — each retry is a no-op session attempt.
    /// Lean-only.
    async fn maybe_start_early_aggregation(&mut self, ctx: &Context<Self>) {
        let lean = self.lean();
        if !lean.aggregator.is_enabled() {
            return;
        }
        // Only fire inside the early-aggregation window
        // `[T2 - EARLY_AGGREGATION_WINDOW, T2)`, where T2 is the current
        // slot's interval-2 boundary; the slot is derived from the wall clock.
        let time_config = self.store.config().time_grid();
        let Some(ms_since_genesis) = unix_now_ms().checked_sub(time_config.genesis_time_ms())
        else {
            return;
        };
        let ms_per_interval = time_config.milliseconds_per_interval();
        let ms_into_slot = ms_since_genesis % time_config.milliseconds_per_slot;
        let t2_offset = 2 * ms_per_interval;
        let window_ms = EARLY_AGGREGATION_WINDOW.as_millis() as u64;
        if ms_into_slot < t2_offset - window_ms || ms_into_slot >= t2_offset {
            return;
        }
        let slot = ms_since_genesis / time_config.milliseconds_per_slot;
        if lean
            .current_aggregation
            .as_ref()
            .is_some_and(|session| session.session_id == slot)
        {
            return;
        }
        let max_group = self.store.max_gossip_group_count_for_slot(slot);
        // Trigger once the largest current-slot group holds two-thirds of the
        // votes we expect it to collect, rounded up. Groups are keyed by
        // attestation data (not by subnet), so one group gathers signatures
        // from every subnet we subscribe to; the expected count is therefore
        // the number of network validators whose committee subnet is one of
        // ours, not a single committee's worth. With `N` validators across `C`
        // committees, subnet `s` holds `N / C` validators, plus one more when
        // `s < N % C`. (0 only when there are no such validators, which never
        // triggers.)
        let min_group_sigs = if lean.attestation_committee_count == 0 {
            0
        } else {
            let validator_count = self.store.head_state().validators.len() as u64;
            let committee_count = lean.attestation_committee_count;
            let expected_votes: u64 = lean
                .subscribed_subnets
                .iter()
                .filter(|&&subnet| subnet < committee_count)
                .map(|&subnet| {
                    validator_count / committee_count
                        + u64::from(subnet < validator_count % committee_count)
                })
                .sum();
            (2 * expected_votes).div_ceil(3) as usize
        };
        if min_group_sigs == 0 || max_group < min_group_sigs {
            return;
        }
        info!(
            %slot,
            max_group,
            min_group_sigs,
            "Early-aggregation threshold met"
        );
        self.start_aggregation_session(slot, ctx).await;
    }

    /// Returns the validator ID if any of our validators is the proposer for
    /// this slot.
    ///
    /// Answers `None` on a beacon follower rather than panicking through
    /// [`Self::lean`], and that is load-bearing: `on_tick` is chain-generic
    /// and asks this on every [`SlotInterval::BlockPublication`], which is the
    /// one interval a beacon follower's once-per-slot tick lands on.
    fn get_our_proposer(&self, slot: u64, num_validators: u64) -> Option<u64> {
        let ChainDuties::Lean(lean) = &self.duties else {
            return None;
        };
        lean.our_proposer(slot, num_validators)
    }

    /// Lean-only.
    fn produce_attestations(&mut self, slot: u64, is_aggregator: bool) {
        let validator_ids = self.lean().key_manager.validator_ids();

        let _timing = metrics::time_attestations_production();

        // Produce attestation data once for all validators
        let attestation_data = store::produce_attestation_data(&self.store, slot);

        // For each registered validator, produce and publish attestation
        for validator_id in validator_ids {
            // Sign the attestation
            let Ok(signature) = self
                .lean_mut()
                .key_manager
                .sign_attestation(validator_id, &attestation_data)
                .inspect_err(
                    |err| error!(%slot, %validator_id, %err, "Failed to sign attestation"),
                )
            else {
                continue;
            };

            // Create signed attestation
            let signed_attestation = SignedAttestation {
                validator_id,
                data: attestation_data.clone(),
                signature,
            };

            // Self-deliver: store our own attestation locally for aggregation.
            // Gossipsub does not deliver messages back to the sender, so without
            // this the aggregator never sees its own validator's signature in
            // gossip_signatures and it is excluded from aggregated proofs.
            if is_aggregator {
                let _ = store::on_gossip_attestation(&mut self.store, &signed_attestation, true)
                    .inspect_err(|err| {
                        warn!(%slot, %validator_id, %err, "Self-delivery of attestation failed")
                    });
            }

            // Publish to gossip network
            if let Some(ref p2p) = self.p2p {
                let _ = p2p.publish_attestation(signed_attestation).inspect_err(
                    |err| error!(%slot, %validator_id, %err, "Failed to publish attestation"),
                );
                info!(%slot, %validator_id, "Published attestation");
            }
        }
    }

    /// Build the target slot's block and publish it, one interval early.
    ///
    /// Runs at the previous slot's interval 4, blocking the actor for the build
    /// (the expensive part is the leanVM single-message → multi-message
    /// aggregate merge). It first
    /// advances the store to the target slot's interval 0 (accepting
    /// attestations) so the block is built on exactly the interval-0 state a
    /// non-prebuilding proposer would see, then builds and publishes — aligned
    /// to the slot boundary: if the build finishes before the slot opens we wait
    /// out the remainder so the block is not published early; if it overran (the
    /// common case under load) we publish at once. The whole proposal is
    /// self-contained here, so it never depends on the interval-0 tick — which
    /// `handle_tick` skips whenever this build overruns its interval.
    ///
    /// Lean-only: a beacon follower has no validator duties, so it never
    /// proposes.
    async fn propose_block(&mut self, slot: u64, validator_id: u64) {
        info!(%slot, %validator_id, "We are the proposer for this slot");

        let time_config = self.store.config().time_grid();
        let slot_start_ms = time_config.genesis_time_ms()
            + SlotInterval::BlockPublication.to_ms_since_genesis(slot, &time_config);

        let proposer_config = self.lean().proposer_config;

        // Build the block. `produce_block_with_signatures` advances the store to
        // this slot's interval 0 (accepting attestations) before building — one
        // interval ahead of the interval-4 tick we are running in — so the block
        // is built on the interval-0 state rather than the previous slot's end
        // state. Building early is safe because we publish below (nothing is
        // stashed for a later tick), and the real interval-0 tick is then skipped
        // by the idempotency guard in `on_tick`, since the store clock is already
        // here.
        //
        // That interval-0 catch-up can move head/justified/finalized (it is the
        // same attestation-acceptance step a non-proposing node runs at its
        // interval-0 tick). Snapshot around the build so those moves surface as
        // chain events here, matching an observer node; otherwise they would
        // land outside every snapshot window and be silently absorbed into the
        // later block-import diff's baseline.
        let pre_build = ChainEventSnapshot::capture(&self.store);
        let timing = metrics::time_block_building();
        let build_result = store::produce_block_with_signatures(
            &mut self.store,
            slot,
            validator_id,
            proposer_config,
        )
        .inspect_err(|err| error!(%slot, %validator_id, %err, "Failed to build block"));

        // `get_proposal_head` advances the store (interval-0 catch-up) inside
        // `produce_block_with_signatures` *before* the build can fail, so emit
        // the resulting head/checkpoint moves on both paths — a build failure
        // must not strand a real finalization move outside every snapshot
        // window. Ordered before the freshly built block's own import (which
        // emits its `block` + head/checkpoint events). The catch-up advanced
        // the store to `slot`'s interval 0, so the head-recency gate uses `slot`.
        pre_build.diff_and_emit(&self.store, &self.events, slot);

        let Ok((block, single_message_aggregates, _post_checkpoints)) = build_result else {
            metrics::inc_block_building_failures();
            return;
        };

        coverage::emit_proposal_coverage(
            &self.store,
            self.lean().attestation_committee_count,
            block.body.attestations.iter(),
        );

        // Sign the block root, wrap the signature as a singleton single-message
        // aggregate, and merge it with every attestation aggregate into the
        // block's multi-message aggregate.
        let head_state = self.store.head_state();
        let Ok(signed_block) = block_builder::seal_block(
            &head_state,
            &mut self.lean_mut().key_manager,
            block,
            single_message_aggregates,
        )
        .inspect_err(|err| error!(%slot, %validator_id, %err, "Failed to seal block")) else {
            metrics::inc_block_building_failures();
            return;
        };

        // Stop timing here: the build is done, and the alignment wait below must
        // not count toward the block-building metric.
        drop(timing);

        info!(%slot, %validator_id, "Finished building block");

        let now_ms = unix_now_ms();

        // Align publication to the slot boundary. If the build finished before
        // the slot opened, wait out the remainder so the block is not published
        // early; if it overran, publish immediately.
        if now_ms < slot_start_ms {
            let wait_ms = slot_start_ms.saturating_sub(now_ms);
            tokio::time::sleep(Duration::from_millis(wait_ms)).await;
        }

        self.process_and_publish_block(slot, validator_id, signed_block)
            .await;
    }

    /// Import a freshly built block locally, then publish it to gossip. On
    /// import failure, logs and counts it, and returns without publishing.
    /// Lean-only: the block this builds and imports is always a lean
    /// [`SignedBlock`].
    async fn process_and_publish_block(
        &mut self,
        slot: u64,
        validator_id: u64,
        signed_block: SignedBlock,
    ) {
        let block_root = signed_block.message.hash_tree_root();
        let attestations = signed_block.message.body.attestations.len();
        let timings = ImportTimings::starting_now();
        let (timings, outcome) = self
            .process_block(SignedBeaconBlock::Lean(signed_block.clone()), timings)
            .await;
        self.log_import_report(slot, block_root, attestations, &outcome, timings);
        if let Err(err) = outcome {
            error!(%slot, %validator_id, %err, "Failed to process built block");
            metrics::inc_block_building_failures();
            return;
        }

        metrics::inc_block_building_success();

        if let Some(ref p2p) = self.p2p {
            let _ = p2p
                .publish_block(signed_block)
                .inspect_err(|err| error!(%slot, %validator_id, %err, "Failed to publish block"));
        }

        info!(%slot, %validator_id, "Published block");
    }

    /// Run block import, emit the resulting chain events, and refresh
    /// metrics. Chain-generic: `signed_block`'s own variant selects which
    /// chain's import call runs.
    async fn process_block(
        &mut self,
        signed_block: SignedBeaconBlock,
        mut timings: ImportTimings,
    ) -> (ImportTimings, Result<ImportOutcome, ImportError>) {
        // Gate the `block` event on whether this root is actually new, so a
        // re-delivery does not announce the same block twice.
        //
        // Only lean's `store::on_block` returns early for an already-imported
        // block. Beacon's `fork_choice::on_block` does not: it goes from
        // cloning the parent state straight into `state_transition`, so a
        // known root would pay the whole import again. `process_or_pend_block`
        // is what keeps that from happening, by skipping a beacon block whose
        // post-state the store already holds before ever reaching here.
        let slot = signed_block.slot();
        let block_root = signed_block.message_hash_tree_root();
        let is_new = !self
            .store
            .has_state(&block_root)
            .expect("DB read should succeed");
        let pre_import = ChainEventSnapshot::capture(&self.store);

        let outcome = match signed_block {
            SignedBeaconBlock::Lean(lean_block) => {
                match store::on_block(&mut self.store, lean_block) {
                    Ok(store_timings) => {
                        timings.absorb_store(store_timings);
                        ImportOutcome::Imported
                    }
                    Err(err) => return (timings, Err(err.into())),
                }
            }
            // Already imported: skip the whole transition rather than redo
            // it. Lean's `store::on_block` makes exactly this `has_state`
            // check itself and returns `Ok` early; beacon's `on_block` has no
            // such guard, so without this a re-delivered block pays a full
            // state transition (two whole-state merkleizations) and a state
            // write to reach the same store it already produced. Range sync
            // and gossip overlap at the tip make that the common case, not a
            // rare one.
            _ if !is_new => ImportOutcome::Imported,
            beacon_block => {
                let config = self.store.config();
                // Cloned out before `fork_choice::on_block` below takes
                // `&mut self.store`: an owned `Arc` handle, rather than a
                // borrow through `self.store.committee_cache()`, is what lets
                // this call also pass `&mut self.store` in the same
                // expression, since the two would otherwise both borrow
                // `self.store` at once.
                let committees = self.store.committee_cache();
                // Extracted before `beacon_block` moves into `fork_choice::on_block`
                // below, which takes ownership of it.
                let (attestations, slashings) = fork_choice::block_operations(&beacon_block);

                // Gate on this node's own custody columns before `on_block`
                // ever runs `state_transition`: an unavailable block is not
                // worth transitioning. `None` holds rather than rejects,
                // since the columns may simply not have arrived yet; see
                // `data_availability_for`'s own documentation for why a
                // partial set must never reach `on_block` as evidence.
                //
                // Only inside the availability boundary, though: below it no
                // peer is obliged to answer for a column at all, so gating
                // there would hold a block against data the network has
                // legitimately forgotten. See `da_check_required_for_slot`.
                let current_slot = fork_choice::get_current_slot(&self.store, &config);
                let within_da_window =
                    da_check_required_for_slot(beacon_block.slot(), current_slot, &config);
                let evidence = if within_da_window {
                    timings.da_check_start = Some(Instant::now());
                    let evidence =
                        data_availability_for(&self.store, &beacon_block, &self.custody_columns);
                    timings.da_check_end = Some(Instant::now());
                    match evidence {
                        Some(evidence) => evidence,
                        None => {
                            timings.columns_wait_start =
                                timings.columns_wait_start.or(timings.da_check_end);
                            self.hold_block_for_columns(beacon_block, current_slot, timings);
                            return (timings, Ok(ImportOutcome::Held));
                        }
                    }
                } else {
                    fork_choice::DataAvailability::NotRequired
                };

                // The engine round trip sits here, between the
                // data-availability gate above and `fork_choice::on_block`
                // below. That order is the specification's:
                // `is_data_available` runs before `state_transition`, so a
                // block about to be held for its custody columns is never one
                // this node asks an execution client about.
                timings.engine_start = Some(Instant::now());
                let validity = match &self.engine {
                    None => fork_choice::PayloadValidity::NotRequired,
                    Some(client) => match beacon_engine::ask(client, &beacon_block).await {
                        Ok(None) => fork_choice::PayloadValidity::NotRequired,
                        Ok(Some(validity)) => validity,
                        // No answer after the whole ladder.
                        // `optimistic-sync.md`: a consensus engine MUST NOT
                        // import the block and MUST NOT apply it to the fork
                        // choice store. Returning `Held` leaves the block out
                        // of the store without marking it imported, so the
                        // cascade does not treat it as having produced a
                        // post-state.
                        Err(err) => {
                            warn!(
                                %slot,
                                block_root = %ShortRoot(&block_root.0),
                                %err,
                                "No verdict from the execution client; not importing"
                            );
                            metrics::inc_engine_no_verdict();
                            timings.engine_end = Some(Instant::now());
                            return (timings, Ok(ImportOutcome::Held));
                        }
                    },
                };
                timings.engine_end = Some(Instant::now());

                // An optimistic import is only permitted for a block that
                // qualifies. A block that does not, and got a NOT_VALIDATED
                // answer, is not imported at all.
                if matches!(validity, fork_choice::PayloadValidity::Optimistic) {
                    let current_slot = self.wall_clock_slot();
                    let parent_root = beacon_block.parent_root();
                    if !fork_choice::is_optimistic_candidate_block(
                        &self.store,
                        current_slot,
                        slot,
                        parent_root,
                        self.safe_slots_to_import_optimistically,
                    ) {
                        warn!(
                            %slot,
                            block_root = %ShortRoot(&block_root.0),
                            "Not importing: the execution client has not validated this \
                             block and it is not an optimistic candidate"
                        );
                        metrics::inc_engine_not_optimistic_candidate();
                        return (timings, Ok(ImportOutcome::Held));
                    }
                }

                // Drop any hand-off span left by an insert outside this call,
                // so the one taken below is this block's alone.
                let _ = self.store.take_state_handoff();
                timings.stf_start = Some(Instant::now());
                let imported = fork_choice::on_block(
                    &mut self.store,
                    beacon_block,
                    &config,
                    &evidence,
                    &validity,
                    &committees,
                );
                timings.stf_end = Some(Instant::now());
                (timings.writer_wait_start, timings.writer_wait_end) =
                    match self.store.take_state_handoff() {
                        Some((start, end)) => (Some(start), Some(end)),
                        None => (None, None),
                    };
                if let Err(err) = imported {
                    return (timings, Err(err.into()));
                }

                // The block is already in the store whatever the rest of this
                // arm does with its body, so nothing below may turn into an
                // `Err` that fails the import: that would make this function's
                // caller (`run_import_cascade`) stop the pending-block cascade,
                // leaving every held descendant stuck behind a block that in
                // fact did import.
                //
                // `get_state(&block_root)` is a direct hit rather than a
                // `fork_choice::block_state`-style lookup: `on_block` just
                // wrote this block's post-state under `block_root`, and the
                // committee source for a block's own attestations is that
                // post-state, not each attestation's target checkpoint state.
                // See `fork_choice::on_block_attestation`'s documentation for
                // why the two name the same committees, and for what asking
                // the checkpoint instead costs.
                timings.block_atts_start = Some(Instant::now());
                let block_state = self
                    .store
                    .get_state(&block_root)
                    .expect("DB read should succeed");
                match block_state {
                    Some(block_state) => {
                        // One `Table::LiveChain` scan for the whole body, not
                        // one per attestation: the table carries a row per
                        // block this node imported and is never pruned on
                        // beacon, so the scan is the expensive part and every
                        // attestation in the block asks the same question of
                        // it.
                        let index = self.store.block_index();
                        for attestation in &attestations {
                            let _ = fork_choice::on_block_attestation(
                                &mut self.store,
                                attestation,
                                &block_state,
                                &config,
                                &index,
                                &committees,
                            )
                            .inspect_err(|err| {
                                trace!(%slot, ?err, "Ignoring an unusable attestation from a block")
                            });
                        }
                    }
                    // A checkpoint-synced follower hits this legitimately for
                    // the first epochs after its anchor: an attestation may
                    // name a target up to `SLOTS_PER_EPOCH` slots back, and a
                    // target below the anchor was never fetched, so
                    // `validate_on_attestation`'s "target.root in store.blocks"
                    // check rejects it. Expected, not a defect, so this warns
                    // once and skips the body rather than failing the import.
                    None => {
                        warn!(
                            %slot,
                            block_root = %ShortRoot(&block_root.0),
                            "Skipping a block's attestations: its own post-state is unreachable"
                        );
                    }
                }
                for slashing in &slashings {
                    let _ = fork_choice::on_attester_slashing(&mut self.store, slashing)
                        .inspect_err(
                            |err| trace!(%slot, ?err, "Ignoring an unusable slashing from a block"),
                        );
                }
                timings.block_atts_end = Some(Instant::now());

                ImportOutcome::Imported
            }
        };

        // `block` goes out first so subscribers see it ahead of the
        // justified/head/finalized moves its import triggers.
        if is_new {
            self.events.emit(ChainEvent::Block {
                slot,
                block: block_root,
            });
        }
        // Block import has no ready-made "now" slot like `on_tick`'s, so
        // read the wall-clock slot fresh for the head-recency gate.
        pre_import.diff_and_emit(&self.store, &self.events, self.wall_clock_slot());

        // A genuine import is one of the two places (with `on_tick`) beacon
        // finality can move, and finality is the only thing that evicts a
        // held block nobody redelivers; see the method's own documentation.
        self.evict_held_blocks_at_or_below_finality();
        self.evict_sidecars_awaiting_parent_at_or_below_finality();

        self.refresh_chain_metrics();

        // Lean-only: a beacon follower tracks no validator keys of its own.
        if let ChainDuties::Lean(lean) = &self.duties {
            metrics::update_validators_count(lean.key_manager.validator_ids().len() as u64);
        }

        for table in ALL_TABLES {
            metrics::update_table_bytes(table.name(), self.store.estimate_table_bytes(table));
        }
        // Everything since the import call returned is bookkeeping it caused:
        // the events, the finality sweep and the gauge refresh. It is charged
        // to the section it follows rather than to sections of its own.
        timings.absorb_tail(Instant::now());
        (timings, Ok(outcome))
    }

    /// Build an unspawned server for offline replay.
    ///
    /// No mailbox, no tick loop, no p2p: the caller drives every import
    /// itself with [`Self::import_block`], on its own task. Every field is
    /// what `start_actor` would give it, with three deliberate differences:
    /// `p2p` is `None` (every use of it is guarded, so nothing here needs a
    /// stub), the custody set is empty (a corpus supplies every block, so
    /// there are no columns to wait on; see `data_availability_for`), and no
    /// first tick is armed.
    ///
    /// The store clock is not placed here. Fork choice rejects a block from
    /// the future, and a beacon store's clock starts at zero, so the caller
    /// sets it per block through its own `Store` clone: the clock is a row in
    /// the shared backend's metadata, not per-handle state.
    pub fn for_replay(
        store: Store,
        engine: Option<EngineClient>,
        safe_slots_to_import_optimistically: u64,
    ) -> Self {
        assert_eq!(
            store.chain(),
            Chain::Beacon,
            "BlockChainServer::for_replay requires a beacon store"
        );

        Self {
            store,
            p2p: None,
            pending_blocks: HashMap::new(),
            pending_block_parents: HashMap::new(),
            blocks_awaiting_columns: HashMap::new(),
            held_timings: HashMap::new(),
            sidecars_awaiting_parent: HashMap::new(),
            custody_columns: Vec::new(),
            engine,
            safe_slots_to_import_optimistically,
            last_tick_instant: None,
            sync_status: SyncStatusTracker::new(false),
            sync_status_controller: SyncStatusController::default(),
            events: EventBus::default(),
            duties: ChainDuties::Beacon,
            beacon_aggregates: Default::default(),
        }
    }

    /// Import one block on the caller's task.
    ///
    /// [`ImportOutcome::Imported`] means a post-state now exists under the
    /// block's root; `Held` means none does; `None` means the block was
    /// rejected. That return value is the completion signal, so no caller
    /// needs to subscribe to the event bus and time out.
    ///
    /// Timed with [`ImportTimings::starting_now`], which is what that
    /// constructor documents for a block entering from storage rather than
    /// the wire, and tagged [`BlockSource::Replay`]. The tag is what gets the
    /// sections published at all (a sourceless import publishes nothing, and
    /// the replay harness reads its phases back from the histogram), and it
    /// keeps them under a label of their own: a replayed block crossed no
    /// wire, so its zero decode section folded into `gossip` or `sync` would
    /// understate either one.
    pub async fn import_block(&mut self, block: SignedBeaconBlock) -> Option<ImportOutcome> {
        let timings = ImportTimings {
            source: Some(BlockSource::Replay),
            ..ImportTimings::starting_now()
        };
        self.on_block(block, timings).await
    }

    /// Process a newly received block, whichever chain it belongs to.
    ///
    /// For beacon this is also where fork choice is re-run and the two clock
    /// gauges are republished, because an import records no head of its own
    /// (see [`Self::recompute_beacon_head`]) and the tick that used to be the
    /// sole writer of both is starved by the very imports whose progress they
    /// are meant to report. Once per arrival rather than once per block in the
    /// cascade, matching what `Handler<NewBlock>` already does with the store
    /// clock: a cascade's blocks are all processed at one instant.
    ///
    /// Returns what became of `signed_block` itself, for the one caller that
    /// has to know: see [`Self::release_block_if_columns_complete`]. `None`
    /// means it never reached [`Self::process_block`], so some other structure
    /// is now responsible for it (a pending-parent entry, a fresh column hold)
    /// or it was deliberately discarded.
    async fn on_block(
        &mut self,
        signed_block: SignedBeaconBlock,
        timings: ImportTimings,
    ) -> Option<ImportOutcome> {
        let mut cascade = CascadeTimings {
            source: timings.source,
            ..CascadeTimings::starting_now()
        };
        let mut queue = VecDeque::new();
        queue.push_back((signed_block, timings));
        let (outcome, blocks) = self.run_import_cascade(queue, &mut cascade).await;

        if self.store.chain() == Chain::Beacon {
            // `lean_current_slot` had the same single writer the head did, so
            // both gauges went stale together on a catching-up follower and
            // `lean_current_slot - lean_head_slot` was a difference between
            // two stale numbers rather than the head lag every panel and
            // alert reads it as. Published from the wall clock rather than
            // the store clock, which only `on_tick` and an early arrival
            // advance.
            metrics::update_current_slot(self.wall_clock_slot());
            let head = self.recompute_beacon_head().await;
            cascade.absorb_head(head);
        }

        cascade.observe(blocks);
        cascade.log(blocks);
        outcome
    }

    /// Drain `queue`, importing each block and enqueuing any pending children
    /// its import unblocks, iteratively rather than recursively so a long
    /// chain of arrivals cannot overflow the stack.
    ///
    /// Reports on the block the cascade was handed, and only that one: a
    /// caller re-delivering a block asks about that block, while the children
    /// its import unblocks are the cascade's own business and each have their
    /// own tracking already. The count beside it is every block the cascade
    /// imported, which is what the timing tree reports.
    async fn run_import_cascade(
        &mut self,
        mut queue: VecDeque<(SignedBeaconBlock, ImportTimings)>,
        cascade: &mut CascadeTimings,
    ) -> (Option<ImportOutcome>, usize) {
        let mut first = None;
        let mut is_first = true;
        let mut blocks = 0;
        while let Some((block, mut timings)) = queue.pop_front() {
            // A block released by its parent's import waited here, behind
            // whatever siblings were ahead of it in the same cascade.
            if timings.cascade_wait_start.is_some() {
                timings.cascade_wait_end = Some(Instant::now());
            }
            blocks += 1;
            let outcome = self.process_or_pend_block(block, timings, &mut queue).await;
            if is_first {
                first = outcome;
                is_first = false;
            }
        }
        cascade.cascade_end = Some(Instant::now());

        // Prune old states and blocks AFTER the entire cascade completes.
        // Running this mid-cascade would delete states that pending children
        // still need, causing re-processing loops when fallback pruning is active.
        //
        // Lean-only: `prune_old_data` prunes `BlockProof`, a table beacon
        // never writes, and deciding whether there is anything to prune costs
        // a whole-block decode (`Store::get_block_header`) on a beacon
        // directory.
        if self.store.chain() == Chain::Lean {
            cascade.prune_start = Some(Instant::now());
            self.store
                .prune_old_data()
                .expect("DB pruning should succeed");
            cascade.prune_end = Some(Instant::now());
        }

        (first, blocks)
    }

    /// Re-deliver `block` to this actor once its own slot has started.
    ///
    /// Beacon's `on_block` requires a block's slot to already be in the past;
    /// the specification says an early block's consideration "must be delayed
    /// until they are in the past", not that the block should be dropped. A
    /// single dropped early block wedged a live follower permanently on
    /// 2026-09-03: every later block became an orphan of a root the node
    /// would never obtain.
    ///
    /// The block rides in the message rather than through the DB, so the hold
    /// costs one timer and leaves nothing behind to reconcile if this process
    /// stops before the slot arrives. [`MAXIMUM_GOSSIP_CLOCK_DISPARITY`] is
    /// what bounds how many such holds one peer can buy, and how long each
    /// one lasts.
    ///
    /// Re-delivery goes through `NewBlock`, the same message the p2p layer
    /// uses, tagged [`BlockSource::Deferred`] so that the arrival bookkeeping
    /// its handler does for a genuine arrival is skipped for a block that
    /// already arrived once.
    ///
    /// Beacon-only: lean absorbs an early block with a margin instead of a
    /// wait, since `store::on_block` admits any block up to a whole slot
    /// ahead. Beacon cannot copy the margin, as its own `on_block` carries
    /// the specification's assertion and the fork-choice fixture suite tests
    /// it.
    fn defer_early_block(
        &self,
        block: SignedBeaconBlock,
        timings: ImportTimings,
        ctx: &Context<Self>,
    ) {
        let delay = Duration::from_millis(self.ms_until_slot_start(block.slot()));
        let now = Instant::now();
        // The re-delivery carries the block's original arrival rather than a
        // fresh one, so the hold shows up as the `defer` row of one report
        // instead of vanishing between two.
        let redelivery = NewBlock {
            block,
            source: BlockSource::Deferred,
            arrival: BlockArrival {
                decode_start: timings.decode_start,
                // The original hand-off, so the first mailbox wait stays the
                // `queue` row and the hold becomes `defer` rather than more
                // queue.
                handed_off: timings.queue_start.unwrap_or(now),
                // The source travels with the hold so the re-delivery reports
                // under it rather than under `Deferred`.
                deferred_from: Some(DeferredFrom {
                    at: now,
                    source: timings.source.unwrap_or(BlockSource::Gossip),
                }),
            },
        };
        send_after(delay, ctx.clone(), redelivery);
    }

    /// Print one block's import tree.
    ///
    /// The single consumer of [`ImportTimings`], and therefore the only place
    /// any of them is subtracted from another. `outcome` is borrowed rather
    /// than taken because the caller still has to act on it.
    fn log_import_report(
        &self,
        slot: u64,
        block_root: H256,
        attestations: usize,
        outcome: &Result<ImportOutcome, ImportError>,
        timings: ImportTimings,
    ) {
        let report = BlockImportReport {
            slot,
            block_root,
            attestations,
            outcome: match outcome {
                Ok(ImportOutcome::Imported) => "imported",
                Ok(ImportOutcome::Held) => "held",
                Err(_) => "failed",
            },
            slot_offset_ms: Some(self.ms_into_slot(slot)),
            timings,
        };
        report.observe();
        report.log();
    }

    /// Milliseconds since `slot` started on the wall clock, negative while it
    /// has not.
    ///
    /// The deadline number: an import that finishes past the interval its
    /// chain expects attestations at was late whatever its sections say.
    fn ms_into_slot(&self, slot: u64) -> i64 {
        let time_config = self.store.config().time_grid();
        let slot_start_ms = time_config
            .genesis_time_ms()
            .saturating_add(SlotInterval::BlockPublication.to_ms_since_genesis(slot, &time_config));
        unix_now_ms() as i64 - slot_start_ms as i64
    }

    /// Milliseconds from now until `slot` starts on the wall clock, zero once
    /// it has.
    ///
    /// Goes through the `time_grid()` [`ChainConfig`], the same grid the tick
    /// cadence and `propose_block`'s own slot-start read use, so "the slot has
    /// started" means the same thing to a held block as it does to the tick
    /// that will import it.
    fn ms_until_slot_start(&self, slot: u64) -> u64 {
        let time_config = self.store.config().time_grid();
        let slot_start_ms = time_config
            .genesis_time_ms()
            .saturating_add(SlotInterval::BlockPublication.to_ms_since_genesis(slot, &time_config));
        slot_start_ms.saturating_sub(unix_now_ms())
    }

    /// The slot the wall clock is in right now.
    ///
    /// Distinct from the store clock, which advances only when something
    /// advances it (`on_tick`, or an arrival whose slot has already started),
    /// and from `on_tick`'s own `slot`, which is derived from the timestamp
    /// that tick was scheduled for. The block path has neither, so anything
    /// there that needs "now" reads it here.
    ///
    /// One grid for both chains: `slot_duration_ms` is authoritative on
    /// either, since `Config::lean` takes it from the network config file
    /// rather than leaving it a placeholder beside a compile-time constant.
    fn wall_clock_slot(&self) -> u64 {
        let time_config = self.store.config().time_grid();
        unix_now_ms().saturating_sub(time_config.genesis_time_ms())
            / time_config.milliseconds_per_slot
    }

    /// Re-run beacon fork choice and republish the head gauge.
    ///
    /// `fork_choice::on_block` does not compute a head, and `Store::beacon_head`
    /// only reads back whatever the last [`fork_choice::get_head`] recorded, so
    /// without this an import moves no head at all: it just adds a block and a
    /// post-state. Until the block path called this too, [`Self::on_tick`] was
    /// the only caller, and it is one message per slot in the same mailbox as
    /// every arriving block. A follower catching up imports back-to-back and
    /// never drains that mailbox, so the tick did not run, the head stayed
    /// pinned at the checkpoint-sync anchor, and `lean_head_slot` sat flat for
    /// the entire catch-up even while imports were landing every few seconds.
    /// That is what "the head is not advancing" looked like on the dashboard.
    ///
    /// A failure here means fork choice could not find a head (for instance
    /// every known block is unjustifiable), which is a condition to log and
    /// wait out, not a reason to crash a follower.
    async fn recompute_beacon_head(&mut self) -> HeadTimings {
        let mut timings = self.update_head_from_fork_choice();
        if let Some((start, end)) = self.notify_forkchoice_updated().await {
            timings.fcu_start = Some(start);
            timings.fcu_end = Some(end);
        }
        timings
    }

    /// Apply an aggregate `ethlambda-p2p`'s gossip validation already
    /// accepted, or hold it until its own slot has passed.
    ///
    /// The applied-bits gate runs first, before anything else: a valid
    /// aggregate whose votes are already covered is the common case on this
    /// topic, since a committee's sixteen aggregators mostly converge on the
    /// same bits, and dropping one here costs a hash and two lookups instead
    /// of another `apply_verified_aggregate` call.
    ///
    /// The hold is not an optimization. `validate_on_attestation` requires
    /// `get_current_slot(store) >= data.slot + 1`, and aggregates are
    /// published two thirds of the way through the slot they vote for, so
    /// every one of them arrives too early. Applying only what is already late
    /// would be applying almost nothing.
    fn on_gossip_beacon_aggregate(
        &mut self,
        aggregate: Box<SignedAggregateAndProof>,
        attesting_indices: Vec<ValidatorIndex>,
        arrival: AggregateArrival,
    ) {
        if let Some(dropped) = self.beacon_aggregates.already_covered(&aggregate) {
            metrics::inc_beacon_aggregate_outcome(dropped.label());
            return;
        }

        let config = self.store.config();
        let current_slot = fork_choice::get_current_slot(&self.store, &config);
        if current_slot < aggregate.slot().saturating_add(1) {
            if let Some(dropped) = self.beacon_aggregates.defer(aggregate, attesting_indices) {
                metrics::inc_beacon_aggregate_outcome(dropped.label());
            }
            metrics::update_beacon_aggregates_deferred(self.beacon_aggregates.deferred_len());
            return;
        }

        let index = self.store.block_index();
        self.apply_beacon_aggregate(&aggregate, &attesting_indices, &index, Some(arrival));
    }

    /// Apply one already-verified aggregate to fork choice and record what
    /// became of it.
    ///
    /// The applied-bits gate is written here, on success only: an aggregate
    /// [`fork_choice::apply_verified_aggregate`] refused (a target this node
    /// has since finalized past, say) must not be able to mark its bits
    /// covered, or a forged claim of coverage would suppress a later,
    /// applicable aggregate for the same committee.
    ///
    /// `index` is [`ethlambda_storage::Store::block_index`], taken as a
    /// parameter so [`Self::drain_deferred_aggregates`] builds it once for the
    /// whole drain rather than once per aggregate; see that function's own
    /// documentation.
    ///
    /// `arrival` is `Some` only on the path that applies an aggregate as it
    /// arrives. A drained one waits a deliberate slot for its own slot to
    /// pass, so reporting its end-to-end time would report that design as
    /// latency.
    fn apply_beacon_aggregate(
        &mut self,
        aggregate: &SignedAggregateAndProof,
        attesting_indices: &[ValidatorIndex],
        index: &HashMap<H256, (u64, H256)>,
        arrival: Option<AggregateArrival>,
    ) {
        let started = Instant::now();
        let config = self.store.config();
        let outcome = fork_choice::apply_verified_aggregate(
            &mut self.store,
            aggregate.data(),
            attesting_indices,
            &config,
            index,
        );
        metrics::observe_beacon_aggregate_processing(started.elapsed());
        if let Some(arrival) = arrival {
            metrics::observe_beacon_aggregate_end_to_end(arrival.decode_start.elapsed());
        }

        match outcome {
            Ok(()) => {
                self.beacon_aggregates.record(aggregate);
                metrics::inc_beacon_aggregate_outcome("applied");
            }
            // Expected in normal operation rather than a defect: a
            // checkpoint-synced follower sees aggregates naming targets below
            // its anchor, and any peer may send one for a block this node has
            // not imported yet.
            Err(err) => {
                trace!(
                    slot = aggregate.slot(),
                    aggregator = aggregate.aggregator_index(),
                    ?err,
                    "Ignoring an unusable gossip aggregate"
                );
                metrics::inc_beacon_aggregate_outcome("invalid");
            }
        }
    }

    /// Apply every held aggregate whose slot has now passed, and prune what
    /// the clock and finality have put out of reach.
    ///
    /// Called once per beacon tick, between the store clock advancing and the
    /// head being recomputed, so the votes released here are in fork choice
    /// before the head this tick reports is chosen.
    ///
    /// Builds [`ethlambda_storage::Store::block_index`] once for the whole
    /// drain: it is a full `Table::LiveChain` scan, and paying for it once per
    /// aggregate here would undo the reason `on_block`'s own attestations
    /// already share one. Skipped entirely when nothing is ready, since most
    /// beacon ticks find no deferred aggregate and a scan has nothing to serve.
    fn drain_deferred_aggregates(&mut self) {
        let config = self.store.config();
        let current_slot = fork_choice::get_current_slot(&self.store, &config);
        let current_epoch = fork_choice::get_current_store_epoch(&self.store, &config);

        let finalized_slot = self
            .store
            .latest_finalized()
            .expect("finalized checkpoint exists")
            .slot;
        self.beacon_aggregates.prune(current_epoch, finalized_slot);

        let ready = self.beacon_aggregates.take_ready(current_slot);
        if !ready.is_empty() {
            let index = self.store.block_index();
            for entry in ready {
                // Re-checked rather than trusted from when it was held: an
                // aggregate applied in the meantime may already cover this one, and
                // that is the whole point of the gate.
                if let Some(dropped) = self.beacon_aggregates.already_covered(&entry.aggregate) {
                    metrics::inc_beacon_aggregate_outcome(dropped.label());
                    continue;
                }
                self.apply_beacon_aggregate(
                    &entry.aggregate,
                    &entry.attesting_indices,
                    &index,
                    None,
                );
            }
        }

        metrics::update_beacon_aggregates_deferred(self.beacon_aggregates.deferred_len());
    }

    /// Re-run beacon fork choice, write the head it finds, and republish the
    /// gauge, without telling the execution client about it.
    ///
    /// The half of [`Self::recompute_beacon_head`] that touches only this
    /// node's own store. Split out because [`Self::apply_forkchoice_verdict`]
    /// runs *inside* `forkchoiceUpdated`'s own response handling and must not
    /// re-enter the call it is answering; the execution client hears about the
    /// new head on the next cascade or tick, the same cadence every other head
    /// move is announced on.
    ///
    /// A failure here means fork choice could not find a head (for instance
    /// every known block is unjustifiable), which is a condition to log and
    /// wait out, not a reason to crash a follower.
    fn update_head_from_fork_choice(&mut self) -> HeadTimings {
        let _timing = metrics::time_beacon_head_compute();
        let mut timings = HeadTimings {
            head_start: Some(Instant::now()),
            ..HeadTimings::default()
        };
        let config = self.store.config();
        if let Err(err) = fork_choice::get_head(&mut self.store, &config) {
            // An invalidated justified checkpoint reaches here:
            // `filter_block_tree` fails its `block_root in store.blocks` assert
            // once the justified root's row is gone. `optimistic-sync.md`
            // sanctions alerting and refusing rather than degrading, which is
            // what this does: the head simply does not move.
            warn!(%err, "Failed to compute beacon head");
            timings.head_end = Some(Instant::now());
            return timings;
        }
        timings.head_end = Some(Instant::now());
        if let Some((head_slot, _)) = self.store.beacon_head() {
            metrics::update_head_slot(head_slot);
        }
        self.pin_head_shufflings();
        timings
    }

    /// Point the committee cache's eviction at the head fork choice just
    /// recorded, so the shufflings that head's children will ask for are
    /// never the ones a full cache drops; see `CommitteeCache::update_head`.
    ///
    /// Reads the head's post-state from the store's state cache only, never
    /// reconstructing it: pinning only steers which entry a full cache evicts,
    /// and the head is almost always a block this node just imported, whose
    /// post-state `insert_state` left resident. A head whose state is no
    /// longer cached (a reorg back to an old block) keeps the previous head's
    /// pinning until a later head is resident, which at worst lets one of its
    /// shufflings be evicted and rebuilt, never serves a wrong committee.
    fn pin_head_shufflings(&mut self) {
        let Some((_, head_root)) = self.store.beacon_head() else {
            return;
        };
        let committees = self.store.committee_cache();
        if committees.head_root() == Some(head_root) {
            return;
        }
        if let Some(head_state) = self.store.cached_state(CacheKey::BlockState(head_root)) {
            committees.update_head(head_root, &head_state);
        }
    }

    /// Tell the execution client where the chain's head, safe and finalized
    /// blocks are.
    ///
    /// Sent once per cascade and once per tick, not once per block: the caller
    /// already runs after the cascade has drained. Sent even when nothing moved,
    /// because an execution client doing state sync needs to keep being fed a
    /// recent head or its sync cannot converge.
    ///
    /// The response carries a `PayloadStatusV1` of its own, which is the channel
    /// by which a block imported on `SYNCING` later becomes `VALID` or is found
    /// to be `INVALID`.
    async fn notify_forkchoice_updated(&mut self) -> Option<(Instant, Instant)> {
        let client = self.engine.clone()?;
        let (_head_slot, head_root) = self.store.beacon_head()?;

        let justified_root = self.store.beacon_justified_checkpoint().root;
        let finalized_root = self.store.beacon_finalized_checkpoint().root;

        // `H256::ZERO` explicitly rather than `unwrap_or_default()`: the zero
        // hash is a meaningful value here, not an absence. EIP-3675 requires
        // `finalized_block_hash` to be zero before a post-transition block is
        // finalized, and the specification's own
        // `get_safe_execution_block_hash` returns zero when no payload is
        // justified yet.
        let state = ForkchoiceStateV1 {
            head_block_hash: self
                .store
                .beacon_el_block_hash(head_root)
                .unwrap_or(H256::ZERO),
            safe_block_hash: self
                .store
                .beacon_el_block_hash(justified_root)
                .unwrap_or(H256::ZERO),
            finalized_block_hash: self
                .store
                .beacon_el_block_hash(finalized_root)
                .unwrap_or(H256::ZERO),
        };

        // Nothing to say yet: a follower whose head has no cached payload hash
        // is still on its checkpoint anchor.
        if state.head_block_hash.is_zero() {
            return None;
        }

        // `head_root` stays valid across the await: this is a single-threaded
        // actor, so no other message is handled until this one returns. An
        // `Invalidated` verdict leaves `KEY_HEAD` and `Table::BlockRoots`
        // naming roots whose `LiveChain` rows are gone, which is a stale store
        // and not merely a stale gauge: the req/resp handlers advertise the
        // head in `Status` and serve blocks out of `BlockRoots`. Which is why
        // `apply_forkchoice_verdict` recomputes the head itself rather than
        // leaving it to the next tick.
        let start = Instant::now();
        match client.forkchoice_updated(&state).await {
            Ok(status) => self.apply_forkchoice_verdict(head_root, &status),
            Err(err) => warn!(%err, "forkchoiceUpdated failed"),
        }
        Some((start, Instant::now()))
    }

    /// Apply a `forkchoiceUpdated` response to the optimistic bookkeeping.
    ///
    /// `VALID` clears the head and every optimistic ancestor; `INVALID` cuts the
    /// condemned branch out of fork choice. `SYNCING` and `ACCEPTED` say the
    /// execution client is still working and change nothing.
    fn apply_forkchoice_verdict(&mut self, head_root: H256, status: &EnginePayloadStatus) {
        match beacon_engine::verdict(status) {
            fork_choice::PayloadValidity::Validated => {
                fork_choice::mark_validated(&mut self.store, head_root);
            }
            fork_choice::PayloadValidity::Invalidated { latest_valid_hash } => {
                let index = self.store.block_index();
                let parent_root = index
                    .get(&head_root)
                    .map(|(_slot, parent)| *parent)
                    .unwrap_or(H256::ZERO);
                let condemned = fork_choice::resolve_invalid_block(
                    &self.store,
                    &index,
                    head_root,
                    parent_root,
                    latest_valid_hash,
                );
                // Unlike the `newPayload` path, `head_root` *is* in the index
                // here: this verdict is about a block already imported, which is
                // why an invalidation reached through `forkchoiceUpdated` can
                // remove the head itself rather than only its descendants.
                let removed = fork_choice::invalidate_subtree(&mut self.store, condemned);
                warn!(
                    condemned = %ShortRoot(&condemned.0),
                    removed,
                    "Execution client invalidated the head's branch"
                );

                // The rows are gone from fork choice, but `KEY_HEAD` and
                // `Table::BlockRoots` still name them, and the p2p req/resp
                // handlers read both: `Status` would advertise the
                // invalidated root, and `BlocksByRange`/`BlocksByRoot` would
                // serve the invalidated block to peers, until the next tick or
                // cascade recomputed the head. Do it here instead, so no peer
                // is handed a block this node has just refused.
                //
                // Head only, deliberately not `recompute_beacon_head`: this
                // runs inside `forkchoiceUpdated`'s own response handling, and
                // announcing the new head from here would re-enter the call
                // being answered.
                if removed > 0 {
                    self.update_head_from_fork_choice();
                }
            }
            fork_choice::PayloadValidity::Optimistic
            | fork_choice::PayloadValidity::NotRequired => {}
        }
    }

    /// Try to process a single block. If its parent state is missing, store it
    /// as pending. On success, collect any unblocked children into `queue` for
    /// the caller to process next (iteratively, avoiding deep recursion).
    ///
    /// `None` is every route that does not reach [`Self::process_block`]: a
    /// block discarded as final or early, one parked on a missing parent, or
    /// one whose import failed outright. What they have in common is that this
    /// block is either already tracked somewhere else or deliberately gone, so
    /// nothing upstream should put it back. `Some` is `process_block`'s own
    /// verdict, which is the only case that distinguishes "imported" from
    /// "dropped with nothing left holding it".
    async fn process_or_pend_block(
        &mut self,
        signed_block: SignedBeaconBlock,
        mut timings: ImportTimings,
        queue: &mut VecDeque<(SignedBeaconBlock, ImportTimings)>,
    ) -> Option<ImportOutcome> {
        let slot = signed_block.slot();
        let block_root = signed_block.message_hash_tree_root();
        let parent_root = signed_block.parent_root();
        let proposer = signed_block.proposer_index();
        timings.guards_start = Some(Instant::now());

        // Asked before the parent check, so that an absent `columns_wait` row
        // can be read two ways rather than one: the columns were never
        // missing, or they landed while this block was held for its parent.
        // Beacon-only, and only on the first pass, since a later pass would
        // answer for a different moment than the one the field names.
        if timings.da_complete_on_arrival.is_none() && !self.custody_columns.is_empty() {
            timings.da_complete_on_arrival = Some(custody_columns_present(
                &self.store,
                slot,
                &block_root,
                &self.custody_columns,
            ));
        }

        // Never process blocks at or below the finalized slot — they are
        // already part of the canonical chain and cannot affect fork choice.
        // Discard any pending children: since we won't process this block,
        // children referencing it as parent would remain stuck indefinitely.
        let latest_finalized_slot = self
            .store
            .latest_finalized()
            .expect("Error: Latest finalized checkpoint does not exist")
            .slot;
        if slot <= latest_finalized_slot {
            self.discard_pending_subtree(block_root);
            return None;
        }

        // Beacon: a block whose post-state is already here needs no work.
        // `fork_choice::on_block` does not short-circuit on a known root: it
        // goes straight from cloning the parent state to `state_transition`,
        // so a re-delivery pays the entire import a second time. On mainnet
        // 2026-09-08 that was 37 of 116 imports, a third of the actor's import
        // budget, spent recomputing post-states the store already held.
        // Children are still collected: this root did import, so anything
        // pending on it is ready whether or not this delivery is the one that
        // imported it. Beacon-only, because lean's `store::on_block` has its
        // own already-imported early return.
        if self.store.chain() == Chain::Beacon
            && self
                .store
                .has_state(&block_root)
                .expect("DB read should succeed")
        {
            debug!(
                %slot,
                block_root = %ShortRoot(&block_root.0),
                "Skipping a beacon block already in the store"
            );
            self.collect_pending_children(block_root, queue);
            return Some(ImportOutcome::Imported);
        }

        // Lean rejects a block for a slot that has not started outright,
        // mirroring the attestation time check in `validate_attestation_data`
        // with the same whole-slot-margin reasoning: a wider bound would let
        // an adversary pre-publish next-slot blocks ahead of any honest
        // proposer. Beacon holds one instead, and does it at arrival rather
        // than here (see `Handler<NewBlock>`), so nothing reaching this point
        // on that chain is still early.
        if self.store.chain() == Chain::Lean {
            let block_start_interval = slot.saturating_mul(INTERVALS_PER_SLOT);
            let store_time = self.store.intervals_since_genesis();
            if block_start_interval > store_time + GOSSIP_DISPARITY_INTERVALS {
                warn!(
                    %slot,
                    store_time,
                    proposer,
                    block_root = %ShortRoot(&block_root.0),
                    parent_root = %ShortRoot(&parent_root.0),
                    "Rejecting block: slot is too far in future"
                );
                self.discard_pending_subtree(block_root);
                return None;
            }
        }

        // Check if parent state exists before attempting to process
        if !self
            .store
            .has_state(&parent_root)
            .expect("DB read should succeed")
        {
            info!(%slot, %parent_root, %block_root, "Block parent missing, storing as pending");
            timings.guards_end = Some(Instant::now());
            timings.parent_wait_start = timings.parent_wait_start.or(timings.guards_end);
            self.held_timings.insert(block_root, timings);

            // Resolve the actual missing ancestor by walking the chain. A stale entry
            // can occur when a cached ancestor was itself received and became pending
            // with its own missing parent — the children still point to the old value.
            let mut missing_root = parent_root;
            while let Some(&ancestor) = self.pending_block_parents.get(&missing_root) {
                missing_root = ancestor;
            }

            self.pending_block_parents.insert(block_root, missing_root);

            // Persist block data to DB (no LiveChain entry — invisible to fork choice)
            self.store
                .insert_pending_block(block_root, signed_block)
                .expect("DB insert should succeed");

            // Store only the H256 reference in memory
            self.pending_blocks
                .entry(parent_root)
                .or_default()
                .insert(block_root);

            // Walk up through DB: if missing_root is already stored from a previous
            // session, the actual missing block is further up the chain.
            // Note: this loop always terminates — blocks reference parents by hash,
            // so a cycle would require a hash collision. `block_entry` reads just
            // the two fields this walk needs and decodes per chain, unlike
            // `get_block_header`, which is lean-only.
            while let Some((_, ancestor_parent_root)) = self.store.block_entry(&missing_root) {
                if self
                    .store
                    .has_state(&ancestor_parent_root)
                    .expect("DB read should succeed")
                {
                    // Held for its custody columns: its parent has a state
                    // because it already reached the availability gate, and
                    // re-importing it would only hold it again. Its release
                    // (`release_block_if_columns_complete`) is what imports it
                    // and cascades to this block through `pending_blocks`.
                    // Without this, every child of a held block re-ran its
                    // import: on a mainnet follower's first range batch after
                    // a checkpoint sync, the 68 blocks behind the first one
                    // re-held it 68 times over 54 s while its columns were
                    // already on their way.
                    if self.blocks_awaiting_columns.contains_key(&missing_root) {
                        return None;
                    }
                    // Parent state available — enqueue for processing, cascade
                    // handles the rest via the outer loop.
                    let fetched = self
                        .store
                        .get_signed_block(&missing_root)
                        .expect("header and parent state exist, so the full signed block must too")
                        .unwrap();
                    // A block taken back out of storage has no arrival to
                    // report, so its clock starts at the moment it was taken.
                    let mut fetched_timings =
                        self.held_timings.remove(&missing_root).unwrap_or_else(|| {
                            let mut fresh = ImportTimings::starting_now();
                            fresh.source = timings.source;
                            fresh
                        });
                    fetched_timings.parent_wait_end = Some(Instant::now());
                    queue.push_back((fetched, fetched_timings));
                    return None;
                }
                // Block exists but parent doesn't have state — register as pending
                // so the cascade works when the true ancestor arrives
                self.pending_blocks
                    .entry(ancestor_parent_root)
                    .or_default()
                    .insert(missing_root);
                self.pending_block_parents
                    .insert(missing_root, ancestor_parent_root);
                missing_root = ancestor_parent_root;
            }

            // Request the actual missing block from network
            self.request_missing_block(missing_root);
            return None;
        }

        // Parent exists, proceed with processing. Clone the block so we
        // can run post-import reaggregation against its merged proof —
        // `process_block` consumes the original for the storage layer.
        //
        // Only when that pass will actually run: a beacon block carries no
        // lean attestations to reaggregate, and a backfilling node discards
        // the result rather than spamming gossip with it, so cloning either
        // one would be a whole block body copied and dropped unread. Beacon
        // bodies carry an execution payload, which makes that the largest
        // single allocation on the import path.
        let block_for_reaggregate = match &signed_block {
            SignedBeaconBlock::Lean(lean_block) if self.sync_status.duties_allowed() => {
                Some(lean_block.clone())
            }
            _ => None,
        };
        timings.guards_end = Some(Instant::now());
        let attestations = match &signed_block {
            SignedBeaconBlock::Lean(lean) => lean.message.body.attestations.len(),
            _ => 0,
        };
        let (timings, outcome) = self.process_block(signed_block, timings).await;
        self.log_import_report(slot, block_root, attestations, &outcome, timings);
        match outcome {
            Ok(ImportOutcome::Imported) => {
                info!(
                    %slot,
                    proposer,
                    block_root = %ShortRoot(&block_root.0),
                    parent_root = %ShortRoot(&parent_root.0),
                    "Block imported successfully"
                );

                // Recover per-attestation single-message aggregates from the
                // block's merged multi-message aggregate and fold them into
                // the local pool. `Some` only for a lean block imported while
                // in sync, which is what selects this pass; see the clone
                // above.
                if let Some(ref lean_block) = block_for_reaggregate {
                    self.run_reaggregate_from_block(lean_block);
                }

                // Enqueue any pending blocks that were waiting for this parent
                self.collect_pending_children(block_root, queue);

                // This root now has a post-state, which is the one thing every
                // sidecar parked under it was waiting for.
                self.drain_sidecars_awaiting_parent(block_root);

                Some(ImportOutcome::Imported)
            }
            // A hold writes no post-state, so nothing pending on this root is
            // actually unblocked yet. Calling `collect_pending_children` here
            // regardless, as a bare `Ok(())` from `process_block` used to make
            // this arm do, re-queues children that can only pend again. It
            // was an infinite cycle, with no yield point, while a child's
            // ancestor walk (see the "Block parent missing" branch above)
            // still re-fetched and re-enqueued a held block: that walk now
            // stops at a block in `blocks_awaiting_columns`, but collecting
            // here would still be work for nothing.
            // `release_block_if_columns_complete` is what reaches
            // `collect_pending_children` for real, once this root actually
            // has a post-state to unblock anything with.
            Ok(ImportOutcome::Held) => {
                debug!(
                    %slot,
                    block_root = %ShortRoot(&block_root.0),
                    "Block held pending its custody columns; nothing pending on it is unblocked yet"
                );

                Some(ImportOutcome::Held)
            }
            Err(err) => {
                warn!(
                    %slot,
                    proposer,
                    block_root = %ShortRoot(&block_root.0),
                    parent_root = %ShortRoot(&parent_root.0),
                    %err,
                    "Failed to process block"
                );

                // Deliberately not `Held`: an import that failed on this
                // block's own contents fails the same way every time it is
                // retried, so re-driving it once a slot until finality evicts
                // it would buy a state transition per slot and nothing else.
                None
            }
        }
    }

    /// Run the post-import reaggregation pass and publish the resulting
    /// aggregates when this node is in the aggregator role. Lean-only: the
    /// caller only invokes this for a [`SignedBeaconBlock::Lean`] import.
    fn run_reaggregate_from_block(&mut self, signed_block: &SignedBlock) {
        let aggregates = reaggregate::reaggregate_from_block(&mut self.store, signed_block);
        if aggregates.is_empty() {
            return;
        }
        let count = aggregates.len();
        let is_aggregator = self.lean().aggregator.is_enabled();
        info!(
            count,
            is_aggregator, "Reaggregated block-borne attestations"
        );
        if !is_aggregator {
            return;
        }
        let Some(ref p2p) = self.p2p else {
            return;
        };
        for aggregate in aggregates {
            let _ = p2p
                .publish_aggregated_attestation(aggregate)
                .inspect_err(|err| warn!(%err, "Failed to publish reaggregated attestation"));
        }
    }

    /// Ask the network for a block this node is missing an ancestor of.
    ///
    /// Chain-agnostic, and deliberately so: the request carries a root and
    /// what is missing under it, and the p2p layer picks the protocol from the
    /// wire it already speaks, so neither this method nor the actor protocol
    /// grows a chain argument. Deduplication is the p2p layer's too, keyed on
    /// the root.
    fn request_missing_block(&mut self, block_root: H256) {
        if let Some(ref p2p) = self.p2p {
            let _ = p2p
                .fetch_block(FetchRequest {
                    block_root,
                    needs_block: true,
                    // Nothing to name: a block this node has never seen has
                    // told it nothing about what it committed to.
                    columns: Vec::new(),
                })
                .inspect(|_| info!(%block_root, "Requested missing block from network"))
                .inspect_err(
                    |err| error!(%block_root, %err, "Failed to send FetchBlock message to P2P"),
                );
        }
    }

    /// Ask the network for the custody columns of a block this node already has.
    ///
    /// The partner of [`Self::request_missing_block`], and the reason
    /// `needs_block` is a field of its own rather than "the column list is
    /// empty": the block is in this node's DB, so asking for it again would put
    /// a redundant by-root lookup on the wire behind every column request.
    fn request_missing_columns(&self, block_root: H256, missing: Vec<u64>) {
        if let Some(ref p2p) = self.p2p {
            let request = FetchRequest {
                block_root,
                needs_block: false,
                columns: missing,
            };
            let _ = p2p.fetch_block(request).inspect_err(
                |err| error!(%block_root, %err, "Failed to request a held block's missing data columns"),
            );
        }
    }

    /// Move pending children of `parent_root` into the work queue for iterative
    /// processing. This replaces the old recursive `process_pending_children`.
    fn collect_pending_children(
        &mut self,
        parent_root: H256,
        queue: &mut VecDeque<(SignedBeaconBlock, ImportTimings)>,
    ) {
        let Some(child_roots) = self.pending_blocks.remove(&parent_root) else {
            return;
        };

        info!(%parent_root, num_children=%child_roots.len(),
              "Processing pending blocks after parent arrival");

        for block_root in child_roots {
            // Clean up lineage tracking
            self.pending_block_parents.remove(&block_root);

            // Load block data from DB
            let Ok(Some(fetched)) = self.store.get_signed_block(&block_root) else {
                warn!(
                    block_root = %ShortRoot(&block_root.0),
                    "Pending block missing from DB, skipping"
                );
                continue;
            };

            let slot = fetched.slot();
            trace!(%parent_root, %slot, "Processing pending child block");

            // The parent's import is what ended this child's wait. Whatever
            // passes between here and the child being popped is the cascade's
            // own queueing, which is a separate row.
            let released = Instant::now();
            let mut timings = self
                .held_timings
                .remove(&block_root)
                .unwrap_or_else(ImportTimings::starting_now);
            timings.parent_wait_end = Some(released);
            timings.cascade_wait_start = Some(released);
            queue.push_back((fetched, timings));
        }
    }

    /// Keep `block` until every column this node custodies for it has arrived.
    ///
    /// The same shape as a block held for a missing parent: the block itself is
    /// already in the DB, so only its root is remembered here, and the map is
    /// cleared by the finality eviction the pending path already performs.
    /// There is no timer on the block. Neither das-core nor lighthouse puts one
    /// there: das-core leaves the timing question open, and lighthouse prunes
    /// its pending components at `max(finalized_epoch + 1, the availability
    /// boundary)` instead.
    ///
    /// Nothing is asked for here for a block still at or ahead of
    /// `current_slot`. A block's columns are published alongside it, so a
    /// block that reaches the gate short of them almost always has the rest
    /// in flight on gossip, and asking peers at this moment races that
    /// delivery: the peers asked usually do not have the columns yet either,
    /// so they answer empty and burn the lookup's attempts. Measured on
    /// mainnet followers at the tip, gossip completed a held block within
    /// 0.3 s at p99, and every stored column came from gossip. Each arriving
    /// column releases the block through
    /// [`Self::release_block_if_columns_complete`]; whatever is still missing
    /// at the next slot's [`Self::redrive_held_blocks`] is asked for there.
    ///
    /// A block older than `current_slot` gets no such courtesy: whatever
    /// gossiped it did so long before this node held it, so there is no
    /// delivery left in flight to race, and asking immediately is strictly
    /// better than waiting out a redrive. Range-synced catch-up is exactly
    /// this case, since every synced block is already older than the slot it
    /// arrives in; leaving it to the redrive cadence instead made a follower
    /// recovering from a checkpoint sync import roughly one such block per
    /// slot.
    fn hold_block_for_columns(
        &mut self,
        block: SignedBeaconBlock,
        current_slot: u64,
        timings: ImportTimings,
    ) {
        let slot = block.slot();
        let block_root = block.message_hash_tree_root();

        let present = self
            .store
            .data_column_indices_for(slot, &block_root)
            .expect("DB read should succeed");
        let missing: Vec<u64> = self
            .custody_columns
            .iter()
            .copied()
            .filter(|index| !present.contains(index))
            .collect();

        info!(
            %slot,
            block_root = %ShortRoot(&block_root.0),
            missing = ?missing,
            "Holding block: its custody columns have not all arrived yet"
        );

        // Written the same way a parent-missing block is (see
        // `process_or_pend_block`): no `LiveChain` entry, so it stays
        // invisible to fork choice until it is re-admitted, but readable back
        // by root once its columns land.
        self.store
            .insert_pending_block(block_root, block)
            .expect("DB insert should succeed");

        // See the doc comment above: an old block's columns are not still
        // arriving on gossip, so this is its first ask rather than the next
        // redrive's.
        if slot < current_slot {
            self.request_missing_columns(block_root, missing);
        }

        self.blocks_awaiting_columns.insert(block_root, slot);
        self.held_timings.insert(block_root, timings);
        metrics::set_blocks_held_for_columns(self.blocks_awaiting_columns.len() as u64);
    }

    /// Recursively discard a block and all its pending descendants.
    ///
    /// Used when a block is rejected (e.g., at/below finalized slot) to clean up
    /// children that would otherwise remain stuck in the pending maps indefinitely.
    fn discard_pending_subtree(&mut self, block_root: H256) {
        // A block held for its custody columns already had a known parent
        // when it was held (see `hold_block_for_columns`), so it carries no
        // entry of its own in `pending_blocks` and would not be reached by
        // the early return below. This has to run unconditionally, ahead of
        // that guard, so both of this function's callers reach it: a
        // redelivery of this exact root finding it at or below the finalized
        // slot (see `process_or_pend_block`), and the periodic sweep in
        // `evict_held_blocks_at_or_below_finality`, which calls this directly
        // on a root with no redelivery in sight.
        if self.blocks_awaiting_columns.remove(&block_root).is_some() {
            metrics::set_blocks_held_for_columns(self.blocks_awaiting_columns.len() as u64);
        }

        // Both eviction paths reach this function, so removing here is what
        // keeps `held_timings` from outliving the blocks it describes.
        self.held_timings.remove(&block_root);

        let Some(child_roots) = self.pending_blocks.remove(&block_root) else {
            return;
        };
        for child_root in child_roots {
            self.pending_block_parents.remove(&child_root);
            self.discard_pending_subtree(child_root);
        }
    }

    /// Drop every held block whose slot is now at or below the finalized
    /// slot, via [`Self::discard_pending_subtree`] so any pending children
    /// still waiting on one as their parent are cleaned up too, not just the
    /// hold itself.
    ///
    /// Needed because nothing else evicts a withheld hold. A block missing
    /// its parent needs a genuine gap in this node's own chain to end up
    /// pending; a block held for its columns needs only a claim, since
    /// nothing about a block's signature or contents is checked before the
    /// gate can hold it (`data_availability_for` runs on the bare
    /// `blob_kzg_commitments` field ahead of `fork_choice::on_block`'s own
    /// verification). A peer can therefore name any known, unfinalized parent,
    /// claim commitments, and simply never answer the resulting
    /// `FetchRequest`, pinning the claimed block in this node's memory
    /// and in its `BlockHeaders`/`BlockBodies` rows (written by
    /// `hold_block_for_columns`'s `insert_pending_block`) for as long as it
    /// likes, at no cost to itself. Calling this after every tick and every
    /// import — the two places beacon finality can move — bounds that by the
    /// unfinalized window rather than by this node's uptime.
    ///
    /// Also bounds the two beacon scratch caches with the same horizon, the
    /// execution-hash cache and the optimistic-root set, which is why the
    /// finalized slot is read before the "nothing is held" early return rather
    /// than after it: all three share a horizon and these two call sites, but
    /// the caches fill on every beacon import whether or not anything is being
    /// held for its columns.
    ///
    /// The held-block half is a no-op whenever nothing is held, which is always
    /// true on lean; the cache halves are no-ops there too, since only a beacon
    /// import ever writes either.
    fn evict_held_blocks_at_or_below_finality(&mut self) {
        let finalized = self
            .store
            .latest_finalized()
            .expect("finalized checkpoint exists");
        let finalized_slot = finalized.slot;

        // Bound the execution-hash cache to the unfinalized window, so it
        // cannot grow without limit on a long-running follower. Strictly
        // below, and the checkpoint root exempted by name, so the finalized
        // block's own hash survives for `forkchoiceUpdated`'s
        // `finalized_block_hash` even when the epoch boundary slot this
        // checkpoint is stored as was itself skipped.
        self.store
            .prune_beacon_el_block_hashes(finalized_slot, finalized.root);

        // Same horizon, same reason. An execution client doing a long state
        // sync answers `NOT_VALIDATED` to every block, so the optimistic set
        // takes one root per import and neither `mark_validated` nor
        // `invalidate_subtree` ever comes for them.
        self.store.prune_beacon_optimistic_roots(finalized_slot);

        if self.blocks_awaiting_columns.is_empty() {
            return;
        }
        let stale: Vec<H256> = self
            .blocks_awaiting_columns
            .iter()
            .filter(|&(_, &slot)| slot <= finalized_slot)
            .map(|(&root, _)| root)
            .collect();
        if stale.is_empty() {
            return;
        }
        info!(
            finalized_slot,
            count = stale.len(),
            "Evicting held blocks that finality has superseded"
        );
        for root in stale {
            self.discard_pending_subtree(root);
        }
    }

    /// Lean-only.
    fn on_gossip_attestation(&mut self, attestation: &SignedAttestation) {
        // Read fresh here too: a gossip event can arrive between ticks, and
        // if the admin API just toggled, the first gossip after the toggle
        // should already use the new value.
        let is_aggregator = self.lean().aggregator.is_enabled();
        let accepted = store::on_gossip_attestation(&mut self.store, attestation, is_aggregator)
            .inspect_err(|err| warn!(%err, "Failed to process gossiped attestation"))
            .is_ok();

        // Surface only votes that passed data validation and signature
        // verification, so subscribers see the same attestations fork choice
        // does. The ~3 KB XMSS signature is not carried. `emit`'s own guard
        // drops the event on a node with no subscribers.
        if accepted {
            self.events.emit(ChainEvent::Attestation {
                validator_id: attestation.validator_id,
                data: attestation.data.clone(),
            });
        }
    }

    fn on_gossip_aggregated_attestation(&mut self, attestation: SignedAggregatedAttestation) {
        // The store consumes the aggregate, so snapshot the event inputs first.
        // Aggregates are low-rate (~one per subnet per slot), so building these
        // unconditionally is cheap; `emit`'s own guard drops them on an
        // unsubscribed node. The SNARK proof bytes are not carried.
        let participants: Vec<u64> = attestation.proof.participant_indices().collect();
        let data = attestation.data.clone();
        let accepted = store::on_gossip_aggregated_attestation(&mut self.store, attestation)
            .inspect_err(|err| warn!(%err, "Failed to process gossiped aggregated attestation"))
            .is_ok();

        // Emit only for aggregates the store accepted, mirroring `attestation`.
        if accepted {
            self.events
                .emit(ChainEvent::Aggregate { participants, data });
        }
    }

    /// Keep sidecars the p2p layer has already checked.
    ///
    /// Nothing here judges them. Every rule ran in the p2p layer, off this
    /// actor's single thread: gossip validation for a sidecar gossip
    /// accepted, and the chain checks
    /// (`ethlambda_state_transition::beacon::gossip::column::chain_checks`)
    /// for any other. Those cost a KZG batch and a BLS verification per
    /// sidecar, which on this thread delayed every block import behind them.
    ///
    /// Debug builds run the chain checks once more, so a p2p path that
    /// forwards a sidecar it never checked fails a test instead of reaching
    /// the store. A sidecar that has become a duplicate or fallen below
    /// finality since it was checked (an `Ignore`) is not a disagreement: the
    /// verdict was right when it was given.
    ///
    /// Beacon-only: a lean node subscribes to no column subnet, so nothing
    /// ever delivers this message there.
    async fn on_checked_data_columns(&mut self, sidecars: Vec<fulu::DataColumnSidecar>) {
        for sidecar in sidecars {
            #[cfg(debug_assertions)]
            {
                use ethlambda_state_transition::beacon::gossip::{
                    Outcome,
                    column::{ChainVerdict, chain_checks},
                };
                let verdict = chain_checks(&self.store, &sidecar, unix_now_ms());
                assert!(
                    matches!(
                        verdict,
                        ChainVerdict::Keep | ChainVerdict::Drop(Outcome::Ignore(_))
                    ),
                    "the p2p layer sent a data column sidecar the chain checks refuse: {verdict:?}"
                );
            }
            self.keep_data_column(sidecar).await;
        }
    }

    /// Store a checked sidecar and release the held block it may complete.
    async fn keep_data_column(&mut self, sidecar: fulu::DataColumnSidecar) {
        let header = &sidecar.signed_block_header.message;
        let slot = header.slot;
        let block_root = header.hash_tree_root();

        // Two copies of one column can pass the checks at once (from gossip
        // and from a fetch, say). The second write would store the same row
        // and count it, and re-check the held block, for nothing.
        let stored = self
            .store
            .data_column_indices_for(slot, &block_root)
            .expect("DB read should succeed");
        if stored.contains(&sidecar.index) {
            return;
        }

        if let Err(err) =
            self.store
                .put_data_column_sidecar(slot, &block_root, sidecar.index, sidecar.to_ssz())
        {
            error!(%err, "Failed to store a data column sidecar");
            return;
        }
        metrics::inc_data_column_stored();

        // A held block may now be complete.
        self.release_block_if_columns_complete(block_root).await;
    }

    /// Park sidecars the chain checks found no parent post-state for, or send
    /// them straight back to be checked if the parent has one by now.
    ///
    /// The second case is a race this actor has to close, because the checks
    /// run elsewhere: the p2p layer looked for the parent's post-state, found
    /// none and sent these, and if the parent imported in between, its
    /// [`Self::drain_sidecars_awaiting_parent`] has already run and will not
    /// run again, so a sidecar parked now would wait for nothing until
    /// finality evicts it. Asked with the same `get_state` the checks use, so
    /// a sidecar sent back is one they will find a parent state for.
    fn park_data_columns(&mut self, sidecars: Vec<fulu::DataColumnSidecar>) {
        let mut ready = Vec::new();
        for sidecar in sidecars {
            let parent_root = sidecar.signed_block_header.message.parent_root;
            if matches!(self.store.get_state(&parent_root), Ok(Some(_))) {
                ready.push(sidecar);
                continue;
            }
            let block_root = sidecar.signed_block_header.message.hash_tree_root();
            self.queue_sidecar_awaiting_parent(block_root, sidecar);
        }
        self.send_data_columns_for_checks(ready);
    }

    /// Hand sidecars to the p2p layer's chain checks, which send back the
    /// ones that pass through `new_data_column_sidecars`.
    fn send_data_columns_for_checks(&self, sidecars: Vec<fulu::DataColumnSidecar>) {
        if sidecars.is_empty() {
            return;
        }
        let Some(ref p2p) = self.p2p else {
            return;
        };
        let _ = p2p.check_data_column_sidecars(sidecars).inspect_err(
            |err| error!(%err, "Failed to send data column sidecars to the p2p layer for checks"),
        );
    }

    /// Park `sidecar` against the parent root it could not be checked against.
    ///
    /// Counted as `queued_for_parent` rather than as a rejection: nothing about
    /// the sidecar has been judged yet, and conflating the two is what made the
    /// deadlock invisible in the metrics (every column read as
    /// `rejected{reason="unknown_parent"}` while the real fault was upstream).
    ///
    /// Nothing is refused here. The queue used to hold whole sidecars and so
    /// carried a count cap, which a follower behind the tip hit constantly:
    /// it receives gossip for the tip continuously, so the queue filled with
    /// sidecars for blocks it would not reach for minutes and then refused
    /// the ones for the block it was about to import. Measured on the eth-4
    /// follower a hundred slots behind, the queue sat pinned at its cap and
    /// dropped 2,561 sidecars in ten minutes while the chain ground through
    /// by-root lookups for slots whose columns gossip had already delivered
    /// and this function had thrown away. Evicting the furthest-ahead entry
    /// instead of the newest fixed which sidecar was lost, not that one was.
    ///
    /// The cap is gone now that the sidecars live in
    /// `Table::PendingDataColumns` and only their keys are held here, so what
    /// grows is disk rather than this actor's memory.
    /// [`Self::evict_sidecars_awaiting_parent_at_or_below_finality`] is what
    /// bounds it, which bounds how *long* an entry lives but not how fast
    /// they arrive: the chain checks do not require `parent_root` to name a
    /// block this node knows. Every sidecar reaching here, gossiped or
    /// fetched, has had its header's signature checked against the head state
    /// by those checks (`queue_unless_forged`, in
    /// `ethlambda_state_transition::beacon::gossip::column`), but only when a
    /// head state is already cached *and* the header's `proposer_index` names
    /// a validator in it: with no cached head state, or a proposer index that
    /// names none (`u64::MAX`, say), that check is skipped and a made-up
    /// header still reaches here and parks a row. A peer exploiting either
    /// gap can still park rows as fast as it can invent a slot, proposer and
    /// index, until finality catches up.
    fn queue_sidecar_awaiting_parent(
        &mut self,
        block_root: H256,
        sidecar: fulu::DataColumnSidecar,
    ) {
        let header = &sidecar.signed_block_header.message;
        let parent_root = header.parent_root;
        let parked = ParkedColumn {
            slot: header.slot,
            block_root,
            index: sidecar.index,
        };

        // A re-delivery of something already parked. The by-root and by-range
        // fetch paths skip gossip's seen cache entirely, so they never touch
        // the p2p actor's `SeenColumns` (which in any case only records an
        // Accept, never a park); a re-delivery reaching here is ordinary, and
        // without this check the same column would take a second slot in the
        // queue and leave a stale key behind after the first replay took its
        // row. Asked before the write rather than left to the set below,
        // because the write is what costs.
        if self
            .sidecars_awaiting_parent
            .get(&parent_root)
            .is_some_and(|parked_columns| parked_columns.contains(&parked))
        {
            return;
        }

        // The bytes go to disk before the key goes in the map, so a failed
        // write leaves no key pointing at a row that is not there.
        if let Err(err) = self.store.put_pending_data_column_sidecar(
            parked.slot,
            &parked.block_root,
            parked.index,
            sidecar.to_ssz(),
        ) {
            error!(%err, "Failed to park a data column sidecar");
            return;
        }

        trace!(
            slot = parked.slot,
            column = parked.index,
            parent_root = %ShortRoot(&parent_root.0),
            "Queueing a data column sidecar until its parent has a post-state"
        );
        self.sidecars_awaiting_parent
            .entry(parent_root)
            .or_default()
            .insert(parked);
        self.publish_sidecars_awaiting_parent();
    }

    /// Republish how many sidecars are parked, from the map that decides it.
    fn publish_sidecars_awaiting_parent(&self) {
        let total: usize = self
            .sidecars_awaiting_parent
            .values()
            .map(HashSet::len)
            .sum();
        metrics::set_sidecars_awaiting_parent(total as u64);
    }

    /// Send every sidecar parked against `block_root` back to the p2p layer's
    /// chain checks, now that it has a post-state to be checked against.
    ///
    /// Called from the one arm that means "this root now has a post-state".
    /// The ones that pass come back through `new_data_column_sidecars` as a
    /// new message, so nothing here re-enters the import path.
    fn drain_sidecars_awaiting_parent(&mut self, block_root: H256) {
        let Some(parked_columns) = self.sidecars_awaiting_parent.remove(&block_root) else {
            return;
        };
        debug!(
            parent_root = %ShortRoot(&block_root.0),
            count = parked_columns.len(),
            "Replaying data column sidecars whose parent just imported"
        );
        self.publish_sidecars_awaiting_parent();

        let mut sidecars = Vec::with_capacity(parked_columns.len());
        for parked in parked_columns {
            // Taken, not read: the row has served its purpose either way. A
            // replay that passes is written to `DataColumns`, and one that
            // fails a check has been judged, so neither leaves anything worth
            // keeping here.
            let encoded = match self.store.take_pending_data_column_sidecar(
                parked.slot,
                &parked.block_root,
                parked.index,
            ) {
                Ok(Some(encoded)) => encoded,
                Ok(None) => {
                    error!(
                        slot = parked.slot,
                        column = parked.index,
                        block_root = %ShortRoot(&parked.block_root.0),
                        "A parked data column sidecar has no row to replay from"
                    );
                    continue;
                }
                Err(err) => {
                    error!(%err, "Failed to read back a parked data column sidecar");
                    continue;
                }
            };
            let Ok(sidecar) = fulu::DataColumnSidecar::from_ssz_bytes(&encoded) else {
                error!(
                    slot = parked.slot,
                    column = parked.index,
                    "A parked data column sidecar did not decode"
                );
                continue;
            };
            sidecars.push(sidecar);
        }
        self.send_data_columns_for_checks(sidecars);
    }

    /// Drop parked sidecars whose block finality has superseded.
    ///
    /// The counterpart of [`Self::evict_held_blocks_at_or_below_finality`] and
    /// run beside it, for the same reason: a parent root that never arrives
    /// would otherwise pin its children's sidecars for this node's whole
    /// uptime. A sidecar at or below the finalized slot can never be needed
    /// again, since the chain checks would drop it outright now.
    fn evict_sidecars_awaiting_parent_at_or_below_finality(&mut self) {
        if self.sidecars_awaiting_parent.is_empty() {
            return;
        }
        let finalized_slot = self
            .store
            .latest_finalized()
            .expect("finalized checkpoint exists")
            .slot;

        let mut dropped: Vec<ParkedColumn> = Vec::new();
        self.sidecars_awaiting_parent.retain(|_, parked_columns| {
            parked_columns.retain(|parked| {
                let keep = parked.slot > finalized_slot;
                if !keep {
                    dropped.push(*parked);
                }
                keep
            });
            !parked_columns.is_empty()
        });

        if !dropped.is_empty() {
            info!(
                finalized_slot,
                count = dropped.len(),
                "Evicting parked data column sidecars that finality has superseded"
            );
            // The rows go with the keys, so a key dropped from the map never
            // leaves its bytes on disk with nothing left to read them.
            let keys = dropped
                .iter()
                .map(|parked| (parked.slot, parked.block_root, parked.index));
            let _ = self
                .store
                .delete_pending_data_column_sidecars(keys)
                .inspect_err(|err| error!(%err, "Failed to drop parked data column sidecars"));
            self.publish_sidecars_awaiting_parent();
        }
    }

    /// Once a slot, revisit every held block: release the ones whose columns
    /// have quietly completed, and ask for whatever the rest are still
    /// missing.
    ///
    /// The only repeat asker. [`Self::hold_block_for_columns`] already asks
    /// once, immediately, for a block old enough that gossip has nothing left
    /// to deliver; a block still at or ahead of the current slot when held
    /// gets no such ask and is left to gossip instead, so its first ask is
    /// the first tick after it was held, by which time a column still
    /// missing is unlikely to be on its way. Either way, every tick from here
    /// on asks again, which is what a lookup that fails needs: the only
    /// other thing that revisits a hold is a sidecar for that exact block
    /// arriving. A block whose missing columns no connected peer custodies
    /// gets neither: every peer answers `DataColumnsByRoot` with an empty
    /// list, the lookup spends its retry ladder against the peer set in a few
    /// seconds, and without this the hold would be left with nothing that
    /// will ever disturb it again while the chain stops behind it.
    ///
    /// Seen following mainnet with the gate on: every connected peer
    /// advertised the minimum `custody_group_count`, so a dozen peers between
    /// them custodied a small fraction of the columns, and two of the eight
    /// this node samples were not among them. Peers churn constantly, and one
    /// that connects a minute later may custody exactly the column that was
    /// missing, so an ask that fails now is worth repeating. A slot is the
    /// cadence blocks arrive at, and the held set is normally empty and
    /// bounded by finality when it is not, so repeating it costs one store
    /// read per held block per slot.
    ///
    /// A no-op whenever nothing is held, which is always true on lean.
    async fn redrive_held_blocks(&mut self) {
        if self.blocks_awaiting_columns.is_empty() {
            return;
        }

        // Collected up front: releasing re-enters the import path, which
        // mutates the very map this would otherwise be iterating.
        let held: Vec<(H256, u64)> = self
            .blocks_awaiting_columns
            .iter()
            .map(|(&block_root, &slot)| (block_root, slot))
            .collect();

        for (block_root, slot) in held {
            let present = self
                .store
                .data_column_indices_for(slot, &block_root)
                .expect("DB read should succeed");
            let missing: Vec<u64> = self
                .custody_columns
                .iter()
                .copied()
                .filter(|index| !present.contains(index))
                .collect();

            // Complete and still held: whatever completed it did not reach
            // `release_block_if_columns_complete`. Release it here rather than
            // leave a block waiting on columns this node already has.
            if missing.is_empty() {
                self.release_block_if_columns_complete(block_root).await;
                continue;
            }

            self.request_missing_columns(block_root, missing);
        }
    }

    /// Re-import a held block once its last missing column lands.
    async fn release_block_if_columns_complete(&mut self, block_root: H256) {
        let Some(&slot) = self.blocks_awaiting_columns.get(&block_root) else {
            return;
        };

        // Cheap presence check before paying for a DB read and decode of the
        // whole block: most sidecar arrivals are not the last column of a
        // held block, and this is the same check `data_availability_for`'s
        // fulu arm makes.
        if !custody_columns_present(&self.store, slot, &block_root, &self.custody_columns) {
            return;
        }

        self.blocks_awaiting_columns.remove(&block_root);
        let mut timings = self
            .held_timings
            .remove(&block_root)
            .unwrap_or_else(ImportTimings::starting_now);
        timings.columns_wait_end = Some(Instant::now());
        metrics::set_blocks_held_for_columns(self.blocks_awaiting_columns.len() as u64);

        let Ok(Some(block)) = self.store.get_signed_block(&block_root) else {
            error!(
                block_root = %ShortRoot(&block_root.0),
                "A held block vanished from the store before its columns completed"
            );
            return;
        };

        info!(
            %slot,
            block_root = %ShortRoot(&block_root.0),
            "Held block's custody columns are complete; re-importing"
        );
        // The same path a new block takes (`Handler<NewBlock>` ends with this
        // same call): iterative, not recursive, so a released block's own
        // pending children still cascade through `run_import_cascade`'s loop
        // rather than growing the stack.
        //
        let outcome = self.on_block(block, timings).await;

        // The re-import can fail for a reason that has nothing to do with
        // columns: no verdict from the execution client, or a `NOT_VALIDATED`
        // verdict on a block that is not yet an optimistic candidate. Both
        // record nothing, so without this the hold removed above is simply
        // gone, and with it every route back to the block:
        // `redrive_held_blocks` and `evict_held_blocks_at_or_below_finality`
        // would both stop seeing it, and it and all its descendants would wait
        // for a restart. Both reasons resolve on their own: the execution
        // client comes back, and the horizon passes, so the block belongs back
        // in the held set where the per-slot redrive can try it again.
        //
        // Safe to re-insert here rather than racing the cycle: the hold came
        // off before the call, so the re-entry this edge allows has already
        // unwound by the time this line runs. It cannot re-drive the edge, it
        // only puts the block back where the redrive and the finality eviction
        // can still find it. A `process_block` that re-held the block for its
        // columns has already inserted the same entry, and writing it twice
        // costs nothing.
        if outcome == Some(ImportOutcome::Held) {
            self.blocks_awaiting_columns.insert(block_root, slot);
            metrics::set_blocks_held_for_columns(self.blocks_awaiting_columns.len() as u64);
            debug!(
                %slot,
                block_root = %ShortRoot(&block_root.0),
                "Re-import produced no post-state; the block stays held for the next redrive"
            );
        }
    }

    /// Refresh the sync-status tracker and its two outputs (the
    /// `lean_node_sync_status` metric and [`SyncStatusController`]).
    ///
    /// Reads the head through [`Self::head_slot`], which is where the
    /// per-chain part of that lives (lean's `Store::head_slot` and beacon's
    /// `Store::beacon_head` decode different tables); everything past that
    /// point is chain-agnostic.
    fn update_sync_status(&mut self, current_slot: u64) {
        let head_slot = self.head_slot();
        let max_seen_slot = self
            .store
            .max_live_chain_slot()
            .expect("max live chain slot exists")
            .unwrap_or(head_slot);
        let status = self
            .sync_status
            .update(current_slot, head_slot, max_seen_slot);
        metrics::set_node_sync_status(status);
        self.sync_status_controller.set(status);
    }

    /// Milliseconds until this actor's next tick, dispatched by chain: lean's
    /// interval grid via [`ms_until_next_interval`], beacon's once-per-slot
    /// cadence via [`ms_until_next_beacon_slot`].
    fn ms_until_next_tick(&self, now_ms: u64) -> u64 {
        let config = self.store.config();
        match &self.duties {
            ChainDuties::Lean(_) => ms_until_next_interval(now_ms, &config.time_grid()),
            ChainDuties::Beacon => {
                ms_until_next_beacon_slot(now_ms, config.genesis_time_ms(), config.slot_duration_ms)
            }
        }
    }

    /// Whether `slot` is close enough to the store clock for its arrival to be
    /// worth measuring.
    ///
    /// Arrival metrics are observed before `on_block` /
    /// `on_gossip_attestation` validate anything, so a gossip-supplied slot
    /// reaches them unchecked. Reuse the same future bound both validators
    /// reject on: past it the delta is not a timeliness measurement but an
    /// attacker-chosen number, and one fabricated far-future slot would
    /// dominate the histogram's sum and mislabel its `position` bucket for the
    /// lifetime of the process.
    fn is_arrival_observable(&self, slot: u64) -> bool {
        let slot_start_interval = slot.saturating_mul(INTERVALS_PER_SLOT);
        let store_time = self.store.intervals_since_genesis();
        slot_start_interval <= store_time + GOSSIP_DISPARITY_INTERVALS
    }
}

// Protocol trait for internal messages only (tick scheduling).
// Network-api messages are handled via manual Handler impls to allow
// Recipient<M> to work across actor boundaries.
#[protocol]
pub(crate) trait BlockChainProtocol: Send + Sync {
    #[allow(dead_code)] // invoked via send_after(Tick), not called directly
    fn tick(&self) -> Result<(), ActorError>;
}

#[actor(protocol = BlockChainProtocol)]
impl BlockChainServer {
    #[send_handler]
    async fn handle_tick(&mut self, _msg: block_chain_protocol::Tick, ctx: &Context<Self>) {
        // Observe the interval between tick-handler invocations here, at the
        // scheduler level, so a sample is taken for *every* tick — including the
        // ones `on_tick` drops via its idempotency guard. The main case is the
        // interval-0 tick after a proposer builds the next block one interval
        // early: the build advances the store clock to interval 0, so that tick
        // is skipped. Recording only inside `on_tick` (after the guard) would
        // miss it, so the following tick's sample would span two intervals and
        // show a false ~1.6s spike in `lean_tick_interval_duration_seconds` even
        // though ticks are firing on their ~800ms cadence.
        //
        // Ticks that fire early from wall-clock drift and are then guard-skipped
        // are also sampled here; that only adds occasional sub-interval samples,
        // which is acceptable for a metric meant to surface *late* ticks.
        if let Some(prev_instant) = self.last_tick_instant {
            metrics::observe_tick_interval_duration(prev_instant.elapsed());
        }
        self.last_tick_instant = Some(Instant::now());

        let now_ms = unix_now_ms();
        self.on_tick(now_ms, ctx).await;

        let remaining_at_entry = self.ms_until_next_tick(now_ms);
        let now_after_tick = unix_now_ms();
        let elapsed = now_after_tick.saturating_sub(now_ms);

        // If on_tick ran past the next interval boundary, tick again
        // immediately so that interval's duty still runs (issue #413).
        let ms_to_next_interval = if elapsed >= remaining_at_entry {
            0
        } else {
            // Schedule the next tick at the next interval boundary
            self.ms_until_next_tick(now_after_tick)
        };
        send_after(
            Duration::from_millis(ms_to_next_interval),
            ctx.clone(),
            block_chain_protocol::Tick,
        );
    }

    /// Actor lifecycle hook: wait for any in-flight aggregation worker to exit
    /// before the actor is fully stopped. We cancel the session's token and
    /// wait up to PRIOR_WORKER_JOIN_TIMEOUT for the worker's current
    /// `aggregate_job` call to finish (the proof itself cannot be interrupted).
    /// Lean-only: a beacon follower never starts an aggregation session.
    #[stopped]
    async fn on_stopped(&mut self, _ctx: &Context<Self>) {
        let ChainDuties::Lean(lean) = &mut self.duties else {
            return;
        };
        let Some(session) = lean.current_aggregation.take() else {
            return;
        };
        session.cancel.cancel();
        match tokio::time::timeout(PRIOR_WORKER_JOIN_TIMEOUT, session.worker).await {
            Ok(Ok(())) => {
                info!(
                    session_id = session.session_id,
                    "Aggregation worker joined on shutdown"
                );
            }
            Ok(Err(err)) => warn!(?err, "Aggregation worker task ended abnormally on shutdown"),
            Err(_) => warn!(
                timeout_secs = PRIOR_WORKER_JOIN_TIMEOUT.as_secs(),
                "Timed out joining aggregation worker on shutdown"
            ),
        }
    }
}

// --- Manual Handler impls for network-api messages ---

use ethlambda_network_api::p2p_to_block_chain::{
    DataColumnSidecarsAwaitingParent, NewAggregatedAttestation, NewAttestation, NewBeaconAggregate,
    NewBlock, NewDataColumnSidecars,
};

impl Handler<InitP2P> for BlockChainServer {
    async fn handle(&mut self, msg: InitP2P, _ctx: &Context<Self>) {
        self.p2p = Some(msg.p2p);
        info!("P2P protocol ref initialized");
    }
}

impl Handler<NewBlock> for BlockChainServer {
    async fn handle(&mut self, msg: NewBlock, ctx: &Context<Self>) {
        let arrival_ms = unix_now_ms();
        // The mailbox hop ends here. Everything before it happened in the p2p
        // actor and rode in on the message, because nothing on this side can
        // see how long the block waited to be picked up.
        let picked_up = Instant::now();
        // A re-delivery reports under the source the block first arrived on,
        // not under `Deferred`. `Deferred` describes this hop, and the hold it
        // names is already a section of the import; letting it stand as the
        // source would move a gossip block out of the gossip population for
        // every section it has left to cross.
        let deferred = msg.arrival.deferred_from;
        let mut timings = ImportTimings {
            source: Some(deferred.map_or(msg.source, |from| from.source)),
            // Gossip decodes the block itself and reports both ends; the
            // req/resp codec has already decoded by the time a handler sees a
            // block, so that path reports no decode at all rather than a zero.
            decode_start: msg.arrival.decode_start,
            decode_end: msg.arrival.decode_start.map(|_| msg.arrival.handed_off),
            queue_start: Some(msg.arrival.handed_off),
            // A re-delivered block waited in this mailbox twice. The first wait
            // is the queue; the second is part of the hold, and ends here.
            queue_end: Some(deferred.map_or(picked_up, |from| from.at)),
            defer_start: deferred.map(|from| from.at),
            defer_end: deferred.map(|_| picked_up),
            admit_start: Some(picked_up),
            ..ImportTimings::default()
        };
        // If message came from gossip, emit event and metric.
        if msg.source == BlockSource::Gossip {
            let slot = msg.block.slot();
            self.events.emit(ChainEvent::BlockGossip {
                slot,
                block: msg.block.message_hash_tree_root(),
            });
            if self.is_arrival_observable(slot) {
                metrics::observe_gossip_block_arrival(
                    arrival_ms,
                    &self.store.config().time_grid(),
                    slot,
                );
            }
        }

        // Beacon decides here, at arrival, what to do with a block whose
        // slot has not started: hold it if it is early only by clock
        // disparity, reject it otherwise. Arrival is the only place holding
        // it is still possible, since by the time the import cascade has the
        // block its caller is a loop with nowhere to put it back. See
        // `Self::defer_early_block`. Lean makes its own future-slot decision
        // inside that cascade, where rejecting is all it has to do.
        if self.store.chain() == Chain::Beacon {
            let slot = msg.block.slot();
            let ms_early = self.ms_until_slot_start(slot);
            if ms_early > 0 {
                let block_root = msg.block.message_hash_tree_root();
                if Duration::from_millis(ms_early) > MAXIMUM_GOSSIP_CLOCK_DISPARITY {
                    warn!(
                        %slot,
                        ms_early,
                        block_root = %ShortRoot(&block_root.0),
                        "Rejecting block: its slot starts further ahead than clock disparity allows"
                    );
                    self.discard_pending_subtree(block_root);
                    return;
                }
                info!(
                    %slot,
                    ms_early,
                    block_root = %ShortRoot(&block_root.0),
                    "Deferring block: its slot has not started yet"
                );
                self.defer_early_block(msg.block, timings, ctx);
                return;
            }
            // The slot has started on the wall clock. Make the store clock
            // agree before importing, since that is the clock `on_block`
            // asserts against and only the tick advances it: a tick still
            // owed for this slot (it is armed for the same instant a held
            // block is, and an import ahead of it can run long) would
            // otherwise turn a perfectly good block into a rejected one.
            // `on_tick` is idempotent through the store-clock guard in
            // `begin_tick`, and the comparison here keeps sync backfill, whose
            // blocks are never near the clock, from paying for the check at
            // all.
            let config = self.store.config();
            if fork_choice::get_current_slot(&self.store, &config) < slot {
                self.on_tick(unix_now_ms(), ctx).await;
            }
        }

        // The import path itself is common to every source and both chains.
        // Everything above ran on this block's behalf between the mailbox and
        // the import, the catch-up tick included, so it is its own section
        // rather than the head of the first pass's guards.
        timings.admit_end = Some(Instant::now());
        self.on_block(msg.block, timings).await;
    }
}

impl Handler<NewAttestation> for BlockChainServer {
    async fn handle(&mut self, msg: NewAttestation, ctx: &Context<Self>) {
        // Lean-only. A beacon node subscribes to no attestation subnet, so
        // nothing delivers this message there; fork choice learns its votes
        // from block bodies inside `on_block` instead. `current_slot` below is
        // lean-only regardless, since it reads the store clock in intervals.
        let ChainDuties::Lean(_) = &self.duties else {
            return;
        };
        let arrival_ms = unix_now_ms();
        let data_slot = msg.attestation.data.slot;
        if self.is_arrival_observable(data_slot) {
            metrics::observe_gossip_attestation_arrival(
                arrival_ms,
                &self.store.config().time_grid(),
                data_slot,
            );
        }
        self.on_gossip_attestation(&msg.attestation);
        // Early aggregation only advances the current slot's group counts, so a
        // late- or future-slot attestation can never cross the threshold; skip
        // the check unless this attestation is for the store's current slot.
        // From the interval clock, the one the tick pipeline drives: this
        // gates on the slot the store has actually ticked into, not on the one
        // the wall clock has reached.
        let current_slot = self.store.intervals_since_genesis() / INTERVALS_PER_SLOT;
        if data_slot == current_slot {
            self.maybe_start_early_aggregation(ctx).await;
        }
    }
}

impl Handler<NewAggregatedAttestation> for BlockChainServer {
    async fn handle(&mut self, msg: NewAggregatedAttestation, _ctx: &Context<Self>) {
        // Lean-only: beacon gossip aggregates are out of scope for this actor.
        let ChainDuties::Lean(_) = &self.duties else {
            return;
        };
        let arrival_ms = unix_now_ms();
        metrics::observe_gossip_aggregation_arrival(arrival_ms, &self.store.config().time_grid());
        self.on_gossip_aggregated_attestation(msg.attestation);
    }
}

impl Handler<NewDataColumnSidecars> for BlockChainServer {
    async fn handle(&mut self, msg: NewDataColumnSidecars, _ctx: &Context<Self>) {
        self.on_checked_data_columns(msg.sidecars).await;
    }
}

impl Handler<DataColumnSidecarsAwaitingParent> for BlockChainServer {
    async fn handle(&mut self, msg: DataColumnSidecarsAwaitingParent, _ctx: &Context<Self>) {
        self.park_data_columns(msg.sidecars);
    }
}

impl Handler<NewBeaconAggregate> for BlockChainServer {
    async fn handle(&mut self, msg: NewBeaconAggregate, _ctx: &Context<Self>) {
        // Beacon-only: nothing subscribes a lean node to this topic, so a
        // message here would be a dispatch bug rather than a chain that has
        // nothing to do with it. Dropped rather than panicked on, the way
        // every other handler treats a message for the other chain.
        let ChainDuties::Beacon = &self.duties else {
            return;
        };
        // Read before anything else: this is the wait no timing on the far
        // side of the mailbox can see, and it is where a backlog would show.
        metrics::observe_beacon_aggregate_mailbox_wait(msg.arrival.handed_off.elapsed());
        self.on_gossip_beacon_aggregate(msg.aggregate, msg.attesting_indices, msg.arrival);
    }
}

// -------------------------------------------------------------------------
// Aggregation message handlers (worker → actor, actor → self for deadline)
// -------------------------------------------------------------------------
//
// All four are lean-only: a beacon follower never starts an aggregation
// session, so none of these messages are ever sent to one in practice. Each
// still opens with the `else { return }` guard rather than reaching for
// `lean()`, because a handler is the actor's outer boundary: dropping a
// message that does not apply to this chain is a real outcome there, while
// below it the same situation is a dispatch bug. See `ChainDuties`.

impl Handler<AggregateProduced> for BlockChainServer {
    async fn handle(&mut self, msg: AggregateProduced, _ctx: &Context<Self>) {
        let ChainDuties::Lean(lean) = &self.duties else {
            return;
        };
        let arrival_ms = unix_now_ms();

        // Drop results from a prior session (or from an unexpected late worker).
        // Current session may be None if the actor already cleaned it up; accept
        // the message only when ids match.
        let current = lean.current_aggregation.as_ref().map(|s| s.session_id);
        if current != Some(msg.session_id) {
            trace!(
                incoming_session_id = msg.session_id,
                current_session_id = ?current,
                "Dropping stale aggregate produced for non-current session"
            );
            return;
        }

        // Count our own aggregate in the same series as gossip-received ones,
        // so an aggregator does not report an empty aggregate arrival profile.
        // Delivery of this message is held to the interval-2 boundary upstream,
        // so a local aggregate lands near zero unless proving overran the
        // interval. Sharing one series with received aggregates is deliberate
        // and costs little in practice: a late aggregate is late for every node
        // at once, so both populations are dominated by production time rather
        // than propagation and their distributions look alike.
        metrics::observe_gossip_aggregation_arrival(arrival_ms, &self.store.config().time_grid());

        // Publish alignment is enforced upstream: the worker delays delivery of
        // this message until the interval-2 boundary, so by the time it lands
        // the aggregate is safe to apply and gossip immediately.
        aggregation::apply_aggregated_group(&mut self.store, &msg.output);

        // Surface our own freshly produced aggregate, the counterpart of the
        // gossip-received path in `on_gossip_aggregated_attestation` (we never
        // receive our own aggregate back over gossip). Low-rate; proof omitted.
        self.events.emit(ChainEvent::Aggregate {
            participants: msg.output.participants.clone(),
            data: msg.output.hashed.data().clone(),
        });

        if let Some(ref p2p) = self.p2p {
            let aggregate = SignedAggregatedAttestation {
                data: msg.output.hashed.data().clone(),
                proof: msg.output.proof,
            };
            let _ = p2p
                .publish_aggregated_attestation(aggregate)
                .inspect_err(|err| error!(%err, "Failed to publish aggregated attestation"));
        }
    }
}

impl Handler<EarlyAggregationCheck> for BlockChainServer {
    async fn handle(&mut self, _msg: EarlyAggregationCheck, ctx: &Context<Self>) {
        let ChainDuties::Lean(_) = &self.duties else {
            return;
        };
        self.maybe_start_early_aggregation(ctx).await;
    }
}

impl Handler<AggregationDone> for BlockChainServer {
    async fn handle(&mut self, msg: AggregationDone, _ctx: &Context<Self>) {
        let ChainDuties::Lean(lean) = &self.duties else {
            return;
        };
        aggregation::finalize_aggregation_session(&self.store);
        metrics::observe_committee_signatures_aggregation(msg.total_elapsed);

        let aggregation_elapsed = msg.total_elapsed;
        let early = lean
            .current_aggregation
            .as_ref()
            .is_some_and(|s| s.session_id == msg.session_id && s.early);
        info!(
            ?aggregation_elapsed,
            session_id = msg.session_id,
            groups_considered = msg.groups_considered,
            groups_aggregated = msg.groups_aggregated,
            total_raw_sigs = msg.total_raw_sigs,
            total_children = msg.total_children,
            cancelled = msg.cancelled,
            early,
            aggregation_deadline_ms =
                aggregation_deadline(self.store.config().milliseconds_per_interval()).as_millis()
                    as u64,
            "Committee signatures aggregated"
        );
    }
}

impl Handler<AggregationDeadline> for BlockChainServer {
    async fn handle(&mut self, msg: AggregationDeadline, _ctx: &Context<Self>) {
        let ChainDuties::Lean(lean) = &self.duties else {
            return;
        };
        if let Some(session) = &lean.current_aggregation
            && session.session_id == msg.session_id
        {
            session.cancel.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use ethlambda_state_transition::beacon::fork_choice::seconds_to_milliseconds;
    use ethlambda_storage::backend::InMemoryBackend;
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::{BeaconState, deneb, electra, phase0, shared};
    use ethlambda_types::beacon::fork::ForkName;
    use ethlambda_types::beacon::preset;
    use ethlambda_types::checkpoint::Checkpoint;
    use ethlambda_types::state::State;

    const GENESIS_TIME: u64 = 1_000;

    fn config(milliseconds_per_slot: u64) -> ChainConfig {
        ChainConfig::new(GENESIS_TIME, milliseconds_per_slot)
    }

    #[test]
    fn interval_boundaries_scale_with_the_slot_duration() {
        let default = config(DEFAULT_MILLISECONDS_PER_SLOT);
        let doubled = config(2 * DEFAULT_MILLISECONDS_PER_SLOT);

        // Same interval index, twice the offset.
        for interval in [
            SlotInterval::BlockPublication,
            SlotInterval::AttestationProduction,
            SlotInterval::Aggregation,
            SlotInterval::SafeTargetUpdate,
            SlotInterval::EndOfSlot,
        ] {
            let at_default = interval.to_ms_since_genesis(7, &default);
            assert_eq!(interval.to_ms_since_genesis(7, &doubled), 2 * at_default);
        }
    }

    #[test]
    fn a_hostile_slot_saturates_instead_of_overflowing() {
        let config = config(DEFAULT_MILLISECONDS_PER_SLOT);

        // Arrival metrics reach `to_ms_since_genesis` with an unvalidated
        // gossip slot, so neither the multiply nor the interval offset may
        // panic in a debug build or wrap in a release one.
        for interval in [
            SlotInterval::BlockPublication,
            SlotInterval::AttestationProduction,
            SlotInterval::Aggregation,
            SlotInterval::SafeTargetUpdate,
            SlotInterval::EndOfSlot,
        ] {
            assert_eq!(interval.to_ms_since_genesis(u64::MAX, &config), u64::MAX);
        }
    }

    #[test]
    fn interval_conversions_round_trip() {
        let config = config(8_000);

        for slot in [0, 1, 42] {
            for interval in [
                SlotInterval::BlockPublication,
                SlotInterval::AttestationProduction,
                SlotInterval::Aggregation,
                SlotInterval::SafeTargetUpdate,
                SlotInterval::EndOfSlot,
            ] {
                let start = interval.to_ms_since_genesis(slot, &config);
                assert_eq!(
                    SlotInterval::from_ms_since_genesis(start, &config),
                    interval
                );
                // Still the same interval one millisecond before the next boundary.
                let last_ms = start + config.milliseconds_per_interval() - 1;
                assert_eq!(
                    SlotInterval::from_ms_since_genesis(last_ms, &config),
                    interval
                );
            }
        }
    }

    #[test]
    fn next_interval_is_a_full_interval_away_at_a_boundary() {
        let config = config(8_000);
        let genesis_ms = config.genesis_time_ms();

        assert_eq!(ms_until_next_interval(genesis_ms, &config), 1_600);
        assert_eq!(ms_until_next_interval(genesis_ms + 1, &config), 1_599);
        assert_eq!(ms_until_next_interval(genesis_ms + 1_599, &config), 1);
        assert_eq!(ms_until_next_interval(genesis_ms + 1_600, &config), 1_600);
    }

    #[test]
    fn before_genesis_the_next_tick_is_genesis_itself() {
        let config = config(8_000);
        let genesis_ms = config.genesis_time_ms();

        assert_eq!(ms_until_next_interval(genesis_ms - 500, &config), 500);
    }

    #[test]
    fn aggregation_deadline_is_one_interval() {
        let config = config(8_000);
        assert_eq!(
            aggregation_deadline(config.milliseconds_per_interval()),
            Duration::from_millis(1_600)
        );
    }

    // -----------------------------------------------------------------
    // ms_until_next_interval / ms_until_next_beacon_slot
    //
    // Both helpers share one shape (elapsed-since-genesis modulo a
    // cadence, with a special case before genesis); these mirror each
    // other's cases so a regression in one grid shows up the same way
    // as in the other.
    // -----------------------------------------------------------------

    #[test]
    fn ms_until_next_interval_returns_a_whole_interval_exactly_on_a_boundary() {
        // A sample taken right on an interval boundary must still schedule a
        // full interval ahead. Regression guard: the beacon slice refactored
        // this function's only caller (`ms_until_next_tick`) to dispatch by
        // chain, and a boundary sample returning zero here would spin the
        // tick loop instead of waiting out the interval.
        let cfg = config(DEFAULT_MILLISECONDS_PER_SLOT);
        assert_eq!(
            ms_until_next_interval(cfg.genesis_time_ms(), &cfg),
            cfg.milliseconds_per_interval()
        );
    }

    #[test]
    fn ms_until_next_interval_returns_the_remainder_mid_interval() {
        let cfg = config(DEFAULT_MILLISECONDS_PER_SLOT);
        let elapsed_into_interval = 300;
        let now_ms = cfg.genesis_time_ms() + elapsed_into_interval;
        assert_eq!(
            ms_until_next_interval(now_ms, &cfg),
            cfg.milliseconds_per_interval() - elapsed_into_interval
        );
    }

    #[test]
    fn ms_until_next_interval_waits_for_genesis_itself_when_called_early() {
        let cfg = config(DEFAULT_MILLISECONDS_PER_SLOT);
        let now_ms = cfg.genesis_time_ms() - 600;
        assert_eq!(
            ms_until_next_interval(now_ms, &cfg),
            cfg.genesis_time_ms() - now_ms
        );
    }

    #[test]
    fn ms_until_next_beacon_slot_returns_a_whole_slot_exactly_on_a_boundary() {
        // Beacon's counterpart to the interval case above: a boundary sample
        // must schedule a whole slot ahead, since the beacon tick loop has no
        // sub-slot grid to fall back on if this ever returned less.
        let genesis_time_ms = 1_000;
        let slot_duration_ms = Config::mainnet().slot_duration_ms;
        assert_eq!(
            ms_until_next_beacon_slot(genesis_time_ms, genesis_time_ms, slot_duration_ms),
            slot_duration_ms
        );
    }

    #[test]
    fn ms_until_next_beacon_slot_returns_the_remainder_mid_slot() {
        let genesis_time_ms = 1_000;
        let slot_duration_ms = Config::mainnet().slot_duration_ms;
        let elapsed_into_slot = 5_000;
        let now_ms = genesis_time_ms + elapsed_into_slot;
        assert_eq!(
            ms_until_next_beacon_slot(now_ms, genesis_time_ms, slot_duration_ms),
            slot_duration_ms - elapsed_into_slot
        );
    }

    #[test]
    fn ms_until_next_beacon_slot_waits_for_genesis_itself_when_called_early() {
        let genesis_time_ms = 1_000;
        let slot_duration_ms = Config::mainnet().slot_duration_ms;
        let now_ms = 400;
        assert_eq!(
            ms_until_next_beacon_slot(now_ms, genesis_time_ms, slot_duration_ms),
            genesis_time_ms - now_ms
        );
    }

    /// A beacon store anchored at a zero root, with `genesis_time` (Unix
    /// seconds) and both realized checkpoints at `finalized_slot`.
    ///
    /// No anchor state is written: its only caller asserts on the chain tag
    /// `Store::init_beacon` sets, which is seeded before any state is.
    fn beacon_store(genesis_time: u64, finalized_slot: u64) -> Store {
        beacon_store_with_config(genesis_time, finalized_slot, Config::mainnet())
    }

    /// A beacon store whose fulu activation is genesis, so a fulu-shaped block
    /// at a single-digit slot is a coherent fixture rather than one sitting
    /// thousands of epochs before its own fork.
    ///
    /// Needed by anything exercising the availability gate: that gate stops at
    /// the fulu fork (see `da_check_required_for_slot`), so under
    /// [`Config::mainnet`]'s real schedule a slot-2 block is simply not a
    /// block the gate has any business holding.
    fn beacon_store_fulu_at_genesis(genesis_time: u64, finalized_slot: u64) -> Store {
        beacon_store_with_config(
            genesis_time,
            finalized_slot,
            Config::mainnet().with_fork_epoch(ForkName::Fulu, 0),
        )
    }

    fn beacon_store_with_config(genesis_time: u64, finalized_slot: u64, config: Config) -> Store {
        let backend = Arc::new(InMemoryBackend::default());
        let anchor_root = H256::ZERO;
        let anchor_checkpoint = Checkpoint {
            root: anchor_root,
            slot: finalized_slot,
        };
        Store::init_beacon(
            backend,
            genesis_time,
            config,
            anchor_root,
            anchor_checkpoint,
            finalized_slot,
        )
    }

    // -----------------------------------------------------------------
    // spawn / spawn_beacon chain assertions
    //
    // Both panic on their very first line, before either constructor
    // touches anything that would need a running actor context, so a
    // plain #[test] (no tokio runtime) is enough to observe them.
    // -----------------------------------------------------------------

    #[test]
    #[should_panic(expected = "BlockChain::spawn requires a lean store")]
    fn spawn_panics_when_handed_a_beacon_store() {
        // Guards against pairing a lean-shaped BlockChainConfig (validator
        // keys, aggregator role, proposer policy) with a beacon store, which
        // would corrupt the directory the moment any duty touched it.
        let store = beacon_store(0, 0);
        let config = BlockChainConfig {
            aggregator: AggregatorController::new(false),
            sync_status_controller: SyncStatusController::default(),
            attestation_committee_count: 0,
            gate_duties: true,
            subscribed_subnets: HashSet::new(),
            aggregation_duty_subnet: 0,
            skip_redundant_aggregation: false,
            proposer_config: ProposerConfig {
                enable_proposer_aggregation: false,
                max_attestations_per_block: 0,
            },
        };

        let _ = BlockChain::spawn(store, HashMap::new(), config, EventBus::default());
    }

    #[test]
    #[should_panic(expected = "BlockChain::spawn_beacon requires a beacon store")]
    fn spawn_beacon_panics_when_handed_a_lean_store() {
        // Mirror of the assertion above: a beacon follower's spawn path must
        // never run against lean-shaped state either.
        let backend = Arc::new(InMemoryBackend::default());
        let store = Store::from_anchor_state(
            backend,
            State::from_genesis(0, Vec::new()),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );

        let _ = BlockChain::spawn_beacon(
            store,
            SyncStatusController::default(),
            EventBus::default(),
            Vec::new(),
            None,
            constants::SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY,
        );
    }

    // -----------------------------------------------------------------
    // Data column sidecars: keeping, parking and replaying them
    //
    // These call the methods directly on a plain `BlockChainServer`, built
    // the way `start_actor` builds one but never spawned: there is no mailbox
    // to drive. The checks themselves run in the p2p layer and are tested
    // with `beacon::gossip::column`.
    // -----------------------------------------------------------------

    fn beacon_server(store: Store) -> BlockChainServer {
        BlockChainServer {
            store,
            p2p: None,
            pending_blocks: HashMap::new(),
            pending_block_parents: HashMap::new(),
            blocks_awaiting_columns: HashMap::new(),
            held_timings: HashMap::new(),
            sidecars_awaiting_parent: HashMap::new(),
            beacon_aggregates: Default::default(),
            custody_columns: Vec::new(),
            engine: None,
            safe_slots_to_import_optimistically: constants::SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY,
            last_tick_instant: None,
            sync_status: SyncStatusTracker::new(false),
            sync_status_controller: SyncStatusController::default(),
            events: EventBus::default(),
            duties: ChainDuties::Beacon,
        }
    }

    /// A sidecar naming `slot` and `parent_root`, structurally valid enough to
    /// clear `verify_data_column_sidecar` (one commitment, one proof, one
    /// column cell, all the same length), so the chain checks judge it on its
    /// parent rather than its shape; every other field is its type's default,
    /// since nothing under test reads past the header.
    fn sidecar_at(slot: u64, parent_root: H256) -> fulu::DataColumnSidecar {
        let cell: fulu::Cell = libssz_types::SszVector::try_from(vec![0u8; preset::BYTES_PER_CELL])
            .expect("exact cell size");
        fulu::DataColumnSidecar {
            index: 0,
            column: vec![cell].try_into().expect("within the per-block limit"),
            kzg_commitments: vec![ethlambda_types::beacon::primitives::KzgCommitment::default()]
                .try_into()
                .expect("within the per-block limit"),
            kzg_proofs: vec![ethlambda_types::beacon::primitives::KzgProof::default()]
                .try_into()
                .expect("within the per-block limit"),
            signed_block_header: shared::SignedBeaconBlockHeader {
                message: shared::BeaconBlockHeader {
                    slot,
                    parent_root,
                    ..Default::default()
                },
                signature: Default::default(),
            },
            // `SszVector` carries its length in the type, so unlike the
            // `SszList` fields above there is no length-zero default for it.
            kzg_commitments_inclusion_proof: vec![
                H256::ZERO;
                preset::KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH
            ]
            .try_into()
            .expect("exactly the required depth"),
        }
    }

    /// A phase0 block good for nothing but its `(slot, parent_root)` pair:
    /// what `Store::insert_signed_block` writes into `LiveChain`, which is
    /// all `get_checkpoint_block`'s ancestry walk ever reads. The fork is
    /// irrelevant to that walk, so the cheapest shape to build stands in.
    fn bare_block(slot: u64, parent_root: H256) -> SignedBeaconBlock {
        SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: H256::ZERO,
                body: phase0::BeaconBlockBody {
                    randao_reveal: Default::default(),
                    eth1_data: Default::default(),
                    graffiti: H256::ZERO,
                    proposer_slashings: Default::default(),
                    attester_slashings: Default::default(),
                    attestations: Default::default(),
                    deposits: Default::default(),
                    voluntary_exits: Default::default(),
                },
            },
            signature: Default::default(),
        })
    }

    /// A structurally minimal phase0 state, good for nothing but existing.
    /// The parent check under test never reads a state's contents, only
    /// whether `Store::get_state` finds one at all, so this only needs to
    /// satisfy the type checker and `Store::insert_state`.
    ///
    /// `latest_block_header.parent_root` is set to a root nothing else in a
    /// test ever writes, so `Store::block_entry` reports it unknown and
    /// `insert_state` takes that as "first state on record" and stores a
    /// plain snapshot, rather than trying to diff against a parent state
    /// this helper never creates.
    fn bare_state() -> BeaconState {
        let block_roots = vec![H256::ZERO; preset::SLOTS_PER_HISTORICAL_ROOT]
            .try_into()
            .expect("exactly the preset length");
        let state_roots = vec![H256::ZERO; preset::SLOTS_PER_HISTORICAL_ROOT]
            .try_into()
            .expect("exactly the preset length");
        let randao_mixes = vec![H256::ZERO; preset::EPOCHS_PER_HISTORICAL_VECTOR]
            .try_into()
            .expect("exactly the preset length");
        let slashings = vec![0u64; preset::EPOCHS_PER_SLASHINGS_VECTOR]
            .try_into()
            .expect("exactly the preset length");
        BeaconState::Phase0(phase0::BeaconState {
            genesis_time: 0,
            genesis_validators_root: H256::ZERO,
            slot: 0,
            fork: Default::default(),
            latest_block_header: shared::BeaconBlockHeader {
                parent_root: H256::repeat_byte(0xee),
                ..Default::default()
            },
            block_roots,
            state_roots,
            historical_roots: Default::default(),
            eth1_data: Default::default(),
            eth1_data_votes: Default::default(),
            eth1_deposit_index: 0,
            validators: Default::default(),
            balances: Default::default(),
            randao_mixes,
            slashings,
            previous_epoch_attestations: Default::default(),
            current_epoch_attestations: Default::default(),
            justification_bits: Default::default(),
            previous_justified_checkpoint: Default::default(),
            current_justified_checkpoint: Default::default(),
            finalized_checkpoint: Default::default(),
        })
    }

    #[test]
    fn the_availability_gate_stops_at_the_window_peers_must_serve() {
        let config = Config::mainnet();
        let fulu_start = config.fulu_fork_epoch * preset::SLOTS_PER_EPOCH;
        // Far enough past fulu that the retention window, not the fork, is
        // what sets the boundary.
        let current_epoch =
            config.fulu_fork_epoch + constants::MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS + 100;
        let current_slot = current_epoch * preset::SLOTS_PER_EPOCH;
        let boundary_epoch =
            current_epoch - constants::MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS;

        // Inside the window: peers MUST be able to serve these, so insisting
        // is fair.
        assert!(da_check_required_for_slot(
            current_slot,
            current_slot,
            &config
        ));
        assert!(da_check_required_for_slot(
            boundary_epoch * preset::SLOTS_PER_EPOCH,
            current_slot,
            &config
        ));

        // One epoch below it a peer MAY answer ResourceUnavailable, so holding
        // a block there would stall the chain against data the network is
        // entitled to have dropped.
        assert!(!da_check_required_for_slot(
            (boundary_epoch - 1) * preset::SLOTS_PER_EPOCH,
            current_slot,
            &config
        ));

        // Before fulu there is no column matrix to be available at all, and
        // the boundary must not walk below the fork even when the retention
        // window reaches past it.
        let just_after_fork = fulu_start + preset::SLOTS_PER_EPOCH;
        assert!(da_check_required_for_slot(
            just_after_fork,
            just_after_fork,
            &config
        ));
        assert!(!da_check_required_for_slot(
            fulu_start - 1,
            just_after_fork,
            &config
        ));
    }

    /// Every `BlockChainToP2P` message the chain actor sends, kept for a test
    /// to read back. Only `check_data_column_sidecars` and `fetch_block` are
    /// recorded: nothing under test here sends the others.
    #[derive(Default)]
    struct RecordingP2P {
        checks: std::sync::Mutex<Vec<Vec<fulu::DataColumnSidecar>>>,
        fetches: std::sync::Mutex<Vec<FetchRequest>>,
    }

    impl ethlambda_network_api::BlockChainToP2P for RecordingP2P {
        fn publish_block(
            &self,
            _block: ethlambda_types::block::SignedBlock,
        ) -> Result<(), spawned_concurrency::error::ActorError> {
            Ok(())
        }
        fn publish_attestation(
            &self,
            _attestation: ethlambda_types::attestation::SignedAttestation,
        ) -> Result<(), spawned_concurrency::error::ActorError> {
            Ok(())
        }
        fn publish_aggregated_attestation(
            &self,
            _attestation: ethlambda_types::attestation::SignedAggregatedAttestation,
        ) -> Result<(), spawned_concurrency::error::ActorError> {
            Ok(())
        }
        fn fetch_block(
            &self,
            request: FetchRequest,
        ) -> Result<(), spawned_concurrency::error::ActorError> {
            self.fetches.lock().unwrap().push(request);
            Ok(())
        }
        fn check_data_column_sidecars(
            &self,
            sidecars: Vec<fulu::DataColumnSidecar>,
        ) -> Result<(), spawned_concurrency::error::ActorError> {
            self.checks.lock().unwrap().push(sidecars);
            Ok(())
        }
    }

    /// `beacon_server(store)` with a [`RecordingP2P`] wired in as its p2p ref.
    fn beacon_server_recording(store: Store) -> (BlockChainServer, Arc<RecordingP2P>) {
        let p2p = Arc::new(RecordingP2P::default());
        let mut server = beacon_server(store);
        server.p2p = Some(p2p.clone());
        (server, p2p)
    }

    /// A beacon store whose clock reads slot 10, so a sidecar at slot 10 is
    /// neither future nor finalized.
    fn beacon_store_at_slot_10() -> Store {
        let mut store = beacon_store(GENESIS_TIME, 0);
        store
            .set_time_ms(seconds_to_milliseconds(
                GENESIS_TIME + 10 * Config::mainnet().seconds_per_slot,
            ))
            .unwrap();
        store
    }

    #[tokio::test]
    async fn a_checked_sidecar_is_stored_as_it_is() {
        // Nothing on this path judges the sidecar (that is the p2p layer's
        // job), so storing it is the whole contract. `keep_data_column`
        // rather than `on_checked_data_columns`, since this placeholder
        // sidecar would fail the debug-build re-check.
        let mut server = beacon_server(beacon_store_at_slot_10());
        let sidecar = sidecar_at(10, H256::repeat_byte(9));
        let block_root = sidecar.signed_block_header.message.hash_tree_root();

        server.keep_data_column(sidecar).await;

        assert_eq!(
            server
                .store
                .data_column_indices_for(10, &block_root)
                .expect("DB read should succeed"),
            vec![0]
        );
    }

    /// The debug-build safety net: a sidecar the p2p layer forwarded as
    /// checked, but that the chain checks would not have kept, stops the
    /// actor rather than reaching the store. Release builds skip the re-check
    /// and store it.
    #[cfg(debug_assertions)]
    #[tokio::test]
    #[should_panic(expected = "the chain checks refuse")]
    async fn a_sidecar_the_p2p_layer_never_checked_fails_the_debug_recheck() {
        let mut server = beacon_server(beacon_store_at_slot_10());
        // Its parent has no state, so the chain checks would park it, never
        // keep it.
        let sidecar = sidecar_at(10, H256::repeat_byte(9));

        server.on_checked_data_columns(vec![sidecar]).await;
    }

    #[test]
    fn a_data_column_sidecar_naming_a_parent_with_no_state_is_parked_not_stored() {
        // `beacon_store` writes no anchor state (see its own doc comment), so
        // any parent root at all is unknown here, including the anchor's own.
        let (mut server, p2p) = beacon_server_recording(beacon_store_at_slot_10());
        let parent_root = H256::repeat_byte(9);
        let sidecar = sidecar_at(10, parent_root);
        let block_root = sidecar.signed_block_header.message.hash_tree_root();

        server.park_data_columns(vec![sidecar]);

        // Not stored: it has not been checked, so it has not been accepted.
        assert_eq!(
            server
                .store
                .data_column_indices_for(10, &block_root)
                .unwrap(),
            Vec::<u64>::new()
        );
        // But kept, under the parent it is waiting on. Dropping it here is
        // what deadlocks a follower running the availability gate: a held
        // block writes no post-state, so every sidecar of every child of it
        // lands in exactly this branch.
        assert_eq!(
            server
                .sidecars_awaiting_parent
                .get(&parent_root)
                .map(HashSet::len),
            Some(1)
        );
        assert!(p2p.checks.lock().unwrap().is_empty());
    }

    #[test]
    fn a_sidecar_whose_parent_imported_meanwhile_goes_back_for_checks_not_into_the_queue() {
        // The race the p2p layer's checks open: they found no parent state,
        // then the parent imported and drained its (still empty) queue before
        // this message arrived. Parking it now would strand it until
        // finality, since that parent never drains again.
        let (mut server, p2p) = beacon_server_recording(beacon_store_at_slot_10());
        let parent_root = H256::repeat_byte(9);
        server
            .store
            .insert_state(parent_root, bare_state())
            .expect("insert");
        let sidecar = sidecar_at(10, parent_root);

        server.park_data_columns(vec![sidecar.clone()]);

        assert!(server.sidecars_awaiting_parent.is_empty());
        assert_eq!(*p2p.checks.lock().unwrap(), vec![vec![sidecar]]);
    }

    #[test]
    fn a_parked_sidecar_goes_back_for_checks_once_its_parent_gains_a_post_state() {
        // The deadlock this closes, in miniature: while the parent has no
        // post-state every sidecar under it parks, and if parking were the end
        // of the story the queue would only ever grow. What breaks the cycle
        // is that gaining a post-state releases them, to the p2p layer's
        // checks, since this actor no longer judges a sidecar itself.
        let (mut server, p2p) = beacon_server_recording(beacon_store_at_slot_10());
        let parent_root = H256::repeat_byte(9);
        let sidecar = sidecar_at(10, parent_root);
        let block_root = sidecar.signed_block_header.message.hash_tree_root();

        server.park_data_columns(vec![sidecar.clone()]);
        assert!(server.sidecars_awaiting_parent.contains_key(&parent_root));

        server.drain_sidecars_awaiting_parent(parent_root);

        // Gone from the queue and from `PendingDataColumns`, and handed to
        // the checks exactly as it was parked.
        assert!(!server.sidecars_awaiting_parent.contains_key(&parent_root));
        assert!(
            server
                .store
                .take_pending_data_column_sidecar(10, &block_root, 0)
                .expect("DB read should succeed")
                .is_none()
        );
        assert_eq!(*p2p.checks.lock().unwrap(), vec![vec![sidecar]]);
    }

    #[test]
    fn a_parked_sidecar_holds_its_bytes_on_disk_and_not_in_the_queue() {
        // The queue's size is chosen by whoever is gossiping, so what it holds
        // per entry is the thing that has to stay small: a key, not a cell per
        // blob.
        let mut server = beacon_server(beacon_store_at_slot_10());
        let parent_root = H256::repeat_byte(9);
        let sidecar = sidecar_at(10, parent_root);
        let block_root = sidecar.signed_block_header.message.hash_tree_root();

        server.park_data_columns(vec![sidecar]);

        assert_eq!(
            server.sidecars_awaiting_parent.get(&parent_root),
            Some(&HashSet::from([ParkedColumn {
                slot: 10,
                block_root,
                index: 0,
            }]))
        );
        assert!(
            server
                .store
                .take_pending_data_column_sidecar(10, &block_root, 0)
                .expect("DB read should succeed")
                .is_some(),
            "the sidecar's bytes belong in PendingDataColumns"
        );
    }

    #[test]
    fn a_parked_sidecar_does_not_satisfy_the_availability_gate() {
        // Why the parked rows get a table of their own. Nothing has judged a
        // parked sidecar's inclusion proof, its KZG batch or its proposer
        // signature, so a peer that could get one counted as custodied would
        // be able to release a held block with a column it invented.
        let mut server = beacon_server(beacon_store_at_slot_10());
        let sidecar = sidecar_at(10, H256::repeat_byte(9));
        let block_root = sidecar.signed_block_header.message.hash_tree_root();

        server.park_data_columns(vec![sidecar]);

        assert_eq!(
            server
                .store
                .data_column_indices_for(10, &block_root)
                .expect("DB read should succeed"),
            Vec::<u64>::new(),
            "an unverified sidecar must be invisible to data_column_indices_for"
        );
    }

    #[test]
    fn a_sidecar_parked_twice_takes_one_slot_in_the_queue() {
        // The by-root and by-range fetch paths skip gossip's seen cache
        // entirely, so nothing between them and this actor dedups a
        // re-delivery while the parent is still stateless; it is ordinary. A
        // second entry would leave a key with no row behind it once the
        // first replay took it.
        let mut server = beacon_server(beacon_store_at_slot_10());
        let parent_root = H256::repeat_byte(9);

        server.park_data_columns(vec![sidecar_at(10, parent_root)]);
        server.park_data_columns(vec![sidecar_at(10, parent_root)]);

        assert_eq!(
            server
                .sidecars_awaiting_parent
                .get(&parent_root)
                .map(HashSet::len),
            Some(1)
        );
    }

    #[test]
    fn parked_sidecars_are_dropped_once_finality_passes_their_slot() {
        // Populated directly rather than through `park_data_columns`: the
        // chain checks refuse a sidecar at or below the finalized slot before
        // it could ever be parked, so the only way to observe the sweep is to
        // park one behind their back. The finalized slot is fixed at init, so
        // the store carries it rather than the test moving it.
        let mut server = beacon_server(beacon_store(GENESIS_TIME, 10));
        let superseded = H256::repeat_byte(1);
        let still_wanted = H256::repeat_byte(2);
        let parked_at = |slot: u64| ParkedColumn {
            slot,
            block_root: H256::repeat_byte(9),
            index: 0,
        };
        server
            .sidecars_awaiting_parent
            .insert(superseded, HashSet::from([parked_at(10)]));
        server
            .sidecars_awaiting_parent
            .insert(still_wanted, HashSet::from([parked_at(20)]));

        server.evict_sidecars_awaiting_parent_at_or_below_finality();

        // A parent root that never arrives would otherwise pin its children's
        // sidecars for this node's whole uptime; one still above finality is
        // a parent that may yet show up.
        assert!(!server.sidecars_awaiting_parent.contains_key(&superseded));
        assert!(server.sidecars_awaiting_parent.contains_key(&still_wanted));
    }

    // -----------------------------------------------------------------
    // data_availability_for / hold_block_for_columns /
    // release_block_if_columns_complete
    //
    // Neither the KZG proofs nor the signature are checked by the function
    // under test in any of these, so `fulu_block_with_commitments` and
    // `sidecar_for` build structurally minimal values: present or absent in
    // the store is all that matters here.
    // -----------------------------------------------------------------

    /// The columns this node is pretending to custody in these three tests.
    const CUSTODY: [u64; 2] = [0, 1];

    /// A fulu block at `slot`, naming `parent_root`, whose body carries
    /// `commitment_count` blob commitments; everything else is a
    /// structurally minimal placeholder. Neither the KZG proofs nor the
    /// signature are checked by `data_availability_for`, the function every
    /// caller of this helper is exercising, so nothing here needs to be real:
    /// only structurally present, so `message_hash_tree_root` and `to_ssz`
    /// succeed.
    fn fulu_block(parent_root: H256, slot: u64, commitment_count: usize) -> SignedBeaconBlock {
        let payload = deneb::ExecutionPayload {
            parent_hash: Default::default(),
            fee_recipient: Default::default(),
            state_root: H256::ZERO,
            receipts_root: H256::ZERO,
            logs_bloom: vec![0u8; preset::BYTES_PER_LOGS_BLOOM]
                .try_into()
                .expect("exactly the preset length"),
            prev_randao: H256::ZERO,
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: Default::default(),
            base_fee_per_gas: Default::default(),
            block_hash: Default::default(),
            transactions: Default::default(),
            withdrawals: Default::default(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
        };
        let body = electra::BeaconBlockBody {
            randao_reveal: Default::default(),
            eth1_data: Default::default(),
            graffiti: H256::ZERO,
            proposer_slashings: Default::default(),
            attester_slashings: Default::default(),
            attestations: Default::default(),
            deposits: Default::default(),
            voluntary_exits: Default::default(),
            sync_aggregate: Default::default(),
            execution_payload: payload,
            bls_to_execution_changes: Default::default(),
            blob_kzg_commitments: vec![Default::default(); commitment_count]
                .try_into()
                .expect("commitment_count stays well within MAX_BLOB_COMMITMENTS_PER_BLOCK here"),
            execution_requests: electra::ExecutionRequests {
                deposits: Default::default(),
                withdrawals: Default::default(),
                consolidations: Default::default(),
            },
        };
        SignedBeaconBlock::Fulu(electra::SignedBeaconBlock {
            message: electra::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: H256::ZERO,
                body,
            },
            signature: Default::default(),
        })
    }

    /// A fulu block whose body carries `commitment_count` blob commitments,
    /// off a zero parent root, at one past `store`'s finalized slot —
    /// matching what would actually reach `data_availability_for` in
    /// `process_block` off a zero-rooted anchor. See [`fulu_block`] for what
    /// the rest of the block looks like.
    fn fulu_block_with_commitments(store: &Store, commitment_count: usize) -> SignedBeaconBlock {
        let slot = store
            .latest_finalized()
            .expect("finalized checkpoint exists")
            .slot
            + 1;
        fulu_block(H256::ZERO, slot, commitment_count)
    }

    /// A sidecar naming `block`'s own header at `index`; every other field is
    /// its type's default, the same minimalism `sidecar_at` uses above.
    fn sidecar_for(block: &SignedBeaconBlock, index: u64) -> fulu::DataColumnSidecar {
        fulu::DataColumnSidecar {
            index,
            column: Default::default(),
            kzg_commitments: Default::default(),
            kzg_proofs: Default::default(),
            signed_block_header: shared::SignedBeaconBlockHeader {
                message: shared::BeaconBlockHeader {
                    slot: block.slot(),
                    proposer_index: block.proposer_index(),
                    parent_root: block.parent_root(),
                    state_root: block.state_root(),
                    body_root: H256::ZERO,
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

    #[test]
    fn a_block_with_no_commitments_needs_no_columns() {
        let store = beacon_store(0, 0);
        let block = fulu_block_with_commitments(&store, 0);
        assert!(matches!(
            data_availability_for(&store, &block, &CUSTODY).unwrap(),
            fork_choice::DataAvailability::NotRequired
        ));
    }

    #[test]
    fn a_block_missing_one_custody_column_is_not_available() {
        let store = beacon_store(0, 0);
        let block = fulu_block_with_commitments(&store, 2);
        let root = block.message_hash_tree_root();
        store
            .put_data_column_sidecar(block.slot(), &root, 0, vec![1])
            .unwrap();
        // Column 1 is custodied and absent, so the question cannot be answered
        // yet. `None` must not collapse into an empty Columns list: that list
        // is vacuously available and would import a block nobody has data for.
        assert!(data_availability_for(&store, &block, &CUSTODY).is_none());
    }

    #[test]
    fn a_block_with_every_custody_column_is_available() {
        let store = beacon_store(0, 0);
        let block = fulu_block_with_commitments(&store, 2);
        let root = block.message_hash_tree_root();
        for index in CUSTODY {
            let sidecar = sidecar_for(&block, index);
            store
                .put_data_column_sidecar(block.slot(), &root, index, sidecar.to_ssz())
                .unwrap();
        }
        assert!(matches!(
            data_availability_for(&store, &block, &CUSTODY).unwrap(),
            fork_choice::DataAvailability::Columns(sidecars) if sidecars.len() == 2
        ));
    }

    #[test]
    fn an_empty_custody_set_means_nothing_to_wait_for() {
        // The replay harness is the one legitimate caller with no custody set:
        // it supplies every block itself and has no columns to wait on. The
        // invariant that a real node custodies a non-empty set is enforced
        // where a node is configured, not re-derived per block.
        //
        // With no column to require, `custody_columns_present` is vacuously
        // true and the collected evidence is `Columns(vec![])` rather than
        // `NotRequired`: the commitments are still there, so this is "nothing
        // outstanding", not "no check needed", but the two are equally
        // admissible to `is_data_available_columns`.
        let store = beacon_store(0, 0);
        let block = fulu_block_with_commitments(&store, 1);

        let evidence = data_availability_for(&store, &block, &[]);

        assert!(
            matches!(
                evidence,
                Some(fork_choice::DataAvailability::Columns(sidecars)) if sidecars.is_empty()
            ),
            "an empty custody set has nothing outstanding, so the block is admissible"
        );
    }

    #[test]
    fn holding_a_block_persists_it_and_records_its_root() {
        let store = beacon_store(GENESIS_TIME, 0);
        let mut server = beacon_server(store);
        server.custody_columns = CUSTODY.to_vec();
        let block = fulu_block_with_commitments(&server.store, 2);
        let root = block.message_hash_tree_root();
        let slot = block.slot();

        server.hold_block_for_columns(block, slot, ImportTimings::default());

        assert_eq!(server.blocks_awaiting_columns.get(&root), Some(&slot));
        assert!(server.store.get_signed_block(&root).unwrap().is_some());
    }

    #[tokio::test]
    async fn releasing_before_every_custody_column_arrives_is_a_no_op() {
        let store = beacon_store(GENESIS_TIME, 0);
        let mut server = beacon_server(store);
        server.custody_columns = CUSTODY.to_vec();
        let block = fulu_block_with_commitments(&server.store, 2);
        let root = block.message_hash_tree_root();
        let slot = block.slot();
        server.hold_block_for_columns(block, slot, ImportTimings::default());

        // Only one of the two custody columns has arrived.
        server
            .store
            .put_data_column_sidecar(slot, &root, 0, vec![1])
            .unwrap();

        server.release_block_if_columns_complete(root).await;

        assert!(server.blocks_awaiting_columns.contains_key(&root));
    }

    #[tokio::test]
    async fn releasing_once_every_custody_column_arrives_clears_the_hold() {
        let store = beacon_store(GENESIS_TIME, 0);
        let mut server = beacon_server(store);
        server.custody_columns = CUSTODY.to_vec();
        let block = fulu_block_with_commitments(&server.store, 2);
        let root = block.message_hash_tree_root();
        let slot = block.slot();
        server.hold_block_for_columns(block.clone(), slot, ImportTimings::default());

        for index in CUSTODY {
            let sidecar = sidecar_for(&block, index);
            server
                .store
                .put_data_column_sidecar(slot, &root, index, sidecar.to_ssz())
                .unwrap();
        }

        server.release_block_if_columns_complete(root).await;

        assert!(!server.blocks_awaiting_columns.contains_key(&root));
    }

    // -----------------------------------------------------------------
    // End-to-end: a held block's fan-out must not livelock the cascade
    //
    // Regression coverage for the defect a bare `Ok(())` from `process_block`
    // used to hide: `process_or_pend_block` treated a hold exactly like an
    // import, called `collect_pending_children` on it, and a child block
    // naming the still-held block as parent turned that into an unbounded
    // cycle on `run_import_cascade`'s own synchronous queue (re-fetch the
    // held block from `BlockHeaders` → re-hold it → re-collect the same
    // child → repeat), with no yield point, spinning the actor at full CPU
    // and starving every tick and gossip message behind it.
    //
    // This test drives the real entry point (`on_block`, what
    // `Handler<NewBlock>` calls) end to end rather than the lower-level
    // methods the tests above call directly, so it is the one that actually
    // exercises `process_or_pend_block`'s handling of `process_block`'s
    // return value — nothing else in this file does.
    //
    // It does not assert that either block ends up with a post-state.
    // `fork_choice::on_block`'s state transition needs a real BLS-signed
    // RANDAO reveal against a real proposer, a real sync-committee
    // aggregate, and a KZG batch over the sidecars this test stores — none
    // of which a structurally-minimal block or a placeholder sidecar can
    // satisfy, and building ones that could means reproducing the
    // spec-fixture machinery `ethlambda-state-transition`'s own test suite
    // uses, in a crate this task does not own. What this gate owns, and what
    // this test asserts instead, is that a held block's fan-out is bounded:
    // the cascade always terminates, the held block is never double-counted,
    // and the release path clears the hold regardless of what the resulting
    // import attempt does with it.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn a_childs_fan_out_does_not_livelock_a_held_parent() {
        // Fulu at genesis: the gate under test only applies inside the
        // availability window, which starts at the fulu fork, and this
        // fixture's blocks live at single-digit slots.
        let mut store = beacon_store_fulu_at_genesis(GENESIS_TIME, 0);
        // `get_ancestor`'s finalized-chain walk (inside `fork_choice::on_block`,
        // reached once the parent's columns are present) needs a block at the
        // zero root to walk from, the same reason
        // `the_finalized_root_itself_is_on_the_finalized_chain` needs one.
        store
            .insert_signed_block(H256::ZERO, bare_block(0, H256::repeat_byte(0xcc)))
            .expect("insert");
        store
            .insert_state(H256::ZERO, bare_state())
            .expect("insert");
        store
            .set_time_ms(seconds_to_milliseconds(
                GENESIS_TIME + 5 * Config::mainnet().seconds_per_slot,
            ))
            .unwrap();
        let mut server = beacon_server(store);
        server.custody_columns = CUSTODY.to_vec();

        let parent = fulu_block_with_commitments(&server.store, 2);
        let parent_root = parent.message_hash_tree_root();

        // First arrival: no columns yet, so the parent must be held, not
        // imported.
        server
            .on_block(parent.clone(), ImportTimings::default())
            .await;
        assert!(
            !server.store.has_state(&parent_root).unwrap(),
            "a held block must not have a post-state"
        );
        assert!(server.blocks_awaiting_columns.contains_key(&parent_root));

        // A child names the still-held block as its parent, in a later,
        // separate `on_block` call — exactly the fan-out the defect this
        // guards against needs. Under the bug this reproduces, this call
        // never returns.
        let child = fulu_block(parent_root, parent.slot() + 1, 0);
        let child_root = child.message_hash_tree_root();
        server.on_block(child, ImportTimings::default()).await;

        // Reaching this line at all is most of the proof: the cascade
        // terminated. What it terminated *into* matters too — the parent
        // still held (not re-held into some duplicated bookkeeping) and the
        // child parked behind it exactly once, the same shape a genuinely
        // missing parent leaves.
        assert!(!server.store.has_state(&parent_root).unwrap());
        assert!(server.blocks_awaiting_columns.contains_key(&parent_root));
        assert_eq!(
            server.pending_blocks.get(&parent_root),
            Some(&HashSet::from([child_root]))
        );

        // The parent's custody columns land and it releases for real.
        for index in CUSTODY {
            let sidecar = sidecar_for(&parent, index);
            server
                .store
                .put_data_column_sidecar(parent.slot(), &parent_root, index, sidecar.to_ssz())
                .unwrap();
        }
        server.release_block_if_columns_complete(parent_root).await;

        // The hold clears unconditionally, before the resulting re-import
        // attempt runs (see `release_block_if_columns_complete`'s own
        // ordering) — so this holds whether or not that attempt itself
        // succeeds, and it does not hang either way.
        assert!(!server.blocks_awaiting_columns.contains_key(&parent_root));
    }

    #[tokio::test]
    async fn the_descendants_of_a_held_block_wait_for_it_without_re_importing_it() {
        // A range batch hands the actor a whole chain at once. When its first
        // block is held for columns, every later block names a held ancestor,
        // and each used to re-queue that ancestor for another import that
        // could only hold it again: 68 re-holds of one block on a mainnet
        // follower's first batch after a checkpoint sync.
        let mut store = beacon_store_fulu_at_genesis(GENESIS_TIME, 0);
        // The held block's parent, as in the test above: a known state is what
        // lets it reach the availability gate at all.
        store
            .insert_signed_block(H256::ZERO, bare_block(0, H256::repeat_byte(0xcc)))
            .expect("insert");
        store
            .insert_state(H256::ZERO, bare_state())
            .expect("insert");
        store
            .set_time_ms(seconds_to_milliseconds(
                GENESIS_TIME + 5 * Config::mainnet().seconds_per_slot,
            ))
            .unwrap();
        let mut server = beacon_server(store);
        server.custody_columns = CUSTODY.to_vec();

        let held = fulu_block_with_commitments(&server.store, 2);
        let held_root = held.message_hash_tree_root();
        server
            .on_block(held.clone(), ImportTimings::default())
            .await;
        assert!(server.blocks_awaiting_columns.contains_key(&held_root));

        let child = fulu_block(held_root, held.slot() + 1, 0);
        let child_root = child.message_hash_tree_root();
        let grandchild = fulu_block(child_root, held.slot() + 2, 0);
        let grandchild_root = grandchild.message_hash_tree_root();

        for block in [child, grandchild] {
            let mut queue = VecDeque::new();
            let outcome = server
                .process_or_pend_block(block, ImportTimings::default(), &mut queue)
                .await;
            assert_eq!(outcome, None, "a block with a held ancestor pends");
            assert!(
                queue.is_empty(),
                "the held ancestor must not be queued for another import"
            );
        }

        // Each waits on its own parent, so the held block's release cascades
        // down the chain one import at a time.
        assert!(server.blocks_awaiting_columns.contains_key(&held_root));
        assert_eq!(
            server.pending_blocks.get(&held_root),
            Some(&HashSet::from([child_root]))
        );
        assert_eq!(
            server.pending_blocks.get(&child_root),
            Some(&HashSet::from([grandchild_root]))
        );
    }

    // -----------------------------------------------------------------
    // The test above proves the cascade cannot livelock; it does not prove
    // the fix's whole point, that a released parent actually unblocks what
    // was waiting on it. It cannot: `fork_choice::on_block` requires a real
    // BLS-signed RANDAO reveal and proposer signature, which a
    // structurally-fake block never has, so its own release attempt takes
    // the `Err` arm and never reaches `collect_pending_children`.
    //
    // Building a block that clears real verification needs a genuinely
    // signed fulu state: a validator with a real BLS keypair whose
    // effective balance and activation make it the deterministic proposer,
    // a RANDAO reveal and proposer signature computed over that state's own
    // domains, a `state_root` matching the actual resulting post-state, and
    // a sync aggregate set to the zero-participant identity-point
    // convention rather than left at its all-zero default. `crate::beacon::bls`
    // cannot even produce half of that today: it wraps `blst`'s
    // verification functions only (`verify`, `aggregate_verify`, ...), with
    // no `sign`, and `fulu::BeaconState` alone carries sync committees,
    // deposit/exit/consolidation churn queues, and a participation registry
    // beyond what a hand-built state can fake its way past. That is exactly
    // the spec-fixture machinery this crate does not own; `ethlambda-blockchain`
    // depends on `ethlambda-test-fixtures` only to *deserialize* downloaded
    // leanSpec vectors, not to synthesize new ones, and no such vector
    // targets this implementation-specific regression.
    //
    // What the test below instead exercises is the nearest reachable case:
    // `process_or_pend_block`'s *other* early return, the "beacon block
    // already in the store" branch just above the `process_block` call, for
    // a root whose post-state exists by the time `on_block` re-delivers it
    // (the same shape a redelivery racing an independent import would
    // leave). That branch calls `collect_pending_children` directly without
    // ever constructing an `ImportOutcome` — a different line than the
    // fix's own `Ok(ImportOutcome::Imported)` arm, but the same promise: a
    // root with a post-state must not leave its parked children behind. It
    // is real production code, not a fake, and seeding the state this way
    // is indistinguishable to it from that state having arrived by any
    // other route.
    //
    // It is not a regression guard for the `Held`/`Imported` distinction
    // itself: reverting that distinction alone would not make this test
    // fail, since the parent here never reaches `process_block` to begin
    // with. `_ if !is_new` — `process_block`'s own no-crypto route to
    // `Ok(ImportOutcome::Imported)` — is unreachable from `on_block` for the
    // same reason: `process_or_pend_block`'s guard intercepts a root whose
    // state already exists before `process_block` is ever called, so
    // `process_block` only ever sees `is_new == true` through this caller.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn releasing_a_parent_whose_post_state_already_exists_drains_its_parked_child() {
        let store = beacon_store(GENESIS_TIME, 0);
        let mut server = beacon_server(store);
        server.custody_columns = CUSTODY.to_vec();

        let parent = fulu_block_with_commitments(&server.store, 2);
        let parent_root = parent.message_hash_tree_root();
        let slot = parent.slot();
        server.hold_block_for_columns(parent.clone(), slot, ImportTimings::default());

        // A child parked behind the still-held parent, seeded directly in
        // the same shape `process_or_pend_block`'s "parent missing" branch
        // leaves one in: readable back by root, and recorded in both
        // pending maps. `a_childs_fan_out_does_not_livelock_a_held_parent`
        // above already proves a child arriving that way lands here; this
        // test starts from that end state to isolate the release side alone.
        let child = fulu_block(parent_root, slot + 1, 0);
        let child_root = child.message_hash_tree_root();
        server
            .store
            .insert_pending_block(child_root, child)
            .expect("insert");
        server
            .pending_blocks
            .insert(parent_root, HashSet::from([child_root]));
        server.pending_block_parents.insert(child_root, parent_root);

        // Every custody column arrives.
        for index in CUSTODY {
            let sidecar = sidecar_for(&parent, index);
            server
                .store
                .put_data_column_sidecar(slot, &parent_root, index, sidecar.to_ssz())
                .unwrap();
        }

        // The parent's post-state exists before release runs, standing in
        // for whatever independent path put it there; `bare_state` needs no
        // parent of its own to diff against (see its own doc), so this
        // writes a plain snapshot under `parent_root` with no further setup.
        server
            .store
            .insert_state(parent_root, bare_state())
            .expect("insert");

        server.release_block_if_columns_complete(parent_root).await;

        // `collect_pending_children` ran: the child is gone from both
        // pending maps, whatever its own (real, crypto-checked) re-import
        // attempt then did with it.
        assert!(!server.pending_blocks.contains_key(&parent_root));
        assert!(!server.pending_block_parents.contains_key(&child_root));
    }

    #[tokio::test]
    async fn a_tick_releases_a_held_block_whose_columns_landed_without_waking_it() {
        let store = beacon_store(GENESIS_TIME, 0);
        let mut server = beacon_server(store);
        server.custody_columns = CUSTODY.to_vec();

        let block = fulu_block_with_commitments(&server.store, 2);
        let block_root = block.message_hash_tree_root();
        let slot = block.slot();
        server.hold_block_for_columns(block, slot, ImportTimings::default());

        // Every custody column is written straight to the store, the way a
        // fetched sidecar that never reached `release_block_if_columns_complete`
        // would leave it: the hold is satisfied and nothing knows.
        for index in CUSTODY {
            let sidecar = sidecar_for(
                &server.store.get_signed_block(&block_root).unwrap().unwrap(),
                index,
            );
            server
                .store
                .put_data_column_sidecar(slot, &block_root, index, sidecar.to_ssz())
                .unwrap();
        }
        // Same stand-in as `releasing_a_parent_whose_post_state_already_exists_
        // drains_its_parked_child`: a post-state under this root sends the
        // re-import down `process_or_pend_block`'s already-in-store branch
        // rather than through crypto a hand-built block cannot pass.
        server
            .store
            .insert_state(block_root, bare_state())
            .expect("insert");

        server.redrive_held_blocks().await;

        assert!(
            !server.blocks_awaiting_columns.contains_key(&block_root),
            "a block whose columns are all present must not stay held"
        );
    }

    /// A release removes the hold *before* re-importing, which is what makes
    /// the re-entry terminate. But the re-import can then fail for a reason
    /// that has nothing to do with columns, and until it put the hold back
    /// that left the block tracked by nothing at all: neither
    /// `redrive_held_blocks` nor `evict_held_blocks_at_or_below_finality`
    /// could still see it, so it and every descendant waited for a restart.
    ///
    /// Driven through the real engine client against a closed port, since an
    /// unreachable execution client is exactly the production shape of this:
    /// `beacon_engine::ask` spends its retry ladder and `process_block`
    /// answers `Held` with nothing recorded.
    #[tokio::test]
    async fn a_release_that_gets_no_engine_verdict_puts_the_block_back_on_hold() {
        let store = beacon_store(GENESIS_TIME, 0);
        let mut server = beacon_server(store);
        server.custody_columns = CUSTODY.to_vec();
        // Port 1 has nothing listening, so every attempt is refused at once
        // rather than waiting out `ENGINE_TIMEOUT`.
        server.engine = Some(
            EngineClient::new(
                "http://127.0.0.1:1".to_string(),
                ethlambda_engine::JwtSecret::new([0u8; 32]),
            )
            .expect("client builds"),
        );

        let block = fulu_block_with_commitments(&server.store, 2);
        let block_root = block.message_hash_tree_root();
        let parent_root = block.parent_root();
        let slot = block.slot();
        server.hold_block_for_columns(block, slot, ImportTimings::default());

        // The parent's post-state, so the re-import reaches `process_block`
        // rather than parking the block on a missing parent.
        server
            .store
            .insert_state(parent_root, bare_state())
            .expect("insert");

        for index in CUSTODY {
            let sidecar = sidecar_for(
                &server.store.get_signed_block(&block_root).unwrap().unwrap(),
                index,
            );
            server
                .store
                .put_data_column_sidecar(slot, &block_root, index, sidecar.to_ssz())
                .unwrap();
        }

        server.release_block_if_columns_complete(block_root).await;

        assert_eq!(
            server.blocks_awaiting_columns.get(&block_root),
            Some(&slot),
            "a re-import that produced no post-state must leave the block \
             somewhere the per-slot redrive can still reach it"
        );
        assert!(
            !server
                .store
                .has_state(&block_root)
                .expect("DB read should succeed"),
            "the premise: the engine never answered, so nothing imported"
        );
    }

    #[tokio::test]
    async fn a_tick_leaves_a_block_held_while_a_column_is_still_missing() {
        let store = beacon_store(GENESIS_TIME, 0);
        let mut server = beacon_server(store);
        server.custody_columns = CUSTODY.to_vec();

        let block = fulu_block_with_commitments(&server.store, 2);
        let block_root = block.message_hash_tree_root();
        let slot = block.slot();
        server.hold_block_for_columns(block, slot, ImportTimings::default());

        // All but one column. The re-drive re-asks for the last one; what it
        // must not do is decide the block is available without it.
        for index in &CUSTODY[..CUSTODY.len() - 1] {
            let sidecar = sidecar_for(
                &server.store.get_signed_block(&block_root).unwrap().unwrap(),
                *index,
            );
            server
                .store
                .put_data_column_sidecar(slot, &block_root, *index, sidecar.to_ssz())
                .unwrap();
        }

        server.redrive_held_blocks().await;

        assert!(
            server.blocks_awaiting_columns.contains_key(&block_root),
            "one missing column is still a missing column"
        );
    }

    #[tokio::test]
    async fn a_new_hold_is_left_to_gossip_and_the_tick_asks_for_what_is_still_missing() {
        let store = beacon_store(GENESIS_TIME, 0);
        let (mut server, p2p) = beacon_server_recording(store);
        server.custody_columns = CUSTODY.to_vec();

        let block = fulu_block_with_commitments(&server.store, 2);
        let block_root = block.message_hash_tree_root();
        let slot = block.slot();
        server.hold_block_for_columns(block, slot, ImportTimings::default());

        assert!(
            p2p.fetches.lock().unwrap().is_empty(),
            "a new hold must not ask peers for columns gossip is still delivering"
        );

        // Gossip delivers all but the last column before the tick.
        let (last, delivered) = CUSTODY.split_last().expect("CUSTODY is not empty");
        for index in delivered {
            let sidecar = sidecar_for(
                &server.store.get_signed_block(&block_root).unwrap().unwrap(),
                *index,
            );
            server
                .store
                .put_data_column_sidecar(slot, &block_root, *index, sidecar.to_ssz())
                .unwrap();
        }

        server.redrive_held_blocks().await;

        let fetches = p2p.fetches.lock().unwrap();
        let [request] = fetches.as_slice() else {
            panic!(
                "the tick must ask exactly once, got {} requests",
                fetches.len()
            );
        };
        assert_eq!(request.block_root, block_root);
        assert!(!request.needs_block, "the held block is already in the DB");
        assert_eq!(
            request.columns,
            vec![*last],
            "only the column gossip did not deliver"
        );
    }

    /// The counterpart above: a block that is already older than the current
    /// slot when it is held gets no gossip window left to race, so this is
    /// where it gets its first ask rather than the next redrive.
    #[tokio::test]
    async fn holding_a_block_older_than_the_current_slot_asks_for_its_columns_at_once() {
        let store = beacon_store_at_slot_10();
        let config = store.config();
        let current_slot = fork_choice::get_current_slot(&store, &config);
        let (mut server, p2p) = beacon_server_recording(store);
        server.custody_columns = CUSTODY.to_vec();

        // One past the store's finalized slot, the shape a range-synced
        // block arrives in: well behind `current_slot`.
        let block = fulu_block_with_commitments(&server.store, 2);
        let block_root = block.message_hash_tree_root();

        server.hold_block_for_columns(block, current_slot, ImportTimings::default());

        let fetches = p2p.fetches.lock().unwrap();
        let [request] = fetches.as_slice() else {
            panic!(
                "an old block must be asked for at hold time, got {} requests",
                fetches.len()
            );
        };
        assert_eq!(request.block_root, block_root);
        assert!(!request.needs_block, "the held block is already in the DB");
        assert_eq!(
            request.columns,
            CUSTODY.to_vec(),
            "neither custody column has arrived yet"
        );
    }
}
