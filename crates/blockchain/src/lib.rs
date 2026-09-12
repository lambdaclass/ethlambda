use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant, SystemTime};

use ethlambda_network_api::{BlockChainToP2PRef, BlockSource, InitP2P};
use ethlambda_state_transition::beacon::error::Error as BeaconError;
use ethlambda_state_transition::beacon::fork_choice;
use ethlambda_state_transition::is_proposer;
use ethlambda_storage::{ALL_TABLES, Chain, Store};
use ethlambda_types::{
    ShortRoot,
    aggregator::AggregatorController,
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    beacon::containers::SignedBeaconBlock,
    block::SignedBlock,
    chain_config::ChainConfig,
    primitives::H256,
};

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
use spawned_concurrency::tasks::{Actor, ActorRef, ActorStart, Context, Handler, send_after};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::block_builder::ProposerConfig;
use crate::events::ChainEventSnapshot;
use crate::store::StoreError;

pub use events::{ChainEvent, EventBus, Topic, UnknownTopic};

pub mod aggregation;
pub mod block_builder;
pub(crate) mod coverage;
pub mod events;
pub(crate) mod fork_choice_tree;
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
pub const MAXIMUM_GOSSIP_CLOCK_DISPARITY: Duration = Duration::from_millis(500);

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

/// Current UNIX timestamp in milliseconds.
fn unix_now_ms() -> u64 {
    SystemTime::UNIX_EPOCH
        .elapsed()
        .expect("already past the unix epoch")
        .as_millis() as u64
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
            proposer_config,
        } = config;

        metrics::set_is_aggregator(aggregator.is_enabled());
        metrics::set_node_sync_status(metrics::SyncStatus::Idle);
        let time_config = store.config().time_grid();
        let mut key_manager = key_manager::KeyManager::new(validator_keys);

        // Catch XMSS keys up to the current slot before the first tick
        // The store clock doesn't work here: after an offline gap it lags wall-clock by
        // exactly the gap we need to catch up through
        let now_ms = unix_now_ms();
        let current_slot = (now_ms.saturating_sub(time_config.genesis_time_ms())
            / time_config.milliseconds_per_slot) as u32;
        key_manager.advance_keys_to(current_slot);

        let lean = LeanDuties {
            key_manager,
            aggregator,
            current_aggregation: None,
            attestation_committee_count,
            subscribed_subnets,
            proposer_config,
            pre_merge_coverage: None,
        };

        Self::start_actor(
            store,
            SyncStatusTracker::new(gate_duties),
            sync_status_controller,
            events,
            ChainDuties::Lean(Box::new(lean)),
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
    pub fn spawn_beacon(
        store: Store,
        sync_status_controller: SyncStatusController,
        events: EventBus,
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
        )
    }

    /// Start the actor and arm its first tick: everything the two public
    /// constructors above do identically, once.
    ///
    /// The first `Tick` is armed for genesis, or immediately when genesis is
    /// already past (`unwrap_or_default` on a negative duration). That is the
    /// contract both chains' tick loops are entered through, which is why it
    /// is stated in one place rather than per chain.
    fn start_actor(
        store: Store,
        sync_status: SyncStatusTracker,
        sync_status_controller: SyncStatusController,
        events: EventBus,
        duties: ChainDuties,
    ) -> BlockChain {
        let genesis_time = store.config().genesis_time;

        let handle = BlockChainServer {
            store,
            p2p: None,
            pending_blocks: HashMap::new(),
            pending_block_parents: HashMap::new(),
            last_tick_instant: None,
            sync_status,
            sync_status_controller,
            events,
            duties,
        }
        .start();
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

    /// Proposer-side block-building policy
    proposer_config: ProposerConfig,

    /// Pre-merge `new_payloads` snapshot for the attestation aggregate coverage
    /// report. Captured at the end-of-slot promote (interval 4), read at the
    /// next slot boundary. Owned solely by the actor and only touched from the
    /// single-threaded message loop, so no synchronization is needed.
    /// Observability-only.
    pre_merge_coverage: Option<coverage::CoverageSnapshot>,
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
        // has no validator set of its own to check.
        if self.store.chain() == Chain::Lean && self.store.head_state().validators.is_empty() {
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
            .then(|| self.get_our_proposer(slot))
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
                self.recompute_beacon_head();
            }
        }
        // `slot` above is already derived from `timestamp_ms` (the wall clock
        // at tick time), so it doubles as the wall-clock slot for the gate.
        pre_tick.diff_and_emit(&self.store, &self.events, slot);

        // Per-interval duties for this tick. Lean-only, so this is where a
        // beacon follower's tick ends: it has no validator duties (see
        // [`ChainDuties::Beacon`]), and everything a tick owes it happened
        // above.
        self.run_interval_duties(interval, slot, is_aggregator, ctx)
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
    /// toggles the role underneath it.
    async fn run_interval_duties(
        &mut self,
        interval: SlotInterval,
        slot: u64,
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
                    .get_our_proposer(next_slot)
                    .filter(|_| self.sync_status.duties_allowed());

                if let Some(validator_id) = next_proposer {
                    self.propose_block(next_slot, validator_id).await;
                }
            }
        }

        // Advance XMSS keys for next slot so the signing paths don't have to.
        // Here rather than back in `on_tick` because it is a validator duty
        // like the rest of this function: a beacon follower holds no keys, and
        // the early return above is what keeps it from asking for them.
        self.lean_mut()
            .key_manager
            .advance_keys_to((slot + 1) as u32);
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
        let next_proposer = self
            .get_our_proposer(slot + 1)
            .filter(|_| self.sync_status.duties_allowed());
        let max_jobs = if next_proposer.is_some() {
            1
        } else {
            MAX_AGGREGATION_JOBS
        };

        let Some(snapshot) = aggregation::snapshot_aggregation_inputs(&self.store, slot, max_jobs)
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
    fn get_our_proposer(&self, slot: u64) -> Option<u64> {
        let ChainDuties::Lean(lean) = &self.duties else {
            return None;
        };
        let head_state = self.store.head_state();
        let num_validators = head_state.validators.len() as u64;

        lean.key_manager
            .validator_ids()
            .into_iter()
            .find(|&vid| is_proposer(vid, slot, num_validators))
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

        self.process_and_publish_block(slot, validator_id, signed_block);
    }

    /// Import a freshly built block locally, then publish it to gossip. On
    /// import failure, logs and counts it, and returns without publishing.
    /// Lean-only: the block this builds and imports is always a lean
    /// [`SignedBlock`].
    fn process_and_publish_block(
        &mut self,
        slot: u64,
        validator_id: u64,
        signed_block: SignedBlock,
    ) {
        if let Err(err) = self.process_block(SignedBeaconBlock::Lean(signed_block.clone())) {
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
    fn process_block(&mut self, signed_block: SignedBeaconBlock) -> Result<(), ImportError> {
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

        match signed_block {
            SignedBeaconBlock::Lean(lean_block) => {
                store::on_block(&mut self.store, lean_block)?;
            }
            // Already imported: skip the whole transition rather than redo
            // it. Lean's `store::on_block` makes exactly this `has_state`
            // check itself and returns `Ok` early; beacon's `on_block` has no
            // such guard, so without this a re-delivered block pays a full
            // state transition (two whole-state merkleizations) and a state
            // write to reach the same store it already produced. Range sync
            // and gossip overlap at the tip make that the common case, not a
            // rare one.
            _ if !is_new => {}
            beacon_block => {
                let config = self.store.config();
                // Extracted before `beacon_block` moves into `fork_choice::on_block`
                // below, which takes ownership of it.
                let (attestations, slashings) = fork_choice::block_operations(&beacon_block);
                fork_choice::on_block(
                    &mut self.store,
                    beacon_block,
                    &config,
                    &fork_choice::DataAvailability::NotRequired,
                )?;

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
            }
        }

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

        self.refresh_chain_metrics();

        // Lean-only: a beacon follower tracks no validator keys of its own.
        if let ChainDuties::Lean(lean) = &self.duties {
            metrics::update_validators_count(lean.key_manager.validator_ids().len() as u64);
        }

        for table in ALL_TABLES {
            metrics::update_table_bytes(table.name(), self.store.estimate_table_bytes(table));
        }
        Ok(())
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
    fn on_block(&mut self, signed_block: SignedBeaconBlock) {
        let mut queue = VecDeque::new();
        queue.push_back(signed_block);
        self.run_import_cascade(queue);

        if self.store.chain() == Chain::Beacon {
            // `lean_current_slot` had the same single writer the head did, so
            // both gauges went stale together on a catching-up follower and
            // `lean_current_slot - lean_head_slot` was a difference between
            // two stale numbers rather than the head lag every panel and
            // alert reads it as. Published from the wall clock rather than
            // the store clock, which only `on_tick` and an early arrival
            // advance.
            metrics::update_current_slot(self.wall_clock_slot());
            self.recompute_beacon_head();
        }
    }

    /// Drain `queue`, importing each block and enqueuing any pending children
    /// its import unblocks, iteratively rather than recursively so a long
    /// chain of arrivals cannot overflow the stack.
    fn run_import_cascade(&mut self, mut queue: VecDeque<SignedBeaconBlock>) {
        while let Some(block) = queue.pop_front() {
            self.process_or_pend_block(block, &mut queue);
        }

        // Prune old states and blocks AFTER the entire cascade completes.
        // Running this mid-cascade would delete states that pending children
        // still need, causing re-processing loops when fallback pruning is active.
        //
        // Lean-only: `prune_old_data` prunes `BlockProof`, a table beacon
        // never writes, and deciding whether there is anything to prune costs
        // a whole-block decode (`Store::get_block_header`) on a beacon
        // directory.
        if self.store.chain() == Chain::Lean {
            self.store
                .prune_old_data()
                .expect("DB pruning should succeed");
        }
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
    fn defer_early_block(&self, block: SignedBeaconBlock, ctx: &Context<Self>) {
        let delay = Duration::from_millis(self.ms_until_slot_start(block.slot()));
        let redelivery = NewBlock {
            block,
            source: BlockSource::Deferred,
        };
        send_after(delay, ctx.clone(), redelivery);
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
    fn recompute_beacon_head(&mut self) {
        let _timing = metrics::time_beacon_head_compute();
        let config = self.store.config();
        if let Err(err) = fork_choice::get_head(&mut self.store, &config) {
            warn!(%err, "Failed to compute beacon head");
            return;
        }
        if let Some((head_slot, _)) = self.store.beacon_head() {
            metrics::update_head_slot(head_slot);
        }
    }

    /// Try to process a single block. If its parent state is missing, store it
    /// as pending. On success, collect any unblocked children into `queue` for
    /// the caller to process next (iteratively, avoiding deep recursion).
    fn process_or_pend_block(
        &mut self,
        signed_block: SignedBeaconBlock,
        queue: &mut VecDeque<SignedBeaconBlock>,
    ) {
        let slot = signed_block.slot();
        let block_root = signed_block.message_hash_tree_root();
        let parent_root = signed_block.parent_root();
        let proposer = signed_block.proposer_index();

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
            return;
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
            return;
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
                return;
            }
        }

        // Check if parent state exists before attempting to process
        if !self
            .store
            .has_state(&parent_root)
            .expect("DB read should succeed")
        {
            info!(%slot, %parent_root, %block_root, "Block parent missing, storing as pending");

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
                    // Parent state available — enqueue for processing, cascade
                    // handles the rest via the outer loop.
                    let fetched = self
                        .store
                        .get_signed_block(&missing_root)
                        .expect("header and parent state exist, so the full signed block must too")
                        .unwrap();
                    queue.push_back(fetched);
                    return;
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
            return;
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
        match self.process_block(signed_block) {
            Ok(()) => {
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
    /// Chain-agnostic, and deliberately so: `fetch_block` carries a root and
    /// nothing else, and the p2p layer picks the protocol from the wire it
    /// already speaks, so neither this method nor the actor protocol grows a
    /// chain argument. Deduplication is the p2p layer's too, keyed on the root.
    fn request_missing_block(&mut self, block_root: H256) {
        if let Some(ref p2p) = self.p2p {
            let _ = p2p
                .fetch_block(block_root)
                .inspect(|_| info!(%block_root, "Requested missing block from network"))
                .inspect_err(
                    |err| error!(%block_root, %err, "Failed to send FetchBlock message to P2P"),
                );
        }
    }

    /// Move pending children of `parent_root` into the work queue for iterative
    /// processing. This replaces the old recursive `process_pending_children`.
    fn collect_pending_children(
        &mut self,
        parent_root: H256,
        queue: &mut VecDeque<SignedBeaconBlock>,
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

            queue.push_back(fetched);
        }
    }

    /// Recursively discard a block and all its pending descendants.
    ///
    /// Used when a block is rejected (e.g., at/below finalized slot) to clean up
    /// children that would otherwise remain stuck in the pending maps indefinitely.
    fn discard_pending_subtree(&mut self, block_root: H256) {
        let Some(child_roots) = self.pending_blocks.remove(&block_root) else {
            return;
        };
        for child_root in child_roots {
            self.pending_block_parents.remove(&child_root);
            self.discard_pending_subtree(child_root);
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
    NewAggregatedAttestation, NewAttestation, NewBlock,
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
                self.defer_early_block(msg.block, ctx);
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
        self.on_block(msg.block);
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
    use ethlambda_storage::backend::InMemoryBackend;
    use ethlambda_types::beacon::config::Config;
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
        let backend = Arc::new(InMemoryBackend::default());
        let anchor_root = H256::ZERO;
        let anchor_checkpoint = Checkpoint {
            root: anchor_root,
            slot: finalized_slot,
        };
        Store::init_beacon(
            backend,
            genesis_time,
            Config::mainnet(),
            anchor_root,
            anchor_checkpoint,
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

        let _ =
            BlockChain::spawn_beacon(store, SyncStatusController::default(), EventBus::default());
    }
}
