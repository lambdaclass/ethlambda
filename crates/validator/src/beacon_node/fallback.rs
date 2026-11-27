//! Ranked failover across several beacon nodes.
//!
//! # Queries: the best-ranked node that answers
//!
//! A request walks the nodes in [`NodeHealth::ranked`]'s order and returns the
//! first answer. The order is [`Tier`]'s, as Lighthouse ranks its nodes: synced
//! and validated first; then synced but optimistic, or with the execution
//! client offline; then syncing, or more than [`super::health::SYNC_TOLERANCE`]
//! slots behind by the node's own `sync_distance`; then nodes not probed yet;
//! then failing ones. Command-line order breaks ties, so a single healthy node,
//! or several equally healthy ones, are asked exactly as listed. The probe that
//! feeds it runs once a slot ([`super::health::run`]), and a request that times
//! out or cannot connect ranks its node failing at once, until a probe sent
//! after it answers ([`NodeHealth::record_request_failure`]): a hung node costs one
//! request timeout per probe, not one per request.
//!
//! The nodes themselves stay in command-line order, and only a list of
//! positions is ranked, so a [`Producer`] still names the node that produced a
//! blinded block.
//!
//! # Signed messages: one node, or every node with `--broadcast`
//!
//! By default a signed message goes to the first node in the walk that accepts
//! it, as a query does. [`Broadcast`] sends a chosen kind to every node at
//! once instead, succeeding when any accepts, so it reaches the network through
//! every node's gossip mesh rather than one. A node ranked failing is sent it
//! only when none of the others accepted, so a hung node does not hold back
//! the answer. Subscriptions and the other state installed on a node
//! ([`FallbackBeaconNode::try_all`]) go to every node whatever the flag says,
//! and a blinded block only ever goes back to its producer. Every message is
//! signed once, before it reaches this module, so slashing protection records
//! it once however many nodes are sent it.
//!
//! # Only nodes on this client's chain
//!
//! Every node carries a usable flag, and every call here skips a node whose
//! flag is down: a node on another chain answers calls without complaint and
//! gets signatures it will reject, or, worse, ones its own chain accepts and
//! this client's slashing-protection record has not seen. The flags start up
//! (see [`FallbackBeaconNode::new`]) and are set by
//! [`FallbackBeaconNode::establish`] at startup and
//! [`FallbackBeaconNode::check_nodes`] afterwards, which compare each node's
//! genesis and spec with the chain the client runs on
//! ([`crate::chain_check::first_chain_difference`]). The order of the nodes
//! never changes, since a [`Producer`] is a position in it.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use ethlambda_types::beacon::builder::SignedValidatorRegistrationV1;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::altair;
use ethlambda_types::beacon::containers::gloas;
use ethlambda_types::beacon::containers::shared::{AttestationData, SignedVoluntaryExit};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch, Root, Slot, ValidatorIndex};
use tracing::{debug, info, warn};

use crate::beacon_node::block_contents::{ProducedBlock, Producer};
use crate::beacon_node::dto::{
    CommitteeSubscriptionDto, ProposerPreparationDto, SingleAttestationDto,
    SyncCommitteeSubscriptionDto, SyncDutyDto,
};
use crate::beacon_node::health::{
    NodeHealth, Probe, Reply, Standing, SyncStatus, SyncVerdict, Tier,
};
use crate::beacon_node::{
    AggregateAttestation, AttesterDuties, BeaconNodeApi, BlockRequest, Delivery, Genesis, Liveness,
    ProposerDuties, PtcDuties, Published, SignedAggregates, ValidatorDetails, ValidatorEntry,
};
use crate::chain_check::{
    ChainId, ExpectedNetwork, Served, first_chain_difference, first_identity_difference,
};
use crate::error::{Error, Result};

/// The boxed future `#[async_trait]` desugars a trait method call into,
/// borrowed from the receiver (and, for methods that take borrowed arguments,
/// from those too). Naming it lets [`FallbackBeaconNode::try_each`] state that
/// the future it gets back is tied to one caller-chosen lifetime `'p`, shared
/// by the node reference and whatever else the closure captures, rather than
/// to `Self`.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// How long a broadcast waits for the nodes still sending once one node has
/// accepted. The message is on the network by then, and a caller with a
/// deadline (a proposal's is the attestation offset, 3 s into a 12 s gloas
/// slot) would otherwise wait out a hung node's whole request timeout, be cut
/// at its deadline. A node still sending when this runs out is cut off, but
/// not ranked failing for it: a node that imports a block more slowly than the
/// fastest one, or uploads a large envelope over a slower link, answers late
/// every time, and ranking it failing would cut it out of every broadcast
/// until the next probe, slot after slot. A node that really hung is ranked
/// failing by its probe, and until then costs each broadcast this much.
const BROADCAST_GRACE: Duration = Duration::from_millis(500);

/// How long an envelope's producer is waited on alone before the other nodes
/// are sent the envelope too, under `--broadcast blocks`. Long enough for a
/// producer holding the block to answer, so the others get the envelope a
/// round trip after it; short enough that a producer that holds the request
/// open (one that answered 202 and never imported the block waits for it) does
/// not keep the envelope from every node until the proposal's deadline.
const PRODUCER_HEAD_START: Duration = BROADCAST_GRACE;

/// What a caller of [`FallbackBeaconNode::broadcast_to_all`] has already done
/// with one node, which the broadcast then leaves out of its own sends.
enum Sent<'p, T> {
    /// Nothing: every node is the broadcast's.
    Nothing,
    /// Sent and answered; `accepted` counts as an acceptance for the
    /// broadcast's rules.
    Answered { position: usize, accepted: bool },
    /// Sent and not answered yet: the broadcast waits on it as on its own
    /// sends.
    Pending {
        position: usize,
        send: BoxFuture<'p, Result<T>>,
    },
}

/// Which nodes a request may be sent to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// Every node.
    Every,
    /// Every node but those whose last sync probe reported syncing or
    /// optimistic, or got no answer, for the calls the Beacon API gives no 503
    /// for in that state. A node with no probe to read is still asked (see
    /// [`Standing::may_serve_ungated`]).
    SkipUnsynced,
    /// Every node but the one at this position, which the caller has already
    /// asked.
    EveryBut(usize),
}

/// One kind of signed message `--broadcast` can send to every node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BroadcastTopic {
    /// Attestations, aggregates and payload attestations.
    Attestations,
    /// Blocks and execution payload envelopes. Never a blinded block, which
    /// goes back to its producer alone.
    Blocks,
    /// Sync committee messages and contributions.
    SyncCommittee,
    /// Committee and sync committee subscriptions, fee recipient preparations,
    /// builder registrations and proposer preferences. Always sent to every
    /// node, so naming it changes nothing; accepted as Lighthouse's flag
    /// accepts it.
    Subscriptions,
    /// `none`, which turns Lighthouse's default subscriptions broadcast off.
    /// Subscriptions always go to every node here, so it changes nothing;
    /// accepted so a Lighthouse command line carries over.
    Nothing,
}

impl BroadcastTopic {
    /// Every topic, by the name the command line takes.
    pub const NAMES: [(&'static str, Self); 5] = [
        ("attestations", Self::Attestations),
        ("blocks", Self::Blocks),
        ("sync-committee", Self::SyncCommittee),
        ("subscriptions", Self::Subscriptions),
        ("none", Self::Nothing),
    ];
}

impl std::str::FromStr for BroadcastTopic {
    type Err = String;

    fn from_str(name: &str) -> std::result::Result<Self, Self::Err> {
        Self::NAMES
            .iter()
            .find(|(known, _)| *known == name)
            .map(|(_, topic)| *topic)
            .ok_or_else(|| {
                let known: Vec<&str> = Self::NAMES.iter().map(|(known, _)| *known).collect();
                format!(
                    "unknown broadcast topic {name:?}; expected one of {}",
                    known.join(", ")
                )
            })
    }
}

/// Which signed messages go to every node at once, rather than to the first
/// node in the walk that accepts them. All off by default, as Lighthouse's
/// `--broadcast` defaults to subscriptions alone, which always go to every
/// node here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Broadcast {
    pub attestations: bool,
    pub blocks: bool,
    pub sync_committee: bool,
}

impl FromIterator<BroadcastTopic> for Broadcast {
    fn from_iter<I: IntoIterator<Item = BroadcastTopic>>(topics: I) -> Self {
        let mut broadcast = Self::default();
        for topic in topics {
            match topic {
                BroadcastTopic::Attestations => broadcast.attestations = true,
                BroadcastTopic::Blocks => broadcast.blocks = true,
                BroadcastTopic::SyncCommittee => broadcast.sync_committee = true,
                BroadcastTopic::Subscriptions | BroadcastTopic::Nothing => {}
            }
        }
        broadcast
    }
}

/// What an error says when every node was skipped for being on another chain
/// (or not yet known to be on this one), so no request was made at all.
const NO_USABLE_NODE: &str = "no configured beacon node is on this client's chain";

/// How many epochs after a node's last answer the configuration it served is
/// still kept: the epoch it answered in and the one after, which covers a node
/// that misses a round or restarts. It is what the duty offsets are read from;
/// a say in the fork schedule needs a more recent answer (see
/// [`MISSES_BEFORE_SAY_IS_LOST`]).
const SERVED_FOR_EPOCHS: u64 = 1;

/// How many checks in a row a node may fail before it loses its say in the
/// fork schedule (see [`Served::say`]). A check runs every slot, so this is a
/// few slots.
///
/// Losing the say on the first failure let one timeout of a correct node
/// leave a single misconfigured one to put a fork on the client's schedule,
/// or postpone one, for good: the merge never unschedules a fork, so the
/// correct node was then refused once the fork's epoch came. A node that
/// restarts for an upgrade is away for longer than this, so it still loses
/// its say in time for the upgraded nodes' schedule to be followed, unless
/// the change comes within this many slots of the fork's epoch.
pub(crate) const MISSES_BEFORE_SAY_IS_LOST: u64 = 3;

/// [`NodeState::misses`] for a node that has not answered a check on this
/// client's chain since it was configured or last found on another one.
const NEVER_ANSWERED: u64 = u64::MAX;

/// How long startup waits between rounds while no beacon node answers, as
/// Lighthouse's validator client does (`RETRY_DELAY`).
const STARTUP_RETRY: std::time::Duration = std::time::Duration::from_secs(2);

/// What asking one node about its chain came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeAnswer {
    /// On this client's chain, with the configuration it serves.
    Compatible(Box<Config>),
    /// On another chain: the first field that differs, or the preset error.
    Incompatible(String),
    /// Did not answer both requests, or answered something unusable. Says
    /// nothing about its chain, so its flag is left as it is.
    Unreachable(String),
}

/// One node's genesis and spec, as the chain it is on.
async fn ask<B: BeaconNodeApi>(node: &B) -> Result<ChainId> {
    let (genesis, spec) = futures_util::future::join(node.genesis(), node.spec()).await;
    // The spec first: a node on another preset fails it with the error that
    // says so, whatever its genesis did.
    let config = spec?;
    Ok(ChainId {
        genesis: genesis?,
        config,
    })
}

/// A node's `asked` chain judged against `ours`.
fn classify(ours: &ChainId, asked: Result<ChainId>, current_epoch: u64) -> NodeAnswer {
    match asked {
        Ok(theirs) => match first_chain_difference(ours, &theirs, current_epoch) {
            None => NodeAnswer::Compatible(Box::new(theirs.config)),
            Some(difference) => NodeAnswer::Incompatible(difference),
        },
        Err(err @ Error::Preset(_)) => NodeAnswer::Incompatible(err.to_string()),
        Err(err) => NodeAnswer::Unreachable(err.to_string()),
    }
}

/// What the chain check keeps about one configured node, beside it in
/// [`FallbackBeaconNode::states`].
struct NodeState {
    /// Whether the node is on this client's chain. Every call skips a node
    /// whose flag is down.
    usable: AtomicBool,
    /// The epoch the node's last unusable-node warning was for, so a node
    /// that stays unusable warns once per epoch rather than once per slot.
    /// `u64::MAX` is never.
    warned_at: AtomicU64,
    /// The configuration the node last served while on this client's chain,
    /// with the epoch it served it in: what the schedule is followed from.
    /// Kept through a check the node does not answer, so one missed round
    /// does not drop its schedule, but only for [`SERVED_FOR_EPOCHS`]: a node
    /// that stays away has no say in a schedule the network may have moved
    /// since. Dropped when the node turns out to be on another chain.
    served: Mutex<Option<(Config, u64)>>,
    /// How many checks of the node have failed in a row since it last
    /// answered one on this client's chain, or [`NEVER_ANSWERED`]. Fewer than
    /// [`MISSES_BEFORE_SAY_IS_LOST`] is what gives it a say in the fork
    /// schedule (see [`Served::say`]).
    misses: AtomicU64,
}

impl NodeState {
    /// Usable, as every node starts: see [`FallbackBeaconNode::new`].
    fn new() -> Self {
        Self {
            usable: AtomicBool::new(true),
            warned_at: AtomicU64::new(u64::MAX),
            served: Mutex::new(None),
            misses: AtomicU64::new(NEVER_ANSWERED),
        }
    }

    fn set_served(&self, config: Option<(Config, u64)>) {
        *self.served.lock().unwrap_or_else(PoisonError::into_inner) = config;
    }

    fn has_say(&self) -> bool {
        self.misses.load(Ordering::SeqCst) < MISSES_BEFORE_SAY_IS_LOST
    }
}

/// A `BeaconNodeApi` backed by a list of others, answering from the
/// best-ranked one that succeeds.
pub struct FallbackBeaconNode<B> {
    /// In the order given, which never changes: a [`Producer`] is a position
    /// in it, so a blinded block goes back to the node that produced it. Only
    /// the walk's list of positions is ranked.
    nodes: Vec<B>,
    /// Each node's last sync probe and unanswered request, by the same
    /// positions. What orders the walk, and what the duty loop gates each slot
    /// on.
    health: Arc<NodeHealth>,
    /// The signed messages sent to every node rather than to one.
    broadcast: Broadcast,
    /// The chain check's state of each node, by position in `nodes`. Built
    /// with it and never resized, so the two always line up.
    states: Vec<NodeState>,
    /// How many times a node has been let back in (its usable flag raised
    /// from down): see [`BeaconNodeApi::readmissions`].
    readmissions: AtomicU64,
}

impl<B: BeaconNodeApi> FallbackBeaconNode<B> {
    /// Every node starts usable, so a caller that never runs a check (the
    /// one-shot `voluntary-exit` command, a test) behaves as before.
    /// [`Self::establish`] is what takes a node out.
    pub fn new(nodes: Vec<B>) -> Self {
        assert!(!nodes.is_empty(), "at least one beacon node is required");
        let health = Arc::new(NodeHealth::new(nodes.len()));
        let states = nodes.iter().map(|_| NodeState::new()).collect();
        Self {
            nodes,
            health,
            broadcast: Broadcast::default(),
            states,
            readmissions: AtomicU64::new(0),
        }
    }

    /// Send the signed messages `broadcast` names to every node. See the
    /// module doc.
    pub fn with_broadcast(mut self, broadcast: Broadcast) -> Self {
        self.broadcast = broadcast;
        self
    }

    /// Each node's last sync probe. Shared, so whatever reports on the nodes
    /// reads the records the walk is ordered by.
    pub fn health(&self) -> &Arc<NodeHealth> {
        &self.health
    }

    /// Ask every usable node for its sync status at once, each within
    /// `budget`, and record each answer, or the error in its place, as it
    /// arrives: a node that hangs holds back only its own record. `slot` is
    /// the slot the probe is taken ahead of. See [`super::health`].
    ///
    /// A node on another chain (or not checked yet) is not probed: no call
    /// goes to it, so a synced answer from it must not open the slot's gate.
    pub async fn probe(&self, slot: Slot, budget: Duration) {
        let health = &self.health;
        let asks = self.usable_nodes().map(|(position, node)| async move {
            let at = SystemTime::now();
            let answer = tokio::time::timeout(budget, node.sync_status_with_date()).await;
            // Stamped here, as the answer lands, for the clock check.
            let received = SystemTime::now();
            let (outcome, reply) = match answer {
                Ok(Ok((status, date))) => (Ok(status), Some(Reply { received, date })),
                Ok(Err(err)) => (Err(err.to_string()), None),
                Err(_) => (
                    Err(format!("no answer within {} ms", budget.as_millis())),
                    None,
                ),
            };
            let probe = Probe {
                slot,
                at,
                outcome,
                reply,
            };
            health.record(position, probe);
        });
        futures_util::future::join_all(asks).await;
    }

    fn is_usable(&self, position: usize) -> bool {
        self.states[position].usable.load(Ordering::SeqCst)
    }

    /// What [`crate::chain_check::follow_schedule`] merges at `current_epoch`:
    /// the configuration each usable node last served, with its position, in
    /// list order, and which of those nodes have a say in the fork schedule.
    ///
    /// A usable node that has never answered a check has no configuration
    /// and is left out, and so is one whose last answer is older than
    /// [`SERVED_FOR_EPOCHS`]: the duty offsets are read from the first one
    /// left, so the first node keeps its place through a round it misses.
    ///
    /// A say needs more: an answer to one of the node's last
    /// [`MISSES_BEFORE_SAY_IS_LOST`] checks. A node that stops answering
    /// keeps its configuration for the offsets, but loses its say after that
    /// many slots, so it cannot pin a fork at the epoch it last reported
    /// against every node that follows a postponement. When that epoch came,
    /// the client would activate the fork alone and refuse them all. It does
    /// not lose it on the first miss, so one timeout of a correct node does
    /// not leave a misconfigured one to move the schedule alone.
    pub fn served_configs(&self, current_epoch: u64) -> Served {
        let mut served = Served::default();
        for (position, _) in self.usable_nodes() {
            let state = &self.states[position];
            let config = state
                .served
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .filter(|(_, answered)| answered + SERVED_FOR_EPOCHS >= current_epoch)
                .map(|(config, _)| config.clone());
            let Some(config) = config else {
                continue;
            };
            served.configs.push((position, config));
            if state.has_say() {
                served.say.push(position);
            }
        }
        served
    }

    /// The nodes calls may go to, with their positions.
    fn usable_nodes(&self) -> impl Iterator<Item = (usize, &B)> {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(position, _)| self.is_usable(*position))
    }

    /// `last_error`, or the no-usable-node message when nothing was asked,
    /// with a note of how many configured nodes were skipped for not being on
    /// this client's chain, so an error from the one node left says that the
    /// others were not tried and why.
    fn failure_detail(&self, last_error: Option<Error>) -> String {
        let skipped = self.nodes.len() - self.usable_nodes().count();
        match last_error {
            None => NO_USABLE_NODE.to_string(),
            Some(err) if skipped == 0 => err.to_string(),
            Some(err) => {
                format!("{err} ({skipped} configured node(s) skipped: not on this client's chain)")
            }
        }
    }

    /// Whether a warning for `position` at `epoch` is due: the first one for
    /// that epoch. Marks it said.
    fn warning_due(&self, position: usize, epoch: u64) -> bool {
        self.states[position]
            .warned_at
            .swap(epoch, Ordering::Relaxed)
            != epoch
    }

    /// Set `position`'s flag from what its check found, and say so when that
    /// changes it: at `info` for a node coming back, at `warn` for one going
    /// out, then again at most once per epoch for as long as it stays out.
    fn record(&self, position: usize, answer: &NodeAnswer, epoch: u64) {
        let node = self.nodes[position].describe();
        let state = &self.states[position];
        // Before the flag and the configuration: a merge that reads the node
        // as usable with what it served reads its say as of this answer.
        match answer {
            NodeAnswer::Compatible(_) => state.misses.store(0, Ordering::SeqCst),
            NodeAnswer::Incompatible(_) => state.misses.store(NEVER_ANSWERED, Ordering::SeqCst),
            NodeAnswer::Unreachable(_) => {
                // `NEVER_ANSWERED` saturates, so a node never heard from
                // stays that way.
                let _ = state
                    .misses
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |misses| {
                        Some(misses.saturating_add(1))
                    });
            }
        }
        match answer {
            NodeAnswer::Compatible(config) => {
                state.set_served(Some(((**config).clone(), epoch)));
                if !state.usable.swap(true, Ordering::SeqCst) {
                    // After the flag: a caller that reads the new count then
                    // selects the usable nodes finds this one among them.
                    self.readmissions.fetch_add(1, Ordering::SeqCst);
                    info!(position, %node, "Beacon node is on this client's chain; using it");
                }
            }
            NodeAnswer::Incompatible(difference) => {
                state.set_served(None);
                let was_usable = state.usable.swap(false, Ordering::Relaxed);
                let due = self.warning_due(position, epoch);
                if was_usable || due {
                    warn!(
                        position,
                        %node,
                        %difference,
                        "Beacon node is on a different chain than this client; not using it"
                    );
                }
            }
            NodeAnswer::Unreachable(err) => {
                if self.is_usable(position) {
                    debug!(position, %node, %err, "Beacon node chain check failed; keeping it");
                } else if self.warning_due(position, epoch) {
                    warn!(
                        position,
                        %node,
                        %err,
                        "Beacon node could not be checked against this client's chain; not using \
                         it until it can"
                    );
                }
            }
        }
    }

    /// The startup check: ask every node about its chain at once and pick the
    /// chain the client runs on.
    ///
    /// The reference is the first node, in command-line order, that answers
    /// both requests and passes the preset check. Every other node is judged
    /// against it. A node that did not answer is marked unusable, not
    /// assumed fine: it has never been checked, so it is not failed over to
    /// until a later [`Self::check_nodes`] round verifies it.
    ///
    /// While no node answers, this warns, naming what each said, and asks
    /// every node again after [`STARTUP_RETRY`], for as long as it takes, as
    /// Lighthouse's validator client does: a client started beside its
    /// beacon node (one container restart, one systemd target) would
    /// otherwise exit before the node's API is up, and read its keystores
    /// again on every restart. Only when every node answered, each with a
    /// preset this client cannot run on or a spec it cannot read (a required
    /// key absent), does it fail, since waiting cannot change that.
    ///
    /// The chain returned is the reference's, schedule included. A fork
    /// another node schedules and the reference lacks is not taken: the
    /// reference has a say, and a fork is taken only when every node with one
    /// schedules it alike ([`crate::chain_check::merge_schedule`]), so one
    /// node alone cannot put a fork on the client's schedule.
    ///
    /// `with_reference` runs once the reference is chosen, and gives the epoch
    /// the wall clock is in on that chain, which decides which forks are still
    /// free to differ. It is where the caller adopts the reference's preset:
    /// nothing before it reads a preset value, and nothing after it may run
    /// ahead of it. An error from it fails the startup.
    pub async fn establish(
        &self,
        with_reference: impl FnOnce(&ChainId) -> Result<u64>,
    ) -> Result<ChainId> {
        self.establish_on(None, with_reference).await
    }

    /// [`Self::establish`], with the chain held to the `network` the operator
    /// named (`--network`) when there is one.
    ///
    /// The reference is then the first node that answers *on that network*:
    /// no [`first_identity_difference`] from it (preset, genesis, slot
    /// duration, genesis fork version). A node that answers on another one is
    /// never the reference, so `with_reference` never sees its chain or
    /// adopts its preset, and is judged against the reference like any other
    /// node, which leaves it unusable. Its answer is as final as an
    /// unreadable spec: when every node has answered with one or the other,
    /// startup fails naming each, rather than waiting for a node that will
    /// not move to another network on its own.
    ///
    /// The fork schedule is not held to the network's: it may differ while a
    /// change rolls out, and is followed from the nodes as without a network
    /// (see [`crate::chain_check::warn_if_schedule_differs`]).
    pub async fn establish_on(
        &self,
        network: Option<&ExpectedNetwork>,
        with_reference: impl FnOnce(&ChainId) -> Result<u64>,
    ) -> Result<ChainId> {
        // Why an answer cannot be the reference: `None` when it can.
        let off_network = |chain: &ChainId| {
            let network = network?;
            first_identity_difference(&network.chain, chain)
                .map(|difference| format!("not on {}: {difference}", network.name))
        };
        let (reference_at, asked) = loop {
            let asked = futures_util::future::join_all(self.nodes.iter().map(ask)).await;
            if let Some(reference_at) = asked.iter().position(|answer| {
                answer
                    .as_ref()
                    .is_ok_and(|chain| off_network(chain).is_none())
            }) {
                break (reference_at, asked);
            }
            let detail = asked
                .iter()
                .enumerate()
                .filter_map(|(position, answer)| match answer {
                    Ok(chain) => off_network(chain).map(|why| format!("node {position}: {why}")),
                    Err(err) => Some(format!("node {position}: {err}")),
                })
                .collect::<Vec<_>>()
                .join("; ");
            // A node that answered with a preset this client cannot run on, a
            // spec it cannot read (a required key absent, say), or a chain
            // off the named network, answered: asking it again gives the
            // same answer. Waiting is for a node that has not answered yet,
            // and for one whose answer was not the node's at all: a body that
            // is not JSON (`Error::Decode`), such as a proxy's maintenance
            // page while the node boots. Every `Ok` here is off the network,
            // or it would have been the reference.
            if asked.iter().all(|answer| {
                matches!(
                    answer,
                    Ok(_) | Err(Error::Preset(_) | Error::UnreadableSpec(_))
                )
            }) {
                warn!(%detail, "No configured beacon node serves a chain this client can run on");
                return Err(Error::AllBeaconNodesFailed(detail));
            }
            warn!(
                %detail,
                retry_in_secs = STARTUP_RETRY.as_secs(),
                "No configured beacon node answered on a chain this client can run on; waiting \
                 for one"
            );
            tokio::time::sleep(STARTUP_RETRY).await;
        };
        let reference = asked[reference_at]
            .as_ref()
            .ok()
            .cloned()
            .expect("the reference answered");
        let epoch = with_reference(&reference)?;
        info!(
            position = reference_at,
            node = %self.nodes[reference_at].describe(),
            "Using this beacon node's chain as the reference; the others are checked against it"
        );

        for (position, answer) in asked.into_iter().enumerate() {
            let answer = if position == reference_at {
                NodeAnswer::Compatible(Box::new(reference.config.clone()))
            } else {
                classify(&reference, answer, epoch)
            };
            if matches!(answer, NodeAnswer::Unreachable(_)) {
                self.states[position].usable.store(false, Ordering::Relaxed);
            }
            self.record(position, &answer, epoch);
        }

        // The reference's schedule is the client's: nothing to follow yet.
        // It answered, so it has a say, and a fork moves or is taken only
        // with every node that has one (see `merge_schedule`), so a merge
        // here could only give the reference's schedule back. The first
        // background check, a slot from now, merges and warns about any
        // disagreement.
        Ok(reference)
    }

    /// Ask every node about its chain, all at once and directly (not through
    /// the failover helpers, which would skip exactly the nodes being asked),
    /// and set each one's flag from the answer.
    ///
    /// A node whose chain matches `ours()` is usable; one that differs, or is
    /// on another preset, is not. A node that did not answer keeps its flag:
    /// an outage says nothing about the chain. A node going out is warned
    /// about with the first field that differs, then again at most once per
    /// epoch.
    ///
    /// Each answer is judged the moment it arrives, at `epoch_now()` as read
    /// then and against `ours()` as it is then, and `after_each` runs right
    /// after it is recorded, with that epoch: the caller follows the schedule
    /// there. A node that hangs until its request timeout therefore holds back
    /// only its own answer. Judged after every answer was in, a prompt answer
    /// reporting a fork while it was still ahead would be judged after the
    /// fork's epoch, if the slow node's timeout crossed it, and refused for
    /// the fork. A fork whose epoch passed while a node took its time
    /// answering still counts as arrived for that node (see
    /// [`crate::chain_check::check_once`]).
    ///
    /// Returns one answer per node, with its position, in list order. The
    /// schedule is followed from [`Self::served_configs`], which this keeps
    /// current.
    pub async fn check_nodes(
        &self,
        ours: impl Fn() -> ChainId,
        epoch_now: impl Fn() -> u64,
        after_each: impl Fn(u64),
    ) -> Vec<(usize, NodeAnswer)> {
        let (ours, epoch_now, after_each) = (&ours, &epoch_now, &after_each);
        let rounds = self
            .nodes
            .iter()
            .enumerate()
            .map(|(position, node)| async move {
                let asked = ask(node).await;
                // Nothing below awaits, so no other node's answer is judged or
                // merged in between.
                let epoch = epoch_now();
                let answer = classify(&ours(), asked, epoch);
                self.record(position, &answer, epoch);
                after_each(epoch);
                (position, answer)
            });
        futures_util::future::join_all(rounds).await
    }

    /// The nodes, in order, for a test outside this module that drives a
    /// service through the fallback and then inspects each mock.
    #[cfg(test)]
    pub(crate) fn nodes(&self) -> &[B] {
        &self.nodes
    }

    /// Try each usable node in order, returning the first success. A node
    /// whose usable flag is down (on another chain, or not checked yet) is
    /// skipped without a request.
    ///
    /// The order is [`NodeHealth::ranked`]'s: by [`Tier`], command-line order
    /// breaking ties. With no probe held and no request failed it is the
    /// command-line order. A node that times out or cannot be connected to is
    /// recorded as such, which ranks it last until its next probe answers.
    ///
    /// "Success" means the node returned `Ok`, nothing more. That is the right
    /// rule only where an `Ok` is an answer this client can act on, which is
    /// why [`BeaconNodeApi::is_optimistic_or_syncing`] does not use this
    /// helper: there, `Ok(true)` is a node reporting itself unusable, and
    /// returning it from the first node would mask every healthy node behind
    /// it.
    ///
    /// A node that is syncing and still listed is skipped here in practice,
    /// because the calls routed through this helper answer 503 while syncing
    /// and 503 is mapped to an error. That is a property of those endpoints,
    /// not something this function arranges; [`Self::try_each_synced`] is for
    /// the calls where it is not.
    ///
    /// `'p` is a single, caller-inferred lifetime rather than a higher-ranked
    /// `for<'b>` one: a higher-ranked bound would force the closure's future to
    /// be valid for every possible `'b`, including `'static`, which is
    /// impossible once the closure also borrows a method argument (e.g.
    /// `pubkeys` in `validator_indices`) with its own, shorter lifetime. Tying
    /// both `&self` and the future to one named `'p` lets the compiler unify
    /// it with whatever the call site's shortest borrow actually is.
    async fn try_each<'p, T, F>(&'p self, what: &'static str, call: F) -> Result<T>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<T>>,
    {
        self.try_each_at(what, call).await.map(|(_, value)| value)
    }

    /// [`Self::try_each`] (usable nodes only, in order), also returning the
    /// position of the node that answered, for the calls whose follow-up must
    /// go to the same node. The logging and the final `warn!` live here so the
    /// two cannot drift.
    async fn try_each_at<'p, T, F>(&'p self, what: &'static str, call: F) -> Result<(usize, T)>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<T>>,
    {
        self.try_each_at_inner(what, true, Reach::Every, call).await
    }

    /// [`Self::try_each`] without the nodes whose last sync probe reported
    /// syncing or optimistic, or got no answer, for a call whose endpoint
    /// answers such a node with no 503 and data this client must not sign. A
    /// node with no probe to read is still asked. When no node is left to ask,
    /// this is `Err(BeaconNodeSyncing)`, which the callers read as "do not
    /// sign" rather than as a failure.
    async fn try_each_synced<'p, T, F>(&'p self, what: &'static str, call: F) -> Result<T>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<T>>,
    {
        self.try_each_at_inner(what, true, Reach::SkipUnsynced, call)
            .await
            .map(|(_, value)| value)
    }

    /// [`Self::try_each`] without the final `warn!`, for a caller whose own
    /// duty did not depend on the answer and which reports the failure itself
    /// (the counterpart of [`Self::try_all`]'s `all_failed: None`). A node that
    /// is syncing, or lacks the endpoint, would otherwise make this warn on
    /// every call for as long as it lasts.
    async fn try_each_quiet<'p, T, F>(&'p self, what: &'static str, call: F) -> Result<T>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<T>>,
    {
        self.try_each_at_inner(what, false, Reach::Every, call)
            .await
            .map(|(_, value)| value)
    }

    /// The walk behind every `try_each`. The position returned is the node's
    /// command-line position, whatever order it was asked in.
    async fn try_each_at_inner<'p, T, F>(
        &'p self,
        what: &'static str,
        warn_when_all_fail: bool,
        reach: Reach,
        call: F,
    ) -> Result<(usize, T)>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<T>>,
    {
        let mut last = None;
        let mut asked = false;
        for (position, standing) in self.health.ranked() {
            let Some(node) = self.nodes.get(position) else {
                continue;
            };
            if !self.is_usable(position) || reach == Reach::EveryBut(position) {
                continue;
            }
            if reach == Reach::SkipUnsynced && !standing.may_serve_ungated() {
                debug!(%what, position, ?standing, "Not asking a beacon node whose last sync probe did not answer synced");
                continue;
            }
            asked = true;
            match call(node).await {
                Ok(value) => return Ok((position, value)),
                Err(err) => {
                    // Debug, not warn: with more than one node configured, an
                    // outage on one of them fires this every slot for as long
                    // as it lasts. The event that actually means the client
                    // missed a duty is every node failing, below. A node that
                    // stopped answering is warned about once, by the record.
                    debug!(%what, position, %err, "Beacon node request failed; trying the next");
                    self.health.record_request_failure(position, what, &err);
                    last = Some(err);
                }
            }
        }
        // No node on this client's chain vouched, at its last probe, for being
        // one this client may sign against: an answer, not a failure. With no
        // node on this client's chain at all, it is the failure below.
        if reach == Reach::SkipUnsynced && !asked && self.usable_nodes().next().is_some() {
            return Err(Error::BeaconNodeSyncing);
        }
        let detail = self.failure_detail(last);
        if warn_when_all_fail {
            warn!(%what, %detail, "All configured beacon nodes failed; duty likely missed");
        }
        Err(Error::AllBeaconNodesFailed(detail))
    }

    /// Send to **every** node on this client's chain, succeeding if any
    /// accepted. A node whose usable flag is down is not sent to: the answer
    /// is [`Delivery::Everywhere`] when every node sent to accepted. A caller
    /// that stops sending once every node has it reads
    /// [`BeaconNodeApi::readmissions`] to send again when a skipped node is
    /// let back in.
    ///
    /// The counterpart to [`Self::try_each`], for the calls where first-success
    /// is the wrong rule. A query has one right answer and any node can give
    /// it; these two calls instead install *state on a node*, and a node that
    /// was never told is a node that cannot serve the duty later.
    ///
    /// That is not hypothetical. With two nodes configured, `try_each` tells
    /// node 1 which committees this client attests in and which it will
    /// aggregate for, and node 2 hears nothing. When node 1 goes down
    /// mid-epoch, every later call fails over to the node least prepared to
    /// answer it: it is not holding those attestation subnets open, and it
    /// collected none of the votes an aggregate is folded from, so it answers
    /// 404 for every committee. The failover node exists for exactly that
    /// moment.
    ///
    /// Succeeding if any node accepted, rather than requiring all, because one
    /// unreachable node must not stop the reachable ones being told. A failure
    /// is logged per node so a partially-registered client is visible rather
    /// than silent.
    ///
    /// The nodes are called at once rather than in turn, as Lighthouse
    /// broadcasts, so the call takes as long as its slowest node rather than
    /// the sum of every node's timeout: a hung node no longer holds back the
    /// healthy ones behind it in the list.
    ///
    /// `node_effect` says what a refusing node costs (said once per refusal);
    /// `all_failed` says what it costs when none accepts, or is `None` when the
    /// caller reports that itself, so a duty that did not depend on the call is
    /// not claimed missed.
    async fn try_all<'p, F>(
        &'p self,
        what: &'static str,
        node_effect: &'static str,
        all_failed: Option<&'static str>,
        call: F,
    ) -> Result<()>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<()>>,
    {
        self.try_all_inner(what, node_effect, all_failed, true, call)
            .await
            .map(|_| ())
    }

    /// [`Self::try_all`] logging each node's refusal at `debug!` instead of
    /// `warn!`, for a call the caller retries every slot and reports itself
    /// (once per entry): a per-node warning here would repeat on every retry
    /// for as long as the refusal lasts. Always without an `all_failed`
    /// message, for the same reason.
    ///
    /// Answers whether every node accepted, rather than only whether one did:
    /// a caller that retries is one that can send again to the nodes that
    /// missed it, and needs to know there are some.
    async fn try_all_quiet<'p, T, F>(
        &'p self,
        what: &'static str,
        node_effect: &'static str,
        call: F,
    ) -> Result<Delivery>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<T>>,
    {
        self.try_all_inner(what, node_effect, None, false, call)
            .await
    }

    /// The shared body of [`Self::try_all`] and [`Self::try_all_quiet`]. A
    /// node's `Ok` value is not looked into: each node here is one node, so
    /// its acceptance is the whole of what it can report.
    async fn try_all_inner<'p, T, F>(
        &'p self,
        what: &'static str,
        node_effect: &'static str,
        all_failed: Option<&'static str>,
        warn_per_node: bool,
        call: F,
    ) -> Result<Delivery>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<T>>,
    {
        // Only the nodes on this client's chain: "every node" below is every
        // one of those.
        let selected: Vec<(usize, &'p B)> = self.usable_nodes().collect();
        let answers =
            futures_util::future::join_all(selected.iter().map(|(_, node)| call(node))).await;
        let mut accepted = 0;
        let mut last = None;
        for ((position, _), answer) in selected.iter().zip(answers) {
            let position = *position;
            match answer {
                Ok(_) => accepted += 1,
                Err(err) => {
                    if warn_per_node {
                        warn!(%what, position, %err, node_effect, "Beacon node did not accept");
                    } else {
                        debug!(%what, position, %err, node_effect, "Beacon node did not accept");
                    }
                    self.health.record_request_failure(position, what, &err);
                    last = Some(err);
                }
            }
        }
        // Nested, so no node at all is never "every node".
        //
        // Against the nodes sent to, not every configured one: a node on
        // another chain can stay skipped for as long as it is configured, and
        // counting it would have a caller resend, and count a failure, every
        // slot for a send every usable node took. A skipped node that is let
        // back in does not hold what was sent; the caller learns of it through
        // `readmissions`.
        if accepted > 0 {
            return if accepted == selected.len() {
                Ok(Delivery::Everywhere)
            } else {
                Ok(Delivery::Partly)
            };
        }
        let detail = self.failure_detail(last);
        if let Some(all_failed) = all_failed {
            warn!(%what, %detail, all_failed, "No configured beacon node accepted");
        }
        Err(Error::AllBeaconNodesFailed(detail))
    }

    /// Send a signed message to every node at once, for `--broadcast`, and
    /// hand back each node's answer by its command-line position.
    ///
    /// Every node not ranked [`Tier::Failing`] is sent it together. The call
    /// waits for them until one accepts, and then at most [`BROADCAST_GRACE`]
    /// longer: a node still sending by then is cut off, though not ranked
    /// failing for it (see [`BROADCAST_GRACE`]). The failing ones are sent it
    /// only when none of the others accepted: a node that timed out on the
    /// last request or probe would otherwise hold every broadcast back, while
    /// a node that accepted has already put the message on the network.
    /// `sent` is a node the caller has already sent to itself, left out here:
    /// its acceptance counts for both rules, and a send still waiting for its
    /// answer is waited on with the broadcast's own.
    ///
    /// Each answer that says the node stopped answering is recorded, as the
    /// walk records it. What each answer means is the caller's to read.
    ///
    /// "Every node" is every node on this client's chain: a node whose usable
    /// flag is down is never sent a signed message.
    async fn broadcast_to_all<'p, T, F>(
        &'p self,
        what: &'static str,
        sent: Sent<'p, T>,
        call: F,
    ) -> Vec<(usize, Result<T>)>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<T>>,
    {
        let (skip, accepted_already, pending) = match sent {
            Sent::Nothing => (None, false, None),
            Sent::Answered { position, accepted } => (Some(position), accepted, None),
            Sent::Pending { position, send } => (Some(position), false, Some((position, send))),
        };
        let (failing, first): (Vec<_>, Vec<_>) = self
            .health
            .tiers()
            .into_iter()
            .filter(|(position, _)| Some(*position) != skip && self.is_usable(*position))
            .partition(|(_, tier)| *tier == Tier::Failing);
        let sends = pending
            .into_iter()
            .chain(self.sends_to(first, &call))
            .collect();
        let mut answers = self.send_to(what, sends, accepted_already).await;
        if !accepted_already && !answers.iter().any(|(_, answer)| answer.is_ok()) {
            let sends = self.sends_to(failing, &call).collect();
            answers.extend(self.send_to(what, sends, false).await);
        }
        answers
    }

    /// `call` started on each node at `positions`, by position.
    fn sends_to<'p, T, F>(
        &'p self,
        positions: Vec<(usize, Tier)>,
        call: &F,
    ) -> impl Iterator<Item = (usize, BoxFuture<'p, Result<T>>)>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<T>>,
    {
        positions
            .into_iter()
            .filter_map(|(position, _)| Some((position, call(self.nodes.get(position)?))))
    }

    /// Await `sends` at once, and record each node that said it is not
    /// answering. Waits for every send until one accepts (or from the start,
    /// when `accepted` says one already has), then at most
    /// [`BROADCAST_GRACE`] for the rest, which are then dropped.
    async fn send_to<'p, T>(
        &'p self,
        what: &'static str,
        sends: Vec<(usize, BoxFuture<'p, Result<T>>)>,
        accepted: bool,
    ) -> Vec<(usize, Result<T>)> {
        use futures_util::StreamExt as _;

        let mut outstanding: Vec<usize> = sends.iter().map(|(position, _)| *position).collect();
        let mut sends: futures_util::stream::FuturesUnordered<_> = sends
            .into_iter()
            .map(|(position, send)| async move {
                let answer = send
                    .await
                    .inspect_err(|err| self.health.record_request_failure(position, what, err));
                (position, answer)
            })
            .collect();
        let mut grace_ends = accepted.then(|| tokio::time::Instant::now() + BROADCAST_GRACE);
        let mut answers = Vec::new();
        loop {
            let next = match grace_ends {
                None => sends.next().await,
                Some(ends) => match tokio::time::timeout_at(ends, sends.next()).await {
                    Ok(next) => next,
                    Err(_) => break,
                },
            };
            let Some((position, answer)) = next else {
                break;
            };
            outstanding.retain(|&waiting| waiting != position);
            if answer.is_ok() && grace_ends.is_none() {
                grace_ends = Some(tokio::time::Instant::now() + BROADCAST_GRACE);
            }
            answers.push((position, answer));
        }
        // Not ranked failing: a node that answers late is not a hung one, and
        // its probe says which (see `BROADCAST_GRACE`).
        for position in outstanding {
            debug!(%what, position, "Beacon node had not answered a broadcast another node accepted; not waiting for it");
        }
        answers
    }

    /// A broadcast's answers read as one: the best accepted answer by
    /// `better`, or every node failing. A node that refused while another
    /// accepted is logged at `debug!`, since a node down for a while would
    /// otherwise warn on every message; none accepting is warned about as
    /// [`Self::try_each`] warns about it.
    fn best_answer<T>(
        what: &'static str,
        answers: Vec<(usize, Result<T>)>,
        better: impl Fn(&T, &T) -> bool,
    ) -> Result<T> {
        let mut best: Option<T> = None;
        let mut refusals = Vec::new();
        for (position, answer) in answers {
            match answer {
                Ok(value) => {
                    if best.as_ref().is_none_or(|held| better(&value, held)) {
                        best = Some(value);
                    }
                }
                Err(err) => refusals.push((position, err)),
            }
        }
        if let Some(best) = best {
            for (position, err) in refusals {
                debug!(%what, position, %err, "Beacon node did not accept a broadcast another node accepted");
            }
            return Ok(best);
        }
        // No answer at all: every node was skipped for not being on this
        // client's chain.
        let detail = refusals
            .pop()
            .map(|(_, err)| err.to_string())
            .unwrap_or_else(|| NO_USABLE_NODE.to_string());
        warn!(%what, %detail, "All configured beacon nodes failed; duty likely missed");
        Err(Error::AllBeaconNodesFailed(detail))
    }

    /// A count of accepted entries, sent to every node under `--broadcast` and
    /// to the first that accepts otherwise. Under broadcast the answer is the
    /// most any node accepted: each of those reached the network through that
    /// node at least.
    async fn send_counted<'p, F>(
        &'p self,
        what: &'static str,
        broadcast: bool,
        call: F,
    ) -> Result<usize>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<usize>>,
    {
        if !broadcast {
            return self.try_each(what, call).await;
        }
        let answers = self.broadcast_to_all(what, Sent::Nothing, call).await;
        Self::best_answer(what, answers, |count, held| count > held)
    }

    /// [`Self::send_counted`] for a message whose acceptance is all a node
    /// says about it.
    async fn send_signed<'p, F>(
        &'p self,
        what: &'static str,
        broadcast: bool,
        call: F,
    ) -> Result<()>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<()>>,
    {
        if !broadcast {
            return self.try_each(what, call).await;
        }
        let answers = self.broadcast_to_all(what, Sent::Nothing, call).await;
        Self::best_answer(what, answers, |_, _| false)
    }
}

/// How good a block publish's answer is, for picking a broadcast's best: a node
/// that imported the block over one that only broadcast it.
fn publish_rank(published: Published) -> u8 {
    match published {
        Published::Imported | Published::HandedToBuilder => 2,
        Published::BroadcastNotImported => 1,
    }
}

#[async_trait]
impl<B: BeaconNodeApi> BeaconNodeApi for FallbackBeaconNode<B> {
    fn readmissions(&self) -> u64 {
        self.readmissions.load(Ordering::SeqCst)
    }

    async fn genesis(&self) -> Result<Genesis> {
        self.try_each("genesis", |node| node.genesis()).await
    }

    async fn spec(&self) -> Result<Config> {
        self.try_each("spec", |node| node.spec()).await
    }

    /// Whether *this fallback* has no usable node, rather than whether the
    /// first reachable one happens to be syncing or optimistic.
    ///
    /// Deliberately not a plain `try_each`. A node answering `true` is
    /// answering successfully, so `try_each` would return that `Ok(true)` from
    /// the first node and never consult the rest, and a caller that turns
    /// `true` into "hold off" would hold off with a perfectly healthy node
    /// sitting behind a syncing one, which is the opposite of what configuring
    /// a second node is for.
    ///
    /// So every node on this client's chain is asked at once, and the answers
    /// are read by the rule the duty loop's per-slot gate reads its probe by
    /// ([`SyncVerdict::signs`]): `false` when some node is usable, `true` when
    /// every node that answered said it was syncing or optimistic. A node that
    /// fails outright is left out of the count, and only if none answers at
    /// all does this surface an error.
    async fn is_optimistic_or_syncing(&self) -> Result<bool> {
        let selected: Vec<(usize, &B)> = self.usable_nodes().collect();
        let answers =
            futures_util::future::join_all(selected.iter().map(|(_, node)| node.sync_status()))
                .await;
        let mut last = None;
        let mut standings = Vec::with_capacity(answers.len());
        for ((position, _), answer) in selected.iter().zip(answers) {
            let position = *position;
            match answer {
                Ok(status) => standings.push(Standing::of(&status)),
                Err(err) => {
                    debug!(what = "syncing", position, %err, "Beacon node request failed");
                    last = Some(err);
                }
            }
        }

        let verdict = SyncVerdict::tally(standings);
        if verdict.answered > 0 {
            // Every node that answered said it was unusable, when none is
            // synced. That is a real answer, not a failure: the caller should
            // hold off, and saying so is more useful than an error claiming
            // nothing could be reached.
            return Ok(!verdict.signs());
        }

        let detail = self.failure_detail(last);
        warn!(
            what = "syncing",
            %detail, "All configured beacon nodes failed; duty likely missed"
        );
        Err(Error::AllBeaconNodesFailed(detail))
    }

    /// The first node in the walk's order to answer, as for any query. The
    /// per-slot probe asks each node itself (see [`Self::probe`]), and nothing
    /// else calls this through the fallback.
    async fn sync_status(&self) -> Result<SyncStatus> {
        self.try_each("syncing", |node| node.sync_status()).await
    }

    async fn validator_indices(&self, pubkeys: &[BlsPubkey]) -> Result<Vec<ValidatorEntry>> {
        self.try_each("validator_indices", |node| node.validator_indices(pubkeys))
            .await
    }

    async fn attester_duties(
        &self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Result<AttesterDuties> {
        self.try_each("attester_duties", |node| {
            node.attester_duties(epoch, indices)
        })
        .await
    }

    async fn proposer_duties(&self, epoch: Epoch) -> Result<ProposerDuties> {
        self.try_each("proposer_duties", |node| node.proposer_duties(epoch))
            .await
    }

    async fn proposer_duties_v2(&self, epoch: Epoch) -> Result<ProposerDuties> {
        // Quiet: both callers report their own failure, the preferences
        // service once per epoch and the duty loop at each fetch it needs.
        self.try_each_quiet("proposer_duties_v2", |node| node.proposer_duties_v2(epoch))
            .await
    }

    async fn attestation_data(&self, slot: Slot, fork: ForkName) -> Result<AttestationData> {
        self.try_each("attestation_data", |node| node.attestation_data(slot, fork))
            .await
    }

    /// Marks the block with the node that produced it, which is where a
    /// blinded block's publish has to go back to (see [`Producer`]).
    async fn produce_block(&self, request: &BlockRequest) -> Result<ProducedBlock> {
        let (position, mut block) = self
            .try_each_at("produce_block", |node| node.produce_block(request))
            .await?;
        block.producer = Producer::at(position);
        Ok(block)
    }

    /// First node in the walk that accepts it wins, unless `--broadcast blocks`
    /// sends it to every node.
    ///
    /// First-wins by default because a node that accepts a block gossips it,
    /// so the other nodes receive it over the network in any case. A broadcast
    /// reaches more of the network's gossip mesh at once, which is what gets a
    /// block from a node with few peers out in time.
    ///
    /// A 202 counts as success and stops the walk. The node could not import
    /// the block, but it did broadcast it, so the network has it and offering
    /// it to another node would not change that.
    ///
    /// Under broadcast the answer is the best any node gave: imported (200)
    /// over broadcast but not imported (202), either over a refusal, so a
    /// proposal is reported clean when some node imported it. Each node's
    /// answer is logged, a refusal at `warn!`, since a proposal is rare and a
    /// node refusing one is worth seeing. Only when no node accepted is this
    /// an error.
    async fn publish_block(&self, fork: ForkName, body: &[u8]) -> Result<Published> {
        let what = "publish_block";
        if !self.broadcast.blocks {
            return self
                .try_each(what, |node| node.publish_block(fork, body))
                .await;
        }
        let answers = self
            .broadcast_to_all(what, Sent::Nothing, |node| node.publish_block(fork, body))
            .await;
        let accepted = answers.iter().any(|(_, answer)| answer.is_ok());
        for (position, answer) in &answers {
            match answer {
                Ok(published) => debug!(%what, position, ?published, "Beacon node took the block"),
                Err(err) if accepted => warn!(
                    %what,
                    position,
                    %err,
                    "Beacon node did not take the block; another node did"
                ),
                Err(_) => {}
            }
        }
        Self::best_answer(what, answers, |published, held| {
            publish_rank(*published) > publish_rank(*held)
        })
    }

    /// Only on the node that produced the block, with no failover, whatever
    /// `--broadcast` says.
    ///
    /// Unlike [`Self::publish_block`], offering the block to another node
    /// would not reach the network: only the producing node's builder holds
    /// the payload the header commits to, and only that node claimed the slot
    /// with it. A second node would at best refuse it and at worst hand a
    /// signed block to a builder that never saw the bid. So if the producing
    /// node fails, the publish fails, and the answer is returned unchanged so
    /// the caller can tell a refusal from an unconfirmed send. Slashing
    /// protection has already recorded the slot, so nothing retries it.
    ///
    /// The node is handed `Producer::default()`, since a single node has no
    /// one to choose. So a fallback of fallbacks would send every blinded
    /// block to its inner list's first node: one level only, which is all the
    /// client builds.
    async fn publish_blinded_block(
        &self,
        producer: Producer,
        fork: ForkName,
        body: &[u8],
    ) -> Result<Published> {
        // A position this fallback never handed out: there is no node the
        // block could go back to.
        let node = self.nodes.get(producer.position()).ok_or_else(|| {
            Error::InconsistentResponse(format!(
                "a blinded block names beacon node {} as its producer, but {} are configured",
                producer.position(),
                self.nodes.len()
            ))
        })?;
        // The producing node left this client's chain after it built the block.
        // Not another node: only the producer holds the payload (see above).
        if !self.is_usable(producer.position()) {
            return Err(Error::AllBeaconNodesFailed(format!(
                "beacon node {}, which produced the blinded block, is no longer on this \
                 client's chain",
                producer.position()
            )));
        }
        // The node behind this one is a single node, with nothing to choose.
        node.publish_blinded_block(Producer::default(), fork, body)
            .await
            .inspect_err(|err| {
                self.health.record_request_failure(
                    producer.position(),
                    "publish_blinded_block",
                    err,
                );
            })
    }

    /// To every node, like the other calls that install state on a node: a
    /// node that never heard the registrations cannot serve a builder bid for
    /// these validators after a failover.
    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistrationV1],
    ) -> Result<()> {
        self.try_all(
            "register_validators",
            "it will not hold these registrations",
            None,
            |node| node.register_validators(registrations),
        )
        .await
    }

    /// Every node works through its own batches at once, so a node that hangs
    /// holds back only its own sequence: the healthy ones have every batch
    /// while it is still timing out on its first. A batch counts as sent when
    /// any node accepted it, as [`Self::register_validators`] does for one.
    ///
    /// Each node that refused anything is logged once, with how many batches,
    /// rather than once per batch.
    async fn register_validators_in_batches(
        &self,
        registrations: &[SignedValidatorRegistrationV1],
    ) -> Vec<Result<()>> {
        let selected: Vec<(usize, &B)> = self.usable_nodes().collect();
        let per_node = futures_util::future::join_all(
            selected
                .iter()
                .map(|(_, node)| node.register_validators_in_batches(registrations)),
        )
        .await;

        let batches = registrations.len().div_ceil(super::REGISTRATION_BATCH);
        let mut accepted = vec![false; batches];
        let mut last = vec![None; batches];
        for ((position, _), outcomes) in selected.iter().zip(per_node) {
            let position = *position;
            let mut refused = 0;
            let mut first_refusal = None;
            // One outcome per batch is the trait's contract. A node that
            // breaks it can neither panic this nor pass a batch off as
            // delivered: extra outcomes are dropped, and a missing one leaves
            // its batch not accepted by that node.
            for (batch, outcome) in outcomes.into_iter().take(batches).enumerate() {
                match outcome {
                    Ok(()) => accepted[batch] = true,
                    Err(err) => {
                        refused += 1;
                        self.health
                            .record_request_failure(position, "register_validators", &err);
                        let detail = err.to_string();
                        first_refusal.get_or_insert_with(|| detail.clone());
                        last[batch] = Some(detail);
                    }
                }
            }
            if let Some(err) = first_refusal {
                warn!(
                    what = "register_validators",
                    position,
                    refused,
                    batches,
                    %err,
                    node_effect = "it will not hold these registrations",
                    "Beacon node did not accept"
                );
            }
        }
        accepted
            .into_iter()
            .zip(last)
            .map(|(accepted, last)| {
                if accepted {
                    Ok(())
                } else {
                    Err(Error::AllBeaconNodesFailed(last.unwrap_or_else(|| {
                        if selected.is_empty() {
                            NO_USABLE_NODE.to_string()
                        } else {
                            "no beacon node gave an outcome for this batch".to_string()
                        }
                    })))
                }
            })
            .collect()
    }

    /// To every node, since each one gossips what it accepts: a preference
    /// only the first node heard reaches the mesh through that node alone, and
    /// builders subscribed elsewhere would ignore the slot. [`Delivery::Partly`]
    /// when some usable node refused, so the service sends it again until every
    /// node holds it.
    async fn submit_proposer_preferences(
        &self,
        fork: ForkName,
        preferences: &[gloas::SignedProposerPreferences],
    ) -> Result<Delivery> {
        // Quiet: the service retries a refused preference every slot and warns
        // once per entry, with what it costs.
        let outcome_unknown = std::sync::atomic::AtomicBool::new(false);
        let delivery = self
            .try_all_quiet(
                "submit_proposer_preferences",
                "it will not gossip these proposer preferences",
                |node| {
                    let outcome_unknown = &outcome_unknown;
                    Box::pin(async move {
                        node.submit_proposer_preferences(fork, preferences)
                            .await
                            .inspect_err(|err| {
                                if err.outcome_unknown() {
                                    outcome_unknown
                                        .store(true, std::sync::atomic::Ordering::Relaxed);
                                }
                            })
                    })
                },
            )
            .await;
        // Whether some node may hold the preference after all decides whether
        // it can be signed again: see `PreferencesService`.
        match delivery {
            Err(Error::AllBeaconNodesFailed(detail)) if outcome_unknown.into_inner() => {
                Err(Error::NoNodeConfirmed(detail))
            }
            other => other,
        }
    }

    /// Fails over like any query: the envelope the node cached is only on the
    /// node that produced the block, and one that did not answers 404.
    async fn execution_payload_envelope(
        &self,
        slot: Slot,
        block_root: Root,
    ) -> Result<gloas::ExecutionPayloadEnvelope> {
        self.try_each("execution_payload_envelope", |node| {
            node.execution_payload_envelope(slot, block_root)
        })
        .await
    }

    /// First node that accepts it wins, for the reason [`Self::publish_block`]
    /// is: the accepting node gossips it. Never broadcast: with no producer
    /// named there is no node to send it to first (see
    /// [`Self::publish_execution_payload_envelope_produced_by`]).
    async fn publish_execution_payload_envelope(
        &self,
        body: &[u8],
        blob_data_included: bool,
    ) -> Result<()> {
        self.try_each("publish_execution_payload_envelope", |node| {
            node.publish_execution_payload_envelope(body, blob_data_included)
        })
        .await
    }

    /// Without `--broadcast blocks`, [`Self::publish_execution_payload_envelope`]:
    /// the first node in the walk that accepts it. A body without its blobs is
    /// the exception, below, with or without the flag.
    ///
    /// With it, the producer first, then every other node. The producer is
    /// the one node certain to hold the block the envelope reveals (it built
    /// it, and imported it on publish), so its answer comes first and puts
    /// the envelope on the network. The others are sent it once the producer
    /// has answered, or once [`PRODUCER_HEAD_START`] has passed without an
    /// answer: a node that has not imported the block yet queues or drops
    /// its envelope, and each has had the block a round trip longer by then,
    /// but a producer that holds the request open (one that answered the
    /// block 202 and never imported it waits for it) must not keep the
    /// envelope from every node until the proposal's deadline cuts the reveal.
    /// Past the head start the producer's answer is awaited with the others'.
    /// It succeeds when any node accepted.
    ///
    /// Two exceptions. A body without its blobs (`blob_data_included: false`)
    /// goes to the producer first, whatever its rank and with or without the
    /// flag, since only it cached the blobs at production time; if it does
    /// not take it, the walk follows among the other nodes, as without the
    /// flag, since a block with no blobs can be revealed through any node.
    /// And for a body with them, a
    /// producer ranked failing (it did not answer a request since its last
    /// probe, the block's own publish perhaps) is not waited on first: it is
    /// one of the failing nodes the broadcast reaches only if no other node
    /// accepts.
    async fn publish_execution_payload_envelope_produced_by(
        &self,
        producer: Producer,
        body: &[u8],
        blob_data_included: bool,
    ) -> Result<()> {
        let what = "publish_execution_payload_envelope";
        if !self.broadcast.blocks && blob_data_included {
            return self
                .publish_execution_payload_envelope(body, blob_data_included)
                .await;
        }
        let position = producer.position();
        let node = self.nodes.get(position).ok_or_else(|| {
            Error::InconsistentResponse(format!(
                "an envelope names beacon node {position} as its producer, but {} are configured",
                self.nodes.len()
            ))
        })?;
        // A producer that left this client's chain is not sent it, as no call
        // goes to such a node: the walk, or the broadcast, takes it instead.
        let producer_usable = self.is_usable(position);
        if !blob_data_included {
            if !producer_usable {
                return self.publish_execution_payload_envelope(body, false).await;
            }
            let answer = node
                .publish_execution_payload_envelope(body, false)
                .await
                .inspect_err(|err| self.health.record_request_failure(position, what, err));
            let Err(err) = answer else {
                return Ok(());
            };
            // The walk leaves the producer out: it just answered this very
            // body. With no other node to walk, its answer is the outcome.
            if self.usable_nodes().all(|(usable, _)| usable == position) {
                let detail = self.failure_detail(Some(err));
                warn!(%what, %detail, "All configured beacon nodes failed; duty likely missed");
                return Err(Error::AllBeaconNodesFailed(detail));
            }
            debug!(%what, position, %err, "The producer did not take its envelope; trying the walk");
            return self
                .try_each_at_inner(what, true, Reach::EveryBut(position), |node| {
                    node.publish_execution_payload_envelope(body, false)
                })
                .await
                .map(|(_, ())| ());
        }
        let producer_failing =
            !producer_usable || self.health.tiers().contains(&(position, Tier::Failing));

        // The producer alone first, for at most `PRODUCER_HEAD_START`; past
        // that, the rest are sent it while its answer is still awaited.
        let mut answers = Vec::new();
        let mut sent = Sent::Nothing;
        if !producer_failing {
            let mut send = node.publish_execution_payload_envelope(body, true);
            sent = match tokio::time::timeout(PRODUCER_HEAD_START, &mut send).await {
                Ok(answer) => {
                    let answer = answer
                        .inspect_err(|err| self.health.record_request_failure(position, what, err));
                    let accepted = answer.is_ok();
                    answers.push((position, answer));
                    Sent::Answered { position, accepted }
                }
                Err(_) => {
                    debug!(%what, position, "The producer has not answered its envelope yet; sending it to the other nodes too");
                    Sent::Pending { position, send }
                }
            };
        }
        let rest = self
            .broadcast_to_all(what, sent, |node| {
                node.publish_execution_payload_envelope(body, true)
            })
            .await;
        answers.extend(rest);
        Self::best_answer(what, answers, |_, _| false)
    }

    async fn ptc_duties(&self, epoch: Epoch, indices: &[ValidatorIndex]) -> Result<PtcDuties> {
        self.try_each("ptc_duties", |node| node.ptc_duties(epoch, indices))
            .await
    }

    /// A 204 is an answer, so the first node that knows no block ends the
    /// walk, even though another might have one. That is the right trade: PTC
    /// votes are due at three quarters of the slot, and a node that has seen
    /// nothing by then is one this client should not be voting through.
    ///
    /// Never from a node whose last sync probe reported syncing or optimistic:
    /// see the trait's contract.
    async fn payload_attestation_data(
        &self,
        slot: Slot,
    ) -> Result<Option<gloas::PayloadAttestationData>> {
        self.try_each_synced("payload_attestation_data", |node| {
            node.payload_attestation_data(slot)
        })
        .await
    }

    /// To every node with `--broadcast attestations`, the most any accepted.
    async fn submit_payload_attestations(
        &self,
        messages: &[gloas::PayloadAttestationMessage],
    ) -> Result<usize> {
        self.send_counted(
            "submit_payload_attestations",
            self.broadcast.attestations,
            |node| node.submit_payload_attestations(messages),
        )
        .await
    }

    /// To every node with `--broadcast attestations`, the most any accepted.
    async fn submit_attestations(
        &self,
        attestations: &[SingleAttestationDto],
        fork_name: &str,
    ) -> Result<usize> {
        self.send_counted("submit_attestations", self.broadcast.attestations, |node| {
            node.submit_attestations(attestations, fork_name)
        })
        .await
    }

    /// A 404 here is a node with nothing to fold, not a broken node, and it is
    /// the reason this is worth failing over: another node may have been on
    /// the subnet when the votes arrived.
    async fn aggregate_attestation(
        &self,
        slot: Slot,
        attestation_data_root: Root,
        committee_index: u64,
    ) -> Result<AggregateAttestation> {
        self.try_each("aggregate_attestation", |node| {
            node.aggregate_attestation(slot, attestation_data_root, committee_index)
        })
        .await
    }

    /// To every node with `--broadcast attestations`.
    async fn publish_aggregates(
        &self,
        fork: ForkName,
        aggregates: &SignedAggregates,
    ) -> Result<()> {
        self.send_signed("publish_aggregates", self.broadcast.attestations, |node| {
            node.publish_aggregates(fork, aggregates)
        })
        .await
    }

    /// Every node, not the first that answers. See [`Self::try_all`]: a node
    /// that was never told where to pay builds a payload paying somewhere else,
    /// and it is the node this client falls over to that needs telling most.
    async fn prepare_beacon_proposer(&self, preparations: &[ProposerPreparationDto]) -> Result<()> {
        self.try_all(
            "prepare_beacon_proposer",
            "it will be unprepared for this duty",
            Some("duty likely missed"),
            |node| node.prepare_beacon_proposer(preparations),
        )
        .await
    }

    /// Every node too, quietly: the duty loop sends this again each slot and
    /// logs its own failure, so a node that is down costs a `debug!` line a
    /// slot rather than two warnings, one of them claiming a missed duty.
    async fn prepare_beacon_proposer_quietly(
        &self,
        preparations: &[ProposerPreparationDto],
    ) -> Result<()> {
        self.try_all_quiet(
            "prepare_beacon_proposer",
            "it keeps the fee recipients it was last given",
            |node| node.prepare_beacon_proposer(preparations),
        )
        .await
        .map(|_| ())
    }

    /// Every node, for the same reason, and with more at stake. A subscription
    /// is what puts a node on the attestation subnets and what makes it collect
    /// the votes an aggregate is folded from, so a node that never received one
    /// answers 404 for every committee this client asks about.
    async fn subscribe_committees(&self, subscriptions: &[CommitteeSubscriptionDto]) -> Result<()> {
        self.try_all(
            "subscribe_committees",
            "it will be unprepared for this duty",
            Some("duty likely missed"),
            |node| node.subscribe_committees(subscriptions),
        )
        .await
    }

    async fn sync_duties(
        &self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Result<Vec<SyncDutyDto>> {
        self.try_each("sync_duties", |node| node.sync_duties(epoch, indices))
            .await
    }

    /// An optimistic head is an error from each implementation, so a node
    /// tracking an unvalidated head is walked past rather than signed over. A
    /// node whose last sync probe reported syncing or optimistic is not asked
    /// at all: see the trait's contract.
    async fn head_block_root(&self) -> Result<Root> {
        self.try_each_synced("head_block_root", |node| node.head_block_root())
            .await
    }

    /// To every node with `--broadcast sync-committee`, the most any accepted.
    async fn submit_sync_committee_messages(
        &self,
        messages: &[altair::SyncCommitteeMessage],
    ) -> Result<usize> {
        self.send_counted(
            "submit_sync_committee_messages",
            self.broadcast.sync_committee,
            |node| node.submit_sync_committee_messages(messages),
        )
        .await
    }

    /// A 404 is a node that holds no messages for this subcommittee; another
    /// node may have been subscribed when they arrived.
    async fn sync_committee_contribution(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        beacon_block_root: Root,
    ) -> Result<altair::SyncCommitteeContribution> {
        self.try_each("sync_committee_contribution", |node| {
            node.sync_committee_contribution(slot, subcommittee_index, beacon_block_root)
        })
        .await
    }

    /// To every node with `--broadcast sync-committee`.
    async fn publish_contribution_and_proofs(
        &self,
        contributions: &[altair::SignedContributionAndProof],
    ) -> Result<()> {
        self.send_signed(
            "publish_contribution_and_proofs",
            self.broadcast.sync_committee,
            |node| node.publish_contribution_and_proofs(contributions),
        )
        .await
    }

    /// Every node, for the reason [`Self::subscribe_committees`] is: a node
    /// that never joined a sync subnet cannot pool the messages a contribution
    /// is folded from.
    async fn subscribe_sync_committees(
        &self,
        subscriptions: &[SyncCommitteeSubscriptionDto],
    ) -> Result<()> {
        self.try_all(
            "subscribe_sync_committees",
            "it will be unprepared for this duty",
            Some("duty likely missed"),
            |node| node.subscribe_sync_committees(subscriptions),
        )
        .await
    }

    /// First answer wins, and `Ok(None)` is an answer: a node that knows no
    /// validator with this key ends the walk, though one further down the
    /// list might know it, the trade [`Self::payload_attestation_data`] makes
    /// with its 204. Nodes at the same head hold the same registry, so the
    /// two differ only while the first lags behind the block that processed
    /// the deposit, and the caller reports `None` as "not known yet", which
    /// asking again settles.
    ///
    /// The one caller is the keymanager's voluntary-exit route. When every
    /// node is down, `try_each`'s warning therefore calls a missed duty what
    /// is only a failed API request.
    async fn validator(&self, pubkey: &BlsPubkey) -> Result<Option<ValidatorDetails>> {
        self.try_each("validator", |node| node.validator(pubkey))
            .await
    }

    /// Fails over from a node that is down, but not from one that refuses the
    /// exit. A 400 is the node's verdict on the exit itself, one every node
    /// on the same chain would repeat, so it ends the walk and comes back as
    /// the [`Error::BeaconNodeStatus`] the trait promises, with that node's
    /// reason. Walking on would resend a refused exit to every node and
    /// report the refusal as all of them having failed.
    async fn submit_voluntary_exit(&self, exit: &SignedVoluntaryExit) -> Result<()> {
        // `try_each` walks past every `Err`, so the refusal goes through it
        // as an answer and is unwrapped on the way out.
        self.try_each("submit_voluntary_exit", |node| {
            Box::pin(async move {
                match node.submit_voluntary_exit(exit).await {
                    Err(refusal @ Error::BeaconNodeStatus { status: 400, .. }) => Ok(Err(refusal)),
                    outcome => outcome.map(Ok),
                }
            })
        })
        .await?
    }

    /// Every node is asked at once, and the first to answer wins. A syncing
    /// node answers `BeaconNodeSyncing` (see the trait's contract), which
    /// counts as a failure, so a node that has not caught up never clears a
    /// key while another has the chain. Each node answers every epoch, so the
    /// answers combined into one decision all come from the same node.
    ///
    /// At once rather than in turn because of when the answer is needed: the
    /// tick that can clear a key starts three quarters into an epoch's last
    /// slot, and walking past a hung first node (up to the request timeout)
    /// would reach a healthy second one in the next epoch, which no longer
    /// answers for the older epoch asked about. Keys would then never clear
    /// for as long as the first node hung, though the duties fail over to
    /// the second in time. The cost is a query to every node per tick, only
    /// while some key is under the check.
    ///
    /// Quiet: no duty depends on the answer, and the doppelganger check
    /// reports its own failures, so a node without the endpoint must not
    /// claim a missed duty every slot.
    ///
    /// Only the usable nodes, like every other call: a node on another chain
    /// would answer for that chain's validators at those indices.
    async fn liveness(
        &self,
        epochs: &[Epoch],
        indices: &[ValidatorIndex],
    ) -> Result<Vec<Vec<Liveness>>> {
        let queries: Vec<_> = self
            .usable_nodes()
            .map(|(_, node)| node.liveness(epochs, indices))
            .collect();
        // `select_ok` panics on no futures.
        if queries.is_empty() {
            return Err(Error::AllBeaconNodesFailed(NO_USABLE_NODE.to_string()));
        }
        match futures_util::future::select_ok(queries).await {
            Ok((answers, _slower)) => Ok(answers),
            Err(err) => {
                debug!(what = "liveness", %err, "Every beacon node failed the request");
                Err(Error::AllBeaconNodesFailed(err.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_node::REGISTRATION_BATCH;
    use crate::beacon_node::mock::MockBeaconNode;
    use ethlambda_types::beacon::primitives::Root;
    use std::sync::Arc;

    /// The fork a caller asks about `slot` under: the one mainnet's schedule
    /// puts it in, as `AttestationService` derives it, rather than one made
    /// up here that the slot does not belong to.
    fn fork_of(slot: Slot) -> ForkName {
        let epoch = ethlambda_types::beacon::signing::compute_epoch_at_slot(slot);
        ethlambda_types::beacon::config::Config::mainnet().fork_at_epoch(epoch)
    }

    fn healthy() -> MockBeaconNode {
        let mut node = MockBeaconNode::new();
        node.genesis = Some(Genesis {
            genesis_time: 1_606_824_023,
            genesis_validators_root: Root::ZERO,
        });
        node
    }

    #[tokio::test]
    async fn the_first_healthy_node_answers() {
        let fallback = FallbackBeaconNode::new(vec![healthy(), MockBeaconNode::failing("down")]);
        let genesis = fallback.genesis().await.expect("answers");
        assert_eq!(genesis.genesis_time, 1_606_824_023);
    }

    #[tokio::test]
    async fn a_failing_first_node_falls_through_to_the_second() {
        let fallback = FallbackBeaconNode::new(vec![MockBeaconNode::failing("down"), healthy()]);
        let genesis = fallback.genesis().await.expect("answers");
        assert_eq!(genesis.genesis_time, 1_606_824_023);
    }

    /// The finding this arrangement exists for: a node that is *up* but stuck
    /// on a stale head must be failed over from, not treated as a success.
    ///
    /// Before the contract moved into the implementations, the slot check ran
    /// above `try_each`, so node 1's stale answer was accepted and returned and
    /// node 2 was never asked. The validator then missed every attestation
    /// while both nodes looked healthy, because nothing was ever `Err`.
    #[tokio::test]
    async fn a_node_answering_about_a_stale_slot_is_failed_over_from() {
        // Node 1 answers about slot 90 whatever it is asked; node 2 about 96.
        let stale = MockBeaconNode::new().with_attestation_data(90);
        let fresh = MockBeaconNode::new().with_attestation_data(96);
        let fallback = FallbackBeaconNode::new(vec![stale, fresh]);

        let data = fallback
            .attestation_data(96, fork_of(96))
            .await
            .expect("the second node answers correctly");

        assert_eq!(
            data.slot, 96,
            "the stale answer must not be the one returned"
        );
    }

    #[tokio::test]
    async fn every_node_answering_about_a_stale_slot_is_an_error() {
        // With nowhere left to fall through to, this must be a failure rather
        // than a stale answer quietly returned.
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::new().with_attestation_data(90),
            MockBeaconNode::new().with_attestation_data(91),
        ]);

        let err = fallback
            .attestation_data(96, fork_of(96))
            .await
            .expect_err("no node answered about the requested slot");

        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
    }

    /// The same arrangement for the index: a node answering with one no vote
    /// at the slot's fork can carry is failed over from, rather than its
    /// answer being signed, recorded and then rejected by every peer.
    #[tokio::test]
    async fn a_node_answering_with_an_index_invalid_at_the_fork_is_failed_over_from() {
        // Slot 96 is before gloas, where the index is zero; node 1 answers 1
        // regardless.
        let wrong = MockBeaconNode::new()
            .with_attestation_data(96)
            .with_attestation_index(1);
        let right = MockBeaconNode::new().with_attestation_data(96);
        let fallback = FallbackBeaconNode::new(vec![wrong, right]);

        let data = fallback
            .attestation_data(96, fork_of(96))
            .await
            .expect("the second node answers correctly");

        assert_eq!(
            data.index, 0,
            "the invalid answer must not be the one returned"
        );
    }

    /// A syncing node at the head of the list must not make the fallback
    /// report itself unusable when a healthy node sits behind it.
    ///
    /// `is_optimistic_or_syncing` returning `Ok(true)` is a *successful* call,
    /// so a plain `try_each` would return the first node's answer and never
    /// look further, and a caller holding off on `true` would leave the second
    /// node unused for as long as the first was syncing.
    #[tokio::test]
    async fn a_syncing_first_node_does_not_mask_a_healthy_second() {
        let syncing = MockBeaconNode {
            syncing: true,
            ..MockBeaconNode::new()
        };
        let fallback = FallbackBeaconNode::new(vec![syncing, healthy()]);

        assert!(
            !fallback.is_optimistic_or_syncing().await.expect("answers"),
            "a healthy node behind a syncing one must be found"
        );
    }

    /// Liveness is answered by a node that has the chain: a syncing one
    /// first in the list is asked nothing and walked past, so its empty
    /// view never clears a key the second node saw act.
    #[tokio::test]
    async fn liveness_skips_a_syncing_node_for_one_that_has_the_chain() {
        let syncing = MockBeaconNode {
            syncing: true,
            ..MockBeaconNode::new()
        };
        let seeing = MockBeaconNode::new();
        seeing.live.lock().expect("lock").push((12, 7));
        let fallback = FallbackBeaconNode::new(vec![syncing, seeing]);

        let answers = fallback.liveness(&[12], &[7]).await.expect("answers");
        assert_eq!(
            answers,
            vec![vec![Liveness {
                index: 7,
                is_live: true
            }]]
        );
        assert!(fallback.nodes[0].liveness_requests().is_empty());
        assert_eq!(fallback.nodes[1].liveness_requests(), vec![(12, vec![7])]);
    }

    /// A hung first node does not delay the answer: every node is asked at
    /// once, so a healthy one answers within the tick's slot.
    #[tokio::test(start_paused = true)]
    async fn liveness_is_not_held_back_by_a_hung_node() {
        use std::time::Duration;
        let hung = MockBeaconNode::new().with_liveness_delay(Duration::from_secs(60));
        let fallback = FallbackBeaconNode::new(vec![hung, MockBeaconNode::new()]);

        let started = tokio::time::Instant::now();
        let answers = fallback.liveness(&[11, 12], &[7]).await.expect("answers");
        assert_eq!(answers.len(), 2);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// Both epochs come from one node: a node that fails fails both, and
    /// another node answers both.
    #[tokio::test]
    async fn liveness_answers_every_epoch_from_one_node() {
        let flaky = MockBeaconNode::new().failing_call("liveness", "down");
        let fallback = FallbackBeaconNode::new(vec![flaky, MockBeaconNode::new()]);

        let answers = fallback.liveness(&[11, 12], &[7]).await.expect("answers");
        assert_eq!(answers.len(), 2);
        assert!(fallback.nodes[0].liveness_requests().is_empty());
        assert_eq!(
            fallback.nodes[1].liveness_requests(),
            vec![(11, vec![7]), (12, vec![7])]
        );
    }

    #[tokio::test]
    async fn every_node_syncing_reports_syncing() {
        // A real answer, not a failure: the caller should hold off, and saying
        // so beats an error claiming nothing could be reached.
        let syncing = || MockBeaconNode {
            syncing: true,
            ..MockBeaconNode::new()
        };
        let fallback = FallbackBeaconNode::new(vec![syncing(), syncing()]);

        assert!(fallback.is_optimistic_or_syncing().await.expect("answers"));
    }

    #[tokio::test]
    async fn a_syncing_node_is_preferred_over_no_answer_at_all() {
        // One node down, one syncing: `true` is the honest report, because a
        // node did answer and it said it was syncing.
        let syncing = MockBeaconNode {
            syncing: true,
            ..MockBeaconNode::new()
        };
        let fallback = FallbackBeaconNode::new(vec![MockBeaconNode::failing("down"), syncing]);

        assert!(fallback.is_optimistic_or_syncing().await.expect("answers"));
    }

    #[tokio::test]
    async fn no_node_answering_syncing_is_an_error() {
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::failing("first down"),
            MockBeaconNode::failing("second down"),
        ]);

        let err = fallback
            .is_optimistic_or_syncing()
            .await
            .expect_err("nothing answered");
        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn every_node_failing_is_reported_as_such() {
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::failing("first down"),
            MockBeaconNode::failing("second down"),
        ]);
        let err = fallback.genesis().await.expect_err("must fail");
        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
        assert!(err.to_string().contains("second down"), "got {err}");
    }

    /// A node that is up but whose duties poll is failing is a different
    /// shape from a node that is entirely down: `genesis` must still be
    /// served by it, while `attester_duties` must fall through to the next.
    #[tokio::test]
    async fn a_node_failing_one_call_still_serves_the_others() {
        let first = healthy().failing_call("attester_duties", "duties down");
        let second = healthy().with_duties(3, Root::repeat_byte(7), vec![]);

        let fallback = FallbackBeaconNode::new(vec![first, second]);

        let genesis = fallback.genesis().await.expect("first node answers");
        assert_eq!(genesis.genesis_time, 1_606_824_023);

        let duties = fallback
            .attester_duties(3, &[])
            .await
            .expect("second node answers");
        assert_eq!(duties.dependent_root, Root::repeat_byte(7));
    }

    fn request(slot: Slot, proposer_index: ValidatorIndex) -> BlockRequest {
        use ethlambda_types::beacon::primitives::{BlsSignature, Bytes32};
        BlockRequest {
            slot,
            fork: ForkName::Electra,
            proposer_index,
            randao_reveal: BlsSignature([0; 96]),
            graffiti: Bytes32::default(),
            builder_boost_factor: None,
            builder_min_bid: 0,
        }
    }

    /// The proposal-shaped version of the stale-head finding above, and the
    /// more expensive one to get wrong: a block signed against a stale node's
    /// answer is a block for the wrong slot, and it burns slashing
    /// protection's record for that validator on the way out.
    #[tokio::test]
    async fn a_node_producing_a_block_for_the_wrong_slot_is_failed_over_from() {
        let stale = MockBeaconNode::new().with_block(90, 7);
        let fresh = MockBeaconNode::new().with_block(96, 7);
        let fallback = FallbackBeaconNode::new(vec![stale, fresh]);

        let block = fallback
            .produce_block(&request(96, 7))
            .await
            .expect("the second node answers correctly");
        assert_eq!(block.slot(), 96);
    }

    /// A node on a different fork computes a different proposer. Signing its
    /// block would produce a signature the network discards, while slashing
    /// protection records the slot as proposed and refuses the real duty.
    #[tokio::test]
    async fn a_node_naming_the_wrong_proposer_is_failed_over_from() {
        let wrong = MockBeaconNode::new().with_block(96, 11);
        let right = MockBeaconNode::new().with_block(96, 7);
        let fallback = FallbackBeaconNode::new(vec![wrong, right]);

        let block = fallback
            .produce_block(&request(96, 7))
            .await
            .expect("the second node names the expected proposer");
        assert_eq!(block.proposer_index(), 7);
    }

    #[tokio::test]
    async fn every_node_naming_the_wrong_proposer_is_an_error() {
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::new().with_block(96, 11),
            MockBeaconNode::new().with_block(96, 12),
        ]);

        let err = fallback
            .produce_block(&request(96, 7))
            .await
            .expect_err("no node produced a block for this proposer");
        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_block_is_published_to_the_first_node_that_accepts_it() {
        let fallback =
            FallbackBeaconNode::new(vec![MockBeaconNode::failing("down"), MockBeaconNode::new()]);

        let outcome = fallback
            .publish_block(ForkName::Electra, b"body")
            .await
            .expect("the second node accepts it");
        assert_eq!(outcome, Published::Imported);
        assert_eq!(
            fallback.nodes[1].published_blocks(),
            vec![(ForkName::Electra, b"body".to_vec())]
        );
        assert!(
            fallback.nodes[0].published_blocks().is_empty(),
            "the failing node recorded nothing"
        );
    }

    /// 202 means the node broadcast the block but could not import it. It is a
    /// success for the walk, so the second node is never tried, but it must not
    /// be reported to the caller as a clean proposal.
    #[tokio::test]
    async fn a_block_the_first_node_broadcast_but_could_not_import_stops_the_walk() {
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::new().with_publish_outcome(Published::BroadcastNotImported),
            MockBeaconNode::new(),
        ]);

        let outcome = fallback
            .publish_block(ForkName::Electra, b"body")
            .await
            .expect("202 is not an error");
        assert_eq!(outcome, Published::BroadcastNotImported);
        assert!(
            fallback.nodes[1].published_blocks().is_empty(),
            "the block was already broadcast; the second node must not be asked"
        );
    }

    fn subscription(slot: Slot) -> CommitteeSubscriptionDto {
        CommitteeSubscriptionDto {
            validator_index: 1,
            committee_index: 2,
            committees_at_slot: 64,
            slot,
            is_aggregator: true,
        }
    }

    /// The finding this helper exists for: a subscription is state installed on
    /// a node, not a query with one right answer. Under `try_each` only node 1
    /// ever heard about this client's committees, and node 2 — the one failover
    /// exists to use — was left unable to serve the duty.
    #[tokio::test]
    async fn a_subscription_reaches_every_node_not_just_the_first() {
        let fallback = FallbackBeaconNode::new(vec![MockBeaconNode::new(), MockBeaconNode::new()]);
        fallback
            .subscribe_committees(&[subscription(96)])
            .await
            .expect("subscribes");

        assert_eq!(fallback.nodes[0].subscriptions().len(), 1);
        assert_eq!(
            fallback.nodes[1].subscriptions().len(),
            1,
            "the second node must be told too, or it cannot serve a failover"
        );
    }

    #[tokio::test]
    async fn a_fee_recipient_registration_reaches_every_node() {
        let fallback = FallbackBeaconNode::new(vec![MockBeaconNode::new(), MockBeaconNode::new()]);
        let preparations = [ProposerPreparationDto {
            validator_index: 1,
            fee_recipient: "0xab".to_string(),
        }];
        fallback
            .prepare_beacon_proposer(&preparations)
            .await
            .expect("registers");

        assert_eq!(fallback.nodes[0].preparations().len(), 1);
        assert_eq!(fallback.nodes[1].preparations().len(), 1);
    }

    /// The per-slot send goes to every node like the epoch's, and fails only
    /// when none accepted. What it changes is the logging, which this does
    /// not see.
    #[tokio::test]
    async fn the_quiet_fee_recipient_send_reaches_every_node_too() {
        let preparations = [ProposerPreparationDto {
            validator_index: 1,
            fee_recipient: "0xab".to_string(),
        }];
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::failing("down"),
            MockBeaconNode::new(),
            MockBeaconNode::new(),
        ]);
        fallback
            .prepare_beacon_proposer_quietly(&preparations)
            .await
            .expect("two nodes accepted");
        assert!(fallback.nodes[0].preparations().is_empty());
        assert_eq!(fallback.nodes[1].preparations().len(), 1);
        assert_eq!(fallback.nodes[2].preparations().len(), 1);

        let down = FallbackBeaconNode::new(vec![
            MockBeaconNode::failing("down"),
            MockBeaconNode::failing("down"),
        ]);
        let err = down
            .prepare_beacon_proposer_quietly(&preparations)
            .await
            .expect_err("no node accepted");
        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
    }

    /// One unreachable node must not stop the reachable ones being told.
    #[tokio::test]
    async fn one_failing_node_does_not_stop_the_others_being_subscribed() {
        let fallback =
            FallbackBeaconNode::new(vec![MockBeaconNode::failing("down"), MockBeaconNode::new()]);
        fallback
            .subscribe_committees(&[subscription(96)])
            .await
            .expect("the healthy node accepted");

        assert!(fallback.nodes[0].subscriptions().is_empty());
        assert_eq!(fallback.nodes[1].subscriptions().len(), 1);
    }

    /// A preference every node refused outright is a plain failure, so it is
    /// signed afresh; one a node may have taken before failing is told apart,
    /// so it is kept as signed (see `PreferencesService`).
    #[tokio::test]
    async fn a_preference_no_node_confirmed_says_whether_one_may_hold_it() {
        let slot = 96;
        let refusing = || {
            let node = MockBeaconNode::new();
            node.refused_preference_slots
                .lock()
                .expect("lock")
                .push(slot);
            node
        };
        let preference = gloas::SignedProposerPreferences {
            message: gloas::ProposerPreferences {
                proposal_slot: slot,
                ..Default::default()
            },
            signature: Default::default(),
        };
        let preferences = std::slice::from_ref(&preference);

        let refused = FallbackBeaconNode::new(vec![refusing(), refusing()]);
        let err = refused
            .submit_proposer_preferences(ForkName::Gloas, preferences)
            .await
            .expect_err("both refused");
        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
        assert!(!err.outcome_unknown());

        let lost = FallbackBeaconNode::new(vec![
            refusing(),
            MockBeaconNode::new().failing_call("submit_proposer_preferences", "timed out"),
        ]);
        let err = lost
            .submit_proposer_preferences(ForkName::Gloas, preferences)
            .await
            .expect_err("neither confirmed");
        assert!(matches!(err, Error::NoNodeConfirmed(_)), "got {err:?}");
        assert!(err.outcome_unknown());
    }

    #[tokio::test]
    async fn no_node_accepting_a_subscription_is_an_error() {
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::failing("down"),
            MockBeaconNode::failing("also down"),
        ]);
        let err = fallback
            .subscribe_committees(&[subscription(96)])
            .await
            .expect_err("nothing was registered anywhere");
        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
    }

    /// The other direction, stated so the two rules do not drift: a query still
    /// stops at the first node that answers. Asking every node for a block
    /// would make every node build one.
    #[tokio::test]
    async fn a_query_still_stops_at_the_first_node_that_answers() {
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::new().with_block(96, 7),
            MockBeaconNode::new().with_block(96, 7),
        ]);
        fallback
            .produce_block(&request(96, 7))
            .await
            .expect("the first node answers");

        assert_eq!(fallback.nodes[0].block_requests().len(), 1);
        assert!(
            fallback.nodes[1].block_requests().is_empty(),
            "the second node must not have been asked to build a block too"
        );
    }

    #[tokio::test]
    async fn an_optimistic_head_fails_over_to_the_next_node() {
        let mut optimistic = MockBeaconNode::new().with_head_root(Root::repeat_byte(1));
        optimistic.head_optimistic = true;
        let healthy = MockBeaconNode::new().with_head_root(Root::repeat_byte(2));
        let fallback = FallbackBeaconNode::new(vec![optimistic, healthy]);

        assert_eq!(
            fallback.head_block_root().await.expect("second answers"),
            Root::repeat_byte(2)
        );
    }

    #[tokio::test]
    async fn a_sync_subscription_reaches_every_node() {
        let fallback = FallbackBeaconNode::new(vec![MockBeaconNode::new(), MockBeaconNode::new()]);
        let subscription = SyncCommitteeSubscriptionDto {
            validator_index: 1,
            sync_committee_indices: vec![3],
            until_epoch: 256,
        };
        fallback
            .subscribe_sync_committees(&[subscription])
            .await
            .expect("subscribes");

        assert_eq!(fallback.nodes[0].sync_subscriptions().len(), 1);
        assert_eq!(
            fallback.nodes[1].sync_subscriptions().len(),
            1,
            "try_all, not try_each"
        );
    }

    fn signed_exit() -> SignedVoluntaryExit {
        use ethlambda_types::beacon::containers::shared::VoluntaryExit;
        use ethlambda_types::beacon::primitives::BlsSignature;
        SignedVoluntaryExit {
            message: VoluntaryExit {
                epoch: 10,
                validator_index: 7,
            },
            signature: BlsSignature([0; 96]),
        }
    }

    /// A refusal is the node's answer about the exit, not a node failing. It
    /// must reach the caller as that node's 400 and reason, and the exit must
    /// not be resent to the nodes behind it.
    #[tokio::test]
    async fn a_refused_exit_ends_the_walk_with_the_nodes_reason() {
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::new().refusing_exits("the validator is not active"),
            MockBeaconNode::new(),
        ]);

        let err = fallback
            .submit_voluntary_exit(&signed_exit())
            .await
            .expect_err("the first node refused it");
        assert!(
            matches!(&err, Error::BeaconNodeStatus { status: 400, body } if body.contains("not active")),
            "got {err:?}"
        );
        assert!(
            fallback.nodes[1].submitted_exits().is_empty(),
            "a refused exit must not be resent to the next node"
        );
    }

    /// A node that is down is still failed over from, as for any other call.
    #[tokio::test]
    async fn an_exit_fails_over_from_a_node_that_is_down() {
        let fallback =
            FallbackBeaconNode::new(vec![MockBeaconNode::failing("down"), MockBeaconNode::new()]);

        fallback
            .submit_voluntary_exit(&signed_exit())
            .await
            .expect("the second node accepts it");
        assert_eq!(fallback.nodes[1].submitted_exits(), vec![signed_exit()]);
    }

    #[tokio::test]
    async fn an_exit_no_node_could_be_reached_for_is_every_node_failing() {
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::failing("first down"),
            MockBeaconNode::failing("second down"),
        ]);

        let err = fallback
            .submit_voluntary_exit(&signed_exit())
            .await
            .expect_err("nothing answered");
        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
    }

    /// The pair a beacon node can genuinely report and this client must still
    /// refuse: caught up, but tracking a head its execution client has not
    /// validated. The specification makes not signing in that position a MUST,
    /// and checking only `is_syncing` would miss it entirely.
    #[tokio::test]
    async fn a_synced_but_optimistic_node_is_not_usable() {
        let mut node = MockBeaconNode::new();
        node.syncing = false;
        node.optimistic = true;
        let fallback = FallbackBeaconNode::new(vec![node]);

        assert!(
            fallback.is_optimistic_or_syncing().await.expect("answers"),
            "an optimistic node must be refused even though it is not syncing"
        );
    }

    /// And the failover half of the same: an optimistic first node must not
    /// mask a healthy second, exactly as a syncing one must not.
    #[tokio::test]
    async fn an_optimistic_first_node_does_not_mask_a_healthy_second() {
        let mut optimistic = MockBeaconNode::new();
        optimistic.optimistic = true;
        let fallback = FallbackBeaconNode::new(vec![optimistic, MockBeaconNode::new()]);

        assert!(
            !fallback.is_optimistic_or_syncing().await.expect("answers"),
            "the healthy second node must be found"
        );
    }

    /// A node that answers every duty endpoint for slot 96, its head root
    /// marked with `mark` so the answer names the node that gave it.
    fn answering(mark: u8) -> MockBeaconNode {
        use ethlambda_types::beacon::primitives::BlsSignature;
        let root = Root::repeat_byte(mark);
        let mut node = MockBeaconNode::new().with_attestation_data(96);
        node.aggregate = node.attestation_data;
        node.with_block(96, 7)
            .with_head_root(root)
            .with_contribution(altair::SyncCommitteeContribution {
                slot: 96,
                beacon_block_root: root,
                subcommittee_index: 0,
                aggregation_bits: Default::default(),
                signature: BlsSignature([1; 96]),
            })
            .with_payload_attestation_data(gloas::PayloadAttestationData {
                beacon_block_root: root,
                slot: 96,
                payload_present: true,
                blob_data_available: true,
            })
    }

    /// The issue's second case: the first node is syncing but answers every
    /// endpoint, as a node that does not refuse with 503 would; the second is
    /// synced. Once a probe has said so, every duty is served by the second,
    /// and the first is asked nothing.
    #[tokio::test]
    async fn every_duty_is_served_by_the_synced_node_listed_second() {
        let syncing = MockBeaconNode {
            syncing: true,
            ..answering(1)
        };
        let fallback = FallbackBeaconNode::new(vec![syncing, answering(2)]);
        fallback.probe(96, std::time::Duration::from_secs(1)).await;

        fallback
            .attestation_data(96, fork_of(96))
            .await
            .expect("attestation data");
        let block = fallback
            .produce_block(&request(96, 7))
            .await
            .expect("a block");
        assert_eq!(block.producer, Producer::at(1));
        fallback
            .publish_block(ForkName::Electra, b"body")
            .await
            .expect("published");
        fallback
            .aggregate_attestation(96, Root::ZERO, 0)
            .await
            .expect("an aggregate");
        let head = fallback.head_block_root().await.expect("a head");
        assert_eq!(head, Root::repeat_byte(2));
        fallback
            .sync_committee_contribution(96, 0, head)
            .await
            .expect("a contribution");
        fallback
            .payload_attestation_data(96)
            .await
            .expect("payload data")
            .expect("a block");

        let first = &fallback.nodes[0];
        assert_eq!(first.attestation_data_call_count(), 0);
        assert!(first.block_requests().is_empty());
        assert!(first.published_blocks().is_empty());
        assert!(first.aggregate_requests().is_empty());
        assert!(first.contribution_requests().is_empty());
        assert_eq!(first.payload_attestation_data_call_count(), 0);

        let second = &fallback.nodes[1];
        assert_eq!(second.attestation_data_call_count(), 1);
        assert_eq!(second.block_requests().len(), 1);
        assert_eq!(second.published_blocks().len(), 1);
        assert_eq!(second.aggregate_requests().len(), 1);
        assert_eq!(second.contribution_requests().len(), 1);
        assert_eq!(second.payload_attestation_data_call_count(), 1);
    }

    /// The order is a preference, not a filter: a call the synced node fails
    /// still falls through to the rest, where the 503 the Beacon API requires
    /// of a syncing node is the backstop.
    #[tokio::test]
    async fn a_node_that_did_not_pass_is_still_asked_after_the_ones_that_did() {
        let syncing = MockBeaconNode {
            syncing: true,
            ..answering(1)
        };
        let failing = answering(2).failing_call("attestation_data", "timed out");
        let fallback = FallbackBeaconNode::new(vec![syncing, failing]);
        fallback.probe(96, std::time::Duration::from_secs(1)).await;

        fallback
            .attestation_data(96, fork_of(96))
            .await
            .expect("the first node answers once the second has failed");
        assert_eq!(fallback.nodes[0].attestation_data_call_count(), 1);
    }

    /// The walk's order is not the list's, but a blinded block still names the
    /// node that produced it by its command-line position, and goes back there.
    #[tokio::test]
    async fn a_blinded_block_goes_back_to_its_producer_whatever_the_walk_order() {
        let syncing = MockBeaconNode {
            syncing: true,
            ..blinded_node()
        };
        let fallback = FallbackBeaconNode::new(vec![syncing, blinded_node()]);
        fallback.probe(5, std::time::Duration::from_secs(1)).await;

        let produced = fallback
            .produce_block(&blinded_request(5, 7))
            .await
            .expect("node 1 produces");
        assert_eq!(produced.producer, Producer::at(1));
        fallback
            .publish_blinded_block(produced.producer, ForkName::Electra, &[4])
            .await
            .expect("published");
        assert!(
            fallback.nodes[0]
                .published_blinded
                .lock()
                .expect("lock")
                .is_empty()
        );
        assert_eq!(
            *fallback.nodes[1].published_blinded.lock().expect("lock"),
            vec![(ForkName::Electra, vec![4])]
        );
    }

    /// A head root and payload attestation data are never taken from a node
    /// whose probe said syncing or optimistic, even when the synced node ahead
    /// of it in the walk fails the call: no 503 would stop the answer.
    #[tokio::test]
    async fn an_unsynced_node_is_not_asked_for_a_head_root_or_payload_data() {
        for unsynced in [
            MockBeaconNode {
                syncing: true,
                ..answering(1)
            },
            MockBeaconNode {
                optimistic: true,
                ..answering(1)
            },
        ] {
            let failing = answering(2)
                .failing_call("head_block_root", "timed out")
                .failing_call("payload_attestation_data", "timed out");
            let fallback = FallbackBeaconNode::new(vec![unsynced, failing]);
            fallback.probe(96, std::time::Duration::from_secs(1)).await;

            let err = fallback.head_block_root().await.expect_err("no root");
            assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
            let err = fallback
                .payload_attestation_data(96)
                .await
                .expect_err("no data");
            assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
            assert_eq!(fallback.nodes[0].payload_attestation_data_call_count(), 0);
        }
    }

    /// With every node unsynced at its last probe, nobody is asked, and the
    /// answer is the one a caller reads as "do not sign" rather than a failed
    /// node.
    #[tokio::test]
    async fn every_node_unsynced_is_a_syncing_answer_without_asking() {
        let optimistic = MockBeaconNode {
            optimistic: true,
            ..answering(1)
        };
        let fallback = FallbackBeaconNode::new(vec![optimistic]);
        fallback.probe(96, std::time::Duration::from_secs(1)).await;

        let err = fallback.head_block_root().await.expect_err("no root");
        assert!(matches!(err, Error::BeaconNodeSyncing), "got {err:?}");
        let err = fallback
            .payload_attestation_data(96)
            .await
            .expect_err("no data");
        assert!(matches!(err, Error::BeaconNodeSyncing), "got {err:?}");
        assert_eq!(fallback.nodes[0].payload_attestation_data_call_count(), 0);
    }

    /// A node whose probe failed vouches for nothing, and nothing stops a
    /// syncing node's stale head root, so it is not asked either. A node with
    /// no probe at all, in a fallback no probe task runs for, still is.
    #[tokio::test]
    async fn a_node_that_did_not_answer_its_probe_is_not_asked_for_a_head_root() {
        let unanswered = answering(3).failing_call("is_syncing", "down");
        let fallback = FallbackBeaconNode::new(vec![unanswered]);
        fallback.probe(96, std::time::Duration::from_secs(1)).await;

        let err = fallback.head_block_root().await.expect_err("no root");
        assert!(matches!(err, Error::BeaconNodeSyncing), "got {err:?}");
        let err = fallback
            .payload_attestation_data(96)
            .await
            .expect_err("no data");
        assert!(matches!(err, Error::BeaconNodeSyncing), "got {err:?}");
        assert_eq!(fallback.nodes[0].payload_attestation_data_call_count(), 0);

        let never_probed = FallbackBeaconNode::new(vec![answering(3)]);
        assert_eq!(
            never_probed.head_block_root().await.expect("a root"),
            Root::repeat_byte(3)
        );
    }

    fn blinded_request(slot: Slot, proposer_index: ValidatorIndex) -> BlockRequest {
        BlockRequest {
            builder_boost_factor: Some(100),
            ..request(slot, proposer_index)
        }
    }

    fn blinded_node() -> MockBeaconNode {
        MockBeaconNode::new().with_block(5, 7).with_blinded_block()
    }

    /// Node 0 cannot produce, node 1 can and answers blinded: the block names
    /// node 1 as its producer, goes back to node 1, and node 0 never sees it.
    #[tokio::test]
    async fn a_blinded_block_is_published_where_it_was_produced() {
        let first = MockBeaconNode::new().failing_call("produce_block", "down");
        let fallback = FallbackBeaconNode::new(vec![first, blinded_node()]);

        let produced = fallback
            .produce_block(&blinded_request(5, 7))
            .await
            .expect("node 1 produces");
        assert!(produced.is_blinded());
        assert_eq!(produced.producer, Producer::at(1));

        let published = fallback
            .publish_blinded_block(produced.producer, ForkName::Electra, &[1, 2, 3])
            .await
            .expect("published");
        assert_eq!(published, Published::HandedToBuilder);

        let first_published = fallback.nodes[0].published_blinded.lock().expect("lock");
        let second_published = fallback.nodes[1].published_blinded.lock().expect("lock");
        assert!(first_published.is_empty(), "node 0 never produced it");
        assert_eq!(*second_published, vec![(ForkName::Electra, vec![1, 2, 3])]);
    }

    /// The producing node failing the publish is the end of it: another node's
    /// builder never saw the bid, so it must not be offered the block.
    #[tokio::test]
    async fn a_blinded_publish_does_not_fail_over() {
        let second = blinded_node().with_unconfirmed_blinded_publish("relay timed out");
        let first = MockBeaconNode::new().failing_call("produce_block", "down");
        let fallback = FallbackBeaconNode::new(vec![first, second]);

        let produced = fallback
            .produce_block(&blinded_request(5, 7))
            .await
            .expect("node 1 produces");
        let err = fallback
            .publish_blinded_block(produced.producer, ForkName::Electra, &[9])
            .await
            .expect_err("node 1 failed to confirm");
        assert!(
            matches!(err, Error::BlindedUnconfirmed { .. }),
            "got {err:?}"
        );
        assert!(
            fallback.nodes[0]
                .published_blinded
                .lock()
                .expect("lock")
                .is_empty(),
            "no failover to node 0"
        );
    }

    /// A producer this fallback never handed out has no node to go back to,
    /// and is refused without reaching any node.
    #[tokio::test]
    async fn a_blinded_publish_naming_an_unknown_producer_is_refused() {
        let fallback = FallbackBeaconNode::new(vec![blinded_node()]);
        let err = fallback
            .publish_blinded_block(Producer::at(3), ForkName::Electra, &[1])
            .await
            .expect_err("there is no node 3");
        assert!(matches!(err, Error::InconsistentResponse(_)), "got {err:?}");
        assert!(
            fallback.nodes[0]
                .published_blinded
                .lock()
                .expect("lock")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn proposer_preferences_reach_every_node_past_a_failing_one() {
        use ethlambda_types::beacon::containers::gloas::{
            ProposerPreferences, SignedProposerPreferences,
        };

        let preference = SignedProposerPreferences {
            message: ProposerPreferences {
                proposal_slot: 70,
                ..Default::default()
            },
            ..Default::default()
        };
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::new(),
            MockBeaconNode::failing("middle down"),
            MockBeaconNode::new(),
        ]);

        let delivery = fallback
            .submit_proposer_preferences(ForkName::Fulu, std::slice::from_ref(&preference))
            .await
            .expect("two of three accepted");
        assert_eq!(delivery, Delivery::Partly, "the middle node missed it");

        for position in [0, 2] {
            assert_eq!(
                *fallback.nodes[position]
                    .submitted_preferences
                    .lock()
                    .expect("lock"),
                vec![(ForkName::Fulu, vec![preference.clone()])],
                "node {position}"
            );
        }
        assert!(
            fallback.nodes[1]
                .submitted_preferences
                .lock()
                .expect("lock")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn proposer_preferences_every_node_accepted_are_delivered_everywhere() {
        let fallback = FallbackBeaconNode::new(vec![MockBeaconNode::new(), MockBeaconNode::new()]);
        let preference = gloas::SignedProposerPreferences::default();

        let delivery = fallback
            .submit_proposer_preferences(ForkName::Fulu, std::slice::from_ref(&preference))
            .await
            .expect("both accepted");

        assert_eq!(delivery, Delivery::Everywhere);
    }

    #[tokio::test]
    async fn proposer_preferences_no_node_accepted_are_an_error() {
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::failing("down"),
            MockBeaconNode::failing("down too"),
        ]);
        let preference = gloas::SignedProposerPreferences::default();

        fallback
            .submit_proposer_preferences(ForkName::Fulu, std::slice::from_ref(&preference))
            .await
            .expect_err("nobody holds it");
    }

    #[tokio::test]
    async fn registrations_reach_every_node() {
        use ethlambda_types::beacon::builder::{
            SignedValidatorRegistrationV1, ValidatorRegistrationV1,
        };
        use ethlambda_types::beacon::primitives::{BlsPubkey, BlsSignature, H160};

        let registration = SignedValidatorRegistrationV1 {
            message: ValidatorRegistrationV1 {
                fee_recipient: H160([1; 20]),
                gas_limit: 30_000_000,
                timestamp: 5,
                pubkey: BlsPubkey([2; 48]),
            },
            signature: BlsSignature([3; 96]),
        };
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::new(),
            MockBeaconNode::failing("middle down"),
            MockBeaconNode::new(),
        ]);

        fallback
            .register_validators(std::slice::from_ref(&registration))
            .await
            .expect("two of three accepted");

        for position in [0, 2] {
            assert_eq!(
                *fallback.nodes[position].registrations.lock().expect("lock"),
                vec![registration.clone()],
                "node {position}"
            );
        }
        assert!(
            fallback.nodes[1]
                .registrations
                .lock()
                .expect("lock")
                .is_empty()
        );
    }

    /// Every node is called at once: the second is called while the first
    /// has not answered yet, so a hung node does not hold back the ones behind
    /// it. Called in turn, the second would wait for a permit that is only
    /// given once both have been called.
    #[tokio::test]
    async fn every_node_is_called_at_once() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let held = || MockBeaconNode::new().with_registration_gate(gate.clone());
        let fallback = Arc::new(FallbackBeaconNode::new(vec![held(), held()]));

        let call = tokio::spawn({
            let fallback = fallback.clone();
            async move { fallback.register_validators(&[]).await }
        });
        for node in &fallback.nodes {
            node.wait_for_registration_calls(1).await;
        }
        gate.add_permits(2);
        call.await.expect("the call ends").expect("both accept");

        for node in &fallback.nodes {
            assert_eq!(*node.registration_batches.lock().expect("lock"), vec![0]);
        }
    }

    /// Every `--broadcast` topic on.
    fn every_topic() -> Broadcast {
        Broadcast {
            attestations: true,
            blocks: true,
            sync_committee: true,
        }
    }

    /// The request timeout an HTTP node fails a hung request after.
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

    /// The issue's first test: a node that takes every request and never
    /// answers, listed first, with a healthy node second. Once the first probe
    /// has found it silent, attestation data comes from the second at once,
    /// slot after slot, and the hung node is not asked again until it answers
    /// a probe.
    #[tokio::test(start_paused = true)]
    async fn a_hung_first_node_is_not_asked_once_a_probe_finds_it_silent() {
        use std::time::Duration;
        let hung = MockBeaconNode::new()
            .with_attestation_data(96)
            .with_hang(TIMEOUT);
        let fallback =
            FallbackBeaconNode::new(vec![hung, MockBeaconNode::new().with_attestation_data(96)]);
        fallback.probe(96, Duration::from_secs(2)).await;

        for _ in 0..3 {
            let started = tokio::time::Instant::now();
            fallback
                .attestation_data(96, fork_of(96))
                .await
                .expect("the second node answers");
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "within the slot"
            );
        }
        assert_eq!(fallback.nodes[0].hung_calls_to("attestation_data"), 0);
        assert_eq!(fallback.nodes[1].attestation_data_call_count(), 3);

        // It answers its next probe, and is first again.
        fallback.nodes[0].set_hang(None);
        fallback.probe(97, Duration::from_secs(2)).await;
        fallback
            .attestation_data(96, fork_of(96))
            .await
            .expect("the first node answers");
        assert_eq!(fallback.nodes[0].attestation_data_call_count(), 1);
        assert_eq!(fallback.nodes[1].attestation_data_call_count(), 3);
    }

    /// Before any probe has found it, a hung node costs one request timeout:
    /// the request that timed out ranks it last at once, so the next request
    /// goes straight to the healthy node, and so does every one after it until
    /// the hung node answers a probe. A probe it does not answer keeps it last.
    #[tokio::test(start_paused = true)]
    async fn a_request_that_timed_out_ranks_its_node_last_until_a_probe_answers() {
        use std::time::Duration;
        let hung = MockBeaconNode::new()
            .with_attestation_data(96)
            .with_hang(TIMEOUT);
        let fallback =
            FallbackBeaconNode::new(vec![hung, MockBeaconNode::new().with_attestation_data(96)]);

        let started = tokio::time::Instant::now();
        fallback
            .attestation_data(96, fork_of(96))
            .await
            .expect("the second node answers after the first timed out");
        assert!(started.elapsed() >= TIMEOUT);
        assert_eq!(fallback.nodes[0].hung_calls_to("attestation_data"), 1);

        let started = tokio::time::Instant::now();
        fallback
            .attestation_data(96, fork_of(96))
            .await
            .expect("the second node answers");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(fallback.nodes[0].hung_calls_to("attestation_data"), 1);

        fallback.probe(97, Duration::from_secs(2)).await;
        fallback
            .attestation_data(96, fork_of(96))
            .await
            .expect("the second node answers");
        assert_eq!(fallback.nodes[0].hung_calls_to("attestation_data"), 1);

        fallback.nodes[0].set_hang(None);
        fallback.probe(98, Duration::from_secs(2)).await;
        fallback
            .attestation_data(96, fork_of(96))
            .await
            .expect("the first node answers");
        assert_eq!(fallback.nodes[0].attestation_data_call_count(), 1);
        assert_eq!(fallback.nodes[1].attestation_data_call_count(), 3);
    }

    /// A node that reports itself not syncing but further behind its clock
    /// than the tolerance is asked after a synced node listed behind it; one
    /// within the tolerance keeps its place.
    #[tokio::test]
    async fn a_node_behind_by_its_sync_distance_is_asked_after_a_synced_one() {
        for (sync_distance, first_asked) in
            [(crate::beacon_node::health::SYNC_TOLERANCE + 1, 1), (5, 0)]
        {
            let lagging = MockBeaconNode::new().with_attestation_data(96);
            lagging.set_sync_status(SyncStatus {
                head_slot: Some(96 - sync_distance),
                sync_distance: Some(sync_distance),
                is_syncing: false,
                is_optimistic: false,
                el_offline: false,
            });
            let fallback = FallbackBeaconNode::new(vec![
                lagging,
                MockBeaconNode::new().with_attestation_data(96),
            ]);
            fallback.probe(96, std::time::Duration::from_secs(1)).await;

            fallback
                .attestation_data(96, fork_of(96))
                .await
                .expect("attestation data");
            assert_eq!(
                fallback.nodes[first_asked].attestation_data_call_count(),
                1,
                "sync distance {sync_distance}"
            );
            assert_eq!(
                fallback.nodes[1 - first_asked].attestation_data_call_count(),
                0,
                "sync distance {sync_distance}"
            );
        }
    }

    /// Two nodes that both answered synced are asked in the order listed.
    #[tokio::test]
    async fn two_healthy_nodes_are_asked_in_command_line_order() {
        let fallback = FallbackBeaconNode::new(vec![answering(1), answering(2)]);
        fallback.probe(96, std::time::Duration::from_secs(1)).await;

        fallback
            .attestation_data(96, fork_of(96))
            .await
            .expect("attestation data");
        assert_eq!(
            fallback.head_block_root().await.expect("a head"),
            Root::repeat_byte(1)
        );
        assert_eq!(fallback.nodes[0].attestation_data_call_count(), 1);
        assert_eq!(fallback.nodes[1].attestation_data_call_count(), 0);
    }

    /// The issue's blinded-block test: a node ranked first but listed second
    /// produces the block, which goes back to position 1, under `--broadcast
    /// blocks` too.
    #[tokio::test]
    async fn a_blinded_block_ranked_first_but_listed_second_goes_back_to_position_one() {
        let lagging = blinded_node();
        lagging.set_sync_status(SyncStatus {
            head_slot: Some(1),
            sync_distance: Some(40),
            is_syncing: false,
            is_optimistic: false,
            el_offline: false,
        });
        let fallback =
            FallbackBeaconNode::new(vec![lagging, blinded_node()]).with_broadcast(every_topic());
        fallback.probe(5, std::time::Duration::from_secs(1)).await;
        assert_eq!(fallback.health().tiers()[0], (1, Tier::Synced));

        let produced = fallback
            .produce_block(&blinded_request(5, 7))
            .await
            .expect("node 1 produces");
        assert_eq!(produced.producer, Producer::at(1));
        fallback
            .publish_blinded_block(produced.producer, ForkName::Electra, &[4])
            .await
            .expect("published");
        assert!(
            fallback.nodes[0]
                .published_blinded
                .lock()
                .expect("lock")
                .is_empty()
        );
        assert_eq!(
            *fallback.nodes[1].published_blinded.lock().expect("lock"),
            vec![(ForkName::Electra, vec![4])]
        );
    }

    /// The issue's broadcast test: answers of 202, a hang and 200 report the
    /// 200, wherever it is in the list, and every node that answered got the
    /// same body. The hung node is not waited for past the grace, so a caller
    /// with a deadline shorter than the request timeout, as a proposal has,
    /// still gets the answer. Being cut off does not rank it failing (its
    /// probe does that), so the next broadcast is sent to it again, and again
    /// waits for it no longer than the grace.
    #[tokio::test(start_paused = true)]
    async fn a_broadcast_block_answered_202_a_hang_and_200_reports_the_200() {
        use std::time::Duration;
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::new().with_publish_outcome(Published::BroadcastNotImported),
            MockBeaconNode::new().with_hang(TIMEOUT),
            MockBeaconNode::new(),
        ])
        .with_broadcast(Broadcast {
            blocks: true,
            ..Broadcast::default()
        });

        let deadline = TIMEOUT / 4;
        let outcome =
            tokio::time::timeout(deadline, fallback.publish_block(ForkName::Electra, b"body"))
                .await
                .expect("answered before a deadline shorter than the hang")
                .expect("two nodes took it");
        assert_eq!(outcome, Published::Imported);
        assert!(!fallback.health().tiers().contains(&(1, Tier::Failing)));
        for position in [0, 2] {
            assert_eq!(
                fallback.nodes[position].published_blocks(),
                vec![(ForkName::Electra, b"body".to_vec())],
                "node {position}"
            );
        }
        assert_eq!(fallback.nodes[1].hung_calls_to("publish_block"), 1);

        let started = tokio::time::Instant::now();
        fallback
            .publish_block(ForkName::Electra, b"next")
            .await
            .expect("two nodes took it");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(fallback.nodes[1].hung_calls_to("publish_block"), 2);
    }

    /// A node that answers every broadcast a little later than the grace, as
    /// one slower to import a block does, is cut off each time but never
    /// ranked failing for it: it is sent every broadcast, rather than being
    /// cut out of the rest of each slot's broadcasts until its next probe.
    #[tokio::test(start_paused = true)]
    async fn a_slow_node_cut_off_by_a_broadcast_is_not_ranked_failing() {
        use std::time::Duration;
        let slower = BROADCAST_GRACE + Duration::from_millis(100);
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::new(),
            MockBeaconNode::new().with_slow_answers(slower),
        ])
        .with_broadcast(every_topic());

        for _ in 0..2 {
            let started = tokio::time::Instant::now();
            fallback
                .submit_attestations(&[single_attestation(11)], "electra")
                .await
                .expect("the first node took it");
            // Waited out the grace: the slow node was sent it, every time.
            assert!(started.elapsed() >= BROADCAST_GRACE);
            assert!(started.elapsed() < slower);
            assert!(!fallback.health().tiers().contains(&(1, Tier::Failing)));
        }
    }

    /// A 202 is still a block on the network, so it is the answer when no node
    /// imported; no node taking it at all is every node failing.
    #[tokio::test]
    async fn a_broadcast_block_no_node_imported_is_a_202_and_none_taking_it_an_error() {
        let blocks = Broadcast {
            blocks: true,
            ..Broadcast::default()
        };
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::failing("down"),
            MockBeaconNode::new().with_publish_outcome(Published::BroadcastNotImported),
        ])
        .with_broadcast(blocks);
        let outcome = fallback
            .publish_block(ForkName::Electra, b"body")
            .await
            .expect("one node took it");
        assert_eq!(outcome, Published::BroadcastNotImported);

        let down = FallbackBeaconNode::new(vec![
            MockBeaconNode::failing("down"),
            MockBeaconNode::failing("also down"),
        ])
        .with_broadcast(blocks);
        let err = down
            .publish_block(ForkName::Electra, b"body")
            .await
            .expect_err("no node took it");
        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
    }

    fn single_attestation(attester_index: ValidatorIndex) -> SingleAttestationDto {
        let data = MockBeaconNode::new()
            .with_attestation_data(96)
            .attestation_data
            .expect("set");
        SingleAttestationDto {
            committee_index: 0,
            attester_index,
            data: crate::beacon_node::dto::AttestationDataOutDto::from(&data),
            signature: crate::beacon_node::dto::encode_hex(&[7u8; 96]),
        }
    }

    fn payload_vote() -> gloas::PayloadAttestationMessage {
        gloas::PayloadAttestationMessage {
            validator_index: 3,
            data: gloas::PayloadAttestationData {
                beacon_block_root: Root::repeat_byte(1),
                slot: 96,
                payload_present: true,
                blob_data_available: true,
            },
            signature: Default::default(),
        }
    }

    /// `--broadcast attestations` sends attestations, aggregates and payload
    /// votes to every node, the same signed message to each, and succeeds
    /// past a node that refused. Without it the first node takes them alone.
    #[tokio::test]
    async fn broadcast_attestations_reach_every_node() {
        let nodes = || {
            vec![
                MockBeaconNode::new(),
                MockBeaconNode::failing("down"),
                MockBeaconNode::new(),
            ]
        };
        let fallback = FallbackBeaconNode::new(nodes()).with_broadcast(Broadcast {
            attestations: true,
            ..Broadcast::default()
        });
        let accepted = fallback
            .submit_attestations(&[single_attestation(11)], "electra")
            .await
            .expect("two nodes took it");
        assert_eq!(accepted, 1);
        fallback
            .publish_aggregates(ForkName::Electra, &SignedAggregates::Electra(Vec::new()))
            .await
            .expect("two nodes took it");
        fallback
            .submit_payload_attestations(&[payload_vote()])
            .await
            .expect("two nodes took it");
        for position in [0, 2] {
            let node = &fallback.nodes[position];
            let submitted = node.submitted();
            assert_eq!(submitted.len(), 1, "node {position}");
            assert_eq!(submitted[0].attester_index, 11);
            assert_eq!(submitted[0].signature, single_attestation(11).signature);
            assert_eq!(node.published_aggregates().len(), 1, "node {position}");
            assert_eq!(node.submitted_payload_attestations(), vec![payload_vote()]);
        }

        let one_node = FallbackBeaconNode::new(nodes());
        one_node
            .submit_attestations(&[single_attestation(11)], "electra")
            .await
            .expect("the first node takes it");
        assert_eq!(one_node.nodes[0].submitted().len(), 1);
        assert!(one_node.nodes[2].submitted().is_empty());
    }

    /// `--broadcast sync-committee` sends messages and contributions to every
    /// node.
    #[tokio::test]
    async fn broadcast_sync_committee_messages_reach_every_node() {
        let fallback = FallbackBeaconNode::new(vec![MockBeaconNode::new(), MockBeaconNode::new()])
            .with_broadcast(Broadcast {
                sync_committee: true,
                ..Broadcast::default()
            });
        let message = altair::SyncCommitteeMessage {
            slot: 96,
            beacon_block_root: Root::repeat_byte(2),
            validator_index: 5,
            signature: Default::default(),
        };
        let accepted = fallback
            .submit_sync_committee_messages(std::slice::from_ref(&message))
            .await
            .expect("both took it");
        assert_eq!(accepted, 1);
        fallback
            .publish_contribution_and_proofs(&[])
            .await
            .expect("both took it");
        for node in &fallback.nodes {
            assert_eq!(node.submitted_sync_messages(), vec![message.clone()]);
        }
    }

    /// A node ranked failing is sent a broadcast only when no other node
    /// took it: here the only other node is down, so the one that timed out
    /// last time, and answers now, is asked after it.
    #[tokio::test(start_paused = true)]
    async fn a_failing_node_is_sent_a_broadcast_when_no_other_node_takes_it() {
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::new().with_hang(TIMEOUT),
            MockBeaconNode::failing("down"),
        ])
        .with_broadcast(every_topic());

        let err = fallback
            .submit_attestations(&[single_attestation(11)], "electra")
            .await
            .expect_err("neither took it");
        assert!(matches!(err, Error::AllBeaconNodesFailed(_)), "got {err:?}");
        assert_eq!(fallback.health().tiers()[1], (0, Tier::Failing));

        fallback.nodes[0].set_hang(None);
        let accepted = fallback
            .submit_attestations(&[single_attestation(11)], "electra")
            .await
            .expect("the failing node takes it once the other refused");
        assert_eq!(accepted, 1);
        assert_eq!(fallback.nodes[0].submitted().len(), 1);
    }

    /// Under `--broadcast blocks` an envelope goes to the node that produced
    /// its block first, and to the rest only once that node has answered (or
    /// its head start ran out; see the next test). One
    /// without its blobs goes to the producer alone, since only it cached
    /// them, with or without the flag. Without the flag, one with its blobs is
    /// the first node in the walk that takes it, as before.
    #[tokio::test]
    async fn a_broadcast_envelope_goes_to_its_producer_first_then_to_the_rest() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let producer = MockBeaconNode::new().with_envelope_publish_gate(gate.clone());
        let blocks = Broadcast {
            blocks: true,
            ..Broadcast::default()
        };
        let fallback = Arc::new(
            FallbackBeaconNode::new(vec![MockBeaconNode::new(), producer, MockBeaconNode::new()])
                .with_broadcast(blocks),
        );

        let publish = tokio::spawn({
            let fallback = fallback.clone();
            async move {
                fallback
                    .publish_execution_payload_envelope_produced_by(
                        Producer::at(1),
                        b"envelope",
                        true,
                    )
                    .await
            }
        });
        fallback.nodes[1].envelope_publish_entered.notified().await;
        assert!(fallback.nodes[0].published_envelopes().is_empty());
        assert!(fallback.nodes[2].published_envelopes().is_empty());
        gate.add_permits(1);
        publish.await.expect("the publish ends").expect("published");
        for node in fallback.nodes.iter() {
            assert_eq!(
                node.published_envelopes(),
                vec![(b"envelope".to_vec(), true)]
            );
        }

        let bare = FallbackBeaconNode::new(vec![MockBeaconNode::new(), MockBeaconNode::new()])
            .with_broadcast(blocks);
        bare.publish_execution_payload_envelope_produced_by(Producer::at(1), b"bare", false)
            .await
            .expect("published");
        assert!(bare.nodes[0].published_envelopes().is_empty());
        assert_eq!(
            bare.nodes[1].published_envelopes(),
            vec![(b"bare".to_vec(), false)]
        );

        let one_node = FallbackBeaconNode::new(vec![MockBeaconNode::new(), MockBeaconNode::new()]);
        one_node
            .publish_execution_payload_envelope_produced_by(Producer::at(1), b"walked", true)
            .await
            .expect("published");
        assert_eq!(one_node.nodes[0].published_envelopes().len(), 1);
        assert!(one_node.nodes[1].published_envelopes().is_empty());

        one_node
            .publish_execution_payload_envelope_produced_by(Producer::at(1), b"bare", false)
            .await
            .expect("published");
        assert_eq!(one_node.nodes[0].published_envelopes().len(), 1);
        assert_eq!(
            one_node.nodes[1].published_envelopes(),
            vec![(b"bare".to_vec(), false)],
            "a body without its blobs goes to its producer without the flag too"
        );

        // A producer that does not take it is followed by the walk: a block
        // with no blobs can be revealed through any node.
        let refusing = || {
            MockBeaconNode::new()
                .failing_call("publish_execution_payload_envelope", "no cached blobs")
        };
        for broadcast in [Broadcast::default(), blocks] {
            let fallback = FallbackBeaconNode::new(vec![MockBeaconNode::new(), refusing()])
                .with_broadcast(broadcast);
            fallback
                .publish_execution_payload_envelope_produced_by(Producer::at(1), b"bare", false)
                .await
                .expect("the other node takes it");
            assert_eq!(
                fallback.nodes[0].published_envelopes(),
                vec![(b"bare".to_vec(), false)]
            );
        }

        // The walk leaves out the producer that just refused it: with no
        // other node, its refusal is the outcome.
        let alone = FallbackBeaconNode::new(vec![refusing()]).with_broadcast(blocks);
        let err = alone
            .publish_execution_payload_envelope_produced_by(Producer::at(0), b"bare", false)
            .await
            .expect_err("the only node refused it");
        assert!(
            matches!(&err, Error::AllBeaconNodesFailed(detail) if detail.contains("no cached blobs")),
            "got {err:?}"
        );
    }

    /// A producer that holds its envelope's request open, as one that
    /// answered the block 202 and waits for a block it never imported does,
    /// keeps the envelope from the other nodes for its head start only. They
    /// are sent it then, so the reveal lands well inside a proposal's
    /// deadline, which would otherwise cut it before any other node had it.
    #[tokio::test(start_paused = true)]
    async fn a_producer_that_holds_its_envelope_open_does_not_keep_it_from_the_rest() {
        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::new(),
            MockBeaconNode::new().with_hang(TIMEOUT),
            MockBeaconNode::new(),
        ])
        .with_broadcast(Broadcast {
            blocks: true,
            ..Broadcast::default()
        });

        let deadline = TIMEOUT / 4;
        let started = tokio::time::Instant::now();
        tokio::time::timeout(
            deadline,
            fallback.publish_execution_payload_envelope_produced_by(
                Producer::at(1),
                b"envelope",
                true,
            ),
        )
        .await
        .expect("answered before the deadline")
        .expect("the other nodes took it");
        assert!(started.elapsed() <= PRODUCER_HEAD_START + BROADCAST_GRACE);
        assert_eq!(
            fallback.nodes[1].hung_calls_to("publish_execution_payload_envelope"),
            1,
            "the producer was sent it first, and once"
        );
        for position in [0, 2] {
            assert_eq!(
                fallback.nodes[position].published_envelopes(),
                vec![(b"envelope".to_vec(), true)],
                "node {position}"
            );
        }
    }

    /// Doppelganger protection's liveness query asks every node at once and
    /// takes the first answer, so the ranking does not decide who answers: a
    /// node ranked failing for a timed-out request still answers it.
    #[tokio::test(start_paused = true)]
    async fn liveness_is_answered_whatever_the_ranking() {
        let seeing = MockBeaconNode::new()
            .with_attestation_data(96)
            .with_hang(TIMEOUT);
        seeing.live.lock().expect("lock").push((12, 7));
        let fallback = FallbackBeaconNode::new(vec![seeing, MockBeaconNode::failing("down")]);
        fallback
            .attestation_data(96, fork_of(96))
            .await
            .expect_err("neither answers");
        assert_eq!(fallback.health().tiers()[1], (0, Tier::Failing));

        fallback.nodes[0].set_hang(None);
        let answers = fallback.liveness(&[12], &[7]).await.expect("answers");
        assert_eq!(
            answers,
            vec![vec![Liveness {
                index: 7,
                is_live: true
            }]]
        );
    }

    /// `count` registrations with distinct keys. Unsigned: no mock checks.
    fn registrations(
        count: usize,
    ) -> Vec<ethlambda_types::beacon::builder::SignedValidatorRegistrationV1> {
        use ethlambda_types::beacon::builder::{
            SignedValidatorRegistrationV1, ValidatorRegistrationV1,
        };
        use ethlambda_types::beacon::primitives::{BlsPubkey, BlsSignature, H160};

        (0..count)
            .map(|index| {
                let mut pubkey = [0u8; 48];
                pubkey[..8].copy_from_slice(&(index as u64).to_be_bytes());
                SignedValidatorRegistrationV1 {
                    message: ValidatorRegistrationV1 {
                        fee_recipient: H160([1; 20]),
                        gas_limit: 30_000_000,
                        timestamp: 5,
                        pubkey: BlsPubkey(pubkey),
                    },
                    signature: BlsSignature([3; 96]),
                }
            })
            .collect()
    }

    /// Each node works through the batches on its own: while one node holds
    /// its first batch, the other has been sent all of them. In step, the
    /// healthy node would have its second batch only once the hung one
    /// answered its first.
    #[tokio::test]
    async fn a_hung_node_holds_back_only_its_own_batches() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let hung = MockBeaconNode::new().with_registration_gate(gate.clone());
        let fallback = Arc::new(FallbackBeaconNode::new(vec![hung, MockBeaconNode::new()]));
        let sent = registrations(2 * REGISTRATION_BATCH + 1);

        let send = tokio::spawn({
            let (fallback, sent) = (fallback.clone(), sent.clone());
            async move { fallback.register_validators_in_batches(&sent).await }
        });
        let healthy_has_every_batch = async {
            while fallback.nodes[1]
                .registration_batches
                .lock()
                .expect("lock")
                .len()
                < 3
            {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), healthy_has_every_batch)
            .await
            .expect("the healthy node is not held back by the hung one");
        assert_eq!(
            fallback.nodes[0]
                .registration_attempts
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the hung node is still on its first batch"
        );

        gate.add_permits(3);
        let outcomes = send.await.expect("the send ends");
        assert_eq!(outcomes.len(), 3);
        assert!(outcomes.iter().all(Result::is_ok));
        assert_eq!(
            *fallback.nodes[0].registration_batches.lock().expect("lock"),
            vec![REGISTRATION_BATCH, REGISTRATION_BATCH, 1]
        );
    }

    /// A node that cannot be reached is sent no more batches: each would cost
    /// another timeout. A batch counts as sent when any node took it, and as
    /// failed when none did.
    #[tokio::test]
    async fn an_unreachable_node_is_sent_no_more_batches() {
        let sent = registrations(REGISTRATION_BATCH + 1);

        let fallback =
            FallbackBeaconNode::new(vec![MockBeaconNode::failing("down"), MockBeaconNode::new()]);
        let outcomes = fallback.register_validators_in_batches(&sent).await;
        assert!(outcomes.iter().all(Result::is_ok), "node 1 took both");
        let attempts = |position: usize| {
            fallback.nodes[position]
                .registration_attempts
                .load(std::sync::atomic::Ordering::SeqCst)
        };
        assert_eq!(attempts(0), 1, "stopped after its first batch");
        assert_eq!(attempts(1), 2);

        let fallback = FallbackBeaconNode::new(vec![
            MockBeaconNode::failing("down"),
            MockBeaconNode::failing("also down"),
        ]);
        let outcomes = fallback.register_validators_in_batches(&sent).await;
        assert_eq!(outcomes.len(), 2);
        assert!(
            outcomes
                .iter()
                .all(|outcome| matches!(outcome, Err(Error::AllBeaconNodesFailed(_)))),
            "got {outcomes:?}"
        );
    }
}
