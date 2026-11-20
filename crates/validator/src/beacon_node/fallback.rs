//! Ordered failover across several beacon nodes.
//!
//! First healthy wins, in the order given on the command line. Deliberately not
//! health-scored: Lighthouse ranks its nodes by sync distance and tie-breaks on
//! list order, which is better, and is a refinement this does not need yet.
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
use std::sync::{Mutex, PoisonError};

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
use crate::beacon_node::{
    AggregateAttestation, AttesterDuties, BeaconNodeApi, BlockRequest, Delivery, Genesis,
    ProposerDuties, PtcDuties, Published, SignedAggregates, ValidatorDetails, ValidatorEntry,
};
use crate::chain_check::{ChainId, first_chain_difference, follow_schedule};
use crate::error::{Error, Result};

/// The boxed future `#[async_trait]` desugars a trait method call into,
/// borrowed from the receiver (and, for methods that take borrowed arguments,
/// from those too). Naming it lets [`FallbackBeaconNode::try_each`] state that
/// the future it gets back is tied to one caller-chosen lifetime `'p`, shared
/// by the node reference and whatever else the closure captures, rather than
/// to `Self`.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What an error says when every node was skipped for being on another chain
/// (or not yet known to be on this one), so no request was made at all.
const NO_USABLE_NODE: &str = "no configured beacon node is on this client's chain";

/// Which nodes a [`FallbackBeaconNode::check_nodes`] round asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckScope {
    /// Every node: the round at an epoch's first slot, which also follows the
    /// schedule.
    All,
    /// Only the nodes not usable now, to let them back in as soon as they are
    /// compatible again, and the ones that did not answer their last check,
    /// so a schedule missed in one round is read at the next slot rather than
    /// the next epoch.
    OnlyUnusable,
}

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

/// A `BeaconNodeApi` backed by an ordered list of others, answering from the
/// first one that succeeds.
pub struct FallbackBeaconNode<B> {
    /// In the order given, which never changes: a [`Producer`] is a position
    /// in it, so a blinded block goes back to the node that produced it.
    nodes: Vec<B>,
    /// Whether each node, by position, is on this client's chain. Every call
    /// skips a node whose flag is down.
    usable: Vec<AtomicBool>,
    /// The epoch each node's last unusable-node warning was for, by position,
    /// so a node that stays unusable warns once per epoch rather than once per
    /// slot. `u64::MAX` is never.
    warned_at: Vec<AtomicU64>,
    /// Whether each node, by position, failed to answer its last check. Such
    /// a node is asked again every slot, whatever its usable flag says.
    unanswered: Vec<AtomicBool>,
    /// The configuration each node last served while on this client's chain,
    /// by position: what the schedule is followed from. Kept through a check
    /// the node does not answer, so one missed round does not drop its
    /// schedule, and dropped when the node turns out to be on another chain.
    served: Vec<Mutex<Option<Config>>>,
}

impl<B: BeaconNodeApi> FallbackBeaconNode<B> {
    /// Every node starts usable, so a caller that never runs a check (the
    /// one-shot `voluntary-exit` command, a test) behaves as before.
    /// [`Self::establish`] is what takes a node out.
    pub fn new(nodes: Vec<B>) -> Self {
        assert!(!nodes.is_empty(), "at least one beacon node is required");
        let usable = nodes.iter().map(|_| AtomicBool::new(true)).collect();
        let warned_at = nodes.iter().map(|_| AtomicU64::new(u64::MAX)).collect();
        let unanswered = nodes.iter().map(|_| AtomicBool::new(false)).collect();
        let served = nodes.iter().map(|_| Mutex::new(None)).collect();
        Self {
            nodes,
            usable,
            warned_at,
            unanswered,
            served,
        }
    }

    fn is_usable(&self, position: usize) -> bool {
        self.usable[position].load(Ordering::Relaxed)
    }

    fn set_served(&self, position: usize, config: Option<Config>) {
        *self.served[position]
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = config;
    }

    /// The configuration each usable node last served, with its position, in
    /// list order: what [`crate::chain_check::follow_schedule`] merges. A
    /// usable node that has never answered a check has none and is left out.
    pub fn served_configs(&self) -> Vec<(usize, Config)> {
        self.usable_nodes()
            .filter_map(|(position, _)| {
                let served = self.served[position]
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                served.clone().map(|config| (position, config))
            })
            .collect()
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
        self.warned_at[position].swap(epoch, Ordering::Relaxed) != epoch
    }

    /// Set `position`'s flag from what its check found, and say so when that
    /// changes it: at `info` for a node coming back, at `warn` for one going
    /// out, then again at most once per epoch for as long as it stays out.
    fn record(&self, position: usize, answer: &NodeAnswer, epoch: u64) {
        let node = self.nodes[position].describe();
        let unanswered = matches!(answer, NodeAnswer::Unreachable(_));
        self.unanswered[position].store(unanswered, Ordering::Relaxed);
        match answer {
            NodeAnswer::Compatible(config) => {
                self.set_served(position, Some((**config).clone()));
                if !self.usable[position].swap(true, Ordering::Relaxed) {
                    info!(position, %node, "Beacon node is on this client's chain; using it");
                }
            }
            NodeAnswer::Incompatible(difference) => {
                self.set_served(position, None);
                let was_usable = self.usable[position].swap(false, Ordering::Relaxed);
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
    /// until a later [`Self::check_nodes`] round verifies it. Fails when no
    /// node answers, naming what each said.
    ///
    /// The chain returned is the reference's with the schedule the compatible
    /// nodes serve already followed
    /// ([`crate::chain_check::follow_schedule`]): a fork still in the future
    /// takes the lowest epoch any of them reports, exactly as at every later
    /// epoch check.
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
        let asked = futures_util::future::join_all(self.nodes.iter().map(ask)).await;
        let Some(reference_at) = asked.iter().position(|answer| answer.is_ok()) else {
            let detail = asked
                .iter()
                .enumerate()
                .filter_map(|(position, answer)| {
                    answer
                        .as_ref()
                        .err()
                        .map(|err| format!("node {position}: {err}"))
                })
                .collect::<Vec<_>>()
                .join("; ");
            warn!(%detail, "No configured beacon node could be used as the chain reference");
            return Err(Error::AllBeaconNodesFailed(detail));
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
                self.usable[position].store(false, Ordering::Relaxed);
            }
            self.record(position, &answer, epoch);
        }

        // Follow the schedule now, not at the next epoch's check: a reference
        // that has not been upgraded would otherwise start the client without
        // a fork another node already schedules, and if that fork's epoch came
        // before the next check, the upgraded node would be the one refused.
        let mut chain = reference;
        if let Some(config) = follow_schedule(&chain.config, &self.served_configs(), epoch) {
            chain.config = config;
        }
        Ok(chain)
    }

    /// Ask the nodes `scope` selects about their chain, all at once and
    /// directly (not through the failover helpers, which would skip exactly
    /// the nodes being asked), and set each one's flag from the answer.
    ///
    /// A node whose chain matches `ours` is usable; one that differs, or is on
    /// another preset, is not. A node that did not answer keeps its flag: an
    /// outage says nothing about the chain. A node going out is warned about
    /// with the first field that differs, then again at most once per epoch.
    ///
    /// Returns one answer per node asked, with its position. The schedule is
    /// followed from [`Self::served_configs`], which this keeps current.
    pub async fn check_nodes(
        &self,
        ours: &ChainId,
        current_epoch: u64,
        scope: CheckScope,
    ) -> Vec<(usize, NodeAnswer)> {
        let selected: Vec<(usize, &B)> = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(position, _)| {
                scope == CheckScope::All
                    || !self.is_usable(*position)
                    || self.unanswered[*position].load(Ordering::Relaxed)
            })
            .collect();
        let asked =
            futures_util::future::join_all(selected.iter().map(|(_, node)| ask(*node))).await;

        let mut answers = Vec::with_capacity(selected.len());
        for ((position, _), asked) in selected.iter().zip(asked) {
            let answer = classify(ours, asked, current_epoch);
            self.record(*position, &answer, current_epoch);
            answers.push((*position, answer));
        }
        answers
    }

    /// The nodes, in order, for a test outside this module that drives a
    /// service through the fallback and then inspects each mock.
    #[cfg(test)]
    pub(crate) fn nodes(&self) -> &[B] {
        &self.nodes
    }

    /// Try each node in order, returning the first success.
    ///
    /// "Success" means the node returned `Ok`, nothing more. That is the right
    /// rule only where an `Ok` is an answer this client can act on, which is
    /// why [`BeaconNodeApi::is_syncing`] does not use this helper: there,
    /// `Ok(true)` is a node reporting itself unusable, and returning it from
    /// the first node would mask every healthy node behind it.
    ///
    /// A node that is syncing is skipped here in practice, because the calls
    /// routed through this helper answer 503 while syncing and 503 is mapped to
    /// an error. That is a property of those endpoints, not something this
    /// function arranges.
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

    /// [`Self::try_each`], also returning the position of the node that
    /// answered, for the calls whose follow-up must go to the same node. The
    /// logging and the final `warn!` live here so the two cannot drift.
    async fn try_each_at<'p, T, F>(&'p self, what: &'static str, call: F) -> Result<(usize, T)>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<T>>,
    {
        self.try_each_at_inner(what, true, call).await
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
        self.try_each_at_inner(what, false, call)
            .await
            .map(|(_, value)| value)
    }

    async fn try_each_at_inner<'p, T, F>(
        &'p self,
        what: &'static str,
        warn_when_all_fail: bool,
        call: F,
    ) -> Result<(usize, T)>
    where
        F: Fn(&'p B) -> BoxFuture<'p, Result<T>>,
    {
        let mut last = None;
        for (position, node) in self.usable_nodes() {
            match call(node).await {
                Ok(value) => return Ok((position, value)),
                Err(err) => {
                    // Debug, not warn: with more than one node configured, an
                    // outage on one of them fires this every slot for as long
                    // as it lasts. The event that actually means the client
                    // missed a duty is every node failing, below.
                    debug!(%what, position, %err, "Beacon node request failed; trying the next");
                    last = Some(err);
                }
            }
        }
        let detail = self.failure_detail(last);
        if warn_when_all_fail {
            warn!(%what, %detail, "All configured beacon nodes failed; duty likely missed");
        }
        Err(Error::AllBeaconNodesFailed(detail))
    }

    /// Send to **every** node, succeeding if any accepted.
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
                    last = Some(err);
                }
            }
        }
        // Nested, so no node at all is never "every node": the constructor
        // refuses an empty list, but this does not lean on it.
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
}

#[async_trait]
impl<B: BeaconNodeApi> BeaconNodeApi for FallbackBeaconNode<B> {
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
    /// the first node and never consult the rest, and the caller
    /// (`refresh_epoch`) turns `true` into "do not refresh duties". A syncing
    /// node at the head of the list would therefore stop duties from being
    /// refreshed for as long as it was syncing, with a perfectly healthy node
    /// sitting behind it unused, which is the opposite of what configuring a
    /// second node is for.
    ///
    /// So: look for a node that is usable, and report `false` the moment one is
    /// found. `true` means every reachable node said it was syncing or
    /// optimistic, which is the only situation where the caller's decision to
    /// hold off is right.
    ///
    /// A node that fails outright is skipped like any other failure, and only
    /// if none answers at all does this surface an error.
    async fn is_optimistic_or_syncing(&self) -> Result<bool> {
        let mut last = None;
        let mut any_answered = false;
        for (position, node) in self.usable_nodes() {
            match node.is_optimistic_or_syncing().await {
                Ok(false) => return Ok(false),
                Ok(true) => {
                    any_answered = true;
                    debug!(
                        position,
                        "Beacon node is syncing or optimistic; trying the next"
                    );
                }
                Err(err) => {
                    debug!(what = "syncing", position, %err, "Beacon node request failed; trying the next");
                    last = Some(err);
                }
            }
        }

        if any_answered {
            // Every node that answered said it was unusable. That is a real
            // answer, not a failure: the caller should hold off, and saying so
            // is more useful than an error claiming nothing could be reached.
            return Ok(true);
        }

        let detail = self.failure_detail(last);
        warn!(
            what = "syncing",
            %detail, "All configured beacon nodes failed; duty likely missed"
        );
        Err(Error::AllBeaconNodesFailed(detail))
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
        // Quiet: the preferences service reports its own failure once per
        // epoch, and no duty depends on this answer.
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

    /// First node that accepts it wins, rather than a broadcast to every node.
    ///
    /// Publishing is the one call where that choice is not obvious, because
    /// sending to every node would reach more of the network's gossip mesh at
    /// once. It stays first-wins for now because a node that accepts a block
    /// gossips it, so the second node would receive it over the network in any
    /// case, and because a broadcast makes the outcome ambiguous: with three
    /// nodes answering 200, 202 and a timeout, there is no single answer to
    /// report.
    ///
    /// A 202 counts as success and stops the walk. The node could not import
    /// the block, but it did broadcast it, so the network has it and offering
    /// it to another node would not change that.
    async fn publish_block(&self, fork: ForkName, body: &[u8]) -> Result<Published> {
        self.try_each("publish_block", |node| node.publish_block(fork, body))
            .await
    }

    /// Only on the node that produced the block, with no failover.
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
    /// when some node refused, so the service sends it again until every node
    /// holds it.
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
    /// is: the accepting node gossips it.
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

    async fn ptc_duties(&self, epoch: Epoch, indices: &[ValidatorIndex]) -> Result<PtcDuties> {
        self.try_each("ptc_duties", |node| node.ptc_duties(epoch, indices))
            .await
    }

    /// A 204 is an answer, so the first node that knows no block ends the
    /// walk, even though another might have one. That is the right trade: PTC
    /// votes are due at three quarters of the slot, and a node that has seen
    /// nothing by then is one this client should not be voting through.
    async fn payload_attestation_data(
        &self,
        slot: Slot,
    ) -> Result<Option<gloas::PayloadAttestationData>> {
        self.try_each("payload_attestation_data", |node| {
            node.payload_attestation_data(slot)
        })
        .await
    }

    async fn submit_payload_attestations(
        &self,
        messages: &[gloas::PayloadAttestationMessage],
    ) -> Result<usize> {
        self.try_each("submit_payload_attestations", |node| {
            node.submit_payload_attestations(messages)
        })
        .await
    }

    async fn submit_attestations(
        &self,
        attestations: &[SingleAttestationDto],
        fork_name: &str,
    ) -> Result<usize> {
        self.try_each("submit_attestations", |node| {
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

    async fn publish_aggregates(
        &self,
        fork: ForkName,
        aggregates: &SignedAggregates,
    ) -> Result<()> {
        self.try_each("publish_aggregates", |node| {
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
    /// tracking an unvalidated head is walked past rather than signed over.
    async fn head_block_root(&self) -> Result<Root> {
        self.try_each("head_block_root", |node| node.head_block_root())
            .await
    }

    async fn submit_sync_committee_messages(
        &self,
        messages: &[altair::SyncCommitteeMessage],
    ) -> Result<usize> {
        self.try_each("submit_sync_committee_messages", |node| {
            node.submit_sync_committee_messages(messages)
        })
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

    async fn publish_contribution_and_proofs(
        &self,
        contributions: &[altair::SignedContributionAndProof],
    ) -> Result<()> {
        self.try_each("publish_contribution_and_proofs", |node| {
            node.publish_contribution_and_proofs(contributions)
        })
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

    /// A syncing node at the head of the list must not stop duties being
    /// refreshed when a healthy node sits behind it.
    ///
    /// `is_syncing` returning `Ok(true)` is a *successful* call, so a plain
    /// `try_each` would return the first node's answer and never look further.
    /// `refresh_epoch` turns `true` into "do not refresh", so the second node
    /// would go unused for as long as the first was syncing.
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
