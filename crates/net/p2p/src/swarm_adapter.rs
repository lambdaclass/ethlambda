use std::collections::HashMap;
use std::time::Duration;

use libp2p::{
    PeerId,
    futures::StreamExt,
    gossipsub::{FailedMessages, IdentTopic, MessageId, PublishError, TopicScoreParams},
    request_response,
    swarm::{SwarmEvent, dial_opts::DialOpts},
};
use tokio::{sync::mpsc, time::MissedTickBehavior};
use tracing::{debug, error, info, warn};

use crate::{
    Behaviour, BehaviourEvent, ReqRespProtocol, ReqRespRequestId, beacon::scoring, metrics,
    req_resp::Request, req_resp::Response,
};

/// Interval between gossipsub mesh peer metric refreshes, and between the
/// checks that disconnect peers scored below the graylist or persistently slow.
const MESH_METRIC_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// How many consecutive [`MESH_METRIC_REFRESH_INTERVAL`] checks a peer must
/// have failed gossipsub sends in before it is disconnected; see [`SlowPeers`].
const SLOW_PEER_CHECK_LIMIT: u32 = 6;

/// A `SlowPeer` report counts towards a peer's streak only when its priority
/// or its non-priority failures exceed this. Lighthouse uses the same cut
/// before it penalizes a slow peer. A few failures in one heartbeat are more
/// likely late forwards that expired in the queue than a dead stream.
const SLOW_PEER_REPORT_THRESHOLD: usize = 10;

/// The most peers one check disconnects for being slow; see
/// [`SlowPeers::check`]. Gossipsub reports a forward that waited too long in a
/// peer's queue the same way it reports a full queue, so a saturated uplink or
/// a stalled runtime on our side makes every peer look slow at once.
/// Disconnecting them all in one check would leave the node without peers.
///
/// The cap bounds the rate, not the total: an uplink that stays too slow for
/// gossip past the streak still drains peers, this many per check, while
/// discovery refills them. That case is deliberately left alone, since
/// bandwidth that slow is not something the node can solve from its side.
const MAX_SLOW_PEER_DISCONNECTS_PER_CHECK: usize = 10;

pub enum SwarmCommand {
    Publish {
        topic: libp2p::gossipsub::IdentTopic,
        data: Vec<u8>,
        /// Where to report what gossipsub did with it, for a caller that logs
        /// or keeps state on the answer (see [`SwarmHandle::publish_reporting`]).
        /// `None` for a fire-and-forget publish, whose failure the adapter logs
        /// at debug itself.
        outcome_tx: Option<tokio::sync::oneshot::Sender<PublishOutcome>>,
    },
    /// Join a topic after startup: the aggregator subnets, which a validator
    /// client names slot by slot.
    Subscribe(libp2p::gossipsub::IdentTopic),
    Unsubscribe(libp2p::gossipsub::IdentTopic),
    Dial {
        /// Carries the full set of addresses worth trying for one dial attempt
        /// (a peer's QUIC and TCP ports both, say): libp2p races every address
        /// in a single `DialOpts` rather than treating each as a separate
        /// attempt, which is what lets a live TCP address rescue a dial whose
        /// advertised QUIC port does not answer.
        opts: DialOpts,
        /// Callback reporting what the swarm did with the dial. `None` when the
        /// caller does not need to know.
        outcome_tx: Option<tokio::sync::oneshot::Sender<DialOutcome>>,
    },
    SendRequest {
        peer: PeerId,
        request: Request,
        protocol: ReqRespProtocol,
        /// Callback to report the assigned [`ReqRespRequestId`].
        request_id_tx: Option<tokio::sync::oneshot::Sender<ReqRespRequestId>>,
    },
    SendResponse {
        channel: request_response::ResponseChannel<Response>,
        response: Response,
    },
    /// Replace these topics' score parameters (beacon only; see
    /// [`scoring::refresh`] and [`crate::beacon::transition::apply`], which
    /// sends them ahead of the topics it joins).
    SetTopicScoreParams(Vec<(IdentTopic, TopicScoreParams)>),
    /// A verdict for a gossip message gossipsub is holding (beacon only).
    ReportValidation {
        message_id: libp2p::gossipsub::MessageId,
        propagation_source: PeerId,
        acceptance: libp2p::gossipsub::MessageAcceptance,
        /// Topic kind, for the expired-verdict metric.
        kind: &'static str,
    },
}

/// What the swarm did with a dial, as far as a caller's bookkeeping cares.
///
/// The distinction matters because the two refusals want opposite handling. A
/// dial refused because one is already in flight has a terminal event coming
/// (`ConnectionEstablished` then eventually `ConnectionClosed`, or
/// `OutgoingConnectionError`), so per-peer bookkeeping recorded now is still
/// torn down later. A dial nothing will ever come of has no such event, so
/// recording anything would leak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialOutcome {
    /// The swarm took the dial. A terminal event will follow.
    Queued,
    /// Refused because this peer is already connected or already being dialed.
    /// That other attempt still produces a terminal event.
    AlreadyInProgress,
    /// Refused with nothing in flight and nothing to come: no address to dial, a
    /// behaviour denied it, the peer is us, or the adapter is gone.
    Unreachable,
}

impl From<&libp2p::swarm::DialError> for DialOutcome {
    /// Matched exhaustively on purpose. `DialError` is not `#[non_exhaustive]`
    /// in the pinned fork, so a variant added on a fork upgrade breaks the build
    /// here and forces a decision, rather than being absorbed by a wildcard as
    /// `Unreachable` — the classification that leaks bookkeeping if it is wrong.
    fn from(err: &libp2p::swarm::DialError) -> Self {
        use libp2p::swarm::DialError;
        match err {
            DialError::DialPeerConditionFalse(_) => Self::AlreadyInProgress,
            // The other three refusals `Swarm::dial` returns synchronously.
            DialError::LocalPeerId { .. } | DialError::NoAddresses | DialError::Denied { .. } => {
                Self::Unreachable
            }
            // Reached only through a terminal `OutgoingConnectionError`, never
            // from `Swarm::dial` itself, so no caller reads this answer; the
            // conservative one is still the right default.
            DialError::Aborted | DialError::WrongPeerId { .. } | DialError::Transport(_) => {
                Self::Unreachable
            }
        }
    }
}

/// What gossipsub did with a publish, for a caller that asked for it through
/// [`SwarmHandle::publish_reporting`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishOutcome {
    /// Handed to at least one peer.
    Published,
    /// Refused as a duplicate. A message's id is its topic and payload alone,
    /// and gossipsub keeps the id of every message it sent to a peer or
    /// received from one for its duplicate cache's lifetime (`seen_ttl`, two
    /// epochs on the beacon wire), refusing to publish it again until then. So
    /// this very message went out from this node earlier, or a peer sent it
    /// here: it cannot be sent again, and that is not this publish failing.
    /// (An earlier publish that found every peer's queue full left its id
    /// there too, so its retry also lands here although no peer got it.)
    Duplicate,
    /// Not handed to any peer, with the reason for the log: no peer is
    /// subscribed to the topic (`NoPeersSubscribedToTopic`, in which case
    /// gossipsub keeps no trace of the message and a later publish of it can
    /// still go out), every recipient's queue was full, the message is too
    /// large, or the adapter is gone.
    Failed(String),
}

impl From<Result<MessageId, PublishError>> for PublishOutcome {
    fn from(result: Result<MessageId, PublishError>) -> Self {
        match result {
            Ok(_) => Self::Published,
            Err(PublishError::Duplicate) => Self::Duplicate,
            Err(err) => Self::Failed(err.to_string()),
        }
    }
}

impl PublishOutcome {
    /// The answer when the adapter never ran the publish.
    fn adapter_closed() -> Self {
        Self::Failed("the swarm adapter is closed".to_string())
    }

    /// Whether no peer was handed the message, so it is still owed a publish.
    pub fn failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }
}

/// A publish already queued with the adapter, whose [`PublishOutcome`] is read
/// with [`Self::outcome`]. The publish does not wait for the receipt to be
/// read, so a caller can hand off other work first.
#[must_use = "the receipt is how the publish's outcome is read"]
pub struct PublishReceipt(Option<tokio::sync::oneshot::Receiver<PublishOutcome>>);

impl PublishReceipt {
    /// What gossipsub did with the publish, once the adapter has run it.
    pub async fn outcome(self) -> PublishOutcome {
        let Some(outcome_rx) = self.0 else {
            return PublishOutcome::adapter_closed();
        };
        outcome_rx
            .await
            .unwrap_or_else(|_| PublishOutcome::adapter_closed())
    }
}

#[derive(Clone)]
pub struct SwarmHandle {
    cmd_tx: mpsc::UnboundedSender<SwarmCommand>,
}

impl SwarmHandle {
    pub fn publish(&self, topic: libp2p::gossipsub::IdentTopic, data: Vec<u8>) {
        let _ = self
            .cmd_tx
            .send(SwarmCommand::Publish {
                topic,
                data,
                outcome_tx: None,
            })
            .inspect_err(|_| debug!("Swarm adapter closed, cannot publish"));
    }

    /// [`Self::publish`], reporting what gossipsub did with it. The publish is
    /// queued at once, in order with every other command; the receipt only
    /// reads its answer.
    ///
    /// For a caller that logs the outcome itself, at the level its topic
    /// warrants, or remembers it: the adapter logs nothing for these.
    pub fn publish_reporting(
        &self,
        topic: libp2p::gossipsub::IdentTopic,
        data: Vec<u8>,
    ) -> PublishReceipt {
        let (outcome_tx, outcome_rx) = tokio::sync::oneshot::channel();
        let queued = self
            .cmd_tx
            .send(SwarmCommand::Publish {
                topic,
                data,
                outcome_tx: Some(outcome_tx),
            })
            .is_ok();
        PublishReceipt(queued.then_some(outcome_rx))
    }

    pub fn subscribe(&self, topic: libp2p::gossipsub::IdentTopic) {
        let _ = self
            .cmd_tx
            .send(SwarmCommand::Subscribe(topic))
            .inspect_err(|_| debug!("Swarm adapter closed, cannot subscribe"));
    }

    pub fn unsubscribe(&self, topic: libp2p::gossipsub::IdentTopic) {
        let _ = self
            .cmd_tx
            .send(SwarmCommand::Unsubscribe(topic))
            .inspect_err(|_| debug!("Swarm adapter closed, cannot unsubscribe"));
    }

    pub fn dial(&self, opts: DialOpts) {
        let _ = self
            .cmd_tx
            .send(SwarmCommand::Dial {
                opts,
                outcome_tx: None,
            })
            .inspect_err(|_| debug!("Swarm adapter closed, cannot dial"));
    }

    /// Dial and report what the swarm did with it.
    ///
    /// `Swarm::dial` rejects some dials synchronously — `LocalPeerId`,
    /// `NoAddresses`, `Denied`, and `DialPeerConditionFalse` (already connected,
    /// or already dialing) — and those produce **no** `OutgoingConnectionError`
    /// event. A caller that keeps per-dial bookkeeping has to know, or nothing
    /// will ever tear that bookkeeping down, and it has to know *which* refusal
    /// it was: see [`DialOutcome`].
    ///
    /// [`DialOutcome::Queued`] only means the dial was taken: success or failure
    /// still arrives later as `ConnectionEstablished` or
    /// `OutgoingConnectionError`.
    pub async fn dial_outcome(&self, opts: DialOpts) -> DialOutcome {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self
            .cmd_tx
            .send(SwarmCommand::Dial {
                opts,
                outcome_tx: Some(tx),
            })
            .is_err()
        {
            debug!("Swarm adapter closed, cannot dial");
            return DialOutcome::Unreachable;
        }
        rx.await.unwrap_or(DialOutcome::Unreachable)
    }

    /// Send a request on `protocol`'s own field and return the assigned
    /// [`ReqRespRequestId`]. Must be called from an async context (actor
    /// handlers are async).
    pub async fn send_request(
        &self,
        peer: PeerId,
        request: Request,
        protocol: ReqRespProtocol,
    ) -> Option<ReqRespRequestId> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self
            .cmd_tx
            .send(SwarmCommand::SendRequest {
                peer,
                request,
                protocol,
                request_id_tx: Some(tx),
            })
            .is_err()
        {
            debug!("Swarm adapter closed, cannot send request");
            return None;
        }
        rx.await.ok()
    }

    pub fn send_response(
        &self,
        channel: request_response::ResponseChannel<Response>,
        response: Response,
    ) {
        let _ = self
            .cmd_tx
            .send(SwarmCommand::SendResponse { channel, response })
            .inspect_err(|_| debug!("Swarm adapter closed, cannot send response"));
    }

    pub fn set_topic_score_params(&self, topics: Vec<(IdentTopic, TopicScoreParams)>) {
        let _ = self
            .cmd_tx
            .send(SwarmCommand::SetTopicScoreParams(topics))
            .inspect_err(|_| debug!("Swarm adapter closed, cannot set topic score parameters"));
    }

    pub fn report_validation(
        &self,
        message_id: libp2p::gossipsub::MessageId,
        propagation_source: PeerId,
        acceptance: libp2p::gossipsub::MessageAcceptance,
        kind: &'static str,
    ) {
        let _ = self
            .cmd_tx
            .send(SwarmCommand::ReportValidation {
                message_id,
                propagation_source,
                acceptance,
                kind,
            })
            .inspect_err(|_| debug!("Swarm adapter closed, cannot report a gossip verdict"));
    }

    /// A handle whose commands land in the returned receiver instead of a
    /// swarm, so a test can read what was sent, and in what order.
    #[cfg(test)]
    pub(crate) fn capturing() -> (Self, mpsc::UnboundedReceiver<SwarmCommand>) {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        (Self { cmd_tx }, cmd_rx)
    }
}

pub fn start_swarm_adapter(
    swarm: libp2p::Swarm<Behaviour>,
    node_names: HashMap<PeerId, String>,
) -> (
    impl futures::Stream<Item = SwarmEvent<BehaviourEvent>>,
    SwarmHandle,
) {
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

    tokio::spawn(swarm_loop(swarm, event_tx, cmd_rx, node_names));

    let stream = tokio_stream::wrappers::UnboundedReceiverStream::new(event_rx);
    let handle = SwarmHandle { cmd_tx };
    (stream, handle)
}

async fn swarm_loop(
    mut swarm: libp2p::Swarm<Behaviour>,
    event_tx: mpsc::UnboundedSender<SwarmEvent<BehaviourEvent>>,
    mut cmd_rx: mpsc::UnboundedReceiver<SwarmCommand>,
    node_names: HashMap<PeerId, String>,
) {
    let mut mesh_metric_tick = tokio::time::interval(MESH_METRIC_REFRESH_INTERVAL);
    mesh_metric_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut slow_peers = SlowPeers::default();
    let exit = loop {
        tokio::select! {
            event = swarm.next() => {
                let Some(event) = event else { break LoopExit::SwarmEnded };
                if let SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(
                    libp2p::gossipsub::Event::SlowPeer { peer_id, failed_messages },
                )) = &event
                {
                    slow_peers.record(*peer_id, failed_messages);
                }
                if event_tx.send(event).is_err() { break LoopExit::ActorStopped }
            }
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break LoopExit::ActorStopped };
                execute_command(&mut swarm, cmd);
            }
            _ = mesh_metric_tick.tick() => {
                metrics::update_gossip_mesh_peers(
                    swarm.behaviour().gossipsub.all_mesh_peers(),
                    &node_names,
                );
                // Published from here because this task owns the swarm, and on
                // a timer rather than per connection event so the figure cannot
                // drift when an event is missed: these are the counters the
                // connection limits are actually enforced against, so they are
                // worth reading from the source on a schedule rather than
                // reconstructing. Compared against `lean_peers_by_direction`, a
                // persistent gap is a connection charged to the cap that no
                // live peer is using.
                let info = swarm.network_info();
                let counters = info.connection_counters();
                metrics::set_swarm_established_connections(
                    counters.num_established_incoming(),
                    counters.num_established_outgoing(),
                );
                disconnect_graylisted_peers(&mut swarm);
                disconnect_slow_peers(&mut swarm, &mut slow_peers);
            }
        }
    };
    match exit {
        LoopExit::ActorStopped => info!("Swarm adapter loop stopped: the P2P actor shut down"),
        LoopExit::SwarmEnded => {
            error!(
                "Swarm adapter loop exited: the swarm stopped, so P2P networking is no longer functional"
            )
        }
    }
}

/// Why [`swarm_loop`] returned.
///
/// The P2P actor dropping its end of either channel is how a graceful
/// shutdown reaches this task, so that exit is routine. An actor that panicked
/// instead of stopping looks the same from here, but `spawned-concurrency`
/// already logs that panic as an error. The swarm's own event stream never
/// ends while the swarm lives, so its end is the one exit worth an error.
enum LoopExit {
    ActorStopped,
    SwarmEnded,
}

/// Peers gossipsub reported as failing to take messages, tracked across the
/// periodic checks so that only a persistent failure costs a peer its
/// connection.
///
/// The failure this exists for is a dead gossipsub stream. The connection
/// handler disables itself for good after a handful of substream
/// negotiations on one connection, successful ones included, and from then
/// on never takes another message off the peer's send queue. The behaviour is
/// not told: it keeps queueing for the peer up to the queue's capacity, and
/// queued messages are only dropped when the handler takes them off, so a
/// full queue of message copies stays in memory for as long as the connection
/// lives, which other protocols keep open. The one trace this leaves is
/// gossipsub's `SlowPeer` report, emitted every heartbeat for each peer whose
/// queue refused a message (or that let a message expire in it, which the
/// report does not tell apart). Disconnecting frees the queue; a peer that
/// reconnects gets a fresh handler.
///
/// Three rules keep a slow but working peer, or a slow node of our own, from
/// costing connections:
/// - A report counts only above [`SLOW_PEER_REPORT_THRESHOLD`] failures.
/// - A peer reported in fewer than [`SLOW_PEER_CHECK_LIMIT`] consecutive
///   checks keeps its connection, so a burst of expiries from a peer that
///   catches up is not enough.
/// - One check disconnects at most [`MAX_SLOW_PEER_DISCONNECTS_PER_CHECK`]
///   peers.
#[derive(Default)]
struct SlowPeers {
    /// Failed messages per peer, from the reports since the last check that
    /// passed [`SLOW_PEER_REPORT_THRESHOLD`].
    reported: HashMap<PeerId, usize>,
    /// Per peer, the consecutive checks it has been reported in and the
    /// failed messages across them.
    streaks: HashMap<PeerId, (u32, usize)>,
}

/// What one [`SlowPeers::check`] found.
#[derive(Debug, PartialEq)]
struct SlowPeerCheck {
    /// Peers to disconnect, the most failed messages first, each with its
    /// failed messages across the streak. At most
    /// [`MAX_SLOW_PEER_DISCONNECTS_PER_CHECK`] of them.
    disconnect: Vec<(PeerId, usize)>,
    /// How many more peers reached [`SLOW_PEER_CHECK_LIMIT`] but were left for
    /// a later check by the cap.
    deferred: usize,
}

impl SlowPeers {
    fn record(&mut self, peer_id: PeerId, failed_messages: &FailedMessages) {
        let FailedMessages {
            priority,
            non_priority,
        } = *failed_messages;
        if priority <= SLOW_PEER_REPORT_THRESHOLD && non_priority <= SLOW_PEER_REPORT_THRESHOLD {
            return;
        }
        let reported = self.reported.entry(peer_id).or_default();
        *reported = reported.saturating_add(priority.saturating_add(non_priority));
    }

    /// Closes one check: a peer reported since the last one extends its
    /// streak, every other peer loses it. Of the peers whose streak reached
    /// [`SLOW_PEER_CHECK_LIMIT`], returns the ones with the most failed
    /// messages, up to [`MAX_SLOW_PEER_DISCONNECTS_PER_CHECK`], and forgets
    /// them. The rest keep their streak, so a peer still reported at the next
    /// check is a candidate again then.
    fn check(&mut self) -> SlowPeerCheck {
        let reported = std::mem::take(&mut self.reported);
        self.streaks
            .retain(|peer_id, _| reported.contains_key(peer_id));
        let mut persistent = Vec::new();
        for (peer_id, failed) in reported {
            let (checks, total) = self.streaks.entry(peer_id).or_default();
            *checks += 1;
            *total = total.saturating_add(failed);
            if *checks >= SLOW_PEER_CHECK_LIMIT {
                persistent.push((peer_id, *total));
            }
        }
        persistent.sort_unstable_by(|(_, a), (_, b)| b.cmp(a));
        let deferred = persistent
            .len()
            .saturating_sub(MAX_SLOW_PEER_DISCONNECTS_PER_CHECK);
        persistent.truncate(MAX_SLOW_PEER_DISCONNECTS_PER_CHECK);
        for (peer_id, _) in &persistent {
            self.streaks.remove(peer_id);
        }
        SlowPeerCheck {
            disconnect: persistent,
            deferred,
        }
    }
}

/// Whether gossipsub peer scoring is on, which is what makes a node beacon
/// rather than lean: the gate both periodic disconnect passes share.
///
/// `peer_score` is `Some` for any peer id, this node's own included, exactly
/// when scoring is on, so asking about our own id answers without depending
/// on which peers are connected. `beacon::scoring`'s
/// `only_the_beacon_swarm_scores_peers` pins that answer for both chains.
fn scoring_enabled(swarm: &libp2p::Swarm<Behaviour>) -> bool {
    swarm
        .behaviour()
        .gossipsub
        .peer_score(swarm.local_peer_id())
        .is_some()
}

/// Disconnect the peers [`SlowPeers`] finds persistently failing to take
/// gossipsub messages, up to its per-check cap.
///
/// Beacon only, like [`disconnect_graylisted_peers`]: the check still runs on
/// lean, so the reports do not pile up, but nothing is disconnected.
fn disconnect_slow_peers(swarm: &mut libp2p::Swarm<Behaviour>, slow_peers: &mut SlowPeers) {
    let SlowPeerCheck {
        disconnect,
        deferred,
    } = slow_peers.check();
    if !scoring_enabled(swarm) {
        return;
    }
    if deferred > 0 {
        let disconnecting = disconnect.len();
        warn!(
            disconnecting,
            deferred,
            "More peers kept failing to take gossipsub messages than one check disconnects, \
             which points at our own uplink or runtime; the rest wait for a later check"
        );
    }
    for (peer_id, failed) in disconnect {
        // `Err` only means the peer had no connection left, so there is no
        // queue to free and nothing to retry; its streak is gone, which is
        // right for a peer that reconnects with a fresh handler.
        if swarm.disconnect_peer_id(peer_id).is_ok() {
            metrics::inc_gossipsub_slow_peer_disconnects();
            info!(
                %peer_id,
                failed,
                "Disconnecting peer that kept failing to take gossipsub messages"
            );
        }
    }
}

/// Disconnect every peer gossipsub scores below the graylist, and publish how
/// the rest are spread across the score bands.
///
/// Gossipsub on its own only ignores a graylisted peer's RPCs, so the peer
/// would keep a connection slot it is no use in. There is no ban list, so the
/// peer may reconnect, but its score is retained for `retain_score` after it
/// leaves: it comes back graylisted and is dropped again on the next pass.
///
/// Does nothing on lean, which runs without scoring.
fn disconnect_graylisted_peers(swarm: &mut libp2p::Swarm<Behaviour>) {
    if !scoring_enabled(swarm) {
        return;
    }
    let gossipsub = &swarm.behaviour().gossipsub;
    let mut bands: HashMap<&'static str, i64> =
        scoring::SCORE_BANDS.iter().map(|&band| (band, 0)).collect();
    let mut graylisted = Vec::new();
    for (peer_id, _topics) in gossipsub.all_peers() {
        let Some(score) = gossipsub.peer_score(peer_id) else {
            continue;
        };
        *bands.entry(scoring::score_band(score)).or_default() += 1;
        if score < scoring::GRAYLIST_THRESHOLD {
            graylisted.push((*peer_id, score));
        }
    }
    metrics::set_gossipsub_peers_by_score(&bands);
    for (peer_id, score) in graylisted {
        if swarm.disconnect_peer_id(peer_id).is_ok() {
            metrics::inc_gossipsub_score_disconnects();
            info!(%peer_id, score, "Disconnecting peer scored below the gossipsub graylist");
        }
    }
}

pub(crate) fn execute_command(swarm: &mut libp2p::Swarm<Behaviour>, cmd: SwarmCommand) {
    match cmd {
        SwarmCommand::Publish {
            topic,
            data,
            outcome_tx,
        } => {
            let result = swarm.behaviour_mut().gossipsub.publish(topic.clone(), data);
            match outcome_tx {
                // The caller logs the outcome, at the level its topic warrants.
                Some(outcome_tx) => {
                    let _ = outcome_tx.send(PublishOutcome::from(result));
                }
                None => {
                    let _ = result
                        .inspect_err(|err| debug!(%topic, %err, "Swarm adapter: publish failed"));
                }
            }
        }
        SwarmCommand::Subscribe(topic) => {
            let _ = swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&topic)
                .inspect_err(|err| warn!(%topic, %err, "Swarm adapter: subscribe failed"));
        }
        SwarmCommand::Unsubscribe(topic) => {
            swarm.behaviour_mut().gossipsub.unsubscribe(&topic);
        }
        SwarmCommand::Dial { opts, outcome_tx } => {
            let outcome = match swarm.dial(opts) {
                Ok(()) => DialOutcome::Queued,
                Err(err) => {
                    debug!(%err, "Swarm adapter: dial failed");
                    DialOutcome::from(&err)
                }
            };
            if let Some(tx) = outcome_tx {
                let _ = tx.send(outcome);
            }
        }
        SwarmCommand::SendRequest {
            peer,
            request,
            protocol,
            request_id_tx,
        } => {
            // Upstream `send_request`, never the fork's own
            // `send_request_with_protocol`: each field already offers exactly
            // the one protocol `protocol` names, so pinning to it per call is
            // no longer needed. Which field is exhaustive on purpose; see
            // `ReqRespProtocol`'s doc comment.
            let behaviour = &mut swarm.behaviour_mut().req_resp;
            let id = match protocol {
                ReqRespProtocol::LeanStatus => behaviour.lean_status.send_request(&peer, request),
                ReqRespProtocol::LeanBlocksByRoot => {
                    behaviour.lean_blocks_by_root.send_request(&peer, request)
                }
                ReqRespProtocol::LeanBlocksByRange => {
                    behaviour.lean_blocks_by_range.send_request(&peer, request)
                }
                ReqRespProtocol::BeaconStatusV1 => {
                    behaviour.beacon_status_v1.send_request(&peer, request)
                }
                ReqRespProtocol::BeaconStatusV2 => {
                    behaviour.beacon_status_v2.send_request(&peer, request)
                }
                ReqRespProtocol::BeaconPing => behaviour.beacon_ping.send_request(&peer, request),
                ReqRespProtocol::BeaconMetadataV1 => {
                    behaviour.beacon_metadata_v1.send_request(&peer, request)
                }
                ReqRespProtocol::BeaconMetadataV2 => {
                    behaviour.beacon_metadata_v2.send_request(&peer, request)
                }
                ReqRespProtocol::BeaconMetadataV3 => {
                    behaviour.beacon_metadata_v3.send_request(&peer, request)
                }
                ReqRespProtocol::BeaconGoodbye => {
                    behaviour.beacon_goodbye.send_request(&peer, request)
                }
                ReqRespProtocol::BeaconBlocksByRange => behaviour
                    .beacon_blocks_by_range
                    .send_request(&peer, request),
                ReqRespProtocol::BeaconBlocksByRoot => {
                    behaviour.beacon_blocks_by_root.send_request(&peer, request)
                }
                ReqRespProtocol::DataColumnSidecarsByRange => behaviour
                    .data_column_sidecars_by_range
                    .send_request(&peer, request),
                ReqRespProtocol::DataColumnSidecarsByRoot => behaviour
                    .data_column_sidecars_by_root
                    .send_request(&peer, request),
                ReqRespProtocol::ExecutionPayloadEnvelopesByRange => behaviour
                    .execution_payload_envelopes_by_range
                    .send_request(&peer, request),
                ReqRespProtocol::ExecutionPayloadEnvelopesByRoot => behaviour
                    .execution_payload_envelopes_by_root
                    .send_request(&peer, request),
            };
            if let Some(tx) = request_id_tx {
                let _ = tx.send(ReqRespRequestId { protocol, id });
            }
        }
        SwarmCommand::SendResponse { channel, response } => {
            // `Behaviour::send_response` is a passthrough to the oneshot
            // sender the `ResponseChannel` already carries
            // (`ch.sender.send(rs)` in the pinned fork, untouched from
            // upstream); it reads no state of the `Behaviour` instance it is
            // called on, so any field answers identically. `lean_status` is
            // picked as a stable, arbitrary anchor rather than routing this by
            // protocol too.
            let _ = swarm
                .behaviour_mut()
                .req_resp
                .lean_status
                .send_response(channel, response)
                .inspect_err(|response| debug!(%response, "Swarm adapter: send_response failed"));
        }
        SwarmCommand::SetTopicScoreParams(topics) => {
            let gossipsub = &mut swarm.behaviour_mut().gossipsub;
            for (topic, params) in topics {
                let _ = gossipsub
                    .set_topic_params(topic, params)
                    .inspect_err(|err| debug!(%err, "Swarm adapter: topic score update failed"));
            }
        }
        SwarmCommand::ReportValidation {
            message_id,
            propagation_source,
            acceptance,
            kind,
        } => {
            // `false`: gossipsub no longer holds the message, because the
            // verdict came after its message-cache entry was evicted, so an
            // Accept propagates nothing.
            let held = swarm
                .behaviour_mut()
                .gossipsub
                .report_message_validation_result(&message_id, &propagation_source, acceptance);
            if !held {
                metrics::inc_beacon_gossip_verdict_expired(kind);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fewest failures in one count that make a report count.
    const COUNTED: usize = SLOW_PEER_REPORT_THRESHOLD + 1;

    fn failed(non_priority: usize) -> FailedMessages {
        FailedMessages {
            priority: 0,
            non_priority,
        }
    }

    /// Runs the checks before the last one of a streak, each with `peers`
    /// reported once with their failed messages.
    fn checks_before_the_limit(slow_peers: &mut SlowPeers, peers: &[(PeerId, usize)]) {
        for _ in 1..SLOW_PEER_CHECK_LIMIT {
            for (peer, non_priority) in peers {
                slow_peers.record(*peer, &failed(*non_priority));
            }
            assert_eq!(slow_peers.check(), nothing());
        }
    }

    fn nothing() -> SlowPeerCheck {
        SlowPeerCheck {
            disconnect: Vec::new(),
            deferred: 0,
        }
    }

    fn checks_in_a_streak() -> usize {
        usize::try_from(SLOW_PEER_CHECK_LIMIT).unwrap()
    }

    #[test]
    fn a_peer_failing_in_every_check_is_returned_at_the_limit() {
        let peer = PeerId::random();
        let mut slow_peers = SlowPeers::default();
        checks_before_the_limit(&mut slow_peers, &[(peer, COUNTED)]);
        slow_peers.record(peer, &failed(COUNTED));
        let expected = SlowPeerCheck {
            disconnect: vec![(peer, COUNTED * checks_in_a_streak())],
            deferred: 0,
        };
        assert_eq!(slow_peers.check(), expected);
    }

    #[test]
    fn a_check_without_a_report_resets_the_streak() {
        let peer = PeerId::random();
        let mut slow_peers = SlowPeers::default();
        checks_before_the_limit(&mut slow_peers, &[(peer, COUNTED)]);
        assert_eq!(slow_peers.check(), nothing());
        slow_peers.record(peer, &failed(COUNTED));
        assert_eq!(slow_peers.check(), nothing());
    }

    #[test]
    fn several_reports_within_one_check_count_once_towards_the_streak() {
        let peer = PeerId::random();
        let mut slow_peers = SlowPeers::default();
        // A whole streak's worth of reports before a single check.
        for _ in 0..checks_in_a_streak() {
            slow_peers.record(peer, &failed(COUNTED));
        }
        assert_eq!(slow_peers.check(), nothing());

        // That check was the streak's first: the peer is returned exactly at
        // the limit counting it. Had it not counted, the last check below
        // would return nothing; had it counted more than once, one in the
        // loop would already have returned the peer.
        for _ in 2..SLOW_PEER_CHECK_LIMIT {
            slow_peers.record(peer, &failed(COUNTED));
            assert_eq!(slow_peers.check(), nothing());
        }
        slow_peers.record(peer, &failed(COUNTED));
        // Every report's failures are kept, the first check's included.
        let reports = checks_in_a_streak() + checks_in_a_streak() - 1;
        let expected = SlowPeerCheck {
            disconnect: vec![(peer, COUNTED * reports)],
            deferred: 0,
        };
        assert_eq!(slow_peers.check(), expected);
    }

    #[test]
    fn a_returned_peer_starts_a_new_streak() {
        let peer = PeerId::random();
        let mut slow_peers = SlowPeers::default();
        let returned = SlowPeerCheck {
            disconnect: vec![(peer, COUNTED * checks_in_a_streak())],
            deferred: 0,
        };
        checks_before_the_limit(&mut slow_peers, &[(peer, COUNTED)]);
        slow_peers.record(peer, &failed(COUNTED));
        assert_eq!(slow_peers.check(), returned);

        // Still failing afterwards, it needs a whole new streak to be returned
        // again, and only that streak's failures are counted.
        checks_before_the_limit(&mut slow_peers, &[(peer, COUNTED)]);
        slow_peers.record(peer, &failed(COUNTED));
        assert_eq!(slow_peers.check(), returned);
    }

    #[test]
    fn a_report_at_the_threshold_does_not_count_and_resets_the_streak() {
        let peer = PeerId::random();
        let mut slow_peers = SlowPeers::default();
        checks_before_the_limit(&mut slow_peers, &[(peer, COUNTED)]);
        slow_peers.record(peer, &failed(SLOW_PEER_REPORT_THRESHOLD));
        assert_eq!(slow_peers.check(), nothing());
        slow_peers.record(peer, &failed(COUNTED));
        assert_eq!(slow_peers.check(), nothing());
    }

    #[test]
    fn the_threshold_applies_to_each_count_on_its_own() {
        let peer = PeerId::random();
        let mut slow_peers = SlowPeers::default();
        // Over the threshold only when the two counts are added up.
        let split = FailedMessages {
            priority: SLOW_PEER_REPORT_THRESHOLD,
            non_priority: SLOW_PEER_REPORT_THRESHOLD,
        };
        for _ in 0..SLOW_PEER_CHECK_LIMIT {
            slow_peers.record(peer, &split);
            assert_eq!(slow_peers.check(), nothing());
        }
        // Priority failures alone are enough.
        let priority = FailedMessages {
            priority: COUNTED,
            non_priority: 0,
        };
        for _ in 1..SLOW_PEER_CHECK_LIMIT {
            slow_peers.record(peer, &priority);
            assert_eq!(slow_peers.check(), nothing());
        }
        slow_peers.record(peer, &priority);
        assert_eq!(slow_peers.check().disconnect.len(), 1);
    }

    #[test]
    fn one_check_returns_at_most_the_cap_most_failed_first() {
        let mut slow_peers = SlowPeers::default();
        let peers: Vec<(PeerId, usize)> = (0..=MAX_SLOW_PEER_DISCONNECTS_PER_CHECK)
            .map(|i| (PeerId::random(), COUNTED + i))
            .collect();
        checks_before_the_limit(&mut slow_peers, &peers);
        for (peer, non_priority) in &peers {
            slow_peers.record(*peer, &failed(*non_priority));
        }
        let check = slow_peers.check();

        let mut most_failed_first = peers.clone();
        most_failed_first.reverse();
        let expected: Vec<(PeerId, usize)> = most_failed_first
            .iter()
            .take(MAX_SLOW_PEER_DISCONNECTS_PER_CHECK)
            .map(|(peer, non_priority)| (*peer, non_priority * checks_in_a_streak()))
            .collect();
        assert_eq!(check.disconnect, expected);
        assert_eq!(check.deferred, 1);

        // The deferred peer kept its streak: still failing, it is returned at
        // the next check.
        let (deferred_peer, non_priority) = peers[0];
        slow_peers.record(deferred_peer, &failed(non_priority));
        let expected = SlowPeerCheck {
            disconnect: vec![(deferred_peer, non_priority * (checks_in_a_streak() + 1))],
            deferred: 0,
        };
        assert_eq!(slow_peers.check(), expected);
    }

    /// A duplicate is told apart from a failure: it means the message already
    /// left this node (or arrived from a peer), so nothing is owed, and its
    /// callers log it at debug rather than warn.
    #[test]
    fn a_publish_result_is_classified_by_whether_a_peer_got_it() {
        let published = PublishOutcome::from(Ok(MessageId::new(b"id")));
        assert_eq!(published, PublishOutcome::Published);
        assert!(!published.failed());

        let duplicate = PublishOutcome::from(Err(PublishError::Duplicate));
        assert_eq!(duplicate, PublishOutcome::Duplicate);
        assert!(!duplicate.failed());

        for err in [
            PublishError::NoPeersSubscribedToTopic,
            PublishError::AllQueuesFull(3),
            PublishError::MessageTooLarge,
        ] {
            assert!(PublishOutcome::from(Err(err)).failed());
        }
    }

    #[tokio::test]
    async fn a_reporting_publish_is_queued_at_once_and_answered_through_its_receipt() {
        let (handle, mut commands) = SwarmHandle::capturing();
        let topic = IdentTopic::new("topic");
        let receipt = handle.publish_reporting(topic.clone(), b"data".to_vec());

        let Ok(SwarmCommand::Publish {
            topic: queued,
            data,
            outcome_tx: Some(outcome_tx),
        }) = commands.try_recv()
        else {
            panic!("the publish is queued before its receipt is read");
        };
        assert_eq!(queued.hash(), topic.hash());
        assert_eq!(data, b"data");
        outcome_tx.send(PublishOutcome::Duplicate).unwrap();
        assert_eq!(receipt.outcome().await, PublishOutcome::Duplicate);
    }

    #[tokio::test]
    async fn a_publish_the_adapter_never_ran_failed() {
        let (handle, commands) = SwarmHandle::capturing();
        drop(commands);
        let receipt = handle.publish_reporting(IdentTopic::new("topic"), Vec::new());
        assert!(receipt.outcome().await.failed());

        // Queued, then dropped unanswered when the adapter stopped.
        let (handle, mut commands) = SwarmHandle::capturing();
        let receipt = handle.publish_reporting(IdentTopic::new("topic"), Vec::new());
        drop(commands.try_recv());
        assert!(receipt.outcome().await.failed());
    }

    #[test]
    fn a_deferred_peer_that_stops_failing_loses_its_streak() {
        let mut slow_peers = SlowPeers::default();
        let peers: Vec<(PeerId, usize)> = (0..=MAX_SLOW_PEER_DISCONNECTS_PER_CHECK)
            .map(|i| (PeerId::random(), COUNTED + i))
            .collect();
        checks_before_the_limit(&mut slow_peers, &peers);
        for (peer, non_priority) in &peers {
            slow_peers.record(*peer, &failed(*non_priority));
        }
        assert_eq!(slow_peers.check().deferred, 1);

        assert_eq!(slow_peers.check(), nothing());
        let (deferred_peer, non_priority) = peers[0];
        slow_peers.record(deferred_peer, &failed(non_priority));
        assert_eq!(slow_peers.check(), nothing());
    }
}
