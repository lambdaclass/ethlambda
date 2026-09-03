use std::collections::HashMap;
use std::time::Duration;

use libp2p::{
    PeerId, StreamProtocol,
    futures::StreamExt,
    request_response::{self, OutboundRequestId},
    swarm::{SwarmEvent, dial_opts::DialOpts},
};
use tokio::{sync::mpsc, time::MissedTickBehavior};
use tracing::{debug, error};

use crate::{Behaviour, BehaviourEvent, metrics, req_resp::Request, req_resp::Response};

/// Interval between gossipsub mesh peer metric refreshes.
const MESH_METRIC_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

pub enum SwarmCommand {
    Publish {
        topic: libp2p::gossipsub::IdentTopic,
        data: Vec<u8>,
    },
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
        protocol: StreamProtocol,
        /// Callback to report the assigned OutboundRequestId.
        request_id_tx: Option<tokio::sync::oneshot::Sender<OutboundRequestId>>,
    },
    SendResponse {
        channel: request_response::ResponseChannel<Response>,
        response: Response,
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

#[derive(Clone)]
pub struct SwarmHandle {
    cmd_tx: mpsc::UnboundedSender<SwarmCommand>,
}

impl SwarmHandle {
    pub fn publish(&self, topic: libp2p::gossipsub::IdentTopic, data: Vec<u8>) {
        let _ = self
            .cmd_tx
            .send(SwarmCommand::Publish { topic, data })
            .inspect_err(|_| debug!("Swarm adapter closed, cannot publish"));
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

    /// Send a request and return the assigned OutboundRequestId.
    /// Must be called from an async context (actor handlers are async).
    pub async fn send_request(
        &self,
        peer: PeerId,
        request: Request,
        protocol: StreamProtocol,
    ) -> Option<OutboundRequestId> {
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
    loop {
        tokio::select! {
            event = swarm.next() => {
                let Some(event) = event else { break };
                if event_tx.send(event).is_err() { break }
            }
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break };
                execute_command(&mut swarm, cmd);
            }
            _ = mesh_metric_tick.tick() => {
                metrics::update_gossip_mesh_peers(
                    swarm.behaviour().gossipsub.all_mesh_peers(),
                    &node_names,
                );
            }
        }
    }
    error!("Swarm adapter loop exited — P2P networking is no longer functional");
}

fn execute_command(swarm: &mut libp2p::Swarm<Behaviour>, cmd: SwarmCommand) {
    match cmd {
        SwarmCommand::Publish { topic, data } => {
            swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic, data)
                .inspect_err(|err| debug!(%err, "Swarm adapter: publish failed"))
                .ok();
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
            let request_id = swarm
                .behaviour_mut()
                .req_resp
                .send_request_with_protocol(&peer, request, protocol);
            if let Some(tx) = request_id_tx {
                let _ = tx.send(request_id);
            }
        }
        SwarmCommand::SendResponse { channel, response } => {
            let _ = swarm
                .behaviour_mut()
                .req_resp
                .send_response(channel, response)
                .inspect_err(|response| debug!(%response, "Swarm adapter: send_response failed"));
        }
    }
}
