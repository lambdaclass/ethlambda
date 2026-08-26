use std::collections::HashMap;
use std::time::Duration;

use libp2p::{
    Multiaddr, PeerId, StreamProtocol,
    futures::StreamExt,
    request_response::{self, OutboundRequestId},
    swarm::SwarmEvent,
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
        addr: Multiaddr,
        /// Callback reporting whether the swarm accepted the dial. `None` when
        /// the caller does not need to know.
        accepted_tx: Option<tokio::sync::oneshot::Sender<bool>>,
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

    pub fn dial(&self, addr: Multiaddr) {
        let _ = self
            .cmd_tx
            .send(SwarmCommand::Dial {
                addr,
                accepted_tx: None,
            })
            .inspect_err(|_| debug!("Swarm adapter closed, cannot dial"));
    }

    /// Dial and report whether the swarm took the dial.
    ///
    /// `Swarm::dial` rejects some dials synchronously — `LocalPeerId`,
    /// `NoAddresses`, `Denied`, and `DialPeerConditionFalse` (already connected,
    /// or already dialing) — and those produce **no** `OutgoingConnectionError`
    /// event. A caller that keeps per-dial bookkeeping has to know, or nothing
    /// will ever tear that bookkeeping down. `false` also covers a dead adapter.
    ///
    /// A `true` only means the dial was queued: success or failure still arrives
    /// later as `ConnectionEstablished` or `OutgoingConnectionError`.
    pub async fn dial_accepted(&self, addr: Multiaddr) -> bool {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self
            .cmd_tx
            .send(SwarmCommand::Dial {
                addr,
                accepted_tx: Some(tx),
            })
            .is_err()
        {
            debug!("Swarm adapter closed, cannot dial");
            return false;
        }
        rx.await.unwrap_or(false)
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
        SwarmCommand::Dial { addr, accepted_tx } => {
            let accepted = swarm
                .dial(addr)
                .inspect_err(|err| debug!(%err, "Swarm adapter: dial failed"))
                .is_ok();
            if let Some(tx) = accepted_tx {
                let _ = tx.send(accepted);
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
