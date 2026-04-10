use libp2p::{
    Multiaddr, PeerId, StreamProtocol,
    futures::StreamExt,
    gossipsub::PublishError,
    request_response::{self, OutboundRequestId},
    swarm::SwarmEvent,
};
use tokio::sync::mpsc;
use tracing::{error, warn};

use crate::{Behaviour, BehaviourEvent, req_resp::Request, req_resp::Response};

pub enum SwarmCommand {
    Publish {
        topic: libp2p::gossipsub::IdentTopic,
        data: Vec<u8>,
        /// When true, suppress NoPeersSubscribedToTopic errors (other errors still warn).
        ignore_no_peers: bool,
    },
    Dial(Multiaddr),
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
            .send(SwarmCommand::Publish {
                topic,
                data,
                ignore_no_peers: false,
            })
            .inspect_err(|_| warn!("Swarm adapter closed, cannot publish"));
    }

    /// Publish, suppressing NoPeersSubscribedToTopic errors. Used when the sender
    /// is also subscribed to the topic (e.g., aggregator publishing its own
    /// attestation to a subnet it subscribes to) and no other peer subscribes.
    pub fn publish_ignore_no_peers(&self, topic: libp2p::gossipsub::IdentTopic, data: Vec<u8>) {
        let _ = self
            .cmd_tx
            .send(SwarmCommand::Publish {
                topic,
                data,
                ignore_no_peers: true,
            })
            .inspect_err(|_| warn!("Swarm adapter closed, cannot publish"));
    }

    pub fn dial(&self, addr: Multiaddr) {
        let _ = self
            .cmd_tx
            .send(SwarmCommand::Dial(addr))
            .inspect_err(|_| warn!("Swarm adapter closed, cannot dial"));
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
            warn!("Swarm adapter closed, cannot send request");
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
            .inspect_err(|_| warn!("Swarm adapter closed, cannot send response"));
    }
}

pub fn start_swarm_adapter(
    swarm: libp2p::Swarm<Behaviour>,
) -> (
    impl futures::Stream<Item = SwarmEvent<BehaviourEvent>>,
    SwarmHandle,
) {
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

    tokio::spawn(swarm_loop(swarm, event_tx, cmd_rx));

    let stream = tokio_stream::wrappers::UnboundedReceiverStream::new(event_rx);
    let handle = SwarmHandle { cmd_tx };
    (stream, handle)
}

async fn swarm_loop(
    mut swarm: libp2p::Swarm<Behaviour>,
    event_tx: mpsc::UnboundedSender<SwarmEvent<BehaviourEvent>>,
    mut cmd_rx: mpsc::UnboundedReceiver<SwarmCommand>,
) {
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
        }
    }
    error!("Swarm adapter loop exited — P2P networking is no longer functional");
}

fn execute_command(swarm: &mut libp2p::Swarm<Behaviour>, cmd: SwarmCommand) {
    match cmd {
        SwarmCommand::Publish {
            topic,
            data,
            ignore_no_peers,
        } => {
            let result = swarm.behaviour_mut().gossipsub.publish(topic, data);
            if let Err(err) = result
                && !(ignore_no_peers && matches!(err, PublishError::NoPeersSubscribedToTopic))
            {
                warn!(%err, "Swarm adapter: publish failed");
            }
        }
        SwarmCommand::Dial(addr) => {
            let _ = swarm
                .dial(addr)
                .inspect_err(|err| warn!(%err, "Swarm adapter: dial failed"));
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
                .inspect_err(|err| warn!(?err, "Swarm adapter: send_response failed"));
        }
    }
}
