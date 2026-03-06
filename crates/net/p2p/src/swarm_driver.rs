use std::collections::HashMap;

use libp2p::{
    Multiaddr, PeerId, StreamProtocol,
    futures::StreamExt,
    gossipsub as libp2p_gossipsub,
    request_response::{self, OutboundRequestId},
    swarm::SwarmEvent,
};
use spawned_concurrency::tasks::ActorRef;
use tokio::sync::mpsc;
use tracing::{debug, error, trace, warn};

use ethlambda_types::{
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    block::SignedBlockWithAttestation,
    primitives::ssz::Decode,
};

use crate::{
    Behaviour, BehaviourEvent, P2PServer, P2pProtocol, ResponseChannelWrapper,
    gossipsub::{
        AGGREGATION_TOPIC_KIND, ATTESTATION_SUBNET_TOPIC_PREFIX, BLOCK_TOPIC_KIND,
        encoding::decompress_message,
    },
    req_resp::{Request, Response, ResponsePayload},
};

/// Commands sent from the P2PServer actor to the SwarmDriver.
pub(crate) enum SwarmCommand {
    GossipPublish {
        topic: libp2p_gossipsub::IdentTopic,
        data: Vec<u8>,
    },
    SendRequest {
        correlation_id: u64,
        peer_id: PeerId,
        request: Request,
        protocol: StreamProtocol,
    },
    SendResponse {
        channel: request_response::ResponseChannel<Response>,
        response: Response,
    },
    Dial(Multiaddr),
}

/// Owns the libp2p Swarm and polls it continuously.
///
/// Forwards decoded network events to the P2PServer actor and executes
/// SwarmCommands received from it. Runs as a plain tokio task so the
/// swarm keeps being polled even when the actor is busy processing messages.
pub(crate) struct SwarmDriver {
    swarm: libp2p::Swarm<Behaviour>,
    command_rx: mpsc::UnboundedReceiver<SwarmCommand>,
    p2p_actor: ActorRef<P2PServer>,
    /// Maps libp2p OutboundRequestId → our correlation ID
    outbound_request_map: HashMap<OutboundRequestId, u64>,
}

impl SwarmDriver {
    pub(crate) fn new(
        swarm: libp2p::Swarm<Behaviour>,
        command_rx: mpsc::UnboundedReceiver<SwarmCommand>,
        p2p_actor: ActorRef<P2PServer>,
    ) -> Self {
        Self {
            swarm,
            command_rx,
            p2p_actor,
            outbound_request_map: HashMap::new(),
        }
    }

    pub(crate) async fn run(mut self) {
        loop {
            tokio::select! {
                Some(command) = self.command_rx.recv() => {
                    self.handle_command(command);
                }
                Some(event) = self.swarm.next() => {
                    self.handle_swarm_event(event);
                }
            }
        }
    }

    fn handle_command(&mut self, command: SwarmCommand) {
        match command {
            SwarmCommand::GossipPublish { topic, data } => {
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic, data)
                    .inspect_err(|err| warn!(%err, "Failed to publish gossip message"));
            }
            SwarmCommand::SendRequest {
                correlation_id,
                peer_id,
                request,
                protocol,
            } => {
                let outbound_id = self
                    .swarm
                    .behaviour_mut()
                    .req_resp
                    .send_request_with_protocol(&peer_id, request, protocol);
                self.outbound_request_map
                    .insert(outbound_id, correlation_id);
            }
            SwarmCommand::SendResponse { channel, response } => {
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .req_resp
                    .send_response(channel, response)
                    .inspect_err(|err| warn!(?err, "Failed to send response"));
            }
            SwarmCommand::Dial(addr) => {
                let _ = self
                    .swarm
                    .dial(addr)
                    .inspect_err(|err| warn!(%err, "Failed to dial"));
            }
        }
    }

    fn handle_swarm_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::ReqResp(req_resp_event)) => {
                self.handle_req_resp_event(req_resp_event);
            }
            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(
                libp2p_gossipsub::Event::Message { message, .. },
            )) => {
                self.handle_gossip_message(message);
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                num_established,
                ..
            } => {
                let direction = connection_direction(&endpoint).to_string();
                let first_connection = num_established.get() == 1;
                let _ = self
                    .p2p_actor
                    .on_peer_connected(peer_id, direction, first_connection);
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                endpoint,
                num_established,
                cause,
                ..
            } => {
                let direction = connection_direction(&endpoint).to_string();
                let reason = categorize_disconnection(&cause).to_string();
                let last_connection = num_established == 0;
                let _ = self.p2p_actor.on_peer_disconnected(
                    peer_id,
                    direction,
                    reason,
                    last_connection,
                );
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                let _ = self
                    .p2p_actor
                    .on_outgoing_connection_error(peer_id, error.to_string());
            }
            SwarmEvent::IncomingConnectionError { peer_id, error, .. } => {
                crate::metrics::notify_peer_connected(&peer_id, "inbound", "error");
                warn!(%error, "Incoming connection error");
            }
            _ => {
                trace!(?event, "Ignored swarm event");
            }
        }
    }

    fn handle_gossip_message(&mut self, message: libp2p_gossipsub::Message) {
        let topic_kind = message.topic.as_str().split("/").nth(3);
        match topic_kind {
            Some(BLOCK_TOPIC_KIND) => {
                let Ok(uncompressed) = decompress_message(&message.data)
                    .inspect_err(|err| error!(%err, "Failed to decompress gossipped block"))
                else {
                    return;
                };
                let Ok(signed_block) = SignedBlockWithAttestation::from_ssz_bytes(&uncompressed)
                    .inspect_err(|err| error!(?err, "Failed to decode gossipped block"))
                else {
                    return;
                };
                let _ = self.p2p_actor.on_gossip_block(signed_block);
            }
            Some(AGGREGATION_TOPIC_KIND) => {
                let Ok(uncompressed) = decompress_message(&message.data)
                    .inspect_err(|err| error!(%err, "Failed to decompress gossipped aggregation"))
                else {
                    return;
                };
                let Ok(aggregation) = SignedAggregatedAttestation::from_ssz_bytes(&uncompressed)
                    .inspect_err(|err| error!(?err, "Failed to decode gossipped aggregation"))
                else {
                    return;
                };
                let _ = self.p2p_actor.on_gossip_aggregated_attestation(aggregation);
            }
            Some(kind) if kind.starts_with(ATTESTATION_SUBNET_TOPIC_PREFIX) => {
                let Ok(uncompressed) = decompress_message(&message.data)
                    .inspect_err(|err| error!(%err, "Failed to decompress gossipped attestation"))
                else {
                    return;
                };
                let Ok(signed_attestation) = SignedAttestation::from_ssz_bytes(&uncompressed)
                    .inspect_err(|err| error!(?err, "Failed to decode gossipped attestation"))
                else {
                    return;
                };
                let _ = self.p2p_actor.on_gossip_attestation(signed_attestation);
            }
            _ => {
                trace!("Received message on unknown topic: {}", message.topic);
            }
        }
    }

    fn handle_req_resp_event(&mut self, event: request_response::Event<Request, Response>) {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => match request {
                    Request::Status(status) => {
                        let _ = self.p2p_actor.on_status_request(
                            status,
                            ResponseChannelWrapper::new(channel),
                            peer,
                        );
                    }
                    Request::BlocksByRoot(request) => {
                        let _ = self.p2p_actor.on_blocks_by_root_request(
                            request,
                            ResponseChannelWrapper::new(channel),
                            peer,
                        );
                    }
                },
                request_response::Message::Response {
                    request_id,
                    response,
                } => match response {
                    Response::Success { payload } => match payload {
                        ResponsePayload::Status(status) => {
                            self.outbound_request_map.remove(&request_id);
                            let _ = self.p2p_actor.on_status_response(status, peer);
                        }
                        ResponsePayload::BlocksByRoot(blocks) => {
                            if let Some(correlation_id) =
                                self.outbound_request_map.remove(&request_id)
                            {
                                let _ = self.p2p_actor.on_blocks_by_root_response(
                                    blocks,
                                    peer,
                                    correlation_id,
                                );
                            } else {
                                warn!(
                                    %peer,
                                    ?request_id,
                                    "Received BlocksByRoot response for unknown request_id"
                                );
                            }
                        }
                    },
                    Response::Error { code, message } => {
                        let error_str = String::from_utf8_lossy(&message);
                        warn!(%peer, ?code, %error_str, "Received error response");
                    }
                },
            },
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                warn!(%peer, ?request_id, %error, "Outbound request failed");
                if let Some(correlation_id) = self.outbound_request_map.remove(&request_id) {
                    let _ =
                        self.p2p_actor
                            .on_req_resp_failure(peer, correlation_id, error.to_string());
                }
            }
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                warn!(%peer, ?request_id, %error, "Inbound request failed");
            }
            request_response::Event::ResponseSent {
                peer, request_id, ..
            } => {
                debug!(%peer, ?request_id, "Response sent successfully");
            }
        }
    }
}

fn connection_direction(endpoint: &libp2p::core::ConnectedPoint) -> &'static str {
    if endpoint.is_dialer() {
        "outbound"
    } else {
        "inbound"
    }
}

fn categorize_disconnection(cause: &Option<impl std::fmt::Display>) -> &'static str {
    match cause {
        None => "remote_close",
        Some(err) => {
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
    }
}
