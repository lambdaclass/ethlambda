//! What `P2PServer` does with beacon traffic.
//!
//! Three things: it opens the `Status` handshake on connect, it answers the
//! handful of requests that keep a connection alive, and it decodes gossip.
//! It publishes nothing and serves no chain data, because nothing this node can
//! produce today would be signature-valid and nothing it holds is worth
//! serving.

use ethlambda_network_api::BlockSource;
use ethlambda_types::beacon::primitives::Root;
use libp2p::PeerId;
use libp2p::gossipsub::Event;
use libp2p::request_response::ResponseChannel;
use tracing::{debug, error, info, warn};

use super::messages::{
    AttnetsBits, BeaconMetaData, BeaconStatus, Goodbye, MetaDataV1, MetaDataV2, MetaDataV3, Ping,
    StatusV1, SyncnetsBits,
};
use super::{BeaconWire, constants, decode, protocols, topics};
use crate::gossipsub::decompress_message;
use crate::req_resp::{
    BeaconRequest, BeaconResponse, Request, Response, ResponseCode, ResponsePayload, error_message,
};
use crate::{P2PServer, metrics};

/// The `Status` this node advertises.
///
/// Every field but the fork digest is zero, which is the honest answer for a
/// node that holds no beacon chain. Lighthouse's relevance check explicitly
/// exempts a zero `finalized_root` from its finalized-root comparison, reading
/// it as "this peer is syncing" rather than as a conflicting chain, so a zero
/// Status keeps the connection instead of earning an `IrrelevantPeer`
/// disconnect. The anchor-and-follow work replaces this with the store-derived
/// Status.
pub fn build_status(wire: &BeaconWire) -> BeaconStatus {
    BeaconStatus::V1(StatusV1 {
        fork_digest: wire.fork_digest,
        finalized_root: Root::zero(),
        finalized_epoch: 0,
        head_root: Root::zero(),
        head_slot: 0,
    })
}

/// The `MetaData` this node advertises, in the version the protocol asked for.
///
/// `attnets` and `syncnets` are all-zero because this node subscribes to no
/// subnet, which is exactly what it serves. `custody_group_count` is
/// `CUSTODY_REQUIREMENT` rather than zero because peers may reject a lower
/// value outright; it is the widest gap between what this node advertises and
/// what it serves, and startup logs it.
pub fn build_metadata(wire: &BeaconWire, protocol: &str) -> Option<BeaconMetaData> {
    let seq_number = wire.metadata_seq_number;
    match protocol {
        protocols::METADATA_V1 => Some(BeaconMetaData::V1(MetaDataV1 {
            seq_number,
            attnets: AttnetsBits::default(),
        })),
        protocols::METADATA_V2 => Some(BeaconMetaData::V2(MetaDataV2 {
            seq_number,
            attnets: AttnetsBits::default(),
            syncnets: SyncnetsBits::default(),
        })),
        protocols::METADATA_V3 => Some(BeaconMetaData::V3(MetaDataV3 {
            seq_number,
            attnets: AttnetsBits::default(),
            syncnets: SyncnetsBits::default(),
            custody_group_count: constants::CUSTODY_REQUIREMENT,
        })),
        _ => None,
    }
}

/// Open the handshake on a newly established connection.
///
/// `status/1` rather than `status/2`: every mainnet client still answers v1, and
/// the probe that proved this path completed its handshake on it. If a client
/// ever drops v1, this is the single line that moves.
pub async fn send_status(server: &P2PServer, peer_id: PeerId, wire_status: BeaconStatus) {
    server
        .swarm_handle
        .send_request(
            peer_id,
            Request::Beacon(BeaconRequest::Status(wire_status)),
            libp2p::StreamProtocol::new(protocols::STATUS_V1),
        )
        .await;
}

/// Answer a beacon request, or drop the channel when the protocol expects no
/// answer.
pub async fn handle_beacon_request(
    server: &mut P2PServer,
    peer: PeerId,
    request: BeaconRequest,
    channel: ResponseChannel<Response>,
) {
    let Some(wire) = server.wire.beacon() else {
        warn!(%peer, "Beacon request arrived on a lean node; refusing");
        let response = Response::error(
            ResponseCode::INVALID_REQUEST,
            error_message("this node does not speak the beacon protocols"),
        );
        server.swarm_handle.send_response(channel, response);
        return;
    };

    let response = match request {
        BeaconRequest::Status(peer_status) => {
            if peer_status.fork_digest() != wire.fork_digest {
                // Not grounds for closing the stream: the peer told us who it
                // is and we answer honestly. Counting it is how a digest that
                // has moved under us becomes visible.
                warn!(
                    %peer,
                    peer_digest = %hex::encode(peer_status.fork_digest()),
                    our_digest = %hex::encode(wire.fork_digest),
                    "Peer is on another fork digest"
                );
                metrics::inc_beacon_status_digest_mismatch();
            } else {
                info!(
                    %peer,
                    peer_head_slot = peer_status.head_slot(),
                    peer_finalized_epoch = peer_status.finalized_epoch(),
                    "Beacon status received"
                );
            }
            Some(BeaconResponse::Status(build_status(wire)))
        }
        BeaconRequest::Ping(ping) => {
            debug!(%peer, peer_seq_number = ping.seq_number, "Ping received");
            Some(BeaconResponse::Pong(Ping {
                seq_number: wire.metadata_seq_number,
            }))
        }
        BeaconRequest::MetaData(protocol) => {
            build_metadata(wire, protocol).map(BeaconResponse::MetaData)
        }
        BeaconRequest::Goodbye(Goodbye { reason }) => {
            // No response: goodbye is one-way. Dropping the channel closes the
            // stream, which is what the peer is waiting for.
            info!(%peer, reason, "Peer said goodbye");
            return;
        }
        // Registered `ProtocolSupport::Outbound`, so libp2p refuses the inbound
        // stream at negotiation and these never arrive. A checkpoint-synced
        // node holds nothing below its anchor, so declining the stream is a
        // more useful answer than a short response the peer has to diagnose.
        BeaconRequest::BlocksByRange(_) | BeaconRequest::BlocksByRoot(_) => {
            debug!(%peer, "Refusing an inbound beacon block request: this node serves none");
            let response = Response::error(
                ResponseCode::RESOURCE_UNAVAILABLE,
                error_message("this node does not serve beacon blocks"),
            );
            server.swarm_handle.send_response(channel, response);
            return;
        }
    };

    let Some(response) = response else {
        warn!(%peer, "No response shape for beacon request");
        return;
    };
    server.swarm_handle.send_response(
        channel,
        Response::success(ResponsePayload::Beacon(response)),
    );
}

/// Record a beacon response. Nothing is driven off one yet.
pub fn handle_beacon_response(server: &mut P2PServer, peer: PeerId, response: BeaconResponse) {
    let Some(wire) = server.wire.beacon() else {
        return;
    };
    match response {
        BeaconResponse::Status(status) => {
            if status.fork_digest() != wire.fork_digest {
                warn!(
                    %peer,
                    peer_digest = %hex::encode(status.fork_digest()),
                    our_digest = %hex::encode(wire.fork_digest),
                    "Handshake answered from another fork digest"
                );
                metrics::inc_beacon_status_digest_mismatch();
                return;
            }
            info!(
                %peer,
                peer_head_slot = status.head_slot(),
                peer_finalized_epoch = status.finalized_epoch(),
                "Beacon handshake complete"
            );
        }
        BeaconResponse::Pong(ping) => {
            debug!(%peer, peer_seq_number = ping.seq_number, "Pong received");
        }
        BeaconResponse::MetaData(_) => {
            debug!(%peer, "Peer metadata received");
        }
        // Routed by `req_resp::handlers`, which knows which request this
        // answers and therefore which slots it was meant to cover. Reaching
        // here means a block response arrived with no matching outbound
        // request recorded.
        BeaconResponse::Blocks(blocks) => {
            debug!(
                %peer,
                count = blocks.len(),
                "Beacon block response with no matching outbound request"
            );
        }
    }
}

/// Decode a gossip message and record what it was.
///
/// Nothing is forwarded to the chain actor yet: driving `on_block` and
/// `on_attestation` arrives with the anchor, since `on_block` rejects a block
/// whose parent is not in the store and nothing has put one there.
pub async fn handle_beacon_gossip_message(server: &mut P2PServer, event: Event) {
    let Event::Message { message, .. } = event else {
        unreachable!("we already matched on Message variant in handle_swarm_event");
    };
    let Some(wire) = server.wire.beacon() else {
        return;
    };

    let Some(kind) = topics::topic_kind(message.topic.as_str()) else {
        debug!(topic = %message.topic, "Gossip on an unparseable topic");
        return;
    };
    // `kind` borrows `message.topic`, and the metric labels need a 'static str,
    // so resolve it against the subscribed set once.
    let Some(label) = topics::SUBSCRIBED_TOPIC_KINDS
        .into_iter()
        .find(|subscribed| *subscribed == kind)
    else {
        debug!(topic = %message.topic, "Gossip on an unsubscribed topic");
        return;
    };

    let Ok(payload) = decompress_message(&message.data) else {
        metrics::inc_beacon_gossip(label, "decompress_failed");
        return;
    };

    match decode::decode_gossip(&wire.config, label, &payload) {
        Ok(decode::BeaconGossip::Block(block)) => {
            metrics::inc_beacon_gossip(label, "decoded");
            debug!(
                slot = block.slot(),
                proposer = block.proposer_index(),
                fork = block.fork_name().as_str(),
                block_root = %ethlambda_types::ShortRoot(&block.message_hash_tree_root().0),
                bytes = payload.len(),
                "Beacon block decoded"
            );
            // Hand it to the chain actor, which holds it if its parent is not
            // in the store yet. Before the anchor-to-head fetch existed there
            // was nothing useful to do with a decoded block, so this only
            // logged; now dropping one here would be the tip-tracking failure
            // by omission.
            let Some(blockchain) = server.blockchain.as_ref() else {
                debug!("No blockchain handler available for a gossiped beacon block");
                return;
            };
            let _ = blockchain
                .new_beacon_block(*block, BlockSource::Gossip)
                .inspect_err(|err| error!(%err, "Failed to forward a gossiped beacon block"));
        }
        Ok(other) => {
            metrics::inc_beacon_gossip(label, "decoded");
            debug!(
                kind = other.topic_kind(),
                bytes = payload.len(),
                "Beacon gossip decoded"
            );
        }
        Err(err) => {
            metrics::inc_beacon_gossip(label, "decode_failed");
            debug!(kind = label, %err, bytes = payload.len(), "Beacon gossip decode failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::config::Config;

    fn wire() -> BeaconWire {
        BeaconWire {
            fork_digest: [0x8c, 0x9f, 0x62, 0xfe],
            topics: topics::BeaconTopics::new([0x8c, 0x9f, 0x62, 0xfe]),
            config: Config::mainnet(),
            genesis_time: 1_606_824_023,
            metadata_seq_number: 0,
        }
    }

    #[test]
    fn the_advertised_status_carries_the_digest_and_nothing_else() {
        // Zero roots are the honest answer for a node with no chain, and
        // lighthouse exempts a zero finalized_root from its relevance check, so
        // this keeps the connection rather than earning a disconnect.
        let BeaconStatus::V1(status) = build_status(&wire()) else {
            panic!("v1 is what we send");
        };
        assert_eq!(status.fork_digest, [0x8c, 0x9f, 0x62, 0xfe]);
        assert_eq!(status.finalized_root, Root::zero());
        assert_eq!(status.head_root, Root::zero());
        assert_eq!(status.finalized_epoch, 0);
        assert_eq!(status.head_slot, 0);
    }

    #[test]
    fn metadata_matches_the_protocol_version_asked_for() {
        let wire = wire();
        assert!(matches!(
            build_metadata(&wire, protocols::METADATA_V1),
            Some(BeaconMetaData::V1(_))
        ));
        assert!(matches!(
            build_metadata(&wire, protocols::METADATA_V2),
            Some(BeaconMetaData::V2(_))
        ));
        let Some(BeaconMetaData::V3(v3)) = build_metadata(&wire, protocols::METADATA_V3) else {
            panic!("v3 requested");
        };
        assert_eq!(v3.custody_group_count, constants::CUSTODY_REQUIREMENT);
        assert!(build_metadata(&wire, protocols::PING_V1).is_none());
    }

    #[test]
    fn the_advertised_subnets_are_empty() {
        // What a node subscribing to no subnet actually serves. Claiming
        // otherwise would earn peer-score penalties for silence on subnets we
        // advertised.
        let Some(BeaconMetaData::V3(v3)) = build_metadata(&wire(), protocols::METADATA_V3) else {
            panic!("v3 requested");
        };
        assert_eq!(v3.attnets, AttnetsBits::default());
        assert_eq!(v3.syncnets, SyncnetsBits::default());
    }
}
