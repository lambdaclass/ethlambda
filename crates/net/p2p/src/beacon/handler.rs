//! What `P2PServer` does with beacon traffic.
//!
//! Three things: it opens the `Status` handshake on connect, it answers the
//! handful of requests that keep a connection alive, and it decodes gossip.
//! It publishes nothing and serves no chain data, because nothing this node can
//! produce today would be signature-valid and nothing it holds is worth
//! serving.

use ethlambda_network_api::BlockSource;
use libp2p::PeerId;
use libp2p::gossipsub::Event;
use libp2p::request_response::ResponseChannel;
use tracing::{debug, error, info, warn};

use super::messages::{
    AttnetsBits, BeaconBlocksByRangeRequest, BeaconMetaData, BeaconStatus, Goodbye,
    MAX_REQUEST_BLOCKS_DENEB, MetaDataV1, MetaDataV2, MetaDataV3, Ping, StatusV1, StatusV2,
    SyncnetsBits,
};
use super::{BeaconWire, constants, decode, protocols, topics};
use crate::gossipsub::decompress_message;
use crate::req_resp::{
    BeaconRequest, BeaconResponse, Request, Response, ResponseCode, ResponsePayload, error_message,
};
use crate::{P2PServer, metrics};
use ethlambda_storage::Store;
use ethlambda_types::beacon::containers::SignedBeaconBlock;

/// The `Status` this node advertises, in the version the stream asked for.
///
/// Derived from the store: the fork-choice head if there is one, falling back
/// to the forward-sync watermark before the first head computation, and the
/// finalized checkpoint the anchor established. A zero Status is what this sent
/// while the node held no chain; it survives peer relevance checks (Lighthouse
/// reads a zero `finalized_root` as "still syncing" rather than as a conflicting
/// chain) but it also tells every peer that we are worth nothing to them, and a
/// well-connected node answers `Goodbye(129)`, "too many peers", to exactly
/// those first.
///
/// `version` is the stream's, not ours to choose: a v1 body written on a v2
/// stream is eight bytes short and the codec refuses it, which killed the
/// connection outright. Answering a request means answering in its own version.
pub fn build_status(wire: &BeaconWire, store: &Store, version: StatusVersion) -> BeaconStatus {
    let finalized = store.beacon_finalized_checkpoint();
    let (head_slot, head_root) = store
        .beacon_head()
        .unwrap_or_else(|| (store.beacon_highest_imported_slot(), finalized.root));

    let v1 = StatusV1 {
        fork_digest: wire.fork_digest,
        finalized_root: finalized.root,
        finalized_epoch: finalized.epoch,
        head_root,
        head_slot,
    };
    match version {
        StatusVersion::V1 => BeaconStatus::V1(v1),
        // The oldest slot this node can serve. Everything below the anchor was
        // never fetched, so the honest answer is the anchor's own slot rather
        // than zero: a peer that backfills from us would otherwise ask for
        // blocks we have never had.
        StatusVersion::V2 => BeaconStatus::V2(StatusV2 {
            fork_digest: v1.fork_digest,
            finalized_root: v1.finalized_root,
            finalized_epoch: v1.finalized_epoch,
            head_root: v1.head_root,
            head_slot: v1.head_slot,
            earliest_available_slot: store.beacon_anchor_slot(),
        }),
    }
}

/// Which `Status` version a stream negotiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusVersion {
    V1,
    V2,
}

impl StatusVersion {
    /// The version to answer a request in: the one it arrived in.
    pub fn of(status: &BeaconStatus) -> Self {
        match status {
            BeaconStatus::V1(_) => Self::V1,
            BeaconStatus::V2(_) => Self::V2,
        }
    }
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
/// the probe that proved this path completed its handshake on it. A peer that
/// has dropped v1 refuses the stream with "the remote supports none of the
/// requested protocols", which is what [`retry_status_on_other_version`]
/// answers.
pub async fn send_status(server: &P2PServer, peer_id: PeerId, wire_status: BeaconStatus) {
    let protocol = match StatusVersion::of(&wire_status) {
        StatusVersion::V1 => protocols::STATUS_V1,
        StatusVersion::V2 => protocols::STATUS_V2,
    };
    server
        .swarm_handle
        .send_request(
            peer_id,
            Request::Beacon(BeaconRequest::Status(wire_status)),
            libp2p::StreamProtocol::new(protocol),
        )
        .await;
}

/// Re-open a refused handshake on the other `Status` version.
///
/// A peer that supports neither version was never going to talk to us, and one
/// retry cannot loop: the retry is sent in the version the first attempt was
/// not.
pub async fn retry_status_on_other_version(server: &P2PServer, peer_id: PeerId) {
    let Some(wire) = server.wire.beacon() else {
        return;
    };
    let status = build_status(wire, &server.store, StatusVersion::V2);
    debug!(%peer_id, "Retrying the beacon handshake on status/2");
    send_status(server, peer_id, status).await;
}

/// The canonical blocks answering `request`, oldest first.
///
/// Three bounds, all of them the specification's:
///
/// * `count` is clamped to `MAX_REQUEST_BLOCKS_DENEB` rather than refused. A
///   peer asking for more than the cap gets the cap's worth, which is what it
///   would have got by asking twice.
/// * The window starts no earlier than this node's own anchor. Everything below
///   it was never fetched, and `Status` v2 already told the peer so through
///   `earliest_available_slot`.
/// * Nothing above the fork-choice head, which
///   [`Store::beacon_canonical_blocks_by_range`] enforces by construction: it
///   walks down from the head, so a slot the head does not descend from cannot
///   appear.
///
/// A short or empty answer is legal and expected here. The asking peer reads
/// the slots it actually received, not the ones it asked for.
fn blocks_by_range(store: &Store, request: &BeaconBlocksByRangeRequest) -> Vec<SignedBeaconBlock> {
    let count = request.count.min(MAX_REQUEST_BLOCKS_DENEB);
    if count == 0 {
        return Vec::new();
    }
    let start_slot = request.start_slot.max(store.beacon_anchor_slot());
    // `count - 1` because the range is inclusive of its start.
    let Some(end_slot) = request.start_slot.checked_add(count - 1) else {
        return Vec::new();
    };
    store.beacon_canonical_blocks_by_range(start_slot, end_slot)
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
            Some(BeaconResponse::Status(build_status(
                wire,
                &server.store,
                StatusVersion::of(&peer_status),
            )))
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
        BeaconRequest::BlocksByRange(request) => {
            let blocks = blocks_by_range(&server.store, &request);
            info!(
                %peer,
                start_slot = request.start_slot,
                count = request.count,
                served = blocks.len(),
                "Serving a beacon range request"
            );
            Some(BeaconResponse::Blocks(blocks))
        }
        BeaconRequest::BlocksByRoot(request) => {
            let blocks: Vec<_> = request
                .roots
                .iter()
                .filter_map(|root| server.store.beacon_block(*root))
                .collect();
            debug!(
                %peer,
                asked = request.roots.len(),
                served = blocks.len(),
                "Serving a beacon by-root request"
            );
            Some(BeaconResponse::Blocks(blocks))
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

    /// A phase0 block at `slot`, for building a canonical chain in the store.
    fn beacon_block(
        slot: u64,
        parent_root: ethlambda_types::beacon::primitives::Root,
    ) -> ethlambda_types::beacon::containers::SignedBeaconBlock {
        use ethlambda_types::beacon::containers::phase0;
        ethlambda_types::beacon::containers::SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: Default::default(),
                body: phase0::BeaconBlockBody {
                    randao_reveal: Default::default(),
                    eth1_data: Default::default(),
                    graffiti: Default::default(),
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

    /// Any state at all: `promote_beacon_anchor` writes one, and nothing under
    /// test here reads it back. The lean variant is the one with a constructor
    /// that takes no fixture, which is why an otherwise all-beacon test uses
    /// it; the storage crate's own tests do the same.
    fn beacon_state() -> ethlambda_types::beacon::containers::BeaconState {
        ethlambda_types::beacon::containers::BeaconState::Lean(
            ethlambda_types::state::State::from_genesis(0, Vec::new()),
        )
    }

    fn empty_beacon_store() -> Store {
        Store::init_beacon(
            std::sync::Arc::new(ethlambda_storage::backend::InMemoryBackend::new()),
            1_606_824_023,
        )
    }

    #[test]
    fn the_advertised_status_reports_the_chain_the_store_holds() {
        let mut store = empty_beacon_store();
        let head_root = ethlambda_types::beacon::primitives::Root::repeat_byte(0xaa);
        let finalized_root = ethlambda_types::beacon::primitives::Root::repeat_byte(0xbb);
        store.set_beacon_head(4_242, head_root);
        store.set_beacon_finalized_checkpoint(ethlambda_types::beacon::containers::Checkpoint {
            epoch: 130,
            root: finalized_root,
        });

        let BeaconStatus::V1(status) = build_status(&wire(), &store, StatusVersion::V1) else {
            panic!("v1 was asked for");
        };
        assert_eq!(status.fork_digest, [0x8c, 0x9f, 0x62, 0xfe]);
        assert_eq!(status.head_slot, 4_242);
        assert_eq!(status.head_root, head_root);
        assert_eq!(status.finalized_epoch, 130);
        assert_eq!(status.finalized_root, finalized_root);
    }

    /// A v1 body on a v2 stream is eight bytes short, and the codec refuses to
    /// write it: answering every `Status` in v1 dropped the connection of every
    /// peer that opened the handshake on `status/2`.
    #[test]
    fn the_status_version_answered_is_the_one_that_was_asked_for() {
        let store = empty_beacon_store();
        let wire = wire();

        assert!(matches!(
            build_status(&wire, &store, StatusVersion::V1),
            BeaconStatus::V1(_)
        ));
        assert!(matches!(
            build_status(&wire, &store, StatusVersion::V2),
            BeaconStatus::V2(_)
        ));

        let peer_asked_in = BeaconStatus::V2(StatusV2 {
            fork_digest: wire.fork_digest,
            finalized_root: Default::default(),
            finalized_epoch: 0,
            head_root: Default::default(),
            head_slot: 0,
            earliest_available_slot: 0,
        });
        assert_eq!(StatusVersion::of(&peer_asked_in), StatusVersion::V2);
    }

    /// A store holding slots 1..=`length` on the canonical chain, anchored at
    /// `anchor_slot`.
    fn store_with_chain(anchor_slot: u64, length: u64) -> Store {
        let mut store = empty_beacon_store();
        let mut parent = ethlambda_types::beacon::primitives::Root::zero();
        let mut last = (0, parent);
        for slot in 1..=length {
            let signed = beacon_block(slot, parent);
            let root = signed.message_hash_tree_root();
            store.insert_beacon_block(root, &signed);
            parent = root;
            last = (slot, root);
        }
        store.set_beacon_head(last.0, last.1);
        if anchor_slot > 0 {
            // `beacon_anchor_slot` reads the oldest anchor's own block, so the
            // anchor list has to name a block the store holds.
            let anchor_root = store
                .beacon_canonical_blocks_by_range(anchor_slot, anchor_slot)
                .first()
                .expect("the anchor slot is on the chain")
                .message_hash_tree_root();
            store.promote_beacon_anchor(anchor_root, &beacon_state());
        }
        store
    }

    /// A peer asking for more than `MAX_REQUEST_BLOCKS_DENEB` gets the cap's
    /// worth rather than an error: that is what it would have got by asking
    /// twice, and refusing teaches it nothing.
    #[test]
    fn an_oversized_range_request_is_clamped_rather_than_refused() {
        let store = store_with_chain(0, 200);

        let served = blocks_by_range(
            &store,
            &BeaconBlocksByRangeRequest::new(1, MAX_REQUEST_BLOCKS_DENEB + 50),
        );

        assert_eq!(served.len() as u64, MAX_REQUEST_BLOCKS_DENEB);
        assert_eq!(served.first().expect("nonempty").slot(), 1);
    }

    #[test]
    fn a_zero_count_request_is_answered_with_nothing() {
        let store = store_with_chain(0, 10);

        assert!(blocks_by_range(&store, &BeaconBlocksByRangeRequest::new(1, 0)).is_empty());
    }

    /// Everything below the anchor was never fetched. The window is raised to
    /// the anchor rather than the whole request being refused, so a peer that
    /// asked across the boundary still gets the half this node has.
    #[test]
    fn a_range_starting_below_the_anchor_is_served_from_the_anchor() {
        let store = store_with_chain(5, 10);

        let served = blocks_by_range(&store, &BeaconBlocksByRangeRequest::new(1, 8));

        assert_eq!(
            served.iter().map(|block| block.slot()).collect::<Vec<_>>(),
            vec![5, 6, 7, 8],
            "from the anchor up to the end the request named"
        );
    }

    /// The count is counted from the slot the peer asked for, not from the
    /// anchor the answer starts at: raising the floor must not extend the top.
    #[test]
    fn raising_the_start_to_the_anchor_does_not_extend_the_end() {
        let store = store_with_chain(5, 20);

        let served = blocks_by_range(&store, &BeaconBlocksByRangeRequest::new(1, 8));

        assert_eq!(
            served.last().expect("nonempty").slot(),
            8,
            "slot 1 + 8 - 1, the end of the range the peer named"
        );
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
