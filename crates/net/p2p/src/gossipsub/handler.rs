//! What `P2PServer` does with gossip, on either chain.
//!
//! One entry point and one dispatch, the shape `crate::req_resp::handlers` has:
//! the topic says which chain a message belongs to, so nothing above this module
//! branches on which chain the node follows. Handler names follow the same
//! convention as there, lean prefixed and beacon bare.

use ethlambda_network_api::BlockSource;
use ethlambda_state_transition::beacon::fork_choice;
use ethlambda_types::{
    ShortRoot,
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    beacon::{
        constants::{DATA_COLUMN_SIDECAR_SUBNET_COUNT, MAXIMUM_GOSSIP_CLOCK_DISPARITY},
        containers::SignedBeaconBlock,
    },
    block::SignedBlock,
    primitives::HashTreeRoot as _,
    time::unix_now_ms,
};
use libp2p::gossipsub::Message;
use libssz::{SszDecode, SszEncode};
use tracing::{debug, error, info, trace, warn};

use super::{
    encoding::{compress_message, decompress_message},
    messages::{
        AGGREGATION_TOPIC_KIND, ATTESTATION_SUBNET_TOPIC_PREFIX, BLOCK_TOPIC_KIND,
        attestation_subnet_topic, topic_kind,
    },
};
use crate::beacon::{BeaconWire, decode as beacon_decode, topics as beacon_topics};
use crate::{P2PServer, metrics};

/// What `P2PServer` does with a gossip message, whichever chain it came from.
///
/// Read the topic's kind, undo the snappy framing, dispatch. None of those three
/// is chain-specific: the two wires name their topics disjointly
/// (`/leanconsensus/…/block` against `/eth2/…/beacon_block`) and frame with the
/// same raw snappy, so the topic alone says where a message goes and nothing
/// here asks `server.wire`. That mirrors req/resp, where the protocol id plays
/// the same part.
///
/// One match, with both chains' topics at the same level. Only the SSZ container
/// behind the decompressed bytes differs, and that is a handler's business.
pub async fn handle_gossip_message(server: &mut P2PServer, message: Message) {
    let Some(kind) = topic_kind(message.topic.as_str()) else {
        trace!(topic = %message.topic, "Gossip on an unparseable topic");
        return;
    };
    trace!(
        kind,
        peer_count = server.connected_peers.len(),
        "P2P message received"
    );

    let compressed_len = message.data.len();
    let Some(payload) = decompress(&message.data, kind) else {
        return;
    };

    match kind {
        BLOCK_TOPIC_KIND => handle_lean_block(server, &payload, compressed_len).await,
        AGGREGATION_TOPIC_KIND => handle_lean_aggregation(server, &payload, compressed_len).await,
        kind if kind.starts_with(ATTESTATION_SUBNET_TOPIC_PREFIX) => {
            handle_lean_attestation(server, &payload, compressed_len).await
        }
        beacon_topics::BEACON_BLOCK => handle_beacon_block(server, &payload).await,
        beacon_topics::BEACON_AGGREGATE_AND_PROOF => {
            handle_beacon_aggregate(server, &payload).await
        }
        // The remaining five beacon topics share an arm because they share a
        // handler: this node decodes them to prove it can and logs that it did,
        // with nothing to say about any of them in particular.
        kind if beacon_topics::SUBSCRIBED_TOPIC_KINDS.contains(&kind) => {
            handle_beacon_other(server, &payload, kind).await
        }
        kind if beacon_topics::data_column_subnet(kind).is_some() => {
            let subnet_id = beacon_topics::data_column_subnet(kind).expect("just matched");
            handle_beacon_data_column(server, &payload, subnet_id).await
        }
        _ => trace!(topic = %message.topic, "Gossip on an unhandled topic"),
    }
}

/// Undo the snappy framing both wires use.
///
/// The failure bookkeeping is the one asymmetric part, and stays that way:
/// beacon counts what it drops per topic kind, lean has no counterpart metric.
/// Both log.
fn decompress(data: &[u8], kind: &str) -> Option<Vec<u8>> {
    decompress_message(data)
        .inspect_err(|err| {
            error!(%err, kind, "Failed to decompress gossipped message");
            if beacon_topics::SUBSCRIBED_TOPIC_KINDS.contains(&kind) {
                metrics::inc_beacon_gossip(kind, "decompress_failed");
            }
        })
        .ok()
}

/// SSZ-decode a lean gossip payload, or `None` after logging why.
fn decode_lean<T: SszDecode>(payload: &[u8], what: &'static str) -> Option<T> {
    T::from_ssz_bytes(payload)
        .inspect_err(|err| error!(?err, what, "Failed to decode gossipped message"))
        .ok()
}

/// The beacon wire, or `None` on a lean node, which serves no beacon topic.
fn beacon_wire<'a>(server: &'a P2PServer, kind: &str) -> Option<&'a BeaconWire> {
    let wire = server.wire.beacon();
    if wire.is_none() {
        debug!(kind, "Beacon gossip arrived on a lean node");
    }
    wire
}

async fn handle_lean_block(server: &mut P2PServer, payload: &[u8], compressed_len: usize) {
    metrics::observe_gossip_block_size(payload.len(), compressed_len);
    let Some(signed_block) = decode_lean::<SignedBlock>(payload, "block") else {
        return;
    };
    let block_root = signed_block.message.hash_tree_root();
    info!(
        slot = %signed_block.message.slot,
        proposer = signed_block.message.proposer_index,
        block_root = %ShortRoot(&block_root.0),
        parent_root = %ShortRoot(&signed_block.message.parent_root.0),
        attestation_count = signed_block.message.body.attestations.len(),
        "Received block from gossip"
    );
    if let Some(ref blockchain) = server.blockchain {
        let _ = blockchain
            .new_block(SignedBeaconBlock::Lean(signed_block), BlockSource::Gossip)
            .inspect_err(|err| error!(%err, "Failed to forward block to blockchain"));
    }
}

async fn handle_lean_aggregation(server: &mut P2PServer, payload: &[u8], compressed_len: usize) {
    metrics::observe_gossip_aggregation_size(payload.len(), compressed_len);
    let Some(aggregation) = decode_lean::<SignedAggregatedAttestation>(payload, "aggregation")
    else {
        return;
    };
    info!(
        slot = %aggregation.data.slot,
        target_slot = aggregation.data.target.slot,
        target_root = %ShortRoot(&aggregation.data.target.root.0),
        source_slot = aggregation.data.source.slot,
        source_root = %ShortRoot(&aggregation.data.source.root.0),
        "Received aggregated attestation from gossip"
    );
    if let Some(ref blockchain) = server.blockchain {
        let _ = blockchain
            .new_aggregated_attestation(aggregation)
            .inspect_err(
                |err| error!(%err, "Failed to forward aggregated attestation to blockchain"),
            );
    }
}

async fn handle_lean_attestation(server: &mut P2PServer, payload: &[u8], compressed_len: usize) {
    metrics::observe_gossip_attestation_size(payload.len(), compressed_len);
    let Some(signed_attestation) = decode_lean::<SignedAttestation>(payload, "attestation") else {
        return;
    };
    trace!(
        slot = %signed_attestation.data.slot,
        validator = signed_attestation.validator_id,
        head_root = %ShortRoot(&signed_attestation.data.head.root.0),
        target_slot = signed_attestation.data.target.slot,
        target_root = %ShortRoot(&signed_attestation.data.target.root.0),
        source_slot = signed_attestation.data.source.slot,
        source_root = %ShortRoot(&signed_attestation.data.source.root.0),
        "Received attestation from gossip"
    );
    if let Some(ref blockchain) = server.blockchain {
        let _ = blockchain
            .new_attestation(signed_attestation)
            .inspect_err(|err| error!(%err, "Failed to forward attestation to blockchain"));
    }
}

/// Decode a beacon block and hand it to the beacon chain actor.
///
/// The anchor block puts a parent in the store before gossip starts, so
/// `on_block` no longer rejects these for want of one: forward every decoded
/// block the way [`handle_lean_block`] forwards its own.
async fn handle_beacon_block(server: &mut P2PServer, payload: &[u8]) {
    const KIND: &str = beacon_topics::BEACON_BLOCK;
    let Some(wire) = beacon_wire(server, KIND) else {
        return;
    };
    match beacon_decode::decode_block(&wire.config, payload) {
        Ok(block) => {
            metrics::inc_beacon_gossip(KIND, "decoded");
            info!(
                slot = block.slot(),
                proposer = block.proposer_index(),
                fork = block.fork_name().as_str(),
                block_root = %ShortRoot(&block.message_hash_tree_root().0),
                bytes = payload.len(),
                "Beacon block decoded"
            );
            if let Some(ref blockchain) = server.blockchain {
                let _ = blockchain
                    .new_block(block, BlockSource::Gossip)
                    .inspect_err(|err| error!(%err, "Failed to forward block to blockchain"));
            }
        }
        Err(err) => {
            metrics::inc_beacon_gossip(KIND, "decode_failed");
            debug!(kind = KIND, %err, bytes = payload.len(), "Beacon gossip decode failed");
        }
    }
}

/// Decode a beacon aggregate and record that it arrived. Forwards nothing:
/// `beacon_aggregate_and_proof` is a global topic carrying roughly a thousand
/// aggregates per slot on mainnet at about 30ms each in `on_attestation`, more
/// work per slot than a slot lasts on a single-threaded actor, so fork choice
/// learns its votes from block bodies inside `on_block` instead of from this
/// topic.
async fn handle_beacon_aggregate(server: &mut P2PServer, payload: &[u8]) {
    const KIND: &str = beacon_topics::BEACON_AGGREGATE_AND_PROOF;
    let Some(wire) = beacon_wire(server, KIND) else {
        return;
    };
    match beacon_decode::decode_aggregate_and_proof(&wire.config, payload) {
        Ok(aggregate) => {
            metrics::inc_beacon_gossip(KIND, "decoded");
            let (target_epoch, target_root) = aggregate.target();
            info!(
                slot = aggregate.slot(),
                aggregator = aggregate.aggregator_index(),
                attesters = aggregate.attester_count(),
                target_epoch,
                target_root = %ShortRoot(&target_root.0),
                bytes = payload.len(),
                "Beacon aggregate attestation decoded"
            );
        }
        Err(err) => {
            metrics::inc_beacon_gossip(KIND, "decode_failed");
            debug!(kind = KIND, %err, bytes = payload.len(), "Beacon gossip decode failed");
        }
    }
}

/// Decode one of the five beacon topics with nothing particular to report, and
/// record that it arrived. Forwards nothing: none of these five has a
/// consumer.
async fn handle_beacon_other(server: &mut P2PServer, payload: &[u8], kind: &str) {
    let Some(wire) = beacon_wire(server, kind) else {
        return;
    };
    match beacon_decode::decode_gossip(&wire.config, kind, payload) {
        Ok(decoded) => {
            metrics::inc_beacon_gossip(kind, "decoded");
            debug!(
                kind = decoded.topic_kind(),
                bytes = payload.len(),
                "Beacon gossip decoded"
            );
        }
        Err(err) => {
            metrics::inc_beacon_gossip(kind, "decode_failed");
            debug!(kind, %err, bytes = payload.len(), "Beacon gossip decode failed");
        }
    }
}

/// Decode a data column sidecar, run the checks that need nothing but the
/// sidecar and the clock, and hand it to the chain actor.
///
/// The split is the same one the block path uses: this rejects what can be
/// rejected without a state, so a peer flooding malformed sidecars never
/// reaches the actor's mailbox. What is left needs fork choice.
async fn handle_beacon_data_column(server: &mut P2PServer, payload: &[u8], subnet_id: u64) {
    let kind = "data_column_sidecar";
    let Some(wire) = beacon_wire(server, kind) else {
        return;
    };

    let sidecar = match beacon_decode::decode_data_column_sidecar(payload) {
        Ok(sidecar) => sidecar,
        Err(err) => {
            metrics::inc_beacon_gossip(kind, "decode_failed");
            debug!(?err, "Dropping an undecodable data column sidecar");
            return;
        }
    };

    // [REJECT] the sidecar is for the correct subnet.
    let expected = sidecar.index % DATA_COLUMN_SIDECAR_SUBNET_COUNT;
    if expected != subnet_id {
        metrics::inc_beacon_gossip(kind, "wrong_subnet");
        return;
    }

    // [REJECT] the sidecar is structurally valid.
    if !fork_choice::verify_data_column_sidecar(&sidecar, &wire.config) {
        metrics::inc_beacon_gossip(kind, "malformed");
        return;
    }

    // [IGNORE] the block is not already finalized on this chain. Reads only
    // the store's own finalized checkpoint, the same field
    // `prune_seen_data_columns` reads, so no state or fork-choice walk is
    // needed to reject a sidecar for a slot this node will never build on.
    let header = &sidecar.signed_block_header.message;
    let finalized_slot = server
        .store
        .latest_finalized()
        .expect("finalized checkpoint exists")
        .slot;
    if header.slot <= finalized_slot {
        metrics::inc_beacon_gossip(kind, "finalized");
        return;
    }

    // [IGNORE] the sidecar's slot is not further ahead of this node's clock
    // than disparity allows. Must run before the seen-dedup insert below: the
    // finalized check above cannot reject a slot far beyond anything real,
    // and `seen_data_columns` is pruned only of entries at or below the
    // finalized slot, which a fabricated slot this large never becomes. Without
    // this check, one gossip message per distinct fake slot grows the set
    // forever.
    let slot_start_ms = wire
        .config
        .genesis_time_ms()
        .saturating_add(header.slot.saturating_mul(wire.config.slot_duration_ms));
    if slot_start_ms > unix_now_ms().saturating_add(MAXIMUM_GOSSIP_CLOCK_DISPARITY) {
        metrics::inc_beacon_gossip(kind, "future_slot");
        return;
    }

    // [IGNORE] the first sidecar for this (slot, proposer, index) wins; a
    // second is either a duplicate or an equivocation, and neither is worth
    // the actor's KZG batch.
    let key = (header.slot, header.proposer_index, sidecar.index);
    if !server.seen_data_columns.insert(key) {
        metrics::inc_beacon_gossip(kind, "duplicate");
        return;
    }

    metrics::inc_beacon_gossip(kind, "decoded");
    if let Some(ref blockchain) = server.blockchain {
        // A batch of one: gossip delivers a single sidecar per message, and
        // the message the chain actor takes is shaped for the fetch paths,
        // which deliver a peer's whole answer at once.
        let _ = blockchain
            .new_data_column_sidecars(vec![sidecar])
            .inspect_err(|err| warn!(%err, "Failed to forward a data column sidecar"));
    }
}

pub async fn publish_attestation(server: &mut P2PServer, attestation: SignedAttestation) {
    let slot = attestation.data.slot;
    let validator = attestation.validator_id;
    let Some(lean) = server.wire.lean() else {
        warn!("Publishing is suppressed on the beacon wire; dropping attestation");
        return;
    };
    let subnet_id = validator % lean.attestation_committee_count;

    // Encode to SSZ
    let ssz_bytes = attestation.to_ssz();

    // Compress with raw snappy
    let compressed = compress_message(&ssz_bytes);

    metrics::observe_gossip_attestation_size(ssz_bytes.len(), compressed.len());

    // Look up subscribed topic or construct on-the-fly for gossipsub fanout
    let topic = lean
        .attestation_topics
        .get(&subnet_id)
        .cloned()
        .unwrap_or_else(|| attestation_subnet_topic(subnet_id));

    server.swarm_handle.publish(topic, compressed);
    trace!(
        %slot,
        validator,
        subnet_id,
        target_slot = attestation.data.target.slot,
        target_root = %ShortRoot(&attestation.data.target.root.0),
        source_slot = attestation.data.source.slot,
        source_root = %ShortRoot(&attestation.data.source.root.0),
        "Published attestation to gossipsub"
    );
}

pub async fn publish_block(server: &mut P2PServer, signed_block: SignedBlock) {
    let slot = signed_block.message.slot;
    let proposer = signed_block.message.proposer_index;
    let block_root = signed_block.message.hash_tree_root();
    let parent_root = signed_block.message.parent_root;
    let attestation_count = signed_block.message.body.attestations.len();

    // Encode to SSZ
    let ssz_bytes = signed_block.to_ssz();

    // Compress with raw snappy
    let compressed = compress_message(&ssz_bytes);

    metrics::observe_gossip_block_size(ssz_bytes.len(), compressed.len());

    // Publish to gossipsub
    let Some(topic) = server.wire.lean().map(|lean| lean.block_topic.clone()) else {
        warn!("Publishing is suppressed on the beacon wire; dropping block");
        return;
    };
    server.swarm_handle.publish(topic, compressed);
    info!(
        %slot,
        proposer,
        block_root = %ShortRoot(&block_root.0),
        parent_root = %ShortRoot(&parent_root.0),
        attestation_count,
        "Published block to gossipsub"
    );
}

pub async fn publish_aggregated_attestation(
    server: &mut P2PServer,
    attestation: SignedAggregatedAttestation,
) {
    let slot = attestation.data.slot;

    // Encode to SSZ
    let ssz_bytes = attestation.to_ssz();

    // Compress with raw snappy
    let compressed = compress_message(&ssz_bytes);

    metrics::observe_gossip_aggregation_size(ssz_bytes.len(), compressed.len());

    // Publish to the aggregation topic
    let Some(topic) = server
        .wire
        .lean()
        .map(|lean| lean.aggregation_topic.clone())
    else {
        warn!("Publishing is suppressed on the beacon wire; dropping aggregate");
        return;
    };
    server.swarm_handle.publish(topic, compressed);
    info!(
        %slot,
        target_slot = attestation.data.target.slot,
        target_root = %ShortRoot(&attestation.data.target.root.0),
        source_slot = attestation.data.source.slot,
        source_root = %ShortRoot(&attestation.data.source.root.0),
        "Published aggregated attestation to gossipsub"
    );
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use ethlambda_storage::Store;
    use ethlambda_storage::backend::InMemoryBackend;
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::{fulu, shared};
    use ethlambda_types::beacon::preset;
    use ethlambda_types::beacon::primitives::{KzgCommitment, KzgProof, Root};
    use ethlambda_types::checkpoint::Checkpoint;
    use ethlambda_types::enr::EnrForkId;
    use ethlambda_types::primitives::H256;
    use libssz_types::SszVector;

    use super::*;
    use crate::beacon::swarm::BeaconWireConfig;
    use crate::{SwarmConfig, WireConfig, build_swarm};

    /// A real, unconnected beacon `P2PServer`, built the same way
    /// `req_resp::handlers::tests::unconnected_server` builds a lean one:
    /// port `0` throughout, so this cannot collide with a running node or a
    /// sibling test, and no bootnodes or peers.
    ///
    /// `handle_beacon_data_column` never reads `swarm_handle` or `discovery`,
    /// but both are required fields, and building the real thing is no more
    /// expensive than faking one would be.
    async fn unconnected_beacon_server(config: Config, finalized_slot: u64) -> P2PServer {
        let built = build_swarm(SwarmConfig {
            node_key: vec![9u8; 32],
            bootnodes: Vec::new(),
            listening_socket: "127.0.0.1:0".parse().expect("valid socket"),
            target_peers: crate::discovery::DEFAULT_DISCOVERY_TARGET_PEERS,
            wire: WireConfig::Beacon(Box::new(BeaconWireConfig {
                fork_digest: [0u8; 4],
                config: config.clone(),
                genesis_time: config.genesis_time,
                genesis_validators_root: Root::ZERO,
                custody_columns: Vec::new(),
            })),
        })
        .expect("swarm builds");

        let (_swarm_stream, swarm_handle) =
            crate::swarm_adapter::start_swarm_adapter(built.swarm, HashMap::new());

        let discovery = crate::discovery::spawn_discovery(crate::discovery::DiscoverySpawnConfig {
            node_key: secp256k1::SecretKey::new(&mut rand::rngs::OsRng)
                .secret_bytes()
                .to_vec(),
            bind_ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port: 0,
            p2p_port: 0,
            subscription_subnets: HashSet::new(),
            attestation_committee_count: 1,
            bootnodes: Vec::new(),
            advertise_ip: None,
            target_peers: 0,
            fork_id: EnrForkId::local(),
            custody_group_count: None,
        })
        .await
        .expect("discovery spawns");

        let backend = Arc::new(InMemoryBackend::new());
        let anchor_checkpoint = Checkpoint {
            root: H256::ZERO,
            slot: finalized_slot,
        };
        let store = Store::init_beacon(
            backend,
            0,
            Config::mainnet(),
            H256::ZERO,
            anchor_checkpoint,
            finalized_slot,
        );

        P2PServer {
            swarm_handle,
            store,
            blockchain: None,
            wire: built.wire,
            connected_peers: HashMap::new(),
            peer_custody: HashMap::new(),
            pending_root_requests: HashMap::new(),
            pending_column_requests: HashMap::new(),
            outbound_requests: HashMap::new(),
            range_sync_state: None,
            beacon_fetched_through: 0,
            bootnode_addrs: HashMap::new(),
            node_names: HashMap::new(),
            discovery: crate::discovery::dial::DiscoveryState::new(discovery, built.local_peer_id),
            seen_data_columns: HashSet::new(),
        }
    }

    /// A sidecar that clears `verify_data_column_sidecar`'s structural checks
    /// (one commitment, one proof, one column cell, all the same length) but
    /// carries no real KZG material: nothing in the gossip handler's reject
    /// path under test verifies the cryptography, only the shape and the
    /// header's slot.
    fn valid_shaped_sidecar(slot: u64, index: u64) -> fulu::DataColumnSidecar {
        let cell: fulu::Cell =
            SszVector::try_from(vec![0u8; preset::BYTES_PER_CELL]).expect("exact cell size");
        fulu::DataColumnSidecar {
            index,
            column: vec![cell].try_into().expect("within the per-block limit"),
            kzg_commitments: vec![KzgCommitment::default()]
                .try_into()
                .expect("within the per-block limit"),
            kzg_proofs: vec![KzgProof::default()]
                .try_into()
                .expect("within the per-block limit"),
            signed_block_header: shared::SignedBeaconBlockHeader {
                message: shared::BeaconBlockHeader {
                    slot,
                    proposer_index: 7,
                    ..Default::default()
                },
                signature: Default::default(),
            },
            kzg_commitments_inclusion_proof: vec![
                H256::ZERO;
                preset::KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH
            ]
            .try_into()
            .expect("exactly the required depth"),
        }
    }

    /// A far-future slot is rejected, and — the property the bug actually
    /// violated — its tuple never enters `seen_data_columns`. A test that
    /// only checked the rejection would still pass if the future-slot check
    /// were moved back after the dedup insert, since the sidecar would still
    /// be dropped on its way out; only this second assertion catches that.
    #[tokio::test]
    async fn a_far_future_slot_is_rejected_and_never_marked_seen() {
        let config = Config::mainnet();
        let mut server = unconnected_beacon_server(config, 0).await;

        // `saturating_mul` in the handler turns this into `u64::MAX`
        // regardless of `slot_duration_ms`, putting the slot's start
        // unreachably far beyond any real clock.
        let sidecar = valid_shaped_sidecar(u64::MAX, 0);
        let payload = sidecar.to_ssz();

        handle_beacon_data_column(&mut server, &payload, 0).await;

        assert!(
            server.seen_data_columns.is_empty(),
            "a rejected far-future sidecar must never enter the dedup set"
        );
    }

    /// A slot whose start sits a little ahead of this node's clock, but well
    /// within `MAXIMUM_GOSSIP_CLOCK_DISPARITY`, is accepted rather than
    /// rejected: this is what would fail if the tolerance were zero (or the
    /// comparison inverted), since only a non-zero, correctly-oriented
    /// allowance lets a slot starting after "now" through.
    #[tokio::test]
    async fn a_slot_within_the_clock_disparity_is_accepted() {
        let now_ms = unix_now_ms();
        // A one-millisecond slot duration gives this test exact control over
        // `slot_start_ms` despite `genesis_time` only having whole-second
        // resolution: the remainder below the second is folded into `slot`
        // instead of lost to truncation.
        let slot_duration_ms = 1;
        let genesis_time = now_ms / 1_000;
        let elapsed_since_genesis_ms = now_ms - genesis_time * 1_000;
        // Ahead of `now_ms` by less than `MAXIMUM_GOSSIP_CLOCK_DISPARITY`,
        // with margin on both sides for the time this test itself takes to
        // run.
        let ahead_of_now_ms = MAXIMUM_GOSSIP_CLOCK_DISPARITY / 2;
        let slot = elapsed_since_genesis_ms + ahead_of_now_ms;

        let config = Config {
            genesis_time,
            slot_duration_ms,
            ..Config::mainnet()
        };
        // The sidecar's slot must clear the finalized-slot check too, so the
        // store's own finalized slot sits at zero rather than at `slot`.
        let mut server = unconnected_beacon_server(config, 0).await;

        let sidecar = valid_shaped_sidecar(slot, 0);
        let payload = sidecar.to_ssz();

        handle_beacon_data_column(&mut server, &payload, 0).await;

        assert_eq!(
            server.seen_data_columns,
            HashSet::from([(slot, 7, 0)]),
            "a sidecar within the clock disparity must be accepted and marked seen"
        );
    }
}
