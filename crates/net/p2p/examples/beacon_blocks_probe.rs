//! Ask a running beacon node for blocks, and report what comes back.
//!
//! Exists because the node's own logs cannot answer "does an inbound
//! `beacon_blocks_by_range/2` actually work end to end". The unit tests cover
//! the codec against itself and the store walk against a hand-built chain;
//! neither can tell whether libp2p will negotiate the protocol inbound, nor
//! whether the live store answers with anything.
//!
//! ```text
//! cargo run -p ethlambda-p2p --example beacon_blocks_probe -- <multiaddr> <start_slot> [count]
//! ```
//!
//! The multiaddr needs no peer id: `/ip4/1.2.3.4/udp/9008/quic-v1` is enough,
//! and the id is read off the connection once it is up.

use std::time::Duration;

use ethlambda_p2p::beacon::messages::{BeaconBlocksByRangeRequest, BeaconStatus, Ping, StatusV1};
use ethlambda_p2p::beacon::protocols;
use ethlambda_p2p::req_resp::{BeaconRequest, BeaconResponse, Request, Response, ResponsePayload};
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::primitives::Root;
use libp2p::futures::StreamExt as _;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, StreamProtocol, identity, noise, request_response, tcp, yamux};

/// Mainnet's `genesis_validators_root`. Only used to build the codec, which
/// needs it to label the chunks it *writes*; this probe only reads.
const MAINNET_GENESIS_VALIDATORS_ROOT: [u8; 32] = [
    0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f, 0xdd, 0x4e,
    0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a, 0xd2, 0x7f, 0x51, 0x1b, 0xfe, 0x95,
];

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let addr: Multiaddr = args
        .next()
        .expect("usage: beacon_blocks_probe <multiaddr> <start_slot> [count]")
        .parse()
        .expect("a valid multiaddr");
    let start_slot: u64 = args
        .next()
        .expect("a start slot")
        .parse()
        .expect("a slot number");
    let count: u64 = args
        .next()
        .map(|value| value.parse().expect("a count"))
        .unwrap_or(8);

    let identity = identity::Keypair::generate_secp256k1();
    let codec = ethlambda_p2p::req_resp::Codec::beacon(
        Config::mainnet(),
        Root::from_slice(&MAINNET_GENESIS_VALIDATORS_ROOT),
    );
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            #[allow(deprecated)]
            (yamux::Config::default, libp2p_mplex::MplexConfig::default),
        )
        .expect("tcp transport")
        .with_quic()
        .with_behaviour(|_| {
            request_response::Behaviour::with_codec(
                codec,
                protocols::registrations(),
                Default::default(),
            )
        })
        .expect("behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
        .build();

    println!("dialing {addr}");
    swarm.dial(addr).expect("dial");

    let deadline = tokio::time::sleep(Duration::from_secs(45));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => {
                println!("TIMED OUT with no answer");
                return;
            }
            event = swarm.select_next_some() => match event {
                // The peer id is learned here rather than required on the
                // command line: a node's ENR is not always to hand, and the
                // address alone is enough to dial.
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    println!("CONNECTED {peer_id}, asking for {count} blocks from slot {start_slot}");
                    // `send_request_with_protocol`, not `send_request`: with
                    // several protocols registered the latter picks the first
                    // one the remote supports, which is `status/1`, and the
                    // range request would go out on the handshake stream.
                    swarm.behaviour_mut().send_request_with_protocol(
                        &peer_id,
                        Request::Beacon(BeaconRequest::BlocksByRange(
                            BeaconBlocksByRangeRequest::new(start_slot, count),
                        )),
                        StreamProtocol::new(protocols::BEACON_BLOCKS_BY_RANGE_V2),
                    );
                }
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message: request_response::Message::Response { response, .. },
                    ..
                }) => {
                    match response {
                        Response::Success {
                            payload: ResponsePayload::Beacon(BeaconResponse::Blocks(blocks)),
                        } => {
                            println!("SERVED {} blocks", blocks.len());
                            for block in &blocks {
                                println!(
                                    "  slot={} fork={} root={}",
                                    block.slot(),
                                    block.fork_name().as_str(),
                                    hex::encode(&block.message_hash_tree_root().0[..4]),
                                );
                            }
                        }
                        other => println!("UNEXPECTED response: {other:?}"),
                    }
                    return;
                }
                // The node opens its own `Status` handshake as soon as the
                // connection is up and drops the peer if it goes unanswered,
                // taking our in-flight request with it. Echoing the digest it
                // sent is enough to stay connected, and is honest: this probe
                // is on whatever chain the peer it dialed is on.
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message: request_response::Message::Request { request, channel, .. },
                    ..
                }) => {
                    let answer = match request {
                        Request::Beacon(BeaconRequest::Status(peer_status)) => {
                            Some(BeaconResponse::Status(BeaconStatus::V1(StatusV1 {
                                fork_digest: peer_status.fork_digest(),
                                finalized_root: Root::zero(),
                                finalized_epoch: 0,
                                head_root: Root::zero(),
                                head_slot: 0,
                            })))
                        }
                        Request::Beacon(BeaconRequest::Ping(_)) => {
                            Some(BeaconResponse::Pong(Ping { seq_number: 0 }))
                        }
                        _ => None,
                    };
                    if let Some(answer) = answer {
                        let _ = swarm.behaviour_mut().send_response(
                            channel,
                            Response::success(ResponsePayload::Beacon(answer)),
                        );
                    }
                }
                SwarmEvent::Behaviour(request_response::Event::OutboundFailure { error, .. }) => {
                    println!("REQUEST FAILED: {error}");
                    return;
                }
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    println!("DIAL FAILED: {error}");
                    return;
                }
                _ => {}
            },
        }
    }
}
