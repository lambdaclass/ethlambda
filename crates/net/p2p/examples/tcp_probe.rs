//! Dial one mainnet peer over TCP and report what the connection does.
//!
//! Exists to answer a single question the node's own logs cannot: when a
//! mainnet beacon peer drops us ~250ms after the TCP handshake with a muxer
//! decode error and no Goodbye, is it the transport stack that is wrong, or
//! something one of our behaviours does on top of it?
//!
//! Run it three times, adding one behaviour each time:
//!
//! ```text
//! cargo run -p ethlambda-p2p --example tcp_probe -- <multiaddr> identify
//! cargo run -p ethlambda-p2p --example tcp_probe -- <multiaddr> gossipsub
//! cargo run -p ethlambda-p2p --example tcp_probe -- <multiaddr> all
//! ```
//!
//! The first mode that dies names the trigger.

use std::time::Duration;

use libp2p::futures::StreamExt as _;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, identify, identity, noise, tcp, yamux};

#[derive(Debug, Clone, Copy, PartialEq)]
enum Mode {
    Identify,
    Gossipsub,
    All,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,libp2p_swarm=debug".into()),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let addr: Multiaddr = args
        .next()
        .expect("usage: tcp_probe <multiaddr> [identify|gossipsub|all]")
        .parse()
        .expect("a valid multiaddr");
    let mode = match args.next().as_deref() {
        None | Some("identify") => Mode::Identify,
        Some("gossipsub") => Mode::Gossipsub,
        Some("all") => Mode::All,
        Some(other) => panic!("unknown mode {other}"),
    };

    let identity = identity::Keypair::generate_secp256k1();
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity.clone())
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            // Both muxers, yamux first. Mainnet CL peers answer `na` to a
            // yamux-only proposal, which is what this probe exists to pin down.
            #[allow(deprecated)]
            (yamux::Config::default, libp2p_mplex::MplexConfig::default),
        )
        .expect("tcp transport")
        .with_behaviour(|_| Behaviour::new(&identity, mode))
        .expect("behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    println!("mode={mode:?} dialing {addr}");
    swarm.dial(addr).expect("dial");

    let deadline = tokio::time::sleep(Duration::from_secs(45));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => {
                println!("SURVIVED 45s in mode {mode:?}");
                return;
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    println!("CONNECTED {peer_id}");
                }
                SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                    println!("CLOSED {peer_id} after mode {mode:?}: {cause:?}");
                    return;
                }
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    println!("DIAL FAILED: {error}");
                    return;
                }
                SwarmEvent::Behaviour(event) => println!("behaviour: {event:?}"),
                _ => {}
            },
        }
    }
}

#[derive(libp2p::swarm::NetworkBehaviour)]
struct Behaviour {
    identify: identify::Behaviour,
    gossipsub: libp2p::swarm::behaviour::toggle::Toggle<libp2p::gossipsub::Behaviour>,
}

impl Behaviour {
    fn new(identity: &identity::Keypair, mode: Mode) -> Self {
        let gossipsub = if mode == Mode::Identify {
            None
        } else {
            Some(
                libp2p::gossipsub::Behaviour::new(
                    libp2p::gossipsub::MessageAuthenticity::Anonymous,
                    libp2p::gossipsub::ConfigBuilder::default()
                        .validation_mode(libp2p::gossipsub::ValidationMode::Anonymous)
                        .build()
                        .expect("gossipsub config"),
                )
                .expect("gossipsub behaviour"),
            )
        };
        Behaviour {
            identify: identify::Behaviour::new(identify::Config::new(
                "eth2/1.0.0".to_owned(),
                identity.public(),
            )),
            gossipsub: gossipsub.into(),
        }
    }
}
