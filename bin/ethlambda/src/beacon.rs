//! `ethlambda beacon`: startup for the mainnet follower.
//!
//! Every network parameter is derived rather than hardcoded. The order matters:
//! the fork digest depends on the epoch, which depends on genesis time, which
//! comes from the Beacon API, so the swarm cannot be built until that call has
//! returned.
//!
//! ```text
//! GET /eth/v1/beacon/genesis
//!   └─► genesis_validators_root, genesis_time
//!       └─► epoch = (now - genesis_time) / (seconds_per_slot * SLOTS_PER_EPOCH)
//!           └─► fork_digest = compute_fork_digest(Config::mainnet(), gvr, epoch)
//!               └─► gossip topics, ENR eth2 entry, discv5 admission
//! ```

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::fork_digest::{compute_fork_digest, next_fork_boundary};
use ethlambda_types::beacon::preset;
use ethlambda_types::beacon::primitives::{Epoch, Root};
use ethlambda_types::enr::EnrForkId;
use eyre::WrapErr as _;
use serde::Deserialize;
use tracing::{info, warn};

/// The sentinel every unscheduled fork epoch carries.
const FAR_FUTURE_EPOCH: Epoch = u64::MAX;

/// The epoch containing wall-clock second `now`.
///
/// Before genesis this is 0 rather than an error: a node started early should
/// pick the genesis fork's topics and wait, not refuse to boot.
pub fn epoch_at(config: &Config, genesis_time: u64, now: u64) -> Epoch {
    now.saturating_sub(genesis_time) / (config.seconds_per_slot * preset::SLOTS_PER_EPOCH)
}

/// The wall-clock second `epoch` begins at.
pub fn time_at_epoch(config: &Config, genesis_time: u64, epoch: Epoch) -> u64 {
    genesis_time + epoch * config.seconds_per_slot * preset::SLOTS_PER_EPOCH
}

/// The `eth2` ENR entry for this chain at this epoch.
///
/// `next_fork_*` point at the next boundary that moves the digest, which
/// includes blob-parameter-only forks. Peers tolerate a difference here by
/// design: only `fork_digest` has to match.
pub fn enr_fork_id(config: &Config, genesis_validators_root: Root, epoch: Epoch) -> EnrForkId {
    let fork_digest = compute_fork_digest(config, genesis_validators_root, epoch);
    match next_fork_boundary(config, epoch) {
        Some(boundary) => EnrForkId {
            fork_digest,
            next_fork_version: config.fork_version(config.fork_at_epoch(boundary)),
            next_fork_epoch: boundary,
        },
        None => EnrForkId {
            fork_digest,
            next_fork_version: config.fork_version(config.fork_at_epoch(epoch)),
            next_fork_epoch: FAR_FUTURE_EPOCH,
        },
    }
}

/// Path of the Beacon API's genesis endpoint, relative to the checkpoint URL.
const GENESIS_PATH: &str = "/eth/v1/beacon/genesis";

/// Timeout for the genesis fetch. The response is a few hundred bytes, so a
/// slow one means an unhealthy peer rather than a large body.
const GENESIS_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Deserialize)]
struct GenesisResponse {
    data: GenesisData,
}

#[derive(Debug, Deserialize)]
struct GenesisData {
    genesis_time: String,
    genesis_validators_root: String,
}

/// The two genesis fields the fork digest is derived from.
#[derive(Debug, Clone, Copy)]
pub struct Genesis {
    pub genesis_time: u64,
    pub genesis_validators_root: Root,
}

/// Fetch `genesis_time` and `genesis_validators_root` from a Beacon API.
///
/// This is the whole of what startup needs from the network: the anchor state
/// itself belongs to the anchor-and-follow work, and must be checked against
/// these two values when it lands.
pub async fn fetch_genesis(base_url: &str) -> eyre::Result<Genesis> {
    let url = format!("{}{GENESIS_PATH}", base_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(GENESIS_TIMEOUT)
        .build()
        .wrap_err("failed to build the genesis HTTP client")?;
    // `reqwest` is built without its `json` feature, so the body is read as
    // text and handed to serde_json rather than widening the workspace dep.
    let body = client
        .get(&url)
        .send()
        .await
        .wrap_err_with(|| format!("failed to GET {url}"))?
        .error_for_status()
        .wrap_err_with(|| format!("{url} returned an error status"))?
        .text()
        .await
        .wrap_err_with(|| format!("failed to read the body of {url}"))?;
    let response: GenesisResponse = serde_json::from_str(&body)
        .wrap_err_with(|| format!("{url} did not return the expected JSON"))?;

    let genesis_time: u64 = response
        .data
        .genesis_time
        .parse()
        .wrap_err("genesis_time is not a number")?;
    let root_hex = response
        .data
        .genesis_validators_root
        .trim_start_matches("0x");
    let root_bytes = hex::decode(root_hex).wrap_err("genesis_validators_root is not hex")?;
    eyre::ensure!(
        root_bytes.len() == 32,
        "genesis_validators_root is {} bytes, not 32",
        root_bytes.len()
    );

    Ok(Genesis {
        genesis_time,
        genesis_validators_root: Root::from_slice(&root_bytes),
    })
}

/// Try each Beacon API in turn, returning the first that answers.
///
/// `--checkpoint-sync-url` takes a list precisely so a single unhealthy
/// provider does not stop the node from booting; every failure is logged so a
/// consistently bad entry is visible rather than silently skipped.
async fn fetch_genesis_from_any(urls: &[String]) -> eyre::Result<Genesis> {
    let mut last_error = None;
    for url in urls {
        match fetch_genesis(url).await {
            Ok(genesis) => return Ok(genesis),
            Err(err) => {
                warn!(%url, %err, "Beacon API did not serve genesis metadata");
                last_error = Some(err);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| eyre::eyre!("no --checkpoint-sync-url was supplied")))
}

/// Everything `run` needs, gathered from the `beacon` subcommand's flags.
pub struct BeaconRunConfig {
    pub checkpoint_sync_urls: Vec<String>,
    pub node_key: Vec<u8>,
    pub gossipsub_port: u16,
    pub discovery_port: u16,
    pub advertise_ip: Option<IpAddr>,
    /// `None` uses the built-in mainnet list.
    pub bootnode_enrs: Option<Vec<String>>,
}

/// Start the mainnet follower and return once the P2P actor is running.
pub async fn run(config: BeaconRunConfig) -> eyre::Result<ethlambda_p2p::P2P> {
    let chain = Config::mainnet();
    let genesis = fetch_genesis_from_any(&config.checkpoint_sync_urls)
        .await
        .wrap_err("failed to fetch genesis metadata")?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the unix epoch")
        .as_secs();
    let epoch = epoch_at(&chain, genesis.genesis_time, now);
    let fork = chain.fork_at_epoch(epoch);
    let fork_id = enr_fork_id(&chain, genesis.genesis_validators_root, epoch);
    let digest_hex = hex::encode(fork_id.fork_digest);

    info!(
        genesis_time = genesis.genesis_time,
        genesis_validators_root = %format!("0x{}", hex::encode(genesis.genesis_validators_root.0)),
        epoch,
        fork = fork.as_str(),
        fork_digest = %digest_hex,
        "Derived the mainnet wire parameters"
    );
    ethlambda_p2p::metrics::set_beacon_fork_digest(&digest_hex);

    // The digest is computed once. Crossing a boundary while running strands
    // this node on topic names nobody publishes to, so say when that is.
    match next_fork_boundary(&chain, epoch) {
        Some(boundary) => info!(
            boundary_epoch = boundary,
            boundary_unix_time = time_at_epoch(&chain, genesis.genesis_time, boundary),
            "The fork digest changes at this boundary; restart the node to cross it"
        ),
        None => info!("No fork or blob-schedule boundary is scheduled"),
    }

    // Say plainly what is advertised but not served, so a running node never
    // implies more than it does.
    warn!(
        "Advertising cgc={} while custodying nothing, subscribing to no attestation, \
         sync committee or data column subnet, and publishing nothing",
        ethlambda_p2p::beacon::constants::CUSTODY_REQUIREMENT
    );

    let enrs = config.bootnode_enrs.unwrap_or_else(|| {
        ethlambda_p2p::beacon::bootnodes::MAINNET_BOOTNODES
            .iter()
            .map(|enr| enr.to_string())
            .collect()
    });
    let bootnodes = ethlambda_p2p::parse_enrs(enrs.clone());
    let discovery_bootnodes = ethlambda_p2p::parse_enrs(enrs);

    let listening_socket = SocketAddr::new(IpAddr::from([0, 0, 0, 0]), config.gossipsub_port);
    let built = ethlambda_p2p::beacon::swarm::build_beacon_swarm(
        ethlambda_p2p::beacon::swarm::BeaconSwarmConfig {
            node_key: config.node_key.clone(),
            listening_socket,
            fork_digest: fork_id.fork_digest,
            config: chain,
            genesis_time: genesis.genesis_time,
            bootnodes,
        },
    )
    .map_err(|err| eyre::eyre!("{err}"))
    .wrap_err("failed to build the beacon swarm")?;

    let node_key = secp256k1::SecretKey::from_slice(&config.node_key)
        .wrap_err("node key is not a valid secp256k1 secret key")?;
    let discovery =
        ethlambda_p2p::discovery::spawn_discovery(ethlambda_p2p::discovery::DiscoverySpawnConfig {
            node_key,
            bind_ip: IpAddr::from([0, 0, 0, 0]),
            discovery_port: config.discovery_port,
            quic_port: config.gossipsub_port,
            // No attestation subnet is subscribed, so the bitfield is 64 bits
            // all unset: exactly what this node serves.
            subscription_subnets: Default::default(),
            attestation_committee_count: ethlambda_p2p::beacon::constants::ATTESTATION_SUBNET_COUNT,
            bootnodes: discovery_bootnodes,
            advertise_ip: config.advertise_ip,
            fork_id,
            custody_group_count: Some(ethlambda_p2p::beacon::constants::CUSTODY_REQUIREMENT),
        })
        .await
        .map_err(|err| eyre::eyre!(err))
        .wrap_err("failed to start discv5 discovery")?;

    // An empty store. `P2PServer` holds one for the lean handlers; no beacon
    // path reads it until the anchor lands, at which point this becomes the
    // DB-backed store checkpoint sync produced.
    let store = ethlambda_storage::Store::from_anchor_state(
        Arc::new(ethlambda_storage::backend::InMemoryBackend::default()),
        ethlambda_types::state::State::from_genesis(genesis.genesis_time, Vec::new()),
    );

    Ok(ethlambda_p2p::P2P::spawn(
        built,
        store,
        Default::default(),
        Some(discovery),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mainnet's genesis, 2020-12-01 12:00:23 UTC.
    const MAINNET_GENESIS_TIME: u64 = 1_606_824_023;

    fn mainnet_gvr() -> Root {
        Root::from_slice(
            &hex::decode("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
                .expect("valid hex"),
        )
    }

    #[test]
    fn the_epoch_is_read_off_the_wall_clock() {
        let config = Config::mainnet();
        assert_eq!(
            epoch_at(&config, MAINNET_GENESIS_TIME, MAINNET_GENESIS_TIME),
            0
        );
        // One epoch is SLOTS_PER_EPOCH slots of seconds_per_slot each.
        let one_epoch = config.seconds_per_slot * preset::SLOTS_PER_EPOCH;
        assert_eq!(
            epoch_at(
                &config,
                MAINNET_GENESIS_TIME,
                MAINNET_GENESIS_TIME + one_epoch
            ),
            1
        );
        assert_eq!(
            epoch_at(
                &config,
                MAINNET_GENESIS_TIME,
                MAINNET_GENESIS_TIME + one_epoch - 1
            ),
            0
        );
    }

    #[test]
    fn a_clock_before_genesis_reports_epoch_zero_rather_than_underflowing() {
        let config = Config::mainnet();
        assert_eq!(epoch_at(&config, MAINNET_GENESIS_TIME, 0), 0);
    }

    #[test]
    fn epoch_and_time_are_inverses() {
        let config = Config::mainnet();
        for epoch in [0u64, 1, 411_392, 419_072] {
            let at = time_at_epoch(&config, MAINNET_GENESIS_TIME, epoch);
            assert_eq!(epoch_at(&config, MAINNET_GENESIS_TIME, at), epoch);
        }
    }

    #[test]
    fn the_enr_fork_id_carries_the_computed_digest() {
        let config = Config::mainnet();
        let fork_id = enr_fork_id(&config, mainnet_gvr(), 419_072);
        assert_eq!(fork_id.fork_digest, [0x8c, 0x9f, 0x62, 0xfe]);
        // Nothing is scheduled past the last blob-schedule entry.
        assert_eq!(fork_id.next_fork_epoch, FAR_FUTURE_EPOCH);
        assert_eq!(fork_id.next_fork_version, config.fulu_fork_version);
    }

    #[test]
    fn a_pending_boundary_is_advertised() {
        let config = Config::mainnet();
        let fork_id = enr_fork_id(&config, mainnet_gvr(), 411_392);
        assert_eq!(fork_id.next_fork_epoch, 412_672);
        // A blob-parameter-only fork keeps fulu's version: it moves the digest
        // without introducing a new fork version, which is EIP-7892's point.
        assert_eq!(fork_id.next_fork_version, config.fulu_fork_version);
    }
}
