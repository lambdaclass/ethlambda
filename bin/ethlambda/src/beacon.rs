//! `ethlambda beacon`: startup for the mainnet follower.
//!
//! Every network parameter is derived rather than hardcoded. The order matters:
//! the fork digest depends on the epoch and on `genesis_validators_root`, both
//! of which are read off the checkpoint anchor, so the swarm cannot be built
//! until checkpoint sync has returned.
//!
//! ```text
//! GET /eth/v2/beacon/blocks/finalized
//!   └─► block.state_root
//!       └─► GET /eth/v2/debug/beacon/states/0x{state_root}
//!           └─► genesis_validators_root, genesis_time
//!               └─► epoch = (now - genesis_time) / (seconds_per_slot * SLOTS_PER_EPOCH)
//!                   └─► fork_digest = compute_fork_digest(Config::mainnet(), gvr, epoch)
//!                       └─► gossip topics, ENR eth2 entry, discv5 admission
//!                           └─► build the swarm
//! ```
//!
//! `/eth/v1/beacon/genesis` is still fetched, but only to cross-check the
//! anchor: plan 4 introduced it as the sole source of these two values and
//! recorded that the anchor "must be checked against" them once it landed.

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

/// Every network parameter that cannot be known before the anchor is fetched.
///
/// Exists to make the startup order structural: the swarm is built only from a
/// value of this type, only [`beacon_network_params`] produces one, and it takes
/// the anchor's own fields. See `docs/beacon_sync.md`.
pub struct BeaconNetworkParams {
    /// Carries the fork digest, plus the `next_fork_*` pair the ENR advertises.
    pub fork_id: EnrForkId,
    pub genesis_validators_root: Root,
    pub genesis_time: u64,
    /// The epoch the digest was computed for: the wall-clock epoch at startup,
    /// not the anchor's. Logged so a boundary crossed while running is
    /// diagnosable from the boot log.
    pub digest_epoch: Epoch,
}

/// Derive the swarm's network parameters.
///
/// `genesis_validators_root` and `genesis_time` come off the checkpoint anchor;
/// the epoch comes off the clock. The anchor is roughly two epochs behind the
/// head, so computing the digest for *its* epoch would put this node on the
/// previous side of any fork or blob-parameter boundary crossed in between.
pub fn beacon_network_params(
    config: &Config,
    genesis_validators_root: Root,
    genesis_time: u64,
    now_unix_secs: u64,
) -> BeaconNetworkParams {
    let digest_epoch = epoch_at(config, genesis_time, now_unix_secs);
    BeaconNetworkParams {
        fork_id: enr_fork_id(config, genesis_validators_root, digest_epoch),
        genesis_validators_root,
        genesis_time,
        digest_epoch,
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
    pub data_dir: std::path::PathBuf,
}

/// Cross-check the anchor against the provider's own genesis endpoint.
///
/// Plan 4 fetched `/eth/v1/beacon/genesis` as the sole source of these two
/// values and recorded that the anchor state, once it landed, "must be checked
/// against" them. This is that check. A disagreement is fatal: the two answers
/// come from the same provider, so they cannot legitimately differ, and a node
/// that booted on the wrong `genesis_validators_root` would compute a digest no
/// peer matches and sit silently at zero peers.
///
/// An unreachable genesis endpoint is only a warning. The anchor is the
/// authority; the endpoint is corroboration, and losing corroboration should
/// not stop a node whose anchor verified.
async fn cross_check_anchor_against_genesis(
    urls: &[String],
    genesis_validators_root: Root,
    genesis_time: u64,
) -> eyre::Result<()> {
    let Ok(genesis) = fetch_genesis_from_any(urls).await else {
        warn!(
            "No provider served /eth/v1/beacon/genesis; skipping the anchor cross-check. \
             The anchor itself verified, so this is corroboration lost, not a bad anchor"
        );
        return Ok(());
    };
    eyre::ensure!(
        genesis.genesis_validators_root == genesis_validators_root,
        "provider disagrees with itself: the anchor state's genesis_validators_root is \
         0x{} but /eth/v1/beacon/genesis reports 0x{}",
        hex::encode(genesis_validators_root.0),
        hex::encode(genesis.genesis_validators_root.0),
    );
    eyre::ensure!(
        genesis.genesis_time == genesis_time,
        "provider disagrees with itself: the anchor state's genesis_time is {} but \
         /eth/v1/beacon/genesis reports {}",
        genesis_time,
        genesis.genesis_time,
    );
    Ok(())
}

/// Start the mainnet follower and return once the P2P actor is running.
pub async fn run(config: BeaconRunConfig) -> eyre::Result<ethlambda_p2p::P2P> {
    let chain = Config::mainnet();

    let checkpoint_urls: Vec<String> = config
        .checkpoint_sync_urls
        .iter()
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty())
        .collect();
    // clap already marks the flag required, so this catches only the empty
    // string, which a shell expanding an unset variable produces easily.
    eyre::ensure!(
        !checkpoint_urls.is_empty(),
        "ethlambda beacon requires --checkpoint-sync-url: the fork digest is \
         derived from the anchor state's genesis_validators_root, so there is \
         no network to join without one"
    );

    // Before the swarm, deliberately: `genesis_validators_root` and
    // `genesis_time` are read off the anchor, and the fork digest computed from
    // them names every gossip topic, the ENR `eth2` entry and the discv5
    // admission test. Nothing about the network is knowable earlier.
    //
    // This runs on every boot, including a restart against a populated data
    // directory. Reading the two values back off disk instead would let a
    // restart skip the download, but the resume decision needs a beacon
    // equivalent of `Store::from_db_state`, which is not part of A1/A2.
    let anchor = crate::beacon_checkpoint::fetch_beacon_anchor_from_any(&checkpoint_urls, &chain)
        .await
        .map_err(|err| eyre::eyre!("{err}"))
        .wrap_err("beacon checkpoint sync failed")?;

    cross_check_anchor_against_genesis(
        &checkpoint_urls,
        anchor.genesis_validators_root(),
        anchor.genesis_time(),
    )
    .await?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the unix epoch")
        .as_secs();
    let params = beacon_network_params(
        &chain,
        anchor.genesis_validators_root(),
        anchor.genesis_time(),
        now,
    );
    let fork_id = params.fork_id;
    let digest_hex = hex::encode(fork_id.fork_digest);
    let anchor_slot = anchor.slot();

    info!(
        anchor_slot,
        fork = anchor.state.fork_name().as_str(),
        genesis_validators_root = %format!("0x{}", hex::encode(params.genesis_validators_root.0)),
        genesis_time = params.genesis_time,
        fork_digest = %digest_hex,
        digest_epoch = params.digest_epoch,
        "Beacon checkpoint sync complete"
    );
    ethlambda_p2p::metrics::set_beacon_fork_digest(&digest_hex);

    // The digest is computed once. Crossing a boundary while running strands
    // this node on topic names nobody publishes to, so say when that is.
    match next_fork_boundary(&chain, params.digest_epoch) {
        Some(boundary) => warn!(
            boundary_epoch = boundary,
            boundary_unix_time = time_at_epoch(&chain, params.genesis_time, boundary),
            "The fork digest is computed once at startup. Restart this node \
             before the epoch above or it will be left on stale topics"
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
            config: chain.clone(),
            genesis_time: params.genesis_time,
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

    // The anchor becomes the store's one trusted block, and every later state
    // is reached by replaying blocks forward from it. `get_forkchoice_store`
    // re-checks the pair `verify_beacon_anchor` already checked; paying the
    // merkleization twice is worth having the provider named in the error.
    let data_dir =
        std::path::absolute(&config.data_dir).unwrap_or_else(|_| config.data_dir.clone());
    std::fs::create_dir_all(&data_dir)
        .wrap_err_with(|| format!("failed to create data directory {}", data_dir.display()))?;
    info!(data_dir = %data_dir.display(), "Initializing DB");
    let backend = Arc::new(
        ethlambda_storage::backend::RocksDBBackend::open(&data_dir)
            .map_err(|err| eyre::eyre!("{err}"))
            .wrap_err_with(|| format!("failed to open RocksDB at {}", data_dir.display()))?,
    );
    let store = ethlambda_beacon::fork_choice::get_forkchoice_store(
        backend,
        anchor.state,
        anchor.block,
        &chain,
    )
    .map_err(|err| eyre::eyre!("{err:?}"))
    .wrap_err("failed to initialize the store from the checkpoint anchor")?;

    ethlambda_blockchain::metrics::set_sync_anchor_slot(anchor_slot);

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

    /// Seconds since genesis that put the clock at the first slot of `epoch`.
    fn now_at_epoch(config: &Config, genesis_time: u64, epoch: u64) -> u64 {
        genesis_time + epoch * preset::SLOTS_PER_EPOCH * config.seconds_per_slot
    }

    /// The digest is a function of values that exist only after the anchor is
    /// in hand, so the type carrying the swarm's inputs cannot be built without
    /// one. This fails to compile, not merely to assert, if
    /// `beacon_network_params` ever stops taking the anchor's fields.
    #[test]
    fn network_params_are_derived_from_the_anchor_and_the_clock() {
        let config = Config::mainnet();
        let gvr = Root::repeat_byte(0x2a);
        let genesis_time = MAINNET_GENESIS_TIME;
        let now = now_at_epoch(&config, genesis_time, config.fulu_fork_epoch);

        let params = beacon_network_params(&config, gvr, genesis_time, now);

        assert_eq!(params.genesis_validators_root, gvr);
        assert_eq!(params.genesis_time, genesis_time);
        assert_eq!(params.digest_epoch, config.fulu_fork_epoch);
        assert_eq!(
            params.fork_id.fork_digest,
            compute_fork_digest(&config, gvr, config.fulu_fork_epoch),
        );
    }

    /// The clock decides the epoch, not the anchor. The anchor is two epochs
    /// behind the head; if a blob-parameter boundary sits in between, using the
    /// anchor's epoch would join the topics the network has already left.
    #[test]
    fn the_digest_follows_the_wall_clock_across_a_boundary() {
        let config = Config::mainnet();
        let gvr = Root::repeat_byte(0x2a);
        let genesis_time = MAINNET_GENESIS_TIME;
        let boundary = config.blob_schedule[1].epoch;

        let before = beacon_network_params(
            &config,
            gvr,
            genesis_time,
            now_at_epoch(&config, genesis_time, boundary - 1),
        );
        let after = beacon_network_params(
            &config,
            gvr,
            genesis_time,
            now_at_epoch(&config, genesis_time, boundary),
        );

        assert_ne!(
            before.fork_id.fork_digest, after.fork_id.fork_digest,
            "a blob-parameter boundary changes the digest, so the epoch it is \
             computed for has to be the current one"
        );
    }

    /// A different chain must produce a different digest: the digest is not a
    /// constant that happens to be recomputed.
    #[test]
    fn a_different_genesis_validators_root_changes_the_digest() {
        let config = Config::mainnet();
        let now = now_at_epoch(&config, 0, config.fulu_fork_epoch);

        let one = beacon_network_params(&config, Root::repeat_byte(1), 0, now);
        let two = beacon_network_params(&config, Root::repeat_byte(2), 0, now);

        assert_ne!(one.fork_id.fork_digest, two.fork_id.fork_digest);
    }

    /// Startup names the next boundary so a digest going stale under a running
    /// node is diagnosable from the boot log rather than from zero peers.
    ///
    /// Plan 5 called this `next_digest_boundary`; plan 4 had already landed it
    /// in the types crate as `next_fork_boundary`. Same function, and this
    /// pins the behaviour plan 5's startup logging depends on.
    #[test]
    fn the_next_boundary_is_the_soonest_scheduled_change() {
        let config = Config::mainnet();
        let boundary = config.blob_schedule[0].epoch;

        assert_eq!(next_fork_boundary(&config, boundary - 1), Some(boundary));
        assert_eq!(
            next_fork_boundary(&config, boundary),
            Some(config.blob_schedule[1].epoch),
            "standing exactly on a boundary, the next one is the one after"
        );
        assert_eq!(
            next_fork_boundary(&config, u64::MAX - 1),
            None,
            "past every scheduled change there is nothing left to warn about"
        );
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
