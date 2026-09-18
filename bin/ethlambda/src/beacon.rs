//! `ethlambda beacon`: mainnet's built-in network configuration.
//!
//! Two things are hardcoded here, and they are the whole of what this chain
//! needs before it can put a node on the wire: the genesis `BeaconState` and
//! the bootnode ENRs. Everything else is derived from the first of them.
//!
//! The order matters, because the fork digest depends on the epoch, which
//! depends on genesis time:
//!
//! ```text
//! assets/mainnet/genesis.ssz
//!   └─► genesis_validators_root, genesis_time
//!       └─► epoch = (now - genesis_time) / (seconds_per_slot * SLOTS_PER_EPOCH)
//!           └─► fork_digest = compute_fork_digest(Config::mainnet(), gvr, epoch)
//!               └─► gossip topics, ENR eth2 entry, discv5 admission
//! ```
//!
//! Deriving them is all this module does; `crate::run_node` builds the swarm,
//! for both chains, from what [`wire_params`] returns.
//!
//! These two values used to come from a Beacon API's `/eth/v1/beacon/genesis`,
//! which made `--checkpoint-sync-url` mandatory on `beacon` and made startup
//! fail whenever every configured provider was down. They are properties of the
//! chain, not of a provider, so they are now read off the genesis state itself
//! and `beacon` boots with no network configuration at all. `node`'s checkpoint
//! sync is untouched: a lean node fetches a *finalized* anchor, which genuinely
//! has no local source.

use ethlambda_p2p::beacon::swarm::BeaconWireConfig;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::constants::FAR_FUTURE_EPOCH;
use ethlambda_types::beacon::containers::BeaconState;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::fork_digest::{compute_fork_digest, next_fork_boundary};
use ethlambda_types::beacon::preset;
use ethlambda_types::beacon::primitives::{Epoch, Root};
use ethlambda_types::enr::EnrForkId;
use eyre::WrapErr as _;
use tracing::{info, warn};

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
    // With no boundary ahead, the spec says to repeat the current fork's own
    // version and name `FAR_FUTURE_EPOCH` as the epoch it activates at.
    let boundary = next_fork_boundary(config, epoch);
    let named_epoch = boundary.unwrap_or(epoch);
    EnrForkId {
        fork_digest,
        next_fork_version: config.fork_version(config.fork_at_epoch(named_epoch)),
        next_fork_epoch: boundary.unwrap_or(FAR_FUTURE_EPOCH),
    }
}

/// Ethereum mainnet's genesis `BeaconState`, SSZ-encoded.
///
/// This is `metadata/genesis.ssz` from `eth-clients/mainnet` byte for byte, so
/// what we ship can be diffed against what that repo publishes rather than
/// taken on trust; [`the_shipped_state_is_eth_clients_file`] pins its SHA-256
/// so a future update to the asset has to be deliberate. It is the same repo
/// [`MAINNET_BOOTNODES`] is copied from, so both of this chain's hardcoded
/// values have one upstream.
///
/// 5,404,504 bytes, stored uncompressed. A deflated copy is under a third the
/// size, but paying for that means carrying a zip or gzip decoder in the
/// dependency graph to read one build-time constant. Carried in the binary
/// rather than read from disk so that `beacon` needs nothing but an argv to
/// start.
static MAINNET_GENESIS_SSZ: &[u8] = include_bytes!("../assets/mainnet/genesis.ssz");

/// The two genesis fields the fork digest is derived from.
#[derive(Debug, Clone, Copy)]
pub struct Genesis {
    pub genesis_time: u64,
    pub genesis_validators_root: Root,
}

/// Decode the built-in mainnet genesis state.
///
/// Fully decoded rather than read off the SSZ prefix the two fields happen to
/// sit in: a truncated or mis-encoded asset then fails here, loudly and at
/// startup, instead of yielding two plausible numbers off a corrupt file. The
/// state is also what the anchor work needs a source of, so it is returned
/// whole rather than reduced to the pair `mainnet_genesis` (below) takes from
/// it.
///
/// The fork is `Phase0` because this is *genesis*, not the current head: the
/// state predates altair by definition, whatever fork the chain is on now.
///
/// A `Result` rather than a `LazyLock` panic because `wire_params` already
/// returns one, and a decode failure is worth a wrapped message naming the
/// asset. Note that a build with `ethlambda-types/preset-minimal` on fails
/// here: the minimal preset shortens the state's fixed-size vectors, so
/// mainnet's encoding no longer fits the container. Nothing enables that
/// feature for this binary, and failing is the right answer if anything does.
pub fn mainnet_genesis_state() -> eyre::Result<BeaconState> {
    BeaconState::from_ssz(ForkName::Phase0, MAINNET_GENESIS_SSZ)
        .wrap_err("the built-in mainnet genesis did not decode as a phase0 BeaconState")
}

/// The two values the wire parameters used to be derived from, before
/// `crate::network::NetworkSource::genesis` took over: that method reads the
/// same pair off whichever network was resolved, mainnet included, so this is
/// no longer on any startup path. Kept `#[cfg(test)]`: it is what
/// `the_built_in_state_is_mainnets_genesis` (below) pins against the state
/// directly, and a lighter fixture than building a whole `NetworkSource` for
/// the handful of checkpoint-sync tests that only want these two fields.
#[cfg(test)]
pub fn mainnet_genesis() -> eyre::Result<Genesis> {
    let state = mainnet_genesis_state()?;
    Ok(Genesis {
        genesis_time: state.genesis_time(),
        genesis_validators_root: state.genesis_validators_root(),
    })
}

/// Ethereum mainnet's consensus-layer bootnodes.
///
/// Copied from `eth-clients/mainnet`'s `metadata/bootstrap_nodes.yaml`, with the
/// maintainer comments kept so a stale entry can be traced back to whoever runs
/// it. `--bootnodes` overrides the whole list.
///
/// Not one of these advertises a `quic` entry. Only Teku's two and Nimbus's two
/// advertise `tcp`; the other thirteen (Prylab, Lighthouse, the EF's, and
/// Lodestar's) advertise neither and remain discv5-seed-only, exactly as before
/// TCP support. `build_swarm` dials the four that do. Discovery is not a flag:
/// the static list alone reaches a minority of the network, and a discv5 crawl
/// is what finds the rest.
///
/// Those two counts used to be asserted against the parsed records, back when
/// this list lived in `ethlambda-p2p` beside `Bootnode`. They cannot be from
/// here: `Bootnode`'s ports are `pub(crate)`, so outside that crate a parsed
/// record is opaque. [`every_bootnode_parses`] is what survived the move.
pub const MAINNET_BOOTNODES: [&str; 17] = [
    // Teku team's bootnodes
    // 3.147.37.0 | aws-us-east-2-ohio
    "enr:-Iu4QLm7bZGdAt9NSeJG0cEnJohWcQTQaI9wFLu3Q7eHIDfrI4cwtzvEW3F3VbG9XdFXlrHyFGeXPn9snTCQJ9bnMRABgmlkgnY0gmlwhAOTJQCJc2VjcDI1NmsxoQIZdZD6tDYpkpEfVo5bgiU8MGRjhcOmHGD2nErK0UKRrIN0Y3CCIyiDdWRwgiMo",
    // 3.107.124.68 | aws-ap-southeast-2-sydney
    "enr:-Iu4QEDJ4Wa_UQNbK8Ay1hFEkXvd8psolVK6OhfTL9irqz3nbXxxWyKwEplPfkju4zduVQj6mMhUCm9R2Lc4YM5jPcIBgmlkgnY0gmlwhANrfESJc2VjcDI1NmsxoQJCYz2-nsqFpeEj6eov9HSi9QssIVIVNr0I89J1vXM9foN0Y3CCIyiDdWRwgiMo",
    // Prylab team's bootnodes
    // 18.223.219.100 | aws-us-east-2-ohio
    "enr:-Ku4QImhMc1z8yCiNJ1TyUxdcfNucje3BGwEHzodEZUan8PherEo4sF7pPHPSIB1NNuSg5fZy7qFsjmUKs2ea1Whi0EBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQOVphkDqal4QzPMksc5wnpuC3gvSC8AfbFOnZY_On34wIN1ZHCCIyg",
    // 18.223.219.100 | aws-us-east-2-ohio
    "enr:-Ku4QP2xDnEtUXIjzJ_DhlCRN9SN99RYQPJL92TMlSv7U5C1YnYLjwOQHgZIUXw6c-BvRg2Yc2QsZxxoS_pPRVe0yK8Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMeFF5GrS7UZpAH2Ly84aLK-TyvH-dRo0JM1i8yygH50YN1ZHCCJxA",
    // 18.223.219.100 | aws-us-east-2-ohio
    "enr:-Ku4QPp9z1W4tAO8Ber_NQierYaOStqhDqQdOPY3bB3jDgkjcbk6YrEnVYIiCBbTxuar3CzS528d2iE7TdJsrL-dEKoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMw5fqqkw2hHC4F5HZZDPsNmPdB1Gi8JPQK7pRc9XHh-oN1ZHCCKvg",
    // Lighthouse team's bootnodes
    // 172.105.173.25 | linode-au-sydney
    "enr:-Le4QPUXJS2BTORXxyx2Ia-9ae4YqA_JWX3ssj4E_J-3z1A-HmFGrU8BpvpqhNabayXeOZ2Nq_sbeDgtzMJpLLnXFgAChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISsaa0Zg2lwNpAkAIkHAAAAAPA8kv_-awoTiXNlY3AyNTZrMaEDHAD2JKYevx89W0CcFJFiskdcEzkH_Wdv9iW42qLK79ODdWRwgiMohHVkcDaCI4I",
    // 139.162.196.49 | linode-uk-london
    "enr:-Le4QLHZDSvkLfqgEo8IWGG96h6mxwe_PsggC20CL3neLBjfXLGAQFOPSltZ7oP6ol54OvaNqO02Rnvb8YmDR274uq8ChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLosQxg2lwNpAqAX4AAAAAAPA8kv_-ax65iXNlY3AyNTZrMaEDBJj7_dLFACaxBfaI8KZTh_SSJUjhyAyfshimvSqo22WDdWRwgiMohHVkcDaCI4I",
    // 139.99.217.220 | ovh-au-sydney
    "enr:-Le4QH6LQrusDbAHPjU_HcKOuMeXfdEB5NJyXgHWFadfHgiySqeDyusQMvfphdYWOzuSZO9Uq2AMRJR5O4ip7OvVma8BhGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLY9ncg2lwNpAkAh8AgQIBAAAAAAAAAAmXiXNlY3AyNTZrMaECDYCZTZEksF-kmgPholqgVt8IXr-8L7Nu7YrZ7HUpgxmDdWRwgiMohHVkcDaCI4I",
    // 139.99.78.39 | ovh-singapore
    "enr:-Le4QIqLuWybHNONr933Lk0dcMmAB5WgvGKRyDihy1wHDIVlNuuztX62W51voT4I8qD34GcTEOTmag1bcdZ_8aaT4NUBhGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLY04ng2lwNpAkAh8AgAIBAAAAAAAAAA-fiXNlY3AyNTZrMaEDscnRV6n1m-D9ID5UsURk0jsoKNXt1TIrj8uKOGW6iluDdWRwgiMohHVkcDaCI4I",
    // EF bootnodes
    // 3.17.30.69 | aws-us-east-2-ohio
    "enr:-Ku4QHqVeJ8PPICcWk1vSn_XcSkjOkNiTg6Fmii5j6vUQgvzMc9L1goFnLKgXqBJspJjIsB91LTOleFmyWWrFVATGngBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAMRHkWJc2VjcDI1NmsxoQKLVXFOhp2uX6jeT0DvvDpPcU8FWMjQdR4wMuORMhpX24N1ZHCCIyg",
    // 18.216.248.220 | aws-us-east-2-ohio
    "enr:-Ku4QG-2_Md3sZIAUebGYT6g0SMskIml77l6yR-M_JXc-UdNHCmHQeOiMLbylPejyJsdAPsTHJyjJB2sYGDLe0dn8uYBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhBLY-NyJc2VjcDI1NmsxoQORcM6e19T1T9gi7jxEZjk_sjVLGFscUNqAY9obgZaxbIN1ZHCCIyg",
    // 54.178.44.198 | aws-ap-northeast-1-tokyo
    "enr:-Ku4QPn5eVhcoF1opaFEvg1b6JNFD2rqVkHQ8HApOKK61OIcIXD127bKWgAtbwI7pnxx6cDyk_nI88TrZKQaGMZj0q0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDayLMaJc2VjcDI1NmsxoQK2sBOLGcUb4AwuYzFuAVCaNHA-dy24UuEKkeFNgCVCsIN1ZHCCIyg",
    // 54.65.172.253 | aws-ap-northeast-1-tokyo
    "enr:-Ku4QEWzdnVtXc2Q0ZVigfCGggOVB2Vc1ZCPEc6j21NIFLODSJbvNaef1g4PxhPwl_3kax86YPheFUSLXPRs98vvYsoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDZBrP2Jc2VjcDI1NmsxoQM6jr8Rb1ktLEsVcKAPa08wCsKUmvoQ8khiOl_SLozf9IN1ZHCCIyg",
    // Nimbus team's bootnodes
    // 3.120.104.18 | aws-eu-central-1-frankfurt
    "enr:-LK4QA8FfhaAjlb_BXsXxSfiysR7R52Nhi9JBt4F8SPssu8hdE1BXQQEtVDC3qStCW60LSO7hEsVHv5zm8_6Vnjhcn0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAN4aBKJc2VjcDI1NmsxoQJerDhsJ-KxZ8sHySMOCmTO6sHM3iCFQ6VMvLTe948MyYN0Y3CCI4yDdWRwgiOM",
    // 3.64.117.223 | aws-eu-central-1-frankfurt
    "enr:-LK4QKWrXTpV9T78hNG6s8AM6IO4XH9kFT91uZtFg1GcsJ6dKovDOr1jtAAFPnS2lvNltkOGA9k29BUN7lFh_sjuc9QBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhANAdd-Jc2VjcDI1NmsxoQLQa6ai7y9PMN5hpLe5HmiJSlYzMuzP7ZhwRiwHvqNXdoN0Y3CCI4yDdWRwgiOM",
    // Lodestar team's bootnodes
    // 160.119.254.161 | hostafrica-southafrica
    "enr:-IS4QPi-onjNsT5xAIAenhCGTDl4z-4UOR25Uq-3TmG4V3kwB9ljLTb_Kp1wdjHNj-H8VVLRBSSWVZo3GUe3z6k0E-IBgmlkgnY0gmlwhKB3_qGJc2VjcDI1NmsxoQMvAfgB4cJXvvXeM6WbCG86CstbSxbQBSGx31FAwVtOTYN1ZHCCIyg",
    // 83.229.71.210 | kamatera-telaviv-israel
    "enr:-KG4QPUf8-g_jU-KrwzG42AGt0wWM1BTnQxgZXlvCEIfTQ5hSmptkmgmMbRkpOqv6kzb33SlhPHJp7x4rLWWiVq5lSECgmlkgnY0gmlwhFPlR9KDaXA2kCoGxcAJAAAVAAAAAAAAABCJc2VjcDI1NmsxoQLdUv9Eo9sxCt0tc_CheLOWnX59yHJtkBSOL7kpxdJ6GYN1ZHCCIyiEdWRwNoIjKA",
];

/// The mainnet wire parameters [`wire_params`] derives.
///
/// The node key, the ports, the HTTP server and the bootnode list are not here:
/// they are the same on either chain, so `crate::run_node` owns them.
pub struct BeaconWireParams {
    /// The beacon half of the swarm configuration: the fork digest every topic
    /// name is keyed on, plus the schedule and genesis time gossip decode needs
    /// once the node is running.
    pub wire: BeaconWireConfig,
    /// The `eth2` ENR entry: published in this node's record, and compared
    /// against every record discv5 turns up.
    pub fork_id: EnrForkId,
}

/// The discv5 node id for this process's `--node-key` bytes.
///
/// A thin pass-through, kept as its own function so `run_node`'s exact
/// composition — resolve the key, derive the id, feed it to [`wire_params`] —
/// is unit-testable here; `run_node` itself needs a live swarm to drive and a
/// test cannot call it directly.
pub fn beacon_node_id(node_key: &[u8]) -> eyre::Result<[u8; 32]> {
    Ok(ethlambda_p2p::discovery::enr::node_id_from_secret_key(
        node_key,
    )?)
}

/// Derive a resolved network's wire parameters.
///
/// This is the whole of what startup needs before it can build a swarm, and it
/// touches no network: every value here is a function of `source` (built-in
/// mainnet or a loaded directory), the wall clock, and `node_id`, which the
/// caller must have derived via [`beacon_node_id`], since a peer computes our
/// custody set off the identity we publish. The anchor state itself belongs to
/// the anchor-and-follow work, and must be checked against the genesis values
/// used here when it lands.
///
/// `node_key_supplied` carries no key material, only whether `node_id` came
/// from a persisted `--node-key` or one generated fresh for this run: this
/// function has no other way to tell the two apart, and that is exactly what
/// the startup warning below needs to know.
pub fn wire_params(
    source: &crate::network::NetworkSource,
    node_id: [u8; 32],
    node_key_supplied: bool,
    custody_group_count: u64,
) -> eyre::Result<BeaconWireParams> {
    let chain = source.config().clone();
    let genesis = source.genesis();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the unix epoch")
        .as_secs();
    let epoch = epoch_at(&chain, genesis.genesis_time, now);
    let fork = chain.fork_at_epoch(epoch);
    let fork_id = enr_fork_id(&chain, genesis.genesis_validators_root, epoch);
    let digest_hex = hex::encode(fork_id.fork_digest);

    info!(
        network = %source.name(),
        genesis_time = genesis.genesis_time,
        genesis_validators_root = %format!("0x{}", hex::encode(genesis.genesis_validators_root.0)),
        epoch,
        fork = fork.as_str(),
        fork_digest = %digest_hex,
        "Derived the wire parameters for this network"
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

    // The node id is the discv5 one, so what this node custodies here is what
    // any peer computes for it from its ENR. A node without a persistent
    // --node-key gets a new identity and therefore a new custody set on every
    // restart, which is why startup warns about it right below.
    //
    // `sampling_size` is the larger of the advertised count and
    // `SAMPLES_PER_SLOT`, so the default advertisement still custodies
    // `SAMPLES_PER_SLOT` columns and the two only converge once
    // `--custody-group-count` is raised past that floor.
    let sampling = ethlambda_state_transition::beacon::das::sampling_size(custody_group_count);
    let custody_columns =
        ethlambda_state_transition::beacon::das::custody_columns(node_id, sampling)
            .expect("the sampling size is within NUMBER_OF_CUSTODY_GROUPS");
    info!(
        custody_group_count,
        sampling,
        columns = ?custody_columns,
        "Custodying data columns"
    );

    // The columns above are stored under this identity and served to peers
    // who compute the same set from it. An ephemeral identity makes both
    // sides of that agreement stale on the next restart: the sidecars already
    // on disk belong to a node id nobody, including this node, will select
    // again, and the fresh id this run advertises has nothing custodied for
    // it yet. Placed next to the custody log line above so an operator reads
    // the two together rather than finding this warning buried in startup
    // noise.
    if !node_key_supplied {
        warn!(
            "No --node-key supplied: this node's custody columns are a function of its \
             discv5 node id, so a fresh identity on every restart means the columns already \
             stored on disk belong to a different custody set than the one this run \
             advertises and serves. Pass --node-key with a persisted key file to keep one \
             identity, and therefore one custody set, across restarts."
        );
    }

    // Say plainly what is still advertised without being backed by behavior,
    // so a running node never implies more than it does. Storing and serving
    // the custodied columns logged above is no longer in that gap; attestation
    // and sync committee subnet subscription, and publishing, still are.
    warn!(
        "Advertising cgc={custody_group_count} while subscribing to no attestation or \
         sync committee subnet, and publishing nothing"
    );

    Ok(BeaconWireParams {
        wire: BeaconWireConfig {
            fork_digest: fork_id.fork_digest,
            config: chain,
            genesis_time: genesis.genesis_time,
            genesis_validators_root: genesis.genesis_validators_root,
            custody_columns,
        },
        fork_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_p2p::parse_enrs;
    use ethlambda_types::beacon::constants::CUSTODY_REQUIREMENT;

    /// Mainnet's genesis, 2020-12-01 12:00:23 UTC.
    const MAINNET_GENESIS_TIME: u64 = 1_606_824_023;

    fn mainnet_gvr() -> Root {
        Root::from_slice(
            &hex::decode("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
                .expect("valid hex"),
        )
    }

    #[test]
    fn every_bootnode_parses() {
        let parsed = parse_enrs(MAINNET_BOOTNODES.iter().map(|s| s.to_string()).collect());
        assert_eq!(
            parsed.len(),
            MAINNET_BOOTNODES.len(),
            "a bootnode ENR failed to parse; parse_enrs warns per skipped entry"
        );
    }

    /// The state we ship is eth-clients', unmodified.
    ///
    /// Every mainnet value below is read out of this file, so replacing it
    /// silently would repoint the node at a different chain while every other
    /// test still passed. Re-derive with:
    ///
    /// ```text
    /// shasum -a 256 bin/ethlambda/assets/mainnet/genesis.ssz
    /// ```
    #[test]
    fn the_shipped_state_is_eth_clients_file() {
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(MAINNET_GENESIS_SSZ);
        assert_eq!(
            hex::encode(digest),
            "bbdf6fa5ffd6ead8ca6714c60a17d14d48ccaabbb18622b8485f88b58633d620"
        );
    }

    /// The state decodes, and is the one mainnet started from.
    ///
    /// This is what replaced the `/eth/v1/beacon/genesis` fetch, so it is the
    /// test that says the replacement carries the same two values the endpoint
    /// used to return.
    #[test]
    fn the_built_in_state_is_mainnets_genesis() {
        let state = mainnet_genesis_state().expect("the built-in archive decodes");
        assert_eq!(state.fork_name(), ForkName::Phase0);
        // Genesis, not a later anchor: slot 0, and `genesis_validators_root`
        // already populated, which is what makes the field readable here.
        assert_eq!(state.slot(), 0);
        assert_eq!(state.genesis_time(), MAINNET_GENESIS_TIME);
        assert_eq!(state.genesis_validators_root(), mainnet_gvr());

        let genesis = mainnet_genesis().expect("the pair is read off that state");
        assert_eq!(genesis.genesis_time, MAINNET_GENESIS_TIME);
        assert_eq!(genesis.genesis_validators_root, mainnet_gvr());
    }

    /// The fast path in [`BeaconState::slot_from_ssz`] reads a byte offset
    /// rather than the container, so pin it against a genuine encoded mainnet
    /// state. The slot is moved off zero first: at zero an offset landing in
    /// the `fork` field that follows would read zero too and pass.
    #[test]
    fn the_state_slot_offset_matches_a_real_encoded_state() {
        let mut state = mainnet_genesis_state().expect("the built-in archive decodes");
        *state.slot_mut() = 12_345;

        let bytes = state.to_ssz();

        assert_eq!(BeaconState::slot_from_ssz(&bytes).unwrap(), 12_345);
    }

    /// Startup derives every wire parameter without touching the network.
    ///
    /// The point of the change: this used to require a reachable Beacon API, so
    /// a test could not call it at all.
    #[test]
    fn the_wire_parameters_are_derived_offline() {
        let source = crate::network::NetworkSource::built_in_mainnet().unwrap();
        let params = wire_params(&source, [0x11; 32], true, CUSTODY_REQUIREMENT)
            .expect("no network is needed");
        assert_eq!(params.wire.genesis_time, MAINNET_GENESIS_TIME);
        // The digest is whatever fork the wall clock lands in, so it is not
        // pinned here; that it agrees with the ENR entry is the invariant.
        assert_eq!(params.wire.fork_digest, params.fork_id.fork_digest);
    }

    /// Two node ids sampling the same size select different columns: this is
    /// what makes the network's total custody wide rather than every node
    /// serving the same slice.
    #[test]
    fn the_custody_columns_are_a_function_of_the_node_id() {
        let sampling = ethlambda_state_transition::beacon::das::sampling_size(
            ethlambda_types::beacon::constants::CUSTODY_REQUIREMENT,
        );

        let source = crate::network::NetworkSource::built_in_mainnet().unwrap();

        let a = wire_params(&source, [0x11; 32], true, CUSTODY_REQUIREMENT)
            .expect("no network is needed");
        assert_eq!(a.wire.custody_columns.len(), sampling as usize);

        let b = wire_params(&source, [0x22; 32], true, CUSTODY_REQUIREMENT)
            .expect("no network is needed");
        assert_ne!(a.wire.custody_columns, b.wire.custody_columns);
    }

    /// `run_node` cannot be driven from a test, but its two-line composition
    /// (resolve the key, derive the id, feed it to `wire_params`) can be, via
    /// `beacon_node_id`.
    #[test]
    fn beacon_node_id_feeds_wire_params_a_valid_identity() {
        let node_id = beacon_node_id(&[0x33; 32]).expect("a well-formed key");
        let source = crate::network::NetworkSource::built_in_mainnet().unwrap();
        let params =
            wire_params(&source, node_id, true, CUSTODY_REQUIREMENT).expect("no network is needed");
        let sampling = ethlambda_state_transition::beacon::das::sampling_size(
            ethlambda_types::beacon::constants::CUSTODY_REQUIREMENT,
        );
        assert_eq!(params.wire.custody_columns.len(), sampling as usize);
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

    #[test]
    fn the_built_in_network_derives_what_it_always_did() {
        // The regression that matters: mainnet's wire parameters must not move
        // when they start coming through NetworkSource.
        let source = crate::network::NetworkSource::built_in_mainnet().unwrap();
        let genesis = source.genesis();
        assert_eq!(genesis.genesis_time, 1_606_824_023);
        assert_eq!(source.config().seconds_per_slot, 12);
        assert_eq!(source.bootnodes().len(), MAINNET_BOOTNODES.len());
    }

    #[test]
    fn a_loaded_directory_supplies_its_own_config() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::copy(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/networks/devnet/config.yaml"),
            dir.path().join("config.yaml"),
        )
        .unwrap();
        let state = mainnet_genesis_state().unwrap();
        std::fs::write(dir.path().join("genesis.ssz"), state.to_ssz()).unwrap();

        let loaded = crate::network::dir::NetworkDir::load(dir.path()).unwrap();
        let source = crate::network::NetworkSource::Loaded(Box::new(loaded));
        assert_eq!(source.config().seconds_per_slot, 6);
        assert_eq!(source.config().deposit_chain_id, 3_151_908);
        // The genesis state written above is mainnet's, so this is its time.
        assert_eq!(source.genesis().genesis_time, 1_606_824_023);
    }
}
