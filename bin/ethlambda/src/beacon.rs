//! `ethlambda beacon`: the wire parameters derived from a resolved network.
//!
//! What a network *is* (its config, genesis values and bootnodes) lives in
//! `crate::network`: a built-in chain's embedded files, or a directory on
//! disk. This module derives what a node needs before it can put itself on the
//! wire, the same way for every network. The order matters, because the fork
//! digest depends on the epoch, which depends on genesis time:
//!
//! ```text
//! genesis_validators_root, genesis_time          (crate::network::NetworkSource::genesis)
//!   └─► epoch = (now - genesis_time) / (seconds_per_slot * SLOTS_PER_EPOCH)
//!       └─► fork_digest = compute_fork_digest(config, gvr, epoch)
//!           └─► gossip topics, ENR eth2 entry, discv5 admission
//! ```
//!
//! `crate::run_node` builds the swarm, for both chains, from what
//! [`wire_params`] returns.
//!
//! The two genesis values used to come from a Beacon API's
//! `/eth/v1/beacon/genesis`, which made `--checkpoint-sync-url` mandatory on
//! `beacon` and made startup fail whenever every configured provider was down.
//! They are properties of the chain, not of a provider, so they are now carried
//! by the network itself and `beacon` boots with no network configuration at
//! all. `node`'s checkpoint sync is untouched: a lean node fetches a
//! *finalized* anchor, which genuinely has no local source.

use ethlambda_p2p::beacon::fork_schedule::ForkSchedule;
use ethlambda_p2p::beacon::swarm::BeaconWireConfig;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::BeaconState;
use ethlambda_types::beacon::preset;
use ethlambda_types::beacon::primitives::{Epoch, Root};
use ethlambda_types::enr::EnrForkId;
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

/// The `eth2` ENR entry for this chain at this epoch, from the same schedule
/// the running node follows, so the record it starts with and the one it would
/// switch to name the same boundaries.
pub fn enr_fork_id(config: &Config, genesis_validators_root: Root, epoch: Epoch) -> EnrForkId {
    ForkSchedule::new(config, genesis_validators_root).enr_fork_id(epoch)
}

/// Ethereum mainnet's genesis `BeaconState`, SSZ-encoded: a test fixture.
///
/// This is `metadata/genesis.ssz` from `eth-clients/mainnet` byte for byte;
/// [`the_fixture_state_is_eth_clients_file`] pins its SHA-256. The binary does
/// not carry it: a built-in network never anchors at genesis, so the node
/// needs only the two values `crate::network::built_in` holds as constants.
/// Tests keep it because it is a real phase0 state, which is what every test
/// that builds a network directory, upgrades a state through the forks or
/// checks those constants needs.
#[cfg(test)]
static MAINNET_GENESIS_SSZ: &[u8] =
    include_bytes!("../tests/fixtures/networks/mainnet/genesis.ssz");

/// The two genesis fields the fork digest is derived from.
#[derive(Debug, Clone, Copy)]
pub struct Genesis {
    pub genesis_time: u64,
    pub genesis_validators_root: Root,
}

impl Genesis {
    /// Read the pair off a genesis state.
    pub fn of(state: &BeaconState) -> Self {
        Self {
            genesis_time: state.genesis_time(),
            genesis_validators_root: state.genesis_validators_root(),
        }
    }
}

/// Decode the mainnet genesis fixture.
///
/// The fork is `Phase0` because this is *genesis*, not the current head: the
/// state predates altair by definition, whatever fork the chain is on now.
/// A build with `ethlambda-types/preset-minimal` on fails here: the minimal
/// preset shortens the state's fixed-size vectors, so mainnet's encoding no
/// longer fits the container.
#[cfg(test)]
pub fn mainnet_genesis_state() -> eyre::Result<BeaconState> {
    use ethlambda_types::beacon::fork::ForkName;
    use eyre::WrapErr as _;

    BeaconState::from_ssz(ForkName::Phase0, MAINNET_GENESIS_SSZ)
        .wrap_err("the mainnet genesis fixture did not decode as a phase0 BeaconState")
}

/// The genesis pair read off the mainnet fixture, for the checkpoint-sync
/// tests that only want these two fields rather than a whole `NetworkSource`.
#[cfg(test)]
pub fn mainnet_genesis() -> eyre::Result<Genesis> {
    Ok(Genesis::of(&mainnet_genesis_state()?))
}

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
/// touches no network: every value here is a function of `source` (a built-in
/// network or a loaded directory), the wall clock, and `node_id`, which the
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

    // The digest moves at every fork and blob-schedule boundary, and the p2p
    // actor follows it without a restart (`ethlambda_p2p::beacon::transition`):
    // the next digest's topics are joined ahead of the boundary, the switch
    // happens at it, and the old topics are left after it, per
    // `SUBSCRIBE_LEAD_EPOCHS` and `UNSUBSCRIBE_LAG_EPOCHS`. Say what is coming.
    //
    // A fork the node does not follow keeps its own warning: crossing its
    // digest works like any other, but the node stops tracking the chain
    // there regardless. No fork is in that state today, since gloas is
    // followed, so the warning is the guard for the next one.
    let schedule = ForkSchedule::new(&chain, genesis.genesis_validators_root);
    match schedule.next_boundary_after(epoch) {
        Some(next) if !next.fork.is_followed() => warn!(
            boundary_epoch = next.activation_epoch,
            boundary_unix_time = time_at_epoch(&chain, genesis.genesis_time, next.activation_epoch),
            fork = next.fork.as_str(),
            fork_digest = %hex::encode(next.digest),
            "The fork digest changes at this boundary and the node will switch topics, but this \
             build cannot follow the fork itself"
        ),
        Some(next) => info!(
            boundary_epoch = next.activation_epoch,
            boundary_unix_time = time_at_epoch(&chain, genesis.genesis_time, next.activation_epoch),
            fork = next.fork.as_str(),
            fork_digest = %hex::encode(next.digest),
            "The fork digest changes at this boundary; the node will cross it without a restart"
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

    // The same node id again, and the same consequence of an ephemeral one:
    // `p2p-interface.md` makes this a public function of the node id so that a
    // peer can compute what this node should be listening to from its ENR
    // alone. Computed at the current epoch and then kept for the process's
    // lifetime; see `subnets`'s module documentation for why this does not
    // rotate.
    let attestation_subnets =
        ethlambda_p2p::beacon::subnets::compute_subscribed_subnets(node_id, epoch, &chain)
            .map_err(|err| eyre::eyre!("computing the attestation subnet backbone: {err:?}"))?;
    info!(
        subnets_per_node = chain.subnets_per_node,
        subnets = ?attestation_subnets,
        "Backboning attestation subnets"
    );

    // Say plainly what is still advertised without being backed by behavior,
    // so a running node never implies more than it does. Storing and serving
    // the custodied columns logged above is no longer in that gap, and neither
    // is the attestation subnet backbone; sync committee subnet subscription,
    // and publishing, still are.
    warn!(
        "Advertising cgc={custody_group_count} while subscribing to no sync committee \
         subnet, and publishing nothing"
    );

    Ok(BeaconWireParams {
        wire: BeaconWireConfig {
            fork_digest: fork_id.fork_digest,
            fork,
            config: chain,
            genesis_time: genesis.genesis_time,
            genesis_validators_root: genesis.genesis_validators_root,
            custody_columns,
            attestation_subnets,
        },
        fork_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::constants::{CUSTODY_REQUIREMENT, FAR_FUTURE_EPOCH};
    use ethlambda_types::beacon::fork::ForkName;

    /// Mainnet's genesis, 2020-12-01 12:00:23 UTC.
    const MAINNET_GENESIS_TIME: u64 = 1_606_824_023;

    fn mainnet_gvr() -> Root {
        Root::from_slice(
            &hex::decode("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
                .expect("valid hex"),
        )
    }

    /// The fixture is eth-clients' state, unmodified.
    ///
    /// Every mainnet value below is read out of this file, and so is the check
    /// on the built-in mainnet constants, so replacing it silently would make
    /// those tests agree with the wrong chain. Re-derive with:
    ///
    /// ```text
    /// shasum -a 256 bin/ethlambda/tests/fixtures/networks/mainnet/genesis.ssz
    /// ```
    #[test]
    fn the_fixture_state_is_eth_clients_file() {
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(MAINNET_GENESIS_SSZ);
        assert_eq!(
            hex::encode(digest),
            "bbdf6fa5ffd6ead8ca6714c60a17d14d48ccaabbb18622b8485f88b58633d620"
        );
    }

    /// The fixture decodes, and is the state mainnet started from.
    #[test]
    fn the_fixture_is_mainnets_genesis() {
        let state = mainnet_genesis_state().expect("the fixture decodes");
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
        let mut state = mainnet_genesis_state().expect("the fixture decodes");
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
        // Mainnet's wall clock is past fulu and no later fork is defined, so
        // fulu is the only fork the wire can name.
        assert_eq!(params.wire.fork, ForkName::Fulu);
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

    /// The regression that matters: mainnet's wire parameters must not move
    /// now that its config comes from the embedded `config.yaml` and its
    /// genesis values from constants, instead of from `Config::mainnet()` and
    /// a decoded genesis state.
    #[test]
    fn the_built_in_network_derives_what_it_always_did() {
        let source = crate::network::NetworkSource::built_in_mainnet().unwrap();
        assert_eq!(source.config(), &Config::mainnet());

        let genesis = source.genesis();
        let fixture = mainnet_genesis().unwrap();
        assert_eq!(genesis.genesis_time, fixture.genesis_time);
        assert_eq!(
            genesis.genesis_validators_root,
            fixture.genesis_validators_root
        );
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
