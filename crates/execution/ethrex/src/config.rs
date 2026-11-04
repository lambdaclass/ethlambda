//! The embedded node's configuration: the `--ethrex.*` flags, and the ethrex
//! [`Options`] they resolve into.
//!
//! The flags are a deliberate subset of ethrex's own. Everything they do not
//! name keeps the value the `ethrex` binary would start with, read the way that
//! binary reads it: clap defaults, overridden by any `ETHREX_*` environment
//! variable. A flag given here wins over both. Two values are derived from the
//! beacon node instead, since ethrex's own defaults would be wrong for an
//! embedded node: the data directory (under ours) and the network (the beacon
//! chain's own).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use clap::Parser as _;
use ethrex::cli::Options;
use ethrex_config::networks::Network;
use ethrex_p2p::sync::SyncMode;
use ethrex_p2p::types::Node;

/// The beacon networks ethrex also ships a genesis for, under the same name.
const SHARED_NETWORK_NAMES: [&str; 4] = ["mainnet", "hoodi", "sepolia", "plataberget"];

/// The `--ethrex.*` flags.
///
/// Present only in a build with the `include-ethrex` feature, and read only
/// when no `--execution-endpoint` is given: an explicit endpoint means an
/// external execution client, and the embedded one does not start.
#[derive(Debug, Clone, clap::Args)]
#[command(next_help_heading = "Embedded ethrex")]
pub struct EthrexArgs {
    /// Directory for the embedded ethrex's database and node identity.
    /// Defaults to `ethrex` under `--data-dir`.
    #[arg(id = "ethrex.datadir", long = "ethrex.datadir")]
    pub datadir: Option<PathBuf>,

    /// Execution network: `mainnet`, `hoodi`, `sepolia`, `plataberget`, or a
    /// path to a `genesis.json`. Defaults to the beacon `--network`: the same
    /// name for a built-in network, or the `genesis.json` in a network
    /// directory.
    #[arg(id = "ethrex.network", long = "ethrex.network", value_parser = clap::value_parser!(Network))]
    pub network: Option<Network>,

    /// How ethrex syncs state: `snap` or `full`. Defaults to ethrex's own
    /// (`snap`).
    #[arg(id = "ethrex.syncmode", long = "ethrex.syncmode", value_parser = ethrex::utils::parse_sync_mode)]
    pub syncmode: Option<SyncMode>,

    /// TCP port for devp2p (RLPx). Defaults to ethrex's own (30303).
    #[arg(id = "ethrex.p2p-port", long = "ethrex.p2p-port")]
    pub p2p_port: Option<u16>,

    /// UDP port for execution-layer discovery (discv4 and discv5). Defaults to
    /// ethrex's own (30303).
    #[arg(id = "ethrex.discovery-port", long = "ethrex.discovery-port")]
    pub discovery_port: Option<u16>,

    /// Comma-separated enode URLs to bootstrap devp2p from, in addition to the
    /// network's own list.
    #[arg(
        id = "ethrex.bootnodes", long = "ethrex.bootnodes",
        value_delimiter = ',',
        value_parser = clap::value_parser!(Node)
    )]
    pub bootnodes: Vec<Node>,

    /// How many devp2p peers ethrex aims for. Defaults to ethrex's own.
    #[arg(id = "ethrex.target-peers", long = "ethrex.target-peers")]
    pub target_peers: Option<usize>,

    /// Address the execution JSON-RPC server (`eth_*`, `net_*`, `web3_*`)
    /// binds, when `--ethrex.http-port` turns it on.
    #[arg(id = "ethrex.http-addr", long = "ethrex.http-addr", default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
    pub http_addr: IpAddr,

    /// Port for the execution JSON-RPC server. Off unless given. The Engine
    /// API is never served on it: the beacon node calls ethrex directly.
    #[arg(id = "ethrex.http-port", long = "ethrex.http-port")]
    pub http_port: Option<u16>,

    /// Port for ethrex's own Prometheus metrics server. Off unless given.
    #[arg(id = "ethrex.metrics-port", long = "ethrex.metrics-port")]
    pub metrics_port: Option<u16>,
}

/// What the flags resolve to once the beacon node fills in the gaps.
#[derive(Debug, Clone)]
pub struct EthrexConfig {
    /// ethrex's complete option set, as the `ethrex` binary would hold it.
    pub options: Options,
    /// Where the execution JSON-RPC server listens, if anywhere.
    pub http: Option<SocketAddr>,
}

/// Why the flags could not be resolved.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading ethrex's default options: {0}")]
    Defaults(#[from] clap::Error),
    #[error(
        "the beacon network {0:?} has no execution genesis built into ethrex; \
         pass --ethrex.network with a network name or a genesis.json path"
    )]
    UnknownNetwork(String),
    #[error(
        "the network directory {0} holds no genesis.json; pass --ethrex.network \
         with the execution genesis"
    )]
    NoGenesisInDirectory(PathBuf),
}

impl EthrexArgs {
    /// Resolves the flags against the beacon node's `--data-dir` and
    /// `--network` (the raw flag value: a built-in name, or a directory).
    pub fn resolve(
        &self,
        data_dir: &Path,
        beacon_network: &str,
    ) -> Result<EthrexConfig, ConfigError> {
        let mut options = Options::try_parse_from(["ethrex"])?;

        options.datadir = self
            .datadir
            .clone()
            .unwrap_or_else(|| data_dir.join("ethrex"));
        options.network = Some(match &self.network {
            Some(network) => network.clone(),
            None => network_for_beacon(beacon_network)?,
        });
        if let Some(syncmode) = &self.syncmode {
            options.syncmode = syncmode.clone();
        }
        if let Some(port) = self.p2p_port {
            options.p2p_port = port.to_string();
        }
        if let Some(port) = self.discovery_port {
            options.discovery_port = port.to_string();
        }
        options.bootnodes.extend(self.bootnodes.iter().cloned());
        if let Some(target_peers) = self.target_peers {
            options.target_peers = target_peers;
        }
        if let Some(port) = self.metrics_port {
            options.metrics_enabled = true;
            options.metrics_port = port.to_string();
        }

        let http = self
            .http_port
            .map(|port| SocketAddr::new(self.http_addr, port));
        Ok(EthrexConfig { options, http })
    }
}

impl EthrexConfig {
    /// The ports the embedded node binds, with the flag that sets each, so the
    /// beacon node can refuse a clash before anything binds. A port option
    /// that does not parse is left out: ethrex itself refuses it at startup.
    pub fn tcp_ports(&self) -> Vec<(&'static str, u16)> {
        let mut ports = Vec::new();
        if !self.options.p2p_disabled
            && let Ok(port) = self.options.p2p_port.parse()
        {
            ports.push(("--ethrex.p2p-port", port));
        }
        if let Some(http) = self.http {
            ports.push(("--ethrex.http-port", http.port()));
        }
        if self.options.metrics_enabled
            && let Ok(port) = self.options.metrics_port.parse()
        {
            ports.push(("--ethrex.metrics-port", port));
        }
        ports
    }

    /// The UDP ports the embedded node binds; see [`Self::tcp_ports`].
    pub fn udp_ports(&self) -> Vec<(&'static str, u16)> {
        let mut ports = Vec::new();
        if !self.options.p2p_disabled
            && let Ok(port) = self.options.discovery_port.parse()
        {
            ports.push(("--ethrex.discovery-port", port));
        }
        ports
    }
}

/// The execution network matching a beacon `--network` value.
///
/// A value with a slash is a network directory, the way the beacon flag reads
/// it; the `eth-clients` layout publishes the execution genesis beside the
/// consensus files as `genesis.json`. A bare name maps only where ethrex ships
/// the same network.
fn network_for_beacon(beacon_network: &str) -> Result<Network, ConfigError> {
    if beacon_network.contains('/') {
        let genesis = Path::new(beacon_network).join("genesis.json");
        if !genesis.is_file() {
            return Err(ConfigError::NoGenesisInDirectory(PathBuf::from(
                beacon_network,
            )));
        }
        return Ok(Network::GenesisPath(genesis));
    }
    if SHARED_NETWORK_NAMES.contains(&beacon_network) {
        return Ok(Network::from(beacon_network));
    }
    Err(ConfigError::UnknownNetwork(beacon_network.to_string()))
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use ethrex_config::networks::PublicNetwork;

    use super::*;

    #[derive(Parser)]
    struct Harness {
        #[command(flatten)]
        ethrex: EthrexArgs,
    }

    fn args(flags: &[&str]) -> EthrexArgs {
        let argv = std::iter::once("ethlambda").chain(flags.iter().copied());
        Harness::try_parse_from(argv).expect("valid flags").ethrex
    }

    /// The flags are flattened into the beacon command next to its own
    /// `metrics_port`, `bootnodes` and `network`. Clap ids default to the field
    /// name, so an unprefixed id collides with those and the command refuses
    /// to build.
    #[test]
    fn every_flag_has_an_id_and_name_in_the_ethrex_namespace() {
        use clap::Args as _;

        let command = EthrexArgs::augment_args(clap::Command::new("harness"));
        for arg in command.get_arguments() {
            let id = arg.get_id().as_str();
            assert!(id.starts_with("ethrex."), "id {id:?} is not prefixed");
            assert_eq!(arg.get_long(), Some(id), "id and flag name differ");
        }
    }

    #[test]
    fn every_built_in_beacon_network_maps_to_ethrex_by_name() {
        for name in SHARED_NETWORK_NAMES {
            let network = network_for_beacon(name).expect("a shared network");
            assert_eq!(network, Network::from(name));
            assert!(matches!(network, Network::PublicNetwork(_)));
        }
    }

    #[test]
    fn a_network_directory_supplies_its_genesis_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("genesis.json"), "{}").unwrap();
        let path = format!("{}/", dir.path().display());

        let network = network_for_beacon(&path).expect("the directory's genesis");
        assert_eq!(
            network,
            Network::GenesisPath(Path::new(&path).join("genesis.json"))
        );
    }

    #[test]
    fn a_network_directory_without_genesis_json_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = format!("{}/", dir.path().display());

        let err = network_for_beacon(&path).unwrap_err();
        assert!(matches!(err, ConfigError::NoGenesisInDirectory(_)));
    }

    #[test]
    fn an_unknown_beacon_network_name_is_refused() {
        let err = network_for_beacon("holesky").unwrap_err();
        assert!(matches!(err, ConfigError::UnknownNetwork(name) if name == "holesky"));
    }

    #[test]
    fn defaults_derive_the_datadir_and_network_and_keep_ethrex_ports() {
        let config = args(&[]).resolve(Path::new("/data"), "sepolia").unwrap();

        assert_eq!(config.options.datadir, PathBuf::from("/data/ethrex"));
        assert_eq!(
            config.options.network,
            Some(Network::PublicNetwork(PublicNetwork::Sepolia))
        );
        assert_eq!(config.options.p2p_port, "30303");
        assert_eq!(config.options.discovery_port, "30303");
        assert!(!config.options.metrics_enabled);
        assert_eq!(config.http, None);
    }

    #[test]
    fn flags_override_ethrex_defaults() {
        let config = args(&[
            "--ethrex.datadir",
            "/el",
            "--ethrex.network",
            "hoodi",
            "--ethrex.syncmode",
            "full",
            "--ethrex.p2p-port",
            "30304",
            "--ethrex.discovery-port",
            "30305",
            "--ethrex.target-peers",
            "7",
            "--ethrex.http-port",
            "8545",
            "--ethrex.metrics-port",
            "9091",
        ])
        .resolve(Path::new("/data"), "sepolia")
        .unwrap();

        assert_eq!(config.options.datadir, PathBuf::from("/el"));
        assert_eq!(
            config.options.network,
            Some(Network::PublicNetwork(PublicNetwork::Hoodi))
        );
        assert_eq!(config.options.syncmode, SyncMode::Full);
        assert_eq!(config.options.p2p_port, "30304");
        assert_eq!(config.options.discovery_port, "30305");
        assert_eq!(config.options.target_peers, 7);
        assert!(config.options.metrics_enabled);
        assert_eq!(config.options.metrics_port, "9091");
        assert_eq!(config.http, Some("127.0.0.1:8545".parse().unwrap()));
        assert_eq!(
            config.tcp_ports(),
            vec![
                ("--ethrex.p2p-port", 30304),
                ("--ethrex.http-port", 8545),
                ("--ethrex.metrics-port", 9091),
            ]
        );
        assert_eq!(config.udp_ports(), vec![("--ethrex.discovery-port", 30305)]);
    }

    #[test]
    fn an_explicit_network_needs_no_beacon_mapping() {
        // A beacon network ethrex does not know resolves fine once the
        // execution network is named outright.
        let config = args(&["--ethrex.network", "mainnet"])
            .resolve(Path::new("/data"), "some-devnet")
            .unwrap();
        assert_eq!(config.options.network, Some(Network::mainnet()));
    }
}
