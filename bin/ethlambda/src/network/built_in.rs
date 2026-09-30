//! The networks compiled into the binary, by the name `--network` accepts.
//!
//! Every built-in chain is an [`EmbeddedChain`]: its publisher's
//! `metadata/config.yaml` and `metadata/bootstrap_nodes.yaml` byte for byte,
//! read through the same parsers a `--network <dir>` goes through, plus its two
//! genesis values. The publisher is the chain's `eth-clients` repo, or for a
//! devnet the ethpandaops repo that runs it. Refreshing a chain is a file copy
//! that can be diffed against upstream.
//!
//! No chain carries its genesis *state*, only the two values the wire is
//! derived from (`genesis_time`, `genesis_validators_root`). A built-in network
//! never anchors at genesis (`fetch_initial_beacon_state` refuses, since every
//! one of them is a live chain and this follower would sit at slot 0), so those
//! two values are all the state would be read for; mainnet's is 5 MB,
//! Platåberget's 14 MB and Hoodi's 150 MB. A wrong constant still fails loudly
//! rather than silently: the anchor state checkpoint sync downloads is checked
//! against both, and so is a resumed data directory's.

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::primitives::Root;
use eyre::WrapErr as _;

use super::config_file::ConfigFile;
use crate::beacon::Genesis;

/// A network compiled into the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BuiltInNetwork {
    Mainnet,
    Sepolia,
    Hoodi,
    Plataberget,
}

impl BuiltInNetwork {
    /// Every built-in network, in the order an unknown-name error lists them.
    pub(crate) const ALL: [Self; 4] =
        [Self::Mainnet, Self::Sepolia, Self::Hoodi, Self::Plataberget];

    /// The name `--network` accepts for this network.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Sepolia => "sepolia",
            Self::Hoodi => "hoodi",
            Self::Plataberget => "plataberget",
        }
    }

    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|network| network.name() == name)
    }

    fn chain(self) -> &'static EmbeddedChain {
        match self {
            Self::Mainnet => &MAINNET,
            Self::Sepolia => &SEPOLIA,
            Self::Hoodi => &HOODI,
            Self::Plataberget => &PLATABERGET,
        }
    }

    /// Build this network's configuration, genesis values and bootnode list.
    pub(crate) fn resolve(self) -> eyre::Result<BuiltIn> {
        let chain = self.chain();
        let parsed = ConfigFile::parse(chain.config_yaml)
            .wrap_err_with(|| format!("the built-in {} config.yaml did not parse", self.name()))?;
        super::check_preset(parsed.config.preset_base.as_str())?;
        super::check_constants(&parsed.config)?;
        // A built-in config can carry a fork whose *keys* this build claims
        // but whose state transition it does not implement yet (gloas), or
        // one whose keys it does not even claim (heze). The ignored-keys
        // warning below only ever said the second half of that; it used to
        // say both, back when GLOAS_* were unclaimed too. `warn_if_unfollowed_fork_scheduled`
        // says the first half explicitly instead of leaving it to be
        // discovered as a stall.
        parsed.warn_about_ignored_keys();

        let genesis = chain.genesis();
        let mut config = parsed.config;
        super::derive_genesis_fields(&mut config, genesis.genesis_time);
        // The name is the one value taken from `--network` rather than the
        // file. Platåberget's file says `testnet`, a placeholder ethpandaops
        // devnets carry for Prysm's sake, and a node told `--network
        // plataberget` should log and report that name. The `eth-clients`
        // files already carry their own, so for them this changes nothing.
        config.config_name = self
            .name()
            .try_into()
            .expect("a built-in network's name fits a ConfigName");
        super::warn_if_unfollowed_fork_scheduled(self.name(), &config);

        Ok(BuiltIn {
            config,
            genesis,
            bootnodes: crate::parse_bootnode_strings(chain.bootnodes_yaml),
        })
    }
}

/// A resolved built-in network: what [`super::NetworkSource`] answers from.
#[derive(Debug)]
pub(crate) struct BuiltIn {
    pub(crate) config: Config,
    pub(crate) genesis: Genesis,
    pub(crate) bootnodes: Vec<String>,
}

/// A built-in chain's embedded files and genesis values.
struct EmbeddedChain {
    /// `metadata/config.yaml` from the chain's publisher.
    config_yaml: &'static str,
    /// `metadata/bootstrap_nodes.yaml` from the chain's publisher.
    bootnodes_yaml: &'static str,
    genesis_time: u64,
    /// Hex, without a `0x` prefix.
    genesis_validators_root: &'static str,
}

impl EmbeddedChain {
    fn genesis(&self) -> Genesis {
        let root = hex::decode(self.genesis_validators_root)
            .expect("a built-in genesis_validators_root is valid hex");
        Genesis {
            genesis_time: self.genesis_time,
            genesis_validators_root: Root::from_slice(&root),
        }
    }
}

/// Ethereum mainnet, from `eth-clients/mainnet`.
///
/// Both genesis values are read off that repo's `metadata/genesis.ssz`, which
/// the tests carry as a fixture and check these against.
const MAINNET: EmbeddedChain = EmbeddedChain {
    config_yaml: include_str!("../../assets/mainnet/config.yaml"),
    bootnodes_yaml: include_str!("../../assets/mainnet/bootstrap_nodes.yaml"),
    // 2020-12-01 12:00:23 UTC.
    genesis_time: 1_606_824_023,
    genesis_validators_root: "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
};

/// Sepolia, from `eth-clients/sepolia`.
///
/// Both genesis values are the ones `eth-clients/sepolia`'s README publishes
/// and a Sepolia Beacon API's `/eth/v1/beacon/genesis` returns.
const SEPOLIA: EmbeddedChain = EmbeddedChain {
    config_yaml: include_str!("../../assets/sepolia/config.yaml"),
    bootnodes_yaml: include_str!("../../assets/sepolia/bootstrap_nodes.yaml"),
    // 2022-06-20 14:00:00 UTC.
    genesis_time: 1_655_733_600,
    genesis_validators_root: "d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078",
};

/// Hoodi, from `eth-clients/hoodi`.
///
/// The root is `metadata/genesis_validators_root.txt` from that repo; both
/// values are what a Hoodi Beacon API's `/eth/v1/beacon/genesis` returns.
const HOODI: EmbeddedChain = EmbeddedChain {
    config_yaml: include_str!("../../assets/hoodi/config.yaml"),
    bootnodes_yaml: include_str!("../../assets/hoodi/bootstrap_nodes.yaml"),
    // 2025-03-17 12:10:00 UTC.
    genesis_time: 1_742_213_400,
    genesis_validators_root: "212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f",
};

/// Platåberget, the long-lived Glamsterdam testnet, from
/// `ethpandaops/glamsterdam-devnets`' `network-configs/devnet-8` (Platåberget
/// is glamsterdam-devnet-8 under its public name).
///
/// Both values are read off that directory's `metadata/genesis.ssz`, agree with
/// its `genesis_validators_root.txt`, and are what
/// `checkpoint-sync.plataberget.ethpandaops.io/eth/v1/beacon/genesis` returns.
/// The chain started at fulu and has run gloas since its `GLOAS_FORK_EPOCH`,
/// a fork the live follower does not take blocks or an anchor from yet.
const PLATABERGET: EmbeddedChain = EmbeddedChain {
    config_yaml: include_str!("../../assets/plataberget/config.yaml"),
    bootnodes_yaml: include_str!("../../assets/plataberget/bootstrap_nodes.yaml"),
    // 2026-08-13 12:00:00 UTC.
    genesis_time: 1_786_622_400,
    genesis_validators_root: "bb4a1a9e3f7f4e10edcd734e4acc3b5ffd4f830efe0af2748fa458cfee5d2658",
};

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_p2p::parse_enrs;
    use ethlambda_types::beacon::fork::ForkName;
    use ethlambda_types::beacon::fork_digest::compute_fork_digest;

    #[test]
    fn every_name_round_trips() {
        for network in BuiltInNetwork::ALL {
            assert_eq!(BuiltInNetwork::from_name(network.name()), Some(network));
        }
        assert_eq!(BuiltInNetwork::from_name("holesky"), None);
    }

    #[test]
    fn every_built_in_network_resolves() {
        for network in BuiltInNetwork::ALL {
            let resolved = network
                .resolve()
                .unwrap_or_else(|err| panic!("{} did not resolve: {err:#}", network.name()));
            // `--network <name>` and the `CONFIG_NAME` the node logs and
            // reports must be the same name.
            assert_eq!(resolved.config.config_name.as_str(), network.name());
            assert_eq!(
                resolved.config.genesis_time,
                resolved.genesis.genesis_time,
                "{}: the config's clock must start at the network's genesis",
                network.name()
            );
            assert_eq!(
                resolved.config.slot_duration_ms,
                resolved.config.seconds_per_slot * 1_000,
                "{}",
                network.name()
            );
        }
    }

    #[test]
    fn every_embedded_bootnode_parses() {
        for network in BuiltInNetwork::ALL {
            let bootnodes = network.resolve().unwrap().bootnodes;
            assert!(
                !bootnodes.is_empty(),
                "{} ships no bootnodes",
                network.name()
            );
            assert_eq!(
                parse_enrs(bootnodes.clone()).len(),
                bootnodes.len(),
                "a {} bootnode ENR failed to parse; parse_enrs warns per skipped entry",
                network.name()
            );
        }
    }

    /// The configs are read from the files, not defaulted to mainnet's
    /// values: an absent key falls back to mainnet silently, so a file that
    /// failed to reach the parser would still "resolve". Mainnet's own config
    /// cannot be told apart from that fallback by value; it is pinned against
    /// `Config::mainnet()` instead (`beacon::tests`).
    #[test]
    fn the_testnet_configs_are_their_own() {
        let sepolia = BuiltInNetwork::Sepolia.resolve().unwrap().config;
        assert_eq!(sepolia.genesis_fork_version, [0x90, 0x00, 0x00, 0x69]);
        assert_eq!(sepolia.fulu_fork_version, [0x90, 0x00, 0x00, 0x75]);
        assert_eq!(sepolia.fulu_fork_epoch, 272_640);
        assert_eq!(sepolia.deposit_chain_id, 11_155_111);

        let hoodi = BuiltInNetwork::Hoodi.resolve().unwrap().config;
        assert_eq!(hoodi.genesis_fork_version, [0x10, 0x00, 0x09, 0x10]);
        assert_eq!(hoodi.fork_at_epoch(0), ForkName::Deneb);
        assert_eq!(hoodi.fulu_fork_version, [0x70, 0x00, 0x09, 0x10]);
        assert_eq!(hoodi.fulu_fork_epoch, 50_688);
        assert_eq!(hoodi.deposit_chain_id, 560_048);

        let plataberget = BuiltInNetwork::Plataberget.resolve().unwrap().config;
        assert_eq!(plataberget.genesis_fork_version, [0x10, 0x73, 0x31, 0x83]);
        assert_eq!(plataberget.fork_at_epoch(0), ForkName::Fulu);
        assert_eq!(plataberget.fulu_fork_version, [0x70, 0x73, 0x31, 0x83]);
        assert_eq!(plataberget.gloas_fork_version, [0x80, 0x73, 0x31, 0x83]);
        assert_eq!(plataberget.gloas_fork_epoch, 1_536);
        assert_eq!(plataberget.deposit_chain_id, 7_091_047_534);
    }

    /// Platåberget's file names the chain `testnet`, so its `CONFIG_NAME`
    /// comes from `--network` instead; this pins why `resolve` overrides it.
    #[test]
    fn plataberget_is_named_for_its_flag_rather_than_its_file() {
        let parsed = ConfigFile::parse(PLATABERGET.config_yaml).unwrap();
        assert_eq!(parsed.config.config_name.as_str(), "testnet");

        let resolved = BuiltInNetwork::Plataberget.resolve().unwrap();
        assert_eq!(resolved.config.config_name.as_str(), "plataberget");
    }

    /// Sepolia's, Hoodi's and Platåberget's genesis roots have no other
    /// offline check, since the state each is the root of is not carried even
    /// as a test fixture (mainnet's is, and `beacon::tests` checks mainnet's
    /// constants against it). What pins them is a digest someone else computed
    /// from it: each expected value below is the `eth2` entry of a bootnode
    /// ENR in the network's own `bootstrap_nodes.yaml`, published while that
    /// fork was current. The digest mixes the fork version with the root, so
    /// a wrong root or a wrong fork version fails here.
    #[test]
    fn the_genesis_roots_reproduce_published_digests() {
        // Sepolia's last listed bootnode, signed during bellatrix, before
        // capella was scheduled: its `next_fork_version` repeats bellatrix's
        // own and its `next_fork_epoch` is FAR_FUTURE_EPOCH.
        let sepolia = BuiltInNetwork::Sepolia.resolve().unwrap();
        let bellatrix = sepolia.config.bellatrix_fork_epoch;
        assert_eq!(
            compute_fork_digest(
                &sepolia.config,
                sepolia.genesis.genesis_validators_root,
                bellatrix
            ),
            [0x36, 0xfa, 0x50, 0x13]
        );

        // Hoodi's two Teku bootnodes, signed at genesis, which was deneb.
        let hoodi = BuiltInNetwork::Hoodi.resolve().unwrap();
        assert_eq!(
            compute_fork_digest(&hoodi.config, hoodi.genesis.genesis_validators_root, 0),
            [0xd2, 0xf1, 0x99, 0x7f]
        );

        // Platåberget's bootnodes come from both sides of its gloas fork.
        // Those signed before it name gloas as their next fork, at its
        // `GLOAS_FORK_EPOCH`; genesis was fulu, so the digest also mixes in
        // the blob schedule's first entry. Those signed after it repeat
        // gloas's version with FAR_FUTURE_EPOCH, so they pin the gloas fork
        // version as well.
        let plataberget = BuiltInNetwork::Plataberget.resolve().unwrap();
        let root = plataberget.genesis.genesis_validators_root;
        assert_eq!(
            compute_fork_digest(&plataberget.config, root, 0),
            [0x5c, 0x94, 0x38, 0x07]
        );
        let gloas = plataberget.config.gloas_fork_epoch;
        assert_eq!(
            compute_fork_digest(&plataberget.config, root, gloas),
            [0x98, 0xc9, 0x10, 0xcf]
        );
    }

    /// Sepolia's README publishes its genesis digest directly.
    #[test]
    fn sepolias_genesis_digest_is_the_published_one() {
        let sepolia = BuiltInNetwork::Sepolia.resolve().unwrap();
        assert_eq!(
            compute_fork_digest(&sepolia.config, sepolia.genesis.genesis_validators_root, 0),
            [0xa8, 0xfe, 0xe8, 0xee]
        );
    }
}
