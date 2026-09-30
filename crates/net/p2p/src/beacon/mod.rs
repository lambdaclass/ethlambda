//! Ethereum mainnet's wire: topic names, req/resp protocol ids, ENR entries,
//! and fork-aware decode.
//!
//! Not the bootnode list: that is operator-facing configuration rather than
//! wire format, and lives with mainnet's genesis in the binary's `beacon`
//! module.
//!
//! Nothing here is shared with lean. What *is* shared is one layer down: the
//! discv5 stack in [`crate::discovery`], the `ssz_snappy` framing and the
//! chunk-per-item response loop in [`crate::req_resp::encoding`], and
//! `compute_message_id` in [`crate`], all of which are the beacon spec's to
//! begin with. Both chains serve blocks as a chunk per block, so that loop is
//! written once and handed the two things the chains disagree about: how wide
//! the `<context-bytes>` field is, and how a chunk body becomes a block.

pub mod column_checks;
pub mod decode;
pub mod encoding;
pub mod fork_schedule;
pub mod handler;
pub mod messages;
pub mod protocols;
pub mod subnets;
pub mod swarm;
pub mod topics;
pub mod transition;
pub mod verdict;

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{ForkDigest, Root};

/// Everything the beacon wire needs after startup has computed it.
///
/// `config` and `genesis_time` are carried rather than looked up because the
/// fork a gossip payload decodes under is derived from its slot, and that
/// derivation must use the same schedule the fork digest was computed from.
pub struct BeaconWire {
    /// The digest this node publishes under and advertises in `Status`. Moves
    /// at each boundary of [`Self::schedule`]; see [`transition`].
    pub fork_digest: ForkDigest,
    /// The fork `fork_digest` was computed at.
    ///
    /// What a message published now is in. A received message's fork comes from
    /// its own topic's digest through [`Self::schedule`] instead, since while a
    /// boundary's window is open this node is subscribed under two digests.
    pub fork: ForkName,
    /// Every digest the chain will use, and when to join and leave each.
    pub schedule: fork_schedule::ForkSchedule,
    /// The topics under `fork_digest`.
    pub topics: topics::BeaconTopics,
    /// The topics of every other digest the subscription window holds: the
    /// next one from an epoch ahead of its boundary, the previous one until two
    /// epochs after. Empty outside a window.
    pub window_topics: Vec<topics::BeaconTopics>,
    pub config: Config,
    pub genesis_time: u64,
    /// The chain every fork digest is bound to.
    ///
    /// Carried alongside `fork_digest`, which is only the *current* one:
    /// a block response labels each chunk with the digest of that block's own
    /// epoch, so serving history means computing digests this node never runs
    /// on. See [`encoding`]'s module docs for the rule.
    pub genesis_validators_root: Root,
    /// Advertised in `Ping` responses and in `MetaData`. Bumped when the
    /// digest switches, the one advertised value that changes at runtime.
    pub metadata_seq_number: u64,
    /// The columns this node custodies, carried alongside `topics` so the
    /// gossip handler and the request handlers can check what this node
    /// promises to serve without recomputing it from the node id.
    pub custody_columns: Vec<u64>,
    /// The attestation subnets this node backbones, from the same node id.
    ///
    /// Read by `build_metadata` for the `attnets` bitfield it advertises, so
    /// what this node claims to serve is what it actually subscribed to.
    pub attestation_subnets: Vec<u64>,
}

impl BeaconWire {
    /// Every topic set this node is subscribed to: the current digest's, then
    /// the window's.
    pub fn held_topics(&self) -> impl Iterator<Item = &topics::BeaconTopics> {
        std::iter::once(&self.topics).chain(self.window_topics.iter())
    }

    /// Whether this node is subscribed under `digest`, so whether a peer on it
    /// is on a digest this node still speaks.
    pub fn holds_digest(&self, digest: ForkDigest) -> bool {
        self.held_topics()
            .any(|topics| topics.fork_digest == digest)
    }

    /// The two values the codec needs to put a block chunk on or off the wire.
    pub fn codec_context(&self) -> BeaconContext {
        BeaconContext {
            config: self.config.clone(),
            genesis_validators_root: self.genesis_validators_root,
        }
    }
}

/// The beacon chain's identity, as the request/response codec needs it.
///
/// A block chunk's `<context-bytes>` are a function of the block's slot, the
/// fork schedule and the chain, so the codec cannot compute them from the
/// payload alone the way it can for every other beacon protocol. `P2PServer`
/// holds the same two values on its [`BeaconWire`], but the codec runs below
/// the actor and never sees it, so it is handed its own copy at
/// [`crate::build_swarm`] time. Lean's half of the codec needs nothing, which is
/// why this is an `Option` there rather than a second codec type.
#[derive(Debug, Clone)]
pub struct BeaconContext {
    pub config: Config,
    pub genesis_validators_root: Root,
}

/// Beacon-chain networking constants.
///
/// `ethlambda_types::beacon::config::Config` carries the networking values a
/// `config.yaml` sets, but this crate runs on compile-time constants instead,
/// because some of them size a type (the `attnets` bitfield). Startup refuses a
/// network whose `Config` disagrees with any of them, so the two never differ
/// on a running node and `/eth/v1/config/spec` can report the `Config`'s.
///
/// `ATTESTATION_SUBNET_COUNT` lives here, with the code that reads it. The
/// other two are re-exported from the types crate because something outside
/// networking reads them too: `CUSTODY_REQUIREMENT` the availability check,
/// `SYNC_COMMITTEE_SUBNET_COUNT` the sync subcommittee container and
/// `/eth/v1/config/spec`.
pub mod constants {
    /// `ATTESTATION_SUBNET_COUNT`. The `attnets` bitfield is this wide even
    /// though this node subscribes to none of them.
    pub const ATTESTATION_SUBNET_COUNT: u64 = 64;

    /// The width of `MetaData`'s `syncnets`. Re-exported so the bitfield and
    /// the sync subcommittee size divide by one value.
    pub use ethlambda_types::beacon::constants::SYNC_COMMITTEE_SUBNET_COUNT;

    /// Re-exported rather than redefined: the subnet subscription, the `cgc`
    /// ENR entry, the `MetaDataV3` field and the availability check must all
    /// name one value, and das-core is where it is defined.
    pub use ethlambda_types::beacon::constants::CUSTODY_REQUIREMENT;
}
