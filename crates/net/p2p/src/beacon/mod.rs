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

pub mod decode;
pub mod encoding;
pub mod handler;
pub mod messages;
pub mod protocols;
pub mod swarm;
pub mod topics;
pub mod verdict;

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::primitives::{ForkDigest, Root};

/// Everything the beacon wire needs after startup has computed it.
///
/// `config` and `genesis_time` are carried rather than looked up because the
/// fork a gossip payload decodes under is derived from its slot, and that
/// derivation must use the same schedule the fork digest was computed from.
pub struct BeaconWire {
    pub fork_digest: ForkDigest,
    pub topics: topics::BeaconTopics,
    pub config: Config,
    pub genesis_time: u64,
    /// The chain every fork digest is bound to.
    ///
    /// Carried alongside `fork_digest`, which is only the *current* one:
    /// a block response labels each chunk with the digest of that block's own
    /// epoch, so serving history means computing digests this node never runs
    /// on. See [`encoding`]'s module docs for the rule.
    pub genesis_validators_root: Root,
    /// Advertised in `Ping` responses and in `MetaData`. Never bumped today:
    /// nothing this node advertises changes at runtime.
    pub metadata_seq_number: u64,
    /// The columns this node custodies, carried alongside `topics` so the
    /// gossip handler and the request handlers can check what this node
    /// promises to serve without recomputing it from the node id.
    pub custody_columns: Vec<u64>,
}

impl BeaconWire {
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
/// `ethlambda_types::beacon::config` deliberately carries no networking values
/// (see its module doc), so the two subnet counts below live with the code
/// that reads them. `CUSTODY_REQUIREMENT` is the exception: das-core defines
/// it because non-networking code (the future availability check) needs it
/// too, so it lives in the types crate and is only re-exported here.
pub mod constants {
    /// `ATTESTATION_SUBNET_COUNT`. The `attnets` bitfield is this wide even
    /// though this node subscribes to none of them.
    pub const ATTESTATION_SUBNET_COUNT: u64 = 64;

    /// `SYNC_COMMITTEE_SUBNET_COUNT`. The width of `MetaData`'s `syncnets`.
    pub const SYNC_COMMITTEE_SUBNET_COUNT: usize = 4;

    /// Re-exported rather than redefined: the subnet subscription, the `cgc`
    /// ENR entry, the `MetaDataV3` field and the availability check must all
    /// name one value, and das-core is where it is defined.
    pub use ethlambda_types::beacon::constants::CUSTODY_REQUIREMENT;
}
