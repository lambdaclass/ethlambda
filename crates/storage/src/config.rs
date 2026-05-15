use ethlambda_types::block::BlockBody;
use ethlambda_types::primitives::{H256, HashTreeRoot as _};
use std::sync::LazyLock;

/// The tree hash root of an empty block body.
///
/// Used to detect genesis/anchor blocks that have no attestations,
/// allowing us to skip storing empty bodies and reconstruct them on read.
pub static EMPTY_BODY_ROOT: LazyLock<H256> =
    LazyLock::new(|| BlockBody::default().hash_tree_root());

/// Metadata key for SSZ-encoded time (u64).
pub const KEY_TIME: &[u8] = b"time";
/// Metadata key for SSZ-encoded ChainConfig.
pub const KEY_CONFIG: &[u8] = b"config";
/// Metadata key for SSZ-encoded head block root (H256).
pub const KEY_HEAD: &[u8] = b"head";
/// Metadata key for SSZ-encoded safe target block root (H256).
pub const KEY_SAFE_TARGET: &[u8] = b"safe_target";
/// Metadata key for SSZ-encoded latest justified checkpoint.
pub const KEY_LATEST_JUSTIFIED: &[u8] = b"latest_justified";
/// Metadata key for SSZ-encoded latest finalized checkpoint.
pub const KEY_LATEST_FINALIZED: &[u8] = b"latest_finalized";

/// ~1 day of block history at 4-second slots (86400 / 4 = 21600).
pub const BLOCKS_TO_KEEP: usize = 21_600;

/// ~3.3 hours of state history at 4-second slots (12000 / 4 = 3000).
pub const STATES_TO_KEEP: usize = 3_000;

const _: () = assert!(
    BLOCKS_TO_KEEP >= STATES_TO_KEEP,
    "BLOCKS_TO_KEEP must be >= STATES_TO_KEEP"
);

/// Hard cap for the known aggregated payload buffer (number of distinct attestation messages).
/// With 1 attestation/slot, this holds ~500 messages (~33 min at 4s/slot).
pub const AGGREGATED_PAYLOAD_CAP: usize = 512;

/// Hard cap for the new (pending) aggregated payload buffer.
/// Smaller than known since new payloads are drained every interval (~4s).
pub const NEW_PAYLOAD_CAP: usize = 64;

/// Hard cap for the gossip signature buffer (individual signatures, not distinct data_roots).
/// With 4 validators and 4-second slots, 2048 signatures covers ~512 slots (~34 min).
/// Each XMSS signature is ~3KB, so worst-case memory is ~6 MB.
pub const GOSSIP_SIGNATURE_CAP: usize = 2048;
