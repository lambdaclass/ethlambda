//! The request/response protocols `ethlambda node` registers.
//!
//! Three, against beacon's seven: this chain has no `ping`, `metadata` or
//! `goodbye`, and keeps a connection alive without them. What it does have that
//! beacon does not is block serving, which is the whole point of the other two.

pub const STATUS_V1: &str = "/leanconsensus/req/status/1/ssz_snappy";
pub const BLOCKS_BY_ROOT_V1: &str = "/leanconsensus/req/blocks_by_root/1/ssz_snappy";
pub const BLOCKS_BY_RANGE_V1: &str = "/leanconsensus/req/blocks_by_range/1/ssz_snappy";

/// Maximum number of blocks in a single `blocks_by_range` request.
pub const MAX_REQUEST_BLOCKS: u64 = 1024;

/// The metrics label for one of this chain's protocols, or `None` if it is not
/// one of them.
///
/// The counterpart of [`crate::beacon::protocols::label`]; `protocol_label` in
/// the codec asks both, which is the only place the two chains' protocol sets
/// meet.
pub fn label(protocol: &str) -> Option<&'static str> {
    match protocol {
        STATUS_V1 => Some("status"),
        BLOCKS_BY_ROOT_V1 => Some("blocks_by_root"),
        BLOCKS_BY_RANGE_V1 => Some("blocks_by_range"),
        _ => None,
    }
}
