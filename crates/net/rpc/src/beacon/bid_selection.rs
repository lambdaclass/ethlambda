//! Choosing between this node's own build and a pooled builder bid for
//! `produceBlockV4`. Pure: no store, no clock.
//!
//! Stubs until filled.

use ethlambda_types::beacon::containers::gloas::{ExecutionPayloadBid, SignedExecutionPayloadBid};
use ethlambda_types::beacon::primitives::Uint256;

/// The local build, as the choice sees it.
#[allow(dead_code)] // filled by Agent C
pub(crate) struct LocalCandidate {
    pub(crate) value_wei: u128,
    pub(crate) should_override_builder: bool,
}

// The enum is short-lived (one per block production), so boxing the bid buys
// nothing.
#[allow(dead_code, clippy::large_enum_variant)] // filled by Agent C
pub(crate) enum PayloadChoice {
    Local,
    Bid(SignedExecutionPayloadBid),
}

/// `value.saturating_add(execution_payment)`; a p2p bid's payment is zero.
#[allow(dead_code, unused_variables)] // filled by Agent C
pub(crate) fn bid_total_gwei(bid: &ExecutionPayloadBid) -> u64 {
    0
}

/// Saturating conversion of a wei amount.
#[allow(dead_code, unused_variables)] // filled by Agent C
pub(crate) fn wei_u128(value: &Uint256) -> u128 {
    0
}

/// `None` when there is neither a local build nor a bid at or above `min_bid`.
#[allow(dead_code, unused_variables)] // filled by Agent C
pub(crate) fn choose_payload(
    local: Option<&LocalCandidate>,
    bids_desc: &[SignedExecutionPayloadBid],
    min_bid: u64,
    builder_boost_factor: u64,
) -> Option<PayloadChoice> {
    None
}
