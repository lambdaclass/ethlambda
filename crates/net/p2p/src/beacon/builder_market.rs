//! Gloas builder market gossip: the `execution_payload_bid` and
//! `proposer_preferences` topics.
//!
//! Stubs until filled. Neither message type ever reaches the chain actor: the
//! rules live in `ethlambda_state_transition::beacon::gossip::{
//! execution_payload_bid, proposer_preferences}`, and what they accept is
//! recorded in the node's shared `BuilderMarket` by the verdict.

use ethlambda_state_transition::beacon::gossip::{IgnoreReason, Outcome};
use ethlambda_types::beacon::containers::gloas::{
    SignedExecutionPayloadBid, SignedProposerPreferences,
};
use ethlambda_types::beacon::primitives::Slot;
use ethlambda_types::time::unix_now_ms;

use crate::P2PServer;
use crate::beacon::verdict::Dispatch;

/// Size cap -> `Reject(Malformed)`; decode -> `Reject(Decode)`;
/// `inc_beacon_gossip(KIND, "decoded")`;
/// `gossip::execution_payload_bid::cheap_checks`; then
/// `Validate(Validated::ExecutionPayloadBid { .. })`.
#[allow(dead_code, unused_variables)] // filled by Agent B
pub(crate) fn triage_execution_payload_bid(server: &P2PServer, payload: &[u8]) -> Dispatch {
    Dispatch::Report(Outcome::Ignore(IgnoreReason::NoConsumer))
}

/// As [`triage_execution_payload_bid`], for `proposer_preferences`.
#[allow(dead_code, unused_variables)] // filled by Agent B
pub(crate) fn triage_proposer_preferences(server: &P2PServer, payload: &[u8]) -> Dispatch {
    Dispatch::Report(Outcome::Ignore(IgnoreReason::NoConsumer))
}

/// Publish on `publish_digest(bid.slot)` / `execution_payload_bid`.
/// Precondition: the caller already recorded it in the market.
#[allow(dead_code, unused_variables)] // filled by Agent B
pub(crate) fn publish_execution_payload_bid(
    server: &mut P2PServer,
    bid: SignedExecutionPayloadBid,
) {
}

/// Publish on `publish_digest(proposal_slot)`: during the epoch before gloas
/// this is the gloas digest, which is held.
#[allow(dead_code, unused_variables)] // filled by Agent B
pub(crate) fn publish_proposer_preferences(
    server: &mut P2PServer,
    preferences: SignedProposerPreferences,
) {
}

/// The wall-clock slot, from the store's config.
pub(crate) fn wall_slot(server: &P2PServer) -> Slot {
    let config = server.store.config();
    let genesis_ms = config.genesis_time_ms();
    unix_now_ms().saturating_sub(genesis_ms) / config.slot_duration_ms.max(1)
}
