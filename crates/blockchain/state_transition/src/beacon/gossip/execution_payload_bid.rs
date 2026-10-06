//! Gossip validation for the gloas `execution_payload_bid` topic: a builder's
//! `SignedExecutionPayloadBid`, the commitment a proposer may choose in place
//! of building its own payload.
//!
//! Split like [`super::envelope`]: [`cheap_checks`] reads only the message, the
//! market's seen state and the clock, so the p2p actor runs it inline;
//! [`stateful_checks`] reads cached states and verifies the signature, so it
//! runs on a blocking thread. Never queues: every "MAY be queued" is IGNORE.
//!
//! Stubs until filled: every rule answers `Ignore(NoConsumer)`.

use std::sync::Arc;

use super::{IgnoreReason, Outcome};
use crate::beacon::builder_market::BuilderMarket;
use crate::beacon::config::Config;
use crate::beacon::containers::{BeaconState, gloas};
use crate::beacon::fork_choice::Store;
use crate::beacon::primitives::{Epoch, Root, Slot};

/// Gloas p2p preset: the largest decompressed `SignedExecutionPayloadBid`.
pub const MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE: usize = 196_932;

/// The spec's `is_gas_limit_target_compatible`.
/// `max_diff = (parent / 1024).saturating_sub(1)`, `min = parent - max_diff`,
/// `max = parent.saturating_add(max_diff)`.
#[allow(dead_code, unused_variables)] // filled by Agent A
pub fn is_gas_limit_target_compatible(
    parent_gas_limit: u64,
    gas_limit: u64,
    target_gas_limit: u64,
) -> bool {
    false
}

/// `is_current_slot(slot) || slot.checked_sub(1).is_some_and(is_current_slot)`.
#[allow(dead_code, unused_variables)] // filled by Agent A
pub(crate) fn is_current_or_next_slot(config: &Config, slot: Slot, now_ms: u64) -> bool {
    false
}

#[allow(unused_variables)] // filled by Agent A
pub fn cheap_checks(
    market: &BuilderMarket,
    store: &Store,
    signed: &gloas::SignedExecutionPayloadBid,
    now_ms: u64,
) -> Result<(), Outcome> {
    Err(Outcome::Ignore(IgnoreReason::NoConsumer))
}

#[allow(unused_variables)] // filled by Agent A
pub fn stateful_checks(
    store: &Store,
    market: &BuilderMarket,
    signed: &gloas::SignedExecutionPayloadBid,
) -> Outcome {
    Outcome::Ignore(IgnoreReason::NoConsumer)
}

/// Both halves. The caller records the bid on `Accept`.
pub fn validate(
    market: &BuilderMarket,
    store: &Store,
    signed: &gloas::SignedExecutionPayloadBid,
    now_ms: u64,
) -> Outcome {
    if let Err(outcome) = cheap_checks(market, store, signed, now_ms) {
        return outcome;
    }
    stateful_checks(store, market, signed)
}

/// The spec's `is_bid_compatible_with_head`, against the recorded head.
#[allow(dead_code, unused_variables)] // filled by Agent A
pub fn is_bid_compatible_with_head(
    store: &Store,
    bid: &gloas::ExecutionPayloadBid,
) -> Result<bool, Outcome> {
    Err(Outcome::Ignore(IgnoreReason::NoConsumer))
}

/// Cached-only: a `CheckpointState{epoch, root}` hit; else the cached
/// `BlockState(root)` advanced to the epoch start and cached. `None` = miss.
#[allow(dead_code, unused_variables)] // filled by Agent A
pub(crate) fn cached_checkpoint_state(
    store: &Store,
    epoch: Epoch,
    root: Root,
) -> Option<Arc<BeaconState>> {
    None
}
