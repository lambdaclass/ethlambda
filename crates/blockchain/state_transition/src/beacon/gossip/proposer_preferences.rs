//! Gossip validation for the gloas `proposer_preferences` topic: a proposer's
//! `SignedProposerPreferences` (fee recipient and gas target) for a slot, which
//! bids on that slot are judged against.
//!
//! Split like [`super::envelope`]: [`cheap_checks`] inline in the p2p actor,
//! [`stateful_checks`] on a blocking thread, reading cached states only.
//!
//! Stubs until filled: every rule answers `Ignore(NoConsumer)`.

use super::{IgnoreReason, Outcome};
use crate::beacon::builder_market::BuilderMarket;
use crate::beacon::config::Config;
use crate::beacon::containers::{BeaconState, gloas};
use crate::beacon::fork_choice::Store;
use crate::beacon::primitives::{Domain, Epoch, Root, Slot};

#[allow(unused_variables)] // filled by Agent A
pub fn cheap_checks(
    market: &BuilderMarket,
    store: &Store,
    signed: &gloas::SignedProposerPreferences,
    now_ms: u64,
) -> Result<(), Outcome> {
    Err(Outcome::Ignore(IgnoreReason::NoConsumer))
}

#[allow(unused_variables)] // filled by Agent A
pub fn stateful_checks(store: &Store, signed: &gloas::SignedProposerPreferences) -> Outcome {
    Outcome::Ignore(IgnoreReason::NoConsumer)
}

/// Both halves. The caller records the preferences on `Accept`.
pub fn validate(
    market: &BuilderMarket,
    store: &Store,
    signed: &gloas::SignedProposerPreferences,
    now_ms: u64,
) -> Outcome {
    if let Err(outcome) = cheap_checks(market, store, signed, now_ms) {
        return outcome;
    }
    stateful_checks(store, signed)
}

/// The spec's `is_valid_dependent_root`: `root == store.head()`, or some block
/// in the index has `parent_root == root` and `slot > dependent_slot`.
#[allow(dead_code, unused_variables)] // filled by Agent A
pub fn is_valid_dependent_root(store: &Store, root: Root, dependent_slot: Slot) -> bool {
    false
}

/// `ancestor_at(state, state_block_root, compute_shuffling_dependent_slot(
/// epoch(proposal_slot)))`. Used by `produceBlockV4` and the validator client.
#[allow(dead_code, unused_variables)] // filled by Agent A
pub fn dependent_root_at(
    state: &BeaconState,
    state_block_root: Root,
    proposal_slot: Slot,
) -> Option<Root> {
    None
}

/// The distinct candidate signing domains, tried in order: `get_domain(
/// lookahead_state, DOMAIN_PROPOSER_PREFERENCES, Some(P))`; the schedule's fork
/// version at `P - MIN_SEED_LOOKAHEAD` (saturating); the schedule's at `P`.
#[allow(dead_code, unused_variables)] // filled by Agent A
pub fn proposer_preferences_domains(
    lookahead_state: &BeaconState,
    config: &Config,
    proposal_epoch: Epoch,
) -> Vec<Domain> {
    Vec::new()
}

/// `now > slot_start + 500 ms`.
#[allow(dead_code, unused_variables)] // filled by Agent A
pub(crate) fn is_past_slot(config: &Config, slot: Slot, now_ms: u64) -> bool {
    false
}
