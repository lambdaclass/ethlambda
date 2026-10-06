//! The shared state behind the gloas builder market: bids seen on
//! `execution_payload_bid` (or posted to the Beacon API) and pooled for block
//! production, the proposer preferences those bids are judged against, and the
//! execution payloads gossip has revealed.
//!
//! One [`SharedBuilderMarket`] exists per node. p2p validates against it and
//! the Beacon API reads it, like [`super::payload_attestation_pool`]. Gossip's
//! stateful checks run on blocking threads, so none of this can be owned by the
//! chain actor.
//!
//! The method signatures are the contract between the gossip rules, p2p and the
//! Beacon API; the bodies are placeholders until they are filled.

use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};

use lru::LruCache;

use super::containers::gloas;
use super::gossip::IgnoreReason;
use super::primitives::{BlsPubkey, ExecutionAddress, ExecutionBlockHash, Root, Slot};

/// Exactly one per node.
pub type SharedBuilderMarket = Arc<BuilderMarket>;

/// Bids pooled per `(slot, parent hash, parent root)`, top values kept.
pub const MAX_BIDS_PER_PARENT: usize = 16;
/// A full slot refuses new keys: `record_bid` answers `false`.
pub const MAX_SEEN_BID_KEYS_PER_SLOT: usize = 4096;
/// Over the cap, the lowest `proposal_slot` is dropped first.
pub const MAX_PREFERENCES: usize = 1024;
/// Known payloads, evicted least recently used first, by block hash.
pub const KNOWN_PAYLOADS_CAPACITY: NonZeroUsize = NonZeroUsize::new(256).unwrap();

/// What gossip learned about an execution payload from its envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownPayload {
    pub gas_limit: u64,
    /// The block whose envelope revealed it.
    pub beacon_block_root: Root,
    /// `(pubkey, source_address)` of every builder exit request it carries.
    pub builder_exits: Vec<(BlsPubkey, ExecutionAddress)>,
}

#[derive(Debug)]
pub struct BuilderMarket {
    // Filled by Agent A: the bid pool and the preferences cache join this.
    #[allow(dead_code)]
    payloads: Mutex<LruCache<ExecutionBlockHash, KnownPayload>>,
}

impl Default for BuilderMarket {
    fn default() -> Self {
        Self {
            payloads: Mutex::new(LruCache::new(KNOWN_PAYLOADS_CAPACITY)),
        }
    }
}

#[allow(dead_code, unused_variables)] // filled by Agent A
impl BuilderMarket {
    // Bids: seen.execution_payload_bids + seen.best_execution_payload_bid + pool.

    /// The spec's two seen rules, in order: `(slot, parent_hash, parent_root,
    /// builder)` recorded -> `AlreadySeen`; value <= best for `(slot,
    /// parent_hash, parent_root)` -> `NotHighestBid`.
    pub fn check_bid_seen(&self, bid: &gloas::ExecutionPayloadBid) -> Result<(), IgnoreReason> {
        Ok(())
    }

    /// Re-runs [`Self::check_bid_seen`] under the lock. If it passes, records
    /// both seen keys and pools the bid. `false` = not recorded (race, or the
    /// per-slot key cap). Prunes slots below `bid.slot - 1`.
    pub fn record_bid(&self, signed: gloas::SignedExecutionPayloadBid) -> bool {
        false
    }

    /// The identical message and signature is pooled (API idempotency).
    pub fn contains_bid(&self, signed: &gloas::SignedExecutionPayloadBid) -> bool {
        false
    }

    /// Pooled bids for the key: value descending, then builder index ascending.
    pub fn bids_for(
        &self,
        slot: Slot,
        parent_block_root: Root,
        parent_block_hash: ExecutionBlockHash,
    ) -> Vec<gloas::SignedExecutionPayloadBid> {
        Vec::new()
    }

    pub fn has_bids_for_slot(&self, slot: Slot) -> bool {
        false
    }

    pub fn prune_bids_before(&self, slot: Slot) {}

    // Proposer preferences: seen.proposer_preferences.

    pub fn preferences(
        &self,
        proposal_slot: Slot,
        dependent_root: Root,
    ) -> Option<gloas::SignedProposerPreferences> {
        None
    }

    /// The first valid preferences per key win. `false` if one is held. Prunes
    /// `proposal_slot < current_slot`.
    pub fn record_preferences(
        &self,
        signed: gloas::SignedProposerPreferences,
        current_slot: Slot,
    ) -> bool {
        false
    }

    pub fn prune_preferences_before(&self, slot: Slot) {}

    // Known payloads: seen.execution_payloads.

    pub fn record_execution_payload(&self, envelope: &gloas::ExecutionPayloadEnvelope) {}

    pub fn known_payload(&self, block_hash: ExecutionBlockHash) -> Option<KnownPayload> {
        None
    }
}
