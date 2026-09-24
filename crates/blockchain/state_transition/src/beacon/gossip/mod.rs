//! Gossip validation for the beacon topics this node consumes.
//!
//! The rules are the specification's `validate_*_gossip` functions
//! (`p2p-interface.md`), split by cost. `cheap_checks` read only the message,
//! the clock and the store's own metadata, so the p2p actor runs them inline.
//! `stateful_checks` read states and verify signatures and proofs, so they run
//! on a blocking thread. The spec's conformance vectors run both, in order.

pub mod block;
pub mod column;
#[cfg(test)]
pub(crate) mod test_support;

use std::num::NonZeroUsize;

use lru::LruCache;

use crate::beacon::config::Config;
use crate::beacon::constants::MAXIMUM_GOSSIP_CLOCK_DISPARITY;
use crate::beacon::fork_choice::{self, Store};
use crate::beacon::helpers::misc::compute_start_slot_at_epoch;
use crate::beacon::precheck::PrecheckError;
use crate::beacon::primitives::{Root, Slot, ValidatorIndex};

/// A gossip message's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Propagate it, and hand the object to the chain.
    Accept,
    /// Do not propagate it, but hand the object to the chain, which parks it
    /// until what it is missing arrives: the specification's "MAY be queued".
    Queue(QueueReason),
    /// Do not propagate it, and drop it. Not the sender's fault.
    Ignore(IgnoreReason),
    /// Do not propagate it, and drop it. The sender forwarded something invalid.
    Reject(RejectReason),
}

impl Outcome {
    /// `(outcome, reason)` metric label values. Both are fixed per variant, so
    /// a message's contents can never add a label value.
    pub fn labels(&self) -> (&'static str, &'static str) {
        match self {
            Self::Accept => ("accept", "valid"),
            Self::Queue(reason) => ("queue", reason.label()),
            Self::Ignore(reason) => ("ignore", reason.label()),
            Self::Reject(reason) => ("reject", reason.label()),
        }
    }
}

/// Why an object was queued rather than judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueReason {
    /// Its parent block has never been seen.
    ParentUnknown,
    /// Its parent is stored but has no cached post-state yet: held for its
    /// columns, still importing, or evicted from the state cache. Also used
    /// when the finalized-ancestry walk cannot finish: a `LiveChain` row is
    /// missing for a block on the way, as after a late `invalidate_subtree`.
    ParentNotReady,
    /// Its slot is outside the parent state's proposer lookahead.
    ShufflingUnavailable,
}

impl QueueReason {
    pub fn label(&self) -> &'static str {
        match self {
            Self::ParentUnknown => "parent_unknown",
            Self::ParentNotReady => "parent_not_ready",
            Self::ShufflingUnavailable => "shuffling_unavailable",
        }
    }
}

/// Why a message was ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoreReason {
    FutureSlot,
    Finalized,
    AlreadySeen,
    AlreadyStored,
    /// A topic this node subscribes to but has no validator for yet.
    NoConsumer,
    /// Every stateful-validation permit was taken.
    Overloaded,
    /// Validation panicked.
    Internal,
}

impl IgnoreReason {
    pub fn label(&self) -> &'static str {
        match self {
            Self::FutureSlot => "future_slot",
            Self::Finalized => "finalized",
            Self::AlreadySeen => "already_seen",
            Self::AlreadyStored => "already_stored",
            Self::NoConsumer => "no_consumer",
            Self::Overloaded => "overloaded",
            Self::Internal => "internal",
        }
    }
}

/// Why a message was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    Decompress,
    Decode,
    WrongSubnet,
    Malformed,
    TooManyBlobs,
    NotAfterParent,
    WrongProposer,
    UnknownProposer,
    BadSignature,
    FinalizedNotAncestor,
    PayloadTimestamp,
    InclusionProof,
    Kzg,
}

impl RejectReason {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Decompress => "decompress",
            Self::Decode => "decode",
            Self::WrongSubnet => "wrong_subnet",
            Self::Malformed => "malformed",
            Self::TooManyBlobs => "too_many_blobs",
            Self::NotAfterParent => "not_after_parent",
            Self::WrongProposer => "wrong_proposer",
            Self::UnknownProposer => "unknown_proposer",
            Self::BadSignature => "bad_signature",
            Self::FinalizedNotAncestor => "finalized_not_ancestor",
            Self::PayloadTimestamp => "payload_timestamp",
            Self::InclusionProof => "inclusion_proof",
            Self::Kzg => "kzg",
        }
    }
}

impl From<PrecheckError> for RejectReason {
    fn from(err: PrecheckError) -> Self {
        match err {
            PrecheckError::NotAfterParent { .. } => Self::NotAfterParent,
            PrecheckError::WrongProposer { .. } => Self::WrongProposer,
            PrecheckError::UnknownProposer { .. } => Self::UnknownProposer,
            PrecheckError::BadSignature => Self::BadSignature,
        }
    }
}

/// The first valid block per `(slot, proposer)`, the key the specification's
/// `seen.proposer_slots` uses.
///
/// Bounded by capacity rather than pruned on finality, so a slot fabricated far
/// in the future cannot grow it.
pub struct SeenBlocks(LruCache<(Slot, ValidatorIndex), Root>);

impl SeenBlocks {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self(LruCache::new(capacity))
    }

    pub fn contains(&self, slot: Slot, proposer: ValidatorIndex) -> bool {
        self.0.contains(&(slot, proposer))
    }

    /// Record `root` as the first valid block for its `(slot, proposer)`.
    /// Returns `false`, changing nothing, when one is already recorded.
    pub fn record(&mut self, slot: Slot, proposer: ValidatorIndex, root: Root) -> bool {
        if self.0.contains(&(slot, proposer)) {
            return false;
        }
        self.0.put((slot, proposer), root);
        true
    }
}

/// The first valid sidecar per `(slot, proposer, column index)`.
///
/// Bounded the same way as [`SeenBlocks`].
pub struct SeenColumns(LruCache<(Slot, ValidatorIndex, u64), ()>);

impl SeenColumns {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self(LruCache::new(capacity))
    }

    pub fn contains(&self, slot: Slot, proposer: ValidatorIndex, index: u64) -> bool {
        self.0.contains(&(slot, proposer, index))
    }

    /// Record the first valid sidecar for its key. Returns `false`, changing
    /// nothing, when one is already recorded.
    pub fn record(&mut self, slot: Slot, proposer: ValidatorIndex, index: u64) -> bool {
        if self.0.contains(&(slot, proposer, index)) {
            return false;
        }
        self.0.put((slot, proposer, index), ());
        true
    }
}

/// The specification's `is_future_slot`: `slot` starts later than `now_ms`
/// plus the gossip clock disparity allowance.
pub(crate) fn is_future_slot(config: &Config, slot: Slot, now_ms: u64) -> bool {
    let slot_start_ms = config
        .genesis_time_ms()
        .saturating_add(slot.saturating_mul(config.slot_duration_ms));
    slot_start_ms > now_ms.saturating_add(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
}

/// The first slot of the store's finalized epoch.
pub(crate) fn finalized_start_slot(store: &Store) -> Slot {
    compute_start_slot_at_epoch(store.beacon_finalized_checkpoint().epoch)
}

/// Where a block's chain stands relative to the finalized checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FinalizedAncestry {
    /// The finalized checkpoint is an ancestor.
    Descends,
    /// The chain passes the finalized epoch at a different block: a fork.
    Conflicts,
    /// The walk could not finish: a block on the way has no `LiveChain` row.
    Unknown,
}

impl FinalizedAncestry {
    /// The verdict this ancestry alone dictates, shared by `block` and
    /// `column`'s `stateful_checks`.
    pub(crate) fn verdict(self) -> Result<(), Outcome> {
        match self {
            Self::Descends => Ok(()),
            Self::Conflicts => Err(Outcome::Reject(RejectReason::FinalizedNotAncestor)),
            Self::Unknown => Err(Outcome::Queue(QueueReason::ParentNotReady)),
        }
    }
}

/// Where `root`'s chain stands relative to the finalized checkpoint. The same
/// walk the chain actor's `parent_is_on_the_finalized_chain` does, but
/// three-way rather than a bool: `fork_choice::get_checkpoint_block` erroring
/// means a row is missing from `LiveChain`, which happens after
/// `fork_choice::invalidate_subtree` deletes a late-invalidated parent's rows
/// while its cached state stays, not that `root`'s chain has forked away from
/// the finalized checkpoint. A caller that folded that into "not an ancestor"
/// would REJECT a child of a parent whose payload was invalidated, penalizing
/// peers who forwarded it before they learned of the invalidation, where the
/// specification asks for IGNORE.
pub(crate) fn finalized_ancestry(store: &Store, root: Root) -> FinalizedAncestry {
    let finalized = store.beacon_finalized_checkpoint();
    let index = store.block_index();
    match fork_choice::get_checkpoint_block(&index, root, finalized.epoch) {
        Ok(ancestor) if ancestor == finalized.root => FinalizedAncestry::Descends,
        Ok(_) => FinalizedAncestry::Conflicts,
        Err(_) => FinalizedAncestry::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capacity(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).expect("non-zero")
    }

    #[test]
    fn a_slot_is_future_only_past_the_clock_disparity() {
        let config = Config {
            genesis_time: 100,
            ..Config::mainnet()
        };
        let slot_start = 100_000 + config.slot_duration_ms;
        assert!(!is_future_slot(
            &config,
            1,
            slot_start - MAXIMUM_GOSSIP_CLOCK_DISPARITY
        ));
        assert!(is_future_slot(
            &config,
            1,
            slot_start - MAXIMUM_GOSSIP_CLOCK_DISPARITY - 1
        ));
    }

    #[test]
    fn a_block_key_records_once() {
        let mut seen = SeenBlocks::new(capacity(4));
        assert!(!seen.contains(10, 3));
        assert!(seen.record(10, 3, Root::repeat_byte(1)));
        assert!(seen.contains(10, 3));
        // An equivocating second block for the same key does not replace it.
        assert!(!seen.record(10, 3, Root::repeat_byte(2)));
        assert!(!seen.contains(10, 4));
    }

    #[test]
    fn a_column_key_records_once_per_index() {
        let mut seen = SeenColumns::new(capacity(4));
        assert!(seen.record(10, 3, 0));
        assert!(!seen.record(10, 3, 0));
        assert!(seen.record(10, 3, 1));
    }

    #[test]
    fn the_caches_forget_their_oldest_entry_past_capacity() {
        let mut seen = SeenBlocks::new(capacity(2));
        seen.record(1, 0, Root::ZERO);
        seen.record(2, 0, Root::ZERO);
        seen.record(3, 0, Root::ZERO);
        assert!(!seen.contains(1, 0));
        assert!(seen.contains(3, 0));
    }

    #[test]
    fn labels_name_the_outcome_and_the_reason() {
        assert_eq!(Outcome::Accept.labels(), ("accept", "valid"));
        assert_eq!(
            Outcome::Queue(QueueReason::ParentUnknown).labels(),
            ("queue", "parent_unknown")
        );
        assert_eq!(
            Outcome::Reject(RejectReason::from(PrecheckError::BadSignature)).labels(),
            ("reject", "bad_signature")
        );
    }
}
