//! Gossip validation for the beacon topics this node consumes.
//!
//! The rules are the specification's `validate_*_gossip` functions
//! (`p2p-interface.md`), split by cost. `cheap_checks` read only the message,
//! the clock and the store's own metadata, so the p2p actor runs them inline.
//! `stateful_checks` read states and verify signatures and proofs, so they run
//! on a blocking thread. The spec's conformance vectors run both, in order.

pub mod aggregate;
pub mod attestation;
pub mod block;
pub mod column;
pub mod envelope;
pub mod execution_payload_bid;
pub mod operations;
pub mod payload_attestation;
pub mod proposer_preferences;
pub mod sync_committee;
#[cfg(test)]
pub(crate) mod test_support;

// Re-exported at the module's own top level, alongside `SeenBlocks` and
// `SeenColumns`: every seen cache lives at the same path regardless of which
// topic's submodule defines it.
pub use aggregate::SeenAggregates;
pub use attestation::SeenAttestations;
pub use envelope::SeenEnvelopes;
pub use payload_attestation::SeenPayloadAttestations;
pub use sync_committee::{SeenSyncCommitteeMessages, SeenSyncContributions};

use std::num::NonZeroUsize;

use lru::LruCache;

use crate::beacon::config::Config;
use crate::beacon::constants::MAXIMUM_GOSSIP_CLOCK_DISPARITY;
use crate::beacon::containers::{AttestationData, BeaconState, gloas};
use crate::beacon::fork::ForkName;
use crate::beacon::fork_choice::{self, PayloadStatusEnum, Store};
use crate::beacon::helpers::accessors::get_block_root_at_slot;
use crate::beacon::helpers::misc::{compute_epoch_at_slot, compute_start_slot_at_epoch};
use crate::beacon::lean_boundary::lean_fork_unreachable;
use crate::beacon::precheck::PrecheckError;
use crate::beacon::preset;
use crate::beacon::primitives::{Epoch, Root, Slot, ValidatorIndex};

/// A gossip message's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Propagate it, and hand the object to the chain.
    Accept,
    /// Do not propagate it, but hand the object to the chain, which parks it
    /// until what it is missing arrives: the specification's "MAY be queued".
    /// A column passes [`column::chain_checks`] on the way, since the chain
    /// keeps a column without checking it.
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
    /// A gloas sidecar names a block that has never been seen.
    BlockUnknown,
    /// A gloas sidecar names a block that is stored but has no post-state yet.
    BlockNotReady,
    /// A gloas envelope names a block whose post-state is stored but not in
    /// the cache the gossip checks read, as when the block was imported
    /// moments ago. See `envelope::stateful_checks` for why this is not an
    /// ignore.
    StateNotCached,
}

impl QueueReason {
    pub fn label(&self) -> &'static str {
        match self {
            Self::ParentUnknown => "parent_unknown",
            Self::ParentNotReady => "parent_not_ready",
            Self::ShufflingUnavailable => "shuffling_unavailable",
            Self::BlockUnknown => "block_unknown",
            Self::BlockNotReady => "block_not_ready",
            Self::StateNotCached => "state_not_cached",
        }
    }
}

/// Why a message was ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoreReason {
    FutureSlot,
    /// An operation's epoch has not begun yet on the wall clock.
    FutureEpoch,
    Finalized,
    AlreadySeen,
    AlreadyStored,
    /// A topic this node subscribes to but has no validator for yet.
    NoConsumer,
    /// Every stateful-validation permit was taken.
    Overloaded,
    /// Validation panicked.
    Internal,
    /// The message's own fork is one this build does not validate or decode
    /// (currently gloas): not the sender's fault, and not malformed, so this
    /// is `Ignore` rather than `Reject`. A `Reject` down-scores the peer in
    /// gossipsub, and every honest peer on the network sends these once this
    /// node's own clock crosses that fork's activation, which would punish
    /// the whole mesh for a gap in this build rather than in the message.
    UnsupportedFork,
    /// An attestation's slot is in neither the current nor the previous epoch.
    OutsideEpochWindow,
    /// An aggregate adds no bit that one already accepted for the same data
    /// and committee does not have.
    CoveredBits,
    /// The block an attestation votes for has never been seen.
    UnknownBlock,
    /// The voted block is known but its post-state is not cached.
    StateUnavailable,
    /// The finalized checkpoint is not an ancestor of the voted block. IGNORE
    /// for attestations, where blocks and columns REJECT.
    FinalizedNotAncestor,
    /// An ancestor lies outside what the state's `block_roots` can answer.
    AncestryUnknown,
    /// A gloas bid or proposer preferences names a slot before the fork.
    PreGloasSlot,
    /// A bid's slot is neither the current nor the next slot.
    NotCurrentOrNextSlot,
    /// A bid's value does not beat the best already seen for its slot and parent.
    NotHighestBid,
    /// A bid or preferences name a slot beyond the proposer lookahead.
    BeyondLookahead,
    /// No proposer preferences are known for a bid's slot and dependent root.
    PreferencesUnseen,
    /// A bid's fee recipient is not the one in the proposer's preferences.
    FeeRecipientMismatch,
    /// A bid's parent block hash is not a known execution payload.
    ParentPayloadUnknown,
    /// A bid's gas limit cannot reach the preferences' target from the parent's.
    GasLimitIncompatible,
    /// A bid is not compatible with this node's head branch.
    NotOnHeadBranch,
    /// A bid's builder cannot cover its value.
    BuilderCannotCover,
    /// A bid's builder exits in the parent payload.
    BuilderMayExit,
    /// Proposer preferences arrived after their proposal slot began.
    SlotStarted,
    /// Proposer preferences name a dependent root no chain here can have.
    ImpossibleDependentRoot,
    /// A gloas block builds on its parent's full payload branch, but the
    /// parent's envelope has not been seen and verified (the specification
    /// lets it be queued until it is).
    ParentPayloadUnverified,
    /// A gloas vote names the full payload (`data.index == 1`) of a block whose
    /// envelope has not been seen and verified (the specification lets it be
    /// queued until it is).
    PayloadEnvelopeUnseen,
    /// A gloas vote names a payload the execution client has not validated.
    PayloadOptimistic,
    /// A payload attestation's slot is not the current slot.
    NotCurrentSlot,
    /// A payload attestation names a block that is not at the attested slot.
    BlockNotAtSlot,
    /// The head state's payload timeliness committee window cannot answer for
    /// the attested slot.
    PtcUnavailable,
    /// The wall clock is before the fork that introduced the topic's message.
    BeforeFork,
    /// A voluntary exit for a validator that has already initiated its exit.
    AlreadyExiting,
    /// The head state's sync committees cannot answer for the message's period.
    SyncCommitteeUnavailable,
}

impl IgnoreReason {
    pub fn label(&self) -> &'static str {
        match self {
            Self::FutureSlot => "future_slot",
            Self::FutureEpoch => "future_epoch",
            Self::Finalized => "finalized",
            Self::AlreadySeen => "already_seen",
            Self::AlreadyStored => "already_stored",
            Self::NoConsumer => "no_consumer",
            Self::Overloaded => "overloaded",
            Self::Internal => "internal",
            Self::UnsupportedFork => "unsupported_fork",
            Self::OutsideEpochWindow => "outside_epoch_window",
            Self::CoveredBits => "covered_bits",
            Self::UnknownBlock => "unknown_block",
            Self::StateUnavailable => "state_unavailable",
            Self::FinalizedNotAncestor => "finalized_not_ancestor",
            Self::AncestryUnknown => "ancestry_unknown",
            Self::PreGloasSlot => "pre_gloas_slot",
            Self::NotCurrentOrNextSlot => "not_current_or_next_slot",
            Self::NotHighestBid => "not_highest_bid",
            Self::BeyondLookahead => "beyond_lookahead",
            Self::PreferencesUnseen => "preferences_unseen",
            Self::FeeRecipientMismatch => "fee_recipient_mismatch",
            Self::ParentPayloadUnknown => "parent_payload_unknown",
            Self::GasLimitIncompatible => "gas_limit_incompatible",
            Self::NotOnHeadBranch => "not_on_head_branch",
            Self::BuilderCannotCover => "builder_cannot_cover",
            Self::BuilderMayExit => "builder_may_exit",
            Self::SlotStarted => "slot_started",
            Self::ImpossibleDependentRoot => "impossible_dependent_root",
            Self::ParentPayloadUnverified => "parent_payload_unverified",
            Self::PayloadEnvelopeUnseen => "payload_envelope_unseen",
            Self::PayloadOptimistic => "payload_optimistic",
            Self::NotCurrentSlot => "not_current_slot",
            Self::BlockNotAtSlot => "block_not_at_slot",
            Self::PtcUnavailable => "ptc_unavailable",
            Self::BeforeFork => "before_fork",
            Self::AlreadyExiting => "already_exiting",
            Self::SyncCommitteeUnavailable => "sync_committee_unavailable",
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
    /// A gloas sidecar's slot is not the slot of the block it names.
    SlotMismatch,
    /// A gloas sidecar names a block of an earlier fork, which has no bid to
    /// take commitments from.
    BlockNotGloas,
    /// An attestation's target epoch is not its slot's epoch.
    EpochMismatch,
    /// An aggregate with no aggregation bit set.
    NoParticipants,
    /// Electra and later require `data.index` to be zero.
    NonZeroDataIndex,
    /// An aggregate's `committee_bits` does not name exactly one committee.
    CommitteeBits,
    /// The committee index is not below the slot's committee count.
    CommitteeIndex,
    /// `aggregation_bits` is not the committee's length.
    BitsLength,
    /// The selection proof does not select the aggregator.
    NotAggregator,
    /// The aggregator or attester is not a member of the named committee.
    NotInCommittee,
    /// A validator index the state has no validator for.
    UnknownValidator,
    /// The selection proof's signature is invalid.
    SelectionProof,
    /// The aggregator's signature over the `AggregateAndProof` is invalid.
    AggregatorSignature,
    /// The aggregate attestation's own signature is invalid.
    AggregateSignature,
    /// The target is not the voted block's ancestor at the target epoch.
    TargetNotAncestor,
    /// A bid promises a payment outside the bid value.
    ExecutionPaymentNonZero,
    /// A bid's block hash is its parent's.
    BlockHashEqualsParent,
    /// A bid's `prev_randao` is not the parent state's current mix.
    PrevRandao,
    /// A bid's builder index is not in the registry.
    UnknownBuilder,
    /// A bid's builder is not a payload builder.
    NotPayloadBuilder,
    /// A bid's builder is not active.
    InactiveBuilder,
    /// Preferences' dependent block is later than the shuffling's dependent slot.
    DependentRootTooLate,
    /// A gloas block body (or its parent execution requests) carries more of
    /// an operation than its limit, or any deposit.
    OperationLimit,
    /// A gloas bid's `parent_block_root` is not the block's `parent_root`.
    BidParentMismatch,
    /// A gloas block builds on its parent's empty branch, but its bid's
    /// `parent_block_hash` is not the parent state's `latest_block_hash`.
    BidNotOnParentHead,
    /// A gloas vote's `data.index` is neither zero nor one.
    DataIndexOutOfRange,
    /// A gloas vote cast in its block's own slot claims the payload is present.
    SameSlotPayloadFlag,
    /// A gloas vote names a payload the execution client found invalid.
    PayloadInvalid,
    /// A gloas envelope's builder is not the one its block's bid committed to.
    BuilderIndexMismatch,
    /// A gloas envelope's payload block hash is not its bid's.
    BlockHashMismatch,
    /// The root of a gloas envelope's execution requests is not its bid's.
    ExecutionRequestsRootMismatch,
    /// A gloas envelope's payload carries more withdrawals than its limit.
    TooManyWithdrawals,
    /// A payload attestation's slot lies before the gloas fork.
    PreGloasSlot,
    /// A payload attestation's validator is not in its slot's payload
    /// timeliness committee.
    NotInPtc,
    /// A voluntary exit, slashing or credentials change that fails its gossip
    /// rule against the head state.
    InvalidOperation,
    /// A sync committee contribution's subcommittee index is not below
    /// `SYNC_COMMITTEE_SUBNET_COUNT`.
    SubcommitteeIndex,
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
            Self::SlotMismatch => "slot_mismatch",
            Self::BlockNotGloas => "block_not_gloas",
            Self::EpochMismatch => "epoch_mismatch",
            Self::NoParticipants => "no_participants",
            Self::NonZeroDataIndex => "non_zero_data_index",
            Self::CommitteeBits => "committee_bits",
            Self::CommitteeIndex => "committee_index",
            Self::BitsLength => "bits_length",
            Self::NotAggregator => "not_aggregator",
            Self::NotInCommittee => "not_in_committee",
            Self::UnknownValidator => "unknown_validator",
            Self::SelectionProof => "selection_proof",
            Self::AggregatorSignature => "aggregator_signature",
            Self::AggregateSignature => "aggregate_signature",
            Self::TargetNotAncestor => "target_not_ancestor",
            Self::ExecutionPaymentNonZero => "execution_payment_nonzero",
            Self::BlockHashEqualsParent => "block_hash_equals_parent",
            Self::PrevRandao => "prev_randao",
            Self::UnknownBuilder => "unknown_builder",
            Self::NotPayloadBuilder => "not_payload_builder",
            Self::InactiveBuilder => "inactive_builder",
            Self::DependentRootTooLate => "dependent_root_too_late",
            Self::OperationLimit => "operation_limit",
            Self::BidParentMismatch => "bid_parent_mismatch",
            Self::BidNotOnParentHead => "bid_not_on_parent_head",
            Self::DataIndexOutOfRange => "data_index_out_of_range",
            Self::SameSlotPayloadFlag => "same_slot_payload_flag",
            Self::PayloadInvalid => "payload_invalid",
            Self::BuilderIndexMismatch => "builder_index_mismatch",
            Self::BlockHashMismatch => "block_hash_mismatch",
            Self::ExecutionRequestsRootMismatch => "execution_requests_root_mismatch",
            Self::TooManyWithdrawals => "too_many_withdrawals",
            Self::PreGloasSlot => "pre_gloas_slot",
            Self::NotInPtc => "not_in_ptc",
            Self::InvalidOperation => "invalid_operation",
            Self::SubcommitteeIndex => "subcommittee_index",
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

/// The first valid gloas sidecar per `(block root, column index)`: the
/// specification's modified `Seen.data_column_sidecar_tuples`.
///
/// A separate type from [`SeenColumns`] since the key differs: fulu's names the
/// proposer, which a gloas sidecar does not carry, and names the block by
/// `(slot, proposer)` where gloas names it by root. Bounded the same way.
pub struct SeenBlockColumns(LruCache<(Root, u64), ()>);

impl SeenBlockColumns {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self(LruCache::new(capacity))
    }

    pub fn contains(&self, block_root: Root, index: u64) -> bool {
        self.0.contains(&(block_root, index))
    }

    /// Record the first valid sidecar for its key. Returns `false`, changing
    /// nothing, when one is already recorded.
    pub fn record(&mut self, block_root: Root, index: u64) -> bool {
        if self.0.contains(&(block_root, index)) {
            return false;
        }
        self.0.put((block_root, index), ());
        true
    }
}

/// `verify_execution_requests_limits` (`specs/gloas/p2p-interface.md`).
///
/// The four lists the specification names: withdrawals, consolidations,
/// builder deposits and builder exits. Deposit requests are deliberately not
/// checked: gloas's `DepositRequests` is progressive and neither the
/// specification nor the state transition bounds it, so a limit here would
/// reject a block that import accepts.
///
/// Shared by [`block`] (a block's parent execution requests) and [`envelope`].
pub(crate) fn execution_requests_within_limits(requests: &gloas::ExecutionRequests) -> bool {
    requests.withdrawals.len() <= preset::MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD
        && requests.consolidations.len() <= preset::MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD
        && requests.builder_deposits.len() as u64
            <= preset::MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD
        && requests.builder_exits.len() as u64 <= preset::MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD
}

/// The specification's `compute_time_at_slot_ms`: the clock reading at the
/// start of `slot`.
pub(crate) fn slot_start_ms(config: &Config, slot: Slot) -> u64 {
    config
        .genesis_time_ms()
        .saturating_add(slot.saturating_mul(config.slot_duration_ms))
}

/// The specification's `is_future_slot`: `slot` starts later than `now_ms`
/// plus the gossip clock disparity allowance.
pub(crate) fn is_future_slot(config: &Config, slot: Slot, now_ms: u64) -> bool {
    slot_start_ms(config, slot) > now_ms.saturating_add(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
}

/// The specification's `is_current_slot` (`altair/p2p-interface.md`): the
/// clock, with the gossip clock disparity allowance on both ends, falls within
/// `slot`'s own span. That is `is_within_slot_range` with a range of zero, so
/// the far edge is the *next* slot's start.
pub(crate) fn is_current_slot(config: &Config, slot: Slot, now_ms: u64) -> bool {
    if now_ms.saturating_add(MAXIMUM_GOSSIP_CLOCK_DISPARITY) < slot_start_ms(config, slot) {
        return false;
    }
    slot_start_ms(config, slot.saturating_add(1)).saturating_add(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
        >= now_ms
}

/// The specification's `is_future_epoch`: the wall clock, with the gossip
/// clock disparity allowance, has not yet reached `epoch`.
pub(crate) fn is_future_epoch(config: &Config, epoch: Epoch, now_ms: u64) -> bool {
    let since_genesis_ms = now_ms
        .saturating_sub(config.genesis_time_ms())
        .saturating_add(MAXIMUM_GOSSIP_CLOCK_DISPARITY);
    let current_slot = since_genesis_ms / config.slot_duration_ms;
    compute_epoch_at_slot(current_slot) < epoch
}

/// The specification's `is_within_epoch`: the clock, with the gossip clock
/// disparity allowance on both ends, falls somewhere in `epoch`'s own span of
/// slots.
///
/// Built from the same two-sided bound `is_within_slot_range` states
/// generally (`phase0/p2p-interface.md`), specialised to a whole epoch's
/// worth of slots: the window's far edge is the *next* epoch's first slot,
/// since `is_within_slot_range`'s own `slot_range` argument is inclusive of
/// its start and the epoch has `SLOTS_PER_EPOCH` slots.
pub(crate) fn is_within_epoch(config: &Config, epoch: Epoch, now_ms: u64) -> bool {
    let start_ms = slot_start_ms(config, compute_start_slot_at_epoch(epoch));
    if now_ms.saturating_add(MAXIMUM_GOSSIP_CLOCK_DISPARITY) < start_ms {
        return false;
    }
    let next_epoch_start_ms = slot_start_ms(config, compute_start_slot_at_epoch(epoch + 1));
    if next_epoch_start_ms.saturating_add(MAXIMUM_GOSSIP_CLOCK_DISPARITY) < now_ms {
        return false;
    }
    true
}

/// The specification's `is_current_or_previous_epoch` (`deneb/p2p-interface.md`):
/// whether the clock places `epoch` within the disparity-widened current or
/// previous epoch's window. Aggregates and subnet attestations both reject
/// (as an `IGNORE`) an epoch outside this pair, on top of
/// [`is_future_slot`]'s own per-slot check: a slot can be non-future yet still
/// name an epoch more than one boundary stale, which this catches instead.
pub(crate) fn is_current_or_previous_epoch(config: &Config, epoch: Epoch, now_ms: u64) -> bool {
    is_within_epoch(config, epoch, now_ms) || is_within_epoch(config, epoch + 1, now_ms)
}

/// Whether `slot` falls in gloas.
///
/// A gloas subnet attestation is the same `SingleAttestation` as electra's, so
/// the message's shape cannot say which rules apply; its slot's fork does.
/// (A gloas aggregate has its own container, which says so itself.)
pub(crate) fn is_gloas_slot(config: &Config, slot: Slot) -> bool {
    match config.fork_at_epoch(compute_epoch_at_slot(slot)) {
        ForkName::Gloas => true,
        ForkName::Phase0
        | ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella
        | ForkName::Deneb
        | ForkName::Electra
        | ForkName::Fulu => false,
        ForkName::Lean => lean_fork_unreachable("gossip::is_gloas_slot"),
    }
}

/// Gloas's `verify_attestation_payload_status` (`specs/gloas/p2p-interface.md`):
/// the payload flag a vote carries in `data.index` must agree with what this
/// node knows of the voted block's payload.
///
/// The specification lets a vote on an unseen envelope be queued and asks the
/// node to request it by root; neither is done here, so it is an `IGNORE`.
pub fn verify_attestation_payload_status(
    store: &Store,
    data: &AttestationData,
) -> Result<(), Outcome> {
    let block_root = data.beacon_block_root;
    let Some((block_slot, _)) = store.block_slot_and_state_root(&block_root) else {
        // The caller has already checked the block is known.
        return Err(Outcome::Ignore(IgnoreReason::UnknownBlock));
    };
    payload_vote_verdict(
        block_slot,
        data,
        || fork_choice::is_payload_verified(store, block_root),
        || fork_choice::block_payload_status(store, block_root),
    )
}

/// The branches of [`verify_attestation_payload_status`], over the facts it
/// reads. The envelope and status lookups are lazy: only a vote for the full
/// payload needs either.
fn payload_vote_verdict(
    block_slot: Slot,
    data: &AttestationData,
    is_payload_verified: impl FnOnce() -> bool,
    payload_status: impl FnOnce() -> PayloadStatusEnum,
) -> Result<(), Outcome> {
    // [REJECT] For same-slot attestations, the payload cannot yet be present.
    if block_slot == data.slot && data.index != 0 {
        return Err(Outcome::Reject(RejectReason::SameSlotPayloadFlag));
    }
    if data.index != 1 {
        return Ok(());
    }
    // [IGNORE] The envelope has been seen and verified.
    if !is_payload_verified() {
        return Err(Outcome::Ignore(IgnoreReason::PayloadEnvelopeUnseen));
    }
    let status = payload_status();
    // [IGNORE] The attested payload is optimistic.
    if status.is_not_validated() {
        return Err(Outcome::Ignore(IgnoreReason::PayloadOptimistic));
    }
    // [REJECT] The attested payload is processed and invalid.
    if status.is_invalidated() {
        return Err(Outcome::Reject(RejectReason::PayloadInvalid));
    }
    Ok(())
}

/// Which block `state`'s own history names as the ancestor at `slot`, given
/// that `state` is `at_block_root`'s post-state.
///
/// `get_block_root_at_slot` only answers for a slot strictly before the
/// state's own (a state cannot look up the `block_roots` entry its own block
/// is about to write). `at_block_root` is the right answer for its own slot
/// and, since every caller here only ever asks for a checkpoint at or before
/// the vote block, for anything at or after it too. `None` means the slot
/// lies outside `state`'s `SLOTS_PER_HISTORICAL_ROOT` window: this state
/// simply cannot answer, which is not the same as there being no ancestor,
/// so callers treat it as unknown (`IGNORE`) rather than a failed check
/// (`REJECT`).
///
/// Shared by [`aggregate`] and [`attestation`] for both of their ancestry
/// checks (the target checkpoint and the finalized checkpoint), since both
/// read it off the same vote block's post-state; see that state's choice
/// documented on [`aggregate::stateful_checks`].
pub(crate) fn ancestor_at(state: &BeaconState, at_block_root: Root, slot: Slot) -> Option<Root> {
    if slot >= state.slot() {
        Some(at_block_root)
    } else {
        get_block_root_at_slot(state, slot).ok()
    }
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

    fn vote(slot: Slot, index: u64) -> AttestationData {
        AttestationData {
            slot,
            index,
            ..Default::default()
        }
    }

    fn never() -> bool {
        unreachable!("a vote that does not claim the full payload reads no envelope")
    }

    fn no_status() -> PayloadStatusEnum {
        unreachable!("a vote that does not claim the full payload reads no status")
    }

    #[test]
    fn a_same_slot_vote_for_the_payload_is_rejected() {
        assert_eq!(
            payload_vote_verdict(5, &vote(5, 1), never, no_status),
            Err(Outcome::Reject(RejectReason::SameSlotPayloadFlag))
        );
    }

    #[test]
    fn a_vote_without_the_payload_flag_reads_no_payload_state() {
        assert_eq!(
            payload_vote_verdict(5, &vote(5, 0), never, no_status),
            Ok(())
        );
        assert_eq!(
            payload_vote_verdict(4, &vote(5, 0), never, no_status),
            Ok(())
        );
    }

    #[test]
    fn a_full_payload_vote_without_a_verified_envelope_is_ignored() {
        assert_eq!(
            payload_vote_verdict(4, &vote(5, 1), || false, no_status),
            Err(Outcome::Ignore(IgnoreReason::PayloadEnvelopeUnseen))
        );
    }

    #[test]
    fn a_full_payload_vote_judges_the_execution_verdict() {
        let verdict = |status| payload_vote_verdict(4, &vote(5, 1), || true, move || status);
        assert_eq!(verdict(PayloadStatusEnum::Valid), Ok(()));
        for status in [PayloadStatusEnum::Syncing, PayloadStatusEnum::Accepted] {
            assert_eq!(
                verdict(status),
                Err(Outcome::Ignore(IgnoreReason::PayloadOptimistic))
            );
        }
        for status in [
            PayloadStatusEnum::Invalid,
            PayloadStatusEnum::InvalidBlockHash,
        ] {
            assert_eq!(
                verdict(status),
                Err(Outcome::Reject(RejectReason::PayloadInvalid))
            );
        }
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
    fn the_current_slot_holds_within_the_clock_disparity_at_either_edge() {
        let config = Config {
            genesis_time: 0,
            ..Config::mainnet()
        };
        let start_ms = slot_start_ms(&config, 3);
        let next_start_ms = slot_start_ms(&config, 4);
        assert!(is_current_slot(
            &config,
            3,
            start_ms - MAXIMUM_GOSSIP_CLOCK_DISPARITY
        ));
        assert!(!is_current_slot(
            &config,
            3,
            start_ms - MAXIMUM_GOSSIP_CLOCK_DISPARITY - 1
        ));
        assert!(is_current_slot(
            &config,
            3,
            next_start_ms + MAXIMUM_GOSSIP_CLOCK_DISPARITY
        ));
        assert!(!is_current_slot(
            &config,
            3,
            next_start_ms + MAXIMUM_GOSSIP_CLOCK_DISPARITY + 1
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
    fn a_block_column_key_records_once_per_root_and_index() {
        let mut seen = SeenBlockColumns::new(capacity(4));
        let root = Root::from([1; 32]);
        assert!(seen.record(root, 0));
        assert!(!seen.record(root, 0));
        assert!(seen.record(root, 1));
        assert!(seen.record(Root::from([2; 32]), 0));
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

    #[test]
    fn an_epoch_window_holds_only_within_the_clock_disparity_at_either_edge() {
        let config = Config {
            genesis_time: 0,
            ..Config::mainnet()
        };
        let epoch = 5;
        let start_ms = slot_start_ms(&config, compute_start_slot_at_epoch(epoch));
        let next_start_ms = slot_start_ms(&config, compute_start_slot_at_epoch(epoch + 1));

        // The near edge: the disparity allowance lets the clock run early.
        assert!(is_within_epoch(
            &config,
            epoch,
            start_ms - MAXIMUM_GOSSIP_CLOCK_DISPARITY
        ));
        assert!(!is_within_epoch(
            &config,
            epoch,
            start_ms - MAXIMUM_GOSSIP_CLOCK_DISPARITY - 1
        ));
        // The far edge: the same allowance lets the clock run late.
        assert!(is_within_epoch(
            &config,
            epoch,
            next_start_ms + MAXIMUM_GOSSIP_CLOCK_DISPARITY
        ));
        assert!(!is_within_epoch(
            &config,
            epoch,
            next_start_ms + MAXIMUM_GOSSIP_CLOCK_DISPARITY + 1
        ));
    }

    #[test]
    fn current_or_previous_epoch_covers_exactly_two_epochs() {
        use crate::beacon::preset;

        let config = Config {
            genesis_time: 0,
            ..Config::mainnet()
        };
        let epoch = 5;
        // Comfortably inside the epoch rather than at either boundary: right
        // at a boundary, the clock disparity allowance deliberately makes
        // the adjacent epoch's window overlap too (covered by
        // `an_epoch_window_holds_only_within_the_clock_disparity_at_either_edge`),
        // which would widen this to three epochs instead of the two this
        // test means to pin down.
        let now_ms = slot_start_ms(&config, compute_start_slot_at_epoch(epoch))
            + preset::SLOTS_PER_EPOCH / 2 * config.slot_duration_ms;

        assert!(is_current_or_previous_epoch(&config, epoch, now_ms));
        assert!(is_current_or_previous_epoch(&config, epoch - 1, now_ms));
        assert!(!is_current_or_previous_epoch(&config, epoch - 2, now_ms));
        assert!(!is_current_or_previous_epoch(&config, epoch + 1, now_ms));
    }

    #[test]
    fn ancestor_at_answers_itself_at_or_after_its_own_slot_and_block_roots_before_it() {
        use crate::beacon::preset;

        let mut state = crate::beacon::helpers::test_state::with_validators(4);
        let at_block_root = Root::repeat_byte(0xaa);
        let historical_slot = state.slot() - 1;
        let historical_root = Root::repeat_byte(0x11);
        state.block_roots_mut()[historical_slot as usize % preset::SLOTS_PER_HISTORICAL_ROOT] =
            historical_root;

        // Strictly before the state's own slot: reads `block_roots`.
        assert_eq!(
            ancestor_at(&state, at_block_root, historical_slot),
            Some(historical_root)
        );
        // At, or after, the state's own slot: the block itself.
        assert_eq!(
            ancestor_at(&state, at_block_root, state.slot()),
            Some(at_block_root)
        );
        assert_eq!(
            ancestor_at(&state, at_block_root, state.slot() + 5),
            Some(at_block_root)
        );

        // Older than the state's `SLOTS_PER_HISTORICAL_ROOT` window: this
        // state cannot answer, so the ancestor is unknown rather than absent.
        *state.slot_mut() = preset::SLOTS_PER_HISTORICAL_ROOT as Slot + 10;
        assert_eq!(ancestor_at(&state, at_block_root, 0), None);
    }
}
