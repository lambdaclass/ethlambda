//! Engine-side types: what a host hands the engine, and the AC vote the walks
//! count.
//!
//! The wire payloads (`HeightCheckpoint`, `AttestationData`, `HeadVoteData`,
//! `HeadVoteMessage`, `ForkChoiceNode`) live in [`ethlambda_types::decoupled`]
//! and are re-exported here. Each chain wraps them in its own signed envelope
//! (XMSS on lean, BLS on the beacon chain), so the engine never sees a
//! signature: signature checks happen before an object reaches a handler.

use std::collections::{BTreeMap, HashMap};

use ethlambda_types::primitives::H256;

pub use ethlambda_types::decoupled::{
    AttestationData, BlockRef, ForkChoiceNode, HeadVoteData, HeadVoteMessage, Height,
    HeightCheckpoint, PayloadStatus, Round, Slot, ValidatorIndex,
};

/// Time on the protocol's public grid, in units of `Δ` since genesis (see
/// [`crate::params`]).
pub type Tick = i64;

/// `INFINITE_TIME_MS`: the resolution time of a vote that does not resolve,
/// and the threshold that admits every received object.
pub const INFINITE_TIME: Tick = Tick::MAX;

/// A head vote carried by a block (`HeadVote` without its signature): the
/// voters of one aggregate and the data they signed. A lean block carries one
/// voter per entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadVote {
    pub voter_indices: Vec<ValidatorIndex>,
    pub data: HeadVoteData,
}

/// `ACVote`: one validator's head vote, in a form fit for set operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AcVote {
    pub slot: Slot,
    pub validator_index: ValidatorIndex,
    pub supported_node: ForkChoiceNode,
}

/// The finality gadget's checkpoints of a block's post-state: what the fork
/// choice reads from `store.block_states[root]`.
///
/// A beacon host reads them from the `BeaconState`; lean derives them with
/// [`crate::chain_state`]. A `target.root` left empty because the block itself
/// advanced the height (`advance_height`) is filled with the block's own root
/// on admission, as the next `process_slot` would.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FgCheckpoints {
    /// `state.target_checkpoint`: the current height and its target.
    pub target: HeightCheckpoint,
    /// `state.justified_checkpoint`.
    pub justified: HeightCheckpoint,
    /// `state.finalized_checkpoint`.
    pub finalized: HeightCheckpoint,
}

/// What `on_block` reads of a block.
///
/// The host has already run the block's state transition (signatures,
/// proposer, `process_head_vote`, `process_attestation`), so the engine sees
/// only fork-choice content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockInput {
    pub root: H256,
    pub parent_root: H256,
    pub slot: Slot,
    /// `get_parent_payload_status`: which of the parent's payload branches the
    /// block builds on, `Empty` or `Full`. Always `Empty` on a host without
    /// payloads.
    pub parent_payload_status: PayloadStatus,
    /// `body.head_votes`.
    pub head_votes: Vec<HeadVote>,
    /// `body.head_vote_support`: one bit per voter of each head vote.
    pub head_vote_support: Vec<Vec<bool>>,
    /// The post-state's finality gadget checkpoints.
    pub fg: FgCheckpoints,
}

/// The block a store starts from (`get_forkchoice_store`'s anchor), trusted as
/// justified and finalized at its post-state's target height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchor {
    pub root: H256,
    pub slot: Slot,
    /// The anchor's post-state checkpoints. `target.root` must be the anchor
    /// (`get_forkchoice_store` asserts it after `process_slot`).
    pub fg: FgCheckpoints,
}

/// Validator weights in finality gadget quorums: `get_validator_weight` for
/// the active, unslashed validators, and `get_total_weight` of the active set.
///
/// Lean gives every validator weight one. A beacon host reads quorums from its
/// own `BeaconState` instead, and never builds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Electorate {
    weights: Vec<u64>,
    total: u128,
}

impl Electorate {
    pub fn new(weights: Vec<u64>) -> Self {
        let total = weights.iter().map(|&w| u128::from(w)).sum();
        Self { weights, total }
    }

    /// Every validator weighs one, as on the lean chain.
    pub fn uniform(validator_count: usize) -> Self {
        Self::new(vec![1; validator_count])
    }

    pub fn len(&self) -> usize {
        self.weights.len()
    }

    pub fn is_empty(&self) -> bool {
        self.weights.is_empty()
    }

    pub fn weight(&self, validator: ValidatorIndex) -> u64 {
        usize::try_from(validator)
            .ok()
            .and_then(|i| self.weights.get(i).copied())
            .unwrap_or(0)
    }

    /// `get_total_weight` of the active validators.
    pub fn total(&self) -> u128 {
        self.total
    }
}

/// One slot's head vote committee: the seats, possibly several per validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadVoteCommittee {
    members: Vec<ValidatorIndex>,
    seats: HashMap<ValidatorIndex, u64>,
}

impl HeadVoteCommittee {
    pub fn new(members: Vec<ValidatorIndex>) -> Self {
        let mut seats = HashMap::new();
        for &member in &members {
            *seats.entry(member).or_insert(0) += 1;
        }
        Self { members, seats }
    }

    pub fn members(&self) -> &[ValidatorIndex] {
        &self.members
    }

    fn seats(&self, validator: ValidatorIndex) -> u64 {
        self.seats.get(&validator).copied().unwrap_or(0)
    }
}

/// Where the engine reads head vote committee seats from
/// (`get_validator_seats_count`, `get_head_vote_committee_seats_count`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadVoteCommittees {
    /// Every validator holds one seat in every slot's committee: lean.
    EveryValidator { validator_count: u64 },
    /// Committees of `size` seats the host records per slot
    /// (`record_head_vote_committee`) before handing the engine a vote of that
    /// slot: the beacon chain's `HEAD_VOTE_COMMITTEE_SIZE` balance-sampled
    /// seats (`get_head_vote_committee`).
    Recorded {
        size: u64,
        by_slot: BTreeMap<Slot, HeadVoteCommittee>,
    },
}

impl HeadVoteCommittees {
    /// Recorded committees of `size` seats, none recorded yet.
    pub fn recorded(size: u64) -> Self {
        Self::Recorded {
            size,
            by_slot: BTreeMap::new(),
        }
    }

    /// `get_head_vote_committee_seats_count()`.
    pub fn seats_count(&self) -> u64 {
        match self {
            Self::EveryValidator { validator_count } => *validator_count,
            Self::Recorded { size, .. } => *size,
        }
    }

    /// `get_validator_seats_count(store, slot, validator_index)`. The spec
    /// asserts the slot's committee is recorded; an unrecorded one gives no
    /// seats here, so a vote of an unrecorded slot weighs nothing.
    pub fn seats(&self, slot: Slot, validator: ValidatorIndex) -> u64 {
        match self {
            Self::EveryValidator { validator_count } => u64::from(validator < *validator_count),
            Self::Recorded { by_slot, .. } => by_slot
                .get(&slot)
                .map_or(0, |committee| committee.seats(validator)),
        }
    }

    /// Whether the committee of `slot` is known.
    pub fn is_recorded(&self, slot: Slot) -> bool {
        match self {
            Self::EveryValidator { .. } => true,
            Self::Recorded { by_slot, .. } => by_slot.contains_key(&slot),
        }
    }
}
