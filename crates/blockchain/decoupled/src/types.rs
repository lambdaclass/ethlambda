//! Engine-side types (PROTOCOL.md §1, appendix A.2/A.6/A.9).
//!
//! The wire payloads (votes, attestations, the chain state) live in
//! [`ethlambda_types::decoupled`] so both chains' containers can embed them;
//! they are re-exported here. Each chain wraps them in its own signed envelope
//! (XMSS on lean, BLS on the beacon chain), so the engine never sees a
//! signature: signature, committee and proposer checks are the host's job and
//! happen before an object reaches a handler.

use ethlambda_types::primitives::H256;

pub use ethlambda_types::decoupled::{
    Attestation, AttestationData, BlockRef, FinalityVote, GoldfishVote, Height, HeightVote,
    Round, SgKey, Slot, VALIDATOR_LIMIT, ValidatorIndex,
};

/// Time on the protocol's public grid, in units of `Δ` since genesis.
///
/// Slot `s` starts at `4s` (`t_s = 4Δs`). Every public time of the protocol is
/// a multiple of `Δ`, so integer ticks represent all of them exactly. An object
/// processed between two public times is stamped with the earlier one
/// (PROTOCOL.md §2), which is `floor(elapsed / Δ)`.
pub type Tick = i64;

/// The protocol content of a block, as the engine's `on_block` reads it
/// (appendix A.2 and §1.4): identity, the carried Goldfish votes and their
/// proposal-time support subset, and the carried combined attestations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockInput {
    pub root: H256,
    pub parent_root: H256,
    pub slot: Slot,
    pub proposer: ValidatorIndex,
    /// `B.votes`: slot-`(B.slot − 1)` Goldfish votes.
    pub votes: Vec<GoldfishVote>,
    /// `B.support_votes ⊆ B.votes`: the members resolved at proposal time.
    pub support_votes: Vec<GoldfishVote>,
    /// `B.attestations`: combined attestations, read by the state transition
    /// and offered to the SG pool.
    pub attestations: Vec<Attestation>,
}

/// Validator weights (appendix A.6): `w(v)`, `W` and the quorum `q = ⌈2W/3⌉`.
///
/// The validator set is fixed for an execution (MODELING_CHOICES §5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Electorate {
    weights: Vec<u64>,
    total: u64,
}

impl Electorate {
    pub fn new(weights: Vec<u64>) -> Self {
        let total = weights.iter().sum();
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

    /// `W = w(V)`.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// `q = ⌈2W/3⌉`.
    pub fn quorum(&self) -> u64 {
        (2 * self.total).div_ceil(3)
    }
}
