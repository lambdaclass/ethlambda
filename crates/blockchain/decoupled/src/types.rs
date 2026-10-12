//! Protocol objects (PROTOCOL.md §1, appendix A.2/A.6/A.9).
//!
//! These are the *unsigned* protocol payloads. Each chain wraps them in its
//! own signed envelope (XMSS on lean, BLS on the beacon chain), so the engine
//! never sees a signature: signature, committee and proposer checks are the
//! host's job and happen before an object reaches a handler.
//!
//! The payloads are SSZ containers so the hosts can embed them verbatim in
//! their wire types and sign their `hash_tree_root`. SSZ has no `Option`, so an
//! optional field is a list of at most one element; that keeps the encoding
//! canonical (an absent field has exactly one representation).

use ethlambda_types::primitives::H256;
use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::SszList;
use serde::{Deserialize, Serialize};

pub type Slot = u64;
pub type Round = u64;
pub type Height = u64;
pub type ValidatorIndex = u64;

/// Time on the protocol's public grid, in units of `Δ` since genesis.
///
/// Slot `s` starts at `4s` (`t_s = 4Δs`). Every public time of the protocol is
/// a multiple of `Δ`, so integer ticks represent all of them exactly. An object
/// processed between two public times is stamped with the earlier one
/// (PROTOCOL.md §2), which is `floor(elapsed / Δ)`.
pub type Tick = i64;

/// The upper bound used for every per-validator bit list.
///
/// Matches the beacon chain's `VALIDATOR_REGISTRY_LIMIT`, so one chain-state
/// type serves both chains.
pub const VALIDATOR_LIMIT: usize = 1 << 40;

/// A Goldfish vote `(val_index, s, B)` (appendix A.2): validator `validator`,
/// a member of slot `slot`'s committee, votes for head `head`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct GoldfishVote {
    pub validator: ValidatorIndex,
    pub slot: Slot,
    pub head: H256,
}

/// A height pair `(h, T, τ)` (appendix A.9).
///
/// `timeout = false` is a target vote naming the block `entry` that brought
/// the chain into height `height`. `timeout = true` is a timeout; it still
/// names the entry it times out at, and a chain counts it only when the entry
/// is the chain's own (the formalization's `matchesEntry`).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct HeightVote {
    pub height: Height,
    pub entry: H256,
    pub timeout: bool,
}

/// A finality pair `(h_f, T_f)` with `T_f ≠ ⊥` (appendix A.9).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct FinalityVote {
    pub height: Height,
    pub target: H256,
}

/// Everything a combined attestation says, minus the signer (appendix A.9):
/// `(round, safe, height pair, finality pair)`.
///
/// This is what validators sign, and what the beacon host aggregates over:
/// honest validators with the same view emit identical data.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Default,
    Serialize,
    Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
#[serde(into = "AttestationDataJson", from = "AttestationDataJson")]
pub struct AttestationData {
    pub round: Round,
    /// The safe block, or empty for `⊥`. Honest validators always vote a
    /// block; `⊥` only appears in adversarial votes.
    pub safe: SszList<H256, 1>,
    pub height_pair: SszList<HeightVote, 1>,
    pub finality_pair: SszList<FinalityVote, 1>,
}

impl AttestationData {
    pub fn new(
        round: Round,
        safe: Option<H256>,
        height_pair: Option<HeightVote>,
        finality_pair: Option<FinalityVote>,
    ) -> Self {
        Self {
            round,
            safe: option_list(safe),
            height_pair: option_list(height_pair),
            finality_pair: option_list(finality_pair),
        }
    }

    pub fn safe(&self) -> Option<H256> {
        self.safe.first().copied()
    }

    pub fn height_pair(&self) -> Option<HeightVote> {
        self.height_pair.first().copied()
    }

    pub fn finality_pair(&self) -> Option<FinalityVote> {
        self.finality_pair.first().copied()
    }
}

/// The JSON shape of [`AttestationData`]: absent fields are `null`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttestationDataJson {
    round: Round,
    safe: Option<H256>,
    height_pair: Option<HeightVote>,
    finality_pair: Option<FinalityVote>,
}

impl From<AttestationData> for AttestationDataJson {
    fn from(data: AttestationData) -> Self {
        Self {
            round: data.round,
            safe: data.safe(),
            height_pair: data.height_pair(),
            finality_pair: data.finality_pair(),
        }
    }
}

impl From<AttestationDataJson> for AttestationData {
    fn from(json: AttestationDataJson) -> Self {
        Self::new(json.round, json.safe, json.height_pair, json.finality_pair)
    }
}

fn option_list<T>(value: Option<T>) -> SszList<T, 1> {
    let items: Vec<T> = value.into_iter().collect();
    SszList::try_from(items).expect("at most one element fits a list of one")
}

/// A combined attestation `(val_index, round, safe, h, T, τ, h_f, T_f)`
/// (appendix A.9). Its SG projection is `(validator, round, safe)`.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, SszEncode, SszDecode, HashTreeRoot,
)]
pub struct Attestation {
    pub validator: ValidatorIndex,
    pub data: AttestationData,
}

impl Attestation {
    pub fn round(&self) -> Round {
        self.data.round
    }

    /// The SG projection `(val_index, round, safe)` every SG rule and grade
    /// reads (PROTOCOL.md §1.4).
    pub fn sg_key(&self) -> SgKey {
        SgKey {
            validator: self.validator,
            round: self.data.round,
            safe: self.data.safe(),
        }
    }
}

/// The SG projection of a combined attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SgKey {
    pub validator: ValidatorIndex,
    pub round: Round,
    pub safe: Option<H256>,
}

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

/// A block identified by root and slot. The chain state keeps these instead
/// of whole blocks: the slot of the height entry gates timeouts, and the slot
/// of a justified or finalized block maps it to a host checkpoint.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct BlockRef {
    pub root: H256,
    pub slot: Slot,
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
