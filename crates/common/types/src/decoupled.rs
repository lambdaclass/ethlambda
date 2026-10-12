//! Decoupled consensus protocol payloads, shared by both chains.
//!
//! The unsigned objects of the decoupled consensus protocol (Goldfish votes,
//! combined attestations, the finality gadget's chain state), as formalized in
//! `fradamt/verified-consensus` (`docs/PROTOCOL.md`). The protocol logic lives
//! in `ethlambda-decoupled`; these live here so that the lean and the beacon
//! wire containers, which this crate defines, can embed them.
//!
//! SSZ has no `Option`, so an optional field is a list of at most one
//! element, which keeps the encoding canonical.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszBitlist, SszList};
use serde::{Deserialize, Serialize};

use crate::primitives::H256;

pub type Slot = u64;
pub type Round = u64;
pub type Height = u64;
pub type ValidatorIndex = u64;

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

/// One bit per validator, sized to the electorate.
pub type ValidatorBits = SszBitlist<VALIDATOR_LIMIT>;

/// The chain state σ (§1.3).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, SszEncode, SszDecode, HashTreeRoot,
)]
pub struct ChainState {
    /// `L`: the latest block.
    pub latest: BlockRef,
    /// `s = L.slot`.
    pub slot: Slot,
    /// `h`: the current height.
    pub height: Height,
    /// `T_h`: the block that brought the chain into height `h`.
    pub entry: BlockRef,
    /// `nj`: computed on entry into `h`, fixed until the height changes.
    pub nonjustifiable: bool,
    /// `target_participation`, `Q_target`.
    #[serde(skip)]
    pub target_participation: ValidatorBits,
    /// `progress`, `Q_prog`.
    #[serde(skip)]
    pub progress: ValidatorBits,
    /// `finalize`, `Q_finality`.
    #[serde(skip)]
    pub finalize: ValidatorBits,
    /// `J`: the latest justification on the chain.
    pub justified: BlockRef,
    /// `h_j`: its height.
    pub justified_height: Height,
    /// `F`: the latest finalization on the chain.
    pub finalized: BlockRef,
    /// `h_F`: its height.
    pub finalized_height: Height,
}

impl ChainState {
    /// The initial state: `L = T_h = J = F = B_gen`, `s = 0`, `h = 1`,
    /// `h_j = h_F = 0`, `nj = false`, every bit clear (§1.3).
    ///
    /// `anchor` is genesis on a chain that runs the protocol from slot 0.
    pub fn initial(anchor: BlockRef, validator_count: usize) -> Self {
        let empty = empty_bits(validator_count);
        Self {
            latest: anchor,
            slot: anchor.slot,
            height: 1,
            entry: anchor,
            nonjustifiable: false,
            target_participation: empty.clone(),
            progress: empty.clone(),
            finalize: empty,
            justified: anchor,
            justified_height: 0,
            finalized: anchor,
            finalized_height: 0,
        }
    }
}

fn empty_bits(validator_count: usize) -> ValidatorBits {
    ValidatorBits::with_length(validator_count).expect("validator count within the registry limit")
}

/// A node's view of the three chains and the finality gadget, for operators
/// and tests: what `GET /lean/v0/decoupled/status` and the beacon node's
/// decoupled status endpoint serve.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecoupledStatus {
    /// The node's protocol clock.
    pub slot: Slot,
    pub round: Round,
    /// The fork-choice head.
    pub head: BlockRef,
    /// `get_confirmed(Σ)`: the available chain's tip.
    pub confirmed: BlockRef,
    /// `get_stable(Σ)`: the stable chain's tip.
    pub stable: BlockRef,
    /// `Σ.F` and the height it was justified at.
    pub finalized: BlockRef,
    pub finalized_height: Height,
    /// `Σ.J`, `Σ.h_j`.
    pub justified: BlockRef,
    pub justified_height: Height,
    /// `Σ.h_max`.
    pub max_height: Height,
    /// `Σ.live_confirmed`, the protocol-facing confirmation.
    pub live_confirmed: H256,
    /// Blocks in the processed tree.
    pub blocks: u64,
}

/// The latest [`DecoupledStatus`], written by a chain actor and read by the
/// HTTP server. `None` until the actor's first tick.
pub type SharedDecoupledStatus = std::sync::Arc<std::sync::RwLock<Option<DecoupledStatus>>>;
