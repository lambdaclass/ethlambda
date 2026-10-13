//! Decoupled consensus protocol payloads, shared by both chains.
//!
//! The unsigned objects of Goldilocks (Goldfish votes, finality attestations,
//! the finality gadget's chain state): Goldfish with locks as the available
//! chain, composed with the height-based finality gadget of
//! `fradamt/verified-consensus`. The protocol logic lives in
//! `ethlambda-decoupled`; these live here so that the lean and the beacon wire
//! containers, which this crate defines, can embed them.
//!
//! SSZ has no `Option`, so an optional field is a list of at most one
//! element, which keeps the encoding canonical.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszBitlist, SszList};
use serde::{Deserialize, Serialize};

use crate::primitives::H256;

pub type Slot = u64;
pub type Height = u64;
pub type ValidatorIndex = u64;

/// The upper bound used for every per-validator bit list.
///
/// Matches the beacon chain's `VALIDATOR_REGISTRY_LIMIT`, so one chain-state
/// type serves both chains.
pub const VALIDATOR_LIMIT: usize = 1 << 40;

/// A Goldfish vote `(val_index, s, B)`: validator `validator`, a member of
/// slot `slot`'s committee, votes for head `head`.
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

/// A height pair `(h, T, timeout)`.
///
/// `timeout = false` is a target vote naming the block `entry` that brought
/// the chain into height `height`. `timeout = true` is a timeout; it still
/// names the entry it times out at, and a chain counts it only when the entry
/// is the chain's own.
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

/// A finality pair `(h_f, T_f)`: a vote to finalize the justification `T_f`
/// made at height `h_f`.
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

/// Everything an attestation says, minus the signer: `(h, T, timeout, h_f,
/// T_f)`, a height pair and a finality pair, either of which may be absent.
///
/// Attestations are pure finality votes: there is no round and no safe block.
/// This is what validators sign, and what the beacon host aggregates over:
/// honest validators with the same view emit identical data, whenever they
/// attest.
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
    pub height_pair: SszList<HeightVote, 1>,
    pub finality_pair: SszList<FinalityVote, 1>,
}

impl AttestationData {
    pub fn new(height_pair: Option<HeightVote>, finality_pair: Option<FinalityVote>) -> Self {
        Self {
            height_pair: option_list(height_pair),
            finality_pair: option_list(finality_pair),
        }
    }

    pub fn height_pair(&self) -> Option<HeightVote> {
        self.height_pair.first().copied()
    }

    pub fn finality_pair(&self) -> Option<FinalityVote> {
        self.finality_pair.first().copied()
    }

    /// Neither pair: an attestation that says nothing.
    pub fn is_empty(&self) -> bool {
        self.height_pair.is_empty() && self.finality_pair.is_empty()
    }
}

/// The JSON shape of [`AttestationData`]: absent fields are `null`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttestationDataJson {
    height_pair: Option<HeightVote>,
    finality_pair: Option<FinalityVote>,
}

impl From<AttestationData> for AttestationDataJson {
    fn from(data: AttestationData) -> Self {
        Self {
            height_pair: data.height_pair(),
            finality_pair: data.finality_pair(),
        }
    }
}

impl From<AttestationDataJson> for AttestationData {
    fn from(json: AttestationDataJson) -> Self {
        Self::new(json.height_pair, json.finality_pair)
    }
}

fn option_list<T>(value: Option<T>) -> SszList<T, 1> {
    let items: Vec<T> = value.into_iter().collect();
    SszList::try_from(items).expect("at most one element fits a list of one")
}

/// An attestation `(validator, h, T, timeout, h_f, T_f)`.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, SszEncode, SszDecode, HashTreeRoot,
)]
pub struct Attestation {
    pub validator: ValidatorIndex,
    pub data: AttestationData,
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

/// The chain state σ of the finality gadget.
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
    /// `h_j = h_F = 0`, `nj = false`, every bit clear.
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

/// A live lock of the available chain: `block` stays locked for every
/// fork-choice run that reads votes of a slot before `deadline`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockStatus {
    pub block: BlockRef,
    pub deadline: Slot,
}

/// A node's view of the available chain and the finality gadget, for
/// operators and tests: what `GET /lean/v0/decoupled/status` and the beacon
/// node's decoupled status endpoint serve.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecoupledStatus {
    /// The node's protocol clock.
    pub slot: Slot,
    /// The fork-choice head.
    pub head: BlockRef,
    /// The confirmed (locked) tip: the fork-choice anchor when it is a live
    /// lock, else `Σ.F`.
    pub confirmed: BlockRef,
    /// The deepest block the latest confirmation update fast locked, whose
    /// state supplies the height pair of attestations.
    pub fg_confirmed: Option<BlockRef>,
    /// The live locks, deepest first.
    pub locks: Vec<LockStatus>,
    /// `Σ.F` and the height it was justified at.
    pub finalized: BlockRef,
    pub finalized_height: Height,
    /// `Σ.J`, `Σ.h_j`.
    pub justified: BlockRef,
    pub justified_height: Height,
    /// `Σ.h_max`.
    pub max_height: Height,
    /// The fork-choice root (`Σ.J` or `Σ.F`) and the height every viable
    /// branch must reach.
    pub fc_root: BlockRef,
    pub height_floor: Height,
    /// Blocks in the processed tree.
    pub blocks: u64,
}

/// The latest [`DecoupledStatus`], written by a chain actor and read by the
/// HTTP server. `None` until the actor's first tick.
pub type SharedDecoupledStatus = std::sync::Arc<std::sync::RwLock<Option<DecoupledStatus>>>;
