//! Decoupled consensus protocol payloads, shared by both chains.
//!
//! The unsigned objects of Goldilocks (Goldfish votes, finality attestations,
//! the finality gadget's chain state): Goldfish with locks as the available
//! chain, composed with a height-based finality gadget, as the Goldilocks
//! specification defines them. The protocol logic lives in
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
/// T_f)`, a height pair and an optional finality pair.
///
/// Attestations are pure finality votes: there is no round and no safe block.
/// This is what validators sign, and what the beacon host aggregates over:
/// honest validators with the same view emit identical data. A handler admits
/// one only when it is [well formed](AttestationData::is_well_formed).
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, SszEncode, SszDecode, HashTreeRoot,
)]
#[serde(into = "AttestationDataJson", from = "AttestationDataJson")]
pub struct AttestationData {
    pub height_pair: HeightVote,
    pub finality_pair: SszList<FinalityVote, 1>,
}

impl AttestationData {
    pub fn new(height_pair: HeightVote, finality_pair: Option<FinalityVote>) -> Self {
        Self {
            height_pair,
            finality_pair: option_list(finality_pair),
        }
    }

    pub fn height_pair(&self) -> HeightVote {
        self.height_pair
    }

    pub fn finality_pair(&self) -> Option<FinalityVote> {
        self.finality_pair.first().copied()
    }

    /// The forms of the spec's section 2: a height pair at a height `h ≥ 1`,
    /// and a finality pair that is absent or below it (`h_f < h`).
    pub fn is_well_formed(&self) -> bool {
        let height = self.height_pair.height;
        height >= 1 && self.finality_pair().is_none_or(|pair| pair.height < height)
    }
}

/// The JSON shape of [`AttestationData`]: an absent finality pair is `null`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttestationDataJson {
    height_pair: HeightVote,
    finality_pair: Option<FinalityVote>,
}

impl From<AttestationData> for AttestationDataJson {
    fn from(data: AttestationData) -> Self {
        Self {
            height_pair: data.height_pair,
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

/// One entry of `σ.pending_finality`: a justification `(j, T)` above `h_F`
/// that is not finalized yet, with its `finality_participation[j]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingFinality {
    /// `j`: the height `T` was justified at.
    pub height: Height,
    /// `T`.
    pub target: BlockRef,
    /// `finality_participation[j]`, whose set is `Q_fin(σ, j)`.
    #[serde(skip)]
    pub participation: ValidatorBits,
}

/// The chain state σ of the finality gadget.
///
/// Node-derived and never on the wire, so it has no SSZ encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainState {
    /// `L`: the latest block.
    pub latest: BlockRef,
    /// `s = L.slot`.
    pub slot: Slot,
    /// `h`: the current height.
    pub height: Height,
    /// `T_h`: the block that brought the chain into height `h`.
    pub entry: BlockRef,
    /// `target_participation`, `Q_target`.
    #[serde(skip)]
    pub target_participation: ValidatorBits,
    /// `progress`, `Q_prog`.
    #[serde(skip)]
    pub progress: ValidatorBits,
    /// `pending_finality` with `finality_participation[·]`: at most `K_W`
    /// justifications in increasing height, each with `h_F < j ≤ h_j`.
    pub pending_finality: Vec<PendingFinality>,
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
    /// `h_j = h_F = 0`, every bit clear, nothing pending.
    ///
    /// `anchor` is genesis on a chain that runs the protocol from slot 0.
    pub fn initial(anchor: BlockRef, validator_count: usize) -> Self {
        let empty = empty_bits(validator_count);
        Self {
            latest: anchor,
            slot: anchor.slot,
            height: 1,
            entry: anchor,
            target_participation: empty.clone(),
            progress: empty,
            pending_finality: Vec::new(),
            justified: anchor,
            justified_height: 0,
            finalized: anchor,
            finalized_height: 0,
        }
    }

    /// The entry of `pending_finality` that a finality pair names, if any.
    pub fn pending(&self, pair: &FinalityVote) -> Option<&PendingFinality> {
        self.pending_finality
            .iter()
            .find(|pending| pending.height == pair.height && pending.target.root == pair.target)
    }
}

fn empty_bits(validator_count: usize) -> ValidatorBits {
    ValidatorBits::with_length(validator_count).expect("validator count within the registry limit")
}

/// A live lock entry of the available chain: `block` (and every ancestor)
/// stays locked until the entry expires at the vote time of slot `deadline`.
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
    /// The available tip `AC_CONFIRMED`: the confirmation record while it
    /// is in the tree, else `Σ.F`.
    pub confirmed: BlockRef,
    /// The source an FG action would read now: the deepest block of the
    /// full viable tree that the latest confirmation update locked by the
    /// fast test. Its state supplies the height pair of attestations.
    pub source: Option<BlockRef>,
    /// The live lock entries, deepest first.
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
