//! Fork-choice test fixture types.
//!
//! Used both by the offline spec-test runner and the Hive `/lean/v0/test_driver/fork_choice/*`
//! endpoints, which receive the same JSON shapes from the lean spec-assets simulator.

use crate::{
    AggregationBits, AttestationData, Block, BlockBody, Checkpoint, TestInfo, TestState,
    deser_xmss_hex,
};
use ethlambda_types::attestation::XmssSignature;
use ethlambda_types::block::{MultiMessageAggregate, SignedBlock};
use ethlambda_types::primitives::H256;
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::path::Path;

// ============================================================================
// Root Structures
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct ForkChoiceTestVector {
    #[serde(flatten)]
    pub tests: HashMap<String, ForkChoiceTest>,
}

impl ForkChoiceTestVector {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let test_vector = serde_json::from_str(&content)?;
        Ok(test_vector)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ForkChoiceTest {
    #[allow(dead_code)]
    pub network: String,
    #[serde(rename = "leanEnv")]
    #[allow(dead_code)]
    pub lean_env: String,
    #[serde(rename = "anchorState")]
    pub anchor_state: TestState,
    #[serde(rename = "anchorBlock")]
    pub anchor_block: Block,
    pub steps: Vec<ForkChoiceStep>,
    /// Aggregation proof regime: 0 = mocked (placeholder bytes, must not be
    /// verified), 1 = real and must verify, 2 = real and must fail
    /// verification. Older fixtures lack the field and carry real proofs.
    #[serde(rename = "proofSetting", default = "default_proof_setting")]
    pub proof_setting: u8,
    #[serde(rename = "maxSlot")]
    #[allow(dead_code)]
    pub max_slot: u64,
    #[serde(rename = "_info")]
    pub info: TestInfo,
}

fn default_proof_setting() -> u8 {
    1
}

impl ForkChoiceTest {
    /// Whether the vector's aggregation proofs are placeholders that must
    /// not be cryptographically verified (`proofSetting == 0`).
    pub fn proofs_are_mocked(&self) -> bool {
        self.proof_setting == 0
    }
}

// ============================================================================
// Step Types
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct ForkChoiceStep {
    /// Whether this step is expected to be accepted by the store.
    ///
    /// Defaults to `true` because the simulator omits the field when it expects
    /// success (`checks`-only steps don't carry a `valid` flag at all).
    #[serde(default = "default_true")]
    pub valid: bool,
    pub checks: Option<StoreChecks>,
    #[serde(rename = "stepType")]
    pub step_type: String,
    pub block: Option<BlockStepData>,
    pub attestation: Option<AttestationStepData>,
    /// UNIX time in seconds for `tick` steps (exclusive with `interval`).
    pub time: Option<u64>,
    /// Absolute interval count since genesis for `tick` steps (exclusive with `time`).
    pub interval: Option<u64>,
    #[serde(rename = "hasProposal")]
    pub has_proposal: Option<bool>,
    #[serde(rename = "isAggregator")]
    pub is_aggregator: Option<bool>,
    /// Whether the harness must advance the store clock to the block's slot
    /// before delivering a `block` step. Early-arrival tests set this to
    /// `false` to deliver the block ahead of the store clock.
    #[serde(rename = "tickToSlot", default = "default_true")]
    pub tick_to_slot: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct AttestationStepData {
    #[serde(rename = "validatorIndex")]
    pub validator_id: Option<u64>,
    pub data: AttestationData,
    #[serde(default, deserialize_with = "deser_opt_xmss_hex")]
    pub signature: Option<XmssSignature>,
    /// Present on `gossipAggregatedAttestation` steps.
    pub proof: Option<ProofStepData>,
}

/// Aggregated-attestation proof carried by `gossipAggregatedAttestation`
/// steps (leanSpec PR #717 schema).
///
/// `participants` arrives as `{ data: [bool, ...] }` and `proof` as
/// `{ data: "0x<hex>" }`; the latter is the lean-multisig Type-1
/// `compress_without_pubkeys()` bytes for that AttestationData.
#[derive(Debug, Clone, Deserialize)]
pub struct ProofStepData {
    pub participants: AggregationBits,
    pub proof: HexByteList,
}

/// Hex-encoded byte list in the fixture format: `{ "data": "0xdeadbeef" }`.
#[derive(Debug, Clone, Deserialize)]
pub struct HexByteList {
    data: String,
}

impl From<HexByteList> for Vec<u8> {
    fn from(value: HexByteList) -> Self {
        let stripped = value.data.strip_prefix("0x").unwrap_or(&value.data);
        hex::decode(stripped).expect("invalid hex in proof data")
    }
}

fn deser_opt_xmss_hex<'de, D>(d: D) -> Result<Option<XmssSignature>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct Wrap(#[serde(deserialize_with = "deser_xmss_hex")] XmssSignature);

    Ok(Option::<Wrap>::deserialize(d)?.map(|w| w.0))
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockStepData {
    pub slot: u64,
    #[serde(rename = "proposerIndex")]
    pub proposer_index: u64,
    #[serde(rename = "parentRoot")]
    pub parent_root: H256,
    #[serde(rename = "stateRoot")]
    pub state_root: H256,
    pub body: BlockBody,
    #[serde(rename = "blockRootLabel")]
    pub block_root_label: Option<String>,
}

impl BlockStepData {
    pub fn to_block(&self) -> ethlambda_types::block::Block {
        ethlambda_types::block::Block {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root: self.state_root,
            body: self.body.clone().into(),
        }
    }

    /// Build a `SignedBlock` with an empty proof blob.
    ///
    /// Used by callers that import the block via `on_block_without_verification`
    /// (fork-choice spec-test runner and Hive test-driver), which skip the
    /// crypto verifier entirely. The merged proof bytes are only inspected by
    /// `verify_block_signatures`, so an empty aggregate suffices.
    pub fn to_blank_signed_block(&self) -> SignedBlock {
        SignedBlock {
            message: self.to_block(),
            proof: MultiMessageAggregate::default(),
        }
    }
}

// ============================================================================
// Check Types
// ============================================================================

/// Store-state expectations for a fork choice test step.
///
/// All fields are optional; only fields explicitly set by the fixture are validated.
/// Root-typed fields have a `*RootLabel` companion that resolves a block label via the
/// step's block registry, mirroring the leanSpec fixture schema.
#[derive(Debug, Clone, Deserialize)]
pub struct StoreChecks {
    /// Expected store time in intervals since genesis.
    pub time: Option<u64>,

    #[serde(rename = "headSlot")]
    pub head_slot: Option<u64>,
    #[serde(rename = "headRoot")]
    pub head_root: Option<H256>,
    #[serde(rename = "headRootLabel")]
    pub head_root_label: Option<String>,

    #[serde(rename = "latestJustifiedSlot")]
    pub latest_justified_slot: Option<u64>,
    #[serde(rename = "latestJustifiedRoot")]
    pub latest_justified_root: Option<H256>,
    #[serde(rename = "latestJustifiedRootLabel")]
    pub latest_justified_root_label: Option<String>,

    /// camelCase alias used by Hive's spec-assets fixtures (`justifiedCheckpoint`).
    #[serde(rename = "justifiedCheckpoint")]
    pub justified_checkpoint: Option<Checkpoint>,

    #[serde(rename = "latestFinalizedSlot")]
    pub latest_finalized_slot: Option<u64>,
    #[serde(rename = "latestFinalizedRoot")]
    pub latest_finalized_root: Option<H256>,
    #[serde(rename = "latestFinalizedRootLabel")]
    pub latest_finalized_root_label: Option<String>,

    /// camelCase alias used by Hive's spec-assets fixtures (`finalizedCheckpoint`).
    #[serde(rename = "finalizedCheckpoint")]
    pub finalized_checkpoint: Option<Checkpoint>,

    /// Legacy single-field schema; expected safe target block root.
    #[serde(rename = "safeTarget")]
    pub safe_target: Option<H256>,
    /// Expected slot of the safe target block (leanSpec #680 schema).
    #[serde(rename = "safeTargetSlot")]
    pub safe_target_slot: Option<u64>,
    /// Expected safe target block root by label reference (leanSpec #680 schema).
    #[serde(rename = "safeTargetRootLabel")]
    pub safe_target_root_label: Option<String>,

    #[serde(rename = "attestationTargetSlot")]
    pub attestation_target_slot: Option<u64>,
    #[serde(rename = "attestationChecks")]
    pub attestation_checks: Option<Vec<AttestationCheck>>,
    #[serde(rename = "lexicographicHeadAmong")]
    pub lexicographic_head_among: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AttestationCheck {
    pub validator: u64,
    #[serde(rename = "attestationSlot")]
    pub attestation_slot: Option<u64>,
    #[serde(rename = "headSlot")]
    pub head_slot: Option<u64>,
    #[serde(rename = "sourceSlot")]
    pub source_slot: Option<u64>,
    #[serde(rename = "targetSlot")]
    pub target_slot: Option<u64>,
    pub location: String,
}
