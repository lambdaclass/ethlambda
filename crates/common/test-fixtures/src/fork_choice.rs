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
#[serde(deny_unknown_fields)]
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
    /// Top-level expected rejection reason for whole-vector negative tests.
    /// Captured only so `deny_unknown_fields` accepts it.
    #[serde(rename = "rejectionReason")]
    #[allow(dead_code)]
    pub rejection_reason: Option<String>,
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
#[serde(deny_unknown_fields)]
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
    /// Full canonical store snapshot the simulator emits after every step
    /// (leanSpec `StoreSnapshot`). Captured but not yet asserted by the offline
    /// runner.
    // TODO(leanSpec storeSnapshot): assert the snapshot contents against Store
    // getters (block roots, block weights, aggregated-payload participant sets,
    // gossip-signature groups) once the required Store plumbing exists.
    #[serde(rename = "storeSnapshot")]
    pub store_snapshot: Option<StoreSnapshot>,
    /// Expected rejection reason for a step marked `valid: false`. Captured only
    /// so `deny_unknown_fields` accepts it; step outcomes are asserted via the
    /// `valid` flag.
    #[serde(rename = "rejectionReason")]
    #[allow(dead_code)]
    pub rejection_reason: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
/// `{ data: "0x<hex>" }`; the latter is the lean-multisig single-message
/// aggregate `compress_without_pubkeys()` bytes for that AttestationData.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofStepData {
    pub participants: AggregationBits,
    pub proof: HexByteList,
}

/// Hex-encoded byte list in the fixture format: `{ "data": "0xdeadbeef" }`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    /// Expected attestation target block root by label reference.
    #[serde(rename = "attestationTargetRootLabel")]
    pub attestation_target_root_label: Option<String>,
    #[serde(rename = "attestationChecks")]
    pub attestation_checks: Option<Vec<AttestationCheck>>,
    #[serde(rename = "lexicographicHeadAmong")]
    pub lexicographic_head_among: Option<Vec<String>>,

    /// Equal-slot equivocation tiebreak: the listed fork labels must each be
    /// targeted by an attestation in the accepted (known) aggregated pool, and
    /// the head must sit on the fork whose attestation carries the largest
    /// `hash_tree_root` (leanSpec #1189). Scheme-independent: roots are read
    /// from the store, never pinned.
    #[serde(rename = "canonicalEquivocationHeadAmong")]
    pub canonical_equivocation_head_among: Option<Vec<String>>,

    /// Expected sorted-unique set of target slots keyed in the raw gossip
    /// signature pool.
    #[serde(rename = "attestationSignatureTargetSlots")]
    pub attestation_signature_target_slots: Option<Vec<u64>>,
    /// Expected sorted-unique set of target slots keyed in the pending (new)
    /// aggregated proof pool.
    #[serde(rename = "latestNewAggregatedTargetSlots")]
    pub latest_new_aggregated_target_slots: Option<Vec<u64>>,
    /// Expected sorted-unique set of target slots keyed in the accepted (known)
    /// aggregated proof pool.
    #[serde(rename = "latestKnownAggregatedTargetSlots")]
    pub latest_known_aggregated_target_slots: Option<Vec<u64>>,

    /// Expected union of validator indices across pending-pool proofs, keyed by
    /// target slot. JSON object keys are stringified slots (e.g. `"1"`); parse
    /// them to `u64` at assertion time.
    #[serde(rename = "newPoolProofParticipants")]
    pub new_pool_proof_participants: Option<HashMap<String, Vec<u64>>>,

    /// Expected number of aggregated attestations in the block built for this
    /// step. More than one means votes split over incompatible sources.
    #[serde(rename = "blockAttestationCount")]
    pub block_attestation_count: Option<u64>,
    /// Detailed per-aggregate checks on the block built for this step.
    #[serde(rename = "blockAttestations")]
    pub block_attestations: Option<Vec<BlockAttestationCheck>>,

    /// Expected count of blocks from the previous head back to its common
    /// ancestor with the new head.
    #[serde(rename = "reorgDepth")]
    pub reorg_depth: Option<u64>,

    /// Block labels that must still be present in the block tree (verifying
    /// abandoned forks are retained).
    #[serde(rename = "labelsInStore")]
    pub labels_in_store: Option<Vec<String>>,

    /// Expected root of the block built for this step, named by label. The
    /// offline runner does not build blocks (it imports fixture-supplied ones),
    /// so this is captured but not asserted.
    // TODO(leanSpec filledBlockRootLabel): assert once a block-building step
    // exists; the offline runner imports blocks rather than building them.
    #[serde(rename = "filledBlockRootLabel")]
    #[allow(dead_code)]
    pub filled_block_root_label: Option<String>,
}

/// Per-validator attestation content check within a step's `attestationChecks`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationCheck {
    pub validator: u64,
    #[serde(rename = "attestationSlot")]
    pub attestation_slot: Option<u64>,
    #[serde(rename = "headSlot")]
    pub head_slot: Option<u64>,
    #[serde(rename = "sourceSlot")]
    pub source_slot: Option<u64>,
    /// Expected source checkpoint root, named by label and resolved to a root.
    #[serde(rename = "sourceRootLabel")]
    pub source_root_label: Option<String>,
    #[serde(rename = "targetSlot")]
    pub target_slot: Option<u64>,
    pub location: String,
}

/// Checks for one aggregated attestation in a built block body
/// (leanSpec `AggregatedAttestationCheck`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockAttestationCheck {
    /// Validator indices this aggregate must cover exactly.
    pub participants: Vec<u64>,
    #[serde(rename = "attestationSlot")]
    pub attestation_slot: Option<u64>,
    #[serde(rename = "targetSlot")]
    pub target_slot: Option<u64>,
}

// ============================================================================
// Store snapshot (leanSpec `StoreSnapshot`)
// ============================================================================

/// Canonical store snapshot emitted after every fork-choice step.
///
/// Parsed in full so `deny_unknown_fields` accepts it, but not yet asserted by
/// the offline runner; see the `TODO(leanSpec storeSnapshot)` on
/// [`ForkChoiceStep::store_snapshot`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct StoreSnapshot {
    pub time: u64,
    #[serde(rename = "headRoot")]
    pub head_root: H256,
    #[serde(rename = "safeTargetRoot")]
    pub safe_target_root: H256,
    #[serde(rename = "latestJustified")]
    pub latest_justified: Checkpoint,
    #[serde(rename = "latestFinalized")]
    pub latest_finalized: Checkpoint,
    #[serde(rename = "blockRoots")]
    pub block_roots: Vec<H256>,
    #[serde(rename = "blockWeights")]
    pub block_weights: Vec<BlockWeightEntry>,
    #[serde(rename = "knownAggregatedPayloads")]
    pub known_aggregated_payloads: Vec<AggregatedPayloadEntry>,
    #[serde(rename = "newAggregatedPayloads")]
    pub new_aggregated_payloads: Vec<AggregatedPayloadEntry>,
    #[serde(rename = "attestationSignatures")]
    pub attestation_signatures: Vec<AttestationSignatureEntry>,
}

/// A `{root, weight}` entry in [`StoreSnapshot::block_weights`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct BlockWeightEntry {
    pub root: H256,
    pub weight: u64,
}

/// A `{dataRoot, participantSets}` entry in the snapshot's aggregated pools.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct AggregatedPayloadEntry {
    #[serde(rename = "dataRoot")]
    pub data_root: H256,
    #[serde(rename = "participantSets")]
    pub participant_sets: Vec<Vec<u64>>,
}

/// A `{dataRoot, validatorIndices}` entry in the snapshot's signature pool.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct AttestationSignatureEntry {
    #[serde(rename = "dataRoot")]
    pub data_root: H256,
    #[serde(rename = "validatorIndices")]
    pub validator_indices: Vec<u64>,
}
