use std::collections::HashMap;
use std::path::Path;

use ethlambda_types::{
    attestation::{
        AggregatedAttestation as DomainAggregatedAttestation,
        AggregationBits as DomainAggregationBits, Attestation as DomainAttestation,
        AttestationData as DomainAttestationData,
        SignedAggregatedAttestation as DomainSignedAggregatedAttestation,
        SignedAttestation as DomainSignedAttestation, XmssSignature,
    },
    block::{
        AggregatedSignatureProof as DomainAggregatedSignatureProof, AttestationSignatures,
        Block as DomainBlock, BlockBody as DomainBlockBody,
        BlockSignatures as DomainBlockSignatures, ByteListMiB, SignedBlock as DomainSignedBlock,
    },
    checkpoint::Checkpoint as DomainCheckpoint,
    primitives::H256,
    state::{
        ChainConfig, JustificationValidators, JustifiedSlots, State, Validator as DomainValidator,
        ValidatorPubkeyBytes,
    },
};
use libssz_types::{SszList, SszVector};
use serde::Deserialize;

// ============================================================================
// Root Structure
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct SszTestVector {
    #[serde(flatten)]
    pub tests: HashMap<String, SszTestCase>,
}

impl SszTestVector {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let test_vector = serde_json::from_str(&content)?;
        Ok(test_vector)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SszTestCase {
    #[allow(dead_code)]
    pub network: String,
    #[serde(rename = "leanEnv")]
    #[allow(dead_code)]
    pub lean_env: String,
    #[serde(rename = "typeName")]
    pub type_name: String,
    pub value: serde_json::Value,
    pub serialized: String,
    pub root: String,
    #[serde(rename = "_info")]
    pub info: TestInfo,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TestInfo {
    #[allow(dead_code)]
    pub hash: String,
    #[allow(dead_code)]
    pub comment: String,
    #[serde(rename = "testId")]
    #[allow(dead_code)]
    pub test_id: String,
    #[allow(dead_code)]
    pub description: String,
    #[serde(rename = "fixtureFormat")]
    pub fixture_format: String,
}

// ============================================================================
// Hex Helpers
// ============================================================================

pub fn decode_hex(hex_str: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    Ok(hex::decode(stripped)?)
}

pub fn decode_hex_h256(hex_str: &str) -> Result<H256, Box<dyn std::error::Error>> {
    let bytes = decode_hex(hex_str)?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes for H256, got {}", bytes.len()).into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(H256(arr))
}

// ============================================================================
// Generic Container
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct Container<T> {
    pub data: Vec<T>,
}

// ============================================================================
// Pubkey Deserialization
// ============================================================================

fn deser_pubkey_hex<'de, D>(d: D) -> Result<ValidatorPubkeyBytes, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let value = String::deserialize(d)?;
    let pubkey: ValidatorPubkeyBytes = hex::decode(value.strip_prefix("0x").unwrap_or(&value))
        .map_err(|_| D::Error::custom("ValidatorPubkey value is not valid hex"))?
        .try_into()
        .map_err(|_| D::Error::custom("ValidatorPubkey length != 52"))?;
    Ok(pubkey)
}

// ============================================================================
// Config
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(rename = "genesisTime")]
    pub genesis_time: u64,
}

impl From<Config> for ChainConfig {
    fn from(value: Config) -> Self {
        ChainConfig {
            genesis_time: value.genesis_time,
        }
    }
}

// ============================================================================
// Checkpoint
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct Checkpoint {
    pub root: H256,
    pub slot: u64,
}

impl From<Checkpoint> for DomainCheckpoint {
    fn from(value: Checkpoint) -> Self {
        Self {
            root: value.root,
            slot: value.slot,
        }
    }
}

// ============================================================================
// BlockHeader
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct BlockHeader {
    pub slot: u64,
    #[serde(rename = "proposerIndex")]
    pub proposer_index: u64,
    #[serde(rename = "parentRoot")]
    pub parent_root: H256,
    #[serde(rename = "stateRoot")]
    pub state_root: H256,
    #[serde(rename = "bodyRoot")]
    pub body_root: H256,
}

impl From<BlockHeader> for ethlambda_types::block::BlockHeader {
    fn from(value: BlockHeader) -> Self {
        Self {
            slot: value.slot,
            proposer_index: value.proposer_index,
            parent_root: value.parent_root,
            state_root: value.state_root,
            body_root: value.body_root,
        }
    }
}

// ============================================================================
// Validator
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct Validator {
    index: u64,
    #[serde(rename = "attestationPubkey")]
    #[serde(deserialize_with = "deser_pubkey_hex")]
    attestation_pubkey: ValidatorPubkeyBytes,
    #[serde(rename = "proposalPubkey")]
    #[serde(deserialize_with = "deser_pubkey_hex")]
    proposal_pubkey: ValidatorPubkeyBytes,
}

impl From<Validator> for DomainValidator {
    fn from(value: Validator) -> Self {
        Self {
            index: value.index,
            attestation_pubkey: value.attestation_pubkey,
            proposal_pubkey: value.proposal_pubkey,
        }
    }
}

// ============================================================================
// State
// ============================================================================

/// SSZ-specific State fixture type.
///
/// Unlike the STF test fixtures where `justifiedSlots` is a list of slot indices,
/// the SSZ fixtures use the true SSZ representation: boolean bitlists.
#[derive(Debug, Clone, Deserialize)]
pub struct TestState {
    pub config: Config,
    pub slot: u64,
    #[serde(rename = "latestBlockHeader")]
    pub latest_block_header: BlockHeader,
    #[serde(rename = "latestJustified")]
    pub latest_justified: Checkpoint,
    #[serde(rename = "latestFinalized")]
    pub latest_finalized: Checkpoint,
    #[serde(rename = "historicalBlockHashes")]
    pub historical_block_hashes: Container<H256>,
    /// Boolean bitlist: each entry is true/false for that slot index.
    #[serde(rename = "justifiedSlots")]
    pub justified_slots: Container<bool>,
    pub validators: Container<Validator>,
    #[serde(rename = "justificationsRoots")]
    pub justifications_roots: Container<H256>,
    /// Boolean bitlist for validator justifications.
    #[serde(rename = "justificationsValidators")]
    pub justifications_validators: Container<bool>,
}

impl From<TestState> for State {
    fn from(value: TestState) -> Self {
        let historical_block_hashes =
            SszList::try_from(value.historical_block_hashes.data).unwrap();
        let validators = SszList::try_from(
            value
                .validators
                .data
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let justifications_roots = SszList::try_from(value.justifications_roots.data).unwrap();

        // Build justified_slots bitlist from boolean array
        let mut justified_slots = JustifiedSlots::new();
        for &b in &value.justified_slots.data {
            justified_slots.push(b).unwrap();
        }

        // Build justifications_validators bitlist from boolean array
        let mut justifications_validators = JustificationValidators::new();
        for &b in &value.justifications_validators.data {
            justifications_validators.push(b).unwrap();
        }

        State {
            config: value.config.into(),
            slot: value.slot,
            latest_block_header: value.latest_block_header.into(),
            latest_justified: value.latest_justified.into(),
            latest_finalized: value.latest_finalized.into(),
            historical_block_hashes,
            justified_slots,
            validators,
            justifications_roots,
            justifications_validators,
        }
    }
}

// ============================================================================
// Block Types
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct Block {
    pub slot: u64,
    #[serde(rename = "proposerIndex")]
    pub proposer_index: u64,
    #[serde(rename = "parentRoot")]
    pub parent_root: H256,
    #[serde(rename = "stateRoot")]
    pub state_root: H256,
    pub body: BlockBody,
}

impl From<Block> for DomainBlock {
    fn from(value: Block) -> Self {
        Self {
            slot: value.slot,
            proposer_index: value.proposer_index,
            parent_root: value.parent_root,
            state_root: value.state_root,
            body: value.body.into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockBody {
    pub attestations: Container<AggregatedAttestation>,
}

impl From<BlockBody> for DomainBlockBody {
    fn from(value: BlockBody) -> Self {
        let attestations = value
            .attestations
            .data
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        Self {
            attestations: SszList::try_from(attestations).expect("too many attestations"),
        }
    }
}

// ============================================================================
// Attestation Types
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct AttestationData {
    pub slot: u64,
    pub head: Checkpoint,
    pub target: Checkpoint,
    pub source: Checkpoint,
}

impl From<AttestationData> for DomainAttestationData {
    fn from(value: AttestationData) -> Self {
        Self {
            slot: value.slot,
            head: value.head.into(),
            target: value.target.into(),
            source: value.source.into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Attestation {
    #[serde(rename = "validatorId")]
    pub validator_id: u64,
    pub data: AttestationData,
}

impl From<Attestation> for DomainAttestation {
    fn from(value: Attestation) -> Self {
        Self {
            validator_id: value.validator_id,
            data: value.data.into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AggregatedAttestation {
    #[serde(rename = "aggregationBits")]
    pub aggregation_bits: AggregationBits,
    pub data: AttestationData,
}

impl From<AggregatedAttestation> for DomainAggregatedAttestation {
    fn from(value: AggregatedAttestation) -> Self {
        Self {
            aggregation_bits: value.aggregation_bits.into(),
            data: value.data.into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AggregationBits {
    pub data: Vec<bool>,
}

impl From<AggregationBits> for DomainAggregationBits {
    fn from(value: AggregationBits) -> Self {
        let mut bits = DomainAggregationBits::new();
        for &b in value.data.iter() {
            bits.push(b).unwrap();
        }
        bits
    }
}

// ============================================================================
// Signed Types (SSZ-specific fixtures)
// ============================================================================

fn deser_signature_hex<'de, D>(d: D) -> Result<XmssSignature, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let value = String::deserialize(d)?;
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(&value))
        .map_err(|_| D::Error::custom("Signature value is not valid hex"))?;
    SszVector::try_from(bytes)
        .map_err(|e| D::Error::custom(format!("Invalid signature length: {e:?}")))
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignedAttestation {
    #[serde(rename = "validatorId")]
    pub validator_id: u64,
    pub data: AttestationData,
    #[serde(deserialize_with = "deser_signature_hex")]
    pub signature: XmssSignature,
}

impl From<SignedAttestation> for DomainSignedAttestation {
    fn from(value: SignedAttestation) -> Self {
        Self {
            validator_id: value.validator_id,
            data: value.data.into(),
            signature: value.signature,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignedBlock {
    pub block: Block,
    pub signature: BlockSignatures,
}

impl From<SignedBlock> for DomainSignedBlock {
    fn from(value: SignedBlock) -> Self {
        Self {
            message: value.block.into(),
            signature: value.signature.into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockSignatures {
    #[serde(rename = "attestationSignatures")]
    pub attestation_signatures: Container<AggregatedSignatureProof>,
    #[serde(rename = "proposerSignature")]
    #[serde(deserialize_with = "deser_signature_hex")]
    pub proposer_signature: XmssSignature,
}

impl From<BlockSignatures> for DomainBlockSignatures {
    fn from(value: BlockSignatures) -> Self {
        let att_sigs: Vec<DomainAggregatedSignatureProof> = value
            .attestation_signatures
            .data
            .into_iter()
            .map(Into::into)
            .collect();
        Self {
            attestation_signatures: AttestationSignatures::try_from(att_sigs)
                .expect("too many attestation signatures"),
            proposer_signature: value.proposer_signature,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AggregatedSignatureProof {
    pub participants: AggregationBits,
    #[serde(rename = "proofData")]
    pub proof_data: HexByteList,
}

impl From<AggregatedSignatureProof> for DomainAggregatedSignatureProof {
    fn from(value: AggregatedSignatureProof) -> Self {
        let proof_bytes: Vec<u8> = value.proof_data.into();
        Self {
            participants: value.participants.into(),
            proof_data: ByteListMiB::try_from(proof_bytes).expect("proof data too large"),
        }
    }
}

/// Hex-encoded byte list in the fixture format: `{ "data": "0xdeadbeef" }`
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

#[derive(Debug, Clone, Deserialize)]
pub struct SignedAggregatedAttestation {
    pub data: AttestationData,
    pub proof: AggregatedSignatureProof,
}

impl From<SignedAggregatedAttestation> for DomainSignedAggregatedAttestation {
    fn from(value: SignedAggregatedAttestation) -> Self {
        Self {
            data: value.data.into(),
            proof: value.proof.into(),
        }
    }
}
