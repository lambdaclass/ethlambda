use ethlambda_types::attestation::{
    AggregatedAttestation as EthAggregatedAttestation,
    AggregationBits as EthAggregationBits, Attestation as EthAttestation,
    AttestationData as EthAttestationData, XmssSignature,
};
use ethlambda_types::block::{
    AggregatedAttestations, AttestationSignatures, Block as EthBlock,
    BlockBody as EthBlockBody, BlockSignatures, BlockWithAttestation,
    NaiveAggregatedSignature, SignedBlockWithAttestation,
};
use ethlambda_types::primitives::{BitList, Encode, H256, VariableList};
use ethlambda_types::state::{Checkpoint as EthCheckpoint, State, ValidatorPubkeyBytes};
use serde::Deserialize;
use ssz_derive::{Decode as SszDecode, Encode as SszEncode};
use ssz_types::typenum::{U28, U32};
use ssz_types::FixedVector;
use std::collections::HashMap;
use std::path::Path;

// ============================================================================
// SSZ Types matching leansig's GeneralizedXMSSSignature structure
// ============================================================================

/// A single hash digest (8 field elements = 32 bytes)
pub type HashDigest = FixedVector<u8, U32>;

/// Randomness (7 field elements = 28 bytes)
pub type Rho = FixedVector<u8, U28>;

/// SSZ-compatible HashTreeOpening matching leansig's structure
#[derive(Clone, SszEncode, SszDecode)]
pub struct SszHashTreeOpening {
    pub co_path: Vec<HashDigest>,
}

/// SSZ-compatible XMSS Signature matching leansig's GeneralizedXMSSSignature
#[derive(Clone, SszEncode, SszDecode)]
pub struct SszXmssSignature {
    pub path: SszHashTreeOpening,
    pub rho: Rho,
    pub hashes: Vec<HashDigest>,
}

/// Root struct for verify signatures test vectors
#[derive(Debug, Clone, Deserialize)]
pub struct VerifySignaturesTestVector {
    #[serde(flatten)]
    pub tests: HashMap<String, VerifySignaturesTest>,
}

impl VerifySignaturesTestVector {
    /// Load a verify signatures test vector from a JSON file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let test_vector = serde_json::from_str(&content)?;
        Ok(test_vector)
    }
}

/// A single verify signatures test case
#[derive(Debug, Clone, Deserialize)]
pub struct VerifySignaturesTest {
    #[allow(dead_code)]
    pub network: String,
    #[serde(rename = "leanEnv")]
    #[allow(dead_code)]
    pub lean_env: String,
    #[serde(rename = "anchorState")]
    pub anchor_state: TestState,
    #[serde(rename = "signedBlockWithAttestation")]
    pub signed_block_with_attestation: TestSignedBlockWithAttestation,
    #[serde(rename = "expectException")]
    pub expect_exception: Option<String>,
    #[serde(rename = "_info")]
    #[allow(dead_code)]
    pub info: TestInfo,
}

/// Pre-state of the beacon chain for signature tests
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
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
    #[serde(rename = "justifiedSlots")]
    pub justified_slots: Container<u64>,
    pub validators: Container<Validator>,
    #[serde(rename = "justificationsRoots")]
    pub justifications_roots: Container<H256>,
    #[serde(rename = "justificationsValidators")]
    pub justifications_validators: Container<bool>,
}

impl From<TestState> for State {
    fn from(value: TestState) -> Self {
        let historical_block_hashes =
            VariableList::new(value.historical_block_hashes.data).unwrap();
        let validators =
            VariableList::new(value.validators.data.into_iter().map(Into::into).collect()).unwrap();
        let justifications_roots = VariableList::new(value.justifications_roots.data).unwrap();

        State {
            config: value.config.into(),
            slot: value.slot,
            latest_block_header: value.latest_block_header.into(),
            latest_justified: value.latest_justified.into(),
            latest_finalized: value.latest_finalized.into(),
            historical_block_hashes,
            justified_slots: BitList::with_capacity(0).unwrap(),
            validators,
            justifications_roots,
            justifications_validators: BitList::with_capacity(0).unwrap(),
        }
    }
}

/// Configuration for the beacon chain
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(rename = "genesisTime")]
    pub genesis_time: u64,
}

impl From<Config> for ethlambda_types::state::ChainConfig {
    fn from(value: Config) -> Self {
        ethlambda_types::state::ChainConfig {
            genesis_time: value.genesis_time,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Checkpoint {
    pub root: H256,
    pub slot: u64,
}

impl From<Checkpoint> for EthCheckpoint {
    fn from(value: Checkpoint) -> Self {
        Self {
            root: value.root,
            slot: value.slot,
        }
    }
}

/// Block header representing the latest block
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
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

/// Validator information
#[derive(Debug, Clone, Deserialize)]
pub struct Validator {
    pub index: u64,
    #[serde(deserialize_with = "deser_pubkey_hex")]
    pub pubkey: ValidatorPubkeyBytes,
}

impl From<Validator> for ethlambda_types::state::Validator {
    fn from(value: Validator) -> Self {
        Self {
            index: value.index,
            pubkey: value.pubkey,
        }
    }
}

/// Generic container for arrays
#[derive(Debug, Clone, Deserialize)]
pub struct Container<T> {
    pub data: Vec<T>,
}

/// Signed block with attestation and signature
#[derive(Debug, Clone, Deserialize)]
pub struct TestSignedBlockWithAttestation {
    pub message: TestBlockWithAttestation,
    pub signature: TestSignatureBundle,
}

impl From<TestSignedBlockWithAttestation> for SignedBlockWithAttestation {
    fn from(value: TestSignedBlockWithAttestation) -> Self {
        let message = BlockWithAttestation {
            block: value.message.block.into(),
            proposer_attestation: value.message.proposer_attestation.into(),
        };

        let proposer_signature = value.signature.proposer_signature.to_xmss_signature();

        // For now, attestation signatures use placeholder proofData (for future SNARK aggregation).
        // We create empty NaiveAggregatedSignature entries to match the attestation count.
        // The actual signature verification for attestations is not yet implemented.
        let attestation_signatures: AttestationSignatures = value
            .signature
            .attestation_signatures
            .data
            .into_iter()
            .map(|_att_sig| {
                // Create empty signature list for each attestation
                // Real implementation would parse proofData or individual signatures
                let empty: NaiveAggregatedSignature = Vec::new().try_into().unwrap();
                empty
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("too many attestation signatures");

        SignedBlockWithAttestation {
            message,
            signature: BlockSignatures {
                proposer_signature,
                attestation_signatures,
            },
        }
    }
}

/// Block with proposer attestation (the message that gets signed)
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct TestBlockWithAttestation {
    pub block: Block,
    #[serde(rename = "proposerAttestation")]
    pub proposer_attestation: ProposerAttestation,
}

/// A block to be processed
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
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

impl From<Block> for EthBlock {
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

/// Block body containing attestations
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct BlockBody {
    pub attestations: Container<AggregatedAttestation>,
}

impl From<BlockBody> for EthBlockBody {
    fn from(value: BlockBody) -> Self {
        let attestations: AggregatedAttestations = value
            .attestations
            .data
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>()
            .try_into()
            .expect("too many attestations");
        Self { attestations }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct AggregatedAttestation {
    #[serde(rename = "aggregationBits")]
    pub aggregation_bits: AggregationBits,
    pub data: AttestationData,
}

impl From<AggregatedAttestation> for EthAggregatedAttestation {
    fn from(value: AggregatedAttestation) -> Self {
        Self {
            aggregation_bits: value.aggregation_bits.into(),
            data: value.data.into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct AggregationBits {
    pub data: Vec<bool>,
}

impl From<AggregationBits> for EthAggregationBits {
    fn from(value: AggregationBits) -> Self {
        let mut bits = EthAggregationBits::with_capacity(value.data.len()).unwrap();
        for (i, &b) in value.data.iter().enumerate() {
            bits.set(i, b).unwrap();
        }
        bits
    }
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct AttestationData {
    pub slot: u64,
    pub head: Checkpoint,
    pub target: Checkpoint,
    pub source: Checkpoint,
}

impl From<AttestationData> for EthAttestationData {
    fn from(value: AttestationData) -> Self {
        Self {
            slot: value.slot,
            head: value.head.into(),
            target: value.target.into(),
            source: value.source.into(),
        }
    }
}

/// Proposer attestation structure
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ProposerAttestation {
    #[serde(rename = "validatorId")]
    pub validator_id: u64,
    pub data: AttestationData,
}

impl From<ProposerAttestation> for EthAttestation {
    fn from(value: ProposerAttestation) -> Self {
        Self {
            validator_id: value.validator_id,
            data: value.data.into(),
        }
    }
}

/// Bundle of signatures for block and attestations
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct TestSignatureBundle {
    #[serde(rename = "proposerSignature")]
    pub proposer_signature: ProposerSignature,
    #[serde(rename = "attestationSignatures")]
    pub attestation_signatures: Container<AttestationSignature>,
}

/// XMSS signature structure as it appears in JSON
#[derive(Debug, Clone, Deserialize)]
pub struct ProposerSignature {
    pub path: SignaturePath,
    pub rho: RhoData,
    pub hashes: HashesData,
}

impl ProposerSignature {
    /// Convert to XmssSignature (FixedVector of bytes).
    ///
    /// Constructs an SSZ-encoded signature matching leansig's GeneralizedXMSSSignature format.
    pub fn to_xmss_signature(&self) -> XmssSignature {
        // Build SSZ types from JSON data
        let ssz_sig = self.to_ssz_signature();

        // Encode to SSZ bytes
        let bytes = ssz_sig.as_ssz_bytes();

        // Pad to exactly SignatureSize bytes (3112)
        let sig_size = 3112;
        let mut padded = bytes.clone();
        padded.resize(sig_size, 0);

        XmssSignature::new(padded).expect("signature size mismatch")
    }

    /// Convert to SSZ signature type
    fn to_ssz_signature(&self) -> SszXmssSignature {
        // Convert path siblings to HashDigest (Vec<u8> of 32 bytes each)
        let co_path: Vec<HashDigest> = self
            .path
            .siblings
            .data
            .iter()
            .map(|sibling| {
                let bytes: Vec<u8> = sibling
                    .data
                    .iter()
                    .flat_map(|&val| val.to_le_bytes())
                    .collect();
                HashDigest::new(bytes).expect("Invalid sibling length")
            })
            .collect();

        // Convert rho (7 field elements = 28 bytes)
        let rho_bytes: Vec<u8> = self
            .rho
            .data
            .iter()
            .flat_map(|&val| val.to_le_bytes())
            .collect();
        let rho = Rho::new(rho_bytes).expect("Invalid rho length");

        // Convert hashes to HashDigest
        let hashes: Vec<HashDigest> = self
            .hashes
            .data
            .iter()
            .map(|hash| {
                let bytes: Vec<u8> = hash
                    .data
                    .iter()
                    .flat_map(|&val| val.to_le_bytes())
                    .collect();
                HashDigest::new(bytes).expect("Invalid hash length")
            })
            .collect();

        SszXmssSignature {
            path: SszHashTreeOpening { co_path },
            rho,
            hashes,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignaturePath {
    pub siblings: Container<HashElement>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct HashElement {
    pub data: [u32; 8],
}

#[derive(Debug, Clone, Deserialize)]
pub struct RhoData {
    pub data: [u32; 7],
}

#[derive(Debug, Clone, Deserialize)]
pub struct HashesData {
    pub data: Vec<HashElement>,
}

/// Attestation signature from a validator
/// Note: proofData is for future SNARK aggregation, currently just placeholder
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct AttestationSignature {
    pub participants: AggregationBits,
    #[serde(rename = "proofData")]
    pub proof_data: ProofData,
}

/// Placeholder for future SNARK proof data
#[derive(Debug, Clone, Deserialize)]
pub struct ProofData {
    pub data: String,
}

/// Test metadata and information
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct TestInfo {
    pub hash: String,
    pub comment: String,
    #[serde(rename = "testId")]
    pub test_id: String,
    pub description: String,
    #[serde(rename = "fixtureFormat")]
    pub fixture_format: String,
}

// Helpers

pub fn deser_pubkey_hex<'de, D>(d: D) -> Result<ValidatorPubkeyBytes, D::Error>
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
