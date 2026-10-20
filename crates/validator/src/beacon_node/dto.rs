//! The Beacon API's JSON representations, and their conversions to the SSZ
//! containers the rest of the crate uses.
//!
//! These types exist here rather than as serde derives on the containers in
//! `ethlambda-types` for two reasons. A `Deserialize` on a consensus container
//! is a footgun in a crate whose whole job is to be the authority on what a
//! block means. And the conventions below, integers quoted as strings, byte
//! vectors as `0x` hex, are properties of one transport, not of the types.
//!
//! # Only the fields this client reads
//!
//! These types declare only what is actually used, not every field the schema
//! marks required, relying on serde ignoring unknown fields. That is deliberate:
//! the client must tolerate any conformant node, so a node that carries an extra
//! field, or a fork that adds one, must not stop it attesting. Do not "complete"
//! these against the schema. Checked against `ethereum/beacon-APIs`:
//!
//! | Schema | Spec requires | Declared here |
//! |---|---|---|
//! | `AttesterDuty` | pubkey, validator_index, committee_index, committee_length, committees_at_slot, validator_committee_index, slot | all seven, all used |
//! | Genesis | genesis_time, genesis_validators_root, genesis_fork_version | the first two; the fork version comes from `/config/spec` |
//! | Syncing | head_slot, sync_distance, is_syncing, is_optimistic, el_offline | is_syncing and is_optimistic gate signing; el_offline is logged |
//! | `ValidatorResponse` | index, balance, status, validator | index, status, validator.pubkey |
//! | `ProposerDuty` | pubkey, validator_index, slot | all three, all used |
//! | `ProposerPreparation` | validator_index, fee_recipient | both, sent not read |
//!
//! The API is JSON throughout on this path. The specification permits SSZ on
//! two of the endpoints used here, but no implementation exercises it: see the
//! design document's "Wire format" section for the evidence.

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::electra::{
    AggregationBits, Attestation, CommitteeBits, SignedAggregateAndProof,
};
use ethlambda_types::beacon::containers::shared::{AttestationData, Checkpoint};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{
    BLS_PUBKEY_SIZE, BLS_SIGNATURE_SIZE, BlsPubkey, BlsSignature, CommitteeIndex, Epoch, Root,
    Slot, ValidatorIndex, Version,
};
use libssz::SszDecode as _;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The Beacon API quotes every 64-bit integer as a JSON string, so that a
/// consumer with 53-bit numbers cannot silently round one.
pub mod quoted_u64 {
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// The envelope almost every Beacon API response uses.
#[derive(Debug, Deserialize)]
pub struct DataResponse<T> {
    pub data: T,
}

/// The envelope the fork-dependent endpoints use: `data`, plus the fork that
/// decides which shape `data` is.
#[derive(Debug, Deserialize)]
pub struct VersionedResponse<T> {
    pub version: String,
    pub data: T,
}

/// A duties response additionally pins the block its schedule depends on.
#[derive(Debug, Deserialize)]
pub struct DutiesResponse<T> {
    pub dependent_root: String,
    pub data: T,
}

/// The beacon-APIs `IndexedErrorMessage` schema: a batch endpoint answers 400
/// with this when some, but not necessarily all, of what was submitted was
/// rejected. `POST /eth/v2/beacon/pool/attestations` still stores and
/// gossips whichever entries were valid, so this is not "the request
/// failed", it is "here is exactly which entries did".
#[derive(Debug, Clone, Deserialize)]
pub struct IndexedErrorResponse {
    pub code: u16,
    pub message: String,
    #[serde(default)]
    pub failures: Vec<IndexedFailure>,
}

/// One rejected entry from an [`IndexedErrorResponse`].
///
/// `index` is the entry's position in the array this client submitted, not a
/// validator index; unlike the `u64`s elsewhere in this module it is not
/// quoted, since the schema types it as a plain integer, not one of the
/// wire's uint64 fields large enough to need string encoding.
#[derive(Debug, Clone, Deserialize)]
pub struct IndexedFailure {
    pub index: u64,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GenesisDto {
    #[serde(with = "quoted_u64")]
    pub genesis_time: u64,
    pub genesis_validators_root: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SyncingDto {
    /// The node's consensus head is behind the network's.
    pub is_syncing: bool,
    /// The node is tracking a head its execution client has not validated.
    ///
    /// `Option` because a node that predates optimistic sync, or one that is
    /// simply not conformant, may omit it. Absent is read as `false`: the
    /// specification marks the field required, so a missing one says nothing,
    /// and reading it as `true` would refuse every duty against such a node.
    pub is_optimistic: Option<bool>,
    /// The node's execution client is unreachable.
    ///
    /// Not a gate on signing, unlike the two above, and modelled only so it can
    /// be reported. A node whose execution client has just gone offline still
    /// has the head it validated before that, which is a head worth attesting
    /// to; what it cannot do is validate new payloads, and it reports that
    /// through `is_optimistic` when it starts to matter.
    pub el_offline: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CheckpointDto {
    #[serde(with = "quoted_u64")]
    pub epoch: Epoch,
    pub root: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AttestationDataDto {
    #[serde(with = "quoted_u64")]
    pub slot: Slot,
    #[serde(with = "quoted_u64")]
    pub index: CommitteeIndex,
    pub beacon_block_root: String,
    pub source: CheckpointDto,
    pub target: CheckpointDto,
}

/// An electra-shaped `Attestation`, as `/eth/v2/validator/aggregate_attestation`
/// returns it in JSON.
///
/// # Why an aggregate goes through JSON when a block does not
///
/// Because the node sends JSON whatever this client asks for. Lighthouse v8.2.2
/// answers this endpoint with `200 application/json` to a request whose
/// `Accept` names only SSZ, where the specification says it should answer SSZ
/// or `406`. It is the most widely run consensus client, so a client that only
/// takes SSZ here aggregates for nobody against it.
///
/// It is also cheap to get right here, unlike for a block. An `Attestation` is
/// four fields, and the two bitfields arrive as hex of their exact SSZ
/// encoding, so they decode through SSZ rather than through anything
/// hand-written. The root this client later signs over is therefore computed
/// from the same bytes the node would have sent as SSZ.
#[derive(Debug, Clone, Deserialize)]
pub struct AttestationDto {
    pub aggregation_bits: String,
    pub data: AttestationDataDto,
    pub signature: String,
    pub committee_bits: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AttesterDutyDto {
    pub pubkey: String,
    #[serde(with = "quoted_u64")]
    pub validator_index: ValidatorIndex,
    #[serde(with = "quoted_u64")]
    pub committee_index: CommitteeIndex,
    #[serde(with = "quoted_u64")]
    pub committee_length: u64,
    #[serde(with = "quoted_u64")]
    pub committees_at_slot: u64,
    #[serde(with = "quoted_u64")]
    pub validator_committee_index: u64,
    #[serde(with = "quoted_u64")]
    pub slot: Slot,
}

/// One proposer duty, from `GET /eth/v1/validator/duties/proposer/{epoch}`.
///
/// Three fields where an attester duty has seven, because a proposer has no
/// committee: a block is proposed by one validator on its own behalf, so there
/// is nothing to say about position or membership.
#[derive(Debug, Clone, Deserialize)]
pub struct ProposerDutyDto {
    pub pubkey: String,
    #[serde(with = "quoted_u64")]
    pub validator_index: ValidatorIndex,
    #[serde(with = "quoted_u64")]
    pub slot: Slot,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidatorEntryDto {
    #[serde(with = "quoted_u64")]
    pub index: ValidatorIndex,
    pub status: String,
    pub validator: ValidatorInnerDto,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidatorInnerDto {
    pub pubkey: String,
}

/// What a validator client submits for one attester duty, from Electra on.
#[derive(Debug, Clone, Serialize)]
pub struct SingleAttestationDto {
    #[serde(with = "quoted_u64")]
    pub committee_index: CommitteeIndex,
    #[serde(with = "quoted_u64")]
    pub attester_index: ValidatorIndex,
    pub data: AttestationDataOutDto,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttestationDataOutDto {
    #[serde(with = "quoted_u64")]
    pub slot: Slot,
    #[serde(with = "quoted_u64")]
    pub index: CommitteeIndex,
    pub beacon_block_root: String,
    pub source: CheckpointOutDto,
    pub target: CheckpointOutDto,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckpointOutDto {
    #[serde(with = "quoted_u64")]
    pub epoch: Epoch,
    pub root: String,
}

/// One entry of `POST /eth/v1/validator/prepare_beacon_proposer`.
///
/// The body is a bare array of these, with no `{"data": ...}` envelope, unlike
/// almost everything else on this API.
#[derive(Debug, Clone, Serialize)]
pub struct ProposerPreparationDto {
    #[serde(with = "quoted_u64")]
    pub validator_index: ValidatorIndex,
    /// The execution address this validator's block rewards should be paid to,
    /// `0x`-prefixed.
    pub fee_recipient: String,
}

/// An electra-shaped `Attestation`, for sending back.
///
/// The bitfields are hex of their SSZ encoding, the same form the node sends
/// them in, so they round-trip through SSZ exactly rather than through anything
/// hand-written.
#[derive(Debug, Clone, Serialize)]
pub struct AttestationOutDto {
    pub aggregation_bits: String,
    pub data: AttestationDataOutDto,
    pub signature: String,
    pub committee_bits: String,
}

impl From<&Attestation> for AttestationOutDto {
    fn from(attestation: &Attestation) -> Self {
        use libssz::SszEncode as _;
        Self {
            aggregation_bits: encode_hex(&attestation.aggregation_bits.to_ssz()),
            data: AttestationDataOutDto::from(&attestation.data),
            signature: encode_hex(&attestation.signature.0),
            committee_bits: encode_hex(&attestation.committee_bits.to_ssz()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AggregateAndProofOutDto {
    #[serde(with = "quoted_u64")]
    pub aggregator_index: ValidatorIndex,
    pub aggregate: AttestationOutDto,
    pub selection_proof: String,
}

/// One entry of `POST /eth/v2/validator/aggregate_and_proofs`, whose body is a
/// bare array of these even for a single aggregate.
#[derive(Debug, Clone, Serialize)]
pub struct SignedAggregateAndProofOutDto {
    pub message: AggregateAndProofOutDto,
    pub signature: String,
}

impl From<&SignedAggregateAndProof> for SignedAggregateAndProofOutDto {
    fn from(signed: &SignedAggregateAndProof) -> Self {
        Self {
            message: AggregateAndProofOutDto {
                aggregator_index: signed.message.aggregator_index,
                aggregate: AttestationOutDto::from(&signed.message.aggregate),
                selection_proof: encode_hex(&signed.message.selection_proof.0),
            },
            signature: encode_hex(&signed.signature.0),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CommitteeSubscriptionDto {
    #[serde(with = "quoted_u64")]
    pub validator_index: ValidatorIndex,
    #[serde(with = "quoted_u64")]
    pub committee_index: CommitteeIndex,
    #[serde(with = "quoted_u64")]
    pub committees_at_slot: u64,
    #[serde(with = "quoted_u64")]
    pub slot: Slot,
    pub is_aggregator: bool,
}

// -- Conversions -------------------------------------------------------------

/// Parses explicitly rather than declaring `Root` (which has its own
/// `Deserialize`) directly on the DTOs. A malformed root then fails at this
/// conversion boundary with this crate's own [`Error::Decode`], naming what
/// was wrong, instead of as a serde error part-way through decoding a
/// response.
pub fn parse_root(text: &str) -> Result<Root> {
    let bytes = hex::decode(text.strip_prefix("0x").unwrap_or(text))
        .map_err(|err| Error::Decode(format!("bad root hex: {err}")))?;
    let array: [u8; 32] = bytes.try_into().map_err(|got: Vec<u8>| {
        Error::Decode(format!("root is {} bytes, expected 32", got.len()))
    })?;
    Ok(Root::from(array))
}

/// Decode one `0x`-prefixed hex field, naming it in the error.
fn parse_hex(text: &str, what: &str) -> Result<Vec<u8>> {
    hex::decode(text.strip_prefix("0x").unwrap_or(text))
        .map_err(|err| Error::Decode(format!("bad {what} hex: {err}")))
}

pub fn parse_signature(text: &str) -> Result<BlsSignature> {
    let bytes = parse_hex(text, "signature")?;
    let array: [u8; BLS_SIGNATURE_SIZE] = bytes.try_into().map_err(|got: Vec<u8>| {
        Error::Decode(format!(
            "signature is {} bytes, expected {BLS_SIGNATURE_SIZE}",
            got.len()
        ))
    })?;
    Ok(BlsSignature(array))
}

pub fn parse_pubkey(text: &str) -> Result<BlsPubkey> {
    let bytes = hex::decode(text.strip_prefix("0x").unwrap_or(text))
        .map_err(|err| Error::Decode(format!("bad pubkey hex: {err}")))?;
    let array: [u8; BLS_PUBKEY_SIZE] = bytes.try_into().map_err(|got: Vec<u8>| {
        Error::Decode(format!(
            "pubkey is {} bytes, expected {BLS_PUBKEY_SIZE}",
            got.len()
        ))
    })?;
    Ok(BlsPubkey(array))
}

/// `0x`-prefixed hex, through the same adapter the beacon node writes its own
/// responses with.
pub fn encode_hex(bytes: &[u8]) -> String {
    ethlambda_types::beacon::serde_helpers::HexPrefixed(bytes).to_string()
}

/// Reads one `0x`-prefixed, 4-byte fork version out of a `GET
/// /eth/v1/config/spec` response. `None` when `key` is absent (the fork is
/// simply not named), `Err` when it is present but malformed.
fn spec_version(value: &serde_json::Value, key: &str) -> Result<Option<Version>> {
    let Some(field) = value.get(key) else {
        return Ok(None);
    };
    let text = field
        .as_str()
        .ok_or_else(|| Error::Decode(format!("config/spec: {key} is not a string")))?;
    let bytes = hex::decode(text.strip_prefix("0x").unwrap_or(text))
        .map_err(|err| Error::Decode(format!("config/spec: bad hex for {key}: {err}")))?;
    let version: Version = bytes.try_into().map_err(|got: Vec<u8>| {
        Error::Decode(format!(
            "config/spec: {key} is {} bytes, expected 4",
            got.len()
        ))
    })?;
    Ok(Some(version))
}

/// Reads one quoted `u64` out of a `GET /eth/v1/config/spec` response. `None`
/// when `key` is absent, `Err` when it is present but malformed.
fn spec_u64(value: &serde_json::Value, key: &str) -> Result<Option<u64>> {
    let Some(field) = value.get(key) else {
        return Ok(None);
    };
    field
        .as_str()
        .ok_or_else(|| Error::Decode(format!("config/spec: {key} is not a string")))?
        .parse()
        .map(Some)
        .map_err(|err| Error::Decode(format!("config/spec: bad integer for {key}: {err}")))
}

/// Build a [`Config`] from a `GET /eth/v1/config/spec` response.
///
/// Starts from the mainnet defaults and overrides only what the response
/// names, because a validator client has to work against a network whose fork
/// schedule differs while the compile-time presets, which fix SSZ list bounds,
/// necessarily do not.
///
/// An absent key keeps its default: a fork this network has not scheduled is
/// normal. A key that is present but unparseable is an error, because silently
/// falling back to a mainnet default would leave the client signing under the
/// wrong fork version, which the network rejects without telling us why.
///
/// Phase0 is handled outside the `ForkName::ALL` loop: its version is named
/// `GENESIS_FORK_VERSION` rather than `PHASE0_FORK_VERSION`, and it has no
/// `PHASE0_FORK_EPOCH` at all, since phase0's activation is always epoch 0.
pub fn config_from_spec_response(value: &serde_json::Value) -> Result<Config> {
    let mut config = Config::mainnet();

    // `SLOT_DURATION_MS` first, `SECONDS_PER_SLOT` only as a fallback.
    //
    // The specification deleted `SECONDS_PER_SLOT` outright; it appears nowhere
    // in the configs, presets or specs, and a spec-current node no longer emits
    // it. Reading only that key, as this did, meant a node that had moved on
    // left the slot length at its compiled-in mainnet default. On mainnet that
    // default is right and the bug is invisible. On anything else the client
    // would run a 12-second clock against a chain with a different slot and
    // miss every duty, while the startup log printed the wrong number
    // confidently.
    //
    // The fallback stays because the key's removal is recent and deployed nodes
    // still send it. A node that sends both is asked to agree with itself.
    let duration_ms = spec_u64(value, "SLOT_DURATION_MS")?;
    let seconds = spec_u64(value, "SECONDS_PER_SLOT")?;
    if let (Some(duration_ms), Some(seconds)) = (duration_ms, seconds)
        && duration_ms != seconds * 1_000
    {
        return Err(Error::Decode(format!(
            "config/spec: SLOT_DURATION_MS is {duration_ms} but SECONDS_PER_SLOT is {seconds}; \
             they describe the same slot and disagree"
        )));
    }
    if let Some(slot_duration_ms) = duration_ms.or_else(|| seconds.map(|s| s * 1_000)) {
        if slot_duration_ms == 0 {
            return Err(Error::Decode(
                "config/spec: the slot duration is 0".to_string(),
            ));
        }
        config.slot_duration_ms = slot_duration_ms;
        // Kept in step because other code still reads it. Truncating is
        // correct for every network that reports a whole number of seconds,
        // and the millisecond field is what the clock actually uses.
        config.seconds_per_slot = slot_duration_ms / 1_000;
    }

    // The duty offsets. Absent means the node has not moved to the
    // basis-point form yet, in which case the mainnet defaults already in
    // `Config` are the right answer for every network that predates it.
    if let Some(bps) = spec_u64(value, "ATTESTATION_DUE_BPS")? {
        config.attestation_due_bps = bps;
    }
    if let Some(bps) = spec_u64(value, "AGGREGATE_DUE_BPS")? {
        config.aggregate_due_bps = bps;
    }
    if let Some(version) = spec_version(value, "GENESIS_FORK_VERSION")? {
        config = config.with_fork_version(ForkName::Phase0, version);
    }

    for fork in ForkName::ALL {
        if fork == ForkName::Phase0 {
            continue;
        }
        let name = fork.as_str().to_uppercase();
        if let Some(epoch) = spec_u64(value, &format!("{name}_FORK_EPOCH"))? {
            config = config.with_fork_epoch(fork, epoch);
        }
        if let Some(version) = spec_version(value, &format!("{name}_FORK_VERSION"))? {
            config = config.with_fork_version(fork, version);
        }
    }

    Ok(config)
}

impl TryFrom<&AttestationDto> for Attestation {
    type Error = Error;

    /// The bitfields decode through SSZ, not by hand: the hex *is* their SSZ
    /// encoding, sentinel bit included for the bitlist, so decoding it this way
    /// cannot disagree with what the node would have sent as SSZ.
    fn try_from(dto: &AttestationDto) -> Result<Self> {
        let aggregation_bits =
            AggregationBits::from_ssz_bytes(&parse_hex(&dto.aggregation_bits, "aggregation_bits")?)
                .map_err(|err| Error::Decode(format!("aggregation_bits: {err:?}")))?;
        let committee_bits =
            CommitteeBits::from_ssz_bytes(&parse_hex(&dto.committee_bits, "committee_bits")?)
                .map_err(|err| Error::Decode(format!("committee_bits: {err:?}")))?;
        Ok(Attestation {
            aggregation_bits,
            data: AttestationData::try_from(&dto.data)?,
            signature: parse_signature(&dto.signature)?,
            committee_bits,
        })
    }
}

impl TryFrom<&AttestationDataDto> for AttestationData {
    type Error = Error;

    fn try_from(dto: &AttestationDataDto) -> Result<Self> {
        Ok(AttestationData {
            slot: dto.slot,
            index: dto.index,
            beacon_block_root: parse_root(&dto.beacon_block_root)?,
            source: Checkpoint {
                epoch: dto.source.epoch,
                root: parse_root(&dto.source.root)?,
            },
            target: Checkpoint {
                epoch: dto.target.epoch,
                root: parse_root(&dto.target.root)?,
            },
        })
    }
}

impl From<&AttestationData> for AttestationDataOutDto {
    fn from(data: &AttestationData) -> Self {
        Self {
            slot: data.slot,
            index: data.index,
            beacon_block_root: encode_hex(&data.beacon_block_root.0),
            source: CheckpointOutDto {
                epoch: data.source.epoch,
                root: encode_hex(&data.source.root.0),
            },
            target: CheckpointOutDto {
                epoch: data.target.epoch,
                root: encode_hex(&data.target.root.0),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `GET /eth/v1/validator/attestation_data` body.
    const ATTESTATION_DATA: &str = r#"{
        "data": {
            "slot": "12345678",
            "index": "0",
            "beacon_block_root": "0x2f6ef3b4f5a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6",
            "source": { "epoch": "385801", "root": "0x1111111111111111111111111111111111111111111111111111111111111111" },
            "target": { "epoch": "385802", "root": "0x2222222222222222222222222222222222222222222222222222222222222222" }
        }
    }"#;

    /// A real `POST /eth/v1/validator/duties/attester/{epoch}` body.
    const DUTIES: &str = r#"{
        "dependent_root": "0x3333333333333333333333333333333333333333333333333333333333333333",
        "execution_optimistic": false,
        "data": [{
            "pubkey": "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "validator_index": "1337",
            "committee_index": "3",
            "committee_length": "128",
            "committees_at_slot": "64",
            "validator_committee_index": "17",
            "slot": "12345678"
        }]
    }"#;

    #[test]
    fn parses_attestation_data_and_converts_to_the_container() {
        let response: DataResponse<AttestationDataDto> =
            serde_json::from_str(ATTESTATION_DATA).expect("parses");
        assert_eq!(response.data.slot, 12_345_678);
        assert_eq!(response.data.index, 0);

        let data = AttestationData::try_from(&response.data).expect("converts");
        assert_eq!(data.slot, 12_345_678);
        assert_eq!(data.target.epoch, 385_802);
        assert_eq!(data.source.epoch, 385_801);
        assert_eq!(data.target.root.0[0], 0x22);
    }

    #[test]
    fn parses_the_duties_envelope_and_its_dependent_root() {
        let response: DutiesResponse<Vec<AttesterDutyDto>> =
            serde_json::from_str(DUTIES).expect("parses");
        assert_eq!(
            response.dependent_root,
            "0x3333333333333333333333333333333333333333333333333333333333333333"
        );
        assert_eq!(response.data.len(), 1);
        let duty = &response.data[0];
        assert_eq!(duty.validator_index, 1337);
        assert_eq!(duty.committee_index, 3);
        assert_eq!(duty.committees_at_slot, 64);
        assert_eq!(duty.slot, 12_345_678);
        parse_pubkey(&duty.pubkey).expect("pubkey parses");
    }

    #[test]
    fn a_submitted_attestation_quotes_its_integers() {
        let data = AttestationData {
            slot: 12_345_678,
            index: 0,
            beacon_block_root: Root::ZERO,
            source: Checkpoint {
                epoch: 1,
                root: Root::ZERO,
            },
            target: Checkpoint {
                epoch: 2,
                root: Root::ZERO,
            },
        };
        let dto = SingleAttestationDto {
            committee_index: 3,
            attester_index: 1337,
            data: AttestationDataOutDto::from(&data),
            signature: encode_hex(&[0u8; 96]),
        };
        let json = serde_json::to_string(&dto).expect("serialises");

        assert!(json.contains(r#""committee_index":"3""#), "got {json}");
        assert!(json.contains(r#""attester_index":"1337""#), "got {json}");
        assert!(json.contains(r#""slot":"12345678""#), "got {json}");
        assert!(json.contains(r#""signature":"0x0000"#), "got {json}");
    }

    /// A real `/eth/v2/validator/aggregate_attestation` body, captured from
    /// Lighthouse v8.2.2 on a kurtosis devnet. It came back as JSON to a
    /// request whose `Accept` named only SSZ, which is why this client decodes
    /// aggregates from JSON at all.
    const LIGHTHOUSE_AGGREGATE: &str = r#"{
        "version": "fulu",
        "data": {
            "aggregation_bits": "0x3f",
            "data": {
                "slot": "5",
                "index": "0",
                "beacon_block_root": "0x7080aca835d465ab7ffad4f2405cc8f2cb7d5e0f511d131f2263344f2be95b55",
                "source": { "epoch": "0", "root": "0x0000000000000000000000000000000000000000000000000000000000000000" },
                "target": { "epoch": "0", "root": "0x96e2147b3fe25eb01b4b310790bfc89ffe9db275f95f05433c1384847ea9e5f5" }
            },
            "signature": "0xae80eb73a6b1716689185b991ce5cd0f9b5b12d699d2beaf32a89704a5335a3c85a91d5c2808639f3d777115fc9fadda00e34157d9abc92944f51f0abcc025426ca5bf9f3dd645d3fda8cbb9d1c88abdd7661c3a23160f10137be5c9bb16f04e",
            "committee_bits": "0x0100000000000000"
        }
    }"#;

    #[test]
    fn a_lighthouse_aggregate_decodes_into_the_electra_container() {
        let response: VersionedResponse<AttestationDto> =
            serde_json::from_str(LIGHTHOUSE_AGGREGATE).expect("parses");
        assert_eq!(response.version, "fulu");

        let attestation = Attestation::try_from(&response.data).expect("converts");
        assert_eq!(attestation.data.slot, 5);
        assert_eq!(attestation.data.index, 0, "electra requires index 0");

        // 0x3f is a five-member committee, all voting, plus the bitlist's
        // sentinel bit. Decoding it through SSZ is what keeps the sentinel
        // from being read as a sixth voter.
        assert_eq!(attestation.aggregation_bits.len(), 5);
        assert!((0..5).all(|i| attestation.aggregation_bits.get(i).unwrap_or(false)));

        // One committee named, committee 0, as electra's gossip rules require.
        assert!(attestation.committee_bits.get(0).unwrap_or(false));
        assert!((1..64).all(|i| !attestation.committee_bits.get(i).unwrap_or(false)));
    }

    /// The bitfields decode through SSZ, so re-encoding must give back the
    /// exact bytes the node sent. That is what makes the root this client signs
    /// over the one the node would have produced from SSZ.
    #[test]
    fn an_aggregates_bitfields_round_trip_byte_for_byte() {
        use libssz::SszEncode as _;
        let response: VersionedResponse<AttestationDto> =
            serde_json::from_str(LIGHTHOUSE_AGGREGATE).expect("parses");
        let attestation = Attestation::try_from(&response.data).expect("converts");

        assert_eq!(encode_hex(&attestation.aggregation_bits.to_ssz()), "0x3f");
        assert_eq!(
            encode_hex(&attestation.committee_bits.to_ssz()),
            "0x0100000000000000"
        );
        assert_eq!(
            encode_hex(&attestation.signature.0),
            response.data.signature
        );
    }

    /// What gets sent back: the aggregate that came in, wrapped and signed,
    /// with the index quoted and the bitfields in the same hex form they
    /// arrived in. Lighthouse refuses an SSZ body on this endpoint, so this
    /// JSON is the only form that reaches it.
    #[test]
    fn a_signed_aggregate_serialises_the_way_it_arrived() {
        use ethlambda_types::beacon::containers::electra::AggregateAndProof;

        let response: VersionedResponse<AttestationDto> =
            serde_json::from_str(LIGHTHOUSE_AGGREGATE).expect("parses");
        let aggregate = Attestation::try_from(&response.data).expect("converts");
        let signed = SignedAggregateAndProof {
            message: AggregateAndProof {
                aggregator_index: 131,
                aggregate,
                selection_proof: BlsSignature([7; 96]),
            },
            signature: BlsSignature([9; 96]),
        };

        let json = serde_json::to_value([SignedAggregateAndProofOutDto::from(&signed)])
            .expect("serialises");
        assert!(json.is_array(), "the endpoint takes a bare array");
        let message = &json[0]["message"];
        assert_eq!(message["aggregator_index"], "131");
        assert_eq!(message["aggregate"]["aggregation_bits"], "0x3f");
        assert_eq!(message["aggregate"]["committee_bits"], "0x0100000000000000");
        assert_eq!(message["aggregate"]["data"]["slot"], "5");
        assert_eq!(message["aggregate"]["signature"], response.data.signature);
    }

    #[test]
    fn a_signature_of_the_wrong_length_is_rejected() {
        let err = parse_signature("0x1234").expect_err("must reject");
        assert!(matches!(err, Error::Decode(_)), "got {err:?}");
    }

    #[test]
    fn a_root_of_the_wrong_length_is_rejected() {
        let err = parse_root("0x1234").expect_err("must reject");
        assert!(matches!(err, Error::Decode(_)), "got {err:?}");
    }

    /// A real `GET /eth/v1/beacon/genesis` body (mainnet's values), including
    /// `genesis_fork_version`, which the DTO deliberately does not declare.
    const GENESIS: &str = r#"{
        "data": {
            "genesis_time": "1606824023",
            "genesis_validators_root": "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe9",
            "genesis_fork_version": "0x00000000"
        }
    }"#;

    #[test]
    fn parses_genesis_ignoring_the_fork_version_it_does_not_declare() {
        let response: DataResponse<GenesisDto> = serde_json::from_str(GENESIS).expect("parses");
        assert_eq!(response.data.genesis_time, 1_606_824_023);
        assert_eq!(
            response.data.genesis_validators_root,
            "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe9"
        );
    }

    /// A real `GET /eth/v1/node/syncing` body, carrying all five spec fields;
    /// only two are declared here.
    const SYNCING: &str = r#"{
        "data": {
            "head_slot": "12345678",
            "sync_distance": "0",
            "is_syncing": false,
            "is_optimistic": true,
            "el_offline": false
        }
    }"#;

    #[test]
    fn parses_syncing_ignoring_the_fields_it_does_not_declare() {
        let response: DataResponse<SyncingDto> = serde_json::from_str(SYNCING).expect("parses");
        assert!(!response.data.is_syncing);
        assert_eq!(response.data.is_optimistic, Some(true));
    }

    /// A real `POST /eth/v1/beacon/states/head/validators` body, including
    /// `balance`, which the DTO deliberately does not declare.
    const VALIDATORS: &str = r#"{
        "data": [{
            "index": "1337",
            "balance": "32000000000",
            "status": "active_ongoing",
            "validator": {
                "pubkey": "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
                "withdrawal_credentials": "0x010000000000000000000000000000000000000000000000000000000000",
                "effective_balance": "32000000000",
                "slashed": false,
                "activation_eligibility_epoch": "0",
                "activation_epoch": "0",
                "exit_epoch": "18446744073709551615",
                "withdrawable_epoch": "18446744073709551615"
            }
        }]
    }"#;

    #[test]
    fn parses_a_validator_entry_ignoring_the_balance_it_does_not_declare() {
        let response: DataResponse<Vec<ValidatorEntryDto>> =
            serde_json::from_str(VALIDATORS).expect("parses");
        let entry = &response.data[0];
        assert_eq!(entry.index, 1337);
        assert_eq!(entry.status, "active_ongoing");
        parse_pubkey(&entry.validator.pubkey).expect("pubkey parses");
    }

    #[test]
    fn a_committee_subscription_quotes_its_integers_but_not_the_flag() {
        let dto = CommitteeSubscriptionDto {
            validator_index: 1337,
            committee_index: 3,
            committees_at_slot: 64,
            slot: 12_345_678,
            is_aggregator: true,
        };
        let json = serde_json::to_string(&dto).expect("serialises");

        assert!(json.contains(r#""validator_index":"1337""#), "got {json}");
        assert!(json.contains(r#""committee_index":"3""#), "got {json}");
        assert!(json.contains(r#""committees_at_slot":"64""#), "got {json}");
        assert!(json.contains(r#""slot":"12345678""#), "got {json}");
        assert!(
            json.contains(r#""is_aggregator":true"#),
            "is_aggregator must be a bare boolean, got {json}"
        );
    }

    #[test]
    fn a_spec_response_overrides_only_what_it_names() {
        let response = serde_json::json!({
            "SECONDS_PER_SLOT": "12",
            "ELECTRA_FORK_EPOCH": "364032",
        });
        let config = config_from_spec_response(&response).expect("builds");
        assert_eq!(config.seconds_per_slot, 12);
        assert_eq!(config.fork_epoch(ForkName::Electra), 364_032);
        // Untouched by the response, so still the mainnet default.
        assert_eq!(config.min_genesis_time, Config::mainnet().min_genesis_time);
    }

    /// The key the specification actually ships now. Reading only the old one
    /// left the slot length at a compiled-in mainnet default, which is right on
    /// mainnet and wrong everywhere else.
    #[test]
    fn the_slot_duration_is_read_from_the_millisecond_key() {
        let response = serde_json::json!({ "SLOT_DURATION_MS": "6000" });
        let config = config_from_spec_response(&response).expect("builds");
        assert_eq!(config.slot_duration_ms, 6_000);
        assert_eq!(config.seconds_per_slot, 6, "the older field tracks it");
    }

    /// Deployed nodes still send the removed key, so it stays as a fallback.
    #[test]
    fn a_node_still_sending_only_seconds_per_slot_is_understood() {
        let response = serde_json::json!({ "SECONDS_PER_SLOT": "6" });
        let config = config_from_spec_response(&response).expect("builds");
        assert_eq!(config.slot_duration_ms, 6_000);
        assert_eq!(config.seconds_per_slot, 6);
    }

    /// A node sending both is asked to agree with itself. They describe one
    /// slot, so a disagreement means one of them is wrong and there is no way
    /// to tell which.
    #[test]
    fn a_node_contradicting_itself_about_the_slot_length_is_rejected() {
        let response = serde_json::json!({
            "SLOT_DURATION_MS": "12000",
            "SECONDS_PER_SLOT": "6",
        });
        let err = config_from_spec_response(&response).expect_err("must reject");
        assert!(matches!(err, Error::Decode(_)), "got {err:?}");
    }

    #[test]
    fn a_node_agreeing_with_itself_about_the_slot_length_is_accepted() {
        let response = serde_json::json!({
            "SLOT_DURATION_MS": "6000",
            "SECONDS_PER_SLOT": "6",
        });
        let config = config_from_spec_response(&response).expect("builds");
        assert_eq!(config.slot_duration_ms, 6_000);
    }

    /// The duty offsets follow the network rather than being divided out of the
    /// slot, which is what makes a fork that moves them work at all.
    #[test]
    fn the_duty_offsets_are_read_from_the_response() {
        let response = serde_json::json!({
            "ATTESTATION_DUE_BPS": "2500",
            "AGGREGATE_DUE_BPS": "5000",
        });
        let config = config_from_spec_response(&response).expect("builds");
        assert_eq!(config.attestation_due_bps, 2_500);
        assert_eq!(config.aggregate_due_bps, 5_000);
    }

    /// A node that has not moved to the basis-point form keeps the defaults,
    /// which are the right answer for every network that predates it.
    #[test]
    fn absent_duty_offsets_keep_the_defaults() {
        let config = config_from_spec_response(&serde_json::json!({})).expect("builds");
        assert_eq!(config.attestation_due_bps, 3_333);
        assert_eq!(config.aggregate_due_bps, 6_667);
    }

    #[test]
    fn the_genesis_fork_version_is_read_under_its_own_name() {
        // No node ever sends PHASE0_FORK_VERSION; the spec calls it
        // GENESIS_FORK_VERSION. This is the regression the review caught: the
        // naive per-fork loop could never reach this field.
        let response = serde_json::json!({
            "GENESIS_FORK_VERSION": "0x01020304",
        });
        let config = config_from_spec_response(&response).expect("builds");
        assert_eq!(
            config.fork_version(ForkName::Phase0),
            [0x01, 0x02, 0x03, 0x04]
        );
    }

    #[test]
    fn a_present_but_malformed_value_is_an_error_not_a_silent_default() {
        let response = serde_json::json!({
            "GENESIS_FORK_VERSION": "0xzz",
        });
        let err = config_from_spec_response(&response).expect_err("must reject");
        assert!(matches!(err, Error::Decode(_)), "got {err:?}");
    }

    #[test]
    fn a_zero_slot_duration_is_rejected_rather_than_handed_to_the_clock() {
        // A slot clock divides by this value; a beacon node reporting 0 is
        // not a network we cannot support, it is a response that cannot be
        // true.
        let response = serde_json::json!({
            "SECONDS_PER_SLOT": "0",
        });
        let err = config_from_spec_response(&response).expect_err("must reject");
        assert!(matches!(err, Error::Decode(_)), "got {err:?}");
    }

    #[test]
    fn a_double_prefixed_version_is_rejected_rather_than_silently_stripped() {
        // Only one "0x" is ever stripped, matching `parse_root`'s convention;
        // a second one must fail to decode as hex rather than be swallowed.
        let response = serde_json::json!({
            "GENESIS_FORK_VERSION": "0x0x000102",
        });
        let err = config_from_spec_response(&response).expect_err("must reject");
        assert!(matches!(err, Error::Decode(_)), "got {err:?}");
    }
}
