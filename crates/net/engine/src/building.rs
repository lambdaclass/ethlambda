//! The Engine API's payload-building half: `PayloadAttributesV3` going out on
//! `engine_forkchoiceUpdatedV3`, and `engine_getPayloadV5`'s answer coming
//! back.
//!
//! A proposer asks its execution client to start building on a head by sending
//! `forkchoiceUpdated` with attributes, gets a `payloadId` back, and later asks
//! for the payload by that id. `getPayloadV5` is Osaka's (fulu's) version: the
//! blobs bundle carries cell proofs (`CELLS_PER_EXT_BLOB` per blob) rather than
//! one proof per blob.
//!
//! The response is decoded straight into `ethlambda-types`' own containers, so
//! the block producer never sees a wire shape.

use ethlambda_types::beacon::containers::{bellatrix, capella, deneb, gloas};
use ethlambda_types::beacon::primitives::{
    Bytes32, ExecutionAddress, H160, H256, KzgCommitment, KzgProof, Root, U256, Uint256,
};
use serde::{Deserialize, Serialize, Serializer};

use crate::error::EngineError;
use crate::types::{data, quantity};

/// `PayloadAttributesV3`: what the execution client needs to build the payload
/// for one slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadAttributesV3 {
    /// The slot's start time, which becomes the payload's `timestamp`.
    pub timestamp: u64,
    /// The RANDAO mix the payload's `prevRandao` must equal.
    pub prev_randao: Bytes32,
    pub suggested_fee_recipient: ExecutionAddress,
    /// The withdrawals the consensus layer expects this payload to carry, as
    /// `get_expected_withdrawals` computes them for the slot.
    pub withdrawals: Vec<capella::Withdrawal>,
    pub parent_beacon_block_root: Root,
}

impl Serialize for PayloadAttributesV3 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let withdrawals: Vec<serde_json::Value> = self
            .withdrawals
            .iter()
            .map(|withdrawal| {
                serde_json::json!({
                    "index": quantity(withdrawal.index),
                    "validatorIndex": quantity(withdrawal.validator_index),
                    "address": data(&withdrawal.address.0),
                    "amount": quantity(withdrawal.amount),
                })
            })
            .collect();
        serde_json::json!({
            "timestamp": quantity(self.timestamp),
            "prevRandao": data(&self.prev_randao.0),
            "suggestedFeeRecipient": data(&self.suggested_fee_recipient.0),
            "withdrawals": withdrawals,
            "parentBeaconBlockRoot": data(&self.parent_beacon_block_root.0),
        })
        .serialize(serializer)
    }
}

/// `PayloadAttributesV4` (Amsterdam): `PayloadAttributesV3` plus the slot the
/// payload is built for and the gas limit the execution client should steer
/// toward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadAttributesV4 {
    /// V3's five fields, serialized flat alongside the two below.
    pub v3: PayloadAttributesV3,
    /// The payload's `slotNumber` (EIP-7843): the beacon slot, not derived
    /// from `timestamp` by the execution client.
    pub slot_number: u64,
    /// The `gasLimit` the payload should move toward, which the execution
    /// client steps to within the protocol's per-block bound.
    pub target_gas_limit: u64,
}

impl Serialize for PayloadAttributesV4 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = serde_json::to_value(&self.v3).map_err(serde::ser::Error::custom)?;
        let object = value
            .as_object_mut()
            .expect("PayloadAttributesV3 serializes as an object");
        object.insert("slotNumber".into(), quantity(self.slot_number).into());
        object.insert(
            "targetGasLimit".into(),
            quantity(self.target_gas_limit).into(),
        );
        value.serialize(serializer)
    }
}

/// The execution client's name for one build process, `DATA` of eight bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PayloadId(pub [u8; 8]);

impl<'de> Deserialize<'de> for PayloadId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        parse_fixed::<8>(&text)
            .map(PayloadId)
            .map_err(serde::de::Error::custom)
    }
}

impl Serialize for PayloadId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&data(&self.0))
    }
}

/// `engine_getPayloadV5`'s answer, decoded.
#[derive(Debug, Clone)]
pub struct BuiltPayload {
    pub execution_payload: deneb::ExecutionPayload,
    /// What the payload pays its fee recipient, in wei.
    pub block_value: Uint256,
    pub blobs_bundle: BlobsBundle,
    /// The EIP-7685 request list, each entry its type byte then its data.
    pub execution_requests: Vec<Vec<u8>>,
}

/// `engine_getPayloadV6`'s answer, decoded: [`BuiltPayload`] with Amsterdam's
/// `ExecutionPayloadV4`, which gloas's envelope carries.
#[derive(Debug, Clone)]
pub struct BuiltGloasPayload {
    pub execution_payload: gloas::ExecutionPayload,
    /// What the payload pays its fee recipient, in wei.
    pub block_value: Uint256,
    pub blobs_bundle: BlobsBundle,
    /// The EIP-7685 request list, each entry its type byte then its data.
    pub execution_requests: Vec<Vec<u8>>,
    /// The engine's `shouldOverrideBuilder`: it wants this payload built
    /// locally whatever a builder bid pays. Absent from an answer means false.
    pub should_override_builder: bool,
}

/// `BlobsBundleV2`: the payload's blobs, their commitments, and every blob's
/// `CELLS_PER_EXT_BLOB` cell proofs, flattened blob by blob.
#[derive(Debug, Clone, Default)]
pub struct BlobsBundle {
    pub commitments: Vec<KzgCommitment>,
    pub proofs: Vec<KzgProof>,
    pub blobs: Vec<Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetPayloadV5Response {
    execution_payload: ExecutionPayloadJson,
    block_value: String,
    blobs_bundle: BlobsBundleJson,
    #[serde(default)]
    execution_requests: Vec<String>,
}

/// `engine_getPayloadV6`'s answer: V5's, with `ExecutionPayloadV4`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetPayloadV6Response {
    execution_payload: ExecutionPayloadJson,
    block_value: String,
    blobs_bundle: BlobsBundleJson,
    #[serde(default)]
    should_override_builder: bool,
    #[serde(default)]
    execution_requests: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecutionPayloadJson {
    parent_hash: String,
    fee_recipient: String,
    state_root: String,
    receipts_root: String,
    logs_bloom: String,
    prev_randao: String,
    block_number: String,
    gas_limit: String,
    gas_used: String,
    timestamp: String,
    extra_data: String,
    base_fee_per_gas: String,
    block_hash: String,
    transactions: Vec<String>,
    withdrawals: Vec<WithdrawalJson>,
    blob_gas_used: String,
    excess_blob_gas: String,
    /// `ExecutionPayloadV4` only (Amsterdam).
    #[serde(default)]
    block_access_list: Option<String>,
    /// `ExecutionPayloadV4` only (Amsterdam).
    #[serde(default)]
    slot_number: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WithdrawalJson {
    index: String,
    validator_index: String,
    address: String,
    amount: String,
}

#[derive(Deserialize)]
struct BlobsBundleJson {
    commitments: Vec<String>,
    proofs: Vec<String>,
    blobs: Vec<String>,
}

impl TryFrom<GetPayloadV5Response> for BuiltPayload {
    type Error = EngineError;

    fn try_from(response: GetPayloadV5Response) -> Result<Self, EngineError> {
        let payload = response.execution_payload;
        let transactions = payload
            .transactions
            .iter()
            .map(|transaction| {
                bellatrix::Transaction::try_from(parse_data(transaction)?)
                    .map_err(|_| decode("a transaction exceeds MAX_BYTES_PER_TRANSACTION"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let withdrawals = decode_withdrawals(&payload.withdrawals)?;

        let execution_payload = deneb::ExecutionPayload {
            parent_hash: H256(parse_fixed(&payload.parent_hash)?),
            fee_recipient: H160(parse_fixed(&payload.fee_recipient)?),
            state_root: H256(parse_fixed(&payload.state_root)?),
            receipts_root: H256(parse_fixed(&payload.receipts_root)?),
            logs_bloom: bellatrix::LogsBloom::try_from(parse_data(&payload.logs_bloom)?)
                .map_err(|_| decode("logsBloom is not BYTES_PER_LOGS_BLOOM long"))?,
            prev_randao: H256(parse_fixed(&payload.prev_randao)?),
            block_number: parse_quantity(&payload.block_number)?,
            gas_limit: parse_quantity(&payload.gas_limit)?,
            gas_used: parse_quantity(&payload.gas_used)?,
            timestamp: parse_quantity(&payload.timestamp)?,
            extra_data: bellatrix::ExtraData::try_from(parse_data(&payload.extra_data)?)
                .map_err(|_| decode("extraData exceeds MAX_EXTRA_DATA_BYTES"))?,
            base_fee_per_gas: parse_uint256(&payload.base_fee_per_gas)?,
            block_hash: H256(parse_fixed(&payload.block_hash)?),
            transactions: transactions
                .try_into()
                .map_err(|_| decode("more transactions than MAX_TRANSACTIONS_PER_PAYLOAD"))?,
            withdrawals: withdrawals
                .try_into()
                .map_err(|_| decode("more withdrawals than MAX_WITHDRAWALS_PER_PAYLOAD"))?,
            blob_gas_used: parse_quantity(&payload.blob_gas_used)?,
            excess_blob_gas: parse_quantity(&payload.excess_blob_gas)?,
        };

        let blobs_bundle = decode_blobs_bundle(response.blobs_bundle)?;

        Ok(BuiltPayload {
            execution_payload,
            block_value: parse_uint256(&response.block_value)?,
            blobs_bundle,
            execution_requests: decode_requests(&response.execution_requests)?,
        })
    }
}

impl TryFrom<GetPayloadV6Response> for BuiltGloasPayload {
    type Error = EngineError;

    fn try_from(response: GetPayloadV6Response) -> Result<Self, EngineError> {
        let payload = response.execution_payload;
        let transactions = payload
            .transactions
            .iter()
            .map(|transaction| parse_data(transaction).map(gloas::Transaction::from))
            .collect::<Result<Vec<_>, _>>()?;
        let withdrawals = decode_withdrawals(&payload.withdrawals)?;
        let block_access_list = payload
            .block_access_list
            .as_deref()
            .ok_or_else(|| decode("ExecutionPayloadV4 carries no blockAccessList"))?;
        let slot_number = payload
            .slot_number
            .as_deref()
            .ok_or_else(|| decode("ExecutionPayloadV4 carries no slotNumber"))?;

        let execution_payload = gloas::ExecutionPayload {
            parent_hash: H256(parse_fixed(&payload.parent_hash)?),
            fee_recipient: H160(parse_fixed(&payload.fee_recipient)?),
            state_root: H256(parse_fixed(&payload.state_root)?),
            receipts_root: H256(parse_fixed(&payload.receipts_root)?),
            logs_bloom: bellatrix::LogsBloom::try_from(parse_data(&payload.logs_bloom)?)
                .map_err(|_| decode("logsBloom is not BYTES_PER_LOGS_BLOOM long"))?,
            prev_randao: H256(parse_fixed(&payload.prev_randao)?),
            block_number: parse_quantity(&payload.block_number)?,
            gas_limit: parse_quantity(&payload.gas_limit)?,
            gas_used: parse_quantity(&payload.gas_used)?,
            timestamp: parse_quantity(&payload.timestamp)?,
            extra_data: bellatrix::ExtraData::try_from(parse_data(&payload.extra_data)?)
                .map_err(|_| decode("extraData exceeds MAX_EXTRA_DATA_BYTES"))?,
            base_fee_per_gas: parse_uint256(&payload.base_fee_per_gas)?,
            block_hash: H256(parse_fixed(&payload.block_hash)?),
            transactions: transactions.into(),
            withdrawals: withdrawals.into(),
            blob_gas_used: parse_quantity(&payload.blob_gas_used)?,
            excess_blob_gas: parse_quantity(&payload.excess_blob_gas)?,
            block_access_list: parse_data(block_access_list)?.into(),
            slot_number: parse_quantity(slot_number)?,
        };

        Ok(BuiltGloasPayload {
            execution_payload,
            block_value: parse_uint256(&response.block_value)?,
            blobs_bundle: decode_blobs_bundle(response.blobs_bundle)?,
            execution_requests: decode_requests(&response.execution_requests)?,
            should_override_builder: response.should_override_builder,
        })
    }
}

fn decode_withdrawals(
    withdrawals: &[WithdrawalJson],
) -> Result<Vec<capella::Withdrawal>, EngineError> {
    withdrawals
        .iter()
        .map(|withdrawal| {
            Ok(capella::Withdrawal {
                index: parse_quantity(&withdrawal.index)?,
                validator_index: parse_quantity(&withdrawal.validator_index)?,
                address: H160(parse_fixed(&withdrawal.address)?),
                amount: parse_quantity(&withdrawal.amount)?,
            })
        })
        .collect()
}

fn decode_blobs_bundle(bundle: BlobsBundleJson) -> Result<BlobsBundle, EngineError> {
    Ok(BlobsBundle {
        commitments: bundle
            .commitments
            .iter()
            .map(|text| parse_fixed(text).map(KzgCommitment))
            .collect::<Result<_, _>>()?,
        proofs: bundle
            .proofs
            .iter()
            .map(|text| parse_fixed(text).map(KzgProof))
            .collect::<Result<_, _>>()?,
        blobs: bundle
            .blobs
            .iter()
            .map(|text| parse_data(text))
            .collect::<Result<_, _>>()?,
    })
}

fn decode_requests(requests: &[String]) -> Result<Vec<Vec<u8>>, EngineError> {
    requests.iter().map(|text| parse_data(text)).collect()
}

fn decode(message: &str) -> EngineError {
    EngineError::Decode(message.to_string())
}

/// A `DATA` of any length.
fn parse_data(text: &str) -> Result<Vec<u8>, EngineError> {
    let digits = text
        .strip_prefix("0x")
        .ok_or_else(|| decode("DATA must be 0x-prefixed"))?;
    hex::decode(digits).map_err(|err| EngineError::Decode(format!("DATA is not hex: {err}")))
}

/// A `DATA` of exactly `N` bytes.
fn parse_fixed<const N: usize>(text: &str) -> Result<[u8; N], EngineError> {
    parse_data(text)?.try_into().map_err(|bytes: Vec<u8>| {
        EngineError::Decode(format!("expected {N} bytes, got {}", bytes.len()))
    })
}

/// A `QUANTITY` that fits in 64 bits.
fn parse_quantity(text: &str) -> Result<u64, EngineError> {
    let digits = text
        .strip_prefix("0x")
        .ok_or_else(|| decode("QUANTITY must be 0x-prefixed"))?;
    u64::from_str_radix(digits, 16)
        .map_err(|err| EngineError::Decode(format!("QUANTITY is not a u64: {err}")))
}

/// A 256-bit `QUANTITY`, into `Uint256`'s little-endian bytes.
fn parse_uint256(text: &str) -> Result<Uint256, EngineError> {
    let digits = text
        .strip_prefix("0x")
        .ok_or_else(|| decode("QUANTITY must be 0x-prefixed"))?;
    if digits.is_empty() || digits.len() > 64 {
        return Err(decode("a 256-bit QUANTITY must have 1 to 64 hex digits"));
    }
    let padded = format!("{digits:0>64}");
    let mut bytes: [u8; 32] = hex::decode(padded)
        .map_err(|err| EngineError::Decode(format!("QUANTITY is not hex: {err}")))?
        .try_into()
        .expect("64 hex digits are 32 bytes");
    bytes.reverse();
    Ok(U256(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::uint256;

    fn response_json() -> serde_json::Value {
        serde_json::json!({
            "executionPayload": {
                "parentHash": format!("0x{}", "11".repeat(32)),
                "feeRecipient": format!("0x{}", "de".repeat(20)),
                "stateRoot": format!("0x{}", "22".repeat(32)),
                "receiptsRoot": format!("0x{}", "33".repeat(32)),
                "logsBloom": format!("0x{}", "00".repeat(256)),
                "prevRandao": format!("0x{}", "44".repeat(32)),
                "blockNumber": "0x10",
                "gasLimit": "0x1c9c380",
                "gasUsed": "0x0",
                "timestamp": "0x6553f100",
                "extraData": "0x",
                "baseFeePerGas": "0x7",
                "blockHash": format!("0x{}", "55".repeat(32)),
                "transactions": ["0x02f8"],
                "withdrawals": [{
                    "index": "0x1", "validatorIndex": "0x2",
                    "address": format!("0x{}", "66".repeat(20)), "amount": "0x3"
                }],
                "blobGasUsed": "0x0",
                "excessBlobGas": "0x0"
            },
            "blockValue": "0x1bc16d674ec80000",
            "blobsBundle": { "commitments": [], "proofs": [], "blobs": [] },
            "shouldOverrideBuilder": false,
            "executionRequests": ["0x00aa"]
        })
    }

    #[test]
    fn a_get_payload_v5_answer_decodes_into_the_consensus_containers() {
        let response: GetPayloadV5Response = serde_json::from_value(response_json()).unwrap();
        let built = BuiltPayload::try_from(response).unwrap();
        let payload = &built.execution_payload;
        assert_eq!(payload.block_number, 16);
        assert_eq!(payload.gas_limit, 30_000_000);
        assert_eq!(payload.block_hash, H256([0x55; 32]));
        assert_eq!(payload.fee_recipient, H160([0xde; 20]));
        assert_eq!(uint256(&payload.base_fee_per_gas), "0x7");
        assert_eq!(payload.transactions.len(), 1);
        assert_eq!(payload.withdrawals[0].validator_index, 2);
        assert_eq!(uint256(&built.block_value), "0x1bc16d674ec80000");
        assert_eq!(built.execution_requests, vec![vec![0x00, 0xaa]]);
    }

    #[test]
    fn a_wrong_width_hash_is_a_decode_error() {
        let mut json = response_json();
        json["executionPayload"]["blockHash"] = "0x1234".into();
        let response: GetPayloadV5Response = serde_json::from_value(json).unwrap();
        assert!(matches!(
            BuiltPayload::try_from(response),
            Err(EngineError::Decode(_))
        ));
    }

    #[test]
    fn payload_attributes_serialize_as_the_spec_names_them() {
        let attributes = PayloadAttributesV3 {
            timestamp: 12,
            prev_randao: H256([1; 32]),
            suggested_fee_recipient: H160([2; 20]),
            withdrawals: vec![capella::Withdrawal {
                index: 0,
                validator_index: 5,
                address: H160([3; 20]),
                amount: 10,
            }],
            parent_beacon_block_root: Root::repeat_byte(4),
        };
        let json = serde_json::to_value(&attributes).unwrap();
        assert_eq!(json["timestamp"], "0xc");
        assert_eq!(json["prevRandao"], format!("0x{}", "01".repeat(32)));
        assert_eq!(
            json["suggestedFeeRecipient"],
            format!("0x{}", "02".repeat(20))
        );
        assert_eq!(json["withdrawals"][0]["validatorIndex"], "0x5");
        assert_eq!(json["withdrawals"][0]["amount"], "0xa");
        assert_eq!(
            json["parentBeaconBlockRoot"],
            format!("0x{}", "04".repeat(32))
        );
    }

    #[test]
    fn a_zero_uint256_and_a_full_one_both_parse() {
        assert_eq!(uint256(&parse_uint256("0x0").unwrap()), "0x0");
        let max = format!("0x{}", "f".repeat(64));
        assert_eq!(uint256(&parse_uint256(&max).unwrap()), max);
        assert!(parse_uint256(&format!("0x{}", "f".repeat(65))).is_err());
    }

    fn v6_json() -> serde_json::Value {
        let mut json = response_json();
        json["executionPayload"]["blockAccessList"] = "0xc180".into();
        json["executionPayload"]["slotNumber"] = "0x1000".into();
        json["blobsBundle"] = serde_json::json!({
            "commitments": [format!("0x{}", "aa".repeat(48))],
            "proofs": [format!("0x{}", "bb".repeat(48)), format!("0x{}", "cc".repeat(48))],
            "blobs": [format!("0x{}", "01".repeat(8))],
        });
        json["executionRequests"] = serde_json::json!(["0x0011", "0x02ff"]);
        json
    }

    #[test]
    fn a_get_payload_v6_answer_decodes_into_the_gloas_containers() {
        let response: GetPayloadV6Response = serde_json::from_value(v6_json()).unwrap();
        let built = BuiltGloasPayload::try_from(response).unwrap();
        let payload = &built.execution_payload;
        assert_eq!(payload.slot_number, 0x1000);
        assert_eq!(payload.block_access_list.as_ref(), &[0xc1, 0x80]);
        assert_eq!(payload.block_hash, H256([0x55; 32]));
        assert_eq!(payload.transactions.len(), 1);
        assert_eq!(payload.withdrawals[0].amount, 3);
        assert_eq!(uint256(&built.block_value), "0x1bc16d674ec80000");
        assert_eq!(built.blobs_bundle.commitments.len(), 1);
        assert_eq!(built.blobs_bundle.proofs.len(), 2);
        assert_eq!(built.blobs_bundle.blobs, vec![vec![1u8; 8]]);
        assert_eq!(
            built.execution_requests,
            vec![vec![0x00, 0x11], vec![0x02, 0xff]]
        );
        assert!(!built.should_override_builder);
    }

    #[test]
    fn a_v6_answer_carries_should_override_builder_and_defaults_it_to_false() {
        let mut json = v6_json();
        json["shouldOverrideBuilder"] = true.into();
        let response: GetPayloadV6Response = serde_json::from_value(json).unwrap();
        assert!(
            BuiltGloasPayload::try_from(response)
                .unwrap()
                .should_override_builder
        );

        let mut json = v6_json();
        json.as_object_mut()
            .unwrap()
            .remove("shouldOverrideBuilder");
        let response: GetPayloadV6Response = serde_json::from_value(json).unwrap();
        assert!(
            !BuiltGloasPayload::try_from(response)
                .unwrap()
                .should_override_builder
        );
    }

    #[test]
    fn a_v6_answer_without_a_slot_number_is_a_decode_error() {
        let mut json = v6_json();
        json["executionPayload"]
            .as_object_mut()
            .unwrap()
            .remove("slotNumber");
        let response: GetPayloadV6Response = serde_json::from_value(json).unwrap();
        assert!(matches!(
            BuiltGloasPayload::try_from(response),
            Err(EngineError::Decode(_))
        ));
    }

    #[test]
    fn payload_attributes_v4_append_the_slot_and_target_gas_limit() {
        let attributes = PayloadAttributesV4 {
            v3: PayloadAttributesV3 {
                timestamp: 12,
                prev_randao: H256([1; 32]),
                suggested_fee_recipient: H160([2; 20]),
                withdrawals: vec![],
                parent_beacon_block_root: Root::repeat_byte(4),
            },
            slot_number: 4096,
            target_gas_limit: 60_000_000,
        };
        let json = serde_json::to_value(&attributes).unwrap();
        assert_eq!(json["timestamp"], "0xc");
        assert_eq!(json["slotNumber"], "0x1000");
        assert_eq!(json["targetGasLimit"], "0x3938700");
        assert_eq!(
            json["parentBeaconBlockRoot"],
            format!("0x{}", "04".repeat(32))
        );
    }
}
