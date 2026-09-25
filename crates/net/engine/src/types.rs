//! The Engine API's JSON wire shapes.
//!
//! Views over the containers `ethlambda-types` already defines, not new
//! definitions: `ExecutionPayloadV3` is deneb's `ExecutionPayload` in JSON, and
//! deneb is the last fork whose payload shape changed, so electra and fulu reuse
//! it unchanged.
//!
//! Every 32-byte value is `DATA`, a `0x`-prefixed even-length hex string. Every
//! number crossing this boundary is `QUANTITY`, `0x`-prefixed with leading zeros
//! stripped: `0x0` for zero, never `0x00` and never `0x`.

use ethlambda_types::beacon::containers::deneb;
use ethlambda_types::beacon::primitives::{ExecutionBlockHash, Uint256};
use ethlambda_types::beacon::serde_helpers::HexPrefixed;
use serde::{Deserialize, Serialize, Serializer};

/// `PayloadStatusV1.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PayloadStatusValue {
    Valid,
    Invalid,
    Syncing,
    Accepted,
    InvalidBlockHash,
}

/// An execution client's answer about a payload, or about a fork choice head.
///
/// Both `engine_newPayloadV4` and `engine_forkchoiceUpdatedV3` return one of
/// these, which is what makes `forkchoiceUpdated` the channel by which a block
/// imported on `SYNCING` later becomes `VALID`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadStatusV1 {
    pub status: PayloadStatusValue,
    /// `#[serde(default)]` for the key being absent entirely; a present `null`
    /// needs nothing, since serde's own `Option` impl reads it as `None`. The
    /// hash itself goes through [`ExecutionBlockHash`]'s own `Deserialize`,
    /// which already takes `0x`-prefixed hex and already checks the length.
    #[serde(default)]
    pub latest_valid_hash: Option<ExecutionBlockHash>,
    #[serde(default)]
    pub validation_error: Option<String>,
}

/// `engine_forkchoiceUpdatedV3`'s first parameter.
///
/// The three hashes serialize through [`ExecutionBlockHash`]'s own `Serialize`,
/// which already writes the `0x`-prefixed lowercase hex the `DATA` encoding
/// wants. [`data`] is still needed for the payload below, whose `feeRecipient`
/// is an [`ExecutionAddress`](ethlambda_types::beacon::primitives::ExecutionAddress)
/// and has no `Serialize` impl of its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkchoiceStateV1 {
    pub head_block_hash: ExecutionBlockHash,
    pub safe_block_hash: ExecutionBlockHash,
    pub finalized_block_hash: ExecutionBlockHash,
}

/// `engine_forkchoiceUpdatedV3`'s result.
///
/// `payloadId` is deserialized and dropped: this client never sends
/// `payloadAttributes`, so an execution client has no build process to name, and
/// a follower would have nothing to do with the identifier if it did.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkchoiceUpdatedResponse {
    pub payload_status: PayloadStatusV1,
}

/// `engine_getClientVersionV1`'s element type, in both directions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientVersionV1 {
    pub code: String,
    pub name: String,
    pub version: String,
    pub commit: String,
}

/// `ExecutionPayloadV3`, borrowed from a decoded block rather than copied.
///
/// A newtype around a reference because a mainnet payload carries every
/// transaction in the block: cloning one to serialize it would double the
/// largest allocation on the import path for no gain.
///
/// Deneb's shape serves electra and fulu unchanged. Neither fork changed the
/// payload container, which is why `engine_newPayloadV4` still takes
/// `ExecutionPayloadV3` and why there is no `V4` of this structure to write.
pub struct ExecutionPayloadV3<'a>(pub &'a deneb::ExecutionPayload);

impl Serialize for ExecutionPayloadV3<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;

        let payload = self.0;
        let mut out = serializer.serialize_struct("ExecutionPayloadV3", 17)?;
        out.serialize_field("parentHash", &data(&payload.parent_hash.0))?;
        out.serialize_field("feeRecipient", &data(&payload.fee_recipient.0))?;
        out.serialize_field("stateRoot", &data(&payload.state_root.0))?;
        out.serialize_field("receiptsRoot", &data(&payload.receipts_root.0))?;
        out.serialize_field("logsBloom", &data(payload.logs_bloom.as_ref()))?;
        out.serialize_field("prevRandao", &data(&payload.prev_randao.0))?;
        out.serialize_field("blockNumber", &quantity(payload.block_number))?;
        out.serialize_field("gasLimit", &quantity(payload.gas_limit))?;
        out.serialize_field("gasUsed", &quantity(payload.gas_used))?;
        out.serialize_field("timestamp", &quantity(payload.timestamp))?;
        out.serialize_field("extraData", &data(payload.extra_data.as_ref()))?;
        out.serialize_field("baseFeePerGas", &uint256(&payload.base_fee_per_gas))?;
        out.serialize_field("blockHash", &data(&payload.block_hash.0))?;

        let transactions: Vec<String> = payload
            .transactions
            .iter()
            .map(|transaction| data(transaction.as_ref()))
            .collect();
        out.serialize_field("transactions", &transactions)?;

        let withdrawals: Vec<serde_json::Value> = payload
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
        out.serialize_field("withdrawals", &withdrawals)?;

        out.serialize_field("blobGasUsed", &quantity(payload.blob_gas_used))?;
        out.serialize_field("excessBlobGas", &quantity(payload.excess_blob_gas))?;
        out.end()
    }
}

/// Encodes a `DATA`: `0x`-prefixed, every byte rendered, no stripping.
pub fn data(bytes: &[u8]) -> String {
    HexPrefixed(bytes).to_string()
}

/// Encodes a `QUANTITY`: `0x`-prefixed, leading zeros stripped, `0x0` for zero.
pub fn quantity(value: u64) -> String {
    format!("0x{value:x}")
}

/// Encodes a 256-bit `QUANTITY`.
///
/// `U256` stores its bytes little-endian and the wire wants big-endian hex with
/// leading zeros stripped, so this reverses before encoding. Zero renders as
/// `0x0`: the `QUANTITY` grammar forbids both the empty `0x` that a naive strip
/// produces and the `0x00` that no stripping produces.
pub fn uint256(value: &Uint256) -> String {
    let mut bytes = value.0;
    bytes.reverse();
    let encoded = hex::encode(bytes);
    let trimmed = encoded.trim_start_matches('0');
    if trimmed.is_empty() {
        return "0x0".to_string();
    }
    format!("0x{trimmed}")
}

#[cfg(test)]
mod tests {
    use ethlambda_types::beacon::containers::bellatrix;
    use ethlambda_types::beacon::preset;
    use ethlambda_types::beacon::primitives::{Bytes32, ExecutionAddress, U256};

    use super::*;

    /// An otherwise-zero deneb execution payload whose `block_hash` is
    /// `block_hash`.
    ///
    /// Hand-built because the consensus containers do not derive `Default`, and
    /// `logs_bloom` is a fixed-length vector that has none even among its
    /// `SszList` neighbours. Matches the idiom in `stf/fulu.rs` and
    /// `containers/bellatrix.rs`.
    fn payload_with_block_hash(block_hash: ExecutionBlockHash) -> deneb::ExecutionPayload {
        deneb::ExecutionPayload {
            parent_hash: ExecutionBlockHash::ZERO,
            fee_recipient: ExecutionAddress::ZERO,
            state_root: Bytes32::ZERO,
            receipts_root: Bytes32::ZERO,
            logs_bloom: bellatrix::LogsBloom::try_from(vec![0u8; preset::BYTES_PER_LOGS_BLOOM])
                .expect("built at exactly BYTES_PER_LOGS_BLOOM"),
            prev_randao: Bytes32::ZERO,
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: Default::default(),
            base_fee_per_gas: Uint256::ZERO,
            block_hash,
            transactions: Default::default(),
            withdrawals: Default::default(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
        }
    }

    #[test]
    fn a_status_deserializes_from_the_wire_shape() {
        let json = r#"{
            "status": "SYNCING",
            "latestValidHash": null,
            "validationError": null
        }"#;
        let status: PayloadStatusV1 = serde_json::from_str(json).expect("the wire shape");

        assert_eq!(status.status, PayloadStatusValue::Syncing);
        assert_eq!(status.latest_valid_hash, None);
    }

    #[test]
    fn an_invalid_status_keeps_its_latest_valid_hash_and_reason() {
        let json = r#"{
            "status": "INVALID",
            "latestValidHash": "0x0202020202020202020202020202020202020202020202020202020202020202",
            "validationError": "invalid"
        }"#;
        let status: PayloadStatusV1 = serde_json::from_str(json).expect("the wire shape");

        assert_eq!(status.status, PayloadStatusValue::Invalid);
        assert_eq!(
            status.latest_valid_hash,
            Some(ExecutionBlockHash::repeat_byte(2))
        );
        assert_eq!(status.validation_error.as_deref(), Some("invalid"));
    }

    #[test]
    fn invalid_block_hash_uses_its_screaming_snake_name() {
        let json = r#"{"status": "INVALID_BLOCK_HASH"}"#;
        let status: PayloadStatusV1 = serde_json::from_str(json).expect("the wire shape");
        assert_eq!(status.status, PayloadStatusValue::InvalidBlockHash);
    }

    #[test]
    fn a_forkchoice_state_serializes_camel_case_and_hex() {
        let state = ForkchoiceStateV1 {
            head_block_hash: ExecutionBlockHash::repeat_byte(1),
            safe_block_hash: ExecutionBlockHash::repeat_byte(2),
            finalized_block_hash: ExecutionBlockHash::ZERO,
        };
        let json = serde_json::to_value(&state).expect("serializes");

        assert_eq!(
            json["headBlockHash"],
            "0x0101010101010101010101010101010101010101010101010101010101010101"
        );
        assert_eq!(
            json["finalizedBlockHash"],
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn a_payload_serializes_every_field_in_the_wire_names() {
        let payload = payload_with_block_hash(ExecutionBlockHash::repeat_byte(7));
        let json = serde_json::to_value(ExecutionPayloadV3(&payload)).expect("serializes");

        for field in [
            "parentHash",
            "feeRecipient",
            "stateRoot",
            "receiptsRoot",
            "logsBloom",
            "prevRandao",
            "blockNumber",
            "gasLimit",
            "gasUsed",
            "timestamp",
            "extraData",
            "baseFeePerGas",
            "blockHash",
            "transactions",
            "withdrawals",
            "blobGasUsed",
            "excessBlobGas",
        ] {
            assert!(json.get(field).is_some(), "missing {field}");
        }
        assert_eq!(json.as_object().expect("a JSON object").len(), 17);
        assert_eq!(
            json["blockHash"],
            "0x0707070707070707070707070707070707070707070707070707070707070707"
        );
    }

    #[test]
    fn quantities_strip_leading_zeros_and_zero_is_a_single_digit() {
        assert_eq!(quantity(0), "0x0");
        assert_eq!(quantity(1), "0x1");
        assert_eq!(quantity(255), "0xff");
        assert_eq!(quantity(4096), "0x1000");
    }

    #[test]
    fn a_uint256_renders_big_endian_with_leading_zeros_stripped() {
        assert_eq!(uint256(&U256::ZERO), "0x0");
        assert_eq!(uint256(&U256::from_u128(1)), "0x1");
        assert_eq!(uint256(&U256::from_u128(255)), "0xff");
        assert_eq!(uint256(&U256::from_u128(0x1_0000_0000)), "0x100000000");

        // The most significant byte set. Little-endian storage puts it last, and
        // the rendered form must lead with it.
        let mut most_significant = [0u8; 32];
        most_significant[31] = 0x0a;
        assert_eq!(
            uint256(&U256(most_significant)),
            format!("0xa{}", "0".repeat(62))
        );
    }
}
