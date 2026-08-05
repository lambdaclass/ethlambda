//! Engine API V3 wire types.
//!
//! Field names + hex encodings match the canonical execution-apis schema
//! so JSON wire format is identical to lighthouse/teku/prysm/ethrex.
//!
//! Only the V3 (Cancun) subset is defined here. V1/V2 are unused by Lean;
//! V4/V5 (Prague+) will be added when needed.
//!
//! The canonical block-component types (`ExecutionPayloadV3`, `Withdrawal`,
//! `HexBytes`, hex serde helpers) live in `ethlambda_types::execution_payload`
//! because the Lean `BlockBody` embeds them. The engine-API-only response
//! and request types (`ForkChoiceState`, `PayloadAttributesV3`,
//! `PayloadStatus`, etc.) stay here.

use ethlambda_types::execution_payload::{hex_bytes_fixed, hex_u64};
use ethlambda_types::primitives::H256;
use serde::{Deserialize, Serialize};

// Re-export the moved canonical types so existing callers
// (`ethlambda_ethrex_client::types::ExecutionPayloadV3`) keep working.
pub use ethlambda_types::execution_payload::{ExecutionPayloadV3, Withdrawal};

/// `engine_forkchoiceUpdated` head/safe/finalized triplet.
///
/// All hashes are *execution-layer* block hashes. For ethlambda's M4
/// scaffold, we pass zeros for all three; the EL responds `SYNCING`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkChoiceState {
    pub head_block_hash: H256,
    pub safe_block_hash: H256,
    pub finalized_block_hash: H256,
}

/// Optional attributes that tell the EL to start building a payload.
///
/// V3 = Cancun (introduces blob-related fields on the resulting payload but
/// the attributes themselves keep the V2 shape plus `parent_beacon_block_root`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadAttributesV3 {
    /// Unix seconds the EL should stamp on the produced block.
    #[serde(with = "hex_u64")]
    pub timestamp: u64,
    pub prev_randao: H256,
    #[serde(with = "hex_bytes_fixed")]
    pub suggested_fee_recipient: [u8; 20],
    pub withdrawals: Vec<Withdrawal>,
    pub parent_beacon_block_root: H256,
}

/// Opaque identifier returned by FCU when payload building was requested.
///
/// 8 bytes on the wire as a hex `DATA` string (`0x` + 16 hex digits), per
/// the execution-apis spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadId(pub [u8; 8]);

impl PayloadId {
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

impl Serialize for PayloadId {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PayloadId {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        let stripped = s.strip_prefix("0x").unwrap_or(&s);
        let bytes = hex::decode(stripped).map_err(serde::de::Error::custom)?;
        if bytes.len() != 8 {
            return Err(serde::de::Error::custom(format!(
                "PayloadId expected 8 bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 8];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }
}

/// EL's verdict on a payload or forkchoice update.
///
/// `SCREAMING_SNAKE_CASE` matches the canonical spec values
/// (`VALID`, `INVALID`, `SYNCING`, `ACCEPTED`, `INVALID_BLOCK_HASH`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PayloadStatusKind {
    Valid,
    Invalid,
    Syncing,
    Accepted,
    InvalidBlockHash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadStatus {
    pub status: PayloadStatusKind,
    pub latest_valid_hash: Option<H256>,
    pub validation_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkChoiceUpdatedResponse {
    pub payload_status: PayloadStatus,
    pub payload_id: Option<PayloadId>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forkchoice_state_roundtrip() {
        let original = ForkChoiceState {
            head_block_hash: H256([1; 32]),
            safe_block_hash: H256([2; 32]),
            finalized_block_hash: H256([3; 32]),
        };
        let json = serde_json::to_string(&original).unwrap();
        // camelCase + 0x-prefixed hex
        assert!(json.contains("headBlockHash"));
        assert!(json.contains("finalizedBlockHash"));
        let round: ForkChoiceState = serde_json::from_str(&json).unwrap();
        assert_eq!(round.head_block_hash.0, original.head_block_hash.0);
        assert_eq!(
            round.finalized_block_hash.0,
            original.finalized_block_hash.0
        );
    }

    #[test]
    fn payload_status_parses_syncing() {
        let json = r#"{"status":"SYNCING","latestValidHash":null,"validationError":null}"#;
        let parsed: PayloadStatus = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.status, PayloadStatusKind::Syncing);
    }

    #[test]
    fn fcu_response_with_no_payload_id() {
        let json = r#"{"payloadStatus":{"status":"VALID","latestValidHash":"0x0000000000000000000000000000000000000000000000000000000000000000","validationError":null},"payloadId":null}"#;
        let parsed: ForkChoiceUpdatedResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.payload_status.status, PayloadStatusKind::Valid);
        assert!(parsed.payload_id.is_none());
    }

    #[test]
    fn payload_status_invalid_block_hash_uses_screaming_snake() {
        let json = r#"{"status":"INVALID_BLOCK_HASH","latestValidHash":null,"validationError":"bad hash"}"#;
        let parsed: PayloadStatus = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.status, PayloadStatusKind::InvalidBlockHash);
        let back = serde_json::to_string(&parsed).unwrap();
        assert!(
            back.contains(r#""status":"INVALID_BLOCK_HASH""#),
            "got: {back}"
        );
    }

    #[test]
    fn payload_id_is_hex_string_on_wire() {
        let id = PayloadId([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, r#""0x0123456789abcdef""#);
        let back: PayloadId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn payload_id_rejects_wrong_length() {
        // 6 bytes instead of 8.
        let err = serde_json::from_str::<PayloadId>(r#""0x010203040506""#).unwrap_err();
        assert!(err.to_string().contains("expected 8 bytes"));
    }
}
