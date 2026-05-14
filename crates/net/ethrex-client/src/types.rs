//! Engine API V3 wire types.
//!
//! Field names + hex encodings match the canonical execution-apis schema
//! so JSON wire format is identical to lighthouse/teku/prysm/ethrex.
//!
//! Only the V3 (Cancun) subset is defined here. V1/V2 are unused by Lean;
//! V4/V5 (Prague+) will be added when needed.

use ethlambda_types::primitives::H256;
use serde::{Deserialize, Serialize};

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
    #[serde(with = "hex_address")]
    pub suggested_fee_recipient: [u8; 20],
    pub withdrawals: Vec<Withdrawal>,
    pub parent_beacon_block_root: H256,
}

/// EIP-4895 withdrawal record carried in payload attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Withdrawal {
    #[serde(with = "hex_u64")]
    pub index: u64,
    #[serde(with = "hex_u64")]
    pub validator_index: u64,
    #[serde(with = "hex_address")]
    pub address: [u8; 20],
    #[serde(with = "hex_u64")]
    pub amount: u64,
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

/// `ExecutionPayloadV3` — Cancun-era payload shape.
///
/// Not consumed by M4 (the FCU-on-tick scaffold) but defined so that the
/// `engine_newPayloadV3` / `engine_getPayloadV3` wrappers compile against
/// the right schema for later milestones.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionPayloadV3 {
    pub parent_hash: H256,
    #[serde(with = "hex_address")]
    pub fee_recipient: [u8; 20],
    pub state_root: H256,
    pub receipts_root: H256,
    #[serde(with = "hex_bytes")]
    pub logs_bloom: Vec<u8>,
    pub prev_randao: H256,
    #[serde(with = "hex_u64")]
    pub block_number: u64,
    #[serde(with = "hex_u64")]
    pub gas_limit: u64,
    #[serde(with = "hex_u64")]
    pub gas_used: u64,
    #[serde(with = "hex_u64")]
    pub timestamp: u64,
    #[serde(with = "hex_bytes")]
    pub extra_data: Vec<u8>,
    #[serde(with = "hex_u256")]
    pub base_fee_per_gas: [u8; 32],
    pub block_hash: H256,
    pub transactions: Vec<HexBytes>,
    pub withdrawals: Vec<Withdrawal>,
    #[serde(with = "hex_u64")]
    pub blob_gas_used: u64,
    #[serde(with = "hex_u64")]
    pub excess_blob_gas: u64,
}

/// Hex-encoded byte string wrapper for typed `Vec<HexBytes>` fields
/// (the spec encodes each transaction as a `DATA` string).
#[derive(Debug, Clone)]
pub struct HexBytes(pub Vec<u8>);

impl Serialize for HexBytes {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&format!("0x{}", hex::encode(&self.0)))
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        let stripped = s.strip_prefix("0x").unwrap_or(&s);
        hex::decode(stripped)
            .map(HexBytes)
            .map_err(serde::de::Error::custom)
    }
}

// ---------- Hex serde helpers ----------

mod hex_u64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &u64, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&format!("0x{v:x}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<u64, D::Error> {
        let s = String::deserialize(de)?;
        let stripped = s.strip_prefix("0x").unwrap_or(&s);
        u64::from_str_radix(stripped, 16).map_err(serde::de::Error::custom)
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&format!("0x{}", hex::encode(v)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(de)?;
        let stripped = s.strip_prefix("0x").unwrap_or(&s);
        hex::decode(stripped).map_err(serde::de::Error::custom)
    }
}

mod hex_u256 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        // Trim leading zero bytes for the canonical `QUANTITY` form.
        let first_nonzero = v.iter().position(|b| *b != 0).unwrap_or(31);
        let stripped = &v[first_nonzero..];
        let hex_str = hex::encode(stripped);
        // Remove leading zero nibble (canonical form has no leading zero in odd-length).
        let trimmed = hex_str.trim_start_matches('0');
        let out = if trimmed.is_empty() { "0" } else { trimmed };
        ser.serialize_str(&format!("0x{out}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(de)?;
        let stripped = s.strip_prefix("0x").unwrap_or(&s);
        // Left-pad to 64 hex chars (32 bytes); reject overflow.
        if stripped.len() > 64 {
            return Err(serde::de::Error::custom(format!(
                "u256 hex too long: {} chars (max 64)",
                stripped.len()
            )));
        }
        let padded = format!("{stripped:0>64}");
        let bytes = hex::decode(&padded).map_err(serde::de::Error::custom)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

/// 20-byte Ethereum address as a `0x`-prefixed hex `DATA` string.
mod hex_address {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 20], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&format!("0x{}", hex::encode(v)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 20], D::Error> {
        let s = String::deserialize(de)?;
        let stripped = s.strip_prefix("0x").unwrap_or(&s);
        let bytes = hex::decode(stripped).map_err(serde::de::Error::custom)?;
        if bytes.len() != 20 {
            return Err(serde::de::Error::custom(format!(
                "address expected 20 bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
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
    fn hex_u64_roundtrip() {
        #[derive(Serialize, Deserialize)]
        struct Wrap {
            #[serde(with = "hex_u64")]
            n: u64,
        }
        let s = serde_json::to_string(&Wrap { n: 0xdead_beef }).unwrap();
        assert_eq!(s, r#"{"n":"0xdeadbeef"}"#);
        let back: Wrap = serde_json::from_str(&s).unwrap();
        assert_eq!(back.n, 0xdead_beef);
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

    #[test]
    fn address_serializes_as_hex_data_string() {
        #[derive(Serialize, Deserialize)]
        struct Wrap {
            #[serde(with = "hex_address")]
            addr: [u8; 20],
        }
        let w = Wrap { addr: [0xab; 20] };
        let json = serde_json::to_string(&w).unwrap();
        let expected = format!(r#"{{"addr":"0x{}"}}"#, "ab".repeat(20));
        assert_eq!(json, expected);
        let back: Wrap = serde_json::from_str(&json).unwrap();
        assert_eq!(back.addr, w.addr);
    }

    #[test]
    fn address_rejects_wrong_length() {
        #[derive(Debug, Deserialize)]
        struct Wrap {
            #[serde(with = "hex_address")]
            #[allow(dead_code)]
            addr: [u8; 20],
        }
        let err = serde_json::from_str::<Wrap>(r#"{"addr":"0xabcd"}"#).unwrap_err();
        assert!(err.to_string().contains("expected 20 bytes"));
    }

    #[test]
    fn hex_u256_rejects_overflow_instead_of_panicking() {
        #[derive(Debug, Deserialize)]
        struct Wrap {
            #[serde(with = "hex_u256")]
            #[allow(dead_code)]
            n: [u8; 32],
        }
        // 65 hex chars = 33 bytes > 32; must error, not panic.
        let too_long = format!(r#"{{"n":"0x{}"}}"#, "a".repeat(65));
        let err = serde_json::from_str::<Wrap>(&too_long).unwrap_err();
        assert!(err.to_string().contains("too long"));
    }
}
