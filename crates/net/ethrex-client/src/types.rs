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
    pub address: [u8; 20],
    #[serde(with = "hex_u64")]
    pub amount: u64,
}

/// Opaque identifier returned by FCU when payload building was requested.
///
/// 8-byte big-endian-encoded ID; we treat it as a 16-char hex string on
/// the wire (`0x` + 16 hex digits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PayloadId(pub [u8; 8]);

impl PayloadId {
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

/// EL's verdict on a payload or forkchoice update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
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
        // Left-pad to 64 hex chars (32 bytes).
        let padded = format!("{stripped:0>64}");
        let bytes = hex::decode(&padded).map_err(serde::de::Error::custom)?;
        let mut out = [0u8; 32];
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
}
