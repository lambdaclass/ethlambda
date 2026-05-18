//! Canonical execution-payload schema types.
//!
//! These mirror Ethereum's `ExecutionPayloadV3` (Cancun) exactly: field names,
//! JSON encoding (`0x`-prefixed hex for `QUANTITY`/`DATA`, camelCase keys),
//! and field ordering match the canonical execution-apis spec. The Lean block
//! body embeds `ExecutionPayloadV3` directly, so the schema lives in the
//! types crate rather than in the engine API client.
//!
//! Phase 1a of M6 (see `docs/plans/engine-api-integration.md`): the types
//! move here from `ethlambda-ethrex-client` with their JSON serde unchanged.
//! SSZ derives and `ExecutionPayloadHeader` land in Phase 2 alongside the
//! `BlockBody` embed.

use serde::{Deserialize, Serialize};

use crate::primitives::H256;

/// EIP-4895 withdrawal record carried in payload attributes and inside
/// `ExecutionPayloadV3.withdrawals`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
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

/// `ExecutionPayloadV3` — Cancun-era payload shape.
///
/// Mirrors the canonical execution-apis schema verbatim. `transactions` is
/// a list of opaque `DATA` strings (RLP-encoded transactions); the EL is the
/// authority on encoding/validation.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
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

/// Hex-encoded byte string wrapper used for `Vec<HexBytes>` fields
/// (the spec encodes each transaction as a `DATA` string).
#[derive(Debug, Default, Clone)]
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
//
// These are `pub` so that engine-API wire types living in the
// `ethlambda-ethrex-client` crate (e.g. `PayloadAttributesV3`) can keep
// using them via `#[serde(with = "ethlambda_types::execution_payload::hex_u64")]`.

pub mod hex_u64 {
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

pub mod hex_bytes {
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

pub mod hex_u256 {
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
pub mod hex_address {
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

    #[test]
    fn execution_payload_v3_default_is_zero_init() {
        let p = ExecutionPayloadV3::default();
        assert!(p.parent_hash.is_zero());
        assert!(p.block_hash.is_zero());
        assert_eq!(p.fee_recipient, [0u8; 20]);
        assert_eq!(p.block_number, 0);
        assert!(p.transactions.is_empty());
        assert!(p.withdrawals.is_empty());
    }

    #[test]
    fn hex_bytes_roundtrip() {
        let hb = HexBytes(vec![0xde, 0xad, 0xbe, 0xef]);
        let json = serde_json::to_string(&hb).unwrap();
        assert_eq!(json, r#""0xdeadbeef""#);
        let back: HexBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(back.0, hb.0);
    }
}
