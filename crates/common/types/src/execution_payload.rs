//! Canonical execution-payload schema types.
//!
//! These mirror Ethereum's `ExecutionPayloadV3` (Cancun) exactly: field names,
//! JSON encoding (`0x`-prefixed hex for `QUANTITY`/`DATA`, camelCase keys),
//! field ordering, and SSZ schema all match the canonical execution-apis spec.
//! The Lean block body embeds `ExecutionPayloadV3` directly, so the schema
//! lives in the types crate rather than in the engine API client.
//!
//! Variable-length list fields (`extra_data`, `transactions`, `withdrawals`)
//! use bounded SSZ types because the SSZ merkle layout requires the limit
//! at compile time. Their JSON serialization is handled by the
//! `byte_list_hex`, `transactions_serde`, and `withdrawals_serde` helper
//! modules below — the wire shape is the same hex/array form lighthouse
//! and prysm emit.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::SszList;
use serde::{Deserialize, Serialize};

use crate::primitives::{ByteList, H256};

/// `BYTES_PER_LOGS_BLOOM` — fixed-size logs bloom filter.
pub const BYTES_PER_LOGS_BLOOM: usize = 256;

/// `MAX_EXTRA_DATA_BYTES` — Cancun upper bound on `extra_data` (32 bytes).
pub const MAX_EXTRA_DATA_BYTES: usize = 32;

/// `MAX_BYTES_PER_TRANSACTION` — Cancun upper bound on a single tx encoding.
pub const MAX_BYTES_PER_TRANSACTION: usize = 1_073_741_824;

/// `MAX_TRANSACTIONS_PER_PAYLOAD` — Cancun upper bound on tx count.
pub const MAX_TRANSACTIONS_PER_PAYLOAD: usize = 1_048_576;

/// `MAX_WITHDRAWALS_PER_PAYLOAD` — EIP-4895 upper bound on withdrawals.
pub const MAX_WITHDRAWALS_PER_PAYLOAD: usize = 16;

/// Bounded transaction list: each tx is an opaque RLP-encoded byte string.
pub type Transactions = SszList<ByteList<MAX_BYTES_PER_TRANSACTION>, MAX_TRANSACTIONS_PER_PAYLOAD>;

/// Bounded withdrawal list (max 16 per EIP-4895).
pub type Withdrawals = SszList<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>;

/// EIP-4895 withdrawal record carried in payload attributes and inside
/// `ExecutionPayloadV3.withdrawals`.
#[derive(Debug, Default, Clone, Serialize, Deserialize, SszEncode, SszDecode, HashTreeRoot)]
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
#[derive(Debug, Clone, Serialize, Deserialize, SszEncode, SszDecode, HashTreeRoot)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionPayloadV3 {
    pub parent_hash: H256,
    #[serde(with = "hex_address")]
    pub fee_recipient: [u8; 20],
    pub state_root: H256,
    pub receipts_root: H256,
    #[serde(with = "hex_bytes_fixed")]
    pub logs_bloom: [u8; BYTES_PER_LOGS_BLOOM],
    pub prev_randao: H256,
    #[serde(with = "hex_u64")]
    pub block_number: u64,
    #[serde(with = "hex_u64")]
    pub gas_limit: u64,
    #[serde(with = "hex_u64")]
    pub gas_used: u64,
    #[serde(with = "hex_u64")]
    pub timestamp: u64,
    #[serde(with = "byte_list_hex")]
    pub extra_data: ByteList<MAX_EXTRA_DATA_BYTES>,
    #[serde(with = "hex_u256")]
    pub base_fee_per_gas: [u8; 32],
    pub block_hash: H256,
    #[serde(with = "transactions_serde")]
    pub transactions: Transactions,
    #[serde(with = "withdrawals_serde")]
    pub withdrawals: Withdrawals,
    #[serde(with = "hex_u64")]
    pub blob_gas_used: u64,
    #[serde(with = "hex_u64")]
    pub excess_blob_gas: u64,
}

/// Hand-rolled because `[u8; 256]` (the logs_bloom field) doesn't auto-derive
/// `Default` — stdlib's blanket only covers arrays up to length 32.
impl Default for ExecutionPayloadV3 {
    fn default() -> Self {
        Self {
            parent_hash: H256::default(),
            fee_recipient: [0u8; 20],
            state_root: H256::default(),
            receipts_root: H256::default(),
            logs_bloom: [0u8; BYTES_PER_LOGS_BLOOM],
            prev_randao: H256::default(),
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: ByteList::default(),
            base_fee_per_gas: [0u8; 32],
            block_hash: H256::default(),
            transactions: Transactions::default(),
            withdrawals: Withdrawals::default(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
        }
    }
}

// ---------- Hex serde helpers ----------
//
// `pub` so engine-API wire types living in `ethlambda-ethrex-client`
// (e.g. `PayloadAttributesV3`) can keep using them via
// `#[serde(with = "ethlambda_types::execution_payload::hex_u64")]`.

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

/// Fixed-size byte array as a single `0x`-prefixed hex `DATA` string.
///
/// Generic over the array length, so it covers `logs_bloom` (256 bytes) and
/// any other fixed-vector field that lands in V4+.
pub mod hex_bytes_fixed {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(
        v: &[u8; N],
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&format!("0x{}", hex::encode(v)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        de: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(de)?;
        let stripped = s.strip_prefix("0x").unwrap_or(&s);
        let bytes = hex::decode(stripped).map_err(serde::de::Error::custom)?;
        if bytes.len() != N {
            return Err(serde::de::Error::custom(format!(
                "expected {N} bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

/// Variable-length `ByteList<N>` as a single `0x`-prefixed hex `DATA` string.
///
/// Used for `extra_data`. JSON shape matches the canonical execution-apis
/// spec (a single hex string, not an array of bytes).
pub mod byte_list_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::primitives::ByteList;

    pub fn serialize<S: Serializer, const N: usize>(
        v: &ByteList<N>,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&format!("0x{}", hex::encode(&v[..])))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        de: D,
    ) -> Result<ByteList<N>, D::Error> {
        let s = String::deserialize(de)?;
        let stripped = s.strip_prefix("0x").unwrap_or(&s);
        let bytes = hex::decode(stripped).map_err(serde::de::Error::custom)?;
        ByteList::<N>::try_from(bytes)
            .map_err(|err| serde::de::Error::custom(format!("ByteList<{N}>: {err:?}")))
    }
}

/// JSON serde for the bounded transaction list. Each transaction is encoded
/// as a `0x`-prefixed hex `DATA` string (opaque, RLP at the EL layer).
pub mod transactions_serde {
    use serde::{Deserialize, Deserializer, Serializer, ser::SerializeSeq};

    use super::{ByteList, MAX_BYTES_PER_TRANSACTION, Transactions};

    pub fn serialize<S: Serializer>(v: &Transactions, ser: S) -> Result<S::Ok, S::Error> {
        let mut seq = ser.serialize_seq(Some(v.len()))?;
        for tx in v.iter() {
            seq.serialize_element(&format!("0x{}", hex::encode(&tx[..])))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Transactions, D::Error> {
        let strings: Vec<String> = Vec::deserialize(de)?;
        let mut txs: Vec<ByteList<MAX_BYTES_PER_TRANSACTION>> = Vec::with_capacity(strings.len());
        for s in strings {
            let stripped = s.strip_prefix("0x").unwrap_or(&s);
            let bytes = hex::decode(stripped).map_err(serde::de::Error::custom)?;
            let bl = ByteList::<MAX_BYTES_PER_TRANSACTION>::try_from(bytes)
                .map_err(|err| serde::de::Error::custom(format!("transaction: {err:?}")))?;
            txs.push(bl);
        }
        Transactions::try_from(txs)
            .map_err(|err| serde::de::Error::custom(format!("transactions: {err:?}")))
    }
}

/// JSON serde for the bounded withdrawal list. Withdrawal's own Serialize/
/// Deserialize derives handle each element.
pub mod withdrawals_serde {
    use serde::{Deserialize, Deserializer, Serializer, ser::SerializeSeq};

    use super::{Withdrawal, Withdrawals};

    pub fn serialize<S: Serializer>(v: &Withdrawals, ser: S) -> Result<S::Ok, S::Error> {
        let mut seq = ser.serialize_seq(Some(v.len()))?;
        for w in v.iter() {
            seq.serialize_element(w)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Withdrawals, D::Error> {
        let vec: Vec<Withdrawal> = Vec::deserialize(de)?;
        Withdrawals::try_from(vec)
            .map_err(|err| serde::de::Error::custom(format!("withdrawals: {err:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::primitives::HashTreeRoot as _;

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
    fn hex_bytes_fixed_roundtrip_for_logs_bloom() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Wrap {
            #[serde(with = "hex_bytes_fixed")]
            v: [u8; BYTES_PER_LOGS_BLOOM],
        }
        let original = Wrap {
            v: [0xab; BYTES_PER_LOGS_BLOOM],
        };
        let json = serde_json::to_string(&original).unwrap();
        let expected = format!(r#"{{"v":"0x{}"}}"#, "ab".repeat(BYTES_PER_LOGS_BLOOM));
        assert_eq!(json, expected);
        let back: Wrap = serde_json::from_str(&json).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn execution_payload_v3_default_is_zero_init() {
        let p = ExecutionPayloadV3::default();
        assert!(p.parent_hash.is_zero());
        assert!(p.block_hash.is_zero());
        assert_eq!(p.fee_recipient, [0u8; 20]);
        assert_eq!(p.logs_bloom, [0u8; BYTES_PER_LOGS_BLOOM]);
        assert_eq!(p.block_number, 0);
        assert!(p.transactions.is_empty());
        assert!(p.withdrawals.is_empty());
        assert!(p.extra_data.is_empty());
    }

    #[test]
    fn execution_payload_v3_json_roundtrip_for_default() {
        let original = ExecutionPayloadV3::default();
        let json = serde_json::to_string(&original).unwrap();
        // Spot-check shape: camelCase keys, hex DATA/QUANTITY forms.
        assert!(json.contains(r#""parentHash":"0x"#));
        assert!(json.contains(r#""logsBloom":"0x"#));
        assert!(json.contains(r#""extraData":"0x""#));
        assert!(json.contains(r#""baseFeePerGas":"0x0""#));
        assert!(json.contains(r#""transactions":[]"#));
        assert!(json.contains(r#""withdrawals":[]"#));
        let back: ExecutionPayloadV3 = serde_json::from_str(&json).unwrap();
        // hash_tree_root is the source of truth for equality across SSZ types.
        assert_eq!(back.hash_tree_root(), original.hash_tree_root());
    }

    #[test]
    fn execution_payload_v3_json_roundtrip_with_data() {
        let original = ExecutionPayloadV3 {
            parent_hash: H256([1u8; 32]),
            fee_recipient: [2u8; 20],
            state_root: H256([3u8; 32]),
            receipts_root: H256([4u8; 32]),
            logs_bloom: [5u8; BYTES_PER_LOGS_BLOOM],
            prev_randao: H256([6u8; 32]),
            block_number: 42,
            gas_limit: 30_000_000,
            gas_used: 21_000,
            timestamp: 1_700_000_000,
            extra_data: ByteList::<MAX_EXTRA_DATA_BYTES>::try_from(vec![0xde, 0xad]).unwrap(),
            base_fee_per_gas: {
                let mut a = [0u8; 32];
                a[31] = 7;
                a
            },
            block_hash: H256([8u8; 32]),
            transactions: Transactions::try_from(vec![
                ByteList::<MAX_BYTES_PER_TRANSACTION>::try_from(vec![0xbe, 0xef]).unwrap(),
            ])
            .unwrap(),
            withdrawals: Withdrawals::try_from(vec![Withdrawal {
                index: 1,
                validator_index: 2,
                address: [9u8; 20],
                amount: 1_000,
            }])
            .unwrap(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
        };
        let json = serde_json::to_string(&original).unwrap();
        let back: ExecutionPayloadV3 = serde_json::from_str(&json).unwrap();
        assert_eq!(back.hash_tree_root(), original.hash_tree_root());
        // SSZ encoding should also roundtrip.
        use libssz::{SszDecode, SszEncode};
        let ssz_bytes = original.to_ssz();
        let from_ssz = ExecutionPayloadV3::from_ssz_bytes(&ssz_bytes).unwrap();
        assert_eq!(from_ssz.hash_tree_root(), original.hash_tree_root());
    }

    #[test]
    fn withdrawal_ssz_roundtrip() {
        use libssz::{SszDecode, SszEncode};
        let original = Withdrawal {
            index: 7,
            validator_index: 13,
            address: [0xaa; 20],
            amount: 1_234_567,
        };
        let bytes = original.to_ssz();
        let back = Withdrawal::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(back.hash_tree_root(), original.hash_tree_root());
    }
}
