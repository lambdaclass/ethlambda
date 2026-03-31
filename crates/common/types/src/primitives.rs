/// Convenience wrapper for SSZ merkle hashing with the default Sha2 hasher.
///
/// All types that derive `libssz_derive::HashTreeRoot` automatically implement this
/// via blanket impl, so callers can use `value.hash_tree_root()` without passing
/// a hasher explicitly.
pub trait HashTreeRoot: libssz_merkle::HashTreeRoot {
    fn hash_tree_root(&self) -> H256 {
        H256(libssz_merkle::HashTreeRoot::hash_tree_root(
            self,
            &libssz_merkle::Sha2Hasher,
        ))
    }
}

impl<T: libssz_merkle::HashTreeRoot> HashTreeRoot for T {}

pub type ByteList<const N: usize> = libssz_types::SszList<u8, N>;

/// 256-bit hash digest used as a block root, state root, etc.
///
/// Encoded as a fixed 32-byte array (transparent SSZ wrapper).
/// Serialized as a `"0x..."` hex string.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    libssz_derive::SszEncode,
    libssz_derive::SszDecode,
    libssz_derive::HashTreeRoot,
)]
#[ssz(transparent)]
pub struct H256(pub [u8; 32]);

impl serde::Serialize for H256 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{self}"))
    }
}

impl<'de> serde::Deserialize<'de> for H256 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        let hex_str = s.strip_prefix("0x").unwrap_or(&s);
        let bytes =
            hex::decode(hex_str).map_err(|_| D::Error::custom("H256: invalid hex string"))?;
        if bytes.len() != 32 {
            return Err(D::Error::custom(format!(
                "H256: expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl H256 {
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        let arr: [u8; 32] = bytes
            .try_into()
            .expect("H256::from_slice requires exactly 32 bytes");
        Self(arr)
    }
}

impl From<[u8; 32]> for H256 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<H256> for [u8; 32] {
    fn from(h: H256) -> Self {
        h.0
    }
}

impl std::fmt::LowerHex for H256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl std::fmt::Display for H256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h256_serialize_has_0x_prefix() {
        let h = H256([0xab; 32]);
        let json = serde_json::to_string(&h).unwrap();
        assert!(json.starts_with("\"0x"), "expected 0x prefix, got: {json}");
    }

    #[test]
    fn h256_roundtrip_serialization() {
        let h = H256([0xab; 32]);
        let json = serde_json::to_string(&h).unwrap();
        let deserialized: H256 = serde_json::from_str(&json).unwrap();
        assert_eq!(h, deserialized);
    }

    #[test]
    fn h256_deserialize_without_prefix() {
        let hex_str = format!("\"{}\"", hex::encode([0xcd; 32]));
        let h: H256 = serde_json::from_str(&hex_str).unwrap();
        assert_eq!(h, H256([0xcd; 32]));
    }

    #[test]
    fn h256_from_slice_exact_32_bytes() {
        let bytes = [0x42u8; 32];
        let h = H256::from_slice(&bytes);
        assert_eq!(h.0, bytes);
    }

    #[test]
    #[should_panic(expected = "H256::from_slice requires exactly 32 bytes")]
    fn h256_from_slice_too_short() {
        H256::from_slice(&[0u8; 31]);
    }

    #[test]
    #[should_panic(expected = "H256::from_slice requires exactly 32 bytes")]
    fn h256_from_slice_too_long() {
        H256::from_slice(&[0u8; 33]);
    }
}
