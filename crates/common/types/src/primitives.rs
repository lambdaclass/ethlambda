// Re-export SSZ traits and types to avoid users having to depend on these directly
pub mod ssz {
    pub use libssz::{ContainerDecoder, ContainerEncoder, DecodeError, SszDecode, SszEncode};
    // Derive macro (macro namespace: used in #[derive(HashTreeRoot)])
    pub use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
    pub use libssz_merkle::{Sha2Hasher, Sha256Hasher};

    /// Default hasher for hash_tree_root computations.
    pub const HASHER: Sha2Hasher = Sha2Hasher;

    /// Convenience trait that wraps libssz_merkle::HashTreeRoot with the default Sha2Hasher.
    ///
    /// All types that derive `HashTreeRoot` automatically implement this via blanket impl,
    /// so callers can use `value.hash_tree_root()` without passing a hasher explicitly.
    // (type namespace: coexists with the derive macro of the same name in macro namespace)
    pub trait HashTreeRoot: libssz_merkle::HashTreeRoot {
        fn hash_tree_root(&self) -> libssz_merkle::Node {
            libssz_merkle::HashTreeRoot::hash_tree_root(self, &HASHER)
        }
    }

    impl<T: libssz_merkle::HashTreeRoot> HashTreeRoot for T {}
}

pub use libssz_types::{SszBitlist, SszBitvector, SszList, SszVector};

pub type ByteList<const N: usize> = SszList<u8, N>;

/// 256-bit hash digest used as a block root, state root, etc.
///
/// Encoded as a fixed 32-byte array (transparent SSZ wrapper).
/// Serialized as a `"0x..."` hex string (without prefix for lowercase display).
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
        serializer.serialize_str(&format!("{:x}", self))
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
        let mut arr = [0u8; 32];
        let len = bytes.len().min(32);
        arr[..len].copy_from_slice(&bytes[..len]);
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
