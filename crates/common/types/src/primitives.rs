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
)]
#[ssz(transparent)]
pub struct H256(pub [u8; 32]);

/// Written out rather than derived because the `transparent` derive does not
/// forward `is_basic_type`. Without it a collection of `H256` is treated as
/// composite: the same root, but a tree-backed list would cache a second copy
/// of every element's root (see `ethlambda_ssz_tree`).
impl libssz_merkle::HashTreeRoot for H256 {
    fn hash_tree_root(&self, hasher: &impl libssz_merkle::Sha256Hasher) -> libssz_merkle::Node {
        libssz_merkle::HashTreeRoot::hash_tree_root(&self.0, hasher)
    }

    fn is_basic_type() -> bool {
        <[u8; 32] as libssz_merkle::HashTreeRoot>::is_basic_type()
    }
}

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

    /// Every byte set to `byte`.
    ///
    /// Test fixtures want a hash that is obviously not the zero hash and is
    /// obviously not any other fixture's hash, which one repeated byte gives
    /// while staying short enough to read at a call site.
    pub const fn repeat_byte(byte: u8) -> Self {
        Self([byte; 32])
    }

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

/// Same as [`Display`](std::fmt::Display), rather than derived.
///
/// A derived `Debug` prints the inner array, so a hash comes out as 32 decimal
/// numbers: unreadable on its own, and unreadable in bulk inside the `Debug` of
/// a container holding thousands of roots. Assertion failures in the spec suites
/// print roots this way, so the hex is the whole point. Truncate at a call site
/// that wants it short with [`crate::ShortRoot`].
impl std::fmt::Debug for H256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
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

    /// Not the derived `Debug`, which would print the inner array as 32 decimal
    /// numbers. Spec-suite assertion failures print roots through `Debug`, so
    /// this is the difference between a readable diff and an unreadable one.
    #[test]
    fn h256_debug_is_the_same_hex_as_display() {
        let h = H256::repeat_byte(0xab);
        assert_eq!(format!("{h:?}"), format!("{h}"));
        assert_eq!(format!("{h:?}"), format!("0x{}", "ab".repeat(32)));
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

    /// Reporting `H256` as basic must not change any root: a collection of it
    /// merkleizes like one of the plain arrays it wraps.
    mod basic_type {
        use super::*;
        use libssz_types::{SszList, SszVector};

        #[derive(libssz_derive::HashTreeRoot)]
        struct WithH256 {
            list: SszList<H256, 64>,
            vector: SszVector<H256, 8>,
            tail: u64,
        }

        #[derive(libssz_derive::HashTreeRoot)]
        struct WithArrays {
            list: SszList<[u8; 32], 64>,
            vector: SszVector<[u8; 32], 8>,
            tail: u64,
        }

        fn items(n: usize) -> Vec<[u8; 32]> {
            (0..n).map(|i| [i as u8 ^ 0x5a; 32]).collect()
        }

        #[test]
        fn h256_reports_basic_like_its_array() {
            assert!(<H256 as libssz_merkle::HashTreeRoot>::is_basic_type());
        }

        #[test]
        fn list_and_vector_of_h256_hash_like_arrays() {
            for n in [0, 1, 2, 3, 33, 64] {
                let arrays = items(n);
                let hashes: Vec<H256> = arrays.iter().copied().map(H256).collect();
                let a = SszList::<[u8; 32], 64>::try_from(arrays).unwrap();
                let h = SszList::<H256, 64>::try_from(hashes).unwrap();
                assert_eq!(
                    HashTreeRoot::hash_tree_root(&a),
                    HashTreeRoot::hash_tree_root(&h),
                    "list of {n}"
                );
            }
            let arrays = items(8);
            let hashes: Vec<H256> = arrays.iter().copied().map(H256).collect();
            let a = SszVector::<[u8; 32], 8>::try_from(arrays).unwrap();
            let h = SszVector::<H256, 8>::try_from(hashes).unwrap();
            assert_eq!(
                HashTreeRoot::hash_tree_root(&a),
                HashTreeRoot::hash_tree_root(&h)
            );
        }

        #[test]
        fn a_container_holding_h256_collections_keeps_its_root() {
            let arrays = items(8);
            let hashes: Vec<H256> = arrays.iter().copied().map(H256).collect();
            let with_arrays = WithArrays {
                list: arrays.clone().try_into().unwrap(),
                vector: arrays.try_into().unwrap(),
                tail: 7,
            };
            let with_h256 = WithH256 {
                list: hashes.clone().try_into().unwrap(),
                vector: hashes.try_into().unwrap(),
                tail: 7,
            };
            assert_eq!(
                HashTreeRoot::hash_tree_root(&with_arrays),
                HashTreeRoot::hash_tree_root(&with_h256)
            );
        }

        /// The lean state's `H256` lists go through the same path.
        #[test]
        fn lean_state_root_is_unchanged_by_the_basic_report() {
            use crate::state::State;
            let mut state = State::from_genesis(0, Vec::new());
            let hashes: Vec<H256> = items(5).into_iter().map(H256).collect();
            state.historical_block_hashes = hashes.try_into().unwrap();
            let mirror = SszList::<[u8; 32], 262_144>::try_from(items(5)).unwrap();
            let expected =
                libssz_merkle::HashTreeRoot::hash_tree_root(&mirror, &libssz_merkle::Sha2Hasher);
            let got = libssz_merkle::HashTreeRoot::hash_tree_root(
                &state.historical_block_hashes,
                &libssz_merkle::Sha2Hasher,
            );
            assert_eq!(got, expected);
            // The container root is computed and stable across calls.
            assert_eq!(
                HashTreeRoot::hash_tree_root(&state),
                HashTreeRoot::hash_tree_root(&state.clone())
            );
        }
    }
}
