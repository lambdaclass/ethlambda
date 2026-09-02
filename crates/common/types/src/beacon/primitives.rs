//! The specification's primitive types.
//!
//! Scalar spec types are aliases of `u64` rather than newtypes. The
//! specification does arithmetic on slots, epochs, and balances freely, and
//! wrapping each in its own type would mean either arithmetic trait impls or
//! constant unwrapping, neither of which makes the state transition easier to
//! check against the spec text.
//!
//! Fixed-length byte strings do get newtypes, because confusing a public key
//! with a signature or a commitment is a real mistake that the compiler can
//! catch for free.
//!
//! [`H160`] and [`U256`] are declared here rather than taken from a crate of
//! Ethereum primitives. A Beacon Chain container needs three types of that
//! family: a 32-byte hash, a 20-byte address, and a 256-bit integer. The first
//! is already [`crate::primitives::H256`], so an external crate would save two
//! declarations and cost a second `H256` that every root in the crate has to be
//! converted through.

use core::{cmp::Ordering, fmt};

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};

pub use crate::primitives::{H256, HashTreeRoot};

/// A slot number.
pub type Slot = u64;
/// An epoch number.
pub type Epoch = u64;
/// An index into a slot's committees.
pub type CommitteeIndex = u64;
/// An index into the validator registry.
pub type ValidatorIndex = u64;
/// An amount of Gwei.
pub type Gwei = u64;
/// An index into the withdrawal sequence.
pub type WithdrawalIndex = u64;
/// An index into a block's blobs.
pub type BlobIndex = u64;
/// An index into a block's data columns.
pub type ColumnIndex = u64;

/// A merkle root or any other 32-byte hash.
///
/// The same [`H256`] the lean types use, so a beacon block root reaching a
/// store lookup needs no conversion. The two chains disagree about nearly
/// everything else, but a 32-byte SSZ hash is a 32-byte SSZ hash.
pub type Root = H256;
/// 32 bytes with no further meaning attached.
pub type Bytes32 = H256;
/// A 256-bit unsigned integer, SSZ-encoded little-endian.
pub type Uint256 = U256;
/// An execution layer address.
pub type ExecutionAddress = H160;
/// An execution layer block hash.
pub type ExecutionBlockHash = H256;

/// A fork version.
pub type Version = [u8; 4];
/// The four-byte prefix that separates signature domains.
pub type DomainType = [u8; 4];
/// A signing domain: a domain type combined with a fork version and the genesis
/// validators root.
pub type Domain = [u8; 32];
/// The four bytes identifying a fork on the wire.
pub type ForkDigest = [u8; 4];

/// A bitfield of participation flags for one validator, one bit per flag index.
pub type ParticipationFlags = u8;

/// The number of bytes in an execution layer address.
pub const ADDRESS_SIZE: usize = 20;
/// The number of bytes in a BLS12-381 public key.
pub const BLS_PUBKEY_SIZE: usize = 48;
/// The number of bytes in a BLS12-381 signature.
pub const BLS_SIGNATURE_SIZE: usize = 96;
/// The number of bytes in a KZG commitment or proof, both compressed G1 points.
pub const KZG_POINT_SIZE: usize = 48;

/// Formats a fixed-length byte string as `Name(0xabcd…)`.
///
/// Shared by the `Debug` implementations below, which are otherwise identical, so
/// that they cannot drift into printing the same kind of value several ways. The
/// name is passed rather than taken from [`core::any::type_name`] so it stays a
/// literal the compiler checks against the type it sits on.
fn debug_byte_vector(f: &mut fmt::Formatter<'_>, name: &str, bytes: &[u8]) -> fmt::Result {
    write!(f, "{name}(0x{})", hex::encode(bytes))
}

/// An execution layer address: an SSZ `Vector[uint8, 20]`.
///
/// [`libssz_merkle::HashTreeRoot`] is written out rather than derived because
/// the derive does not carry `is_basic_type` through, and 20 bytes is the width
/// where that answer matters: a list or vector of *basic* elements packs them
/// contiguously into 32-byte chunks, while one of *composite* elements pads each
/// to a leaf of its own. No container holds a collection of addresses, so the
/// two agree everywhere the question is asked today; writing the answer out is
/// what keeps the first container that does hold one from silently merkleizing
/// the other way. Every other type in this module is 32 bytes wide, where
/// packing and padding coincide.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, SszEncode, SszDecode)]
#[ssz(transparent)]
pub struct H160(pub [u8; ADDRESS_SIZE]);

impl H160 {
    /// The all-zero address.
    pub const ZERO: Self = Self([0; ADDRESS_SIZE]);

    /// Every byte set to `byte`. See [`H256::repeat_byte`].
    pub const fn repeat_byte(byte: u8) -> Self {
        Self([byte; ADDRESS_SIZE])
    }

    /// # Panics
    ///
    /// If `bytes` is not exactly [`ADDRESS_SIZE`] long.
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(
            bytes
                .try_into()
                .expect("H160::from_slice requires exactly 20 bytes"),
        )
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl libssz_merkle::HashTreeRoot for H160 {
    fn hash_tree_root(&self, hasher: &impl libssz_merkle::Sha256Hasher) -> libssz_merkle::Node {
        libssz_merkle::HashTreeRoot::hash_tree_root(&self.0, hasher)
    }

    fn is_basic_type() -> bool {
        <[u8; ADDRESS_SIZE] as libssz_merkle::HashTreeRoot>::is_basic_type()
    }
}

impl From<[u8; ADDRESS_SIZE]> for H160 {
    fn from(bytes: [u8; ADDRESS_SIZE]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for H160 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_byte_vector(f, "H160", &self.0)
    }
}

/// A 256-bit unsigned integer.
///
/// Held as the 32 little-endian bytes SSZ encodes it as, so encoding, decoding
/// and merkleizing are the inner array's and cannot disagree with the wire. The
/// consequence is that the stored byte order is the reverse of the numeric one,
/// which is why [`Ord`] is written out below instead of derived.
///
/// No arithmetic, because the specification never computes on one:
/// `terminal_total_difficulty` is only ever compared against a PoW block's
/// accumulated difficulty, and `base_fee_per_gas` is carried through the
/// execution payload header untouched.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(transparent)]
pub struct U256(pub [u8; 32]);

impl U256 {
    /// Zero.
    pub const ZERO: Self = Self([0; 32]);
    /// The largest representable value, `2^256 - 1`.
    pub const MAX: Self = Self([0xff; 32]);

    /// The integer `value`, widened.
    ///
    /// `const` so a configuration constant that fits 128 bits can be written as
    /// its decimal digits rather than as bytes.
    pub const fn from_u128(value: u128) -> Self {
        let mut bytes = [0; 32];
        let low = value.to_le_bytes();
        let mut i = 0;
        while i < low.len() {
            bytes[i] = low[i];
            i += 1;
        }
        Self(bytes)
    }

    /// Parses a decimal string, the form every specification configuration file
    /// writes a `uint256` in.
    ///
    /// Kept even though nothing on the shipping path parses one: the values that
    /// *are* hard-coded get pinned against their decimal digits by a test, and
    /// reading them back is how a mistranscribed byte is caught.
    pub fn from_dec_str(digits: &str) -> Result<Self, ParseU256Error> {
        if digits.is_empty() {
            return Err(ParseU256Error::Empty);
        }

        let mut bytes = [0u8; 32];
        for byte in digits.bytes() {
            let digit = match byte {
                b'0'..=b'9' => u16::from(byte - b'0'),
                _ => return Err(ParseU256Error::InvalidDigit),
            };

            // `value = value * 10 + digit`, low byte first. Each step is at
            // most `255 * 10 + 9`, so the running carry fits the same `u16`.
            let mut carry = digit;
            for limb in &mut bytes {
                let widened = u16::from(*limb) * 10 + carry;
                *limb = widened as u8;
                carry = widened >> 8;
            }
            if carry != 0 {
                return Err(ParseU256Error::Overflow);
            }
        }
        Ok(Self(bytes))
    }
}

impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        Self::from_u128(u128::from(value))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        // Most significant byte first, the reverse of how the bytes are
        // stored. Deriving this would compare the least significant byte first
        // and answer nonsense.
        self.0.iter().rev().cmp(other.0.iter().rev())
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::LowerHex for U256 {
    /// Most significant digit first, with leading zeros trimmed, so the output
    /// reads as a number rather than as a byte string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.iter().rposition(|&byte| byte != 0) {
            None => f.write_str("0"),
            Some(high) => {
                write!(f, "{:x}", self.0[high])?;
                for &byte in self.0[..high].iter().rev() {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "U256(0x{self:x})")
    }
}

/// Why a decimal string was not a [`U256`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseU256Error {
    #[error("a uint256 needs at least one digit")]
    Empty,
    #[error("a uint256 is written in decimal digits only")]
    InvalidDigit,
    #[error("the value does not fit 256 bits")]
    Overflow,
}

// Each of the four types below is an SSZ `Vector[uint8, N]`: it encodes and
// merkleizes as its inner array. `Default` is written out rather than derived
// because the standard library implements it for arrays only up to length 32,
// well short of all four of these, and a derive requires every field's type to
// implement the trait.

/// A BLS12-381 public key, compressed.
///
/// Not validated on construction. The specification only requires a key to be a
/// valid curve point where it is used in a signature check, and deposit
/// processing depends on being able to hold a key that never validates.
#[derive(Clone, Copy, PartialEq, Eq, Hash, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(transparent)]
pub struct BlsPubkey(pub [u8; BLS_PUBKEY_SIZE]);

impl Default for BlsPubkey {
    fn default() -> Self {
        Self([0; BLS_PUBKEY_SIZE])
    }
}

impl AsRef<[u8]> for BlsPubkey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for BlsPubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_byte_vector(f, "BlsPubkey", &self.0)
    }
}

/// A BLS12-381 signature, compressed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(transparent)]
pub struct BlsSignature(pub [u8; BLS_SIGNATURE_SIZE]);

impl Default for BlsSignature {
    fn default() -> Self {
        Self([0; BLS_SIGNATURE_SIZE])
    }
}

impl AsRef<[u8]> for BlsSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for BlsSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_byte_vector(f, "BlsSignature", &self.0)
    }
}

/// A KZG commitment to a blob.
///
/// The same width as [`KzgProof`] and as [`BlsPubkey`], and a separate type from
/// both for that reason: an alias would make all three interchangeable.
#[derive(Clone, Copy, PartialEq, Eq, Hash, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(transparent)]
pub struct KzgCommitment(pub [u8; KZG_POINT_SIZE]);

impl Default for KzgCommitment {
    fn default() -> Self {
        Self([0; KZG_POINT_SIZE])
    }
}

impl AsRef<[u8]> for KzgCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for KzgCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_byte_vector(f, "KzgCommitment", &self.0)
    }
}

/// A KZG proof.
#[derive(Clone, Copy, PartialEq, Eq, Hash, SszEncode, SszDecode, HashTreeRoot)]
#[ssz(transparent)]
pub struct KzgProof(pub [u8; KZG_POINT_SIZE]);

impl Default for KzgProof {
    fn default() -> Self {
        Self([0; KZG_POINT_SIZE])
    }
}

impl AsRef<[u8]> for KzgProof {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for KzgProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug_byte_vector(f, "KzgProof", &self.0)
    }
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};
    use libssz_merkle::Sha2Hasher;

    use super::*;

    /// The two-argument root, spelled out because [`HashTreeRoot`] is in scope
    /// here and its own `hash_tree_root` takes no hasher.
    fn ssz_root<T: libssz_merkle::HashTreeRoot>(value: &T) -> libssz_merkle::Node {
        libssz_merkle::HashTreeRoot::hash_tree_root(value, &Sha2Hasher)
    }

    #[test]
    fn byte_vectors_round_trip_through_ssz() {
        let key = BlsPubkey([7; BLS_PUBKEY_SIZE]);
        let bytes = key.to_ssz();
        assert_eq!(bytes.len(), BLS_PUBKEY_SIZE);
        assert_eq!(BlsPubkey::from_ssz_bytes(&bytes).unwrap(), key);
    }

    #[test]
    fn debug_output_is_hex() {
        let proof = KzgProof([0xab; KZG_POINT_SIZE]);
        assert!(format!("{proof:?}").starts_with("KzgProof(0xabab"));
    }

    #[test]
    fn an_address_encodes_as_its_twenty_bytes() {
        let address = H160::repeat_byte(0xcd);
        assert_eq!(address.to_ssz(), [0xcd; ADDRESS_SIZE]);
        assert_eq!(H160::from_ssz_bytes(&address.to_ssz()).unwrap(), address);
    }

    /// The property the hand-written [`libssz_merkle::HashTreeRoot`] exists for:
    /// a 20-byte value is a basic type, so a collection of them packs rather
    /// than padding. Both halves are checked, since the root alone would pass
    /// with `is_basic_type` left at its default.
    #[test]
    fn an_address_is_a_basic_type_rooted_as_its_padded_bytes() {
        assert!(<H160 as libssz_merkle::HashTreeRoot>::is_basic_type());

        let address = H160::repeat_byte(0xcd);
        let mut expected = [0u8; 32];
        expected[..ADDRESS_SIZE].fill(0xcd);
        assert_eq!(ssz_root(&address), expected);
    }

    #[test]
    fn a_uint256_encodes_little_endian() {
        let value = U256::from(258u64);
        let bytes = value.to_ssz();
        assert_eq!(bytes.len(), 32);
        assert_eq!(&bytes[..3], &[2, 1, 0]);
        assert_eq!(U256::from_ssz_bytes(&bytes).unwrap(), value);
    }

    /// A `uint256` roots to its own little-endian bytes, unhashed, so the
    /// encoding above is also the leaf.
    #[test]
    fn a_uint256_roots_to_its_encoding() {
        let value = U256::from(258u64);
        assert_eq!(ssz_root(&value).as_slice(), value.to_ssz().as_slice());
    }

    /// Numeric order, not stored-byte order. `256` and `1` differ only in bytes
    /// a derived `Ord` would reach in the wrong order, and would compare the
    /// wrong way round: `256`'s low byte is `0` where `1`'s is `1`.
    #[test]
    fn uint256_compares_numerically() {
        assert!(U256::from(256u64) > U256::from(1u64));
        assert!(U256::from(1u64) > U256::ZERO);
        assert!(U256::MAX > U256::from(u64::MAX));
        assert_eq!(U256::from(7u64).cmp(&U256::from(7u64)), Ordering::Equal);
    }

    #[test]
    fn a_decimal_string_parses_to_the_same_value_as_its_digits() {
        assert_eq!(U256::from_dec_str("0").unwrap(), U256::ZERO);
        assert_eq!(U256::from_dec_str("258").unwrap(), U256::from(258u64));
        assert_eq!(
            U256::from_dec_str("340282366920938463463374607431768211455").unwrap(),
            U256::from_u128(u128::MAX),
        );
        assert_eq!(
            U256::from_dec_str(
                "115792089237316195423570985008687907853269984665640564039457584007913129639935",
            )
            .unwrap(),
            U256::MAX,
        );
    }

    #[test]
    fn a_decimal_string_that_is_not_a_uint256_is_rejected() {
        assert_eq!(U256::from_dec_str(""), Err(ParseU256Error::Empty));
        assert_eq!(
            U256::from_dec_str("0x10"),
            Err(ParseU256Error::InvalidDigit)
        );
        assert_eq!(
            // 2^256, one past the largest representable value.
            U256::from_dec_str(
                "115792089237316195423570985008687907853269984665640564039457584007913129639936",
            ),
            Err(ParseU256Error::Overflow),
        );
    }

    #[test]
    fn uint256_debug_is_big_endian_hex() {
        assert_eq!(format!("{:?}", U256::ZERO), "U256(0x0)");
        assert_eq!(format!("{:?}", U256::from(258u64)), "U256(0x102)");
    }
}
