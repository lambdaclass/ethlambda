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

use core::fmt;

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};

pub use ethereum_types::{H160, H256, U256};

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

/// The number of bytes in a BLS12-381 public key.
pub const BLS_PUBKEY_SIZE: usize = 48;
/// The number of bytes in a BLS12-381 signature.
pub const BLS_SIGNATURE_SIZE: usize = 96;
/// The number of bytes in a KZG commitment or proof, both compressed G1 points.
pub const KZG_POINT_SIZE: usize = 48;

/// Declares a fixed-length byte string: an SSZ `Vector[uint8, N]` that encodes
/// and merkleizes as its inner array, with hex `Debug` output.
///
/// Deriving `Default` is not possible because the standard library implements it
/// for arrays only up to length 32.
macro_rules! byte_vector {
    ($(#[$doc:meta])* $name:ident, $size:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, SszEncode, SszDecode, HashTreeRoot)]
        #[ssz(transparent)]
        pub struct $name(pub [u8; $size]);

        impl Default for $name {
            fn default() -> Self {
                Self([0; $size])
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}(0x{})", stringify!($name), hex::encode(self.0))
            }
        }
    };
}

byte_vector!(
    /// A BLS12-381 public key, compressed.
    ///
    /// Not validated on construction. The specification only requires a key to
    /// be a valid curve point where it is used in a signature check, and deposit
    /// processing depends on being able to hold a key that never validates.
    BlsPubkey,
    BLS_PUBKEY_SIZE
);

byte_vector!(
    /// A BLS12-381 signature, compressed.
    BlsSignature,
    BLS_SIGNATURE_SIZE
);

byte_vector!(
    /// A KZG commitment to a blob.
    KzgCommitment,
    KZG_POINT_SIZE
);

byte_vector!(
    /// A KZG proof.
    KzgProof,
    KZG_POINT_SIZE
);

/// Calls `hash_tree_root` with this crate's hasher, so callers do not pass one.
///
/// Every type deriving `libssz_derive::HashTreeRoot` gets this through the
/// blanket implementation.
pub trait HashTreeRoot: libssz_merkle::HashTreeRoot {
    fn hash_tree_root(&self) -> Root {
        H256(libssz_merkle::HashTreeRoot::hash_tree_root(
            self,
            &libssz_merkle::Sha2Hasher,
        ))
    }
}

impl<T: libssz_merkle::HashTreeRoot> HashTreeRoot for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_vectors_round_trip_through_ssz() {
        use libssz::{SszDecode as _, SszEncode as _};

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
}
