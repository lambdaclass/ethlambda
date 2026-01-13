use ssz_types::typenum::Unsigned;
use tree_hash::Hash256;

// Re-export SSZ traits to avoid users having to depend on these directly
pub use ssz::{Decode, Encode};
pub use tree_hash::TreeHash;

pub use ssz_types::{BitList, BitVector, FixedVector, VariableList};
pub type H256 = Hash256;

pub type ByteList<N: Unsigned> = ssz_types::VariableList<u8, N>;
