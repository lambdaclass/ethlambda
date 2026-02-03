// Re-export SSZ traits and types to avoid users having to depend on these directly
pub mod ssz {
    pub use ssz::*;
    pub use ssz_derive::{Decode, Encode};
    pub use tree_hash::TreeHash;
    pub use tree_hash_derive::TreeHash;
}

pub use ssz_types::{BitList, BitVector, FixedVector, VariableList};
pub type H256 = tree_hash::Hash256;

pub type ByteList<N> = ssz_types::VariableList<u8, N>;
