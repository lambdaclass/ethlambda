use tree_hash::Hash256;

// Re-export SSZ traits to avoid users having to depend on these directly
pub use ssz::{Decode, Encode};
pub use tree_hash::TreeHash;

pub type H256 = Hash256;
