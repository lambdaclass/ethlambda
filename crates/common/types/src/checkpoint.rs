use serde::{Deserialize, Serialize};

use crate::primitives::{
    H256,
    ssz::{HashTreeRoot, SszDecode, SszEncode},
};

/// Represents a checkpoint in the chain's history.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    SszEncode,
    SszDecode,
    HashTreeRoot,
)]
pub struct Checkpoint {
    /// The root hash of the checkpoint's block.
    pub root: H256,
    /// The slot number of the checkpoint's block.
    #[serde(deserialize_with = "deser_dec_str")]
    pub slot: u64,
}

// Taken from ethrex-common
fn deser_dec_str<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let value = String::deserialize(d)?;
    value
        .parse()
        .map_err(|_| D::Error::custom("Failed to deserialize u64 value"))
}
