use ethlambda_types::{genesis::GenesisMismatch, primitives::H256};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("storage error: {0}")]
    Storage(#[from] crate::api::Error),
    #[error("unexpected missing block header for root {0}")]
    UnexpectedMissingBlockHeader(H256),
    #[error("unexpected missing state for root {0}")]
    UnexpectedMissingState(H256),
    /// The data directory holds a chain from a different network. Refusing to
    /// touch it is deliberate: re-initializing on top would leave the foreign
    /// blocks in place, and they are reachable through the slot-indexed reads
    /// that serve `BlocksByRange`.
    #[error("persisted state does not match the configured genesis: {0}")]
    GenesisMismatch(#[from] GenesisMismatch),
}
