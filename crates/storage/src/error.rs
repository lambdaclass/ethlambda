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
    /// The data directory was written by a build with a different on-disk
    /// format. There is no migration: the `States` value layout changed, so
    /// every state already written would decode as the wrong shape.
    ///
    /// `found` is `0` for a directory written before versioning existed.
    #[error(
        "data directory has database version {found}, this build requires {expected}; \
         wipe the data directory and resync"
    )]
    DbVersionMismatch { found: u64, expected: u64 },
    /// The data directory holds the other chain. Opening it would write lean
    /// rows into a beacon chain's tables, or the reverse.
    #[error(
        "data directory holds a beacon chain, not a lean chain; wipe it or use `ethlambda beacon`"
    )]
    WrongChain,
}
