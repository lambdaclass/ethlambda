#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("storage error: {0}")]
    Storage(#[from] crate::api::Error),
    #[error("SSZ decode error: {0:?}")]
    Decode(#[from] libssz::DecodeError),
    #[error("anchor block header does not match state's latest_block_header")]
    AnchorHeaderMismatch,
    #[error("metadata not found")]
    MissingMetadata,
    #[error("head block header not found")]
    MissingHeadBlockHeader,
    #[error("safe target block header not found")]
    MissingSafeTarget,
    #[error("head state not found")]
    MissingHeadState,
    #[error("safe target block header not found")]
    MissingSafeTargetBlockHeader,
    #[error("parent block header not found")]
    MissingParentBlockHeader,
}
