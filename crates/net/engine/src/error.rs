//! Engine API client errors.
//!
//! The variants are split by what a caller should do about them, not by where
//! they came from. [`Rpc`](EngineError::Rpc) is the execution client refusing a
//! well-formed call and says so with the specification's own error code;
//! everything else is a failure to get an answer at all, which
//! `optimistic-sync.md` treats identically: do not import, do not touch fork
//! choice, retry later.

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("jwt: {0}")]
    Jwt(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("timed out after {0:?}")]
    Timeout(std::time::Duration),
    #[error("rpc error {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error("decoding the response: {0}")]
    Decode(String),
}
