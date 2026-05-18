//! JSON-RPC client for the Ethereum Engine API, scoped to ethlambda's
//! integration with the ethrex execution client.
//!
//! Speaks HS256-JWT-authenticated JSON-RPC against an ethrex auth port
//! (default `:8551`). Exposes typed wrappers for the four engine methods
//! ethlambda currently uses:
//!
//! - `engine_exchangeCapabilities` (startup handshake)
//! - `engine_forkchoiceUpdatedV3` (per-tick head/safe/finalized update)
//! - `engine_newPayloadV3` (block import — not wired in the M4 milestone)
//! - `engine_getPayloadV3` (block proposal — not wired in the M4 milestone)
//!
//! The schema mirrors the mainline execution-apis spec; we re-derive it
//! locally instead of depending on ethrex's RPC crate because ethrex is a
//! sibling project, not an upstream library.

pub mod auth;
pub mod client;
pub mod error;
pub mod types;

pub use auth::{JwtSecret, JwtSecretError};
pub use client::EngineClient;
pub use error::EngineClientError;
pub use types::{
    ExecutionPayloadV3, ForkChoiceState, ForkChoiceUpdatedResponse, PayloadAttributesV3, PayloadId,
    PayloadStatus, PayloadStatusKind,
};

/// Capabilities ethlambda advertises in `engine_exchangeCapabilities`.
///
/// We list everything we *might* call; the EL's response is the source of
/// truth for what we can actually invoke. Today only V3 is exercised.
pub const ETHLAMBDA_ENGINE_CAPABILITIES: &[&str] = &[
    "engine_exchangeCapabilities",
    "engine_forkchoiceUpdatedV3",
    "engine_newPayloadV3",
    "engine_getPayloadV3",
    "engine_getClientVersionV1",
];
