//! JSON-RPC client for the Ethereum Engine API, scoped to ethlambda's
//! integration with the ethrex execution client.
//!
//! Speaks HS256-JWT-authenticated JSON-RPC against an ethrex auth port
//! (default `:8551`). Exposes typed wrappers for the engine methods
//! ethlambda uses:
//!
//! - `engine_exchangeCapabilities` (startup handshake)
//! - `engine_forkchoiceUpdatedV3` (per-tick head/safe/finalized update,
//!   plus build-mode at interval 4 with `PayloadAttributesV3`)
//! - `engine_newPayloadV3` (Cancun-era payload import)
//! - `engine_newPayloadV4` (Prague-era payload import; adds
//!   `executionRequests`)
//! - `engine_getPayloadV3` (block proposal — fetches a built payload by id)
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
/// truth for what we can actually invoke. The V4 newPayload entry covers
/// Prague-era payloads; the actor picks V3 vs V4 by payload timestamp.
pub const ETHLAMBDA_ENGINE_CAPABILITIES: &[&str] = &[
    "engine_exchangeCapabilities",
    "engine_forkchoiceUpdatedV3",
    "engine_newPayloadV3",
    "engine_newPayloadV4",
    "engine_getPayloadV3",
    "engine_getClientVersionV1",
];
