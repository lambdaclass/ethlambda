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
//! - `engine_newPayloadV4` (Prague-era payload import)
//! - `engine_getPayloadV4` (Prague-era payload fetch by id)
//!
//! Other method versions (Cancun V3, Amsterdam V5) are deliberately not
//! wrapped yet: ethlambda pins the Prague pair (the pre-Amsterdam, no-BAL
//! path that pairs with a default ethrex) and will grow fork-aware version
//! selection when a second fork window is actually needed.
//!
//! The schema mirrors the mainline execution-apis spec; we re-derive it
//! locally instead of depending on ethrex's RPC crate because ethrex is a
//! sibling project, not an upstream library.

pub mod auth;
pub mod client;
pub mod error;
pub mod types;

pub use auth::{JwtSecret, JwtSecretError};
pub use client::{EngineClient, ExecutionEngine};
pub use error::EngineClientError;
pub use types::{
    ExecutionPayloadV3, ForkChoiceState, ForkChoiceUpdatedResponse, PayloadAttributesV3, PayloadId,
    PayloadStatus, PayloadStatusKind,
};

/// Capabilities ethlambda advertises in `engine_exchangeCapabilities`:
/// exactly the methods the client wraps and the actor calls. The EL's
/// response is the source of truth for what we can actually invoke.
///
/// Per the execution-apis spec, `engine_exchangeCapabilities` itself must
/// NOT appear in the advertised set.
pub const ETHLAMBDA_ENGINE_CAPABILITIES: &[&str] = &[
    "engine_forkchoiceUpdatedV3",
    "engine_newPayloadV4",
    "engine_getPayloadV4",
];
