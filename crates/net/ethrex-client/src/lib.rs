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
//! - `engine_newPayloadV5` (Amsterdam-era payload import; EIP-7928 BAL
//!   carried as an optional field on the payload)
//! - `engine_getPayloadV3` (Cancun-era payload fetch by id)
//! - `engine_getPayloadV4` (Prague-era payload fetch by id)
//! - `engine_getPayloadV5` (Amsterdam-era payload fetch by id)
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
/// truth for what we can actually invoke. V3/V4/V5 newPayload+getPayload
/// are all advertised so the EL accepts handshakes across the Cancun→
/// Amsterdam range. Today the actor pins `forkchoiceUpdatedV3` and the V5
/// flavours of new/get payload (matching ethrex main); selecting the
/// version per payload timestamp against the EL's fork schedule is a
/// future refinement once the V4/V5 FCU wrappers land.
///
/// Per the execution-apis spec, `engine_exchangeCapabilities` itself must
/// NOT appear in the advertised set.
pub const ETHLAMBDA_ENGINE_CAPABILITIES: &[&str] = &[
    "engine_forkchoiceUpdatedV3",
    "engine_newPayloadV3",
    "engine_newPayloadV4",
    "engine_newPayloadV5",
    "engine_getPayloadV3",
    "engine_getPayloadV4",
    "engine_getPayloadV5",
    "engine_getClientVersionV1",
];
