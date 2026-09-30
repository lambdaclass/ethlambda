//! The Ethereum Engine API, as a consensus-layer follower needs it.
//!
//! Wire concerns only: JWT authentication, the JSON-RPC envelope, and the four
//! methods a follower calls. Nothing here knows what a beacon block is beyond
//! the containers it serializes, and nothing here decides what an answer means.
//! Assembling a request from a block, and reading a status as a fork choice
//! verdict, both live in `ethlambda-blockchain`, which already depends on the
//! state transition; see that crate's `beacon_engine` module.
//!
//! # Which methods, and why so few
//!
//! Osaka introduces no new `newPayload`: its own document adds only
//! `engine_getPayloadV5` and `engine_getBlobsV2`/`V3`, and `engine_newPayloadV5`
//! belongs to Amsterdam. So the Osaka-current call for a payload is Prague's
//! `engine_newPayloadV4`, and the Osaka-current fork choice notification is
//! Cancun's `engine_forkchoiceUpdatedV3`.
//!
//! Payload building (`PayloadAttributesV3` on `forkchoiceUpdated`, and
//! Osaka's `engine_getPayloadV5`) is in [`building`], for the Beacon API's
//! block production. Two method families a full client would have are
//! deliberately absent: `engine_getBlobs*`, because there is no blob-pool
//! fetch path and data columns come from peers; and
//! `engine_getPayloadBodies*`, because nothing consumes them.

pub mod auth;
pub mod building;
pub mod client;
pub mod error;
pub mod types;

pub use auth::JwtSecret;
pub use client::EngineClient;
pub use error::EngineError;
pub use types::{ForkchoiceStateV1, PayloadStatusV1, PayloadStatusValue};

/// The methods this client will call, sent in the `engine_exchangeCapabilities`
/// handshake.
///
/// The specification requires each name to carry its version suffix, and
/// requires `engine_exchangeCapabilities` itself not to appear.
pub const ETHLAMBDA_ENGINE_CAPABILITIES: &[&str] = &[
    "engine_newPayloadV4",
    "engine_forkchoiceUpdatedV3",
    "engine_getPayloadV5",
    "engine_getClientVersionV1",
];
