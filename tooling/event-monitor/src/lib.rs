//! event-monitor library: SSE collector + normalizer + axum dashboard server
//! for lean-consensus (ethlambda) nodes. See `CONTRACT.md` for the frozen
//! wire interface shared with the `web/` frontend.

pub mod collector;
pub mod config;
pub mod hub;
pub mod model;
pub mod server;
pub mod timing;
