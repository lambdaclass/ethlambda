//! In-process ethrex execution-layer engine (Phase 0 spike).
//!
//! This module currently only links the three core ethrex library crates to
//! prove they resolve and compile cleanly inside the ethlambda workspace. The
//! `ExecutionEngine` implementation is added in Phase 1.
use ethrex_blockchain as _;
use ethrex_common as _;
use ethrex_storage as _;
