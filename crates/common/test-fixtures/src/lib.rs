//! Shared deserialization types for leanSpec test fixtures.
//!
//! Used by the blockchain crate's spec-test runners and by the RPC crate's
//! Hive test-driver handlers (which receive the same fixture JSON over HTTP
//! from the lean spec-assets simulator).

mod common;
pub mod fork_choice;
pub mod state_transition;
pub mod verify_signatures;

pub use common::*;
