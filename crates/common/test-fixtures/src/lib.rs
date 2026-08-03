//! Shared deserialization types for leanSpec test fixtures.
//!
//! Used by the blockchain crate's spec-test runners and by the RPC crate's
//! Hive test-driver handlers (which receive the same fixture JSON over HTTP
//! from the lean spec-assets simulator).
//!
//! # Tracking the fixture format
//!
//! These types mirror the *current* leanSpec fixture format, the one the
//! `releases/latest` bundle carries (see the `leanSpec/fixtures` Makefile
//! target), and nothing older. A field or spelling leanSpec has dropped is
//! removed here too rather than kept as a `serde` alias: a retired field cannot
//! appear in a bundle the runners actually load, so keeping it only adds a
//! second shape to reason about, and `deny_unknown_fields` then says plainly
//! that a pinned old bundle no longer matches instead of half-parsing it.
//!
//! Renames are therefore a straight swap, and an old bundle is expected to fail
//! loudly. `RejectionReason` is the deliberate exception: an *unknown* reason
//! string still deserializes as [`RejectionReason::Unknown`] so the Hive driver
//! keeps answering a step when leanSpec adds a reason name, and only the offline
//! runners fail on it.

mod common;
pub mod fork_choice;
pub mod rejection;
pub mod state_transition;
pub mod verify_signatures;

pub use common::*;
pub use rejection::RejectionReason;
