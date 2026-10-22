//! The specification's helper functions.
//!
//! Grouped the way the specification groups them: math, predicates, the
//! committee shuffle, slot and epoch arithmetic with signing domains, state
//! accessors, and state mutators.
//!
//! One systematic difference from the spec's own signatures: the spec reads its
//! parameters from global scope, whereas here preset values are compile-time
//! constants but configuration values are not, so any function needing a
//! configuration value takes a [`crate::beacon::config::Config`]. Everything else keeps
//! the spec's name and argument order, so a call site can be checked against the
//! spec line by line.

pub mod accessors;
pub mod altair;
pub mod attestation;
pub mod capella;
pub mod electra;
pub mod finality;
pub mod fulu;
pub mod math;
pub mod misc;
pub mod mutators;
pub mod participation;
#[cfg(any(test, debug_assertions))]
pub mod participation_reference;
pub mod predicates;
pub mod shuffling;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_state;
