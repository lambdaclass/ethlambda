//! Wall-clock reading shared by crates that have no dependency relationship
//! with each other, but both depend on this one.
//!
//! Not a `constants` module: [`crate::constants`] and
//! [`crate::beacon::constants`] hold values the specification (or the shared
//! protocol) fixes outright, and a clock reading is neither. It lives here for
//! the same underlying reason those modules exist at all: the blockchain and
//! p2p crates each need it, neither depends on the other, and both already
//! depend on this crate.

use std::time::SystemTime;

/// Current UNIX timestamp in milliseconds.
pub fn unix_now_ms() -> u64 {
    SystemTime::UNIX_EPOCH
        .elapsed()
        .expect("already past the unix epoch")
        .as_millis() as u64
}
