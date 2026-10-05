//! The Ethereum Beacon Chain consensus specification, phase0 through fulu.
//!
//! This implements [`ethereum/consensus-specs`][specs]: the beacon state
//! transition function, the fork choice store, and the helpers and cryptography
//! they need. It is verified against the spec test fixtures released with the
//! specification, pinned at the version in the `Makefile`.
//!
//! The Beacon Chain is a different protocol from the Lean consensus the rest of
//! this crate implements, and this module implements only the former. The two sit
//! in one crate so that a caller dispatching on a state's fork can reach either
//! chain's rules without them living in separate dependency trees; they share no
//! code, nothing above this module reads anything inside it, and nothing here
//! reads lean's own modules.
//!
//! One thing they genuinely do share is [`ethlambda_types`], which carries the
//! beacon containers, presets, configuration and primitives under its own
//! `beacon` namespace. Those stayed out of this crate because the storage and
//! networking crates need them and must not depend on `blst` and `c-kzg`, which
//! this module does pull in. Everything they define is re-exported here at its
//! old path, so a use site inside this module names [`crate::beacon::containers`], [`crate::beacon::preset`] or
//! [`crate::beacon::config`] as if they were still local modules.
//!
//! Those two C libraries are consequently on the lean binary's dependency path,
//! since `ethlambda-blockchain` and `ethlambda-rpc` depend on this crate. This
//! module is not feature-gated, so that cost is unconditional; only the tests
//! that read the multi-gigabyte fixture tree are gated, behind
//! `beacon-spec-tests`.
//!
//! One consequence reaches every match in this module. `ethlambda-types` gives
//! [`crate::beacon::containers::BeaconState`] and [`crate::beacon::ForkName`] a `Lean` variant, so that one
//! state type can carry either chain. No lean value can reach this module through
//! a beacon fixture or a beacon block, so those arms panic through
//! `lean_boundary`'s two functions rather than returning a `Result`: reaching one
//! means a caller dispatched on the wrong chain, which is a bug in the caller and
//! not a state this code can transition.
//!
//! # How forks are represented
//!
//! Containers that change between forks are defined once per fork (in
//! `ethlambda-types`, re-exported here), as plain structs that derive their SSZ
//! encoding and merkleization, and wrapped in an enum
//! ([`crate::beacon::containers::BeaconState`] and friends). Deriving the SSZ traits is the
//! reason for that shape: the per-fork field lists are not a growing tail.
//! Two of phase0's fields are *replaced* in altair, one field changes type in
//! five separate forks, and the state's merkle tree gains a level at electra, so
//! a single container with fork-conditional serialization would have to
//! reproduce all of that by hand. Derived codecs get it from the struct
//! definition instead.
//!
//! State transition functions take the enum, read through the accessors
//! generated in `containers`, and match on the fork only where the
//! specification itself changes behavior, so a match arm can be reviewed
//! against the spec's own diff. Functions that exist only from some fork onward
//! return [`crate::beacon::Error::UnsupportedForFork`] for earlier ones.
//!
//! No `macro_rules!` is defined here at all. The ones covering bulk boilerplate,
//! chiefly the fork-invariant state accessors in `containers`, went to
//! `ethlambda-types` with the definitions they generate, and there are no
//! procedural macros beyond the SSZ derives.
//!
//! # Presets
//!
//! Container bounds are compile-time constants, so the preset is a compile-time
//! choice: mainnet by default, minimal with the `preset-minimal` feature. See
//! [`crate::beacon::preset`]. Values that only affect fork *scheduling* are runtime
//! configuration instead, in [`crate::beacon::config`], because the `transition` fixture suite
//! sets fork epochs per case.
//!
//! [specs]: https://github.com/ethereum/consensus-specs

pub mod aggregate;
pub mod attestation_pool;
pub mod block_production;
pub mod bls;
pub mod das;
pub mod fork_choice;
pub mod genesis;
pub mod gossip;
pub mod hash;
pub mod helpers;
pub mod kzg;
pub mod payload_attestation_pool;
pub mod precheck;
pub mod stf;
pub mod upgrade;

mod lean_boundary;

// The types this module transitions, at the paths they had while they lived here.
// A plain re-export rather than `pub mod x { pub use ... }` wrappers: this way
// `crate::beacon::containers::phase0::BeaconState` and
// `ethlambda_types::beacon::containers::phase0::BeaconState` are one type by one
// name, so a caller holding either spelling can hand it straight to this module.
pub use ethlambda_types::beacon::{
    committees, config, constants, containers, error, fork, preset, primitives,
};

pub use error::{Error, Result, verify};
pub use fork::ForkName;
pub(crate) use lean_boundary::{
    lean_block_unreachable, lean_fork_unreachable, lean_state_unreachable,
};
