//! The Ethereum Beacon Chain consensus specification, phase0 through fulu.
//!
//! This implements [`ethereum/consensus-specs`][specs]: the beacon state
//! transition function, the fork choice store, and the containers, helpers, and
//! cryptography they need. It is verified against the spec test fixtures
//! released with the specification, pinned at the version in the `Makefile`.
//!
//! This crate implements no part of the Lean consensus protocol the rest of this
//! repository implements, but it no longer stands apart from it. Its containers
//! live in `ethlambda-types` (see `ForkName::Lean` and `BeaconState::Lean` for
//! why), and its fork choice store *is* `ethlambda_storage::Store`, because a
//! mainnet `BeaconState` is ~350 MB and cannot live in a `HashMap`. What stays
//! here is Beacon Chain *behavior*: `helpers`, `stf`, `genesis`, `upgrade`,
//! `fork_choice`, `bls`, `kzg`, and `hash`.
//!
//! # How forks are represented
//!
//! Containers that change between forks are defined once per fork, as plain
//! structs that derive their SSZ encoding and merkleization, and wrapped in an
//! enum ([`containers::BeaconState`] and friends). Deriving the SSZ traits is
//! the reason for that shape: the per-fork field lists are not a growing tail.
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
//! return [`Error::UnsupportedForFork`] for earlier ones.
//!
//! Two small `macro_rules!` cover boilerplate that would otherwise run to
//! hundreds of near-identical lines: the fixed-length byte strings in
//! [`primitives`], and the fork-invariant state accessors in `containers`. There
//! are no others, and no procedural macros beyond the SSZ derives.
//!
//! # Presets
//!
//! Container bounds are compile-time constants, so the preset is a compile-time
//! choice: mainnet by default, minimal with the `preset-minimal` feature. See
//! [`preset`]. Values that only affect fork *scheduling* are runtime
//! configuration instead, in [`config`], because the `transition` fixture suite
//! sets fork epochs per case.
//!
//! [specs]: https://github.com/ethereum/consensus-specs

pub mod bls;
pub use ethlambda_types::beacon::config;
pub use ethlambda_types::beacon::constants;
pub use ethlambda_types::beacon::containers;
pub use ethlambda_types::beacon::error;
pub use ethlambda_types::beacon::fork;
pub mod fork_choice;
pub mod genesis;
pub mod hash;
pub mod helpers;
pub mod kzg;
pub use ethlambda_types::beacon::preset;
pub use ethlambda_types::beacon::primitives;
pub mod stf;
pub mod upgrade;

pub use error::{Error, Result, verify};
pub use fork::ForkName;
