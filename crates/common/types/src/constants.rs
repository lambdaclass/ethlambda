//! Protocol constants shared across crates.

/// Fork digest embedded in every gossipsub topic string, as lowercase hex
/// without a `0x` prefix.
///
/// The [leanSpec](https://github.com/leanEthereum/leanSpec/pull/622)
/// currently mandates a dummy value shared across all clients; this will
/// eventually be derived from the fork version and genesis validators root.
// TODO: derive dynamically once the spec defines fork identification.
pub const FORK_DIGEST: &str = "12345678";

/// Number of intervals per slot.
///
/// Fixed rather than configurable: each interval carries a distinct validator
/// duty (see `SlotInterval` in `ethlambda-blockchain`), so the count is part of
/// the protocol rather than a tuning knob. The slot duration is configurable;
/// see [`crate::chain_config::ChainConfig`].
pub const INTERVALS_PER_SLOT: u64 = 5;

/// Slot duration used when the network's config file omits
/// `MILLISECONDS_PER_SLOT`.
///
/// Matches the spec's `SECONDS_PER_SLOT = 4`, so a config file written before
/// the key existed keeps the cadence it was running.
pub const DEFAULT_MILLISECONDS_PER_SLOT: u64 = 4_000;

/// Shortest slot duration a network's config file may ask for.
///
/// The knob exists to slow a network down, not to speed it up. Timings that
/// are fixed in milliseconds rather than expressed as a fraction of the slot
/// — notably `EARLY_AGGREGATION_WINDOW` in `ethlambda-blockchain`, which is
/// subtracted from an interval offset — are sized against the spec cadence and
/// stay in range for every slot duration at or above this floor. Below it they
/// would underflow, and the leanVM proofs a slot has to fit do not get any
/// cheaper either.
///
/// Equal to [`DEFAULT_MILLISECONDS_PER_SLOT`]: the spec cadence is both the
/// value a config file gets by omitting the key and the fastest it may pick.
pub const MIN_MILLISECONDS_PER_SLOT: u64 = DEFAULT_MILLISECONDS_PER_SLOT;
