//! Protocol constants shared across crates.

/// Milliseconds per interval (1000ms ticks).
pub const MILLISECONDS_PER_INTERVAL: u64 = 1000;

/// Number of intervals per slot (4 intervals of 1000ms = 4 seconds).
pub const INTERVALS_PER_SLOT: u64 = 4;

/// Milliseconds in a slot (derived from interval duration and count).
///
/// Deliberately unchanged at 4000 ms across the 5 -> 4 interval switch: the XMSS
/// epoch is the slot, so key lifetime in wall-clock terms is untouched, existing
/// `GENESIS_TIME` configs stay valid, and slot numbers still line up with other
/// clients even while the interval grid inside the slot diverges.
pub const MILLISECONDS_PER_SLOT: u64 = MILLISECONDS_PER_INTERVAL * INTERVALS_PER_SLOT;

/// How many slots of vote memory recency-latest-message-driven (RLMD) fork
/// choice keeps: the window is the half-open range `[S - N, S)`.
///
/// 8 slots is 32 s at a 4-second slot. It doubles as the cap on how far the fast
/// head's expanding fallback will walk back looking for evidence, and as the
/// retention bound for the heartbeat vote store — nothing ever reads further
/// back than this, so retaining more during a finality stall is unbounded waste.
pub const RLMD_LOOKBACK_LIMIT: u64 = 8;

/// Fork digest embedded in every gossipsub topic string, as lowercase hex
/// without a `0x` prefix.
///
/// The [leanSpec](https://github.com/leanEthereum/leanSpec/pull/622)
/// currently mandates a dummy value shared across all clients; this will
/// eventually be derived from the fork version and genesis validators root.
// TODO: derive dynamically once the spec defines fork identification.
pub const FORK_DIGEST: &str = "12345678";

/// Heartbeat committee size applied when the genesis config omits
/// `HEARTBEAT_COMMITTEE_SIZE`.
///
/// 16 rather than a smaller committee because every heartbeat threshold is a
/// *fraction* of the committee: the tolerated number of absent members is what
/// scales with the size. At 16 the safe target survives 4 absences, against 1
/// at a committee of 4.
///
/// Lives here, not next to `is_heartbeat_committee_member`, only because
/// `ethlambda-storage` needs it to seed its metadata key and does not depend on
/// `ethlambda-state-transition`. It is a plain `u64` and binds nothing on the
/// wire.
pub const DEFAULT_HEARTBEAT_COMMITTEE_SIZE: u64 = 16;

/// Largest `HEARTBEAT_COMMITTEE_SIZE` accepted from a genesis config.
///
/// Any value at or above the validator count behaves identically (the effective
/// size is clamped to the registry), so this is a typo guard rather than a
/// protocol bound. It matches `MAX_ATTESTATIONS_DATA` because that is the entry
/// budget a wide committee split competes for.
pub const MAX_HEARTBEAT_COMMITTEE_SIZE: u64 = 4096;
