//! The one place this module names the lean half of `ethlambda-types`.
//!
//! [`crate::beacon::containers::BeaconState`] carries a `Lean` variant and
//! [`crate::beacon::ForkName`] a `Lean` name, because `ethlambda-types` holds one
//! state type for both chains. Nothing in this module can transition either: a
//! fixture case, a gossiped beacon block and a genesis deposit set all produce
//! beacon states, so a lean value here means the caller dispatched on the wrong
//! chain. That is a bug above this module rather than an input it can reject, so
//! these arms panic instead of widening every signature to a `Result` no correct
//! caller could ever see.
//!
//! Both carry the same wording as `ethlambda_types::beacon`'s own
//! `lean_state_unreachable` and `lean_fork_unreachable`, which are `pub(crate)`
//! there and so cannot simply be imported. Two functions rather than one taking a
//! discriminant, for the reason that crate split its own: they are two unrelated
//! diagnoses, and rejoining them would only make each caller say which it meant.

/// Panics, naming the beacon accessor a lean state reached.
///
/// This is the state-shaped boundary: reaching it means a caller dispatched on
/// the wrong thing. For the fork-shaped one see [`lean_fork_unreachable`], kept
/// separate because the two are crossed by different mistakes.
///
/// `#[track_caller]` so the panic still reports the arm's own file and line, the
/// way an `unreachable!` written inline there would have.
#[cold]
#[track_caller]
pub(crate) fn lean_state_unreachable(function: &str) -> ! {
    unreachable!(
        "lean state reached a beacon accessor ({function}); \
         BlockChainServer must dispatch on fork_name() before this point"
    )
}

/// Panics, naming the Beacon Chain-only function [`crate::beacon::ForkName::Lean`]
/// reached.
///
/// The fork-shaped counterpart to [`lean_state_unreachable`]: lean is not a point
/// on the beacon fork schedule at all, so no state is involved and the fault is
/// the argument the caller passed rather than the state it dispatched on.
#[cold]
#[track_caller]
pub(crate) fn lean_fork_unreachable(function: &str) -> ! {
    unreachable!(
        "ForkName::Lean reached a Beacon Chain function ({function}); \
         lean is not a point on the beacon fork schedule, so the caller \
         passed a fork it should have dispatched on first"
    )
}
