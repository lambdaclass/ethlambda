//! The beacon state transition function.
//!
//! Applying a block is two stages. First the state is advanced to the block's
//! slot, one slot at a time, running epoch processing at each epoch boundary
//! crossed. Then the block's own contents are applied. Both stages can fail, and
//! a failure at any point means the block is invalid.
//!
//! # Failure is the normal case
//!
//! The specification expresses invalidity by letting an `assert` fail or an index
//! go out of range, and says that a `uint64` overflow or underflow is invalid
//! too. Here every one of those is a [`crate::Error`] returned through `?`, so
//! nothing panics on a hostile block. That is why balance arithmetic goes through
//! checked operations rather than `+` and `-`: in release builds Rust wraps
//! silently, which would turn an invalid block into a corrupted state.
//!
//! # Mutation in place, and what that costs the caller
//!
//! The spec mutates the state in place and so does this, which means a state
//! passed to [`state_transition`] is left partly modified when a block turns out
//! to be invalid. Callers that need to keep the pre-state must clone it first,
//! which is what the fixture runners do. The alternative, threading a fresh state
//! through every function, would depart from the spec's structure everywhere
//! without making anything safer.

pub mod block;
pub mod epoch;
pub mod operations;

use crate::containers::{BeaconState, phase0};
use crate::error::{Error, Result, verify};
use crate::helpers::accessors::get_domain;
use crate::helpers::misc::compute_signing_root;
use crate::preset;
use crate::primitives::{HashTreeRoot as _, Slot};
use crate::{bls, config::Config, constants};

/// Applies a signed block to the state.
///
/// With `validate_result` set, the proposer's signature and the block's committed
/// `state_root` are both checked. The fixture suites that feed in blocks the
/// proposer never really signed clear it, which is also what a block producer
/// building on a state it already trusts would do.
pub fn state_transition(
    state: &mut BeaconState,
    signed_block: &phase0::SignedBeaconBlock,
    validate_result: bool,
    config: &Config,
) -> Result<()> {
    let block = &signed_block.message;

    process_slots(state, block.slot, config)?;

    if validate_result {
        verify(
            verify_block_signature(state, signed_block),
            "block signature",
        )?;
    }

    block::process_block(state, block, config)?;

    if validate_result {
        verify(
            block.state_root == state.hash_tree_root(),
            "block state root matches the post-state",
        )?;
    }

    Ok(())
}

/// Whether the block carries its proposer's signature.
pub fn verify_block_signature(
    state: &BeaconState,
    signed_block: &phase0::SignedBeaconBlock,
) -> bool {
    let Ok(proposer) = state.validator(signed_block.message.proposer_index) else {
        return false;
    };
    let domain = get_domain(state, constants::DOMAIN_BEACON_PROPOSER, None);
    let signing_root = compute_signing_root(signed_block.message.hash_tree_root(), domain);
    bls::verify(&proposer.pubkey, signing_root, &signed_block.signature)
}

/// Advances the state to `slot`, running epoch processing at each boundary.
///
/// Rejects a slot at or before the current one, so this can only ever move
/// forward.
pub fn process_slots(state: &mut BeaconState, slot: Slot, config: &Config) -> Result<()> {
    verify(state.slot() < slot, "target slot is after the current slot")?;

    while state.slot() < slot {
        process_slot(state)?;
        // Epoch processing runs on the last slot of an epoch, before the counter
        // moves into the next one.
        if (state.slot() + 1).is_multiple_of(preset::SLOTS_PER_EPOCH) {
            epoch::process_epoch(state, config)?;
        }
        *state.slot_mut() += 1;
    }

    Ok(())
}

/// Records the outgoing slot's state and block roots.
///
/// The `latest_block_header.state_root` fixup is the resolution of a
/// circularity: a block commits to the root of the state that results from
/// applying it, so the header stored while processing that block cannot yet know
/// it. It is left zero and filled in here, one slot later, which is the first
/// moment the value exists.
pub fn process_slot(state: &mut BeaconState) -> Result<()> {
    let previous_state_root = state.hash_tree_root();
    let position = state.slot() as usize % preset::SLOTS_PER_HISTORICAL_ROOT;
    state.state_roots_mut()[position] = previous_state_root;

    if state.latest_block_header().state_root.is_zero() {
        state.latest_block_header_mut().state_root = previous_state_root;
    }

    let previous_block_root = state.latest_block_header().hash_tree_root();
    state.block_roots_mut()[position] = previous_block_root;

    Ok(())
}

/// The phase0 state, or an error naming the function that needs one.
///
/// Functions whose body is specific to phase0's state shape start here rather
/// than matching inline, so the fork check reads the same in each of them.
#[allow(
    unreachable_patterns,
    reason = "phase0 is currently the enum's only variant, so the fallback arm \
              cannot be reached yet; it becomes live with the first later fork, \
              and dropping it now would only mean adding it back then"
)]
pub(crate) fn phase0_state<'a>(
    state: &'a mut BeaconState,
    function: &'static str,
) -> Result<&'a mut phase0::BeaconState> {
    match state {
        BeaconState::Phase0(state) => Ok(state),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

/// The phase0 state, immutably.
#[allow(
    unreachable_patterns,
    reason = "see the note on `phase0_state`: the fallback arm is not reachable \
              until a later fork adds a variant"
)]
pub(crate) fn phase0_state_ref<'a>(
    state: &'a BeaconState,
    function: &'static str,
) -> Result<&'a phase0::BeaconState> {
    match state {
        BeaconState::Phase0(state) => Ok(state),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}
