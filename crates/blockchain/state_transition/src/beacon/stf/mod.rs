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
//! too. Here every one of those is a [`crate::beacon::Error`] returned through `?`, so
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
//!
//! # Dispatching on the block's fork, not a shared body type
//!
//! [`containers::BeaconState`] and [`containers::SignedBeaconBlock`] are enums
//! over per-fork structs, so every entry point here has to decide, at some
//! point, which fork's rules apply. [`block::process_block`] makes that
//! decision once, by matching [`containers::SignedBeaconBlock`]'s variant, and
//! hands each fork's own concrete `BeaconBlock` to a function written just for
//! it: [`block::process_block_phase0`], [`block::process_block_altair`], and a
//! stub per later fork in this module's [`bellatrix`], [`capella`], [`deneb`],
//! [`electra`], and [`fulu`] siblings.
//!
//! Deliberately absent from that list is any shared `BeaconBlockBody` enum, a
//! `BeaconBlockBodyRef`, or a trait over bodies. Such a type would have to grow
//! a method (or a match arm) per fork-specific field or operation list, which
//! defeats the point of dispatching once: a caller of `body.attester_slashings()`
//! would still have to know which fork it is dealing with to make sense of what
//! comes back, since electra's attester slashings are not phase0's. What
//! actually lets one function serve every fork is narrower and cheaper than any
//! of that: [`block::process_block_header`], [`block::process_randao`], and
//! [`block::process_eth1_data`] take the handful of fields they each read
//! directly, rather than a whole body, so nothing about validating a header
//! cares whether the body it came from also carries a sync aggregate or an
//! execution payload. A shared step earns its genericity by needing less, not
//! by being handed a bigger abstraction to see through.
//!
//! [`state_transition`] adds one check the specification itself has no
//! occasion to make: that the block's fork actually matches the state's. See
//! its own documentation for why that check belongs there and not inside
//! [`block::process_block`].

pub mod altair;
pub mod bellatrix;
pub mod block;
pub mod capella;
pub mod deneb;
pub mod electra;
pub mod epoch;
pub mod fulu;
pub mod operations;

use crate::beacon::containers;
use crate::beacon::containers::{BeaconState, phase0};
use crate::beacon::error::{Error, Result, verify};
use crate::beacon::helpers::accessors::{CommitteeCache, get_domain};
use crate::beacon::helpers::misc::compute_signing_root;
use crate::beacon::preset;
use crate::beacon::primitives::{HashTreeRoot as _, Slot};
use crate::beacon::{bls, config::Config, constants};

/// What the execution layer would answer for a block's payload.
///
/// The specification models this as a call out to an execution client:
/// `notify_new_payload` and the rest of `verify_and_notify_new_payload`, present
/// from bellatrix on. Nothing in this module speaks to a real execution client,
/// and the fixture suites that exercise this path supply the answer directly as
/// a boolean in `execution.yaml` rather than a payload to actually validate, so
/// the whole interface collapses to that one value.
#[derive(Debug, Clone, Copy)]
pub struct ExecutionEngine {
    pub execution_valid: bool,
}

impl ExecutionEngine {
    /// An engine that accepts every payload it is asked about.
    pub fn valid() -> Self {
        ExecutionEngine {
            execution_valid: true,
        }
    }

    /// An engine that rejects every payload it is asked about.
    pub fn invalid() -> Self {
        ExecutionEngine {
            execution_valid: false,
        }
    }
}

/// Applies a signed block to the state.
///
/// With `validate_result` set, the proposer's signature and the block's committed
/// `state_root` are both checked. The fixture suites that feed in blocks the
/// proposer never really signed clear it, which is also what a block producer
/// building on a state it already trusts would do.
///
/// Checks the block's fork against the state's own before doing anything else,
/// which is a check the specification never has occasion to write: its
/// `BeaconState` and `BeaconBlock` are already one fork's own types, so a
/// mismatch between them cannot even be expressed there. Here it can be, since
/// both are enums, so this module has to enforce by hand an invariant the
/// specification gets for free. The check belongs in this function rather than
/// in [`block::process_block`] because a mismatch would not reliably fail
/// inside that dispatcher for the reason a reader would expect: most of what an
/// earlier fork's block shares with a later one (the header, the RANDAO reveal,
/// the eth1 vote, and every operation through deneb's shape) reads and writes
/// only the state's fork-invariant fields, so it runs to completion regardless
/// of which variant `state` actually is. A phase0-shaped block applied to an
/// altair state, for instance, would simply never reach `process_sync_aggregate`,
/// since a phase0 body has no such field to read, silently skipping a step the
/// specification requires instead of failing on it. Rejecting the mismatch
/// before any of that runs is what keeps the failure legible: "wrong fork," not
/// some unrelated-looking assertion three steps later.
pub fn state_transition(
    state: &mut BeaconState,
    signed_block: &containers::SignedBeaconBlock,
    validate_result: bool,
    config: &Config,
    engine: &ExecutionEngine,
    committees: &CommitteeCache,
) -> Result<()> {
    process_slots(state, signed_block.slot(), config)?;

    // After `process_slots`, never before it. A block proposed at the first slot
    // of a fork's activation epoch is the *post*-fork shape while the state
    // arriving here is still the pre-fork one, which is exactly the case a fork
    // transition consists of. `process_slots` is what upgrades the state, so
    // checking first would reject every legitimate fork-boundary block and make
    // crossing a fork impossible.
    verify(
        signed_block.fork_name() == state.fork_name(),
        "the block's fork matches the state's",
    )?;

    if validate_result {
        verify(
            verify_block_signature(state, signed_block),
            "block signature",
        )?;
    }

    block::process_block(state, signed_block, config, engine, committees)?;
    // As in `process_slot`: the post-state's root, checked below and needed
    // again in the next slot, is then computed on the state's own nodes.
    state.apply_pending_mutations();

    if validate_result {
        verify(
            signed_block.state_root() == state.hash_tree_root(),
            "block state root matches the post-state",
        )?;
    }

    Ok(())
}

/// Whether the block carries its proposer's signature.
pub fn verify_block_signature(
    state: &BeaconState,
    signed_block: &containers::SignedBeaconBlock,
) -> bool {
    let Ok(proposer) = state.validator(signed_block.proposer_index()) else {
        return false;
    };
    let domain = get_domain(state, constants::DOMAIN_BEACON_PROPOSER, None);
    let signing_root = compute_signing_root(signed_block.message_hash_tree_root(), domain);
    bls::verify(&proposer.pubkey, signing_root, &signed_block.signature())
}

/// Advances the state to `slot`, running epoch processing at each boundary and
/// upgrading the state's shape at each fork boundary crossed.
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
        upgrade_at_fork_boundary(state, config)?;
    }

    // Epoch processing above can leave writes buffered past the last
    // `process_slot`'s own flush (it runs before, not after, that step). A
    // state returned here without a block on top, such as a checkpoint state
    // built for attestation targets or an empty-slot pre-state, would
    // otherwise be cloned and cached with the whole epoch's writes still
    // pending.
    state.apply_pending_mutations();

    Ok(())
}

/// Replaces the state with the next fork's shape if the slot just reached is the
/// first slot of that fork's activation epoch.
///
/// The specification does not list this as a step of `process_slots`. Each fork's
/// `fork.md` instead describes it as an "irregular state change" made when
/// `state.slot % SLOTS_PER_EPOCH == 0` and the resulting epoch equals that fork's
/// activation epoch, leaving where to put it to the implementation. Here is the
/// only place that works: it has to happen after the slot counter advances and
/// before anything reads the state again, and `process_slots` is the one function
/// every path into a new slot goes through.
///
/// Without this, nothing can cross a fork. Every per-fork state transition in the
/// crate could be perfectly correct and the chain would still stop dead at the
/// first activation epoch, because the state would keep the old fork's shape while
/// blocks arrived in the new one.
///
/// The loop, rather than a single check, is for a configuration that activates
/// two forks at the same epoch. The fixture suites do exactly that: a `transition`
/// case moves one fork's activation epoch, and nothing stops it landing on
/// another's. Upgrading one fork per slot would silently leave the state a fork
/// behind.
fn upgrade_at_fork_boundary(state: &mut BeaconState, config: &Config) -> Result<()> {
    if !state.slot().is_multiple_of(preset::SLOTS_PER_EPOCH) {
        return Ok(());
    }
    let epoch = state.slot() / preset::SLOTS_PER_EPOCH;

    while let Some(next) = state.fork_name().next() {
        if config.fork_epoch(next) != epoch {
            break;
        }
        // Bound the borrow of `state` to this statement, since the assignment
        // needs it back mutably.
        let upgraded = crate::beacon::upgrade::upgrade_state(state, next, config)?;
        *state = upgraded;
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
///
/// A caller that already knows the root may perform that fixup early, writing
/// it into the field itself; [`BeaconState::compute_state_root`] then hands it
/// back instead of merkleizing a mainnet-sized registry a second time per
/// import. The value is the one this would have computed, so the state comes
/// out the same either way.
pub fn process_slot(state: &mut BeaconState) -> Result<()> {
    // Fold buffered registry writes into their trees first, so the root below
    // is computed on, and cached in, the state's own nodes rather than on a
    // throwaway copy.
    state.apply_pending_mutations();
    let previous_state_root = state.compute_state_root();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::helpers::test_state;

    #[test]
    fn process_slot_leaves_no_buffered_registry_writes() {
        let mut state = test_state::with_validators(4);
        state.balances_mut()[0] += 1;
        state.validator_mut(1).unwrap().effective_balance -= 1;
        assert!(state.balances().has_pending_updates());
        assert!(state.validators().has_pending_updates());

        process_slot(&mut state).unwrap();

        assert!(!state.balances().has_pending_updates());
        assert!(!state.validators().has_pending_updates());
    }

    /// Epoch processing (`process_rewards_and_penalties` here) writes every
    /// validator's balance through `increase_balance`/`decrease_balance`
    /// after the last `process_slot`'s own flush has already run, so without
    /// `process_slots`' own flush at the end, a state handed back after
    /// crossing an epoch boundary carries the whole epoch's balance writes
    /// still buffered.
    #[test]
    fn process_slots_across_an_epoch_boundary_leaves_no_buffered_writes() {
        let mut state = test_state::with_validators(4);
        let config = Config::mainnet();
        let target_slot = state.slot() + preset::SLOTS_PER_EPOCH;

        process_slots(&mut state, target_slot, &config).unwrap();

        assert!(!state.balances().has_pending_updates());
        assert!(!state.validators().has_pending_updates());
    }
}
