//! Test scaffolding shared by `block`'s, `column`'s, `aggregate`'s and
//! `attestation`'s unit tests: a bare store anchored at a chosen finalized
//! slot, a keyed fulu parent state whose lookahead names one proposer, and
//! the seen-cache and clock helpers every module's tests build on.
//!
//! `precheck.rs` keeps its own `fulu_parent`: it is built through that
//! module's own multi-fork `keyed_state` helper, which this module has no use
//! for, so its shape genuinely differs rather than merely being copy-pasted.

use std::num::NonZeroUsize;
use std::sync::Arc;

use ethlambda_storage::backend::InMemoryBackend;
use ethlambda_types::checkpoint::Checkpoint;

use super::aggregate::SeenAggregates;
use super::attestation::SeenAttestations;
use super::{SeenBlocks, SeenColumns};
use crate::beacon::config::Config;
use crate::beacon::containers::BeaconState;
use crate::beacon::fork::ForkName;
use crate::beacon::fork_choice::Store;
use crate::beacon::helpers::test_state::{secret_key_for, with_validators_at};
use crate::beacon::primitives::{BlsPubkey, Root, Slot, ValidatorIndex};

pub(crate) const GENESIS_TIME: u64 = 1_000;

/// A store with no blocks, finalized at `finalized_slot`, fulu from genesis.
pub(crate) fn store(finalized_slot: Slot) -> Store {
    Store::init_beacon(
        Arc::new(InMemoryBackend::new()),
        GENESIS_TIME,
        Config::mainnet().with_fork_epoch(ForkName::Fulu, 0),
        Root::ZERO,
        Checkpoint {
            root: Root::ZERO,
            slot: finalized_slot,
        },
        finalized_slot,
    )
}

/// The millisecond clock reading at the start of `slot`, under `store`'s
/// config.
pub(crate) fn slot_start_ms(store: &Store, slot: Slot) -> u64 {
    let config = store.config();
    config.genesis_time_ms() + slot * config.slot_duration_ms
}

/// An empty [`SeenBlocks`] cache, sized generously for a test's handful of
/// messages.
pub(crate) fn seen_blocks() -> SeenBlocks {
    SeenBlocks::new(NonZeroUsize::new(8).expect("non-zero"))
}

/// The [`seen_blocks`] counterpart for columns.
pub(crate) fn seen_columns() -> SeenColumns {
    SeenColumns::new(NonZeroUsize::new(8).expect("non-zero"))
}

/// The [`seen_blocks`] counterpart for aggregates: both capacities sized the
/// same generous way, since a test's handful of messages never approaches
/// either bound.
pub(crate) fn seen_aggregates() -> SeenAggregates {
    let capacity = NonZeroUsize::new(8).expect("non-zero");
    SeenAggregates::new(capacity, capacity)
}

/// The [`seen_blocks`] counterpart for subnet attestations.
pub(crate) fn seen_attestations() -> SeenAttestations {
    SeenAttestations::new(NonZeroUsize::new(8).expect("non-zero"))
}

/// A fulu state of eight keyed validators whose lookahead names `proposer`
/// for every slot in its window.
pub(crate) fn fulu_parent(proposer: ValidatorIndex) -> BeaconState {
    let mut state = with_validators_at(ForkName::Fulu, 8);
    for index in 0..8 {
        state
            .validator_mut(index as ValidatorIndex)
            .expect("eight validators")
            .pubkey = BlsPubkey(secret_key_for(index).sk_to_pk().to_bytes());
    }
    if let BeaconState::Fulu(fulu_state) = &mut state {
        for entry in fulu_state.proposer_lookahead.iter_mut() {
            *entry = proposer;
        }
    }
    state
}
