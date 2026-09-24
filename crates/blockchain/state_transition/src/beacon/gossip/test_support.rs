//! Test scaffolding shared by `block`'s and `column`'s unit tests (and the
//! parent module's own): a bare store anchored at a chosen finalized slot, a
//! store finalized past a fork whose `LiveChain` rows the advance pruned, a
//! keyed fulu parent state whose lookahead names one proposer, and the
//! seen-cache and clock helpers both modules' tests build on.
//!
//! `precheck.rs` keeps its own `fulu_parent`: it is built through that
//! module's own multi-fork `keyed_state` helper, which this module has no use
//! for, so its shape genuinely differs rather than merely being copy-pasted.

use std::num::NonZeroUsize;
use std::sync::Arc;

use ethlambda_storage::backend::InMemoryBackend;
use ethlambda_types::checkpoint::Checkpoint;

use super::{SeenBlocks, SeenColumns};
use crate::beacon::config::Config;
use crate::beacon::containers::{
    BeaconState, Checkpoint as BeaconCheckpoint, SignedBeaconBlock, electra,
};
use crate::beacon::fork::ForkName;
use crate::beacon::fork_choice::{self, Store};
use crate::beacon::helpers::misc::compute_start_slot_at_epoch;
use crate::beacon::helpers::test_state::{secret_key_for, with_validators_at};
use crate::beacon::primitives::{BlsPubkey, Epoch, Root, Slot, ValidatorIndex};

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

/// An empty fulu block at `slot` under `parent_root`: enough for
/// `BlockHeaders` and `LiveChain` to place it, and nothing else.
pub(crate) fn empty_block(slot: Slot, parent_root: Root) -> SignedBeaconBlock {
    SignedBeaconBlock::Fulu(electra::SignedBeaconBlock {
        message: electra::BeaconBlock {
            slot,
            proposer_index: 0,
            parent_root,
            state_root: Root::ZERO,
            body: electra::BeaconBlockBody::empty(),
        },
        signature: Default::default(),
    })
}

/// The epoch [`store_finalized_past_a_fork`] finalizes.
pub(crate) const FINALIZED_EPOCH: Epoch = 1;

/// What [`store_finalized_past_a_fork`] builds.
pub(crate) struct PastAFork {
    pub(crate) store: Store,
    /// The finalized block, one slot below [`FINALIZED_EPOCH`]'s start slot,
    /// which has no block.
    pub(crate) finalized: Root,
    /// A child of `finalized`, one slot past that empty start slot.
    pub(crate) descendant: Root,
    /// The first block of a fork that split off from genesis below
    /// `finalized`'s slot. The advance pruned its `LiveChain` row.
    pub(crate) fork_base: Root,
    /// `fork_base`'s child, at `descendant`'s slot. Its row survives the
    /// advance, so a walk from it reaches `fork_base`'s pruned one.
    pub(crate) fork_tip: Root,
}

/// A store finalized at [`FINALIZED_EPOCH`] by a real finalization advance
/// (`fork_choice::update_checkpoints`, which prunes `LiveChain` as a side
/// effect), over
///
/// ```text
/// genesis ─┬─ finalized ──────────── descendant
///          └─ fork_base ── fork_tip
/// ```
///
/// Genesis is [`store`]'s own anchor root. The advance drops genesis' and
/// `fork_base`'s `LiveChain` rows, both below `finalized`'s slot; every block
/// keeps its `BlockHeaders` row.
pub(crate) fn store_finalized_past_a_fork() -> PastAFork {
    let mut store = store(0);
    let epoch_start = compute_start_slot_at_epoch(FINALIZED_EPOCH);
    let finalized = Root::repeat_byte(0xf0);
    let descendant = Root::repeat_byte(0xf1);
    let fork_base = Root::repeat_byte(0xa0);
    let fork_tip = Root::repeat_byte(0xa1);
    let blocks = [
        (Root::ZERO, empty_block(0, Root::ZERO)),
        (finalized, empty_block(epoch_start - 1, Root::ZERO)),
        (descendant, empty_block(epoch_start + 1, finalized)),
        (fork_base, empty_block(1, Root::ZERO)),
        (fork_tip, empty_block(epoch_start + 1, fork_base)),
    ];
    for (root, block) in blocks {
        store
            .insert_signed_block(root, block)
            .expect("insert block");
    }

    let checkpoint = BeaconCheckpoint {
        epoch: FINALIZED_EPOCH,
        root: finalized,
    };
    fork_choice::update_checkpoints(&mut store, checkpoint, checkpoint);
    let index = store.block_index();
    assert!(
        !index.contains_key(&fork_base) && index.contains_key(&finalized),
        "the advance must prune below the finalized block's own slot, and only there"
    );

    PastAFork {
        store,
        finalized,
        descendant,
        fork_base,
        fork_tip,
    }
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
