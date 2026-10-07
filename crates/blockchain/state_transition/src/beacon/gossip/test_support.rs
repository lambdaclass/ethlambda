//! Test scaffolding shared by `block`'s, `column`'s, `aggregate`'s and
//! `attestation`'s unit tests (and the parent module's own): a bare store
//! anchored at a chosen finalized slot, a store finalized past a fork whose
//! `LiveChain` rows the advance pruned, a keyed fulu parent state whose
//! lookahead names one proposer, and the seen-cache and clock helpers every
//! module's tests build on.
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
    store_with_config(
        finalized_slot,
        Config::mainnet().with_fork_epoch(ForkName::Fulu, 0),
    )
}

/// [`store`] under a fork schedule of the test's own.
pub(crate) fn store_with_config(finalized_slot: Slot, config: Config) -> Store {
    Store::init_beacon(
        Arc::new(InMemoryBackend::new()),
        GENESIS_TIME,
        config,
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

/// The [`seen_blocks`] counterpart for aggregates: both capacities sized the
/// same generous way, since a test's handful of messages never approaches
/// either bound.
pub(crate) fn seen_aggregates() -> SeenAggregates {
    let capacity = NonZeroUsize::new(8).expect("non-zero");
    SeenAggregates::new(capacity, capacity)
}

/// The [`seen_blocks`] counterpart for gloas execution payload envelopes.
pub(crate) fn seen_envelopes() -> super::SeenEnvelopes {
    super::SeenEnvelopes::new(NonZeroUsize::new(8).expect("non-zero"))
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
    // The pubkey writes above are buffered in the registry tree, and the
    // tests cache this state behind an `Arc`, which `Store::cache_state`
    // refuses to hold unflushed.
    state.apply_pending_mutations();
    state
}

/// The builder-market rules' shared scene: a gloas chain whose head `PARENT`
/// (slot 32, epoch 1) is a FULL block with a funded active builder 0, the
/// proposer preferences and parent payload gossip would have delivered, and a
/// signed bid for slot 34 that passes every rule.
pub(crate) mod builder_scene {
    use ethlambda_storage::ForkCheckpoints;
    use ethlambda_types::beacon::containers::{SignedBeaconBlock, electra, gloas};

    use super::*;
    use crate::beacon::builder_market::{BuilderMarket, test_support};
    use crate::beacon::fork_choice::PayloadStatus;
    use crate::beacon::gloas_block_production::test_support as gloas_support;
    use crate::beacon::gossip::proposer_preferences::dependent_root_at;
    use crate::beacon::helpers::accessors::{get_current_epoch, get_randao_mix};
    use crate::beacon::primitives::{ExecutionAddress, ExecutionBlockHash};

    pub(crate) const PARENT: Root = Root::repeat_byte(0x50);
    pub(crate) const BID_SLOT: Slot = 34;
    /// The slot the scene's parent sits at: epoch 1, whose state can hold a
    /// funded builder only with a finalized epoch that a real chain cannot have
    /// there (a builder is active once the finalized epoch passes its deposit
    /// epoch, and the finalized epoch never exceeds the previous one). Fine for
    /// a rule that reads the state as it is; a test that advances it through
    /// an epoch's end needs [`scene_at`] with a parent in epoch 2 or later.
    pub(crate) const PARENT_SLOT: Slot = 32;
    pub(crate) const PARENT_GAS_LIMIT: u64 = 30_000_000;

    pub(crate) fn fee_recipient() -> ExecutionAddress {
        ExecutionAddress::repeat_byte(0x11)
    }

    /// The hash of the FULL parent's payload, which the bid builds on.
    pub(crate) fn parent_block_hash() -> ExecutionBlockHash {
        ExecutionBlockHash::repeat_byte(gloas_support::PARENT_BLOCK_HASH)
    }

    /// A fulu-shaped block at `slot`: the store only reads its slot and parent.
    pub(crate) fn block_at(slot: Slot) -> SignedBeaconBlock {
        block_with_parent(slot, Root::ZERO)
    }

    pub(crate) fn block_with_parent(slot: Slot, parent_root: Root) -> SignedBeaconBlock {
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

    /// An empty store, gloas from genesis, anchored (and headed) at `PARENT`,
    /// whose block the caller must store.
    fn gloas_store_at(parent_slot: Slot) -> Store {
        Store::init_beacon(
            Arc::new(InMemoryBackend::new()),
            GENESIS_TIME,
            gloas_support::config(),
            PARENT,
            Checkpoint {
                root: PARENT,
                slot: parent_slot,
            },
            parent_slot,
        )
    }

    pub(crate) struct Scene {
        pub store: Store,
        pub market: BuilderMarket,
        /// `PARENT`'s post-state.
        pub state: BeaconState,
        /// A signed bid that passes every rule at [`Scene::now_ms`].
        pub bid: gloas::SignedExecutionPayloadBid,
    }

    /// `PARENT`'s post-state at `parent_slot`, with an active funded builder 0.
    /// Reached by advancing the epoch-1 state while nothing is finalized, so
    /// every epoch transition on the way is one a real chain takes, then
    /// finalizing epoch 1: reachable once `parent_slot` is in epoch 2 or later.
    fn parent_state_at(parent_slot: Slot) -> BeaconState {
        let mut state = test_support::gloas_state_with_builder(0, 100_000_000_000, 0);
        if parent_slot == PARENT_SLOT {
            return state;
        }
        let BeaconState::Gloas(inner) = &mut state else {
            unreachable!("built as gloas")
        };
        inner.finalized_checkpoint.epoch = 0;
        let config = gloas_support::config();
        let mut state =
            crate::beacon::block_production::advance_to_slot(&state, parent_slot, &config)
                .expect("advance to the parent's slot");
        let BeaconState::Gloas(inner) = &mut state else {
            unreachable!("built as gloas")
        };
        inner.finalized_checkpoint.epoch = 1;
        inner.latest_block_header.slot = inner.slot;
        state
    }

    impl Scene {
        /// 100 ms into the bid's slot.
        pub(crate) fn now_ms(&self) -> u64 {
            slot_start_ms(&self.store, self.bid.message.slot) + 100
        }

        /// The scene's bid after `edit`, re-signed by its builder.
        pub(crate) fn signed(
            &self,
            edit: impl FnOnce(&mut gloas::ExecutionPayloadBid),
        ) -> gloas::SignedExecutionPayloadBid {
            let mut bid = self.bid.message.clone();
            edit(&mut bid);
            test_support::sign_bid(&self.state, bid, self.bid.message.builder_index)
        }
    }

    /// The scene with `edit` applied to the parent's state before it is stored,
    /// and the prerequisites of a passing bid recorded in the market.
    pub(crate) fn scene_with(edit: impl FnOnce(&mut gloas::BeaconState)) -> Scene {
        scene_at(PARENT_SLOT, edit)
    }

    /// [`scene_with`] for a parent at `parent_slot`, whose bid is for the slot
    /// two after it.
    pub(crate) fn scene_at(parent_slot: Slot, edit: impl FnOnce(&mut gloas::BeaconState)) -> Scene {
        let bid_slot = parent_slot + (BID_SLOT - PARENT_SLOT);
        let mut state = parent_state_at(parent_slot);
        let BeaconState::Gloas(inner) = &mut state else {
            unreachable!("built as gloas")
        };
        edit(inner);
        state.apply_pending_mutations();
        let mut store = gloas_store_at(parent_slot);
        store
            .insert_pending_block(PARENT, block_at(state.slot()))
            .expect("insert the parent");
        store
            .insert_state(PARENT, state.clone())
            .expect("insert the parent state");
        store
            .update_checkpoints(ForkCheckpoints::head_only(PARENT))
            .expect("move the head");
        store.set_head_payload_status(PARENT, PayloadStatus::Full);

        let dependent_root = dependent_root_at(&state, PARENT, bid_slot).expect("in the window");
        let proposer = crate::beacon::precheck::fixed_proposer(&state, bid_slot).expect("window");
        let market = BuilderMarket::default();
        let preferences = test_support::sign_preferences(
            &state,
            gloas::ProposerPreferences {
                dependent_root,
                proposal_slot: bid_slot,
                validator_index: proposer,
                fee_recipient: fee_recipient(),
                target_gas_limit: PARENT_GAS_LIMIT,
            },
        );
        assert!(market.record_preferences(preferences, bid_slot - 1));
        market.record_execution_payload(&test_support::envelope_with_gas_limit(
            parent_block_hash(),
            PARENT_GAS_LIMIT,
            PARENT,
            vec![],
        ));
        let bid = test_support::sign_bid(
            &state,
            gloas::ExecutionPayloadBid {
                parent_block_hash: parent_block_hash(),
                parent_block_root: PARENT,
                block_hash: ExecutionBlockHash::repeat_byte(0x33),
                prev_randao: get_randao_mix(&state, get_current_epoch(&state)),
                fee_recipient: fee_recipient(),
                gas_limit: PARENT_GAS_LIMIT,
                builder_index: 0,
                slot: bid_slot,
                value: 1,
                ..Default::default()
            },
            0,
        );
        Scene {
            store,
            market,
            state,
            bid,
        }
    }

    pub(crate) fn scene() -> Scene {
        scene_with(|_| {})
    }
}
