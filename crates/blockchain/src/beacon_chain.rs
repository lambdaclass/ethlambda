//! The beacon arm of each [`crate::BlockChainServer`] handler.
//!
//! Nothing here is shared with `crate::store`, by decision: lean's fork-choice
//! weight is one vote per validator over an unfiltered tree, beacon's is summed
//! effective balances with proposer boost and equivocation exclusion over an
//! FFG-filtered tree, and only the descent loop itself coincides.
//!
//! `on_attestation` and `on_attester_slashing` have no production caller yet.
//! `ethlambda_beacon::fork_choice::tests::measures_the_warm_path_cost_of_on_attestation`
//! puts a single gossiped aggregate's warm-path cost (checkpoint state already
//! cached, only committee derivation and one BLS verification left to do) at
//! 7.6ms at 4,096 validators and 37.7ms at roughly today's real mainnet active
//! validator count, because `get_beacon_committee` calls
//! `get_active_validator_indices` (twice) with no cache of its own: an
//! unconditional scan of the whole registry on every single call, however warm
//! everything else is. Mainnet's aggregate-and-proof topic alone can carry on
//! the order of `MAX_COMMITTEES_PER_SLOT * TARGET_AGGREGATORS_PER_COMMITTEE`
//! messages a slot, all landing on the same single-threaded mailbox that also
//! does block import; at this per-message cost, even ordinary healthy volume
//! risks starving it well before a slot ends. Wiring gossip votes into fork
//! choice is deferred until that scan has a fix, rather than shipped behind an
//! arbitrary drop cap chosen without room to validate it against real
//! contention.
//!
//! `on_block`'s beacon block import and the head recomputation around it
//! (`update_head`, called from `BlockChainServer::on_beacon_block` and
//! `beacon_on_tick`) do have callers. Every function here is still tested on
//! its own regardless of caller status: the dispatch they sit behind is what
//! makes `BeaconState::Lean`'s `unreachable!()` arms sound, and that has to
//! hold before anything crosses the boundary, not after.
//!
//! # Why `update_head`'s own call rate is safe *today*, and only today
//!
//! `get_head`'s descent calls `get_weight` once per level of the unfinalized
//! suffix, and `get_weight` shares `on_attestation`'s exact bottleneck: the
//! same unconditional registry scan, plus a `get_ancestor` walk for every
//! validator that has a `latest_message` on record.
//! `ethlambda_beacon::fork_choice::tests::measures_get_weight_cost_with_and_without_votes`
//! measures that second part directly: 17.4ms/call at mainnet scale with no
//! votes recorded, 165.4ms/call with every validator voting. With gossip
//! ingestion deferred (above), `latest_messages` in production today is
//! populated only by `on_block`'s block-embedded attestations, so "once per
//! cascade, once per tick" lands near the first number, not the second.
//! Shipping Part 2 without first fixing the shared scan would push every
//! `update_head` call from "once per slot at ~17ms times the unjustified
//! depth" toward "once per slot at ~165ms times the same depth", which is the
//! other reason that wiring stays out for now.

use ethlambda_beacon::config::Config;
use ethlambda_beacon::containers::{SignedBeaconBlock, phase0};
use ethlambda_beacon::error::{Error, Result};
use ethlambda_beacon::fork_choice::{
    self, Attestation, AttesterSlashing, BeaconBlockIndex, DataAvailability,
};
use ethlambda_beacon::primitives::{Root, Slot};
use ethlambda_storage::Store;
use tracing::trace;

/// Bound on how far [`reorg_depth`] walks back before giving up.
///
/// Mirrors the lean path's own `MAX_REORG_DEPTH` in `crate::store::reorg_depth`:
/// a walk this deep only happens for a genuinely pathological fork, and the
/// exact count stops mattering once it is already this large.
const MAX_REORG_DEPTH: u64 = 128;

/// Advances the store's clock to `timestamp_ms`.
///
/// The beacon clock is Unix **seconds**, so this is where the actor's
/// millisecond tick is truncated. That is not a loss of resolution the handler
/// cares about: `fork_choice`'s only sub-slot comparisons recompute
/// milliseconds from this value on demand (see its module documentation).
pub fn on_tick(store: &mut Store, timestamp_ms: u64, config: &Config) {
    fork_choice::on_tick(store, timestamp_ms / 1000, config);
}

/// Imports `block`, then replays every attestation and attester slashing its
/// body carries, matching what the reference test generator's `add_block` does.
///
/// `DataAvailability::NotRequired` unconditionally: no column subnet is
/// subscribed, so no sampling evidence exists to pass. Sub-project D is what
/// makes post-fulu data availability enforceable; until then this is logged once
/// at startup rather than silently implied.
pub fn on_block(store: &mut Store, block: SignedBeaconBlock, config: &Config) -> Result<()> {
    let (attestations, slashings) = block_operations(&block);
    let slot = block.slot();
    fork_choice::on_block(store, block, config, &DataAvailability::NotRequired)?;

    // The block is imported by the line above; what follows is fork choice
    // learning from its body, and a body item this store cannot evaluate is not
    // grounds for calling the import a failure.
    //
    // The reference test generator can propagate here because every fixture
    // adds a block's antecedents before the block itself. A checkpoint-synced
    // follower cannot: an attestation may name a target up to
    // `SLOTS_PER_EPOCH` slots back, and for the first epochs after the anchor
    // that target is below it and was never fetched, so
    // `validate_on_attestation`'s "target.root in store.blocks" rejects it. The
    // spec-test harness keeps its own strict replay
    // (`tests/spec/fork_choice.rs::apply_block`), so the fixtures still fail on
    // anything they can legitimately reach.
    //
    // Returning `Err` here also cost more than a log line: the caller reads it
    // as "this block did not import" and stops the cascade, leaving every held
    // descendant held behind a block that is in fact in the store.
    for attestation in &attestations {
        let _ = fork_choice::on_attestation(store, attestation, true, config).inspect_err(
            |err| trace!(%slot, ?err, "Ignoring an unusable attestation from a block"),
        );
    }
    for slashing in &slashings {
        let _ = fork_choice::on_attester_slashing(store, slashing, config)
            .inspect_err(|err| trace!(%slot, ?err, "Ignoring an unusable slashing from a block"));
    }
    Ok(())
}

/// Applies a gossiped aggregate's attestation to fork choice.
pub fn on_attestation(store: &mut Store, attestation: &Attestation, config: &Config) -> Result<()> {
    fork_choice::on_attestation(store, attestation, false, config)
}

/// Records every validator common to both halves of `slashing` as equivocating.
pub fn on_attester_slashing(
    store: &mut Store,
    slashing: &AttesterSlashing,
    config: &Config,
) -> Result<()> {
    fork_choice::on_attester_slashing(store, slashing, config)
}

/// The LMD GHOST head.
pub fn head(store: &Store, config: &Config) -> Result<Root> {
    fork_choice::get_head(store, config)
}

/// The slot `store`'s own clock currently falls in.
///
/// A thin wrapper for the same reason every other function in this file is
/// one: `crate::lib` calls into `beacon_chain::*` rather than
/// `ethlambda_beacon::fork_choice::*` directly, so the boundary the module
/// documentation describes stays in one place.
pub fn current_slot(store: &Store, config: &Config) -> Slot {
    fork_choice::get_current_slot(store, config)
}

/// What [`update_head`] changed, for the caller to log and feed to metrics.
pub struct HeadUpdate {
    /// The new head's own slot.
    pub slot: Slot,
    /// The new head's block root.
    pub root: Root,
    /// The new head's parent root, for a "head moved" log line that names the
    /// chain it extends without a second store lookup.
    pub parent_root: Root,
    /// The head before this call, or `None` on the first call this store has
    /// ever made (nothing to compare a reorg against yet).
    pub previous: Option<(Slot, Root)>,
    /// `Some(depth)` if moving from `previous` to the new head is a reorg
    /// (the new head does not descend from the old one); `None` for ordinary
    /// chain growth, and also when `previous` is `None`.
    pub reorg_depth: Option<u64>,
}

/// Recomputes the LMD GHOST head and records it as `store`'s canonical head.
///
/// Called once per beacon-block cascade, after every block it unblocked has
/// imported, and once per tick when the slot advances: proposer boost expiry
/// and attestation arrival can each move the head with no new block involved,
/// so a block-only trigger would leave the reported head stale between
/// blocks. Never called per block inside a cascade: [`fork_choice::get_head`]
/// walks the whole filtered tree, and only the head after the cascade's last
/// block is ever acted on, so recomputing mid-cascade would repeat that walk
/// for a result the next block immediately supersedes.
pub fn update_head(store: &mut Store, config: &Config) -> Result<HeadUpdate> {
    let root = fork_choice::get_head(store, config)?;
    let index = store.beacon_block_index();
    let (slot, parent_root) = index
        .get(&root)
        .copied()
        .ok_or(Error::SpecAssert("head root in store.blocks"))?;

    let previous = store.beacon_head();
    store.set_beacon_head(slot, root);

    let reorg_depth = previous.and_then(|old_head| reorg_depth(&index, old_head, (slot, root)));

    Ok(HeadUpdate {
        slot,
        root,
        parent_root,
        previous,
        reorg_depth,
    })
}

/// Whether moving the head from `old` to `new` is a reorg, and if so how many
/// slots separate `old` from the last block both branches still share.
///
/// Mirrors the lean path's `crate::store::reorg_depth`: walk back from
/// whichever head has the higher slot until reaching the other head's own
/// slot, then compare roots there. `None` covers two different cases the
/// caller does not need to tell apart: ordinary growth (the walk lands
/// exactly on `old`), and a walk that runs off the known index before
/// resolving either way, which happens only when `old` has already fallen out
/// of the retained anchor window (see `Store::promote_beacon_anchor`) and is
/// too far back to say anything meaningful about.
fn reorg_depth(index: &BeaconBlockIndex, old: (Slot, Root), new: (Slot, Root)) -> Option<u64> {
    let (old_slot, old_root) = old;
    let (new_slot, new_root) = new;
    if old_root == new_root {
        return None;
    }

    let (mut current_root, target_slot, target_root) = if new_slot >= old_slot {
        (new_root, old_slot, old_root)
    } else {
        (old_root, new_slot, new_root)
    };

    let mut depth: u64 = 0;
    while let Some(&(slot, parent_root)) = index.get(&current_root) {
        if slot <= target_slot {
            return (current_root != target_root).then_some(depth);
        }
        current_root = parent_root;
        depth += 1;
        if depth >= MAX_REORG_DEPTH {
            return Some(depth);
        }
    }

    None
}

/// The attestations and attester slashings carried in `block`'s body, in the
/// fork-generic shapes the handlers take.
fn block_operations(block: &SignedBeaconBlock) -> (Vec<Attestation>, Vec<AttesterSlashing>) {
    match block {
        SignedBeaconBlock::Electra(block) | SignedBeaconBlock::Fulu(block) => (
            block
                .message
                .body
                .attestations
                .iter()
                .cloned()
                .map(Attestation::Electra)
                .collect(),
            block
                .message
                .body
                .attester_slashings
                .iter()
                .cloned()
                .map(AttesterSlashing::Electra)
                .collect(),
        ),
        SignedBeaconBlock::Phase0(block) => phase0_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
        ),
        SignedBeaconBlock::Altair(block) => phase0_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
        ),
        SignedBeaconBlock::Bellatrix(block) => phase0_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
        ),
        SignedBeaconBlock::Capella(block) => phase0_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
        ),
        SignedBeaconBlock::Deneb(block) => phase0_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
        ),
    }
}

/// Phase0 through deneb share one attestation and slashing shape, so their five
/// arms above share one body.
///
/// Takes iterators rather than the lists themselves: each fork's body names its
/// own `SszList` bound, so a parameter typed on the list would need one generic
/// per bound, and `.iter()` erases exactly that difference.
fn phase0_operations<'a>(
    attestations: impl Iterator<Item = &'a phase0::Attestation>,
    slashings: impl Iterator<Item = &'a phase0::AttesterSlashing>,
) -> (Vec<Attestation>, Vec<AttesterSlashing>) {
    (
        attestations.cloned().map(Attestation::Phase0).collect(),
        slashings.cloned().map(AttesterSlashing::Phase0).collect(),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ethlambda_beacon::containers::{BeaconState, Checkpoint, Validator};
    use ethlambda_beacon::preset;
    use ethlambda_storage::backend::InMemoryBackend;

    use super::*;

    /// A signed block with an empty body and a zero signature, for tests that
    /// only care about `slot` and `parent_root`. Phase0-shaped since nothing
    /// under test here reads anything fork-specific, matching
    /// `ethlambda_beacon::fork_choice`'s own test helper of the same name.
    fn block(slot: Slot, parent_root: Root) -> SignedBeaconBlock {
        SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: Root::zero(),
                body: phase0::BeaconBlockBody {
                    randao_reveal: Default::default(),
                    eth1_data: Default::default(),
                    graffiti: Root::zero(),
                    proposer_slashings: Default::default(),
                    attester_slashings: Default::default(),
                    attestations: Default::default(),
                    deposits: Default::default(),
                    voluntary_exits: Default::default(),
                },
            },
            signature: Default::default(),
        })
    }

    /// A phase0 state with `count` fully active, zero-pubkey validators.
    ///
    /// This crate cannot reach `ethlambda_beacon`'s own
    /// `helpers::test_state::with_validators`, which builds the same shape:
    /// that module is `pub(crate)` there. Good enough for `get_weight` and
    /// `get_voting_source`, neither of which ever reads a pubkey.
    fn state_with_validators(count: usize) -> BeaconState {
        let validators: Vec<Validator> = (0..count)
            .map(|_| Validator {
                effective_balance: 1,
                activation_eligibility_epoch: 0,
                activation_epoch: 0,
                exit_epoch: ethlambda_beacon::constants::FAR_FUTURE_EPOCH,
                withdrawable_epoch: ethlambda_beacon::constants::FAR_FUTURE_EPOCH,
                ..Default::default()
            })
            .collect();

        BeaconState::Phase0(phase0::BeaconState {
            genesis_time: 0,
            genesis_validators_root: Root::zero(),
            slot: 0,
            fork: Default::default(),
            latest_block_header: Default::default(),
            block_roots: vec![Root::zero(); preset::SLOTS_PER_HISTORICAL_ROOT]
                .try_into()
                .expect("the vector is built at its exact length"),
            state_roots: vec![Root::zero(); preset::SLOTS_PER_HISTORICAL_ROOT]
                .try_into()
                .expect("the vector is built at its exact length"),
            historical_roots: Default::default(),
            eth1_data: Default::default(),
            eth1_data_votes: Default::default(),
            eth1_deposit_index: 0,
            validators: validators
                .try_into()
                .expect("count is far below the registry limit"),
            balances: vec![1; count]
                .try_into()
                .expect("count is far below the registry limit"),
            randao_mixes: vec![Default::default(); preset::EPOCHS_PER_HISTORICAL_VECTOR]
                .try_into()
                .expect("the vector is built at its exact length"),
            slashings: vec![0; preset::EPOCHS_PER_SLASHINGS_VECTOR]
                .try_into()
                .expect("the vector is built at its exact length"),
            previous_epoch_attestations: Default::default(),
            current_epoch_attestations: Default::default(),
            justification_bits: Default::default(),
            previous_justified_checkpoint: Default::default(),
            current_justified_checkpoint: Default::default(),
            finalized_checkpoint: Default::default(),
        })
    }

    /// A beacon store with `genesis_root` justified and finalized at
    /// `GENESIS_EPOCH`, and a checkpoint state of `validator_count` active
    /// validators cached over it.
    ///
    /// Matches `ethlambda_beacon::fork_choice`'s own
    /// `get_head_breaks_equal_weight_ties_by_higher_root`: the `GENESIS_EPOCH`
    /// shortcut in `filter_block_tree`'s `correct_justified`/`correct_finalized`
    /// checks means every leaf below only needs what `get_weight` and
    /// `get_voting_source` actually read, not a fully spec-shaped justified
    /// history.
    fn store_with_genesis(genesis_root: Root, validator_count: usize) -> Store {
        let mut store = Store::init_beacon(Arc::new(InMemoryBackend::new()), 0);
        let genesis_checkpoint = Checkpoint {
            epoch: ethlambda_beacon::constants::GENESIS_EPOCH,
            root: genesis_root,
        };
        store.set_beacon_justified_checkpoint(genesis_checkpoint);
        store.set_beacon_finalized_checkpoint(genesis_checkpoint);
        store.insert_beacon_block(genesis_root, &block(0, Root::zero()));
        store.cache_checkpoint_state(
            genesis_checkpoint,
            Arc::new(state_with_validators(validator_count)),
        );
        store
    }

    /// Inserts `root` at `slot` under `parent_root`, and caches a post-state
    /// for it.
    ///
    /// Every test store here keeps its clock at genesis (current epoch 0) and
    /// every test block's own slot within that epoch too, so
    /// `get_voting_source` always takes the "read the block's own post-state"
    /// branch for whichever root turns out to be a leaf; caching one for
    /// every inserted block rather than only the eventual leaves costs
    /// nothing and avoids having to predict which one that will be.
    fn insert_block(
        store: &mut Store,
        root: Root,
        slot: Slot,
        parent_root: Root,
        validator_count: usize,
    ) {
        store.insert_beacon_block(root, &block(slot, parent_root));
        store.cache_beacon_state(root, Arc::new(state_with_validators(validator_count)));
    }

    /// Gives `validator_index`'s latest LMD GHOST vote to `root`, unconditionally.
    ///
    /// Calls `Store::set_latest_message` directly rather than going through
    /// `fork_choice::on_attestation`: these tests are about what `get_head`
    /// does with a given vote set, not about how a vote gets validated and
    /// recorded, which `ethlambda_beacon::fork_choice`'s own test suite
    /// already covers.
    fn vote_for(store: &mut Store, validator_index: u64, root: Root, epoch: u64) {
        store.set_latest_message(validator_index, fork_choice::LatestMessage { epoch, root });
    }

    #[test]
    fn the_beacon_tick_advances_the_store_in_seconds() {
        // The actor's clock is milliseconds and the beacon store's is seconds,
        // so this pins the one conversion the dispatch is responsible for.
        let config = Config::active();
        let mut store = Store::init_beacon(Arc::new(InMemoryBackend::new()), 0);

        on_tick(&mut store, 3 * config.seconds_per_slot * 1000, &config);

        assert_eq!(store.beacon_time(), 3 * config.seconds_per_slot);
    }

    #[test]
    fn the_beacon_tick_resets_the_proposer_boost_at_a_slot_boundary() {
        let config = Config::active();
        let mut store = Store::init_beacon(Arc::new(InMemoryBackend::new()), 0);
        store.set_proposer_boost_root(Root::repeat_byte(1));

        on_tick(&mut store, config.seconds_per_slot * 1000, &config);

        assert_eq!(store.proposer_boost_root(), Root::zero());
    }

    #[test]
    fn the_beacon_tick_pulls_up_justification_at_an_epoch_boundary() {
        let config = Config::active();
        let mut store = Store::init_beacon(Arc::new(InMemoryBackend::new()), 0);
        let unrealized = Checkpoint {
            epoch: 1,
            root: Root::repeat_byte(5),
        };
        store.set_beacon_unrealized_justified_checkpoint(unrealized);

        let epoch_start_seconds = preset::SLOTS_PER_EPOCH * config.seconds_per_slot;
        on_tick(&mut store, epoch_start_seconds * 1000, &config);

        assert_eq!(store.beacon_justified_checkpoint(), unrealized);
    }

    #[test]
    fn the_head_advances_to_an_imported_block_and_a_heavier_branch_overtakes_it() {
        let config = Config::active();
        let genesis_root = Root::repeat_byte(1);
        let mut store = store_with_genesis(genesis_root, 2);

        // The higher root of the two children about to compete: a naive
        // tie-break would favor this one if weight were not actually driving
        // the choice.
        let a_root = Root::repeat_byte(3);
        insert_block(&mut store, a_root, 1, genesis_root, 2);

        let first = update_head(&mut store, &config).expect("head computes");
        assert_eq!(first.root, a_root, "genesis's only child becomes head");
        assert_eq!(first.slot, 1);
        assert_eq!(
            first.previous, None,
            "nothing was computed on this store before this call"
        );
        assert_eq!(store.beacon_head(), Some((1, a_root)));

        // The lower root, but voted for. If this wins despite losing the
        // root tie-break, `get_head`'s weight computation is genuinely
        // driving the outcome rather than `update_head` merely calling
        // through to whichever child happens to sort last.
        let b_root = Root::repeat_byte(2);
        insert_block(&mut store, b_root, 1, genesis_root, 2);
        vote_for(&mut store, 0, b_root, 0);

        let second = update_head(&mut store, &config).expect("head computes");
        assert_eq!(
            second.root, b_root,
            "the voted-for branch must overtake the root tie-break"
        );
        assert_eq!(second.parent_root, genesis_root);
        assert_eq!(second.previous, Some((first.slot, first.root)));
        assert_eq!(store.beacon_head(), Some((1, b_root)));
    }

    #[test]
    fn a_reorg_is_detected_with_the_right_depth() {
        let config = Config::active();
        let genesis_root = Root::repeat_byte(1);
        let mut store = store_with_genesis(genesis_root, 3);

        let a1 = Root::repeat_byte(0xA1);
        insert_block(&mut store, a1, 1, genesis_root, 3);
        let a2 = Root::repeat_byte(0xA2);
        insert_block(&mut store, a2, 2, a1, 3);
        vote_for(&mut store, 0, a2, 0);

        let first = update_head(&mut store, &config).expect("head computes");
        assert_eq!(first.root, a2);
        assert_eq!(first.slot, 2);
        assert_eq!(
            first.reorg_depth, None,
            "the first computation has no previous head to compare against"
        );

        // A three-block branch that ends up carrying every validator's vote,
        // including validator 0's, which switches away from `a2`.
        let b1 = Root::repeat_byte(0xB1);
        insert_block(&mut store, b1, 1, genesis_root, 3);
        let b2 = Root::repeat_byte(0xB2);
        insert_block(&mut store, b2, 2, b1, 3);
        let b3 = Root::repeat_byte(0xB3);
        insert_block(&mut store, b3, 3, b2, 3);
        vote_for(&mut store, 0, b3, 0);
        vote_for(&mut store, 1, b3, 0);
        vote_for(&mut store, 2, b3, 0);

        let second = update_head(&mut store, &config).expect("head computes");
        assert_eq!(second.root, b3, "the fully-voted branch must become head");
        assert_eq!(second.previous, Some((2, a2)));
        // Walking back from b3 (slot 3) to a2's own slot (2) lands on b2,
        // which is not a2: exactly one hop off the old head's branch.
        assert_eq!(
            second.reorg_depth,
            Some(1),
            "the new head shares no ancestor with the old one within one hop"
        );
    }

    #[test]
    fn the_fork_choice_head_can_differ_from_the_highest_imported_slot() {
        // `lean_head_slot` (fed by `update_head`) and
        // `lean_sync_local_head_slot` (fed by `beacon_highest_imported_slot`)
        // must be able to disagree: a deeper import on a branch fork choice
        // does not choose must not move the reported head.
        let config = Config::active();
        let genesis_root = Root::repeat_byte(1);
        let mut store = store_with_genesis(genesis_root, 2);

        // The shallow, voted-for branch: this is what fork choice settles on.
        let a1 = Root::repeat_byte(0xA1);
        insert_block(&mut store, a1, 1, genesis_root, 2);
        let a2 = Root::repeat_byte(0xA2);
        insert_block(&mut store, a2, 2, a1, 2);
        vote_for(&mut store, 0, a2, 0);

        // The deeper, unvoted branch: it wins the raw import watermark by
        // slot alone, but must not be chosen as head.
        let b1 = Root::repeat_byte(0xB1);
        insert_block(&mut store, b1, 1, genesis_root, 2);
        let b2 = Root::repeat_byte(0xB2);
        insert_block(&mut store, b2, 2, b1, 2);
        let b3 = Root::repeat_byte(0xB3);
        insert_block(&mut store, b3, 3, b2, 2);
        let b4 = Root::repeat_byte(0xB4);
        insert_block(&mut store, b4, 4, b3, 2);

        assert_eq!(
            store.beacon_highest_imported_slot(),
            4,
            "the watermark tracks the highest slot imported, on any branch"
        );

        let update = update_head(&mut store, &config).expect("head computes");
        assert_eq!(
            update.slot, 2,
            "fork choice must settle on the voted branch, not the deeper one"
        );
        assert_ne!(
            update.slot,
            store.beacon_highest_imported_slot(),
            "lean_head_slot and lean_sync_local_head_slot must disagree here"
        );
    }
}
