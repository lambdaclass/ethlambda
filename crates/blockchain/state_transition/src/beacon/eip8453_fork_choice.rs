//! The beacon chain's host of EIP-8453's fork choice.
//!
//! EIP-8453 ("Decoupled Consensus", `specs/_features/eip8453/fork-choice.md`
//! at consensus-specs `0f4fa3ffdd26ec083ff4dba65645d81433178413`) replaces
//! LMD-GHOST and Casper FFG with a finality gadget (FG) and an available chain
//! (AC). The protocol itself is the chain-agnostic engine in
//! `ethlambda-decoupled`; this module is what a beacon node hands it and reads
//! back:
//!
//! * the time grid: the engine counts ticks of `Δ = SLOT_DURATION_MS / 4`,
//!   and the beacon slot duration changes at heze (EIP-8198), so a tick is
//!   `4 * slot + quarter`, from the schedule-aware slot clock;
//! * what the engine reads of a block (`BlockInput`): its post-state's FG
//!   checkpoints, its parent payload status and its carried head votes;
//! * the anchor the engine starts from, including the fork transition, where
//!   the gadget starts at height 0 from Casper FFG's last finalized block;
//! * the host-side spec functions the engine leaves out:
//!   `is_finalized_ancestor`, `get_latest_attestation_committee_slot` and the
//!   execution hashes `get_confirmed_execution_block_hash` and
//!   `notify_forkchoice_updated` read.
//!
//! The shared, lockable node built on it (engine, pools, seen sets) is
//! [`crate::beacon::eip8453_node`].

use std::collections::HashMap;

use ethlambda_decoupled::params as engine_params;
use ethlambda_decoupled::{
    Anchor, BlockInput, FgCheckpoints, HeadVote, HeadVoteCommittees, Params, Store as Engine, Tick,
};
use ethlambda_storage::Store;
use ethlambda_types::decoupled as protocol;

use crate::beacon::config::Config;
use crate::beacon::containers::{BeaconState, SignedBeaconBlock};
use crate::beacon::error::{Error, Result};
use crate::beacon::fork::ForkName;
use crate::beacon::fork_choice::{self, PayloadStatus};
use crate::beacon::helpers::eip8453::{
    compute_attestation_committee_slot, compute_round_at_slot, eip8453_state,
    get_head_vote_committee,
};
use crate::beacon::preset;
use crate::beacon::primitives::{CommitteeIndex, ExecutionBlockHash, Root, Slot, ValidatorIndex};

/// `MAXIMUM_GOSSIP_CLOCK_DISPARITY`, in milliseconds.
const MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS: u64 = 500;

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/// The engine's parameters for the compiled preset: `SLOTS_PER_ROUND` (and
/// with it `TIMEOUT_DELAY_SLOTS`), and the spec's `PENDING_FINALITY_WINDOW`
/// and `SLOW_LOCK_WINDOW`.
pub fn params() -> Params {
    let mut params = Params::with_slots_per_round(preset::SLOTS_PER_ROUND);
    params.pending_finality_window = preset::PENDING_FINALITY_WINDOW as u64;
    params
}

/// A fresh engine anchored at `anchor`, with head vote committees of
/// `HEAD_VOTE_COMMITTEE_SIZE` seats recorded per slot.
pub fn new_engine(anchor: Anchor) -> Engine {
    Engine::new(
        params(),
        HeadVoteCommittees::recorded(preset::HEAD_VOTE_COMMITTEE_SIZE as u64),
        anchor,
    )
}

/// Why a configuration cannot run the engine.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TimeParametersError {
    #[error("{name} is {configured}, but the EIP-8453 fork choice runs on {expected}")]
    Mismatch {
        name: &'static str,
        configured: u64,
        expected: u64,
    },
}

/// The fork choice's three due times are compile-time constants of the
/// engine's `Δ` grid (`HEAD_VOTE_DUE_BPS`, `SUPPORT_CUTOFF_BPS`,
/// `VIEW_FREEZE_BPS` at the quarter points of a slot). A configuration naming
/// other values describes a fork choice this node does not run, so it is
/// refused rather than followed on the wrong schedule.
pub fn check_time_parameters(config: &Config) -> std::result::Result<(), TimeParametersError> {
    let pairs = [
        (
            "HEAD_VOTE_DUE_BPS",
            config.head_vote_due_bps,
            engine_params::HEAD_VOTE_DUE_BPS,
        ),
        (
            "SUPPORT_CUTOFF_BPS",
            config.support_cutoff_bps,
            engine_params::SUPPORT_CUTOFF_BPS,
        ),
        (
            "VIEW_FREEZE_BPS",
            config.view_freeze_bps,
            engine_params::VIEW_FREEZE_BPS,
        ),
    ];
    for (name, configured, expected) in pairs {
        if configured != expected {
            return Err(TimeParametersError::Mismatch {
                name,
                configured,
                expected,
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// Whether `slot` is an EIP-8453 slot under `config`'s schedule.
pub fn is_eip8453_slot(config: &Config, slot: Slot) -> bool {
    config.fork_at_epoch(slot / preset::SLOTS_PER_EPOCH) >= ForkName::Eip8453
}

/// The first EIP-8453 slot, or `None` when the fork is not scheduled.
pub fn fork_slot(config: &Config) -> Option<Slot> {
    let epoch = config.eip8453_fork_epoch;
    (epoch != crate::beacon::constants::FAR_FUTURE_EPOCH)
        .then(|| epoch.saturating_mul(preset::SLOTS_PER_EPOCH))
}

/// The engine tick containing Unix time `time_ms`: `4 * slot + quarter`, with
/// the slot and its duration from the schedule-aware slot clock. Ticks before
/// genesis are 0.
///
/// The engine's own `slot_of(t) = t / 4`, so this is the grid it expects
/// whatever the slot duration was before heze.
pub fn tick_at_ms(config: &Config, time_ms: u64) -> Tick {
    let genesis_ms = config.genesis_time_ms();
    if time_ms < genesis_ms {
        return 0;
    }
    let slot = config.slot_at_time_ms(genesis_ms, time_ms);
    let start_ms = config.time_at_slot_ms(genesis_ms, slot);
    let duration_ms = config.slot_duration_ms_at_slot(slot).max(1);
    let ticks_per_slot = engine_params::TICKS_PER_SLOT as u64;
    let quarter =
        (time_ms.saturating_sub(start_ms) * ticks_per_slot / duration_ms).min(ticks_per_slot - 1);
    (slot.saturating_mul(ticks_per_slot) + quarter) as Tick
}

/// The Unix millisecond at which `tick` starts: the inverse of
/// [`tick_at_ms`] on its grid.
pub fn tick_start_ms(config: &Config, tick: Tick) -> u64 {
    let tick = tick.max(0) as u64;
    let ticks_per_slot = engine_params::TICKS_PER_SLOT as u64;
    let slot = tick / ticks_per_slot;
    let quarter = tick % ticks_per_slot;
    let start_ms = config.time_at_slot_ms(config.genesis_time_ms(), slot);
    start_ms + quarter * config.slot_duration_ms_at_slot(slot) / ticks_per_slot
}

// ---------------------------------------------------------------------------
// What the engine reads of a block
// ---------------------------------------------------------------------------

/// The finality gadget checkpoints of an EIP-8453 post-state, as the engine
/// reads `store.block_states[root]`. A target root left empty by
/// `advance_height` stays empty: the engine fills it with the block's own
/// root, as the next `process_slot` would.
pub fn fg_checkpoints(state: &BeaconState) -> Result<FgCheckpoints> {
    let inner = eip8453_state(state, "fg_checkpoints")?;
    Ok(FgCheckpoints {
        target: inner.target_checkpoint.into(),
        justified: inner.justified_checkpoint.into(),
        finalized: inner.finalized_checkpoint.into(),
    })
}

/// The checkpoints the engine is given for a block from before the fork,
/// which has no finality gadget state: every checkpoint at height 0 on the
/// block the gadget starts from (Casper FFG's finalized block when the fork
/// choice was handed over).
///
/// fork.md starts the gadget at height 0 from that block, and the first
/// EIP-8453 state names height 1; giving the pre-fork blocks height 0 keeps
/// them viable until height 1 is justified and never makes one an FG source a
/// validator could attest from (a height-0 target is not well formed).
pub fn pre_fork_checkpoints(gadget_root: Root) -> FgCheckpoints {
    let start = protocol::HeightCheckpoint::new(0, gadget_root);
    FgCheckpoints {
        target: start,
        justified: start,
        finalized: start,
    }
}

/// The engine's view of an imported EIP-8453 block: its parent payload
/// status, its head votes with their support bits, and its post-state's
/// finality gadget checkpoints.
pub fn block_input(
    root: Root,
    block: &SignedBeaconBlock,
    parent_payload_status: PayloadStatus,
    post_state: &BeaconState,
) -> Result<BlockInput> {
    let SignedBeaconBlock::Eip8453(signed) = block else {
        return Err(Error::UnsupportedForFork {
            function: "eip8453_fork_choice::block_input",
            fork: block.fork_name(),
        });
    };
    let body = &signed.message.body;
    let head_votes = body
        .head_votes
        .iter()
        .map(|vote| HeadVote {
            voter_indices: vote.voter_indices.iter().copied().collect(),
            data: vote.data.into(),
        })
        .collect();
    let head_vote_support = body
        .head_vote_support
        .iter()
        .map(|bits| {
            (0..bits.len())
                .map(|i| bits.get(i).unwrap_or(false))
                .collect()
        })
        .collect();
    Ok(BlockInput {
        root,
        parent_root: signed.message.parent_root,
        slot: signed.message.slot,
        parent_payload_status: parent_payload_status.into(),
        head_votes,
        head_vote_support,
        fg: fg_checkpoints(post_state)?,
    })
}

/// The engine's view of a block from before the fork: no head votes, and
/// [`pre_fork_checkpoints`] for its state.
pub fn pre_fork_block_input(
    root: Root,
    parent_root: Root,
    slot: Slot,
    parent_payload_status: PayloadStatus,
    gadget_root: Root,
) -> BlockInput {
    BlockInput {
        root,
        parent_root,
        slot,
        parent_payload_status: parent_payload_status.into(),
        head_votes: Vec::new(),
        head_vote_support: Vec::new(),
        fg: pre_fork_checkpoints(gadget_root),
    }
}

/// The anchor an engine starts from: `root` at `slot`, with `state` its
/// post-state.
///
/// An EIP-8453 state's own checkpoints; `get_forkchoice_store` asserts the
/// anchor is its state's target once `process_slot` has filled the root in,
/// so a target naming any other block is refused. A pre-fork state anchors the
/// gadget at height 0 on `root` itself ([`pre_fork_checkpoints`]).
pub fn anchor(root: Root, slot: Slot, state: &BeaconState) -> Result<Anchor> {
    let fg = match state {
        BeaconState::Eip8453(_) => {
            let fg = fg_checkpoints(state)?;
            if fg.target.root != root && !fg.target.root.is_zero() {
                return Err(Error::SpecAssert(
                    "advanced_anchor_state.target_checkpoint.root == anchor_root",
                ));
            }
            fg
        }
        _ => pre_fork_checkpoints(root),
    };
    Ok(Anchor { root, slot, fg })
}

/// `get_head_vote_committee(state, slot)` as the engine records it.
pub fn head_vote_committee(
    state: &BeaconState,
    slot: Slot,
    config: &Config,
) -> Result<Vec<ValidatorIndex>> {
    Ok(get_head_vote_committee(state, slot, config)?
        .iter()
        .copied()
        .collect())
}

// ---------------------------------------------------------------------------
// Host-side spec functions
// ---------------------------------------------------------------------------

/// Where a block stands relative to the finalized block (p2p-interface.md's
/// `is_finalized_ancestor`), three ways: the walk over the store's live chain
/// can fall off a pruned row, which says nothing either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizedDescent {
    Descends,
    Conflicts,
    Unknown,
}

/// `is_finalized_ancestor(store, state, root)`: whether the finalized block of
/// `state` (the head's post-state) is an ancestor of `root`.
///
/// Two readings the specification leaves implicit:
///
/// * the gadget starts at height 0 on Casper FFG's finalized checkpoint, whose
///   root is the zero root on a chain that never finalized (and at genesis).
///   That root names the genesis block, as `get_forkchoice_store` reads the
///   genesis checkpoint, so every block descends from it;
/// * the store's own finalized block may be ahead of the head state's (the
///   store adopts the best finalization of any branch), and pruning drops the
///   live-chain rows below it. Since the head descends from the store's
///   finalized block, which descends from the head state's, descending from
///   the deeper of the two answers the question without walking pruned rows.
pub fn is_finalized_ancestor(store: &Store, state: &BeaconState, root: Root) -> FinalizedDescent {
    let Ok(inner) = eip8453_state(state, "is_finalized_ancestor") else {
        return FinalizedDescent::Unknown;
    };
    let (mut finalized_root, mut finalized_slot) =
        (inner.finalized_checkpoint.root, inner.finalized_slot);
    if let Ok(stored) = store.latest_finalized()
        && stored.slot >= finalized_slot
    {
        (finalized_root, finalized_slot) = (stored.root, stored.slot);
    }
    if finalized_root.is_zero() {
        return FinalizedDescent::Descends;
    }
    let index = store.block_index();
    descent_in(&index, root, finalized_root, finalized_slot)
}

/// [`is_finalized_ancestor`]'s walk over a prebuilt live-chain index.
pub fn descent_in(
    index: &HashMap<Root, (Slot, Root)>,
    root: Root,
    finalized_root: Root,
    finalized_slot: Slot,
) -> FinalizedDescent {
    match fork_choice::get_ancestor_or_missing(index, root, finalized_slot) {
        Ok(ancestor) if ancestor == finalized_root => FinalizedDescent::Descends,
        Ok(_) => FinalizedDescent::Conflicts,
        Err(missing) if missing == finalized_root => FinalizedDescent::Descends,
        Err(_) => FinalizedDescent::Unknown,
    }
}

/// `get_latest_attestation_committee_slot(store, committee_index,
/// current_time_ms)`: the latest slot of the committee's schedule that has
/// started, allowing for `MAXIMUM_GOSSIP_CLOCK_DISPARITY`.
pub fn get_latest_attestation_committee_slot(
    config: &Config,
    committee_index: CommitteeIndex,
    now_ms: u64,
) -> Result<Slot> {
    let genesis_ms = config.genesis_time_ms();
    let current_slot = config.slot_at_time_ms(
        genesis_ms,
        now_ms.saturating_add(MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS),
    );
    let round = compute_round_at_slot(current_slot);
    let slot = compute_attestation_committee_slot(round, committee_index)?;
    if slot > current_slot {
        return compute_attestation_committee_slot(round.saturating_sub(1), committee_index);
    }
    Ok(slot)
}

/// The execution block hash a fork-choice node stands for: a FULL node's
/// payload is its bid's `block_hash`; an EMPTY or PENDING one stands for the
/// payload it builds on, the bid's `parent_block_hash`. A block from before
/// gloas carries its payload itself (its cached execution hash).
///
/// `get_confirmed_execution_block_hash` is this of `get_confirmed_node`, and
/// `forkchoiceUpdated`'s head hash this of the head node.
pub fn node_execution_block_hash(
    store: &Store,
    node: protocol::ForkChoiceNode,
) -> Option<ExecutionBlockHash> {
    let block = store.get_signed_block(&node.root).ok().flatten()?;
    match block.payload_bid() {
        Some(signed_bid) => Some(match node.payload_status {
            protocol::PayloadStatus::Full => signed_bid.message.block_hash,
            protocol::PayloadStatus::Empty | protocol::PayloadStatus::Pending => {
                signed_bid.message.parent_block_hash
            }
        }),
        None => store.beacon_el_block_hash(node.root),
    }
}

/// `get_confirmed_execution_block_hash(store)`.
pub fn get_confirmed_execution_block_hash(
    store: &Store,
    engine: &Engine,
) -> Option<ExecutionBlockHash> {
    node_execution_block_hash(store, engine.get_confirmed_node())
}

/// The execution block hash `forkchoiceUpdated` names as finalized.
///
/// Gloas's `notify_forkchoice_updated` names a checkpoint block's
/// `parent_block_hash`, the payload it builds on, since its own payload may
/// never be revealed; EIP-8453 does not modify that. The finalized node is
/// `Pending` in the gadget's frame, which [`node_execution_block_hash`] reads
/// the same way.
pub fn finalized_execution_block_hash(
    store: &Store,
    finalized_root: Root,
) -> Option<ExecutionBlockHash> {
    node_execution_block_hash(store, protocol::ForkChoiceNode::pending(finalized_root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::helpers::test_state;

    fn quick_slots_config() -> Config {
        // Heze shortens the slot (EIP-8198), so the grid must follow the
        // schedule rather than a fixed duration.
        Config::active()
            .with_fork_epoch(ForkName::Gloas, 0)
            .with_fork_epoch(ForkName::Heze, 1)
            .with_fork_epoch(ForkName::Eip8453, 2)
    }

    #[test]
    fn ticks_are_quarters_of_each_slot_across_a_duration_change() {
        let config = quick_slots_config();
        let genesis_ms = config.genesis_time_ms();
        for slot in [
            0,
            1,
            preset::SLOTS_PER_EPOCH,
            3 * preset::SLOTS_PER_EPOCH + 5,
        ] {
            let start = config.time_at_slot_ms(genesis_ms, slot);
            let duration = config.slot_duration_ms_at_slot(slot);
            for quarter in 0..4u64 {
                let at = start + quarter * duration / 4;
                let tick = tick_at_ms(&config, at);
                assert_eq!(tick, (4 * slot + quarter) as Tick, "slot {slot} q{quarter}");
                assert_eq!(tick_start_ms(&config, tick), at);
                // The instant before the next quarter is still this tick.
                let before_next = start + (quarter + 1) * duration / 4 - 1;
                assert_eq!(tick_at_ms(&config, before_next), tick);
            }
        }
        assert_eq!(tick_at_ms(&config, genesis_ms.saturating_sub(1)), 0);
    }

    #[test]
    fn the_spec_due_times_pass_and_others_are_refused() {
        let config = Config::active();
        assert_eq!(check_time_parameters(&config), Ok(()));
        let mut moved = config.clone();
        moved.support_cutoff_bps = 4_000;
        assert!(matches!(
            check_time_parameters(&moved),
            Err(TimeParametersError::Mismatch {
                name: "SUPPORT_CUTOFF_BPS",
                ..
            })
        ));
    }

    #[test]
    fn a_pre_fork_anchor_starts_the_gadget_at_height_zero_on_itself() {
        let state = test_state::with_validators_at(ForkName::Heze, 4);
        let root = Root::repeat_byte(1);
        let anchor = anchor(root, 7, &state).unwrap();
        assert_eq!(anchor.fg, pre_fork_checkpoints(root));
        assert_eq!(anchor.fg.target.height, 0);
    }

    #[test]
    fn an_eip8453_anchor_must_be_its_own_target() {
        let mut state = test_state::with_validators_at(ForkName::Eip8453, 4);
        let root = Root::repeat_byte(2);
        let BeaconState::Eip8453(inner) = &mut state else {
            unreachable!()
        };
        inner.target_checkpoint.root = Root::ZERO;
        // An empty target root is filled with the anchor by `process_slot`.
        assert!(anchor(root, 9, &state).is_ok());
        let BeaconState::Eip8453(inner) = &mut state else {
            unreachable!()
        };
        inner.target_checkpoint.root = root;
        let fg = anchor(root, 9, &state).unwrap().fg;
        assert_eq!(fg.target.root, root);
        let BeaconState::Eip8453(inner) = &mut state else {
            unreachable!()
        };
        inner.target_checkpoint.root = Root::repeat_byte(3);
        assert!(anchor(root, 9, &state).is_err());
    }

    #[test]
    fn a_blocks_head_votes_and_checkpoints_reach_the_engine_input() {
        use crate::beacon::containers::eip8453;
        let mut state = test_state::with_validators_at(ForkName::Eip8453, 4);
        let BeaconState::Eip8453(inner) = &mut state else {
            unreachable!()
        };
        inner.justified_checkpoint = eip8453::HeightCheckpoint {
            height: 2,
            root: Root::repeat_byte(4),
        };
        let mut block = eip8453::SignedBeaconBlock::default();
        block.message.slot = 12;
        block.message.parent_root = Root::repeat_byte(5);
        let vote = eip8453::HeadVote {
            voter_indices: vec![1, 3].try_into().unwrap(),
            data: eip8453::HeadVoteData {
                slot: 11,
                beacon_block_root: Root::repeat_byte(5),
                payload_status: 1,
            },
            signature: Default::default(),
        };
        block.message.body.head_votes = vec![vote].into();
        let mut bits = eip8453::HeadVoteSupportBits::default();
        bits.push(true);
        bits.push(false);
        block.message.body.head_vote_support = vec![bits].into();
        let root = Root::repeat_byte(6);
        let input = block_input(
            root,
            &SignedBeaconBlock::Eip8453(block),
            PayloadStatus::Full,
            &state,
        )
        .unwrap();
        assert_eq!(input.root, root);
        assert_eq!(input.slot, 12);
        assert_eq!(input.parent_root, Root::repeat_byte(5));
        assert_eq!(input.parent_payload_status, protocol::PayloadStatus::Full);
        assert_eq!(input.head_votes.len(), 1);
        assert_eq!(input.head_votes[0].voter_indices, vec![1, 3]);
        assert_eq!(input.head_votes[0].data.block_root, Root::repeat_byte(5));
        assert_eq!(input.head_vote_support, vec![vec![true, false]]);
        assert_eq!(input.fg.justified.height, 2);
        assert_eq!(input.fg.justified.root, Root::repeat_byte(4));
    }

    #[test]
    fn descent_names_the_ancestor_at_the_finalized_slot() {
        // 1 <- 2 <- 3 and 1 <- 4, at slots 1..=4.
        let r = Root::repeat_byte;
        let index: HashMap<Root, (Slot, Root)> = [
            (r(1), (1, r(0))),
            (r(2), (2, r(1))),
            (r(3), (3, r(2))),
            (r(4), (4, r(1))),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            descent_in(&index, r(3), r(2), 2),
            FinalizedDescent::Descends
        );
        assert_eq!(
            descent_in(&index, r(4), r(2), 2),
            FinalizedDescent::Conflicts
        );
        // Falling off at the finalized root itself is a descent; anywhere
        // else is unknown.
        assert_eq!(
            descent_in(&index, r(3), r(0), 0),
            FinalizedDescent::Descends
        );
        assert_eq!(descent_in(&index, r(9), r(2), 2), FinalizedDescent::Unknown);
    }

    #[test]
    fn the_latest_committee_slot_is_the_last_one_that_started() {
        let config = Config::active();
        let genesis_ms = config.genesis_time_ms();
        let per_slot = preset::ATTESTATION_COMMITTEES_PER_ROUND as u64 / preset::SLOTS_PER_ROUND;
        let round = 3;
        let round_start = round * preset::SLOTS_PER_ROUND;
        // The last committee of the round attests in the round's last slot.
        let last_committee = preset::ATTESTATION_COMMITTEES_PER_ROUND as u64 - 1;
        let at = config.time_at_slot_ms(genesis_ms, round_start + 1);
        // Its slot this round has not started: the previous round's.
        assert_eq!(
            get_latest_attestation_committee_slot(&config, last_committee, at).unwrap(),
            round_start - 1
        );
        // The first committee's slot has.
        assert_eq!(
            get_latest_attestation_committee_slot(&config, 0, at).unwrap(),
            round_start
        );
        // A committee of the next slot within the clock disparity counts.
        let next_slot_start = config.time_at_slot_ms(genesis_ms, round_start + 2);
        assert_eq!(
            get_latest_attestation_committee_slot(&config, 2 * per_slot, next_slot_start - 100)
                .unwrap(),
            round_start + 2
        );
    }
}
