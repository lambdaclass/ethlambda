//! Unit tests of the fork choice's spec functions on hand-built trees.
//!
//! Blocks carry hand-picked finality gadget checkpoints, so a test controls
//! heights and justifications directly; votes enter through
//! `on_head_vote_message`. Times are ticks: slot `s` starts at `4s`, its head
//! vote deadline is `4s + 1`, its support cutoff `4s + 2`.

use ethlambda_types::primitives::H256;

use crate::params::{Params, head_vote_due, slot_start, support_cutoff};
use crate::store::{BlockError, CommitteeError, HeadVoteError, Store};
use crate::types::{
    Anchor, BlockInput, FgCheckpoints, ForkChoiceNode, HeadVoteCommittees, HeadVoteData,
    HeadVoteMessage, HeightCheckpoint, PayloadStatus, Slot, Tick, ValidatorIndex,
};

const G: H256 = H256([0x10; 32]);

fn root(byte: u8) -> H256 {
    H256([byte; 32])
}

fn pending(byte: u8) -> ForkChoiceNode {
    ForkChoiceNode::pending(root(byte))
}

fn empty(byte: u8) -> ForkChoiceNode {
    ForkChoiceNode::empty(root(byte))
}

fn cp(height: u64, root: H256) -> HeightCheckpoint {
    HeightCheckpoint::new(height, root)
}

fn genesis_fg() -> FgCheckpoints {
    FgCheckpoints {
        target: cp(1, G),
        justified: cp(0, G),
        finalized: cp(0, G),
    }
}

fn store_with(committees: HeadVoteCommittees) -> Store {
    let anchor = Anchor {
        root: G,
        slot: 0,
        fg: genesis_fg(),
    };
    let mut store = Store::new(Params::minimal(), committees, anchor);
    store.advance_to(0);
    store
}

/// Four validators with one seat each in every committee.
fn store() -> Store {
    store_with(HeadVoteCommittees::EveryValidator { validator_count: 4 })
}

fn input(byte: u8, parent: H256, slot: Slot, fg: FgCheckpoints) -> BlockInput {
    BlockInput {
        root: root(byte),
        parent_root: parent,
        slot,
        parent_payload_status: PayloadStatus::Empty,
        head_votes: Vec::new(),
        head_vote_support: Vec::new(),
        fg,
    }
}

/// A block building on its parent's `Empty` branch with its parent's
/// checkpoints (no height event).
fn add(store: &mut Store, byte: u8, parent: H256, slot: Slot) -> H256 {
    let fg = store.block_checkpoints(&parent).expect("parent held");
    store
        .on_block(&input(byte, parent, slot, fg))
        .expect("block admitted");
    root(byte)
}

fn add_with(store: &mut Store, byte: u8, parent: H256, slot: Slot, fg: FgCheckpoints) -> H256 {
    store
        .on_block(&input(byte, parent, slot, fg))
        .expect("block admitted");
    root(byte)
}

fn vote(
    store: &mut Store,
    validator: ValidatorIndex,
    slot: Slot,
    node: ForkChoiceNode,
) -> Result<(), HeadVoteError> {
    store.on_head_vote_message(HeadVoteMessage {
        validator_index: validator,
        data: HeadVoteData::new(slot, node),
    })
}

fn at(store: &mut Store, t: Tick) {
    store.advance_to(t);
}

// ── Handlers ───────────────────────────────────────────────────────────────

#[test]
fn on_block_admits_only_what_the_spec_admits() {
    let mut store = store();
    // Future slot.
    assert_eq!(
        store.on_block(&input(1, G, 1, genesis_fg())),
        Err(BlockError::FutureSlot {
            slot: 1,
            current: 0
        })
    );
    at(&mut store, slot_start(1));
    assert_eq!(
        store.on_block(&input(1, root(9), 1, genesis_fg())),
        Err(BlockError::UnknownParent(root(9)))
    );
    let mut full_parent = input(1, G, 1, genesis_fg());
    full_parent.parent_payload_status = PayloadStatus::Full;
    assert_eq!(
        store.on_block(&full_parent),
        Err(BlockError::ParentPayloadNotVerified)
    );
    full_parent.parent_payload_status = PayloadStatus::Pending;
    assert_eq!(
        store.on_block(&full_parent),
        Err(BlockError::PendingParentStatus)
    );
    let mut malformed = input(1, G, 1, genesis_fg());
    malformed.head_vote_support = vec![vec![true]];
    assert_eq!(
        store.on_block(&malformed),
        Err(BlockError::MalformedSupport)
    );
    add(&mut store, 1, G, 1);
    assert_eq!(
        store.on_block(&input(1, G, 1, genesis_fg())),
        Err(BlockError::Duplicate)
    );
    assert_eq!(
        store.on_block(&input(2, root(1), 1, genesis_fg())),
        Err(BlockError::SlotNotAfterParent {
            slot: 1,
            parent_slot: 1
        })
    );
}

#[test]
fn a_target_entered_by_the_block_is_filled_with_its_root() {
    let mut store = store();
    at(&mut store, slot_start(1));
    let fg = FgCheckpoints {
        target: cp(2, H256::ZERO),
        ..genesis_fg()
    };
    let a = add_with(&mut store, 1, G, 1, fg);
    assert_eq!(store.block_checkpoints(&a).unwrap().target, cp(2, a));
    assert_eq!(store.max_height(), 2);
}

#[test]
fn on_head_vote_message_takes_the_previous_and_current_slots_once() {
    let mut store = store();
    at(&mut store, slot_start(3));
    let a = ForkChoiceNode::empty(G);
    assert_eq!(
        vote(&mut store, 0, 1, a),
        Err(HeadVoteError::WrongSlot { slot: 1 })
    );
    assert_eq!(
        vote(&mut store, 0, 4, a),
        Err(HeadVoteError::WrongSlot { slot: 4 })
    );
    assert_eq!(vote(&mut store, 0, 2, a), Ok(()));
    assert_eq!(vote(&mut store, 0, 2, a), Err(HeadVoteError::Duplicate));
    assert_eq!(vote(&mut store, 0, 3, a), Ok(()));
    assert_eq!(
        vote(&mut store, 9, 3, a),
        Err(HeadVoteError::NotInCommittee {
            slot: 3,
            validator: 9
        })
    );
    let bad_status = HeadVoteMessage {
        validator_index: 1,
        data: HeadVoteData {
            slot: 3,
            block_root: G,
            payload_status: 7,
        },
    };
    assert_eq!(
        store.on_head_vote_message(bad_status),
        Err(HeadVoteError::InvalidPayloadStatus(7))
    );
}

#[test]
fn recorded_committees_weigh_votes_by_seats() {
    let mut store = store_with(HeadVoteCommittees::recorded(4));
    at(&mut store, slot_start(1));
    let a = add(&mut store, 1, G, 1);
    let b = add(&mut store, 2, G, 1);
    at(&mut store, head_vote_due(1));
    // Validator 0 holds three of the four seats.
    assert_eq!(
        vote(&mut store, 0, 1, ForkChoiceNode::pending(a)),
        Err(HeadVoteError::UnknownCommittee(1))
    );
    store
        .record_head_vote_committee(1, vec![0, 0, 0, 1])
        .unwrap();
    assert_eq!(
        store.record_head_vote_committee(1, vec![0, 1, 2, 3]),
        Err(CommitteeError::Mismatch(1))
    );
    assert_eq!(
        vote(&mut store, 2, 1, ForkChoiceNode::pending(a)),
        Err(HeadVoteError::NotInCommittee {
            slot: 1,
            validator: 2
        })
    );
    // The greater root would win a tie of one seat each; three seats win.
    assert!(b > a);
    vote(&mut store, 0, 1, ForkChoiceNode::pending(a)).unwrap();
    vote(&mut store, 1, 1, ForkChoiceNode::pending(b)).unwrap();
    at(&mut store, slot_start(2));
    assert_eq!(store.get_ac_proposal().head, ForkChoiceNode::empty(a));

    let mut uniform = store_with(HeadVoteCommittees::EveryValidator { validator_count: 4 });
    assert_eq!(
        uniform.record_head_vote_committee(1, vec![0]),
        Err(CommitteeError::NotRecorded)
    );
}

// ── The head ───────────────────────────────────────────────────────────────

#[test]
fn get_head_reads_the_current_slot_from_its_support_cutoff() {
    let mut store = store();
    at(&mut store, slot_start(1));
    let a = add(&mut store, 1, G, 1);
    let b = add(&mut store, 2, G, 1);
    at(&mut store, head_vote_due(2));
    // Slot 1: three for A. Slot 2: three for B (an earlier block, so `Empty`).
    for v in 0..3 {
        vote(&mut store, v, 1, ForkChoiceNode::pending(a)).unwrap();
        vote(&mut store, v, 2, ForkChoiceNode::empty(b)).unwrap();
    }
    vote(&mut store, 3, 1, ForkChoiceNode::pending(b)).unwrap();
    vote(&mut store, 3, 2, ForkChoiceNode::empty(a)).unwrap();
    // Before the cutoff: the previous slot's votes.
    assert_eq!(store.get_head(), ForkChoiceNode::empty(a));
    at(&mut store, support_cutoff(2));
    assert_eq!(store.get_head(), ForkChoiceNode::empty(b));
}

#[test]
fn the_genesis_slot_head_is_the_finalized_block() {
    let store = store();
    assert_eq!(store.get_head(), ForkChoiceNode::empty(G));
}

// ── Confirmation and locks ─────────────────────────────────────────────────

/// G ← A (slot 1), with slot-1 votes for A from `voters`, run to slot 2's
/// support cutoff, which confirms slot 1.
fn confirm_one(voters: std::ops::Range<u64>) -> Store {
    let mut store = store();
    at(&mut store, slot_start(1));
    let a = add(&mut store, 1, G, 1);
    at(&mut store, head_vote_due(1));
    for v in voters {
        vote(&mut store, v, 1, ForkChoiceNode::pending(a)).unwrap();
    }
    at(&mut store, support_cutoff(2));
    store
}

#[test]
fn a_confirmation_with_half_of_all_seats_takes_a_fast_lock() {
    // Two of four seats: eligible (4 > 2 participating) and exactly half of
    // all seats, which the fast test admits.
    let store = confirm_one(0..2);
    let params = store.params();
    assert_eq!(store.latest_confirmed(), pending(1));
    assert_eq!(store.saved_confirmations().get(&1), Some(&pending(1)));
    assert!(store.fast_confirmed_path().contains(&pending(1)));
    assert_eq!(
        store.locks().get(&params.lock_deadline(1)),
        Some(&pending(1))
    );
    // The genesis block is never on the fast path.
    assert_eq!(store.fast_confirmed_path().len(), 1);
}

#[test]
fn a_confirmation_short_of_half_the_seats_takes_no_fast_lock() {
    // One of four: a majority of the participants confirms, but the fast test
    // needs half of all seats.
    let store = confirm_one(0..1);
    assert_eq!(store.latest_confirmed(), pending(1));
    assert_eq!(store.saved_confirmations().get(&1), Some(&pending(1)));
    assert!(store.fast_confirmed_path().is_empty());
    assert!(store.locks().is_empty());
}

#[test]
fn votes_resolved_after_the_support_cutoff_do_not_confirm() {
    let mut store = store();
    at(&mut store, slot_start(1));
    let a = add(&mut store, 1, G, 1);
    at(&mut store, support_cutoff(1));
    for v in 0..4 {
        vote(&mut store, v, 1, ForkChoiceNode::pending(a)).unwrap();
    }
    at(&mut store, support_cutoff(2));
    assert!(store.saved_confirmations().is_empty());
    assert_eq!(store.latest_confirmed(), ForkChoiceNode::pending(G));
}

#[test]
fn a_live_lock_vetoes_a_conflicting_confirmation_which_is_still_saved() {
    let mut store = store();
    at(&mut store, slot_start(1));
    let a = add(&mut store, 1, G, 1);
    at(&mut store, head_vote_due(1));
    for v in 0..4 {
        vote(&mut store, v, 1, ForkChoiceNode::pending(a)).unwrap();
    }
    // B conflicts with A. One vote for it, before slot 2's support cutoff,
    // confirms it among the participants but opposes A with too few seats to
    // unlock it.
    at(&mut store, slot_start(2));
    let b = add(&mut store, 2, G, 2);
    at(&mut store, head_vote_due(2));
    vote(&mut store, 0, 2, ForkChoiceNode::pending(b)).unwrap();
    // Slot 1's confirmation locks A.
    at(&mut store, support_cutoff(2));
    assert_eq!(store.latest_confirmed(), pending(1));
    at(&mut store, support_cutoff(3));
    assert_eq!(store.saved_confirmations().get(&2), Some(&pending(2)));
    assert!(store.fast_confirmed_path().is_empty());
    assert_eq!(store.latest_confirmed(), pending(1), "the veto keeps it");
    assert!(store.locks().values().all(|lock| *lock == pending(1)));
}

#[test]
fn unlock_moves_an_opposed_lock_to_its_deepest_unopposed_ancestor() {
    let mut store = store();
    at(&mut store, slot_start(1));
    let a1 = add(&mut store, 1, G, 1);
    at(&mut store, head_vote_due(1));
    for v in 0..4 {
        vote(&mut store, v, 1, ForkChoiceNode::pending(a1)).unwrap();
    }
    at(&mut store, slot_start(2));
    let a2 = add(&mut store, 2, a1, 2);
    at(&mut store, head_vote_due(2));
    for v in 0..4 {
        vote(&mut store, v, 2, ForkChoiceNode::pending(a2)).unwrap();
    }
    // B forks off A1's empty branch. Half of all seats vote for it.
    at(&mut store, slot_start(3));
    let b = add(&mut store, 3, a1, 3);
    at(&mut store, head_vote_due(3));
    vote(&mut store, 0, 3, ForkChoiceNode::pending(b)).unwrap();
    vote(&mut store, 1, 3, ForkChoiceNode::pending(b)).unwrap();
    // Slot 2's confirmation locks A2.
    at(&mut store, support_cutoff(3));
    let deadline = store.params().lock_deadline(2);
    assert_eq!(store.locks().get(&deadline), Some(&pending(2)));
    // Slot 3's votes oppose A2 with half the seats; A1's empty node is on
    // B's chain and unopposed.
    at(&mut store, head_vote_due(4));
    assert_eq!(
        store.locks().get(&deadline),
        Some(&empty(1)),
        "deadline kept"
    );
    // The lock of slot 1 is compatible with B and stays.
    assert_eq!(
        store.locks().get(&store.params().lock_deadline(1)),
        Some(&pending(1))
    );
}

#[test]
fn locks_anchor_the_head_walk_until_they_expire() {
    let mut store = confirm_one(0..4);
    let deadline = store.params().lock_deadline(1);
    // B conflicts with the locked A; slot-2 votes for it come after slot 2's
    // support cutoff, so they neither confirm nor (one vote) unlock.
    let b = add(&mut store, 2, G, 2);
    at(&mut store, support_cutoff(2) + 1);
    vote(&mut store, 0, 2, ForkChoiceNode::pending(b)).unwrap();
    at(&mut store, slot_start(3));
    // The walk starts at the lock, so B is out of reach.
    assert_eq!(store.get_head(), ForkChoiceNode::empty(root(1)));
    at(&mut store, deadline);
    assert!(
        store.live_locks().is_empty(),
        "a lock is live strictly before its deadline"
    );
}

#[test]
fn a_slow_lock_needs_a_saved_confirmation_for_every_slot_of_the_window() {
    // One voter of four per slot: confirmations without fast locks.
    let run = |skip: Option<Slot>| {
        let mut store = store();
        let mut parent = G;
        for slot in 1..=4u64 {
            at(&mut store, slot_start(slot));
            parent = add(&mut store, slot as u8, parent, slot);
            at(&mut store, head_vote_due(slot));
            if Some(slot) != skip {
                vote(&mut store, 0, slot, ForkChoiceNode::pending(parent)).unwrap();
            }
        }
        at(&mut store, support_cutoff(4));
        // Slot 3's confirmation: slot 0 has no saved confirmation.
        assert!(store.locks().is_empty());
        at(&mut store, support_cutoff(5));
        store
    };
    let store = run(None);
    let params = *store.params();
    assert!(store.fast_confirmed_path().is_empty());
    // Under the saved confirmations of slots 1, 2 and 3 and the candidate of
    // slot 4: the deepest is A1.
    assert_eq!(
        store.locks().get(&params.lock_deadline(4)),
        Some(&pending(1))
    );
    let store = run(Some(2));
    assert!(
        store.locks().is_empty(),
        "slot 2 saved nothing, so slot 4 has no slow lock"
    );
}

#[test]
fn get_confirmed_node_falls_back_to_the_finalized_node() {
    let mut store = store();
    // Nothing confirmed yet: latest_confirmed is the finalized node.
    at(&mut store, slot_start(1));
    assert_eq!(store.get_confirmed_node(), ForkChoiceNode::pending(G));

    let mut store = confirm_one(0..4);
    assert_eq!(store.get_confirmed_node(), pending(1));
    // B conflicts with A. Its votes arrive after slot 2's support cutoff: they
    // do not confirm it, but unlock and the head read every resolved vote.
    let b = add(&mut store, 2, G, 2);
    at(&mut store, support_cutoff(2) + 1);
    for v in 0..4 {
        vote(&mut store, v, 2, ForkChoiceNode::pending(b)).unwrap();
    }
    at(&mut store, head_vote_due(3));
    assert_eq!(store.latest_confirmed(), pending(1));
    assert_eq!(store.get_head(), ForkChoiceNode::empty(b));
    assert_eq!(store.get_confirmed_node(), ForkChoiceNode::pending(G));
}

// ── The finality gadget's frame ────────────────────────────────────────────

/// G ← X (enters height 2) ← Y (justifies X, enters height 3).
fn justified_chain() -> (Store, H256, H256) {
    let mut store = store();
    at(&mut store, slot_start(1));
    let x = add_with(
        &mut store,
        1,
        G,
        1,
        FgCheckpoints {
            target: cp(2, root(1)),
            justified: cp(1, G),
            finalized: cp(0, G),
        },
    );
    at(&mut store, slot_start(2));
    let y = add_with(
        &mut store,
        2,
        x,
        2,
        FgCheckpoints {
            target: cp(3, root(2)),
            justified: cp(2, x),
            finalized: cp(0, G),
        },
    );
    (store, x, y)
}

#[test]
fn update_finality_adopts_greater_justifications_and_viable_finalizations() {
    let (mut store, x, y) = justified_chain();
    assert_eq!(store.max_height(), 3);
    assert_eq!(store.justified_checkpoint(), cp(2, x));
    assert_eq!(store.finalized_checkpoint(), cp(1, G));
    // A chain state finalizing X with Y justified: X strictly descends from
    // the finalized block, is under the justified one and has viable blocks.
    at(&mut store, slot_start(3));
    add_with(
        &mut store,
        3,
        y,
        3,
        FgCheckpoints {
            target: cp(3, root(2)),
            justified: cp(2, x),
            finalized: cp(2, x),
        },
    );
    assert_eq!(store.finalized_checkpoint(), cp(2, x));
    // A lower justification never replaces a higher one.
    at(&mut store, slot_start(4));
    add_with(
        &mut store,
        4,
        root(3),
        4,
        FgCheckpoints {
            target: cp(3, root(2)),
            justified: cp(1, G),
            finalized: cp(0, G),
        },
    );
    assert_eq!(store.justified_checkpoint(), cp(2, x));
}

#[test]
fn the_frame_roots_at_the_justification_when_it_is_the_latest_height() {
    let (store, x, y) = justified_chain();
    assert!(!store.is_fg_contest());
    let frame = store.get_fg_frame();
    assert_eq!(frame.finalized_node, ForkChoiceNode::pending(G));
    assert_eq!(frame.forkchoice_root, ForkChoiceNode::pending(x));
    // Height floor max_height − 1 = 2: X and Y are viable, G (height 1) is
    // not under the root anyway.
    assert!(frame.viable_heads.contains(&ForkChoiceNode::pending(x)));
    assert!(frame.viable_heads.contains(&ForkChoiceNode::empty(y)));
    assert!(!frame.viable_heads.contains(&ForkChoiceNode::pending(G)));
}

#[test]
fn an_fg_contest_roots_the_frame_at_the_finalized_block_and_raises_the_floor() {
    let (mut store, x, y) = justified_chain();
    // Z conflicts with the justified X but reaches the maximum height.
    let z = add_with(
        &mut store,
        3,
        G,
        2,
        FgCheckpoints {
            target: cp(3, root(3)),
            justified: cp(1, G),
            finalized: cp(0, G),
        },
    );
    assert!(store.is_fg_contest());
    let frame = store.get_fg_frame();
    assert_eq!(frame.forkchoice_root, ForkChoiceNode::pending(G));
    // The floor is max_height itself: X (height 2) drops out, Y and Z stay.
    assert!(!frame.viable_heads.contains(&ForkChoiceNode::pending(x)));
    assert!(frame.viable_heads.contains(&ForkChoiceNode::pending(y)));
    assert!(frame.viable_heads.contains(&ForkChoiceNode::pending(z)));
    // A height beyond the justified one + 1 ends the contest.
    at(&mut store, slot_start(3));
    add_with(
        &mut store,
        4,
        y,
        3,
        FgCheckpoints {
            target: cp(5, root(4)),
            justified: cp(2, x),
            finalized: cp(0, G),
        },
    );
    assert!(!store.is_fg_contest());
}

#[test]
fn the_viable_subtree_keeps_only_ancestors_of_viable_heads() {
    let (mut store, x, y) = justified_chain();
    // W stays at height 1 under G: below the floor, and not under the root.
    let w = add(&mut store, 5, G, 2);
    let frame = store.get_fg_frame();
    let viable = store.get_viable_subtree(&frame, &frame.tree);
    assert!(viable.contains(&ForkChoiceNode::pending(x)));
    assert!(viable.contains(&ForkChoiceNode::empty(y)));
    assert!(!viable.contains(&ForkChoiceNode::pending(w)));
    assert!(!viable.contains(&ForkChoiceNode::pending(G)));
}

#[test]
fn finality_prunes_conflicting_branches_at_the_next_slot() {
    let (mut store, x, y) = justified_chain();
    let w = add(&mut store, 5, G, 2);
    at(&mut store, slot_start(3));
    add_with(
        &mut store,
        3,
        y,
        3,
        FgCheckpoints {
            target: cp(3, root(2)),
            justified: cp(2, x),
            finalized: cp(2, x),
        },
    );
    // Still held for the rest of the slot.
    assert!(store.contains(&w));
    at(&mut store, slot_start(4));
    assert!(!store.contains(&w));
    assert!(
        !store.contains(&G),
        "ancestors of F are remembered by root only"
    );
    assert_eq!(
        store.on_block(&input(6, G, 4, genesis_fg())),
        Err(BlockError::NotDescendantOfFinalized)
    );
    assert_eq!(
        store.on_block(&input(7, w, 4, genesis_fg())),
        Err(BlockError::UnknownParent(w))
    );
}

// ── Payloads ───────────────────────────────────────────────────────────────

#[test]
fn a_verified_payload_adds_a_full_branch_the_proposer_extends() {
    let build = |satisfied: bool| {
        let mut store = store();
        at(&mut store, slot_start(1));
        let a = add(&mut store, 1, G, 1);
        at(&mut store, head_vote_due(1));
        for v in 0..4 {
            vote(&mut store, v, 1, ForkChoiceNode::pending(a)).unwrap();
        }
        store.on_execution_payload_envelope(&a, satisfied).unwrap();
        at(&mut store, slot_start(2));
        store
    };
    // Same score for both branches of the previous slot's block: the
    // tiebreaker extends a payload satisfying the inclusion list.
    assert_eq!(
        build(true).get_ac_proposal().head,
        ForkChoiceNode::full(root(1))
    );
    assert_eq!(build(false).get_ac_proposal().head, empty(1));

    let mut store = build(true);
    // A block on the full branch hangs under the full node.
    let mut child = input(2, root(1), 2, genesis_fg());
    child.parent_payload_status = PayloadStatus::Full;
    store.on_block(&child).unwrap();
    assert!(store.is_ancestor(&pending(2), &ForkChoiceNode::full(root(1))));
    assert!(!store.is_ancestor(&pending(2), &empty(1)));
    assert!(!store.is_compatible(&pending(2), &empty(1)));
    assert!(store.is_compatible(&pending(2), &pending(1)));
}

#[test]
fn a_full_vote_resolves_only_once_the_payload_is_verified() {
    let mut store = store();
    at(&mut store, slot_start(1));
    let a = add(&mut store, 1, G, 1);
    at(&mut store, slot_start(2));
    let full = ForkChoiceNode::full(a);
    assert_eq!(store.get_vote_resolution_time(&full, 2, 9), Tick::MAX);
    // A vote of the block's own slot must be pending.
    assert_eq!(
        store.get_vote_resolution_time(&ForkChoiceNode::empty(a), 1, 5),
        Tick::MAX
    );
    assert_eq!(
        store.get_vote_resolution_time(&ForkChoiceNode::pending(a), 1, 5),
        5
    );
    at(&mut store, slot_start(2) + 1);
    store.on_execution_payload_envelope(&a, true).unwrap();
    // The later of the vote, the block and the payload.
    assert_eq!(
        store.get_vote_resolution_time(&full, 2, 8),
        slot_start(2) + 1
    );
    assert_eq!(store.get_vote_resolution_time(&full, 2, 11), 11);
}
