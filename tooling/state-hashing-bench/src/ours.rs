//! ethlambda's tree, `ethlambda-ssz-tree`, driven the way the node's state
//! transition drives it.
//!
//! The lists are the state's own types, update buffers included (a `VecMap`
//! for balances and participation, a `BTreeMap` for validators and
//! inactivity scores). Writes are buffered and folded in by `apply_updates`,
//! except where they cover a large share of a list, as epoch processing's
//! balance rewrite does: those go through the write cursor (`iter_cow`), as
//! `try_update_balances` does. Participation rotates with `mem::take` plus
//! `List::repeat`, as `process_participation_flag_updates` does. Each list's
//! time is its clone, its writes and its root.
//!
//! The node also walks every validator through the cursor at an epoch
//! (`try_update_validators_with_balances`), because it computes each one's
//! effective balance on the way. That walk is the state transition's work,
//! not hashing, and Silver is not charged for it either, so the few epoch
//! writes to validators are buffered here.

use ethlambda_ssz_tree::{Length, ListOf, UpdateMap, Value};
use ethlambda_types::beacon::containers::{
    Balances, EpochParticipation, InactivityScores, Validators,
};
use ethlambda_types::primitives::HashTreeRoot;

use crate::format::{Root, Roots};
use crate::trace::{Initial, Step, Writes};
use crate::{Candidate, ListTimes, timed};

#[derive(Clone)]
pub struct Ours {
    validators: Validators,
    balances: Balances,
    previous: EpochParticipation,
    current: EpochParticipation,
    inactivity: InactivityScores,
    roots: Roots,
}

impl Candidate for Ours {
    fn build(initial: Initial) -> Self {
        let validators = Validators::try_from(initial.validators).expect("under the limit");
        let balances = Balances::try_from(initial.balances).expect("under the limit");
        let previous = EpochParticipation::try_from(initial.previous).expect("under the limit");
        let current = EpochParticipation::try_from(initial.current).expect("under the limit");
        let inactivity = InactivityScores::try_from(initial.inactivity).expect("under the limit");
        let roots = Roots {
            validators: root(&validators),
            balances: root(&balances),
            previous_participation: root(&previous),
            current_participation: root(&current),
            inactivity_scores: root(&inactivity),
        };
        Self {
            validators,
            balances,
            previous,
            current,
            inactivity,
            roots,
        }
    }

    fn step(&self, step: &Step, times: &mut ListTimes) -> Self {
        let (validators, validators_root) = timed(&mut times[0], || {
            let mut list = self.validators.clone();
            write(&mut list, &step.validators);
            commit(list)
        });
        let (balances, balances_root) = timed(&mut times[1], || {
            let mut list = self.balances.clone();
            write(&mut list, &step.balances);
            commit(list)
        });
        let (previous, previous_root) = timed(&mut times[2], || {
            let mut list = match step.rotation {
                // The node's rotation moves current into previous, after the
                // epoch's new validators were appended to it.
                Some(len) => {
                    let mut list = self.current.clone();
                    while list.len() < len {
                        list.push(0).expect("under the limit");
                    }
                    list
                }
                None => self.previous.clone(),
            };
            write(&mut list, &step.previous);
            commit(list)
        });
        let (current, current_root) = timed(&mut times[3], || {
            let mut list = match step.rotation {
                Some(len) => EpochParticipation::repeat(0, len).expect("under the limit"),
                None => self.current.clone(),
            };
            write(&mut list, &step.current);
            commit(list)
        });
        let (inactivity, inactivity_root) = timed(&mut times[4], || {
            let mut list = self.inactivity.clone();
            write(&mut list, &step.inactivity);
            commit(list)
        });
        Self {
            validators,
            balances,
            previous,
            current,
            inactivity,
            roots: Roots {
                validators: validators_root,
                balances: balances_root,
                previous_participation: previous_root,
                current_participation: current_root,
                inactivity_scores: inactivity_root,
            },
        }
    }

    fn roots(&self) -> Roots {
        self.roots
    }
}

fn root(list: &impl HashTreeRoot) -> Root {
    HashTreeRoot::hash_tree_root(list).0
}

/// Folds the buffered writes into the tree and hashes it, as the state
/// transition does before every state root.
fn commit<T: Value, L: Length, U: UpdateMap<T>>(
    mut list: ListOf<T, L, U>,
) -> (ListOf<T, L, U>, Root) {
    list.apply_updates();
    let root = root(&list);
    (list, root)
}

/// A rewrite of at least this share of a list goes through the cursor.
const CURSOR_SHARE: usize = 8;

/// Through the cursor when the writes cover at least `1 / CURSOR_SHARE` of the
/// list, buffered otherwise.
fn write<T: Value, L: Length, U: UpdateMap<T>>(list: &mut ListOf<T, L, U>, writes: &Writes<T>) {
    if writes.count() * CURSOR_SHARE >= list.len() {
        cursor(list, writes);
    } else {
        buffered(list, writes);
    }
}

/// One buffered write per element, then the appends.
///
/// The writes below the old length go in descending index order. The trace
/// holds them sorted, but the node's arrive unsorted (sync committee members
/// and attesters in committee order), so its first few already reach near the
/// end of the list and a `VecMap` buffer grows to full size about once.
/// Ascending order would regrow and copy it every time the highest index
/// written doubled, a cost the node does not pay.
fn buffered<T: Value, L: Length, U: UpdateMap<T>>(list: &mut ListOf<T, L, U>, writes: &Writes<T>) {
    let len = list.len();
    let split = writes
        .indices
        .partition_point(|&index| (index as usize) < len);
    let in_range = writes.indices[..split].iter().zip(&writes.values[..split]);
    for (&index, value) in in_range.rev() {
        *list.get_mut(index as usize).expect("in range") = value.clone();
    }
    for value in &writes.values[split..] {
        list.push(value.clone()).expect("under the limit");
    }
}

/// The writes below the old length through one in-order cursor pass, then the
/// appends.
fn cursor<T: Value, L: Length, U: UpdateMap<T>>(list: &mut ListOf<T, L, U>, writes: &Writes<T>) {
    let len = list.len();
    let split = writes
        .indices
        .partition_point(|&index| (index as usize) < len);
    {
        let mut pending = writes.indices[..split]
            .iter()
            .zip(&writes.values[..split])
            .peekable();
        let mut pass = list.iter_cow();
        while let Some(&(&index, value)) = pending.peek() {
            let mut element = pass.next_cow().expect("a write past the end");
            if element.index() == index as usize {
                element.set(value.clone());
                pending.next();
            }
        }
    }
    for value in &writes.values[split..] {
        list.push(value.clone()).expect("under the limit");
    }
}
