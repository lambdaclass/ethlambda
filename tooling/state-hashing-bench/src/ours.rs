//! ethlambda's tree, `ethlambda-ssz-tree`, driven the way the node's state
//! transition drives it.
//!
//! The lists are the state's own types, update buffers included (a
//! `SparseMap` for balances and participation, a `BTreeMap` for validators and
//! inactivity scores). Writes are buffered and folded in by `apply_updates`,
//! as block processing does, except where they cover a large share of a list:
//! the epoch's balance rewrite goes through the write cursor (`iter_cow`), as
//! fulu's epoch pass (`single_pass::write_back`) does. Participation rotates
//! with `mem::take` plus `List::repeat`, as `process_participation_flag_updates`
//! does. Each list's time is its clone, its writes and its root.
//!
//! `Ours` is generic over how the two participation lists are kept: the
//! state's own tree (`EpochParticipation`), or a [`FlatList`], every Merkle
//! level kept flat as Silver keeps its lists.

use ethlambda_ssz_tree::{FlatList, Length, ListOf, UpdateMap, Value};
use ethlambda_types::beacon::containers::{
    Balances, EpochParticipation, InactivityScores, Validators,
};
use ethlambda_types::primitives::HashTreeRoot;

use crate::format::{Root, Roots};
use crate::trace::{Initial, Step, Writes};
use crate::{Candidate, ListTimes, timed};

/// How the participation lists are kept.
pub trait Participation: Clone + Send + Sync + 'static {
    fn build(values: Vec<u8>) -> (Self, Root);
    /// Next epoch's previous participation: `current`, grown to `len` with
    /// the epoch's new validators.
    fn rotated(current: &Self, len: usize) -> Self;
    /// Next epoch's current participation: `len` zeros.
    fn zeros(len: usize) -> Self;
    fn write_and_commit(self, writes: &Writes<u8>) -> (Self, Root);
}

impl Participation for EpochParticipation {
    fn build(values: Vec<u8>) -> (Self, Root) {
        let list = Self::try_from(values).expect("under the limit");
        let root = root(&list);
        (list, root)
    }

    fn rotated(current: &Self, len: usize) -> Self {
        let mut list = current.clone();
        while list.len() < len {
            list.push(0).expect("under the limit");
        }
        list
    }

    fn zeros(len: usize) -> Self {
        Self::repeat(0, len).expect("under the limit")
    }

    fn write_and_commit(mut self, writes: &Writes<u8>) -> (Self, Root) {
        write(&mut self, writes);
        commit(self)
    }
}

/// The participation flags in a [`FlatList`], with the state's bound.
pub type FlatParticipation = FlatList<u8, { 1 << 40 }>;

impl Participation for FlatParticipation {
    fn build(values: Vec<u8>) -> (Self, Root) {
        let mut list = Self::try_from(values).expect("under the limit");
        let root = list.commit();
        (list, root)
    }

    fn rotated(current: &Self, len: usize) -> Self {
        let mut list = current.clone();
        while list.len() < len {
            list.push(0).expect("under the limit");
        }
        list
    }

    fn zeros(len: usize) -> Self {
        Self::zeros(len).expect("under the limit")
    }

    /// Writes go straight into the pages: a flat list has no buffer.
    fn write_and_commit(mut self, writes: &Writes<u8>) -> (Self, Root) {
        let len = self.len();
        for (&index, &value) in writes.indices.iter().zip(&writes.values) {
            let index = index as usize;
            if index < len {
                self.set(index, value);
            } else {
                self.push(value).expect("under the limit");
            }
        }
        let root = self.commit();
        (self, root)
    }
}

#[derive(Clone)]
pub struct Ours<P = EpochParticipation> {
    validators: Validators,
    balances: Balances,
    previous: P,
    current: P,
    inactivity: InactivityScores,
    roots: Roots,
}

impl<P: Participation> Candidate for Ours<P> {
    fn build(initial: Initial) -> Self {
        let validators = Validators::try_from(initial.validators).expect("under the limit");
        let balances = Balances::try_from(initial.balances).expect("under the limit");
        let (previous, previous_root) = P::build(initial.previous);
        let (current, current_root) = P::build(initial.current);
        let inactivity = InactivityScores::try_from(initial.inactivity).expect("under the limit");
        let roots = Roots {
            validators: root(&validators),
            balances: root(&balances),
            previous_participation: previous_root,
            current_participation: current_root,
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
            let list = match step.rotation {
                // The node's rotation moves current into previous, after the
                // epoch's new validators were appended to it.
                Some(len) => P::rotated(&self.current, len),
                None => self.previous.clone(),
            };
            list.write_and_commit(&step.previous)
        });
        let (current, current_root) = timed(&mut times[3], || {
            let list = match step.rotation {
                Some(len) => P::zeros(len),
                None => self.current.clone(),
            };
            list.write_and_commit(&step.current)
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
/// end of the list. That matters to a dense `VecMap` buffer, which ascending
/// order would regrow every time the highest index written doubled, a cost the
/// node does not pay.
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
