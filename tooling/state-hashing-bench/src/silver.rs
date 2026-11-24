//! Silver's tree, `silver_state_hashing`, through its public multi-owner API
//! (`SharedList`), the one its own benchmark compares.
//!
//! Page sizes are the ones Silver's client declares for these lists
//! (`crates/beacon_state/data/src/tree/mod.rs`): 16 nodes for balances, 256
//! for participation and inactivity scores, 1024 for validator roots. A list
//! of validators is a list of their roots, so every changed validator's root
//! is computed in the timed region, with the same `hash_tree_root` the node's
//! tree uses for its elements. Each list's time is its clone, its writes, its
//! `commit` and its root.
//!
//! This API has no zero-fill for the participation rotation (Silver's client
//! zero-fills its single-owner flat tree in place), so the new current list
//! is `SharedList::new` over zeros, in its own page pool, which hashes the
//! zero leaves once. That cost lands in the epoch's `current` column. Cloning
//! one prebuilt zero list instead would put two lists that are written in
//! turn on one pool, whose single parked flat tree would then be reloaded on
//! every block.

use ethlambda_types::primitives::HashTreeRoot as _;
use silver_state_hashing::{B256, HashFormat, SharedList, TreeSpec};

use crate::format::{Root, Roots};
use crate::trace::{Initial, Step, Writes};
use crate::{Candidate, ListTimes, timed};

pub struct ValidatorRoots;
impl TreeSpec for ValidatorRoots {
    type Val = B256;
    type Page = [B256; 1024];
}

pub struct Balances;
impl TreeSpec for Balances {
    type Val = u64;
    type Page = [B256; 16];
}

/// Both participation lists. Silver's client declares two markers of one
/// layout (`Previous`, `Current`); one type here lets the rotation hand
/// current's pages to previous by cloning, as its client copies them.
pub struct Participation;
impl TreeSpec for Participation {
    type Val = u8;
    type Page = [B256; 256];
}

pub struct Inactivity;
impl TreeSpec for Inactivity {
    type Val = u64;
    type Page = [B256; 256];
}

#[derive(Clone)]
pub struct Silver {
    validators: SharedList<ValidatorRoots>,
    balances: SharedList<Balances>,
    previous: SharedList<Participation>,
    current: SharedList<Participation>,
    inactivity: SharedList<Inactivity>,
    roots: Roots,
}

impl Candidate for Silver {
    fn build(initial: Initial) -> Self {
        let validator_roots: Vec<B256> = initial
            .validators
            .iter()
            .map(|validator| validator.hash_tree_root().0)
            .collect();
        let validators = new_list(&validator_roots);
        let balances = new_list(&initial.balances);
        let previous = new_list(&initial.previous);
        let current = new_list(&initial.current);
        let inactivity = new_list(&initial.inactivity);
        let roots = Roots {
            validators: validators.hash_root(),
            balances: balances.hash_root(),
            previous_participation: previous.hash_root(),
            current_participation: current.hash_root(),
            inactivity_scores: inactivity.hash_root(),
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
            let roots = step
                .validators
                .values
                .iter()
                .map(|validator| validator.hash_tree_root().0);
            write(&mut list, &step.validators.indices, roots);
            commit(list)
        });
        let (balances, balances_root) = timed(&mut times[1], || {
            let mut list = self.balances.clone();
            write_all(&mut list, &step.balances);
            commit(list)
        });
        let (previous, previous_root) = timed(&mut times[2], || {
            let mut list = match step.rotation {
                Some(len) => {
                    let mut list = self.current.clone();
                    while list.len() < len {
                        list.push(0).expect("under the limit");
                    }
                    list
                }
                None => self.previous.clone(),
            };
            write_all(&mut list, &step.previous);
            commit(list)
        });
        let (current, current_root) = timed(&mut times[3], || {
            let mut list = match step.rotation {
                Some(len) => new_list(&vec![0; len]),
                None => self.current.clone(),
            };
            write_all(&mut list, &step.current);
            commit(list)
        });
        let (inactivity, inactivity_root) = timed(&mut times[4], || {
            let mut list = self.inactivity.clone();
            write_all(&mut list, &step.inactivity);
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

/// A committed list whose flat tree is parked in its pool, as after any
/// commit. `new` leaves the flat tree on the list itself, where the clones
/// that make every later version cannot reach it, so without the `commit`
/// each list's first write would rebuild its flat tree from every page.
fn new_list<C: TreeSpec>(values: &[C::Val]) -> SharedList<C> {
    let mut list = SharedList::new(values, HashFormat::Fixed).expect("under the limit");
    list.commit();
    list
}

fn commit<C: TreeSpec>(mut list: SharedList<C>) -> (SharedList<C>, Root) {
    list.commit();
    let root = list.hash_root();
    (list, root)
}

fn write_all<C: TreeSpec>(list: &mut SharedList<C>, writes: &Writes<C::Val>) {
    write(list, &writes.indices, writes.values.iter().copied());
}

fn write<C: TreeSpec>(
    list: &mut SharedList<C>,
    indices: &[u32],
    values: impl Iterator<Item = C::Val>,
) {
    for (&index, value) in indices.iter().zip(values) {
        let index = index as usize;
        if index < list.len() {
            list.set(index, value).expect("in range");
        } else {
            assert_eq!(index, list.len(), "appends come in order");
            list.push(value).expect("under the limit");
        }
    }
}
