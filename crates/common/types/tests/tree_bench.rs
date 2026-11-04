//! Mainnet-scale comparison of the tree-backed `Validators` / `Balances`
//! against the `Vec`-backed `SszList`s they replaced.
//!
//! `#[ignore]`d: it allocates several gigabytes and runs for seconds.
//!
//! ```text
//! cargo test -p ethlambda-types --profile release-fast --test tree_bench \
//!     -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Every line it prints starts with `tree_bench`, so the numbers can be
//! grepped out of the test harness's output.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use ethlambda_ssz_tree::ProgressiveList;
use ethlambda_types::beacon::containers::{Balances, Validator, Validators};
use ethlambda_types::beacon::preset;
use ethlambda_types::beacon::primitives::BlsPubkey;
use libssz::{SszDecode as _, SszEncode as _};
use libssz_merkle::{HashTreeRoot, Sha2Hasher};
use libssz_types::SszList;

/// Counts live heap bytes, so memory is measured without an external tool.
struct Counting;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every method forwards to `System` unchanged and only adds
// bookkeeping on an atomic counter.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
        if !new_pointer.is_null() {
            LIVE_BYTES.fetch_add(new_size, Ordering::Relaxed);
            LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        new_pointer
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const VALIDATOR_COUNT: usize = 2_400_000;

/// Derived states held at once, as the storage LRU holds up to 32. The
/// `Vec`-backed side holds fewer, since each is a full copy.
const TREE_STATES: usize = 32;
const VEC_STATES: usize = 4;

type VecValidators = SszList<Validator, { preset::VALIDATOR_REGISTRY_LIMIT }>;
type VecBalances = SszList<u64, { preset::VALIDATOR_REGISTRY_LIMIT }>;

fn validator(index: usize) -> Validator {
    let mut pubkey = [0u8; 48];
    pubkey[..8].copy_from_slice(&(index as u64).to_le_bytes());
    Validator {
        pubkey: BlsPubkey(pubkey),
        effective_balance: preset::MAX_EFFECTIVE_BALANCE,
        exit_epoch: u64::MAX,
        withdrawable_epoch: u64::MAX,
        ..Default::default()
    }
}

fn root<L: HashTreeRoot>(list: &L) -> [u8; 32] {
    HashTreeRoot::hash_tree_root(list, &Sha2Hasher)
}

fn live_mib() -> f64 {
    LIVE_BYTES.load(Ordering::Relaxed) as f64 / f64::from(1 << 20)
}

fn time<R>(label: &str, run: impl FnOnce() -> R) -> R {
    let start = Instant::now();
    let result = black_box(run());
    println!(
        "tree_bench {label} {:.1} ms",
        start.elapsed().as_secs_f64() * 1e3
    );
    result
}

/// The registry indices one block writes: a sync committee's worth of balance
/// changes plus the proposer (513), spread over the registry the way sync
/// committee members are.
fn block_balance_indices(block: usize) -> impl Iterator<Item = usize> {
    (0..513).map(move |i| (i * 4679 + block * 131) % VALIDATOR_COUNT)
}

/// The validator records one block writes: an exit and a slashing.
fn block_validator_indices(block: usize) -> [usize; 2] {
    [
        (block * 7919) % VALIDATOR_COUNT,
        (block * 104_729 + 1) % VALIDATOR_COUNT,
    ]
}

fn write_block_vec(validators: &mut VecValidators, balances: &mut VecBalances, block: usize) {
    for index in block_balance_indices(block) {
        balances[index] += 1;
    }
    for index in block_validator_indices(block) {
        validators[index].exit_epoch = block as u64;
    }
}

fn write_block_tree(validators: &mut Validators, balances: &mut Balances, block: usize) {
    for index in block_balance_indices(block) {
        balances[index] += 1;
    }
    for index in block_validator_indices(block) {
        validators[index].exit_epoch = block as u64;
    }
    validators.apply_updates();
    balances.apply_updates();
}

#[test]
#[ignore = "mainnet-scale benchmark: several GB and seconds to run"]
// Index loops on both sides keep the Vec and tree measurements the same shape.
#[allow(clippy::needless_range_loop)]
fn tree_bench() {
    let validators: Vec<Validator> = (0..VALIDATOR_COUNT).map(validator).collect();
    let balances: Vec<u64> = (0..VALIDATOR_COUNT)
        .map(|i| preset::MAX_EFFECTIVE_BALANCE + i as u64)
        .collect();

    // One unshared copy of each. Each side is built from clones made inside
    // the measured window, so the source Vecs, allocated before it, do not
    // skew the delta.
    let before = live_mib();
    let vec_validators: VecValidators = validators.clone().try_into().unwrap();
    let vec_balances: VecBalances = balances.clone().try_into().unwrap();
    println!(
        "tree_bench memory_one_vec_state {:.0} MiB",
        live_mib() - before
    );

    let before = live_mib();
    let tree_validators: Validators = time("build_tree", || validators.clone().try_into().unwrap());
    let tree_balances: Balances = balances.clone().try_into().unwrap();
    println!(
        "tree_bench memory_one_tree_state {:.0} MiB",
        live_mib() - before
    );
    drop(validators);
    drop(balances);

    // Hashing from scratch.
    let vec_roots = time("cold_hash_vec", || {
        (root(&vec_validators), root(&vec_balances))
    });
    let tree_roots = time("cold_hash_tree", || {
        (root(&tree_validators), root(&tree_balances))
    });
    assert_eq!(vec_roots, tree_roots, "the tree must hash like SszList");

    // What an import does: clone the parent, write one block, hash.
    time("clone_write_block_rehash_vec", || {
        let mut validators = vec_validators.clone();
        let mut balances = vec_balances.clone();
        write_block_vec(&mut validators, &mut balances, 1);
        (root(&validators), root(&balances))
    });
    time("clone_write_block_rehash_tree", || {
        let mut validators = tree_validators.clone();
        let mut balances = tree_balances.clone();
        write_block_tree(&mut validators, &mut balances, 1);
        (root(&validators), root(&balances))
    });

    // An epoch boundary: every balance written, then hashed.
    time("epoch_sweep_vec", || {
        let mut balances = vec_balances.clone();
        for index in 0..VALIDATOR_COUNT {
            balances[index] += 1;
        }
        root(&balances)
    });
    time("epoch_sweep_tree", || {
        let mut balances = tree_balances.clone();
        for index in 0..VALIDATOR_COUNT {
            balances[index] += 1;
        }
        balances.apply_updates();
        root(&balances)
    });

    // Where `epoch_sweep_tree`'s time goes: filling the pending-write map,
    // folding it into the tree, hashing the result.
    {
        let mut balances = tree_balances.clone();
        let start = Instant::now();
        for index in 0..VALIDATOR_COUNT {
            balances[index] += 1;
        }
        let write = start.elapsed();
        let start = Instant::now();
        balances.apply_updates();
        let apply = start.elapsed();
        let start = Instant::now();
        black_box(root(&balances));
        println!(
            "tree_bench epoch_sweep_tree_phases write {:.1} ms apply {:.1} ms hash {:.1} ms",
            write.as_secs_f64() * 1e3,
            apply.as_secs_f64() * 1e3,
            start.elapsed().as_secs_f64() * 1e3
        );
    }

    // The same sweep through the write cursor: no pending-write map, no sorted
    // copy of it.
    let sweep_root = time("epoch_sweep_cursor_tree", || {
        let mut balances = tree_balances.clone();
        balances
            .try_update_each(|balance| {
                balance.set(**balance + 1);
                Ok::<_, ()>(())
            })
            .unwrap();
        root(&balances)
    });
    let mut expected_sweep = tree_balances.clone();
    for index in 0..VALIDATOR_COUNT {
        expected_sweep[index] += 1;
    }
    expected_sweep.apply_updates();
    assert_eq!(
        sweep_root,
        root(&expected_sweep),
        "the cursor must write the same"
    );
    drop(expected_sweep);

    // Nothing changes, so every leaf and its hash are kept.
    time("epoch_sweep_noop_cursor_tree", || {
        let mut balances = tree_balances.clone();
        balances
            .try_update_each(|balance| {
                let same = **balance;
                balance.set(same);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(balances.ptr_eq(&tree_balances));
        root(&balances)
    });

    // The rebuild alternative: copy out, write, build a new list, share what is
    // equal with the old one.
    time("epoch_sweep_rebuild_tree", || {
        let mut values = tree_balances.to_vec();
        for value in &mut values {
            *value += 1;
        }
        let mut balances = Balances::try_from(values).unwrap();
        balances.rebase_on(&tree_balances);
        root(&balances)
    });

    // The rewards step: four (reward, penalty) pairs per validator, each
    // applied as a saturating add then subtract, in order.
    let deltas: Vec<(Vec<u64>, Vec<u64>)> = (0..4u64)
        .map(|pair| {
            let rewards = (0..VALIDATOR_COUNT as u64)
                .map(|i| (i + pair) % 7)
                .collect();
            let penalties = (0..VALIDATOR_COUNT as u64)
                .map(|i| (i * 3 + pair) % 5)
                .collect();
            (rewards, penalties)
        })
        .collect();
    let get_mut_root = time("rewards_apply_4_pairs_get_mut", || {
        let mut balances = tree_balances.clone();
        for (rewards, penalties) in &deltas {
            for index in 0..VALIDATOR_COUNT {
                let balance = balances.get_mut(index).unwrap();
                *balance = balance.saturating_add(rewards[index]);
                let balance = balances.get_mut(index).unwrap();
                *balance = balance.saturating_sub(penalties[index]);
            }
        }
        balances.apply_updates();
        root(&balances)
    });
    let cursor_root = time("rewards_apply_4_pairs_cursor", || {
        let mut balances = tree_balances.clone();
        balances
            .try_update_each(|balance| {
                let index = balance.index();
                let mut value = **balance;
                for (rewards, penalties) in &deltas {
                    value = value
                        .saturating_add(rewards[index])
                        .saturating_sub(penalties[index]);
                }
                balance.set(value);
                Ok::<_, ()>(())
            })
            .unwrap();
        root(&balances)
    });
    assert_eq!(
        get_mut_root, cursor_root,
        "the cursor must apply the same deltas"
    );
    drop(deltas);

    // Memory held by a chain of derived states, per state.
    let before = live_mib();
    let mut tree_states = Vec::with_capacity(TREE_STATES);
    let (mut validators, mut balances) = (tree_validators.clone(), tree_balances.clone());
    for block in 0..TREE_STATES {
        write_block_tree(&mut validators, &mut balances, block);
        root(&validators);
        root(&balances);
        tree_states.push((validators.clone(), balances.clone()));
    }
    println!(
        "tree_bench memory_per_derived_tree_state {:.1} MiB",
        (live_mib() - before) / TREE_STATES as f64
    );
    drop(tree_states);

    let before = live_mib();
    let mut vec_states = Vec::with_capacity(VEC_STATES);
    let (mut validators, mut balances) = (vec_validators.clone(), vec_balances.clone());
    for block in 0..VEC_STATES {
        write_block_vec(&mut validators, &mut balances, block);
        vec_states.push((validators.clone(), balances.clone()));
    }
    println!(
        "tree_bench memory_per_derived_vec_state {:.1} MiB",
        (live_mib() - before) / VEC_STATES as f64
    );
    drop(vec_states);

    // Storage round trip.
    let bytes = time("encode_vec", || vec_validators.to_ssz());
    let tree_bytes = time("encode_tree", || tree_validators.to_ssz());
    assert_eq!(bytes, tree_bytes, "the tree must encode like SszList");
    time("decode_vec", || {
        VecValidators::from_ssz_bytes(&bytes).unwrap()
    });
    let mut decoded = time("decode_tree", || {
        Validators::from_ssz_bytes(&bytes).unwrap()
    });
    time("rebase_decoded_onto_resident", || {
        decoded.rebase_on(&tree_validators)
    });
    assert!(decoded.ptr_eq(&tree_validators));

    // A pubkey -> index lookup scans the whole registry.
    let needle = validator(VALIDATOR_COUNT - 1).pubkey;
    time("scan_vec", || {
        vec_validators.iter().position(|v| v.pubkey == needle)
    });
    time("scan_tree", || {
        tree_validators.iter().position(|v| v.pubkey == needle)
    });

    // Scattered single-element reads, as `state.validator(i)` does.
    time("reads_1m_vec", || {
        (0..1_000_000)
            .map(|i| vec_validators[(i * 7919) % VALIDATOR_COUNT].effective_balance)
            .sum::<u64>()
    });
    time("reads_1m_tree", || {
        (0..1_000_000)
            .map(|i| tree_validators[(i * 7919) % VALIDATOR_COUNT].effective_balance)
            .sum::<u64>()
    });

    // About the number of `state.validator(i)` calls `get_base_reward` makes
    // for one mainnet block, with a different stride than `reads_1m` so the
    // access pattern isn't identical.
    const ATTESTER_READS: usize = 32 * 1024;
    time("block_attester_reads_vec", || {
        (0..ATTESTER_READS)
            .map(|i| vec_validators[(i * 104_729 + 17) % VALIDATOR_COUNT].effective_balance)
            .sum::<u64>()
    });
    time("block_attester_reads_tree", || {
        (0..ATTESTER_READS)
            .map(|i| tree_validators[(i * 104_729 + 17) % VALIDATOR_COUNT].effective_balance)
            .sum::<u64>()
    });

    // The shape of `process_effective_balance_updates`, which loops over
    // every validator and reads `balances[index]`.
    time("effective_balance_sweep_indexed_vec", || {
        let mut sum = 0u64;
        for index in 0..VALIDATOR_COUNT {
            sum = sum
                .wrapping_add(vec_balances[index])
                .wrapping_add(vec_validators[index].effective_balance);
        }
        sum
    });
    time("effective_balance_sweep_indexed_tree", || {
        let mut sum = 0u64;
        for index in 0..VALIDATOR_COUNT {
            sum = sum
                .wrapping_add(tree_balances[index])
                .wrapping_add(tree_validators[index].effective_balance);
        }
        sum
    });
    time("effective_balance_sweep_zipped_tree", || {
        tree_validators
            .iter()
            .zip(tree_balances.iter())
            .fold(0u64, |sum, (validator, balance)| {
                sum.wrapping_add(*balance)
                    .wrapping_add(validator.effective_balance)
            })
    });

    // `process_effective_balance_updates` with 0.1% of the validators changing:
    // the old indexed read plus buffered writes, against the cursor over the
    // registry zipped with the balances.
    let indexed_root = time("eb_updates_indexed", || {
        let mut validators = tree_validators.clone();
        let mut updates = Vec::new();
        for (index, validator) in validators.iter().enumerate() {
            let balance = tree_balances[index];
            if index % 1000 == 0 && balance != validator.effective_balance {
                updates.push((index, validator.effective_balance + 1));
            }
        }
        for (index, effective) in updates {
            validators[index].effective_balance = effective;
        }
        validators.apply_updates();
        root(&validators)
    });
    let cursor_root = time("eb_updates_cursor", || {
        let mut validators = tree_validators.clone();
        let mut balances = tree_balances.iter();
        let mut pass = validators.iter_cow();
        while let Some(mut validator) = pass.next_cow() {
            let balance = *balances.next().unwrap();
            if validator.index() % 1000 == 0 && balance != validator.effective_balance {
                let effective = validator.effective_balance + 1;
                validator.make_mut().effective_balance = effective;
            }
        }
        drop(pass);
        root(&validators)
    });
    assert_eq!(indexed_root, cursor_root, "the cursor must write the same");

    // Validators, balances and a third list swept in one loop, as a single
    // epoch pass would: one cursor each, only the third one written.
    time("lockstep_three_lists_cursor", || {
        let (mut validators, mut balances) = (tree_validators.clone(), tree_balances.clone());
        let mut scores = tree_balances.clone();
        {
            let mut validators = validators.iter_cow();
            let mut balances = balances.iter_cow();
            let mut scores = scores.iter_cow();
            while let (Some(validator), Some(balance), Some(mut score)) = (
                validators.next_cow(),
                balances.next_cow(),
                scores.next_cow(),
            ) {
                score.set(validator.effective_balance.wrapping_add(*balance));
            }
        }
        (root(&validators), root(&balances), root(&scores))
    });
}

/// Gloas turns the validator registry into a `ProgressiveList` (EIP-7916).
/// Same scale as [`tree_bench`], but a validators-only
/// [`Validators`](ethlambda_types::beacon::containers::Validators) baseline
/// is built in *this* test rather than reusing [`tree_bench`]'s
/// `memory_one_tree_state`, which holds `Validators` **and** `Balances`
/// together and so is not a like-for-like figure. `#[ignore]`d tests in this
/// file share one process-wide byte counter (see the module doc), so this
/// file must run with `--test-threads=1` for either figure to be trustworthy.
type ProgressiveValidators = ProgressiveList<Validator, BTreeMap<usize, Validator>>;

/// 1000 scattered registry indices, spread across the whole registry the way
/// [`block_validator_indices`] spreads its handful. At this sample size the
/// writes mostly land in the handful of large subtrees near the end of the
/// chain: a mainnet-sized registry's first six subtrees together hold only
/// 1365 of its elements (EIP-7916 boundaries at 0, 1, 5, 21, 85, 341, 1365,
/// ...), under one expected hit out of 1000 uniform-ish samples, so the small
/// subtrees near the start are rarely touched by this write set.
fn scattered_indices() -> impl Iterator<Item = usize> {
    (0..1000).map(|i| (i * 2_654_435_761) % VALIDATOR_COUNT)
}

#[test]
#[ignore = "mainnet-scale benchmark: several GB and seconds to run"]
fn progressive_list_bench() {
    let validators: Vec<Validator> = (0..VALIDATOR_COUNT).map(validator).collect();

    // The `List` baseline this compares against, same elements, same
    // process, measured before the progressive list exists so the two
    // memory deltas do not overlap.
    let before = live_mib();
    let list_validators: Validators = time("list_build", || validators.clone().try_into().unwrap());
    println!(
        "tree_bench memory_one_list_validators_state {:.0} MiB",
        live_mib() - before
    );
    time("list_cold_hash", || root(&list_validators));
    drop(list_validators);

    let before = live_mib();
    let progressive: ProgressiveValidators =
        time("progressive_build", || validators.clone().into());
    println!(
        "tree_bench memory_one_progressive_state {:.0} MiB",
        live_mib() - before
    );

    // First root: nothing cached yet.
    let first_root = time("progressive_cold_hash", || root(&progressive));

    // 1000 scattered writes, applied, then rehashed.
    let mut written = progressive.clone();
    let written_root = time("progressive_scattered_writes_apply_rehash", || {
        for index in scattered_indices() {
            written[index].exit_epoch = 1;
        }
        written.apply_updates();
        root(&written)
    });
    assert_ne!(
        first_root, written_root,
        "the scattered writes must change the root"
    );
    drop(validators);

    // An independent copy of the source data, built from scratch (sharing no
    // `Arc` with `written`), then rebased onto it to reclaim every subtree
    // the scattered writes did not touch. `rebase_on` only shares
    // allocations; it does not adopt `written`'s content, so `independent`
    // must still hash like the untouched registry.
    let source: Vec<Validator> = (0..VALIDATOR_COUNT).map(validator).collect();
    let mut independent: ProgressiveValidators =
        time("progressive_independent_build", || source.into());
    time("progressive_rebase", || independent.rebase_on(&written));
    assert_eq!(
        root(&independent),
        first_root,
        "a rebase must not change the contents"
    );
}
