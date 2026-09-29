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
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

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
}
