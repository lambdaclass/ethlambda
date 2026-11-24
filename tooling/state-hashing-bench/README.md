# state-hashing-bench

Compares how fast two beacon-state Merkle trees absorb real mainnet blocks:
ethlambda's `ethlambda-ssz-tree` and Silver's
[`silver_state_hashing`](https://crates.io/crates/silver_state_hashing)
0.2.0. Silver's [write-up](https://github.com/gattaca-com/silver/tree/main/crates/hashing)
benchmarks synthetic random writes; this replays the writes real blocks made.

Its own Cargo workspace, like `tooling/event-monitor`: Silver's crate builds C
and assembly (`hashtree`) and stays out of the node's lockfile.

## What is measured

The five validator-indexed lists of a beacon state, the ones that hold nearly
all of its size and its hashing: validators, balances, previous and current
epoch participation, inactivity scores. Each step of a real replay (one
epoch transition, or one block) is applied to both libraries as a new version
of the previous one, and each library recomputes all five roots. A step's
time is, per list: clone the parent's list, apply the writes, recompute the
root.

Every root is compared with the one the replayed state had at that step.
Those come from a replay that checks every block's `state_root` against what
mainnet committed to, so a library computing a different root fails the run
instead of reporting a time.

How each library is driven:

| | ethlambda-ssz-tree | silver_state_hashing |
|---|---|---|
| API | the state's own list types (`Validators`, `Balances`, ...) with their update buffers (`VecMap` for balances and participation, `BTreeMap` for validators and inactivity scores) | `SharedList` (the `multi-owner` storage its own benchmark uses); every list is committed once after `new`, so its flat tree is parked in the pool as after any commit |
| Pages | 4 KiB leaves, wide inner nodes | Silver's client's page sizes: balances 16 nodes, participation and inactivity 256, validator roots 1024 |
| Writes | buffered (`get_mut`/`push`, highest index first, as the node's unsorted writes reach the end of the list early and grow a `VecMap` buffer once), then `apply_updates`; through the write cursor (`iter_cow`) when they cover at least 1/8 of the list, which is the epoch's balance rewrite (fulu's epoch pass buffers those too; at that density both cost the same, 49.8 vs 50.0 ms per epoch on an M3 Pro) | `set`/`push`, then `commit` |
| Participation rotation | `mem::take` + `List::repeat(0, n)`, as `process_participation_flag_updates` does | previous = clone of current, current = `SharedList::new(zeros)` (this API has no in-place zero fill) |
| Validators | the list holds `Validator`s and hashes the changed ones itself | the list holds roots; each changed validator's root is computed in the timed region with the same `hash_tree_root` |
| Threads | 1, and every core (it hashes large subtrees on rayon) | 1 |

Both run under jemalloc (the node's allocator) and the node's release
profile (`lto = "fat"`, one codegen unit). `--keep` versions stay alive
behind the head, as a node keeps recent states, so both libraries really copy
on write; dropping the oldest version is not timed. The libraries take turns
within each round, so a drift in machine speed lands on all of them.

Not measured: reorgs. Era files hold the canonical chain only, so there are
no real competing branches to switch between. Silver's single-owner storage
(`PagePool`/`PageSnapshot`, which its client uses) is not driven either: it
hashes the same way and skips the per-page reference counts.

## Running it

1. Record a trace with the node binary. Era file `N` holds the blocks of
   slots `[(N-1)*8192, N*8192)` and starts from file `N-1`'s state; era 1874
   holds the October 2026 range Silver measured (slots 15,343,777 to
   15,347,039):

   ```sh
   cargo build --profile release-fast -p ethlambda   # the recording is not timed
   target/release-fast/ethlambda replay-era --network mainnet --era-dir ~/era \
       --era 1874 --download --max-blocks 3400 \
       --hashing-trace ~/mainnet-1874.trace
   ```

   The two era files are about 1.6 GB. The replay verifies every signature,
   at roughly 0.65 s per mainnet block, so 3,400 blocks take around 40
   minutes. The log's `Hashing trace written` line gives the mean writes per
   block per list.

2. Replay it through both libraries:

   ```sh
   cd tooling/state-hashing-bench
   cargo run --release -- --trace ~/mainnet-1874.trace --json results.json
   ```

   | Flag | Default | |
   |---|---|---|
   | `--rounds` | 3 | whole-trace replays per library; each step reports its median |
   | `--keep` | 32 | versions kept alive behind the head |
   | `--threads` | every core | threads for ethlambda's parallel run |
   | `--max-steps` | all | replay only the first N steps |
   | `--json` | none | also write every summary and per-step time |
   | `--only` | both | `silver` or `ours`, for a quicker loop while working on one |

   It prints Markdown tables: per-block and per-epoch-transition times
   (median, mean, tail), the same split per list, build time, and memory.

## The trace

`replay-era --hashing-trace` writes it; the format is documented in
`bin/ethlambda/src/era/hashing_trace.rs`, which this crate includes by path,
so the writer and the reader are one definition. It starts with the five
lists in full and then holds, per step, the `(index, value)` of every element
that changed plus each list's new root. The participation rotation at an
epoch transition is recorded as an operation rather than as a million writes,
since neither library performs it as writes.
