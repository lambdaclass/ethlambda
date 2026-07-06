# Spec Deviations

ethlambda diverges from the [leanSpec](https://github.com/leanEthereum/leanSpec)
reference in a few places, mainly for performance reasons. This page lists those
deviations; each will be fleshed out with rationale, implementation notes, and
trade-offs over time.

## Asynchronous signature aggregation with early stop

Aggregation runs off the main BlockChainServer actor loop and stops early once it ran out of time.

- **ethlambda:** at interval 2 the actor snapshots its state and spawns a `tokio::task::spawn_blocking` worker (`run_aggregation_worker`, `crates/blockchain/src/aggregation.rs:504`). The worker streams each finished group back as an `AggregateProduced` message; the actor loop is never blocked on XMSS work.
- **Early stop:** a `send_after(AGGREGATION_DEADLINE, ...)` timer cancels the session after 750ms (`AGGREGATION_DEADLINE`, `aggregation.rs:33`); the interval is 800ms (`MILLISECONDS_PER_INTERVAL`, `lib.rs:47`), leaving ~50ms for publish/propagation. The worker checks `cancel.is_cancelled()` before each job (`aggregation.rs:519`); in-flight jobs finish, remaining jobs are dropped.
- **leanSpec:** `aggregate()` is called inline and synchronously from `tick_interval` at interval 2 (`forks/lstar/spec.py`). It processes every group with no time budget, no worker, no cancellation.
- **Equivalence:** same XMSS proofs are produced; deviation is scheduling + a partial-result bound, not signature logic.

## Attestation scoring on block building

Attestations are scored and selected when packing a block, rather than greedily included as they arrive.

- **ethlambda:** `select_attestations` (`crates/blockchain/src/block_builder.rs:170`) ranks candidate `AttestationData` entries by tier `Finalize > Justify > Build` (`enum Tier`, `block_builder.rs:473`). The within-tier order is tier-dependent (`EntryScore::ordering_key`, `block_builder.rs:517`): `Finalize`/`Justify` entries already cross 2/3, so newer chain progress leads (target slot, attestation slot, then new-voter count); `Build` entries only add marginal voters, so coverage leads (new-voter count, target slot, then attestation slot). `data_root` is the final deterministic tiebreak in both tiers. Each round picks the best candidate against a projected post-state, up to `MAX_ATTESTATIONS_DATA = 8` entries (`crates/common/types/src/block.rs:109`).
- **leanSpec:** `build_block` iterates entries sorted by `target.slot` (oldest first) and includes the first ones that pass filters (greedy, no scoring), re-running the loop as a fixed point when justification/finalization advances. Same cap: `MAX_ATTESTATIONS_DATA = 8` (`subspecs/chain/config.py`).
- **Equivalence:** both produce a valid block; ethlambda prioritizes attestations that advance finality/justification rather than processing in slot order.

