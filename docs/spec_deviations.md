# Spec Deviations

ethlambda diverges from the [leanSpec](https://github.com/leanEthereum/leanSpec)
reference in a few places, mainly for performance reasons. This page lists those
deviations; each will be fleshed out with rationale, implementation notes, and
trade-offs over time.

## Asynchronous signature aggregation with early stop

Aggregation runs off the main BlockChainServer actor loop and stops early once it runs out of time.

- **ethlambda:** at interval 2 the actor snapshots the current slot's raw gossip signatures (`snapshot_current_slot_aggregation_inputs`, `crates/blockchain/src/aggregation.rs`) and spawns a `tokio::task::spawn_blocking` worker (`run_aggregation_worker`, `aggregation.rs`). The snapshot deliberately covers only current-slot raw gossip signatures, skipping existing-proof reuse and stale-slot groups so the interval-2 budget is never spent re-aggregating past slots (proof reuse is handled later, at block build). The worker streams each finished group back as an `AggregateProduced` message; the actor loop is never blocked on XMSS work.
- **Early stop:** a `send_after(AGGREGATION_DEADLINE, ...)` timer cancels the session after 750ms (`AGGREGATION_DEADLINE`, `aggregation.rs`); the interval is 800ms (`MILLISECONDS_PER_INTERVAL`, `crates/blockchain/src/lib.rs`), leaving ~50ms for publish/propagation. The worker checks `cancel.is_cancelled()` before each job (`aggregation.rs`); in-flight jobs finish, remaining jobs are dropped.
- **leanSpec:** `aggregate()` is called inline and synchronously from `tick_interval` at interval 2. It processes every group with no time budget, no worker, no cancellation.
- **Equivalence:** the per-group XMSS aggregation logic is the same as leanSpec's; the deviations are scheduling (off the actor loop), input scope (current-slot raw gossip only), and a partial-result bound. On cancellation the worker emits only the groups that finished, so a slot may pack fewer aggregates than the synchronous path would; any such subset still yields a valid block, affecting how many votes are included rather than signature validity.

## Attestation scoring on block building

Attestations are scored and selected when packing a block, rather than greedily included as they arrive.

- **ethlambda:** `select_attestations` (`crates/blockchain/src/block_builder.rs`) ranks candidate `AttestationData` entries by tier `Finalize > Justify > Build` (`enum Tier`, `block_builder.rs`). The within-tier order is tier-dependent (`EntryScore::ordering_key`, `block_builder.rs`): `Finalize`/`Justify` entries already cross 2/3, so newer chain progress leads (target slot, attestation slot, then new-voter count); `Build` entries only add marginal voters, so coverage leads (new-voter count, target slot, then attestation slot). `data_root` is the final deterministic tiebreak in both tiers. Each round picks the best candidate against a projected post-state, up to `MAX_ATTESTATIONS_DATA = 8` distinct `AttestationData` entries (`crates/common/types/src/block.rs`); a winning entry may carry several proofs, which a later compaction step (`compact_attestations`, `block_builder.rs`) merges back to one per `AttestationData`.
- **leanSpec:** `build_block` iterates entries sorted by `target.slot` (oldest first) and includes the first ones that pass filters (greedy, no scoring), re-running the loop as a fixed point when justification/finalization advances. Same cap: `MAX_ATTESTATIONS_DATA = 8`.
- **Equivalence:** both produce a valid block; ethlambda prioritizes attestations that advance finality/justification rather than processing in slot order.
