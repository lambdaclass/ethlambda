# Spec Deviations

ethlambda diverges from the [leanSpec](https://github.com/leanEthereum/leanSpec)
reference in a few places, mainly for performance reasons. This page lists those
deviations; each will be fleshed out with rationale, implementation notes, and
trade-offs over time.

## Asynchronous signature aggregation with an early start and an early stop

Aggregation runs off the main BlockChainServer actor loop, may start before its
interval, and stops early once it runs out of time.

- **ethlambda:** the actor snapshots everything aggregation needs (`snapshot_aggregation_inputs`, `crates/blockchain/src/aggregation.rs`) and spawns a `tokio::task::spawn_blocking` worker (`run_aggregation_worker`, `aggregation.rs`). Candidates are the store's gossip-signature groups plus payload-only groups (`new_payload_keys`, which need at least two existing proofs to merge). A tiered greedy selector orders them by consensus value (current-slot before stale, then `Finalize > Justify > Build`, mirroring the block builder) and emits at most `MAX_AGGREGATION_JOBS` jobs, dropping to a single job in the slot before one of our validators proposes. The worker streams each finished group back as an `AggregateProduced` message; the actor loop is never blocked on XMSS work.
- **Early start:** a session normally fires at interval 2, but may start up to `EARLY_AGGREGATION_WINDOW` earlier once the 2/3 signature threshold is already met (`maybe_start_early_aggregation`, `crates/blockchain/src/lib.rs`), so the proof lands earlier in the slot.
- **Early stop:** a `send_after(AGGREGATION_DEADLINE, ...)` timer cancels the session that long after **session start**, so a session that started early also ends early (`AGGREGATION_DEADLINE`, `aggregation.rs`). The worker checks `cancel.is_cancelled()` before each job (`aggregation.rs`); in-flight jobs finish, remaining jobs are dropped.
- **leanSpec:** `aggregate()` is called inline and synchronously from `tick_interval`, at interval 2 only. It walks every attestation data with fresh evidence, with no job cap, no time budget, no worker, and no cancellation.
- **Equivalence:** on cancellation the worker emits only the groups that finished, so a slot may pack fewer aggregates than the synchronous path would; any such subset still yields a valid block, affecting how many votes are included rather than signature validity. The job cap has the same character: it bounds prover work per slot, not what a block may carry.

## Attestation scoring on block building

Attestations are scored and selected when packing a block, rather than taken in
target-slot order as they are scanned.

- **ethlambda:** `select_attestations` (`crates/blockchain/src/block_builder.rs`) ranks candidate `AttestationData` entries by tier `Finalize > Justify > Build` (`enum Tier`, `block_builder.rs`). The within-tier order is tier-dependent (`EntryScore::ordering_key`, `block_builder.rs`): `Finalize`/`Justify` entries already cross 2/3, so newer chain progress leads (target slot, attestation slot, then new-voter count); `Build` entries only add marginal voters, so coverage leads (new-voter count, target slot, then attestation slot). `data_root` is the final deterministic tiebreak in both tiers. Each round picks the best candidate against a projected post-state.
- **Proposer budget:** rounds stop at `max_attestations_per_block` distinct `AttestationData` entries (`--max-attestations-per-block`, default 3), clamped to `MAX_ATTESTATIONS_DATA`. The *consensus* cap is `MAX_ATTESTATIONS_DATA`, the same value leanSpec enforces in its state transition; only the proposer-side budget differs, and it is configurable.
- **Collapsing duplicate data:** a winning entry may carry several proofs, which must collapse to one proof per `AttestationData` before the block is valid. By default ethlambda keeps only the best-coverage proof and **drops** the rest (`keep_best_proof_per_data`, `block_builder.rs`), skipping the leanVM merge at the cost of the voters those proofs carried. With `--enable-proposer-aggregation`, `compact_attestations` (`block_builder.rs`) instead merges them through recursive proof aggregation, which is what leanSpec always does.
- **leanSpec:** `build_block` scans candidates sorted by `(target.slot, data_root)`, oldest target first, and includes the first ones that pass its filters (greedy, no scoring), re-running the scan as a fixed point when justification/finalization advances. Its proposer budget is `MAX_ATTESTATIONS_DATA` itself.
- **Equivalence:** both produce a valid block. ethlambda front-loads the attestations that advance justification and finality, and within those tiers prefers the *newest* target where leanSpec takes the *oldest*; combined with the smaller default budget, an older entry can be outranked by newer ones round after round, so which votes reach peers through blocks differs even though every block stays valid. The smaller budget yields smaller blocks and lower build times.
- **Upstream status:** the tiered strategy is proposed upstream as leanSpec [PR #1149](https://github.com/leanEthereum/leanSpec/pull/1149) (open at the time of writing), so this deviation may converge; the recursive-merge collapse follows leanSpec #510.
