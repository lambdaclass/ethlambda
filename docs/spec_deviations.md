# Spec Deviations

ethlambda diverges from the [leanSpec](https://github.com/leanEthereum/leanSpec)
reference in a few places, mainly for performance reasons. This page lists those
deviations; each will be fleshed out with rationale, implementation notes, and
trade-offs over time.

## Continuous signature aggregation, published on the interval grid

Aggregation is not a per-slot duty in ethlambda: it runs continuously off the main
BlockChainServer actor loop, and only the publication of its results sits on the interval
grid.

- **ethlambda:** one worker thread (`spawn_aggregation_worker`, `crates/blockchain/src/aggregation.rs`) is started with the actor and lives as long as it does. It holds its own `Store` handle and loops: pick the single best job (`select_best_job`), prove it, send it to the actor as an `AggregateProduced` message, pick again; an idle round sleeps `WORKER_IDLE_POLL`. Candidates are the store's gossip-signature groups plus payload-only groups (`new_payload_keys`, which need at least two existing proofs to merge), ranked by consensus value (current-slot before stale, then `Finalize > Justify > Build`, mirroring the block builder). The actor loop is never blocked on XMSS work.
- **Deferred publication:** the actor applies each aggregate to its store on arrival — so the pool the worker re-reads accounts for it — but buffers the gossip publication until interval 2 (`publish_pending_aggregates`, `crates/blockchain/src/lib.rs`). Proving therefore happens whenever there is work; the network still only sees aggregates at the vote-aggregation interval.
- **What the worker may take up** is a function of where the slot is (`JobPolicy`, `aggregation.rs`). Early in the slot: backlog work, plus a current-slot group that already holds two thirds of the signatures this node expects (`min_current_slot_group_sigs`), so a slot's votes go out as one wide aggregate instead of several thin ones. Inside the last `EARLY_AGGREGATION_WINDOW` before interval 2: that group and nothing else, since a backlog job is a recursive merge that would occupy the single prover across the boundary and delay the aggregate the slot is waiting on. From interval 2 on: everything, however few signatures back it.
- **Yielding to the block build:** the actor raises the worker's pause flag around `propose_block` (`AggregationWorker::pause`), since both run leanVM proofs and only the block has a deadline. A proof already in flight is not interrupted.
- **leanSpec:** `aggregate()` is called inline and synchronously from `tick_interval`, at interval 2 only. It walks every attestation data with fresh evidence, with no worker, no gate, and no separation between producing an aggregate and publishing it.
- **Equivalence:** the worker produces the same aggregates over a slot, at different times; what a block may carry is unchanged. Where the two can differ is count: a slot whose proving overruns publishes fewer aggregates than the synchronous path would, which affects how many votes are included rather than signature validity.

## Proposer signature outside the block proof

The block proof is a pair — the proposer's raw signature and the attestation aggregate —
rather than one merged proof over both.

- **ethlambda:** `SignedBlock.proof` is a `BlockProof { proposer_signature, attestation_proof }` (`crates/common/types/src/block.rs`). `proposer_signature` is the raw XMSS signature over the block root, verified directly against the proposer's `proposal_pubkey` with the hash-based verifier; `attestation_proof` is the lean-multisig Type-2 over the body's attestations only, and is empty when the block carries none (`verify_block_signatures`, `crates/blockchain/src/store.rs`).
- **leanSpec:** the proposer signature is wrapped as a singleton Type-1 and merged into a single block Type-2 alongside every attestation.
- **Why:** the merged form makes the proposer signature the reason a block needs a prover at all — even an attestation-less one — and it ties the merge to the block root, so nothing can be merged before the block exists. Splitting removes prover work from the empty case entirely and is what makes a gossiped block body proof possible.
- **Consequence:** this is a wire-format divergence. The signature and SSZ fixtures no longer apply, and a node running this cannot interop with one that does not.

## Block body proofs, and a proposer that packs no body

Candidate bodies are built by aggregators and gossiped; the proposer adopts one instead of
packing its own.

- **ethlambda:** during the head-update interval the aggregation worker packs a candidate body for the next slot and merges its attestation proofs into one Type-2, and the actor gossips the pair as a `BlockBodyProof` on `/leanconsensus/{fork_digest}/block_body_proof/ssz_snappy` (`crates/blockchain/src/body_proof.rs`). At the slot boundary the proposer scores the candidates it has collected and adopts the most valuable one — or signs an empty block if none beats one (`choose_body`).
- **leanSpec:** the proposer selects attestations from its own pool, merges their proofs itself, and does both inside its proposal slot.
- **Why:** the merge is the one part of proposing that costs seconds, and it does not need the proposer, the block root, or the slot. Moving it to the aggregators that already hold the proofs takes it off the critical path; the proposer is left with a state transition, a verification and a signature.
- **Safety:** the proposer keeps the last word. A candidate is dropped if any of its votes does not sit on the chain the block extends (`attestation_data_matches_chain` — the state transition does not check those roots), if its attestations do not survive that transition, or if its aggregate fails verification; the state root is computed from the transition rather than trusted. Verification happens before signing: XMSS keys are one-time, so a proposer cannot try a candidate, fail the import, and try another. The screen deliberately stops there: a body is all-or-nothing, so dropping one for a merely stale entry would cost the whole block, and staleness is already discounted by the adoption score.
- **Consequence:** a proposer whose candidates all fail, or that received none, proposes an empty block instead of packing what its own pool holds. On a chain with no aggregator gossiping body proofs, every block is empty.

## Attestation scoring on block building

Attestations are scored and selected when packing a block, rather than taken in
target-slot order as they are scanned.

- **ethlambda:** `select_attestations` (`crates/blockchain/src/block_builder.rs`) ranks candidate `AttestationData` entries by tier `Finalize > Justify > Build` (`enum Tier`, `block_builder.rs`). The within-tier order is tier-dependent (`EntryScore::ordering_key`, `block_builder.rs`): `Finalize`/`Justify` entries already cross 2/3, so newer chain progress leads (target slot, attestation slot, then new-voter count); `Build` entries only add marginal voters, so coverage leads (new-voter count, target slot, then attestation slot). `data_root` is the final deterministic tiebreak in both tiers. Each round picks the best candidate against a projected post-state.
- **Proposer budget:** rounds stop at `max_attestations_per_block` distinct `AttestationData` entries (`--max-attestations-per-block`, default 3), clamped to `MAX_ATTESTATIONS_DATA`. The *consensus* cap is `MAX_ATTESTATIONS_DATA`, the same value leanSpec enforces in its state transition; only the proposer-side budget differs, and it is configurable.
- **Collapsing duplicate data:** a winning entry may carry several proofs, which must collapse to one proof per `AttestationData` before the block is valid. By default ethlambda keeps only the best-coverage proof and **drops** the rest (`keep_best_proof_per_data`, `block_builder.rs`), skipping the leanVM merge at the cost of the voters those proofs carried. With `--enable-proposer-aggregation`, `compact_attestations` (`block_builder.rs`) instead merges them through recursive proof aggregation, which is what leanSpec always does.
- **leanSpec:** `build_block` scans candidates sorted by `(target.slot, data_root)`, oldest target first, and includes the first ones that pass its filters (greedy, no scoring), re-running the scan as a fixed point when justification/finalization advances. Its proposer budget is `MAX_ATTESTATIONS_DATA` itself.
- **Equivalence:** both produce a valid block. ethlambda front-loads the attestations that advance justification and finality, and within those tiers prefers the *newest* target where leanSpec takes the *oldest*; combined with the smaller default budget, an older entry can be outranked by newer ones round after round, so which votes reach peers through blocks differs even though every block stays valid. The smaller budget yields smaller blocks and lower build times.
- **Upstream status:** the tiered strategy is proposed upstream as leanSpec [PR #1149](https://github.com/leanEthereum/leanSpec/pull/1149) (open at the time of writing), so this deviation may converge; the recursive-merge collapse follows leanSpec #510.
