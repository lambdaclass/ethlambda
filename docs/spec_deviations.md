# Spec Deviations

ethlambda diverges from its reference specifications in a few places. This page
lists those deviations; each will be fleshed out with rationale, implementation
notes, and trade-offs over time.

There are two references, because this repository builds for two chains. The
lean node is measured against [leanSpec](https://github.com/leanEthereum/leanSpec),
and its deviations below are mainly for performance. The beacon node is
measured against [consensus-specs](https://github.com/ethereum/consensus-specs)
and the [Beacon API](https://github.com/ethereum/beacon-APIs), and the validator
client against consensus-specs and the
[keymanager API](https://github.com/ethereum/keymanager-APIs). Their deviations
are scope decisions rather than optimizations.

> **Read the validator client's deviation before running it with real keys.**
> It is the only entry on this page that can cost you money rather than
> performance.

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

## The validator client keeps no slashing-protection record

`ethlambda validator` signs attestations and blocks without recording what it
has signed. It cannot detect that a previous run, or another client holding the
same keys, already signed.

- **The specification:** [EIP-3076](https://eips.ethereum.org/EIPS/eip-3076)
  defines an interchange format and the conditions a validator client must never
  violate. For attestations: signing two *distinct* attestations with the same
  target epoch (a double vote), and signing one whose source and target surround
  or are surrounded by another's. For blocks: signing two distinct ones for the
  same slot. Enforcing any of them requires a durable record, written before the
  signature leaves the process.
- **ethlambda:** there is no such record and no store to hold one. This is a
  deliberate scope decision for the client's first phase, not an oversight.
- **What partially covers it:** two in-memory guards, one per message kind.
  `crate::attestation_guard::AttestationGuard` refuses to sign a second
  conflicting attestation for a validator *within one run*, using EIP-3076's
  minimal rule (the target must advance, the source must not regress).
  `crate::proposal_guard::ProposalGuard` does the same for blocks, with the
  minimal rule for those (the slot must strictly advance). Between them they
  close the shapes reachable through ordinary operation: a backward wall-clock
  step, or a duty schedule replaced mid-epoch. Both are held in memory only, so
  a restart empties them and neither knows anything about any other process.
- **Why a proposer slashing is the worse of the two:** a double vote needs a
  second validator's attestation to be caught. Two signed block headers for one
  slot are the whole of the evidence on their own.
- **What is therefore not covered:** restarting into a state where the chain has
  moved, and running these keys in two places at once. Both can produce a
  slashable double vote or a double proposal, and nothing in this client will
  stop them.
- **Keymanager consequences:** `DELETE /eth/v1/keystores` must return an
  EIP-3076 interchange. This client returns a well-formed but empty one whose
  `genesis_validators_root` is deliberately all-zero, so a conformant importer
  rejects it outright rather than trusting an empty history that was never
  recorded. `POST` accepts the `slashing_protection` field and ignores it, with
  a server-side warning. A key migrated in or out through this API does not
  carry its history.
- **Operationally:** do not run these keys in any other client while this one
  runs, and treat a restart as an event that needs the same care a manual key
  move would. The client warns about this at startup on every run.

## `block_id` cannot name `genesis`, and `state_id` cannot be a state root

Two id forms the Beacon API defines return `404` here.

- **`genesis`, on either id.** `Table::BlockRoots` is the slot-to-root index
  every slot lookup reads, and `Store::update_checkpoints` is its only writer.
  That writer computes its delta by walking from the old head to the new one
  (`block_root_index_changes`, `crates/storage/src/store.rs`) and returns early
  when the two are the same root, which is exactly the situation at bootstrap:
  `Store::init_beacon` seeds `KEY_HEAD` with the anchor. So the anchor's own
  slot is never written to that index, on either chain, and a
  checkpoint-synced directory has no genesis block to serve in any case.
  `BlockId::Genesis` refuses outright rather than resolving to the anchor and
  calling that genesis.
- **A `state_id` given as a `0x…` root.** That id is a *state* root, and states
  are stored keyed by **block** root (`Store::get_state`) with no reverse
  index. Refusing is better than answering with a state that is right only when
  the two roots happen to coincide. The refusal names the ids that do work.

**The anchor's own slot is not among these.** It is missing from `BlockRoots`
for the reason above, but it is the slot `checkpoint_sync.rs` asks a peer for
immediately after reading that peer's finalized state, so a `404` there would
make this node unusable as a checkpoint-sync source for any client.
`anchored_root_at_slot` (`crates/net/rpc/src/shared/block_id.rs`) covers it: on
an index miss it tries the roots the store can name (finalized, justified,
head) and accepts one only when `Store::block_entry` confirms that root's block
really sits at the slot asked for. A slot the store holds nothing at still
answers `404`, since no candidate matches.

This was found by running a mainnet follower and pointing a second one at its
API: before the fallback existed, the second died with `peer served no block at
the anchor slot 15265888`.
