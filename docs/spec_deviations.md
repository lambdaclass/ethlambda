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
- **Gloas messages:** a gloas proposer also signs an execution payload
  envelope, and a payload timeliness committee member signs a payload
  attestation. Neither is slashable, so neither has a guard. An envelope is
  published once per proposal, right after its block, and a failure to publish it
  is logged at error and counted without failing the proposal. A PTC vote has an
  in-memory dedup of `(validator, slot)` pairs recorded at signing time
  (`PayloadAttestationService`), so a duty abandoned between signing and
  submission is lost rather than re-signed. It is emptied by a restart and says
  nothing about another process, so it is not slashing protection either: a
  second, different vote for one slot is equivocation that peers penalize in
  gossip, not a slashing.
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

## Builder bids: gossip and API only (no builder API)

A gloas proposer served by this node can take a builder's bid from gossip or
from the Beacon API, and no other way.

- **The specification:** a gloas proposer may take a builder's signed bid
  (`SignedExecutionPayloadBid`, from gossip or a builder API) instead of building
  its own payload. `produceBlockV4` takes a `BuilderConfig` (`min_bid`,
  `builder_boost_factor`, `builders`) to steer that choice.
- **ethlambda:** bids seen on `execution_payload_bid` or posted to
  `POST /eth/v1/beacon/execution_payload_bids` are pooled, and `produceBlockV4`
  compares the best one with the local build under the top-level `min_bid` and
  `builder_boost_factor`: the bid must reach `min_bid`, and wins when
  `builder_boost_factor * bid_value > local_value / 10^7` (in Gwei against Wei,
  so a factor of 100 is parity). The local build wins a tie, and
  `shouldOverrideBuilder` from the execution client is honored. With no
  execution client, or a failed local build, the best viable bid is taken.
- **What it does not do:** the `builders` entries are decoded and ignored, so
  no builder is asked for a bid over HTTP and no `Eth-Builder-Url` is returned.
  Gossip bids are not filtered by `builder_pubkeys` either, since the Beacon API
  puts that list on each entry and it governs only that entry's own bid.
  `Eth-Consensus-Block-Value` stays `0`, because the consensus reward is not
  computed.
- **A bid win returns no envelope.** The block commits to the builder's bid, the
  builder reveals the payload, and nothing is cached for
  `GET .../execution_payload_envelopes`, so that endpoint answers `404` and
  `Eth-Execution-Payload-Included` is `false`. The node never signs or
  publishes an envelope for such a block, and the proposer-signed
  self-build envelope is refused for it, since its `builder_index` differs from
  the bid's.
- **Why:** gossip and API bids need only a pool and the gossip rules. A builder
  API client is a separate crate with its own failure modes and timeouts, and
  is left for a later phase.

## Fee recipient and gas target come from proposer preferences, with fallbacks

- **The specification:** the payload is built toward the `target_gas_limit` of
  the proposer's `SignedProposerPreferences`, which also names the fee
  recipient builders must pay, and `bid.gas_limit` must be compatible with the
  target (`is_gas_limit_target_compatible`).
- **ethlambda:** the self-build reads the signed preferences for
  `(slot, dependent_root)` that name the proposer, from gossip or the Beacon API.
  The fee recipient is theirs, else `prepare_beacon_proposer`'s, else zero with
  a warning. The target gas limit is theirs, else the `gas_limit` of
  `latest_execution_payload_bid` of the state being built on, so the execution
  client holds the gas limit where it is.
- **Equivalence:** the bid is built from the payload the execution client
  returns, so `bid.gas_limit` is whatever that payload carries and is always
  consistent with the block. A proposer that wants the limit to move without
  preferences cannot say so through this node: it follows the previous block's.

## Bid and preference gossip never queues

- **The specification:** several rules say the message "MAY be queued": an
  unknown parent block, an unimported parent, an unseen dependent block.
- **ethlambda:** every one of them is IGNORE. A bid or preferences message that
  names a block or state this node lacks is dropped, never parked, so a burst
  of them holds no memory and nothing is replayed later.
- **Why:** both topics are only useful for the next slot or two, and a bid that
  arrives after its parent was imported would be stale by the time a replay ran.
  A proposer that missed a message builds locally.

## Bid gossip judges against the recorded head and cached states

- **The specification:** `validate_execution_payload_bid_gossip` reads
  `get_head(store)`, `store.block_states[parent]` and the parent state advanced
  with `process_slots` to the bid's slot.
- **ethlambda:** the head node is the one the chain actor recorded
  (`Store::head` and `head_payload_status`), with a fresh `get_head_node` walk
  only when no status is recorded. The dependent root is read from the parent
  state's `block_roots`, which the lookahead rule keeps in range. The parent
  state stands in for the advanced one when the bid is in the parent's own
  epoch, since gloas's `process_slot` touches none of `builders`,
  `finalized_checkpoint`, `builder_pending_*`, `fork` or
  `latest_execution_payload_bid`, which are all the later rules read. Across an
  epoch the cached `CheckpointState` of the bid's epoch is used and filled, the
  same entry attestation target states use. A state that is not cached is
  IGNORE and is never rebuilt from disk.
- **Why:** gossip verdicts are waited on by gossipsub, and the state cache holds
  32 states, so a spec-literal read of a parent about an epoch old would miss
  often. The head record and the equivalence above give the same verdict
  without a replay.

## Known execution payloads are gossip-accepted or self-published envelopes only

- **The specification:** `seen.execution_payloads` holds a payload for every
  envelope accepted from gossip.
- **ethlambda:** the known payloads are the market's, a 256-entry LRU filled by
  envelopes that passed gossip validation and by envelopes this node publishes
  (gossip never echoes a node's own messages). They are not persisted, and an
  envelope that was queued and verified later, or fetched by request and
  response, does not count. After a restart bids on a pre-restart payload are
  IGNORE until new envelopes arrive.
- **Exception:** a pre-gloas parent's own payload counts as known, with its
  execution payload header's gas limit, see the fork boundary entry below.

## Proposer preferences are judged off cached states only

- **The specification:** the lookahead is read from
  `store.block_states[dependent_root]` advanced to the epoch before the
  proposal's.
- **ethlambda:** the cached head state is used when it shares the dependent root
  and is in the epoch before the proposal's or the proposal's own (the whole
  canonical case), else the cached `CheckpointState` of the epoch before the
  proposal's, else IGNORE. Nothing is rebuilt from disk.
- **Why:** a dependent block about an epoch old is usually out of the 32-state
  cache, so reading it would IGNORE most honest preferences.

## The fulu-to-gloas boundary for bids and preferences

- **The specification:** says nothing about a parent that is not a gloas block.
- **ethlambda:** a pre-gloas parent's payload counts as known, with its header's
  `gas_limit`. A pre-gloas head's payload hashes come from its payload header,
  and a bid is compatible with it when it builds on that head and its payload.
  The builder-exit check is skipped for a pre-gloas parent, which carries no
  envelope.
- **Preference signatures** are accepted under the lookahead state's own
  `DOMAIN_PROPOSER_PREFERENCES` domain (the specification's), the fork version of
  the epoch before the proposal's, or the proposal epoch's. They coincide outside
  the first epoch of a fork. Lighthouse signs with the proposal epoch's version
  and the specification gives the earlier one, so accepting both avoids
  rejecting an honest client's messages around the gloas upgrade.
- **Consequence:** builders onboarded at the fork are inactive until their
  deposit epoch is finalized, so gossip bids are rejected for the first epochs of
  gloas and `produceBlockV4` self-builds.

## Beacon API answers for bids and preferences

- **An IGNORE verdict is a `400`,** the same as a REJECT, because the API has no
  separate status for it. The message names the verdict and the reason, such as
  `ignore: preferences_unseen`.
- **An identical resubmission is a `200`** and is not published again.
- **The prose and the rules disagree** on a mismatched fee recipient or gas
  limit: the Beacon API text says the bid is rejected, while consensus-specs
  IGNOREs it. ethlambda follows consensus-specs.
- **`Eth-Consensus-Version` may be absent** on the bid and preferences posts. If
  present it must name a gloas-compatible fork.

## No minimum bid increment or rate limit

- **The specification:** a note says implementations SHOULD guard against
  builders spamming bids with minimal increments, for example with a minimum
  threshold or by forwarding only the best bid at intervals.
- **ethlambda:** neither is implemented. Spam is bounded by one bid per builder
  per `(slot, parent_hash, parent_root)`, a strictly higher value than the best
  seen, a funded active registered builder with a valid signature, a cap on keys
  per slot and on bids pooled per parent, and a separate permit pool for
  validating them. A configurable minimum increment is a follow-up.

## `skip_randao_verification` is ignored

- **The specification:** `produceBlockV4`'s `skip_randao_verification` lets a
  caller skip the node's check of `randao_reveal`; when it is set, the reveal
  must be the point at infinity.
- **ethlambda:** the parameter is accepted and not honored. The block's state
  root comes from running it through the state transition, which verifies the
  reveal, so the endpoint checks the reveal against the slot's proposer up front
  and answers `400` (`invalid randao_reveal`) for one that does not verify,
  infinity included.
- **Consequence:** a caller cannot get a block without a real reveal. Every
  caller this client knows of (including its own validator client) sends one.

## A pre-gloas head counts as FULL in `attestation_data.index`

- **The specification:** at a gloas slot `data.index` is `0` when the attested
  block is from the attestation's own slot, and otherwise `0` for an `EMPTY` and
  `1` for a `FULL` payload status in the validator's fork choice. It does not say
  which a pre-gloas block is.
- **ethlambda:** at a gloas slot `data.index` is `0` when the head block is from
  the requested slot, `1` when fork choice holds the head's payload as FULL
  (`Store::head_payload_status`, or one `get_head_node` walk when none is
  recorded), and `1` for a pre-gloas head, the same boundary rule
  [fork choice applies](#the-fulu-to-gloas-fork-choice-boundary). So the first
  gloas slots vote for the last fulu block's payload.
- **Why:** the vote should name the node fork choice itself walks to, and
  that rule makes a pre-gloas block's one node FULL.

## `payload_present` is judged by the envelope's arrival time

- **The specification:** a PTC member sets `payload_present` when it has
  received the block's envelope by `get_payload_due_ms()` into the slot.
- **ethlambda:** `GET payload_attestation_data` compares the time the envelope
  reached the node (`Store::beacon_envelope_seen_ms`, recorded by the chain
  actor from the arrival time of the envelope, not the time it finished
  verifying; the earliest arrival wins) with the slot's start plus
  `get_payload_due_ms()`. An envelope held for its block or columns is
  therefore judged by when it came, as the rule intends. The record lives in
  memory only, pruned with the execution block hash cache.
- **Consequence:** a restart forgets it. Only the slot in flight can be wrong
  (a member asked after a restart answers `payload_present = false` for an
  envelope that arrived before it), and the next slot's record starts fresh.

## `/eth/v1/node/identity` reports no ENR

The endpoint's `enr`, `p2p_addresses` and `discovery_addresses` are empty
rather than populated, which is not spec-valid.

- **ethlambda:** `get_identity` (`crates/net/rpc/src/beacon/node.rs`) reports
  `peer_id` and a placeholder `metadata` block and nothing else. The ENR is
  built for discv5 and owned by the P2P actor; `BuiltSwarm` hands `run_node`
  only a `local_peer_id`, so serving the record means widening the
  `ethlambda-p2p` surface and threading it through startup.
- **Beacon API:** `enr` is the node's base64 ENR and the two lists are its
  libp2p multiaddrs.
- **Consequence:** a consumer reading `enr` to dial this node gets an empty
  string rather than a record, so peer discovery through this endpoint does not
  work. Everything that reads `peer_id` is unaffected. Out of scope for the
  change that added the Beacon API surface; a follow-up exposes the record.

## Sync duties are not served for a period before the head's

`POST /eth/v1/validator/duties/sync/{epoch}` refuses a period before the head
state's own with a `400`. Later periods follow the wall clock, as the Beacon
API defines: up to the clock's current period plus one, read from the head or,
when the head lags a period boundary, from a copy advanced across it.

- **Beacon API:** allows any period up to the current one plus one, so an
  earlier period is valid to ask about.
- **ethlambda:** the head state carries only `current_sync_committee` and
  `next_sync_committee`. Answering an earlier period means loading the state
  at the start of that period, which is what Lighthouse does; Prysm also
  serves it. A validator client only asks about the current and next period,
  so this refuses rather than add a historical state lookup to a duty
  endpoint (`sync_duties`, `crates/net/rpc/src/beacon/validator.rs`).

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

## The inactivity-leak check runs once per epoch step, not once per validator

A state whose finalized checkpoint is past its previous epoch fails epoch
processing here even where the specification never reaches the failing check.

- **ethlambda:** `get_finality_delay`
  (`crates/blockchain/state_transition/src/beacon/helpers/finality.rs`) returns
  `ArithmeticOverflow` when `previous_epoch - finalized_checkpoint.epoch`
  underflows. From altair on, the inactivity-score update and
  `RewardContext::new` read the leak flag once, before their loop over
  validators, so either fails whenever the delay does. altair's
  `get_inactivity_penalty_deltas` also builds a `RewardContext`, so it fails
  too. phase0 reads the flag where the specification does.
- **consensus-specs:** the subtraction is the same, and a `uint64` underflow
  makes the transition invalid. But `process_inactivity_updates` and
  `get_flag_index_deltas` call `is_in_inactivity_leak` inside their loops, for
  eligible (and, for rewards, participating) validators only, and altair's
  `get_inactivity_penalty_deltas` never calls it. A state where no validator
  reaches the check passes.
- **Consequence:** none on a real chain. Justification only finalizes an epoch
  behind the current one, so the finalized epoch never passes the previous
  epoch, and only a crafted pre-state tells the two apart. Lighthouse reads
  the leak once per epoch as well (`process_epoch_single_pass`), failing on the
  same `safe_sub`. The randomized equivalence tests keep the finalized epoch
  behind the previous one for this reason: past it, the fast path and the
  specification-shaped reference fail at different points.

## The fulu-to-gloas fork-choice boundary

The gloas fork-choice text describes only a store anchored at a gloas block, so
it says nothing about a tree that crosses from fulu into gloas, which is the
tree every live follower holds at the fork epoch.

- **The specification:** `get_parent_payload_status` reads the parent block's
  execution payload bid, which a fulu parent does not have. Consensus-specs
  issue #5096 asked what a pre-gloas parent should answer and was closed as
  not planned. Pull request #5125 is open, as of this writing, and proposes
  `PENDING`.
- **ethlambda:** a pre-gloas block is a single node whose payload status is
  `FULL`, since its payload ran inside the block and never had an empty branch.
  Concretely, `get_parent_payload_status` of a gloas block with a pre-gloas
  parent answers `FULL`; a pre-gloas block's only child (`get_node_children`) is
  its `FULL` node; a vote for one (`get_supported_node`) supports that node
  whatever its `payload_present` says; and `gloas_get_ancestor` stepping onto
  one lands on `FULL`. Its payload also counts as verified, timely and available
  (`is_payload_verified`, `payload_timeliness`, `payload_data_availability`), so
  the first gloas block passes `on_block` and an `index == 1` vote for the last
  fulu block passes `validate_on_attestation`.
- **Which rules the head uses:** `get_head_node` runs one bottom-up walk for
  every fork, and the current slot's fork, not the head block's or the
  justified checkpoint's, selects its two fork-dependent rules. From
  `GLOAS_FORK_EPOCH` on, blocks carry the payload dimension their bids give
  them and the proposer boost is gated by `should_apply_proposer_boost`; before
  it, every block is a single full node and the boost applies whenever it is
  set. `compute_head` and `gloas_get_head` are the references the walk is
  tested against.
- **Other clients:** Lodestar and Prysm also treat a pre-gloas parent as
  `FULL`. Lighthouse (v8.2.2) answers `EMPTY` for a pre-gloas parent, although
  #5125 describes its handling as `PENDING`.
- **Consequence:** if #5125 lands, only the answers above change, and each is
  named in the header comment of `fork_choice.rs`'s gloas section.

## The gloas head tolerates state the specification asserts on

Three places in the gloas head read something the specification would abort on,
because a live node holds gaps a fixture tree never has. Each is marked
"Implementation choice, not spec text" at its definition. The head the node
runs is `walk_head` (through `get_head_node`) over the weights of
`compute_node_weights`; the spec-literal references carry the same tolerances so
that the tests compare like with like.

- **Pruned votes** (`compute_node_weights`; in the references,
  `get_attestation_score`, and through it `is_head_weak` and
  `is_parent_strong`, the latter reached from `get_proposer_head`). A vote
  for a root missing from the block index contributes nothing, where
  `get_ancestor` would raise. Pruning removes only entries below the finalized
  slot, and every root scored is indexed at or above it, so such a vote cannot
  descend from the scored root and the specification's own contribution for it
  is zero too.
- **Unknown voters** (`compute_node_weights`; `gloas_get_attestation_score` in
  the reference). A vote for a root the store never held is skipped, where
  `get_supported_node` would raise, so one stale voter cannot abort a head
  computation. The walk drops a block pruned from the index but still in the
  store the same way, with the pruned votes above; the reference does not skip
  it, and its vote walks the block table and contributes nothing.
- **Missing timeliness** (`should_apply_proposer_boost`). A candidate with no
  `block_timeliness` entry reads as not timely by either deadline, where the
  specification indexes the entry directly. A gloas block's entry is persisted
  (`Table::BlockTimeliness`) and reloaded on resume; a pre-gloas block's is in
  memory only, so a restart empties it. The reading can only miss withholding a boost from an
  early equivocation, never withhold one wrongly.
- **Equivalence:** each is the specification's answer wherever the specification
  has one; they differ only where it would have raised.

## The envelope check reads the cached state root

`verify_execution_payload_envelope` compares `envelope.beacon_block_root` with
the root of the state's latest block header.

- **The specification:** sets `header.state_root = hash_tree_root(state)` on a
  copy of the header. That is exact for a state fresh out of block processing,
  whose `latest_block_header.state_root` is still zero.
- **ethlambda:** uses `BeaconState::compute_state_root`. The function's caller
  hands it a stored state, and this repository writes the real root into that
  header field as soon as the block's transition returns. Hashing such a state
  would hash a header whose `state_root` is already set, a different value from
  the one the header committed to, and every stored state's envelope would fail.
  `compute_state_root` returns the cached value only while the state is still
  at that block's slot and the field is set, and hashes otherwise, so both
  shapes give the same root.
- **Equivalence:** the same check, on both kinds of state.

## The attestation deadline takes the epoch that picks the fork's rule

- **The specification:** `get_attestation_due_ms()` takes no argument, and
  gloas replaces it with a function that reads `ATTESTATION_DUE_BPS_GLOAS`.
- **ethlambda:** one `get_attestation_due_ms(epoch, config)`
  (`fork_choice.rs`) that reads the basis points of the fork `epoch` falls in
  (`ForkRules::of`), so both sides of the fulu-to-gloas boundary share it.
- **Equivalence:** the same deadline for every slot, since the epoch is the
  one the specification's own per-fork function would have been selected for.

## The head is one bottom-up walk, not the specification's per-node `get_weight`

The specification's gloas `get_head` calls `get_weight` for every candidate
node, and each call walks every latest message and every ancestor step.

- **ethlambda:** `get_head_node` computes every node's attestation score in one
  pass over the latest messages and one over the blocks (highest slot first),
  folding each block's total into the payload node of its parent that it builds
  on, then descends from the justified checkpoint over that table. The proof
  that the fold equals `get_attestation_score` for every node, from
  `is_ancestor`'s definition, is in the `fork_choice.rs` section "The head
  computation". The proposer boost is added along the boosted block's chain
  after `should_apply_proposer_boost` has read the parent's score from the same
  table, so that gate no longer re-walks the votes either.
- **Few decodes:** a block's fork and parent payload status are recorded as a
  `BlockPayloadLink` when `on_block` imports it, and the head's slot reads
  come from the block index, so a head computation decodes no block in the
  ordinary case. Two cases still decode. A block imported before a restart has
  no entry (the scratch is in memory), and the walk derives it once by
  decoding the block and its parent and records it; the actor does the same for
  each new finalized root before pruning links. And a weak boosted-block parent
  from the previous slot scans same-slot candidates for an early equivocation,
  which needs their proposer indexes; that scan is rare and bounded by the
  candidates at one slot.
- **Bounded at the finalized block:** vote placement, the fold and the boost
  chain stop at the least of the finalized block's slot, the justified block's
  slot and the boosted block's parent's slot, which on a live node is the
  finalized block's. The other two terms make the bound safe without assuming
  that the justified block and the boosted block's parent are at or above the
  finalized block. The block index of a beacon store is never pruned, so
  without the bound each head computation would fold, and read the link of,
  every block since the anchor. Links below the finalized block are pruned
  because nothing reads them.
- **Cost:** work is proportional to the latest messages plus the indexed
  blocks at or above the finalized block, the unfinalized window. The
  spec-literal form is proportional to the messages times the
  candidate nodes, with block decodes at each ancestor step and for each voter,
  which would wedge the chain actor on a large tree.
- **Equivalence:** the walk names the head and gives every node at or above the
  finalized block the weight the specification's `get_head` and `get_weight`
  do, wherever they do not raise; the tolerances above are the only
  differences. The fixture harness checks the head at every `head` step and
  every viable leaf's weight, and a seeded randomized test checks both over
  trees that cross the fork boundary.
- **Why still tested against the spec-literal form:** `gloas_get_head` and
  `gloas_get_weight` remain, as the references the walk is compared with, at
  every `head` check of every fork-choice fixture and on randomized trees;
  `compute_head` is the pre-gloas reference.

## The execution client judges a gloas payload before the envelope is applied

`verify_execution_payload_envelope` asks the execution engine last, as part of
one boolean function. The follower runs the pure consensus checks first
(`check_execution_payload_envelope`: signature, bid, state, data availability),
then asks the engine with `engine_newPayloadV5` only about an envelope that
passed them, and records it with `accept_execution_payload_envelope`. The
engine's part is answered "valid" inside the checks because its answer has
three outcomes and the specification's `ExecutionEngine` has two.

- **`VALID`:** applied; the payload is recorded `VALID`.
- **`SYNCING` / `ACCEPTED`:** applied, since the consensus checks passed and the
  payload is `NOT_VALIDATED` (`optimistic-sync.md`); recorded `SYNCING`, which
  the attestation gossip rules already read as not yet validated. A later
  `forkchoiceUpdated` `VALID` for the head, or for a descendant payload, moves
  it and every optimistic payload on that chain to `VALID`. Unlike a pre-gloas
  block there is no `is_optimistic_candidate_block` gate: a payload is applied
  to a block the consensus layer already imported, so there is no
  merge-transition poisoning to guard against.
- **`INVALID`:** not applied, so the FULL node of the block never exists; the
  payload is recorded `INVALID`, children held for it are dropped and later
  blocks that name it as their FULL parent are dropped instead of held. The
  block itself and its EMPTY branch stay. `latestValidHash` can reach further
  back, in which case the first payload after it is condemned the same way
  (`beacon_payloads::resolve_invalid_payload`, which skips blocks that carry no
  payload, unlike the pre-gloas `resolve_invalid_block`). A `forkchoiceUpdated`
  `INVALID` for a payload already applied removes it again (its FULL node, its
  stored envelope, and every child built on it).
- **A hash mismatch (`INVALID_BLOCK_HASH`, or `INVALID` with a null
  `latestValidHash`):** the envelope's contents do not hash to the block hash it
  claims, so only that envelope (by its own root) is refused; the root's
  payload is not condemned, since the builder's real envelope may still arrive.
  ethrex has no `INVALID_BLOCK_HASH` status: it answers a block hash mismatch
  with `INVALID` and a null `latestValidHash`, and an executed-and-failed
  payload with `INVALID` and its last valid ancestor. So a null one is read as
  a mismatch and a non-null one as the payload being invalid. A payload that
  failed with no valid ancestor to name is read as a mismatch too, which only
  costs a refused envelope.
- **No answer after the retry ladder:** the payload is not applied, as for a
  block, but unlike a block the envelope is consensus-valid and already held,
  so it is kept and the per-slot redrive asks again, about the oldest held
  envelope only and the rest once that ask is answered, so a down client costs
  one retry ladder per slot however many wait. It is not fetched again:
  that would repeat the ladder for every copy that arrives.

`latestValidHash` and `VALID` follow the execution-layer chain, not every
verified ancestor: a gloas block's EL parent is the ancestor whose payload hash
is its `bid.parent_block_hash`, skipping blocks it built past on their EMPTY
node, and a pre-gloas block's is its parent. Both walks stop at finality.

## `forkchoiceUpdated` for a gloas head

- The head hash follows the head node: `bid.block_hash` for a FULL head,
  `bid.parent_block_hash` for an EMPTY one. A head whose payload status has not
  been computed yet is skipped.
- `finalized_block_hash` is the finalized block's `bid.parent_block_hash`, as
  the specification has it.
- `safe_block_hash` is the justified block's `bid.parent_block_hash`. The
  specification's `get_safe_execution_block_hash` is built on fast
  confirmation, which the follower does not run, so this is the fallback. It
  can only be older than the confirmed block, which keeps it safe.
- A pre-gloas checkpoint block, including one beneath a gloas head, keeps its
  own payload hash.
- The call is V4 with the node's custody columns when the head block is gloas,
  and V3 before; `engine_newPayloadV5` is for envelopes and V4 for pre-gloas
  blocks.
- A hash of zero is "nothing to say" on either fork, so a payload whose hash is
  zero (the fixtures' placeholder) sends no `forkchoiceUpdated`.

## Sync committee gossip resolves the committee by the message's slot and the domain by the fork schedule

`sync_committee_{subnet_id}` and `sync_committee_contribution_and_proof`
validate against the cached head state, choosing the committee from the
message's slot and the signing domain from the config's fork schedule.

- **Specification:** `p2p-interface.md`'s `get_sync_subcommittee_pubkeys` and
  `validator.md`'s `compute_subnets_for_sync_committee` pick the committee by
  `state.slot + 1`, and `get_domain(state, ..)` takes the fork version from
  `state.fork`.
- **ethlambda:** the committee is chosen by `message.slot + 1`
  (`current_sync_committee` in the head's own period, `next_sync_committee` in
  the one after), and the domain comes from `Config`'s schedule
  (`helpers::sync_committee`). The validator client signs with the same
  domain. When the head is in the message's period and fork the answer is the
  specification's. When it lags across a period or fork boundary, the
  specification would reject honest messages and this does not.
- **Unanswerable cases are IGNORE:** a head state that is not cached is
  `IGNORE` (`state_unavailable`), like every other topic, and a period the head
  state's two committees cannot cover is `IGNORE sync_committee_unavailable`,
  since neither is the sender's fault.

## Sync committee subnets are joined on request, immediately, and advertised in MetaData only

- **Specification:** `validator.md` ("Sync committee subnet stability") has a
  validator join its subnets a random 1 to `SYNC_COMMITTEE_SUBNET_COUNT` epochs
  before its period starts, and has the node advertise them in the ENR's
  `syncnets`.
- **ethlambda:** a subnet is joined only when a validator client posts
  `POST /eth/v1/validator/sync_committee_subscriptions`, at once, until
  `until_epoch` (exclusive) clamped to the end of the next period. The node
  never subscribes without a request, because validating every subnet would
  cost each follower up to `SYNC_COMMITTEE_SIZE` BLS verifications a slot.
  `syncnets` appears in MetaData, never in the ENR: ethrex's `DiscoveryServer`
  cannot replace the served record at runtime, the same known gap as the
  `eth2` entry. Peers therefore find this node's sync subnets by chance, while
  publishing still reaches the mesh, because a joined subnet is subscribed.
- The `sync_committee_contribution_and_proof` topic is the exception: it is
  subscribed under every digest and always validated, and accepted
  contributions are relayed and pooled for block production.

## Block production packs only the parent's sync committee votes

`validator.md` ("Sync committee") describes block packing in terms of
contributions only.

- **ethlambda:** a block at slot `N` packs only what is pooled for
  `(N - 1, parent_root)`. For each subcommittee it takes the best pooled
  contribution and adds every pooled direct message at a position that
  contribution does not cover. The result is verified exactly as
  `process_sync_aggregate` will check it
  (`block_production::verified_sync_aggregate`); a failure, or a proposer
  whose parent is not the root the committee signed, gets the empty aggregate.
  Every "retry without operations" fallback also drops it. That costs rewards,
  never the block.
- Messages from earlier slots over the same root are not packed.

## The validator client signs a sync committee message at the deadline only

`validator.md` ("Prepare sync committee message") has a member sign as soon as
it sees the block for the slot, or at the sync-message deadline, whichever
comes first. The validator client signs once, at the deadline
(`SYNC_MESSAGE_DUE_BPS`, or its gloas variant), over the head root it then
reads, and refuses to when that root is optimistic
(`specs/bellatrix/optimistic-sync.md`).
