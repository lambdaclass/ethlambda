# The execution layer pairing

`ethlambda beacon` follows the Ethereum Beacon Chain. A beacon block carries an
execution payload that consensus cannot validate on its own: only an execution
client can say whether the transactions in it are valid and whether the state
root they produce matches. This page describes how the follower asks, what it
does with each answer, and what it does not yet do.

The consensus rules implemented here are
[`specs/bellatrix/optimistic-sync.md`](https://github.com/ethereum/consensus-specs/blob/master/specs/bellatrix/optimistic-sync.md)
and the `verify_and_notify_new_payload` half of each fork's `process_execution_payload`.
The wire is
[`execution-apis/src/engine`](https://github.com/ethereum/execution-apis/tree/main/src/engine).

## Which methods, and why so few

Seven:

| Method | Introduced | Why |
|---|---|---|
| `engine_newPayloadV4` | prague | Validate one block's payload |
| `engine_newPayloadV5` | amsterdam | Validate the payload a gloas envelope reveals |
| `engine_forkchoiceUpdatedV3` | cancun | Say where the head, safe and finalized blocks are |
| `engine_forkchoiceUpdatedV4` | amsterdam | The same, from a gloas head on; also carries the node's custody columns |
| `engine_exchangeCapabilities` | common | Startup handshake |
| `engine_getClientVersionV1` | identification | Log what the execution client is |
| `engine_getBlobsV2` | osaka | Rebuild a held fulu block's custody columns from the execution client's blob pool |

Osaka introduces **no new `newPayload`**. Its own document adds only
`engine_getPayloadV5` and `engine_getBlobsV2`/`V3`, of which this node calls
`engine_getBlobsV2` (see [Blobs from the execution client](#blobs-from-the-execution-client)); `engine_newPayloadV5` belongs
to Amsterdam, where gloas's envelope import uses it. So the Osaka-current call for a payload is prague's V4, and the
Osaka-current fork choice notification is cancun's V3. Amsterdam's pair (newPayload V5, forkchoiceUpdated V4) is
used from gloas on; the startup handshake warns when the execution client does not advertise either, but only on a network whose schedule includes gloas.

Two method families a full client would have are deliberately absent:

- **`engine_getPayload*` outside block production.** The follower asks an
  execution client to build only for a proposal of a validator client it
  serves (for every slot's proposer with `--always-prepare-payload`), so the
  `forkchoiceUpdated` calls that follow its head carry `null` payload
  attributes. Block production for a validator client
  (`produceBlockV3` for fulu, `produceBlockV4` for gloas) does:
  `forkchoiceUpdatedV3` with `PayloadAttributesV3` then `engine_getPayloadV5`
  before gloas, and `forkchoiceUpdatedV4` with `PayloadAttributesV4` (V3's fields
  plus `slotNumber` and `targetGasLimit`, the parent bid's gas limit) then
  `engine_getPayloadV6` (`ExecutionPayloadV4`, with `blockAccessList` and
  `slotNumber`) from gloas on. The handshake warns when a gloas network's
  execution client does not advertise `engine_getPayloadV6`. The chain actor
  sends that `forkchoiceUpdated` with attributes a third of a slot ahead, for
  a proposer a validator client registered (every proposer with
  `--always-prepare-payload`), with the same safe and finalized hashes as the
  head's own update, and block production collects the build with
  `getPayload`; see the `payload_attributes` event in [`rpc.md`](rpc.md).
- **`engine_getPayloadBodies*`.** Nothing consumes them.

Blocks before electra are not asked about at all. This node checkpoint-syncs onto
a chain far past bellatrix, capella and deneb and never imports one of their
blocks, and `engine_newPayloadV4` would refuse their payloads as an unsupported
fork anyway. Supporting them would mean carrying V1 through V3 as well, for
chains this follower cannot reach.

## Where the call sits

```
process_block (beacon arm)
  │
  ├─ data availability gate ────────────► held, if a custody column is missing
  │
  ├─ engine_newPayloadV4  ◄── this page
  │
  └─ fork_choice::on_block(…, payload_validity)
        │
        ├─ state_transition, with the engine derived from the verdict
        └─ record the block's execution hash and its optimistic status
```

This diagram is the pre-gloas path. A gloas block carries no payload, only a
builder's bid, so nothing is asked about it at import; the question moves to the
envelope that reveals the payload (see [Gloas](#gloas) below).

The order is the specification's own: `is_data_available` runs before
`state_transition`, so a block about to be held for its custody columns is never
one this node asks an execution client about.

Every field of the request is a pure function of the block:
`parent_beacon_block_root` is `state.latest_block_header.parent_root`, which
after `process_block_header` is the block's own `parent_root`, and the other
three are body fields. That is what lets the round trip happen *outside* the
state transition, so the state transition itself stays synchronous while the
import cascade above it is `async`.

The verdict then reaches `state_transition` as an `ExecutionEngine`: an
`INVALIDATED` answer makes `verify_and_notify_new_payload` return false and the
transition fail from inside `process_execution_payload`, which is where the
specification puts that failure. The transition is run even when the verdict is
already `INVALIDATED`, which costs one merkleization on a path that should never
run and buys the failure arriving where a reviewer checks this code against the
specification.

### The transition runs while the answer is in flight

With an execution client, `process_block` does not wait idle for the answer. It
builds the request on the actor (copying only the payload, never the block),
sends it from a spawned task so the HTTP exchange keeps progressing, and runs
`fork_choice::speculate_transition` on the actor meanwhile: the block's state
transition against its parent's post-state, with the engine assumed valid. The
import then costs `max(engine wait, transition)` instead of their sum. Every
block's transition is computed this way, ahead of `on_block`: one with no
request to send (no execution client, pre-merge, gloas) runs it on its own,
and its `PayloadValidity::NotRequired` verdict always lets it stand in.

That needs the spawned task to run on another thread while the actor computes,
and in the node it does: the chain actor runs on `Backend::Thread`, whose thread
blocks on a multi-thread tokio runtime of its own, and the task runs on that
runtime's workers. On a current-thread runtime (a `#[tokio::test]` calling
`process_block` directly) the request only leaves at the `await`, so the two add
up again: the same result, without the gain.

Why that is the transition `on_block` would run: `on_block` derives the
`ExecutionEngine` from the verdict in one place, `invalid()` for `INVALIDATED`
and `valid()` for `NOT_REQUIRED`, `VALID` and optimistic alike, and the
transition reads nothing else off the store except content-keyed caches. What
keeps it harmless:

- A block `on_block` would refuse before its own transition gets no
  speculation: one already imported, a gloas block whose parent's full payload
  is not verified, one from the future, one at or before the finalized epoch's
  first slot, or one whose parent is off the finalized chain.
  `speculate_transition` runs the same guard functions `on_block` does
  (`check_parent_payload`, `check_timely_and_on_the_finalized_chain`) before
  transitioning anything. A block fetched over req/resp carries no
  gossip-checked signature, and the transition checks the signature only after
  advancing the parent's state to the block's slot, so without this such a
  block could make the actor run that advance where `on_block` would have
  refused it for free.
- The result is a local value (`SpeculativeTransition`). The block, its
  post-state and its fork choice records reach neither the store nor the network
  until `on_block_speculative` accepts it, and that runs every check `on_block`
  makes, unchanged and in the same order. Computing it can write two cache
  entries, both keyed by a checkpoint: an epoch-crossing block's boundary
  balances, built from the parent's state alone, and an epoch's first block's
  own checkpoint balances, built from its post-state. Both are entries
  `on_block` would write, and right whatever becomes of the block; for one that
  never imports (an `INVALID` verdict) the second is an entry nothing reads, in
  a bounded cache.
- The argument above rests on the actor handling one message at a time, which
  no type enforces. Builds with debug assertions (the test suite's
  `release-fast` among them) therefore run the transition again whenever a
  speculation is used and panic unless both agree on the outcome and the
  post-state root.
- It stands in for the transition only when it was computed for this block's
  root and parent root and the verdict is not `INVALIDATED`. For `INVALIDATED`
  it is dropped and `on_block` recomputes with `invalid()`, so the invalidation
  path is the one described above, unchanged. The decision is
  `SpeculativeTransition::stands_in_for`, which compares the speculation's
  engine with `PayloadValidity::execution_engine`, the function `on_block` picks
  its own engine with, and the actor counts `used` with that same call.
- A block that ends up held (no verdict, or `SYNCING`/`ACCEPTED` for a block
  that is not an optimistic candidate) drops it. The attempt is counted in
  `lean_engine_speculation_total{outcome}`.
- A panicked or cancelled request task holds the block too, since there is no
  verdict, but it is a fault in this node rather than in the execution client:
  it is logged as an error and is not counted in `lean_engine_no_verdict_total`.
- The request task is aborted if the import is dropped before the answer is
  read, so an abandoned import never leaves a request running out its retry
  ladder.
- Reading the parent's state for the speculation never panics the actor: a
  storage error there skips the speculation, and `on_block` meets the same error
  on its own lookup.

The overlap shows in the import timing tree: the transition that ran during the
round trip is reported under `stf` (used or discarded), and `engine` reports only
what the question cost beyond it: building the request (a copy of the
payload) and the wait that was left once the transition finished, the request's
construction alone when the answer was already in. Without an execution client,
and for forks that have no request to send (pre-merge, gloas), nothing overlaps,
`engine` is zero, and the transition still runs ahead of `on_block`, on its
own. How long the execution client itself took to answer is
`lean_engine_new_payload_seconds{outcome}`, timed around every `engine_newPayload*`
request this module sends (`timed_new_payload`), a gloas envelope's included.

## The verdicts

`optimistic-sync.md` groups the five wire statuses into three outcomes:

| Wire status | Alias | What happens |
|---|---|---|
| `VALID` | | Imported. The block and every optimistic ancestor leave `optimistic_roots` |
| `SYNCING`, `ACCEPTED` | `NOT_VALIDATED` | Imported *if* `is_optimistic_candidate_block` allows it, and joins `optimistic_roots` |
| `INVALID`, `INVALID_BLOCK_HASH` | `INVALIDATED` | Not imported. `latestValidHash` decides how much of the branch dies with it |

A block in `optimistic_roots` carries normal fork-choice weight and can be the
head. That is the point of optimistic sync, and the `sync/optimistic` fixture
suite proves it: its one case, `from_syncing_to_invalid`, has a `SYNCING` branch
take the head from a `VALID` one on attestation weight, and then requires the
head to fall back when the `SYNCING` branch turns out to be invalid.

An invalidated block leaves fork choice by having its `LiveChain` index row
deleted. That is sufficient because `Store::block_index()` is the only block
source `filter_block_tree`, `compute_node_weights` and `walk_head` read: a root
with no row contributes no weight to any ancestor and can never be walked to.
The deletion also marks the store's cached fork-choice weights stale, so the next
head computation rebuilds them without the removed blocks. The block
and its state stay in their own tables, so an operator can still inspect what
was rejected.

That an `INVALIDATED` block is never imported is enforced on the verdict itself,
in `on_block`, not on the state transition having failed. The transition still
runs first, so the failure arrives from inside `process_execution_payload` where
the specification puts it and where the `sync/optimistic` fixture exercises it.
But it only fails there for forks that consult the `ExecutionEngine` at all:
bellatrix gates that step on `is_execution_enabled`, and phase0 and altair have
no such step, so on those a condemned block would otherwise transition cleanly.

### Optimistic roots

A block imported on `NOT_VALIDATED` is recorded in `optimistic_roots` against
its slot. An entry leaves on a later `VALID` (which clears the whole optimistic
prefix, per `optimistic-sync.md`'s "all *ancestors* of the block MUST also
transition") or `INVALIDATED` verdict, and, for the ones that get neither, on
finality: an execution client doing a long state sync answers `NOT_VALIDATED` to
every block, so without that bound the set would take one root per import for
the life of the process.

Besides `mark_validated`'s own ancestor walk, the Beacon API reads the set:
every `execution_optimistic` response field (see
[rpc.md](./rpc.md#execution_optimistic-under-gloas) for a gloas block's),
`is_optimistic` on `/eth/v1/node/syncing` and the `206` on
`/eth/v1/node/health` (both about the head only), and `attestation_data` and
`aggregate_attestation`, which answer `503` rather than hand a validator a
vote for a block the execution client has not validated (see
[`rpc.md`](rpc.md#validator-endpoints)).

### `is_optimistic_candidate_block`

A `NOT_VALIDATED` verdict is not enough on its own. The block must also either

1. have a parent this node has already recorded an execution hash for, or
2. be at least `--safe-slots-to-import-optimistically` behind the wall clock.

Condition 1 is `store.beacon_el_block_hash(parent_root).is_some()`: the
specification's `is_execution_block(parent)`, read off a cache of the parent's
payload hash rather than by decoding the block. The cache holds a hash for every
post-merge block the store has, and none for a pre-merge block (a zero payload
hash is not an execution block). It is filled at import, for the checkpoint
anchor when the store is built, and on resume for the unfinalized window.

The horizon guards against a poisoned *merge transition* block, whose parent hash
names an execution block nobody can produce. Once a node is on a post-merge chain
every block's parent has a recorded hash, so condition 1 carries each one and
condition 2 stops mattering.

The anchor is never imported and never asked about (see [The anchor is assumed
valid](#the-anchor-is-assumed-valid)), so its hash is cached when the store is
built; only the hash, not a verdict. That is what lets the first block after a
checkpoint-sync anchor take condition 1 even while the execution client is still
syncing and answers `SYNCING` to every `newPayload`. A restart empties the cache,
so resume rebuilds it from the stored blocks.

### `latestValidHash`

An `INVALID` answer names the last execution block that was valid. Resolving
which beacon block that condemns is a walk up the **rejected block's own
ancestry**, not a lookup in a global index, because the specification scopes it
that way: "the *child* of a block with
`body.execution_payload.block_hash == latestValidHash` **in the chain containing
the block with payload in question**". Two branches can share a parent whose
payload is the last valid one, and only the branch that was rejected may die.

| `latestValidHash` | Condemned |
|---|---|
| An execution hash found on this chain | The child of the block carrying it |
| All zeroes | The deepest indexed ancestor carrying a payload |
| `null`, or a hash not on this chain | The rejected block itself |

The last row is the specification's own instruction, not a convenience: "when
`latestValidHash` is a meaningful execution block hash but consensus engine
cannot find a block satisfying
`body.execution_payload.block_hash == latestValidHash`, consensus engine SHOULD
behave the same as if `latestValidHash` was `null`". A checkpoint-synced follower
meets this whenever the named block is below its anchor.

### The finality floor

A condemned root at or below the finalized checkpoint is refused: the log says
so and nothing is removed. Obeying it would delete every `LiveChain` row from
finality upward, after which `get_head` fails its "block_root in store.blocks"
check on every call and the node can only report that it cannot compute a head
until its database is rebuilt.

The all-zeroes row above is what reaches this without anyone naming a finalized
block: the walk it describes stops where the execution hash cache does, and that
cache is bounded by finality, so its deepest entry is the finalized block
itself. An execution client condemning finalized history means it and this node
disagree about what is final, which is an operator emergency rather than
something to resolve by emptying fork choice.

## Gloas

A gloas block commits to a builder's bid and the payload arrives later in a
`SignedExecutionPayloadEnvelope`, so the execution client judges the envelope,
not the block. The order differs from the specification's, which asks the engine
last inside one boolean function: the follower runs the pure consensus checks
first (signature, bid, state, data availability), and only an envelope that
passed them is sent to `engine_newPayloadV5`. That way an unsigned copy with the
honest block hash and a different body cannot earn an `INVALID` that lands on the
honest payload, and the engine never spends time on an envelope this node would
refuse anyway.

| Answer | What happens to the envelope |
|---|---|
| `VALID` | Applied; the payload is recorded `VALID` |
| `SYNCING`, `ACCEPTED` | Applied and recorded `SYNCING` (not yet validated); a later `forkchoiceUpdated` `VALID` promotes it |
| `INVALID` with a `latestValidHash` | The payload is invalid: not applied, so the block's FULL node never exists; the block and its EMPTY branch stay |
| `INVALID` with a null `latestValidHash`, or `INVALID_BLOCK_HASH` | The envelope's contents do not hash to the block hash it claims: only that envelope is refused, since the builder's real one may still arrive |
| no answer after the retry ladder | Kept (it is consensus-valid) and asked again once a slot |

The null-`latestValidHash` row exists because ethrex has no `INVALID_BLOCK_HASH`
status: it answers a mismatch with a null hash and an executed-and-failed payload
with its last valid ancestor. `latestValidHash` and `VALID` follow the execution
chain (each block's `bid.parent_block_hash`), not every verified ancestor, since
a block built past an ancestor's EMPTY node skips that ancestor's payload. The
details, and why each departs from the specification, are in
[spec_deviations.md](./spec_deviations.md#the-execution-client-judges-a-gloas-payload-before-the-envelope-is-applied).

With the engine down, the per-slot retry asks about the oldest held envelope
only and releases the rest once that ask is answered, so an unreachable client
costs one retry ladder per slot however many envelopes wait. This is the gloas
counterpart of the limitation below, and unlike a block the envelope is not
dropped.

## Blobs from the execution client

A fulu block is held until its custody data columns are stored. Gossip usually
delivers them within a fraction of a second, but the execution client may
already have every blob the block commits to, since the blob transactions went
through its pool first. The fulu p2p spec ("Distributed blob publishing using
blobs retrieved from local execution-layer client") says honest nodes SHOULD
ask `engine_getBlobsV2` on receiving a valid `beacon_block` or
`data_column_sidecar` from gossip, and turn a complete answer into data columns.
The code is `crates/blockchain/src/beacon_blobs.rs`.

**When it fires.** On the first data-availability hold of a block
(`hold_block_for_columns`), when all of these hold: the block is fulu, it
commits to at least one blob, `--execution-endpoint` is set, the block is at
most `MAX_ASK_AGE_SLOTS` (4) slots behind the store's clock, and it passes
`precheck_block` against its parent's post-state (expected proposer and
proposer signature). Any source qualifies (gossip, or a by-root answer). A
redelivery of a held root does not ask again.

The age bound is what keeps range sync out. Every block it delivers is older
than the slot it arrives in, and a catch-up holds them by the batch, so asking
for each would be an unbounded fan-out of prechecks on the chain actor, engine
calls and cell computations. Such a block's columns are asked of peers as soon
as it is held, so it does not wait for a redrive either way. How often the
execution client would still hold an older block's blobs is not measured.

The age bound limits which slots qualify, not how many blocks: a peer answering
by root can hand over any number of distinct roots for a recent slot. So an ask
is also admitted against a budget, before the precheck runs:
`MAX_ASKS_PER_SLOT` (4) per block slot, spent whether or not the precheck
passes, and `MAX_ASKS_IN_FLIGHT` (4) at once, held from the engine call through
the cell computation and the chain checks. That bounds the BLS verifications
this ask adds on the chain actor and the blocking-pool work a flood of roots
can buy. A root whose signature fails never gets that far: the import runs the
same precheck before it holds a block (`precheck_before_waiting`) and refuses
it instead. What reaches the budget was signed by the validator it names,
which past the parent state's proposer lookahead need not be the slot's
proposer (see below). The cost: such roots that arrive first can spend a
slot's budget before the genuine block, which is then left to gossip and the
peer asks, where a miss leaves it anyway. Skips are counted in
`lean_engine_get_blobs_skipped_total{reason}`.

The precheck is a filter, not the guard: the built columns go through every
chain check before they are published (see the build below). Since the import
ran it before the hold, it repeats a check the block has already passed, at one
more BLS verification per first hold of a block that would be asked about. It
cannot catch everything: past the parent state's proposer lookahead,
`precheck_block` checks the signature against whichever validator the block
names, not that this validator is the slot's proposer.

**The call.** One attempt with a 1 s timeout (`ENGINE_GET_BLOBS_TIMEOUT`, the
value `osaka.md` gives the method), outside the retry ladder. The call races
gossip delivery of the same columns, and a retry after the ladder's first
backoff would land after that race is decided. A miss leaves the block to
gossip and the per-slot peer asks, which is where it was anyway. The answer is
all-or-nothing: `null` means the execution client lacks at least one blob (or is
syncing), and counts as a miss.

**V2, not V3.** V3 answers partially, but a column holds one cell from every
blob, so a partial blob set builds no complete column, and this node has no
partial-column assembly.

**The build.** On a full answer, a blocking task first re-checks that the block
was not imported meanwhile and which custody columns are still missing from the
store, then builds only those (cells and sidecars) off the async runtime and off
the chain actor. Still in that task, the sidecars then go through the chain
checks a fetched column gets (`ChainPrechecks`, then one `kzg_verdicts` batch):
the signed header, including the expected proposer past the lookahead,
finalized ancestry, the inclusion proof, and the KZG proofs. Only the ones that
pass go on. The spec says a node SHOULD skip verifying blobs from its own
execution client; this one does not (see `docs/spec_deviations.md`).

**The hand-over.** The sidecars go to p2p through the existing
`check_data_column_sidecars`, with `SidecarOrigin::ExecutionLayer`. p2p runs no
checks of its own on that origin, since the chain actor's task ran them. p2p
records each column in the gossip seen cache first (so a
copy gossip delivers later is ignored, and a column gossip already accepted is
not published twice), publishes the newly recorded ones on their subnet topics
if and only if this node is subscribed to them, which here means its custody
columns, and forwards one batch to the chain actor. The chain actor stores the
columns and releases the held block through the usual completeness check.

One copy gossip delivers is not ignored: the identical column, received just
before and still in validation when the execution-layer copy is recorded.
Gossipsub put its message id in the duplicate cache on arrival, so our publish
of the same bytes was refused as a duplicate and sent nothing; ignoring the
gossip copy too would relay the column to no one. p2p remembers the message ids
it published (`engine_columns::PublishedColumns`), and a gossip verdict under
one of them keeps its `Accept`.

```
hold (1st, recent) -> engine_getBlobsV2       1 s, one attempt
                       |-- null / error  -> count; gossip and peer asks carry on
                       '-- every blob    -> build missing custody columns
                                            (block imported meanwhile? stop)
                                            chain checks, KZG included
                                            (refused -> count, drop)
                                                  |
                         check_data_column_sidecars(ExecutionLayer)
                                                  |
   p2p: seen cache -> publish on subscribed subnets -> forward one batch
                                                  |
   chain actor: store columns -> release the held block
```

**Trust.** Nothing the execution client returns is taken on trust. A blob that
is not the one a commitment names, or a wrong proof, fails the KZG batch, and
the columns built from it are counted in
`lean_engine_blob_columns_refused_total` and dropped: never published, never
recorded seen, never stored. That matters beyond peer score. A stored column
keeps every other copy of it out (gossip and the fetch checks answer
`AlreadyStored`), and block import trusts what is stored, so a column taken on
trust would either stop its block for good or import it on data nobody
verified. The block then waits for gossip and the peer asks, as on a miss. The
price is one KZG batch over the custody columns per hit, on the blocking pool,
before the columns are published.

**Not done.**

- No ask when a sidecar arrives, only on a block's first hold.
- Gloas: data availability moves to the payload envelope, so a held gloas block
  has no columns to fill this way.
- Partial columns (see V3 above).

**Metrics.**

| Metric | Reads |
|---|---|
| `lean_engine_get_blobs_total{outcome}` | Attempts: `hit`, `miss`, `error` |
| `lean_engine_get_blobs_skipped_total{reason}` | Holds not asked about, the ask budget spent: `slot_budget`, `in_flight` |
| `lean_engine_get_blobs_duration_seconds` | One round trip, whatever the outcome |
| `lean_engine_blobs_to_columns_seconds` | Cell computation plus sidecar build |
| `lean_engine_blob_columns_refused_total{reason}` | Built columns the chain checks refused, by rule (`kzg`, `wrong_proposer`, ...); any of these points at the execution client or a forged block |
| `lean_data_columns_from_execution_layer_total{result}` | What p2p did with each column: `published`, `no_digest`, `already_seen`, `not_custody` |

A high `miss` rate means the execution client's pool does not have the blobs.
That is normal while the execution client is syncing.

## `forkchoiceUpdated`

Sent once after every head recompute, which is once per import cascade and once
per tick, not once per block. It is sent even when nothing moved: an execution
client doing state sync needs to keep being fed a recent head or its sync cannot
converge.

Its three hashes come from the cached execution hash of the head, the root of
the block the Fast Confirmation Rule last confirmed (see
[`beacon_stf.md`](beacon_stf.md#fast-confirmation-rule)) and the finalized
checkpoint's root. The rule's confirmed root starts at the finalized block and
is updated once per slot, in the same tick, before this call. Between two runs
an import can move the head off the confirmed block's chain, and the finalized
block is sent as safe until the head is back on it (see `docs/spec_deviations.md`,
"`forkchoiceUpdated` for a gloas head"; the rule applies on every fork). A root with no
cached hash contributes the zero hash, which is a meaningful value here rather
than an absence: EIP-3675 requires `finalized_block_hash` to be zero before a
post-transition block is finalized, and a confirmed block before the merge has
no payload. A follower whose *head* has no cached hash is still sitting on its
checkpoint anchor and sends nothing at all.

The cache is pruned to the unfinalized window on every tick and every import,
with the finalized checkpoint's own root exempted by name. The slot bound alone
does not reach it: a checkpoint is stored as its epoch's start slot, while its
root is the last block at *or before* that boundary, so a missed proposal at an
epoch boundary leaves the finalized block below the bound. Dropping its hash
would make every later call carry `finalized_block_hash = 0x00..0` and stop the
execution client advancing its own finalized block for the life of the process.

For a gloas head the hashes come from bids rather than from a cached payload
hash: the head node's `bid.block_hash` when it is FULL and its
`bid.parent_block_hash` when it is EMPTY, the finalized block's
`bid.parent_block_hash`, and the confirmed block's `bid.parent_block_hash` as
the safe hash (the specification's gloas `get_safe_execution_block_hash`: only
the parent payload of a confirmed beacon block is safe). The call is V4 with
the node's custody columns. A head whose payload status has not been computed
yet (the first moments after a restart) sends nothing.

The response carries a `PayloadStatusV1` of its own, and that is the channel by
which a block imported on `SYNCING` later becomes `VALID` or is found to be
`INVALID`. An invalidation reaching the follower this way can remove the head
itself, unlike one reaching it through `newPayload`, because the block in
question has already been imported and *is* in the index. When it does, fork
choice is re-run and the head rewritten before the response handler returns:
`KEY_HEAD` and `Table::BlockRoots` still name the removed roots otherwise, and
the req/resp handlers read both, so a peer would be advertised and served a
block this node has just refused. Only the head is rewritten there, not
announced: telling the execution client from inside its own response would
re-enter the call being answered, so the new head goes out on the next cascade
or tick.

## Configuration

```
--execution-endpoint <URL>                   e.g. http://127.0.0.1:8551
--execution-jwt-secret <PATH>                file holding 32 bytes of hex
--safe-slots-to-import-optimistically <N>    default: the spec's own value
```

The first two must be given **together**: an Engine API endpoint always requires
authentication, so an endpoint without a secret is refused at startup, before
anything binds or connects. Clap cannot express "both or neither" across two
optional flags, so the pairing is checked once, in `From<BeaconOptions>`.

Blob fetching has no flag of its own: it is on whenever `--execution-endpoint` is set.

With **neither** flag, the follower contacts no execution client and every block
gets `PayloadValidity::NotRequired`, which is exactly what it did before any of
this existed.

Authentication is HMAC-SHA256 over a JOSE header and a claim set whose only
member is `iat`. Execution clients accept about a minute of skew either way; a
fresh token is minted per request rather than cached, because minting is two
hashes and a cache would need a clock of its own.

The startup handshake warns rather than refuses when the execution client does
not advertise a method this node needs: an execution client that under-reports
its capabilities still works, and refusing to start over a handshake would turn a
cosmetic mismatch into an outage.

## Limitations

### The retry ladder gives up, and nothing re-drives it

Each call is attempted `ENGINE_MAX_ATTEMPTS` times, with a per-attempt timeout of
`ENGINE_TIMEOUT` and a backoff starting at `ENGINE_INITIAL_BACKOFF` and doubling.
An RPC *error* is not retried: that is the execution client answering, with a
refusal but an answer, so asking again would get the same refusal and burn the
ladder for nothing.

`engine_getPayloadV5` and `engine_getPayloadV6` have no ladder: one attempt at
`ENGINE_GET_PAYLOAD_TIMEOUT` (1 s). execution-apis #958 removed the method's
timeout ("MUST respond immediately", and the consensus client "MAY abort such a
call at its own discretion"); 1 s is the value it replaced and what Nimbus and
Prysm (before gloas) use, where Lighthouse and Teku allow 2 s. A retry could not
deliver the slot's payload in time, and an execution client may stop the build
once it has served the call.

After the last attempt the block is **dropped**. `optimistic-sync.md` requires
exactly that much ("a consensus engine MUST NOT import the block and MUST NOT
apply it to the fork choice store"), but nothing here re-drives the call
afterwards, so a persistently unreachable execution client parks the follower's
head behind the first block it could not ask about, permanently, until a
restart.

This was accepted knowingly for this change. The intended fix is a tick-driven
re-drive of the set of blocks that got no verdict. `lean_engine_no_verdict_total` is the
metric that says it is happening: a non-zero rate means the follower has stopped
following rather than merely slowed down.

### `optimistic_roots` does not survive a restart

The optimistic set lives in memory alongside the rest of the beacon fork-choice
scratch and is not persisted. After a restart, blocks that were imported
optimistically are no longer marked as such.

This is safe because the set is advisory. It records which blocks have not yet
been vouched for, so that a later `VALID` can clear them and a later `INVALID`
can be attributed; it never gates whether a block stays in fork choice. On
restart the execution client is asked again about everything the follower
imports from that point on, and `forkchoiceUpdated` re-establishes the head's
status on the first tick.

### The anchor is assumed valid

A checkpoint-synced follower takes its anchor state and block on trust, without
asking an execution client about the anchor's own payload. That is inherent to
checkpoint sync, not specific to this change.

### The merge transition is untouched

`validate_merge_block` and the terminal-PoW checks are bellatrix's, are reached
from one place, and were removed outright by capella. Nothing here changes them.
