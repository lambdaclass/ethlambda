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

Six:

| Method | Introduced | Why |
|---|---|---|
| `engine_newPayloadV4` | prague | Validate one block's payload |
| `engine_newPayloadV5` | amsterdam | Validate the payload a gloas envelope reveals |
| `engine_forkchoiceUpdatedV3` | cancun | Say where the head, safe and finalized blocks are |
| `engine_forkchoiceUpdatedV4` | amsterdam | The same, from a gloas head on; also carries the node's custody columns |
| `engine_exchangeCapabilities` | common | Startup handshake |
| `engine_getClientVersionV1` | identification | Log what the execution client is |

Osaka introduces **no new `newPayload`**. Its own document adds only
`engine_getPayloadV5` and `engine_getBlobsV2`/`V3`; `engine_newPayloadV5` belongs
to Amsterdam, where gloas's envelope import uses it. So the Osaka-current call for a payload is prague's V4, and the
Osaka-current fork choice notification is cancun's V3. Amsterdam's pair (newPayload V5, forkchoiceUpdated V4) is
used from gloas on; the startup handshake warns when the execution client does not advertise either, but only on a network whose schedule includes gloas.

Three method families a full client would have are deliberately absent:

- **`engine_getPayload*` outside the gloas path.** The follower itself never
  asks an execution client to start building a block, so its own
  `forkchoiceUpdated` calls carry `null` payload attributes. Block production for
  a validator client (`produceBlockV3` for fulu, `produceBlockV4` for gloas) does:
  `forkchoiceUpdatedV3` with `PayloadAttributesV3` then `engine_getPayloadV5`
  before gloas, and `forkchoiceUpdatedV4` with `PayloadAttributesV4` (V3's fields
  plus `slotNumber` and `targetGasLimit`, the parent bid's gas limit) then
  `engine_getPayloadV6` (`ExecutionPayloadV4`, with `blockAccessList` and
  `slotNumber`) from gloas on. The handshake warns when a gloas network's
  execution client does not advertise `engine_getPayloadV6`.
- **`engine_getBlobs*`.** There is no blob-pool fetch path here; data columns come
  from peers over the network.
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
deleted. That is sufficient because `Store::block_index()` is the only source
`filter_block_tree`, `compute_node_weights` and `walk_head` read: a root with no
row contributes no weight to any ancestor and can never be walked to. The block
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

Condition 1 is `store.beacon_el_block_hash(parent_root).is_some()`, and that hash
is written when a block is *imported*. So it asks whether this node imported the
parent and saw its payload, not whether the parent is post-merge.

The horizon guards against a poisoned *merge transition* block, whose parent hash
names an execution block nobody can produce. Once a node is importing a
post-merge chain every block's parent carries a recorded hash, so condition 1
carries each one and condition 2 stops mattering.

The exception is the first block after a checkpoint-sync anchor. The anchor is
never imported and never asked about (see [The anchor is assumed
valid](#the-anchor-is-assumed-valid)), so no execution hash is recorded for it
and its child fails condition 1. Paired with an execution client that is itself
still syncing, and so answers `SYNCING` to every `newPayload`, that child has
only condition 2 left and the follower's head sits at the anchor until the
horizon admits it.

The wait is `--safe-slots-to-import-optimistically` minus however far the anchor
already trails the wall clock, which for a finalized anchor is most of it:
measured against mainnet on 2026-09-15, an anchor 85 slots back cleared in about
9 minutes rather than the full 128 slots. It costs that once per sync. Importing
that block records its hash, so every descendant takes condition 1 and the
backlog cascades.

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

## `forkchoiceUpdated`

Sent once after every head recompute, which is once per import cascade and once
per tick, not once per block. It is sent even when nothing moved: an execution
client doing state sync needs to keep being fed a recent head or its sync cannot
converge.

Its three hashes come from the cached execution hash of the head, the justified
checkpoint's root and the finalized checkpoint's root. A root with no cached hash
contributes the zero hash, which is a meaningful value here rather than an
absence: EIP-3675 requires `finalized_block_hash` to be zero before a
post-transition block is finalized, and the specification's own
`get_safe_execution_block_hash` returns zero when no payload is justified yet. A
follower whose *head* has no cached hash is still sitting on its checkpoint
anchor and sends nothing at all.

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
`bid.parent_block_hash`, and the justified block's `bid.parent_block_hash` as
the safe hash. The last is a fallback, since the specification builds the safe
hash on fast confirmation, which the follower does not run. The call is V4 with
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
