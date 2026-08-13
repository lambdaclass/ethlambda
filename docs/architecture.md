# Architecture

A running node is two actors, a few helper tasks, and one shared `Store`. The actors are
genservers: each owns its state, and the only way in is a message.

- **`BlockChainServer`** (`crates/blockchain/src/lib.rs`) drives consensus. It runs the slot
  clock, performs validator duties, imports blocks and attestations, and is the sole writer
  of consensus state.
- **`P2PServer`** (`crates/net/p2p/src/lib.rs`) owns the network side: gossip publication,
  request/response, peer bookkeeping and long-range sync.

Everything else hangs off those two: an aggregation worker on a blocking thread, the libp2p
swarm loop on its own task, and the axum servers that expose the node to the outside world.

> Note: for what a genserver is, read [this blogpost on the `spawned` crate](https://blog.lambdaclass.com/introducing-spawned-erlang-style-actors-for-rust/).

```text
                        Tick (self-message, one per interval)
                      ┌──────────────────────────────┐
                      ▼                              │
       ┌─────────────────────────────┐               │      ┌────────────────────┐
       │      BlockChainServer       │───────────────┘      │  aggregation       │
  ┌───▶│  actor, sole state writer   │─────── jobs ────────▶│  worker            │
  │    │                             │◀───── aggregates ────│  (blocking thread) │
  │    └──────────────┬──────────────┘                      └────────────────────┘
  │                   │
  │ P2PToBlockChain   │ BlockChainToP2P
  │ new block/vote    │ publish, fetch block
  │                   ▼
  │    ┌─────────────────────────────┐  SwarmCommand   ┌────────────────────┐
  └────│          P2PServer          │────────────────▶│   swarm adapter    │
       │  actor, gossip + req/resp   │◀────────────────│   (libp2p task)    │◀══▶ peers
       └─────────────────────────────┘   SwarmEvent    └────────────────────┘

       ┌────────────────────────────────────────────────────────────────────┐
       │ Store: pluggable key-value backend + in-memory fork-choice buffers │
       │ written by BlockChainServer, read by P2PServer and the API servers │
       └────────────────────────────────────────────────────────────────────┘
```

## Actor protocols

The two actors never share memory: they talk over the typed protocols in
`crates/net/api/src/lib.rs`.

| Direction | Messages |
| --- | --- |
| `BlockChain` → `P2P` | `publish_block`, `publish_attestation`, `publish_aggregated_attestation`, `fetch_block` |
| `P2P` → `BlockChain` | `new_block` (tagged `Gossip` or `Sync`), `new_attestation`, `new_aggregated_attestation` |

Both refs start as `None`. The `InitP2P` and `InitBlockChain` messages fill them in right
after spawn, so neither actor needs the other to exist at construction time.

## The `BlockChainServer`

### The tick loop

The actor schedules its first `Tick` for genesis time, and every handler re-arms the next one
at the following interval boundary. A handler that overruns that boundary re-arms with a zero
delay instead, so the interval it just missed still gets its duty. The handler derives
`(slot, interval)` from the wall clock, compares it against the store's own interval counter,
and skips ticks the store already passed.

`store::on_tick` then walks the store clock forward one interval at a time, fast-forwarding
if it fell more than a slot behind, so a late tick still runs each interval's bookkeeping in
order. That walk and the actor split the duties:

| Interval | In `store::on_tick` | In the actor |
| --- | --- | --- |
| 0 | accept new attestations, if we propose this slot | nothing: the build ran at the previous interval 4 |
| 1 | nothing | produce attestations, arm the early-aggregation check |
| 2 | nothing | start the aggregation session |
| 3 | update the safe target | nothing |
| 4 | accept accumulated attestations | build and publish the next slot's block |

See [Slots and Intervals](./slots_and_intervals.md) for what each duty means at the protocol
level, and why the proposer builds one interval early.

The actor also advances its XMSS signing keys on every tick, and catches them up to the
current slot once at spawn. The keys are one-time and slot-bound, so a node that skipped this
would have nothing left to sign with.

### Block import

Blocks take the same path whether they arrived on gossip or came back from a `BlocksByRange`
sync request. The actor verifies the signature, then runs the state transition
(`crates/blockchain/state_transition`): `process_slots` advances the pre-state through empty
slots, `process_block` validates the header and applies the block's attestations, and the
result is rejected unless the recomputed state root matches the one the proposer committed
to. Justification and finalization move as part of that transition, following the
[3SF-mini](./3sf_mini.md) rules. The actor then writes the block and its post-state, and
recomputes the head with [LMD GHOST](./lmd_ghost.md) (`crates/blockchain/fork_choice`).

### Aggregation off the message loop

XMSS proving costs hundreds of milliseconds, so it cannot run on the actor loop: a blocked
actor stops importing blocks. The actor instead snapshots aggregation inputs from the store,
ranks candidates by consensus value, and hands a job list to a `spawn_blocking` worker
(`crates/blockchain/src/aggregation.rs`). The worker holds no store access, streams one
`AggregateProduced` message back per finished job, and ends with `AggregationDone`. The actor
publishes each result on gossip when it arrives.

A soft deadline cancels the worker through a `CancellationToken`, so an overrunning slot
cannot eat the next one. The session can also start up to `EARLY_AGGREGATION_WINDOW` before
interval 2, once two thirds of the expected signatures are in. Either entry point counts as
the slot's one session, so a slot aggregates once. Starting early buys proving time, not an
earlier publication: the worker holds each finished aggregate until the interval-2 boundary
before delivering it to the actor.

Block import runs a second, smaller aggregation path. `reaggregate.rs` splits an imported
block's merged proof back into per-attestation aggregates and folds them into the local pool,
which is how a node that only saw a vote inside a block gets its fork-choice weight.
Aggregators go one step further and republish those aggregates on gossip. Each split runs a
fresh SNARK, so `reaggregate.rs` caps how many it does per block, and the actor skips the
whole path while the node is catching up.

### Sync gate

`sync_status.rs` tracks how far the local head lags the slot clock. Past the threshold the
node reports itself syncing and stops attesting and proposing, since a head derived from a
partial view is not worth voting for. A hysteresis band stops the state from flapping at the
boundary, and a network-wide stall (nobody else is ahead either) leaves the node synced so
its validators can help the chain recover. The same status feeds the `lean_node_sync_status`
metric and, through a shared controller, the `/lean/v0/node/syncing` endpoint.
`--disable-duty-sync-gate` reduces the gate to observe-only.

### Missing parents

The actor cannot import a block whose parent is unknown, so it parks the block in
`pending_blocks` under its parent root and records the deepest missing ancestor it can find,
walking back through already-stored pending blocks, in `pending_block_parents`. That ancestor
is what it asks the `P2PServer` to fetch. Once the ancestor lands, the actor cascades down
the parent index and re-imports every block that was waiting.

### Chain events

The actor is the sole publisher on an `EventBus` (`crates/blockchain/src/events.rs`), which
carries seven topics: head moves, imports and gossip sightings of blocks, single votes and
aggregates, plus justification and finalization updates. The bus is best-effort:
emission never blocks the actor, and a slow subscriber loses events instead of
back-pressuring consensus. The API server subscribes one receiver per SSE client.

## The `P2PServer`

Only the swarm adapter task touches the `libp2p::Swarm`. The actor sends it `SwarmCommand`s
(publish, dial, send request, send response) and receives `SwarmEvent`s back as actor
messages. That split keeps non-`Clone` swarm types (response channels, for one) out of the
typed protocol, and keeps the adapter polling network I/O while the actor is busy with a
message.

What the actor does with those events:

- **Gossip.** It decodes blocks, aggregates and per-subnet attestations, then forwards them
  to the `BlockChainServer`. The node computes its subscriptions once at startup from its
  validator set and aggregator role, and never revisits them.
- **Status.** Sent on the first connection to a peer, not on every redundant one. When a peer
  reports a head ahead of ours, the actor opens a long-range sync range or extends the one it
  has, then requests `BlocksByRange` batches one at a time, dropping peers that fall behind
  the range.
- **`BlocksByRoot`.** Backs the `fetch_block` requests above. Retries use exponential backoff
  and prefer a peer that has not already failed for that root, falling back to the full
  connected set once every peer has failed.

The `P2PServer` holds its own `Store` clone, which it only ever reads, so it answers `Status`
and `BlocksBy*` requests without a round trip through the consensus actor.

## The `Store`

The `Store` follows a similar approach as ethrex's: a safe, easy to use interface over a
pluggable key-value backend (`StorageBackend`, RocksDB for a normal node and in-memory for
tests and the Hive test driver).
Cloning one shares the backend, the state LRU cache, and the in-memory buffers that fork
choice runs on: the new and known attestation payload buffers, the latest votes, and the
gossip signatures awaiting aggregation. The node never persists those buffers, since they
only matter for the slot they belong to.

Every component gets a clone, but only the `BlockChainServer` writes consensus state. A
reader can therefore hold a handle without interleaving with a state transition.

See [Data Storage](./data_storage.md) for the table layout, the snapshot/diff scheme used for
states, and pruning rules.

## HTTP API

We use `axum` as our API router, with requests served in tokio tasks. Handlers read node state
without messaging the actors: the `Store` is router state, and the `EventBus` and the runtime
controllers arrive as extension layers. Metrics and debug endpoints live in their own routers,
on a port you configure separately: distinct ports bind two independent servers, equal ports
merge all three routers onto a single listener. See [HTTP API](./rpc.md) for the endpoint
reference.

## Startup

`bin/ethlambda/src/main.rs` wires the node in a fixed order. Everything before the actors
spawn is fail-fast, so a misconfigured node stops at boot instead of hours later.

1. Install the tracing subscriber, parse CLI options, register metrics, raise the
   file-descriptor limit for RocksDB's unbounded table cache.
2. Load the node key, then genesis config, validator config, bootnode ENRs and validator keys.
3. Open the database, then pick an anchor: resume from disk if the on-disk head is recent
   enough, otherwise [checkpoint sync](./checkpoint_sync.md) from the configured URLs, and
   otherwise build the genesis state. A stale database with no checkpoint URL configured is
   resumed anyway, with a warning, since that is the setup the node was given.
4. Build the shared handles: aggregator controller, sync-status controller, event bus, and
   the subnet set that both the swarm and the actor need to agree on.
5. Spawn `BlockChainServer` (which schedules its first tick for genesis time), build the
   swarm, spawn `P2PServer`, and wire the two together with `InitP2P` and `InitBlockChain`.
6. Spawn the API and metrics servers.

Shutdown runs in reverse: the first ctrl+c stops both actors and cancels the servers'
shutdown token, and three more force the process to exit if a graceful stop hangs.

> Note: booting with `HIVE_LEAN_TEST_DRIVER=1` short-circuits everything from step 2 on and
> exposes only the Hive test-driver endpoints, so a driver run never touches the node key,
> the genesis config or any other consensus prerequisite.
