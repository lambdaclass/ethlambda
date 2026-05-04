# Architecture

This page describes how an ethlambda node is wired together: the crate layout,
the actor model, the slot tick loop, the inbound and outbound message paths,
and the storage and HTTP surfaces.

For a visual companion, see the
[architecture infographic](./infographics/ethlambda_architecture.html), which
covers the same material as four interactive diagrams (actor topology, block
data flow, crate layers, crate dependencies).

## Process model at a glance

A running node is a single OS process containing **two long-lived actors**
plus a handful of background tokio tasks:

```text
┌─────────────────────────── ethlambda process ───────────────────────────┐
│                                                                         │
│   ┌──────────────┐           InitP2P / NewBlock / NewAttestation        │
│   │ BlockChain   │ ◄───────────────────────────────────────────         │
│   │ Server       │                                                      │
│   │ (actor)      │ ─────────► PublishBlock / PublishAttestation /       │
│   └──────┬───────┘            FetchBlock                                │
│          │                                  ┌────────────────┐          │
│          │ Store (Arc<dyn StorageBackend>)  │ P2P (actor)    │          │
│          ▼                                  └────┬───────────┘          │
│   ┌──────────────┐                               │                      │
│   │ RocksDB /    │                               │ SwarmCommand /       │
│   │ in-memory    │                               │ WrappedSwarmEvent    │
│   │ backend      │                               ▼                      │
│   └──────┬───────┘                       ┌────────────────┐             │
│          │                               │ SwarmAdapter   │             │
│          │   read-only access            │ (tokio task)   │             │
│          ▼                               └────┬───────────┘             │
│   ┌──────────────┐                            │ libp2p swarm            │
│   │ API server   │                            ▼                         │
│   │ :5052 (axum) │                       (QUIC + gossipsub + req/resp)  │
│   ├──────────────┤                                                      │
│   │ Metrics srv  │      reads global prometheus registry                │
│   │ :5054 (axum) │                                                      │
│   └──────────────┘                                                      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

Communication is one-way through the `spawned-concurrency` actor system:
`BlockChain` and `P2P` exchange typed messages via `Recipient<M>` handles, never
direct method calls. The `SwarmAdapter` background task isolates the
`!Send` libp2p swarm from the actor mailboxes. Both HTTP servers read directly
from the `Store` (or, for metrics, from the global Prometheus registry); they
do not go through the `BlockChain` actor.

## Crate map

The workspace is organized as **one binary plus 11 library crates**: four
"common" libraries shared across layers, and three layer crates (one with
sub-crates).

| Crate | Path | Role |
|-------|------|------|
| `ethlambda` | `bin/ethlambda/` | Entry point, CLI parsing, startup orchestration. |
| `ethlambda-blockchain` | `crates/blockchain/` | `BlockChainServer` actor, fork-choice store, validator duty orchestration, signature aggregation. |
| `ethlambda-fork-choice` | `crates/blockchain/fork_choice/` | Pure LMD-GHOST functions adapted to 3SF-mini. |
| `ethlambda-state-transition` | `crates/blockchain/state_transition/` | Pure STF: `process_slots`, `process_block`, justifications, finalization. |
| `ethlambda-types` | `crates/common/types/` | Core SSZ-serializable types (`State`, `Block`, `Attestation`, `Checkpoint`, `H256`, `ShortRoot`). |
| `ethlambda-crypto` | `crates/common/crypto/` | XMSS sign/verify (leansig) and aggregation (leanVM). |
| `ethlambda-metrics` | `crates/common/metrics/` | Prometheus re-exports, `TimingGuard`, `gather_default_metrics`. |
| `ethlambda-test-fixtures` | `crates/common/test-fixtures/` | Shared loaders for `leanSpec` consensus fixtures used by the spec-test harnesses. |
| `ethlambda-network-api` | `crates/net/api/` | Message contract between `BlockChain` and `P2P` (two `#[protocol]` traits). |
| `ethlambda-p2p` | `crates/net/p2p/` | `P2P` actor + `SwarmAdapter`, gossipsub topics, req/resp protocols. |
| `ethlambda-rpc` | `crates/net/rpc/` | Axum API server + metrics server. |
| `ethlambda-storage` | `crates/storage/` | `StorageBackend` trait, RocksDB and in-memory backends, `Store` cache. |

The four "common" crates (`types`, `crypto`, `metrics`, `test-fixtures`) hold
no actor logic. `types`, `crypto`, and `metrics` are depended on from every
layer; `test-fixtures` is a `dev-dependency` of the spec-test harnesses.
The runtime dependency graph flows
`bin → blockchain → state_transition + fork_choice + storage + types`,
`bin → p2p → api + types`, and `bin → rpc → storage + types`. There is no
direct dependency between `blockchain` and `p2p`: they communicate exclusively
through the `network-api` traits.

## Actor model

ethlambda uses [`spawned-concurrency`](https://github.com/lambdaclass/spawned)
v0.5, the `#[actor]` and `#[protocol]` macros, and `Recipient<M>` handles for
type-erased message passing. Two actors run for the lifetime of the node.

### `BlockChainServer`

Defined in `crates/blockchain/src/lib.rs:100`. Single-threaded sequencer for
all chain state mutations: block import, attestation processing, head and
finalization updates, validator duties.

```rust
#[actor(protocol = BlockChainProtocol)]
impl BlockChainServer { /* ... */ }
```

Holds:

- `store: Store` — the `Arc<dyn StorageBackend>` cache plus in-memory fork-choice state.
- `p2p: Option<BlockChainToP2PRef>` — set by the `InitP2P` message at startup.
- `key_manager: KeyManager` — validator XMSS key pairs.
- `pending_blocks` / `pending_block_parents` — orphan pool for blocks awaiting their parent.
- `aggregator: AggregatorController` — runtime-toggleable flag (see [Aggregator role](#aggregator-role)).
- `current_aggregation: Option<AggregationSession>` — handle to a leanVM aggregation worker spawned per slot.

Internal protocol (self-messages only):

```rust
#[protocol]
pub(crate) trait BlockChainProtocol: Send + Sync {
    fn tick(&self) -> Result<(), ActorError>;
}
```

The `Tick` message is rescheduled by the actor itself on every interval (see
[Tick system](#tick-system)). All cross-actor messages
(`NewBlock`, `NewAttestation`, `NewAggregatedAttestation`, `InitP2P`) are
handled through manual `Handler<M>` impls so that the `Recipient<M>` handles
in `network-api` can be erased across actor boundaries
(`crates/blockchain/src/lib.rs:629`).

### `P2P`

Defined in `crates/net/p2p/src/lib.rs`. Wraps a libp2p swarm and forwards
validated gossip / req-resp payloads to the `BlockChain` actor.

Holds:

- `blockchain: Option<P2PToBlockChainRef>` — set by `InitBlockChain`.
- `swarm_handle: SwarmHandle` — clone-able command sender into the swarm.
- pending fetch state, peer set, retry timers.

Internal protocol:

```rust
#[protocol]
pub(crate) trait P2PProtocol {
    fn retry_block_fetch(&self, root: H256) -> Result<(), ActorError>;
    fn retry_peer_redial(&self, peer: PeerId) -> Result<(), ActorError>;
}
```

The actor never owns the libp2p swarm directly: the swarm types are `!Send`
and incompatible with the actor mailbox. The `SwarmAdapter` task owns it.

### `SwarmAdapter` — the libp2p bridge

`crates/net/p2p/src/swarm_adapter.rs`. Pure tokio task, no actor:

```text
┌──────────────────────────────────────────────┐
│   swarm_loop (tokio::spawn)                  │
│     loop {                                   │
│       tokio::select! {                       │
│         event = swarm.next() => forward as   │
│           WrappedSwarmEvent to P2P actor     │
│         cmd = cmd_rx.recv() => translate to  │
│           swarm.dial / behaviour_mut()...    │
│       }                                      │
│     }                                        │
└──────────────────────────────────────────────┘
```

`start_swarm_adapter()` returns:

- a `SwarmHandle`: clone-able command channel (`Publish`, `Dial`, `SendRequest`, `SendResponse`).
- an event stream wired into the `P2P` actor with `spawn_listener()`, so each
  swarm event lands in the actor mailbox as a `WrappedSwarmEvent`.

Outbound publishing therefore takes two steps:

```text
BlockChain ──PublishBlock──► P2P ──SwarmCommand::Publish──► SwarmAdapter ──► swarm
```

`SendRequest` returns the libp2p `OutboundRequestId` via a oneshot channel
so the `P2P` actor can correlate responses with in-flight fetches.

### Message contract

The two crates exchange types defined in `crates/net/api/src/lib.rs`:

| Direction | Trait / Message | Purpose |
|-----------|-----------------|---------|
| BlockChain → P2P | `BlockChainToP2P::publish_block` | Gossip a freshly produced block. |
| BlockChain → P2P | `BlockChainToP2P::publish_attestation` | Gossip a single signed attestation. |
| BlockChain → P2P | `BlockChainToP2P::publish_aggregated_attestation` | Gossip an aggregated attestation proof. |
| BlockChain → P2P | `BlockChainToP2P::fetch_block` | Trigger a `BlocksByRoot` request to peers. |
| P2P → BlockChain | `P2PToBlockChain::new_block` | Validated block from gossip / req-resp. |
| P2P → BlockChain | `P2PToBlockChain::new_attestation` | Validated single attestation. |
| P2P → BlockChain | `P2PToBlockChain::new_aggregated_attestation` | Validated aggregated attestation. |
| Init | `InitP2P { p2p: BlockChainToP2PRef }` | Hand the P2P recipient to the `BlockChain` actor. |
| Init | `InitBlockChain { blockchain: P2PToBlockChainRef }` | Hand the blockchain recipient to the `P2P` actor. |

`#[protocol]` generates `*Ref` newtypes (`BlockChainToP2PRef`, `P2PToBlockChainRef`)
that are clone-able, type-erased recipient handles. Each actor only knows
about the trait it imports, never the concrete type of the other actor.

## Tick system

Slot timing constants live in `crates/blockchain/src/lib.rs:39-44`:

```rust
pub const MILLISECONDS_PER_INTERVAL: u64 = 800;
pub const INTERVALS_PER_SLOT: u64 = 5;
pub const MILLISECONDS_PER_SLOT: u64 = 4_000;
```

A 4-second slot is divided into 5 intervals of 800 ms each. The `BlockChain`
actor schedules a `Tick` for the next interval boundary at the end of every
`handle_tick` call, with the very first tick scheduled for `genesis_time`
during `BlockChain::spawn`:

```rust
async fn handle_tick(&mut self, _msg: Tick, ctx: &Context<Self>) {
    let now = SystemTime::UNIX_EPOCH.elapsed().unwrap();
    self.on_tick(now.as_millis() as u64, ctx).await;
    let ms_to_next = MILLISECONDS_PER_INTERVAL
        - (now.as_millis() as u64 % MILLISECONDS_PER_INTERVAL);
    send_after(Duration::from_millis(ms_to_next), ctx.clone(), Tick);
}
```

This self-scheduling keeps tick alignment locked to wall-clock interval
boundaries even if `on_tick` itself takes a few hundred milliseconds (e.g.,
for state transition or aggregation kickoff).

### Per-interval validator duties

| Interval | Wall-clock offset in slot | Action |
|----------|---------------------------|--------|
| 0 | 0 ms     | Block proposal: assigned proposer builds and gossips a block. Once the proposal is observed, the node also begins promoting accumulated attestations into the fork-choice store. |
| 1 | 800 ms   | Attestation production: every validator produces and gossips one attestation, including the proposer. |
| 2 | 1600 ms  | Aggregation: aggregators package gossip XMSS signatures into a leanVM proof and gossip the aggregated attestation. The safe-target deadline kicks in. |
| 3 | 2400 ms  | Safe-target / fork-choice update. |
| 4 | 3200 ms  | Final acceptance window: any remaining accumulated attestations are promoted before the next slot. |

The exact branches live in `crates/blockchain/src/lib.rs::on_tick` (search for
`interval` and `slot_phase`).

## Block lifecycle

### Inbound

```text
gossip / req-resp
   │
   ▼
swarm event ──► SwarmAdapter ──WrappedSwarmEvent──► P2P actor
                                                       │
                              (ssz_snappy decode +     │
                               XMSS signature verify)  │
                                                       ▼
                                               P2PToBlockChain::new_block
                                                       │
                                                       ▼
                                                 BlockChain actor
                                                       │
                                          (parent known?) ─ no ─► pending_blocks
                                                       │ yes
                                                       ▼
                                          Store::on_block (STF + fork choice)
                                                       │
                                                       ▼
                                          atomic write batch to RocksDB
                                                       │
                                                       ▼
                                       attempt to drain orphans whose parent
                                       has just been imported
```

Block validation has two distinct gates: gossip-time signature verification
in `P2P` (so invalid blocks never reach the actor mailbox), and full state
transition + fork-choice integration in `BlockChain::on_block`.

### Outbound (proposer path)

Triggered at interval 0 if `is_proposer(state, slot, validator)` returns
true for any locally managed key:

```text
KeyManager pulls validator key
   │
   ▼
build_block(state, attestations, signatures)
   │   ├─ pick attestations from known pool
   │   ├─ aggregate signatures (or fall back to previous proofs)
   │   └─ XMSS-sign the SignedBlock
   ▼
self-import via on_block (so head/state are advanced before publish)
   │
   ▼
PublishBlock recipient ──► P2P actor ──► SwarmHandle.publish() ──► gossipsub
```

Self-importing the block before gossiping it guarantees that the proposer's
own head reflects its proposal even if gossip propagation is slow.

## Attestation pipeline

Attestations have a two-stage in-memory pipeline before they influence fork
choice. This keeps the fork-choice input frozen during a slot while still
admitting attestations as they arrive on gossip.

```text
                        ┌───────────────────────────┐
gossip attestation ────►│ new_attestations          │
                        │ (just verified, pending)  │
                        └────────┬──────────────────┘
                                 │ promotion at interval 0 (after proposal)
                                 │ and interval 4
                                 ▼
                        ┌───────────────────────────┐
                        │ known_attestations        │
                        │ (fork-choice active)      │
                        └────────┬──────────────────┘
                                 │
                                 ▼
                        compute_lmd_ghost_head
```

### Aggregator role

ethlambda implements a hot-standby aggregator model. Every node may be
**subscribed** to aggregation subnets at startup; whether it actually
**produces** aggregations is controlled by `AggregatorController`, a shared
`Arc<AtomicBool>` defined in `crates/common/types/src/aggregator.rs`.

```text
─────────── boot ───────────       ─────────── runtime ───────────
--is-aggregator (CLI flag)         POST /lean/v0/admin/aggregator
   │                                  │
   ├─ seeds AggregatorController      └─ flips the AtomicBool
   │  (read on every tick)               in process; subscriptions
   │                                     are NOT re-evaluated
   └─ used at build_swarm time to
      decide gossipsub subnet
      subscriptions (frozen)
```

The split is deliberate: the libp2p swarm decides subscriptions exactly once
in `build_swarm` (`bin/ethlambda/src/main.rs:179`), and `SwarmConfig.is_aggregator`
is a plain `bool`, not the controller. Toggling at runtime can therefore
**activate** aggregation logic for already-subscribed subnets but cannot
**add** subscriptions. Standby nodes should boot with `--is-aggregator=true`
and be toggled off by the admin endpoint when not on duty.

When aggregation is enabled and at least one signature is pending, the
`BlockChain` actor spawns a `run_aggregation_worker` task with a deadline
(`AGGREGATION_DEADLINE`) and a `CancellationToken`. The proof itself runs in
leanVM and cannot be interrupted; cancellation only prevents the *next* round
from starting. On actor shutdown, the `#[stopped]` lifecycle hook waits up
to `PRIOR_WORKER_JOIN_TIMEOUT` for the in-flight worker to drain
(`crates/blockchain/src/lib.rs:603-626`).

## Storage layer

`crates/storage/src/api/` defines three minimal traits:

| Trait | Purpose |
|-------|---------|
| `StorageBackend` | Owns the database; vends read views and write batches. |
| `StorageReadView` | Read-only handle (`get`, `get_batch`, `iter_table`). |
| `StorageWriteBatch` | Atomic write batch (`put`, `put_batch`, `delete`, `commit`). |

There are six tables, defined in `crates/storage/src/api/tables.rs:3`:

| Table | Key → Value | Purpose |
|-------|-------------|---------|
| `BlockHeaders` | `H256` → `BlockHeader` | Block headers by root. |
| `BlockBodies` | `H256` → `BlockBody` | Block bodies. Genesis has none (detected via `EMPTY_BODY_ROOT`). |
| `BlockSignatures` | `H256` → `BlockSignatures` | Per-block signatures. Absent for the genesis block. |
| `States` | `H256` → `State` | Beacon states by state root. |
| `Metadata` | `String` → various | Store-level scalars: head, config, checkpoints. |
| `LiveChain` | `(slot \|\| root)` → `parent_root` | Fast `(slot, root) → parent` index used by fork choice without deserializing full blocks. Pruned as slots finalize, but the finalized block itself is retained as the anchor. |

There is a RocksDB backend for production and an in-memory backend for
tests. The trait split lets a single test exercise the same `Store` code
paths against either backend.

The `Store` type wraps `Arc<dyn StorageBackend>` plus an in-memory cache of
fork-choice state (head, justified/finalized checkpoints, attestation
pools, justified-slots window). Cloning a `Store` clones the cache cheaply
while sharing the underlying backend handle, which is how the API server
can read from the chain without owning the backend.

> Earlier revisions had separate tables for individual gossip signatures,
> aggregated payloads, and pending attestation pools. As of 2026-04-30 those
> live entirely in memory inside the `Store`; on disk we persist only the
> chain itself.

## Networking layer

The transport is QUIC over UDP with TLS 1.3, configured by `build_swarm`
(`crates/net/p2p/src/lib.rs`). Three libp2p behaviours sit on top.

### Identify

`/ipfs/id/1.0.0` is registered purely for cross-client interop: go-libp2p
(used by [gean](https://github.com/devlongs/gean)) gates gossipsub `GRAFT`
on the identify exchange completing, so a peer that doesn't respond to
identify is silently excluded from the mesh. ethlambda does not act on
identify events itself; the registration alone is enough to keep gean
willing to peer with us.

### Gossipsub

ethlambda runs gossipsub v1.1 with snappy *raw* compression (per the lean
spec) and 20-byte truncated SHA256 message IDs. Topics include the
4-byte `fork_digest` (currently the placeholder `12345678`):

```text
/leanconsensus/{fork_digest}/block/ssz_snappy
/leanconsensus/{fork_digest}/attestation_{N}/ssz_snappy
/leanconsensus/{fork_digest}/aggregation/ssz_snappy
```

Mesh parameters: target size 8, bounds 6–12, heartbeat 700 ms.

### Request/Response

Two protocols, framed as length-prefixed snappy chunks:

- `STATUS_PROTOCOL_V1` — handshake exchanging finalized and head checkpoints.
- `BLOCKS_BY_ROOT_PROTOCOL_V1` — fetch one or more blocks by root.

Block fetches are retried with `×2` exponential backoff (5, 10, 20, 40, 80,
160, 320, 640, 1280, 2560 ms; `MAX_FETCH_RETRIES = 10` in
`crates/net/p2p/src/lib.rs:57`) and a randomly chosen peer per attempt,
scheduled through the actor's own `RetryBlockFetch` self-message rather than
a synchronous sleep. This keeps the actor responsive while a peer is
unreachable.

## HTTP servers

The RPC crate (`crates/net/rpc/`) starts **two independent Axum servers** as
top-level `tokio::spawn` tasks from `bin/ethlambda/src/main.rs:207`. Each
binds a separate port so that operators can apply different network policies
to the public API and the internal metrics endpoint.

| Server | Default address | Endpoints | Source of truth |
|--------|-----------------|-----------|-----------------|
| API | `127.0.0.1:5052` | `GET /lean/v0/health`, `GET /lean/v0/states/finalized` (SSZ), `GET /lean/v0/checkpoints/justified` (JSON), `GET /lean/v0/fork_choice` (JSON), `GET /lean/v0/fork_choice/ui` (D3.js viz), `GET/POST /lean/v0/admin/aggregator` | `Store` clone + `AggregatorController`. |
| Metrics | `127.0.0.1:5054` | `GET /metrics`, `GET /debug/pprof/allocs`, `GET /debug/pprof/allocs/flamegraph` | Global Prometheus registry; no `Store` access. |

If either server fails to bind, the failure is logged at `error!()` level
but does not crash the node — gossip, fork choice, and finality continue
without the HTTP surface.

## Cryptography

ethlambda uses XMSS (eXtended Merkle Signature Scheme), a stateful
post-quantum signature scheme:

- 52-byte public keys, 3112-byte signatures.
- One-time per leaf: each slot consumes a fresh leaf, and `KeyManager` tracks
  slot usage to prevent reuse.
- Signing and verification are wrapped in `ethlambda-crypto` over the
  external `leansig` crate.

Aggregation is handled by leanVM, which produces a succinct proof binding
multiple validator signatures to a single attestation. This step is
expensive enough that nodes co-located on the same host must coordinate to
avoid CPU contention; in practice we run **one aggregator per host**.

## Startup sequence

Walking through `bin/ethlambda/src/main.rs` end to end:

```text
1.  parse CLI flags                              (clap)
2.  load genesis config + bootnodes              (config.yaml, ENRs)
3.  open RocksDB, initialize empty state if      (Store::init)
    this is a fresh database
4.  build AggregatorController from --is-aggregator
5.  spawn BlockChainServer                       BlockChain::spawn → first
                                                  Tick scheduled at genesis_time
6.  build libp2p swarm (subnet subscriptions     build_swarm(SwarmConfig {...})
    frozen here)
7.  spawn P2P actor wrapping the swarm           P2P::spawn(built, store.clone())
8.  send InitP2P to BlockChain                   blockchain.recipient::<InitP2P>()
9.  send InitBlockChain to P2P                   p2p.recipient::<InitBlockChain>()
10. spawn metrics server on :5054                tokio::spawn
11. spawn API server on :5052                    tokio::spawn
12. wait on ctrl-C
```

Once steps 8 and 9 complete, the two actors hold each other's recipient
handles and can exchange messages. The first `Tick` fires at the configured
`GENESIS_TIME` (or immediately if genesis is already in the past), at which
point the node begins participating in the chain.
