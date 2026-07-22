# HTTP API

ethlambda exposes HTTP over **two independent [Axum](https://github.com/tokio-rs/axum) servers** on separate ports, so the API and the metrics/debug surface can have different network policies:

- **API server** — consensus data (blocks, states, checkpoints, fork choice) and admin controls.
- **Metrics & debug server** — Prometheus metrics and heap-profiling endpoints. No store access.


All consensus API paths are versioned under the `/lean/v0` prefix. Roots are serialized as `0x`-prefixed hex strings.

## Servers & Ports

| Flag | Default | Description |
|------|---------|-------------|
| `--http-address` | `127.0.0.1` | Bind address shared by both servers |
| `--api-port` | `5052` | API server port |
| `--metrics-port` | `5054` | Metrics & debug server port |

If `--api-port` and `--metrics-port` are equal, all routers are merged onto a single port.

## API Server (`:5052`)

| Method | Path | Response | Description |
|--------|------|----------|-------------|
| `GET` | `/lean/v0/health` | JSON | Liveness check |
| `GET` | `/lean/v0/config/spec` | JSON | Protocol constants the node runs with |
| `GET` | `/lean/v0/genesis` | JSON | Genesis time and validator count |
| `GET` | `/lean/v0/states/finalized` | SSZ | Latest finalized `State` |
| `GET` | `/lean/v0/blocks/finalized` | SSZ | Latest finalized `SignedBlock` |
| `GET` | `/lean/v0/checkpoints/justified` | JSON | Latest justified `Checkpoint` |
| `GET` | `/lean/v0/events` | SSE | Live stream of chain events |
| `GET` | `/lean/v0/blocks/{block_id}` | JSON | Block by root or slot |
| `GET` | `/lean/v0/blocks/{block_id}/header` | JSON | Block header by root or slot |
| `GET` | `/lean/v0/fork_choice` | JSON | Fork-choice tree with per-block weights |
| `GET` | `/lean/v0/fork_choice/ui` | HTML | Interactive D3.js visualization |
| `GET` | `/lean/v0/node/identity` | JSON | Client version and libp2p peer ID |
| `GET` | `/lean/v0/node/syncing` | JSON | Sync status relative to the wall clock |
| `GET` | `/lean/v0/admin/aggregator` | JSON | Current aggregator role |
| `POST` | `/lean/v0/admin/aggregator` | JSON | Toggle aggregator role at runtime |

### `GET /lean/v0/health`

The handler emits a fixed, compact body (no whitespace):

```json
{"status":"healthy","service":"lean-rpc-api"}
```

### `GET /lean/v0/config/spec`

Protocol constants the node was built with. Keys mirror the leanSpec constant names:

```json
{
  "MILLISECONDS_PER_SLOT": 4000,
  "INTERVALS_PER_SLOT": 5,
  "MILLISECONDS_PER_INTERVAL": 800,
  "HISTORICAL_ROOTS_LIMIT": 262144,
  "FORK_DIGEST": "12345678"
}
```

`FORK_DIGEST` is the 4-byte hex string (no `0x` prefix) embedded in gossipsub topic names.

### `GET /lean/v0/genesis`

```json
{ "genesis_time": 1770407233, "validator_count": 16 }
```

`validator_count` is read from the head state's validator registry. Lean validators are fixed at genesis (no churn), so it always equals the size of the genesis registry.

### `GET /lean/v0/states/finalized`

SSZ-encoded `State` at the latest finalized checkpoint (`Content-Type: application/octet-stream`). The served state has its `latest_block_header.state_root` zeroed to match the canonical post-state representation the state transition produces, so checkpoint-sync peers reconstruct an identical state root. See [Checkpoint Sync](./checkpoint_sync.md).

### `GET /lean/v0/blocks/finalized`

SSZ-encoded `SignedBlock` at the latest finalized checkpoint. The genesis/anchor block has no stored signature, so a placeholder blank proof is synthesized and the endpoint still returns `200`. Returns `404` only in the rare case where a non-genesis finalized block's signature has been pruned below the finalized boundary and can no longer be served.

### `GET /lean/v0/checkpoints/justified`

```json
{ "slot": 128, "root": "0x1a2b…" }
```

### `GET /lean/v0/events`

Server-Sent Events stream (`Content-Type: text/event-stream`) of live chain events published by the blockchain actor. Five event types:

Payload fields mirror the Ethereum beacon-API eventstream: `block` is the block root, `state` the state root, and `slot` stands in for the beacon `epoch`.

| Event | Payload | Emitted when |
|-------|---------|--------------|
| `head` | `{ "slot": 128, "block": "0x…", "state": "0x…" }` | Fork choice selects a new head within `HEAD_EVENT_RECENCY_SLOTS` (32 slots) of the wall clock; no head events fire during catch-up |
| `block` | `{ "slot": 128, "block": "0x…" }` | A block is imported into the store |
| `justified_checkpoint` | `{ "slot": 120, "block": "0x…", "state": "0x…" }` | The justified checkpoint advances |
| `finalized_checkpoint` | `{ "slot": 96, "block": "0x…", "state": "0x…" }` | The finalized checkpoint advances |
| `block_gossip` | `{ "slot": 128, "block": "0x…" }` | A block is seen on the network, before import |

The topic name travels only on the SSE `event:` line; the `data:` line carries the flat JSON payload. Example frame:

```
event: head
data: {"slot":128,"block":"0x1a2b…","state":"0x3c4d…"}
```

#### Filtering with `?topics=`

A **required** comma-separated list of event names selects which events to stream:

```bash
curl -N 'http://127.0.0.1:5052/lean/v0/events?topics=head,finalized_checkpoint'
```

Valid values are exactly the event names above: `head`, `block`, `justified_checkpoint`, `finalized_checkpoint`, `block_gossip`. As in the Beacon API `eventstream` endpoint, `topics` is mandatory: there is no "subscribe to everything" default; list the topics you want.

| Status | Condition |
|--------|-----------|
| `200` | Stream opened for the listed topics |
| `400` | `topics` is missing or empty, or any listed name is not a known topic (body names the offending value) |

Events are fanned out over a bounded broadcast channel. A client that reads too slowly skips past the events it missed: they are dropped for that subscriber rather than back-pressured onto the actor, so treat the stream as best-effort and re-sync via the blocks endpoints after a gap. A client that falls behind receives an SSE comment line `: error - dropped N messages` marking the gap (wire-compatible with Lighthouse) before the stream continues; re-sync via the blocks endpoints rather than trusting the skipped range. Keep-alive comments are sent periodically to hold idle connections open.

### `GET /lean/v0/blocks/{block_id}` and `/header`

`block_id` is either:

- a `0x`-prefixed **32-byte hex root**, or
- a **decimal slot**.

Slot lookups resolve through the head state's `historical_block_hashes`, so **only canonical blocks are reachable by slot**; blocks on side forks must be addressed by their root. The `/header` variant returns just the `BlockHeader`.

| Status | Condition |
|--------|-----------|
| `200` | Block (or header) found, returned as JSON |
| `400` | `block_id` is neither a valid `0x` root nor a decimal slot |
| `404` | No block at that root, or the slot is empty / out of range |

Error bodies are JSON: `{ "error": "invalid block_id" }` / `{ "error": "block not found" }`.

### `GET /lean/v0/fork_choice`

The fork-choice tree from the finalized root, with LMD-GHOST weights computed over the live chain and currently known attestations.

```json
{
  "nodes": [
    { "root": "0x…", "slot": 128, "parent_root": "0x…", "proposer_index": 3, "weight": 12 }
  ],
  "head": "0x…",
  "justified": { "slot": 128, "root": "0x…" },
  "finalized": { "slot": 96,  "root": "0x…" },
  "safe_target": "0x…",
  "validator_count": 16
}
```

`/lean/v0/fork_choice/ui` serves an interactive D3.js page rendering this data. See [Fork Choice Visualization](./fork_choice_visualization.md).

### `GET /lean/v0/node/identity`

```json
{
  "version": "ethlambda/v0.1.0-main-892ad575/x86_64-unknown-linux-gnu/rustc-v1.85.0",
  "peer_id": "16Uiu2HAm7v1x…"
}
```

`version` is the full client version string, identical to what `ethlambda --version` prints: crate semver, git branch and short SHA, target triple, and rustc version. Baked in at compile time from `CARGO_PKG_VERSION` plus the `vergen-git2` build metadata.

`peer_id` is the node's libp2p peer ID (base58), derived from the node key and fixed for the lifetime of the process; it matches the identity the node presents to peers on the wire.

### `GET /lean/v0/node/syncing`

```json
{ "is_syncing": false, "head_slot": 1024, "sync_distance": 1, "finalized_slot": 986 }
```

`is_syncing` is the node's own stateful sync decision: head-vs-wall-clock lag with hysteresis and a network-stall override, updated each tick. It is the same signal that gates validator duties and drives the `lean_node_sync_status` metric, so the endpoint, the gate, and the metric always agree.

`sync_distance` is the raw number of slots between the node's current head and the current wall-clock slot, computed per request. Because `is_syncing` carries hysteresis and stall handling and is not recomputed from `sync_distance`, the two can point different ways near the threshold or during a network-wide stall.

### `GET` / `POST /lean/v0/admin/aggregator`

Toggle the aggregator role at runtime without restarting the node (hot-standby model, ported from leanSpec PR #636).

```bash
# Read current role
curl http://127.0.0.1:5052/lean/v0/admin/aggregator
# → {"is_aggregator": true}

# Toggle role; body must be a JSON boolean
curl -X POST http://127.0.0.1:5052/lean/v0/admin/aggregator \
  -H 'content-type: application/json' -d '{"enabled": false}'
# → {"is_aggregator": false, "previous": true}
```

| Status | Condition |
|--------|-----------|
| `200` | Role read / set |
| `400` | Missing/malformed body, missing `enabled`, or `enabled` not a JSON boolean (integers `0`/`1` and strings are rejected) |
| `503` | Aggregator controller not wired (does not occur in normal `main.rs` boot) |

> **Note:** Runtime toggles do **not** resubscribe gossip subnets, which are frozen at startup. A standby aggregator should boot with `--is-aggregator=true` (so subscriptions are in place), then use this endpoint to rotate duties. See the CLAUDE.md "Runtime Aggregator Toggle" notes for the operational model.

## Metrics & Debug Server (`:5054`)

| Method | Path | Response | Description |
|--------|------|----------|-------------|
| `GET` | `/metrics` | text | Prometheus-format metrics |
| `GET` | `/health` | JSON | Liveness check (same payload as the API health endpoint) |
| `GET` | `/debug/pprof/allocs` | pprof | jemalloc heap profile |
| `GET` | `/debug/pprof/allocs/flamegraph` | SVG | jemalloc heap flamegraph |

The metrics endpoint reads from the global Prometheus registry and needs no store access. See [Metrics](./metrics.md) for the full list of exposed series.

Heap-profiling endpoints are backed by jemalloc's built-in profiler and are **only functional on Linux**; other platforms return `501 Not Implemented`. On Linux they return `500` if profiling was not enabled at startup.

## Test-Driver Endpoints (Hive)

When the binary boots with `HIVE_LEAN_TEST_DRIVER=1` (any of `1`/`true`/`yes`), it runs in **test-driver mode** instead of the normal API server. The [ethereum/hive](https://github.com/ethereum/hive) lean simulator drives these endpoints to replay leanSpec fixtures over HTTP. The driver swaps its in-process `Store` on every `fork_choice/init`, so one container can replay many fixtures without restart.

| Method | Path | Response |
|--------|------|----------|
| `GET` | `/lean/v0/health` | JSON liveness (for the hive port check) |
| `POST` | `/lean/v0/test_driver/fork_choice/init` | `204` / `400` |
| `POST` | `/lean/v0/test_driver/fork_choice/step` | `StepResponse` |
| `POST` | `/lean/v0/test_driver/state_transition/run` | `StateTransitionResponse` |
| `POST` | `/lean/v0/test_driver/verify_signatures/run` | `VerifySignaturesResponse` |

## Content Types

| Kind | `Content-Type` |
|------|----------------|
| JSON | `application/json; charset=utf-8` |
| SSE | `text/event-stream` |
| SSZ | `application/octet-stream` |
| Prometheus metrics | `text/plain; version=0.0.4; charset=utf-8` |
| HTML | `text/html; charset=utf-8` |
