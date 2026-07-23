# event-monitor — interface contract (authoritative)

This file is the **single source of truth** for every interface shared between the
Rust backend (`src/`) and the vanilla-JS frontend (`web/`). Neither side may
change a field name, endpoint, or event name defined here without the other.

Hard constraints:

- Standalone Cargo project under `tooling/event-monitor/`. Its `Cargo.toml`
  declares an empty `[workspace]` table so it is its own workspace root, fully
  decoupled from the parent `ethlambda` workspace.
- **No dependency on any ethlambda crate.** The tool only knows the SSE *wire
  shape* documented below (copied from `docs/rpc.md`); it never imports
  `ethlambda-*`.

---

## 1. What it does

Dials the `GET /lean/v0/events` SSE endpoint of several ethlambda nodes,
timestamps each event on arrival (one collector clock), normalizes it, and
re-serves the browser a single merged stream plus a static dashboard. The
dashboard shows, for `block` / `attestation` / `aggregate` events:

- a **rolling beeswarm** of arrival offset *within the slot* per node (top), and
- a **propagation-delta** view: for one block/aggregate, how long after the
  first node each other node saw it (bottom).

```
 ethlambda nodes            event-monitor (Rust/axum)                 browser
 node-2 :5052 ─/events─┐   per-node SSE client → stamp arrival        EventSource
 node-3 :5052 ─/events─┼─▶  → normalize → tokio::broadcast hub  ─────▶ /stream
 node-N       ─/events─┘   axum: GET /  GET /stream  GET /api/meta     beeswarm+propagation
```

---

## 2. Upstream input — ethlambda SSE (what the collector consumes)

Endpoint per node: `GET {node.url}/lean/v0/events?topics=<csv>`.
Default subscribed topics (configurable): `block,attestation,aggregate`.

The response is `text/event-stream`. Each frame has an `event:` line (the topic
name) and a `data:` line (flat JSON). The collector must read **both**: the topic
comes from the `event:` line, the payload from `data:`. Comment lines
(`: keep-alive`, `: error - dropped N messages`) must be ignored.

Per-topic `data:` JSON shapes the collector must handle:

| topic (`event:` line) | `data:` JSON | slot is at |
|---|---|---|
| `block` | `{ "slot": 128, "block": "0x…" }` | `slot` |
| `attestation` | `{ "validator_id": 7, "data": { "slot": 12, "head": {…}, "target": {…}, "source": {…} } }` | `data.slot` |
| `aggregate` | `{ "participants": [0,1,2], "data": { "slot": 12, "head": {…}, "target": {…}, "source": {…} } }` | `data.slot` |
| `head` | `{ "slot": 128, "block": "0x…", "state": "0x…" }` | `slot` |
| `justified_checkpoint` | `{ "slot": 128, "block": "0x…", "state": "0x…" }` | `slot` |
| `finalized_checkpoint` | `{ "slot": 128, "block": "0x…", "state": "0x…" }` | `slot` |
| `safe_target` | `{ "slot": 128, "block": "0x…" }` | `slot` |
| `chain_reorg` | `{ "slot":…, "depth":…, "old_head_block":"0x…", "old_head_state":"0x…", "new_head_block":"0x…", "new_head_state":"0x…" }` | `slot` |
| `block_gossip` | `{ "slot": 128, "block": "0x…" }` | `slot` |

A `Checkpoint` (`head`/`target`/`source`) is `{ "root": "0x…", "slot": N }`.
The collector must be resilient: an unknown topic or a payload it can't parse is
logged and skipped, never fatal.

### Timing bootstrap (how the collector learns slot geometry)

On startup, fetch once from the first reachable node:

- `GET {node.url}/lean/v0/genesis` → `{ "genesis_time": 1770407233, "validator_count": 16 }`
- `GET {node.url}/lean/v0/config/spec` → `{ "MILLISECONDS_PER_SLOT": 4000, "INTERVALS_PER_SLOT": 5, … }`

`genesis_time` is in **seconds**. Offset formula (all ms):

```
slot_start_ms = genesis_time * 1000 + slot * MILLISECONDS_PER_SLOT
offset_ms     = arrival_ms - slot_start_ms        // may be negative under clock skew
```

`arrival_ms` = collector wall-clock at the moment the frame is received
(`SystemTime::now()` → epoch ms). Config may override `genesis_time` /
`ms_per_slot` for offline testing.

---

## 3. NormalizedEvent (collector → browser payload)

Serialized as JSON. Field names are frozen:

```json
{
  "node": "node-2",
  "topic": "block",
  "slot": 128,
  "arrival_ms": 1770407745123,
  "offset_ms": 742,
  "id": "0xabc123…",
  "validator_id": null,
  "participants": null
}
```

| field | type | meaning |
|---|---|---|
| `node` | string | configured node name |
| `topic` | string | one of the topic names in §2 |
| `slot` | u64 | slot the event refers to (from `slot` or `data.slot`) |
| `arrival_ms` | i64 | collector receive time, epoch ms |
| `offset_ms` | i64 | `arrival_ms - slot_start_ms`; can be negative |
| `id` | string \| null | grouping/propagation identity: block/head/safe_target/gossip → the `block` root; reorg → `new_head_block`; checkpoints → `block`; **aggregate → a session-stable content hash** of `(data, sorted participants)`, hex `0x…`; **attestation → null** |
| `validator_id` | u64 \| null | set only for `attestation` |
| `participants` | u32 \| null | set only for `aggregate`: participant **count** (never the full list — keep frames light) |

The aggregate `id` need only be stable **within one collector session** (used to
group the same aggregate seen across nodes); a simple FNV-1a / hash of the
canonical JSON of `{data, sorted participants}` rendered as `0x…` hex is fine.

---

## 4. Collector HTTP API (browser → collector)

Served by axum on the configured `listen` address.

### `GET /`
Serves `web/index.html` (and `web/` assets under their paths, e.g. `/app.js`,
`/style.css`). Static file serving rooted at the configured `static_dir`
(default `web`).

### `GET /stream`  (SSE, `text/event-stream`)
The merged live stream. Two SSE **event names**:

- `event: chain` — `data:` is one NormalizedEvent (§3).
- `event: status` — `data:` is a node status object:
  ```json
  { "node": "node-2", "state": "connected", "events_per_sec": 4.2 }
  ```
  `state` ∈ `"connected" | "reconnecting" | "down"`. Emitted on every state
  change and at least every few seconds as a heartbeat with a refreshed rate.

Keep-alive comments are sent to hold idle connections open. Best-effort: a slow
browser may miss events (same contract as upstream).

### `GET /api/meta`  (JSON)
One-shot bootstrap the frontend fetches on load:

```json
{
  "genesis_time": 1770407233,
  "ms_per_slot": 4000,
  "intervals_per_slot": 5,
  "window_slots": 30,
  "topics": ["block", "attestation", "aggregate"],
  "nodes": [
    { "name": "node-2", "url": "http://127.0.0.1:5052" },
    { "name": "node-3", "url": "http://127.0.0.1:5053" }
  ]
}
```

### `GET /api/history`  (JSON)
Startup backfill so a freshly-opened dashboard isn't blank. Returns the
collector's bounded in-memory ring of recent events (retained for
`history_slots` slots, hard-capped) plus the latest status per node:

```json
{
  "events": [ /* NormalizedEvent (§3), oldest first */ ],
  "status": [ { "node": "node-2", "state": "connected", "events_per_sec": 4.2 } ]
}
```

Each `events` element is byte-identical in shape to a `/stream` `chain`
event. **Startup ordering:** the frontend opens `/stream` first (buffering
live events), then fetches `/api/history`, seeds history, and flushes the
buffer, de-duping the overlap by `(node, topic, slot, id, validator_id,
arrival_ms)`. The broadcast never replays to new subscribers, so this
guarantees no gap and no double-count.

---

## 5. Config file (TOML)

Path via `--config <path>` (default `config.toml`). See `config.example.toml`.

```toml
listen = "127.0.0.1:8080"     # collector bind address
window_slots = 30             # initial rolling window; adjustable live in the UI
history_slots = 64            # slots of events buffered for GET /api/history backfill
static_dir = "web"            # dir served at GET /
topics = ["block", "attestation", "aggregate"]   # upstream topics to subscribe

# optional offline overrides; normally auto-fetched from the first node
# genesis_time = 1770407233
# ms_per_slot = 4000

[[nodes]]
name = "node-2"
url  = "http://127.0.0.1:5052"

[[nodes]]
name = "node-3"
url  = "http://127.0.0.1:5053"
```

---

## 6. Frontend visualization spec

Single dark/light-adaptive page, no framework, no build step. Fetches
`/api/meta`, backfills from `/api/history`, and streams live from
`EventSource("/stream")` (startup ordering per §4).

**Window control** (header): a numeric input, seeded from `meta.window_slots`,
that live-adjusts the rolling `window_slots` for **both** panels (clamped
`1..500`). Client-side only; no collector restart.

**Top — rolling beeswarm** (canvas): x-axis `0 … ms_per_slot`, gridlines at every
`ms_per_slot / intervals_per_slot`. One horizontal lane per node. Each incoming
`chain` event for topic `block`/`attestation`/`aggregate` is a dot at
`x = clamp(offset_ms, 0, ms_per_slot)`, small vertical jitter within its lane,
colored by topic: block `#4f8cff`, attestation `#37b24d`, aggregate `#f59f00`.
Keep only events from the last `window_slots` slots; older dots fade then drop.
Cap points per node (e.g. 2000) with oldest-first decimation so an attestation
flood can't wedge rendering. Legend + a note that older slots fade.

**Bottom — propagation delta** (canvas beeswarm): a topic toggle
(`block` default / `aggregate` / `head`). Group events of that topic by `id`;
for every id in the last `window_slots`, plot one dot per node in that node's
lane at `x = clamp(arrival_ms − min(arrival_ms over nodes for that id), 0,
ms_per_slot)`, jittered, faded by slot age. **Fixed 0…`ms_per_slot` x-axis**
(not rescaled to the data), so a dot's position is comparable across ids and
slots; a delta beyond one slot saturates at the right edge. Colors are kept off
the topic hues so the panels don't read as the same scale: the first node to
see an id (`delta == 0`) is `--prop-first` (violet), normal lag is
`--prop-normal` (teal), over-one-slot is `--prop-over` (magenta). Legend maps
the three colors; empty topics show a "Waiting for … events" note.

**Status bar**: one chip per node showing `state` (green/amber/red) and
`events_per_sec`, driven by `status` events.

Design language: match the calm, technical look of the approved mockup (thin
gridlines, muted labels, the three topic colors above). Must be readable in both
light and dark; degrade gracefully if a node is `down` (empty lane, red chip).
