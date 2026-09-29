# HTTP API

ethlambda exposes HTTP over **two independent [Axum](https://github.com/tokio-rs/axum) servers** on separate ports, so the API and the metrics/debug surface can have different network policies:

- **API server** — consensus data (blocks, states, checkpoints, fork choice) and admin controls.
- **Metrics & debug server** — Prometheus metrics and heap-profiling endpoints. No store access.


Which API server a node serves follows from its store's chain tag, not from the
sub-command: `ethlambda node` serves the lean surface under `/lean/v0`,
`ethlambda beacon` serves the [Beacon API](#beacon-api-server-5052-on-ethlambda-beacon)
under `/eth/v1` and `/eth/v2`. The two are alternatives, never merged, because the
lean handlers read state variants and metadata keys a beacon directory does not
carry. Roots are serialized as `0x`-prefixed hex strings on both.

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
| `GET` | `/lean/v0/blocks/finalized` | SSZ, or JSON on request | Latest finalized `SignedBlock` |
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

Protocol parameters the node is running on. Keys mirror the leanSpec constant names.
`MILLISECONDS_PER_SLOT` and `MILLISECONDS_PER_INTERVAL` reflect the network's config
file rather than a compile-time constant, so a node on an 8-second network reports
`8000` and `1600` here:

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

Server-Sent Events stream (`Content-Type: text/event-stream`) of live chain events published by the blockchain actor. Eight event types:

Payload fields mirror the Ethereum beacon-API eventstream where an analog exists: `block` is the block root, `state` the state root, and `slot` stands in for the beacon `epoch`. `justified_checkpoint` and `aggregate` are ethlambda extensions with no beacon topic.

| Event | Payload | Emitted when |
|-------|---------|--------------|
| `head` | `{ "slot": 128, "block": "0x…", "state": "0x…" }` | Fork choice selects a new head within `HEAD_EVENT_RECENCY_SLOTS` (32 slots) of the wall clock; no head events fire during catch-up |
| `block` | `{ "slot": 128, "block": "0x…" }` | A block is imported into the store |
| `justified_checkpoint` | `{ "slot": 120, "block": "0x…", "state": "0x…" }` | The justified checkpoint advances |
| `finalized_checkpoint` | `{ "slot": 96, "block": "0x…", "state": "0x…" }` | The finalized checkpoint advances |
| `block_gossip` | `{ "slot": 128, "block": "0x…" }` | A block is seen on the network, before import |
| `attestation` | `{ "validator_id": 4, "data": { "slot": 128, "head": {…}, "target": {…}, "source": {…} } }` | A single validator vote passes gossip validation (signature omitted) |
| `aggregate` | `{ "participants": [0, 3, 4], "data": { "slot": 128, "head": {…}, "target": {…}, "source": {…} } }` | A committee-signature aggregate is produced locally or accepted from gossip (proof omitted) |
| `chain_reorg` | `{ "slot": 130, "depth": 1, "old_head_block": "0x…", "new_head_block": "0x…", "old_head_state": "0x…", "new_head_state": "0x…" }` | The new head does not descend from the previous one; sent ahead of that `head`, and never gated on recency. `slot` is the new head's; `depth` is how many slots the old head sat above the two heads' common ancestor (the Beacon API's definition, in slots; the `lean_fork_choice_reorg_depth` metric counts blocks walked instead) |

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

Valid values are exactly the event names above: `head`, `block`, `justified_checkpoint`, `finalized_checkpoint`, `block_gossip`, `attestation`, `aggregate`, `chain_reorg`. A Beacon API topic this surface does not serve (`data_column_sidecar`, say) is refused as unknown. As in the Beacon API `eventstream` endpoint, `topics` is mandatory: there is no "subscribe to everything" default; list the topics you want.

| Status | Condition |
|--------|-----------|
| `200` | Stream opened for the listed topics |
| `400` | `topics` is missing or empty, or any listed name is not a known topic (body names the offending value) |

Events are fanned out over a single bounded broadcast channel shared by all topics. A client that reads too slowly skips past the events it missed: they are dropped for that subscriber rather than back-pressured onto the actor, so treat the stream as best-effort and re-sync via the blocks endpoints after a gap. A client that falls behind receives an SSE comment line `: error - dropped N messages` marking the gap (wire-compatible with Lighthouse) before the stream continues; re-sync via the blocks endpoints rather than trusting the skipped range. Keep-alive comments are sent periodically to hold idle connections open.

Because the ring buffer is shared, the high-rate `attestation` events (roughly one per validator per slot) dominate its occupancy: a subscriber's tolerable stall is `capacity / total_event_rate`, not per-topic, so filtering with `?topics=` narrows what you receive but does **not** widen the lag window against an attestation flood. Subscribers that only need low-rate topics (`head`, `finalized_checkpoint`, …) are still evicted at the aggregate rate. If real usage shows this biting, the fix is a per-topic channel split behind the event bus (the `subscribe(TopicSet)` API is unaffected).

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
  "version": "ethlambda/v0.1.0-main-892ad575/x86_64-unknown-linux-gnu/rustc-v1.97.1",
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

## Beacon API Server (`:5052`, on `ethlambda beacon`)

The subset of the [Ethereum Beacon API](https://ethereum.github.io/beacon-APIs/)
that this follower can answer from its own store. It **replaces** the `/lean/v0`
surface rather than sitting beside it; a `/lean/v0` path on a beacon node is a
`404`.

| Method | Path | Response | Description |
|--------|------|----------|-------------|
| `GET` | `/eth/v2/beacon/blocks/{block_id}` | JSON or SSZ | `SignedBeaconBlock` at `block_id` |
| `GET` | `/eth/v1/beacon/blocks/{block_id}/root` | JSON | That block's root |
| `GET` | `/eth/v1/beacon/headers/{block_id}` | JSON | `SignedBeaconBlockHeader`, plus `canonical` |
| `GET` | `/eth/v2/debug/beacon/states/{state_id}` | JSON or SSZ | `BeaconState` at `state_id` |
| `GET` | `/eth/v1/beacon/states/{state_id}/finality_checkpoints` | JSON | That state's three checkpoints |
| `GET` | `/eth/v1/beacon/genesis` | JSON | Genesis time, validators root, fork version |
| `GET` | `/eth/v1/config/spec` | JSON | The store's `Config`, plus `PRESET_BASE`, `CONFIG_NAME`, the preset and the constants (see below) |
| `GET` | `/eth/v1/node/syncing` | JSON | Head slot, sync distance, optimistic flag |
| `GET` | `/eth/v1/node/health` | *(status only)* | `200` caught up, `206` syncing |
| `GET` | `/eth/v1/node/version` | JSON | Client version string |
| `GET` | `/eth/v1/node/identity` | JSON | Peer ID and metadata only (see below) |
| `GET`, `POST` | `/eth/v1/beacon/states/{state_id}/validators` | JSON | Registry entries by index or pubkey, with status |
| `GET` | `/eth/v1/validator/duties/proposer/{epoch}` | JSON | Proposers for the head's epoch or the next |
| `POST` | `/eth/v1/validator/duties/attester/{epoch}` | JSON | Committee assignments for the given indices |
| `GET` | `/eth/v1/validator/attestation_data` | JSON | What to attest to at `slot` |
| `POST` | `/eth/v2/beacon/pool/attestations` | *(status only)* | Validate and gossip `SingleAttestation`s |
| `POST` | `/eth/v1/validator/beacon_committee_subscriptions` | *(status only)* | Aggregators' entries join their committee's subnet |
| `GET` | `/eth/v2/validator/aggregate_attestation` | JSON | The pooled votes for a data root and committee, aggregated |
| `POST` | `/eth/v2/validator/aggregate_and_proofs` | *(status only)* | Validate and gossip `SignedAggregateAndProof`s |
| `GET` | `/eth/v3/validator/blocks/{slot}` | SSZ or JSON | An unsigned block built on the head (`produceBlockV3`) |
| `POST` | `/eth/v2/beacon/blocks` | *(status only)* | Gossip and import a signed block (`publishBlockV2`, SSZ) |
| `POST` | `/eth/v1/validator/prepare_beacon_proposer` | *(status only)* | Acknowledged, not acted on (see below) |
| `GET` | `/eth/v1/events` | SSE | Live stream of chain events (see below) |

### Validator endpoints

These are what `ethlambda validator` needs to attest through this node. Every
answer is computed from the fork-choice head's post-state, read off the store
the chain actor writes, so no request waits on the actor.

- **Duties** answer for a window around the head, not any epoch. Proposer
  duties read fulu's `proposer_lookahead`, which covers the head's epoch and the
  next; attester duties cover the head's previous, current and next epoch,
  which is as far as its shuffling is already fixed. Anything else is a `400`.
  `dependent_root` follows each endpoint's v1 definition. Attester duties walk
  every committee of the epoch, a full shuffle per request on mainnet.
- **`attestation_data`** follows phase0's `validator.md`: the head block, the
  epoch's boundary block as target, and as source the current justified
  checkpoint of the head state advanced to the slot's epoch (through fork
  choice's cached `checkpoint_state`, and only when the head is in an earlier
  epoch). A slot before the head, or past the wall clock, is a `400`.
- **`pool/attestations`** checks each attestation against the electra
  `beacon_attestation_{subnet_id}` gossip conditions it can evaluate (clock
  window, `data.index == 0`, target epoch, the voted block known and the target
  its checkpoint block, committee membership, BLS signature), then gossips it on
  its subnet through fanout, without subscribing. A rejected attestation comes
  back in an `IndexedErrorMessage` with its position; the valid ones in the
  same batch are still published. There is no seen-attestation cache. Each
  accepted attestation also goes into the node's **attestation pool**, since
  gossip never delivers a node its own messages.
- **`beacon_committee_subscriptions`**: each aggregator's entry makes the node
  join its committee's attestation subnet until the end of that slot, so the
  committee's votes from other validators reach the pool too: every
  attestation this node relays has passed the `beacon_attestation_{subnet_id}`
  checks first, and the ones accepted on a joined subnet are pooled. Joined
  subnets are left once their slot has passed, and never appear in `attnets`.
- **`aggregate_attestation`** answers from the pool: every vote held for the
  data root and committee, as electra's `Attestation` with the BLS aggregate of
  their signatures. `404` when nothing is held.
- **`aggregate_and_proofs`** checks each aggregate with the same
  `beacon_aggregate_and_proof` gossip conditions this node applies to its
  peers' aggregates (`gossip::aggregate`), signatures included, against a
  fresh seen-cache (a node never receives its own messages, so P2P's says
  nothing about them). What passes is gossiped on the topic, goes into the
  pool, and is handed to the chain actor, which applies it to fork choice and
  announces it on `/eth/v1/events`'s `attestation`.
- **The attestation pool** holds, the best-covered per data root and
  committee: votes from `pool/attestations` and the aggregator subnets,
  aggregates from `aggregate_and_proofs`, and every electra gossip aggregate
  P2P accepts, once all three of its signatures have verified. Gossip
  aggregates are pooled on arrival, so a slot's aggregates are there when the
  next slot's block is asked for. Entries more than an epoch old are dropped
  once a slot.
- **`prepare_beacon_proposer`** records each validator's fee recipient, in
  memory (a validator client repeats the call every epoch).
- **`blocks/{slot}`** advances the head state to the slot and asks the node's
  own execution client to build on the head (`forkchoiceUpdatedV3` with
  payload attributes, then `getPayloadV5`), with the proposer's fee recipient.
  The body packs the pool's best aggregates (committees voting alike merged
  into one EIP-7549 attestation, up to `MAX_ATTESTATIONS_ELECTRA`). A candidate
  is packed only if its target root is the advanced state's own block root for
  that epoch and its aggregate signature verifies against that state, so an
  aggregate made on another branch cannot fail the whole block. The body also
  votes the state's own `eth1_data`, and carries an empty sync aggregate and no
  slashings, exits or credential changes. The state root comes from running
  the block through `process_block`. The answer is fulu `BlockContents`, with
  `Eth-Execution-Payload-Blinded: false`; there is no builder flow. It is a
  **`503`** without a configured execution client, or when the payload carries
  blobs.
- **`POST beacon/blocks`** takes SSZ `SignedBlockContents`, checks the block
  is after the head and its proposer signature, then gossips it on
  `beacon_block` and hands it to the chain actor to import.

**Blobs are not supported yet.** Publishing a blob-carrying block means
computing and gossiping its data column sidecars, which this node does not do,
and peers will not import a block they cannot sample. Such payloads are refused
at production (`503`, which a validator client fails over on) and such blocks
at publication (`400`).

`tooling/kurtosis-validator/network_params_ethlambda_beacon.yaml` points the
validator client at this node alone, so every block on that devnet is one this
node built.

### Encoding

**JSON is the default**; SSZ is served on `Accept: application/octet-stream`,
which is the order lighthouse serves. An `Accept` listing both is ranked by its
`q` weights. Every response carrying a fork-versioned container also sets
`Eth-Consensus-Version` to the lowercase fork name, in both encodings, since SSZ
carries no type tag.

JSON here follows the Beacon API's own encoding, which is **not** the lean
surface's: every integer is a quoted decimal string, byte strings are
`0x`-prefixed hex, and `Uint256` is quoted decimal rather than hex. Errors are
`{"code": ..., "message": ...}`, where the lean surface uses `{"error": ...}`.

Serving `/eth/v2/debug/beacon/states/finalized` as SSZ is what makes this client
checkpoint-syncable from itself: it is the exact path
[`checkpoint_sync.rs`](./checkpoint_sync.md) fetches from other clients.

### `GET /eth/v1/config/spec`

One flat object holding the network's configuration, the compiled preset, and
the specification's constants, as the Beacon API asks. Validator clients depend
on it: lighthouse's refuses a beacon node whose `PRESET_BASE` does not match
its own, and treats an absent key as a mismatch.

The key set is lighthouse's, less gloas-only keys (this build cannot process
gloas) and three keys the specification does not define
(`GAS_LIMIT_ADJUSTMENT_FACTOR`, `RESP_TIMEOUT`, `TTFB_TIMEOUT`). Domain types
and withdrawal prefixes are `0x`-prefixed hex; `VERSIONED_HASH_VERSION_KZG` is
a decimal, as lighthouse reports it. `GENESIS_TIME` is absent:
`/eth/v1/beacon/genesis` reports it.

The configuration keys come from the `Config` the data directory was
initialized with. Some of them (the custody and subnet counts, the
`MAX_REQUEST_*` limits, `MAX_PAYLOAD_SIZE`, the snappy message domains,
`MAXIMUM_GOSSIP_CLOCK_DISPARITY`) the node runs on compile-time constants for,
rather than reading them from `Config`. Startup refuses a network whose
`config.yaml` sets any of them to a different value (see
[`cli.md`](./cli.md)), so what this endpoint reports is what the node uses.
`CONFIG_NAME` is the stored name: a resume under a renamed `config.yaml` warns
and keeps it.

### Accepted ids, and three that are refused

`block_id` and `state_id` accept `head`, `finalized`, `justified`, a slot
number, and a `0x`-prefixed 32-byte root. Two cases are deliberate refusals,
both recorded in [Spec Deviations](./spec_deviations.md):

- **`genesis`** is a `404` on either id. `Table::BlockRoots` indexes the
  canonical branch above the store's anchor, and the anchor's own slot is never
  written to it; a checkpoint-synced directory has no genesis block either way.
- **A `state_id` given as a `0x…` root** is a `404`: states are keyed by *block*
  root here, with no reverse index. The refusal names the ids that do work.

The **anchor's own slot** does resolve, despite being absent from that index:
the lookup falls back to the roots the store can name and accepts one only when
the block under it really sits at that slot. This matters because it is the
slot a checkpoint-syncing peer asks for right after reading the finalized
state. A slot the store holds nothing at is still a `404`.

`/eth/v1/node/identity` reports `peer_id` and `metadata`; `enr`,
`p2p_addresses` and `discovery_addresses` are empty.

### `GET /eth/v1/events`

The Beacon API eventstream: the same Server-Sent Events stream as
[`/lean/v0/events`](#get-leanv0events) (topic on the `event:` line, payload on
`data:`, one shared best-effort ring, `: error - dropped N messages` on a gap),
with the Beacon API's own topics and payloads. The response also sets
`X-Accel-Buffering: no`, so a reverse proxy does not hold events back.

```bash
curl -N 'http://127.0.0.1:5052/eth/v1/events?topics=head&topics=block,finalized_checkpoint'
```

`topics` is required, and may be repeated (`?topics=head&topics=block`, the
specification's form) or comma-separated (`?topics=head,block`, which
lighthouse also accepts). Duplicates collapse. A missing or empty `topics`, or
a name that is not a Beacon API topic, is a `400` in the Beacon API error shape:
`{"code":400,"message":"Invalid topic: weather_forecast"}`.

**Accepted is not emitted.** Every topic in the specification is accepted, so
a validator client subscribing to several at once is not turned away, but only
these are ever sent:

| Event | Payload | Emitted when |
|-------|---------|--------------|
| `head` | `{"slot":"10", "block":"0x…", "state":"0x…", "epoch_transition":false, "previous_duty_dependent_root":"0x…", "current_duty_dependent_root":"0x…", "execution_optimistic":false}` | The head changed, and is within 32 slots of the wall clock |
| `block` | `{"slot":"10", "block":"0x…", "execution_optimistic":false}` | A block is imported |
| `block_gossip` | `{"slot":"10", "block":"0x…"}` | A block passed gossip validation, or was published through `POST /eth/v2/beacon/blocks` |
| `finalized_checkpoint` | `{"block":"0x…", "state":"0x…", "epoch":"2", "execution_optimistic":false}` | The finalized checkpoint advanced |
| `chain_reorg` | `{"slot":"200", "depth":"50", "old_head_block":"0x…", "new_head_block":"0x…", "old_head_state":"0x…", "new_head_state":"0x…", "epoch":"2", "execution_optimistic":false}` | The new head does not descend from the previous one |
| `attestation` | the aggregate's `Attestation` | An aggregate passed the `beacon_aggregate_and_proof` rules: accepted from gossip, or submitted through `POST /eth/v2/validator/aggregate_and_proofs` |
| `data_column_sidecar` | `{"block_root":"0x…", "index":"1", "slot":"1"}` | A column this node custodies is stored, from any source |

Never emitted: `single_attestation` (subnet votes are verified and relayed but
never reach the chain actor), the operation topics (`voluntary_exit`,
`proposer_slashing`, `attester_slashing`, `bls_to_execution_change`,
`contribution_and_proof`: no operation pools), `payload_attributes`, the light
client topics, `blob_sidecar`, and `head_v2` with every other gloas topic (this
build stops at fulu).

How head and finality events behave:

- **One `head` per head recompute.** The chain actor recomputes the head once
  per tick and once per import cascade, and diffs it against the head it last
  reported. A cascade importing several blocks announces each `block`, then a
  single `head` for where it ended.
- **Any head change counts**, including one no block caused (a tick's votes
  moving the head to a sibling, or an execution client's `INVALID` verdict
  moving it back to an ancestor). Lighthouse reports only the `chain_reorg` for
  those; Prysm reports both, as this node does.
- **Stale heads are not reported.** A head more than 32 slots behind the wall
  clock (catch-up) sends no `head`; `block` events still show progress.
  `chain_reorg` and `finalized_checkpoint` are not gated.
- **Order:** each `block` as it imports, then `chain_reorg`, `head`,
  `finalized_checkpoint`.
- `epoch_transition` is whether the head's epoch is later than the previous
  head's. The dependent roots follow the specification, with the genesis block
  root on underflow (epochs 0 and 1).
- `chain_reorg.depth` is how many slots the previous head sat above the two
  heads' common ancestor (lighthouse's definition).
- `execution_optimistic` is reported as it is, optimistic heads included
  (lighthouse suppresses those `head` events; Prysm sends them flagged).

An aggregate this node's own validator client submits reaches the chain actor
too: gossip never delivers a node its own messages, so
`POST /eth/v2/validator/aggregate_and_proofs` hands each accepted one to the
actor after gossiping it. That is also what puts this node's own aggregates
into its fork choice.

Event payloads are built only while at least one client is connected, whatever
topics that client asked for; with none, the stream costs nothing.

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
