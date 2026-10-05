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

Server-Sent Events stream (`Content-Type: text/event-stream`) of live chain events published by the blockchain actor. Seven event types:

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

Valid values are exactly the event names above: `head`, `block`, `justified_checkpoint`, `finalized_checkpoint`, `block_gossip`, `attestation`, `aggregate`. As in the Beacon API `eventstream` endpoint, `topics` is mandatory: there is no "subscribe to everything" default; list the topics you want.

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
that this node can answer from its own store. It **replaces** the `/lean/v0`
surface rather than sitting beside it; a `/lean/v0` path on a beacon node is a
`404`.

| Method | Path | Response | Description |
|--------|------|----------|-------------|
| `GET` | `/eth/v2/beacon/blocks/{block_id}` | JSON or SSZ | `SignedBeaconBlock` at `block_id` |
| `GET` | `/eth/v1/beacon/blocks/{block_id}/root` | JSON | That block's root |
| `GET` | `/eth/v1/beacon/execution_payload_envelopes/{block_id}` | JSON or SSZ | Gloas `SignedExecutionPayloadEnvelope` of that block (see below) |
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
| `POST` | `/eth/v1/validator/duties/ptc/{epoch}` | JSON | Payload timeliness committee seats for the given indices (gloas) |
| `GET` | `/eth/v1/validator/attestation_data` | JSON | What to attest to at `slot` |
| `GET` | `/eth/v1/validator/payload_attestation_data` | JSON or SSZ | What a committee member signs for `slot` (gloas) |
| `POST` | `/eth/v2/beacon/pool/attestations` | *(status only)* | Validate and gossip `SingleAttestation`s |
| `POST` | `/eth/v1/beacon/pool/payload_attestations` | *(status only)* | Validate, pool and gossip `PayloadAttestationMessage`s (gloas) |
| `GET` | `/eth/v1/beacon/pool/payload_attestations` | JSON | The pool's votes as aggregated `PayloadAttestation`s (gloas) |
| `POST` | `/eth/v1/validator/beacon_committee_subscriptions` | *(status only)* | Aggregators' entries join their committee's subnet |
| `GET` | `/eth/v2/validator/aggregate_attestation` | JSON | The pooled votes for a data root and committee, aggregated |
| `POST` | `/eth/v2/validator/aggregate_and_proofs` | *(status only)* | Validate and gossip `SignedAggregateAndProof`s |
| `GET` | `/eth/v3/validator/blocks/{slot}` | SSZ or JSON | An unsigned fulu block built on the head (`produceBlockV3`) |
| `POST` | `/eth/v4/validator/blocks/{slot}` | SSZ or JSON | An unsigned self-built gloas block, with its envelope and blobs when asked (`produceBlockV4`) |
| `GET` | `/eth/v1/validator/execution_payload_envelopes/{slot}/{beacon_block_root}` | SSZ or JSON | The unsigned envelope `produceBlockV4` built (gloas) |
| `POST` | `/eth/v2/beacon/blocks` | *(status only)* | Gossip and import a signed fulu or gloas block (`publishBlockV2`, SSZ) |
| `POST` | `/eth/v1/beacon/execution_payload_envelopes` | *(status only)* | Gossip a signed envelope and its data columns (gloas, SSZ) |
| `POST` | `/eth/v1/validator/prepare_beacon_proposer` | *(status only)* | Acknowledged, not acted on (see below) |

### Validator endpoints

These are what `ethlambda validator` needs to attest through this node. Every
answer is computed from the fork-choice head's post-state, read off the store
the chain actor writes, so no request waits on the actor.

- **Duties** answer for a window around the head, not any epoch. Proposer
  duties read fulu's `proposer_lookahead`, which covers the head's epoch and the
  next; attester duties cover the head's previous, current and next epoch,
  which is as far as its shuffling is already fixed. Anything else is a `400`.
  `dependent_root` follows each endpoint's v1 definition. Attester duties walk
  every committee of the epoch, a full shuffle per request on mainnet. Gloas
  epochs are served like fulu ones: gloas keeps fulu's `proposer_lookahead` and
  `upgrade_to_gloas` carries it over, so a fulu head already answers proposer
  duties for the first gloas epoch.
- **`attestation_data`** follows phase0's `validator.md`: the head block, the
  epoch's boundary block as target, and as source the current justified
  checkpoint of the head state advanced to the slot's epoch (through fork
  choice's cached `checkpoint_state`, and only when the head is in an earlier
  epoch). A slot before the head, or past the wall clock, is a `400`.
  `committee_index` is optional and ignored: from electra on every committee of
  a slot attests to the same data. `data.index` is `0` before gloas. At a gloas
  slot it is the payload-present flag: `0` when the head block is from the
  requested slot itself (its payload cannot be revealed yet), otherwise `1`
  exactly when fork choice holds the head block's payload as FULL
  (`Store::head_payload_status`, or one fresh `get_head_node` walk when none is
  recorded for this head). A pre-gloas head counts as FULL (see
  [Spec Deviations](./spec_deviations.md#a-pre-gloas-head-counts-as-full-in-attestation_dataindex)).
- **`pool/attestations`** checks each attestation against the electra
  `beacon_attestation_{subnet_id}` gossip conditions it can evaluate (clock
  window, `data.index == 0`, target epoch, the voted block known and the target
  its checkpoint block, committee membership, BLS signature), then gossips it on
  its subnet through fanout, without subscribing. A rejected attestation comes
  back in an `IndexedErrorMessage` with its position; the valid ones in the
  same batch are still published. There is no seen-attestation cache. Each
  accepted attestation also goes into the node's **attestation pool**, since
  gossip never delivers a node its own messages. `Eth-Consensus-Version` must
  name electra, fulu or gloas here and on `aggregate_and_proofs`, and must match
  the fork of each item's slot: a `gloas` header on a pre-gloas slot, or an older
  one on a gloas slot, fails that item (not the batch) with
  `Eth-Consensus-Version does not match the attestation slot's fork`. At a
  gloas slot `data.index` may be `0` or `1`, checked with gloas's payload-status
  gossip rule (a vote in the voted block's own slot must be `0`; `1` needs the
  node to have verified the payload, otherwise the item fails). A gloas
  `SingleAttestation` is electra's own container.
- **`beacon_committee_subscriptions`**: each aggregator's entry makes the node
  join its committee's attestation subnet until the end of that slot, so the
  committee's votes from other validators reach the pool too: every
  attestation this node relays has passed the `beacon_attestation_{subnet_id}`
  checks first, and the ones accepted on a joined subnet are pooled. Joined
  subnets are left once their slot has passed, and never appear in `attnets`.
- **`aggregate_attestation`** answers from the pool: every vote held for the
  data root and committee, as electra's `Attestation` with the BLS aggregate of
  their signatures; at a gloas slot the answer is `{version: "gloas", data}`
  with gloas's `Attestation` (the same JSON shape). JSON only. `404` when
  nothing is held.
- **`aggregate_and_proofs`** checks each aggregate with the same
  `beacon_aggregate_and_proof` gossip conditions this node applies to its
  peers' aggregates (`gossip::aggregate`), signatures included, against a
  fresh seen-cache (a node never receives its own messages, so P2P's says
  nothing about them). What passes is gossiped on the topic and goes into the
  pool. The `Eth-Consensus-Version` header picks the decoder: `gloas` takes
  gloas's `SignedAggregateAndProof`, the others electra's.
- **The attestation pool** holds, the best-covered per data root and
  committee: votes from `pool/attestations` and the aggregator subnets,
  aggregates from `aggregate_and_proofs`, and every electra gossip aggregate
  P2P accepts (gloas aggregates included, in gloas's container), once all three
  of its signatures have verified. Gossip aggregates are pooled on arrival, so a slot's aggregates are there when the
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
  blobs. A slot the schedule does not place at fulu (gloas included) is a
  `400`, checked before the execution client; `produceBlockV3` is the fulu
  endpoint, and a gloas slot goes to `produceBlockV4`.
- **`POST beacon/blocks`** takes SSZ and the `Eth-Consensus-Version` header
  (`fulu` or `gloas`, else `400`; a non-SSZ content type is a `415`). Fulu: a
  `SignedBlockContents`; the node checks the block is after the head and its
  proposer signature, then gossips it on `beacon_block` and hands it to the
  chain actor to import. A slot the schedule does not place at fulu is a `400`,
  checked before the head state is advanced. Gloas: a bare
  `gloas::SignedBeaconBlock` (a gloas block carries no payload or blobs; they
  follow in the envelope). The slot must be scheduled at gloas, the parent must
  be held, the slot must be after the parent's, and the proposer and signature
  are checked against the parent's state advanced to the slot (all `400`
  otherwise), before the block is gossiped and handed to the chain actor.

**Fulu blobs are not supported.** Publishing a blob-carrying fulu block means
computing and gossiping its data column sidecars, which this node does not do
for fulu, and peers will not import a block they cannot sample. Such payloads
are refused at production (`503`, which a validator client fails over on) and
such blocks at publication (`400`). Gloas blobs are supported: the envelope
publication below builds and gossips the columns.

### Gloas block production

A gloas proposer signs two things on their own, the block and the envelope that
reveals its payload, and this node serves both halves. It only builds for
itself: no builder bid is taken from gossip or a builder API, and no
`SignedProposerPreferences` is read (see
[Spec Deviations](./spec_deviations.md#self-build-only)).

**`POST /eth/v4/validator/blocks/{slot}`** (`produceBlockV4`):

| | |
|---|---|
| Query | `randao_reveal` (required), `include_payload` (required, `true` or `false`), `graffiti` (optional, 32-byte hex), `skip_randao_verification` (accepted, ignored) |
| Request headers | `Eth-Consensus-Version` is optional but must be `gloas` when present. `Accept: application/octet-stream` for SSZ, JSON otherwise |
| Body | A `BuilderConfig` (`min_bid`, `builder_boost_factor`, `builders`), JSON, or SSZ with `Content-Type: application/octet-stream`. It is decoded and otherwise ignored; a missing or undecodable one is a `400` |
| `200` SSZ | With `include_payload=true`, `BlockContents` (`block`, `execution_payload_envelope`, `kzg_proofs`, `blobs`); with `false`, the bare `gloas::BeaconBlock` |
| `200` JSON | `{version: "gloas", consensus_block_value, execution_payload_value, execution_payload_included, data}`, where `data` is the same container as the SSZ body |
| Response headers | `Eth-Consensus-Version: gloas`, `Eth-Execution-Payload-Included` (`true` or `false`), `Eth-Execution-Payload-Value` (wei, decimal), `Eth-Consensus-Block-Value` (always `0`: no builder comparison happens on this node) |
| `400` | A slot the schedule does not place at gloas, a missing or malformed query, a wrong `Eth-Consensus-Version`, a bad body, a slot not after the head block, or a `randao_reveal` that does not verify against the slot's proposer. The slot check precedes the execution-client check, so it is a `400` on any node |
| `503` | No execution client configured, the execution client did not start or return a build, or the node is building on a FULL parent whose envelope it does not hold |

The node advances the head state to the slot, and decides which parent payload
to build on with `should_build_on_full` over the payload status fork choice
recorded for the head. It then asks its execution client to build
(`forkchoiceUpdatedV4` with `PayloadAttributesV4`, then `getPayloadV6`) with the
proposer's `prepare_beacon_proposer` fee recipient. The body packs the
attestation pool's best aggregates and the payload attestation pool's votes for
the parent block (an aggregate that does not verify against the advanced state
is dropped, since one bad operation fails the block), and the state root comes
from running the block through `process_block`. The bid is a zero-value
self-build bid read off the built payload. What was built is cached by `(slot,
block root)`, for the current and previous slot only.

**`GET /eth/v1/validator/execution_payload_envelopes/{slot}/{beacon_block_root}`**
serves the cached unsigned envelope, for a client that asked for the block with
`include_payload=false`: `{version: "gloas", data}` as JSON, or the SSZ
`ExecutionPayloadEnvelope` on `Accept: application/octet-stream`, with
`Eth-Consensus-Version: gloas`. `404` when nothing is cached for the pair
(unknown, or older than the previous slot); `400` for an unparseable slot or
root.

**`POST /eth/v1/beacon/execution_payload_envelopes`** takes the signed envelope,
SSZ only (`415` otherwise), with `Eth-Consensus-Version: gloas` and
`Eth-Blob-Data-Included` (both required, else `400`):

- `true`: the body is `SignedExecutionPayloadEnvelopeContents` (the signed
  envelope, `kzg_proofs`, `blobs`).
- `false`: the body is the bare signed envelope, and the blobs and proofs come
  from the production cache. `400` when none is cached and the block's bid
  commits to blobs.

The envelope's block is waited for, polling every 50 ms for up to 4 seconds,
since a validator client publishes the envelope right after the block returns,
which is before the chain actor has imported it; a block still unknown after
that is a `400` (`unknown block`). The envelope must fulfill the block's bid
(builder index and block hash), the blobs must match the bid's commitments, the
signature must verify under `DOMAIN_BEACON_BUILDER` against the block's
post-state, and every data column built from the blobs must verify against the
commitments and cell proofs; any failure is a `400`. A success is `200` once the
envelope and all `NUMBER_OF_COLUMNS` gloas data column sidecars are handed to
P2P, which gossips them together. A node that does not subscribe to a column's
subnet publishes through gossipsub fanout.

### Payload timeliness committee

- **`POST /eth/v1/validator/duties/ptc/{epoch}`** takes a JSON array of quoted
  validator indices (an empty array or a bad index is a `400`) and answers
  `{dependent_root, execution_optimistic, data: [{pubkey, validator_index,
  slot}]}`: one duty per validator, the first slot of the epoch whose committee
  seats it. An index with no seat, or unknown, gets none. The epoch may be at
  most one past the later of the head state's and the wall clock's epoch (else
  `400`). An epoch before the gloas fork answers `200` with an empty `data`, so
  a client can ask every epoch. A gloas head state answers from its
  `ptc_window`; an epoch the head has not caught up to, or the first gloas epoch
  under a fulu head, is answered from a copy of the head state advanced to the
  epoch's first slot, crossing the gloas upgrade where it falls, on a blocking
  thread. A gloas epoch more than one before the head state's is a `400`.
  `dependent_root` is defined as for attester duties. There is no `503`.
- **`GET /eth/v1/validator/payload_attestation_data?slot=`** answers
  `{version: "gloas", data: {beacon_block_root, slot, payload_present,
  blob_data_available}}` as JSON, or the SSZ `PayloadAttestationData` on
  `Accept: application/octet-stream`, with `Eth-Consensus-Version: gloas`. The
  data is for the block of that very slot on the head's chain; a slot with no
  such block (or whose block is not a gloas block) answers `204` with no body,
  which a client reads as "cast no vote". A slot before the gloas fork is a
  `400`, and a node that is syncing answers `503`. `payload_present` is whether
  the block's envelope reached this node before the slot's start plus
  `PAYLOAD_DUE_BPS` of it, judged by arrival time (see
  [Spec Deviations](./spec_deviations.md#payload_present-is-judged-by-the-envelopes-arrival-time)).
  `blob_data_available` is true when the bid commits to no blobs, the payload is
  verified, or every column this node custodies for the block is stored.
- **`POST /eth/v1/beacon/pool/payload_attestations`** takes a JSON array of
  `PayloadAttestationMessage`s; `Eth-Consensus-Version` is optional and must be
  `gloas` when present. Each message passes the checks gossip applies to a
  peer's (the current slot, a known block at the slot, committee membership,
  signature) against a fresh seen-cache. A valid one is pooled and gossiped; one
  already pooled is neither pooled nor gossiped again and still counts as
  accepted. A rejected one comes back in an `IndexedErrorMessage` (`400`) as
  `{outcome}: {reason}` with its position, and the rest still go out; a
  head-state cache miss is a per-item `ignore: state_unavailable`.
- **`GET /eth/v1/beacon/pool/payload_attestations?slot=`** answers `{version:
  "gloas", data}` with the pool's votes as the specification's
  `PayloadAttestation`s, those of `slot` only when given: one aggregate per slot
  and `PayloadAttestationData`, a bit per seat of that slot's committee
  (`get_ptc` on the head state) and the seats' signatures aggregated, the way
  block production packs them. The pool itself keeps the individual messages.
  JSON only; a vote whose slot falls outside the head state's committee window
  is left out.

The payload attestation pool is shared with P2P, which fills it from accepted
gossip, so a block this node builds carries the votes its peers sent too.

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

### `GET /eth/v1/beacon/execution_payload_envelopes/{block_id}`

Gloas moves a block's execution payload into a separate signed envelope. This
serves the one the node has verified, as `{version: "gloas", execution_optimistic,
finalized, data}` JSON or as SSZ on `Accept: application/octet-stream`, with
`Eth-Consensus-Version: gloas` either way. It is also what a checkpoint-syncing
node asks for the payload of its anchor (see
[`checkpoint_sync.md`](./checkpoint_sync.md)).

| Status | When |
|--------|------|
| `400` | `block_id` is malformed |
| `404` | the block is unknown, or the node holds no envelope for it |

The second `404` is deliberately one status for several situations: the store
keeps verified envelopes only, so a withheld payload, a payload not yet
received and a pre-gloas block (which has no envelope; the specification's
error list names no other status for it) are indistinguishable here. A caller
must read `404` as "unknown to this node", not as "the payload is empty".

### `execution_optimistic` under gloas

Before gloas a block's payload ran inside the block, so the flag is whether the
block is in the store's optimistic set. From gloas on the payload is a separate
object that may arrive late or never, and two rules share the flag:

- an **envelope** response is optimistic iff that payload's verdict is not
  `VALID` (an unrecorded verdict reads as `NOT_VALIDATED`);
- a **block, header, state or finality-checkpoints** response for a gloas block
  is optimistic iff the latest FULL payload the block builds on is not `VALID`.
  The walk starts at the block's parent: if the block's bid names the parent's
  payload as its parent block hash it reads the parent's verdict, and otherwise
  it steps back to the parent and repeats. A pre-gloas block on the way reads
  the optimistic set. The block's own payload does not count, so a withheld
  payload does not make the chain look unverified.

Pre-gloas responses are unchanged. One helper implements both rules
(`shared/optimistic.rs`) and every response that carries the flag goes through
it.

### `GET /eth/v1/config/spec`

One flat object holding the network's configuration, the compiled preset, and
the specification's constants, as the Beacon API asks. Validator clients depend
on it: lighthouse's refuses a beacon node whose `PRESET_BASE` does not match
its own, and treats an absent key as a mismatch.

The key set is lighthouse's plus gloas's preset and constant keys, read from
`beacon::preset` and `beacon::constants` rather than typed here: `PTC_SIZE`,
`MAX_PAYLOAD_ATTESTATIONS`, `MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD`,
`MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD`, `MAX_BUILDERS_PER_WITHDRAWALS_SWEEP`,
the four gloas domains (`DOMAIN_BEACON_BUILDER`, `DOMAIN_PTC_ATTESTER`,
`DOMAIN_PROPOSER_PREFERENCES`, `DOMAIN_BUILDER_DEPOSIT`), the builder
withdrawal prefix and request types, and the `BUILDER_INDEX_*`,
`BUILDER_PAYMENT_THRESHOLD_*` and `PAYLOAD_BUILDER_VERSION` constants. Gloas's
schedule, timing and churn keys are `Config` fields, so they were already
reported. Three keys are left out because the specification does not define
them (`GAS_LIMIT_ADJUSTMENT_FACTOR`, `RESP_TIMEOUT`, `TTFB_TIMEOUT`), and so are
gloas's `MAX_*_SIZE` preset keys, which bound gossip message sizes the node does
not run on. Domain types and withdrawal prefixes are `0x`-prefixed hex;
`VERSIONED_HASH_VERSION_KZG` is a decimal, as lighthouse reports it.
`GENESIS_TIME` is absent: `/eth/v1/beacon/genesis` reports it.

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
