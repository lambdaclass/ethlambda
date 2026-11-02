# Block telemetry (ClickHouse)

With `--telemetry.clickhouse-url`, a node writes one row per point in each
block's life, and per data column arrival, to a ClickHouse table named
`block_events`. The table layout is [Silver](https://github.com/gattaca-com/silver)'s,
so both clients' rows can share one table and one set of queries.

Rows are batched and sent over ClickHouse's HTTP interface on a one second
tick, with one request in flight at a time, since ClickHouse writes a part per
insert. A full request's worth of backlog goes out without waiting for the next
tick. A failed request is retried on a later tick, with the backlog capped so an
unreachable ClickHouse costs bounded memory (the oldest rows are dropped first).
A batch ClickHouse rejects as malformed (HTTP 400) is dropped instead, since
retrying it would block every later row.

Delivery is at least once: a request that times out after ClickHouse committed
it is sent again, so a query should take `min`/`any` per block, stage and client
rather than count rows. Rows still pending when the node exits are lost.
`lean_telemetry_rows_total` and `lean_telemetry_insert_failures_total` say what
happened to the rows. The table is created on first use; that statement is best
effort, so a user that may insert but not create still works against an existing
table.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--telemetry.clickhouse-url` (or `ETHLAMBDA_TELEMETRY_CLICKHOUSE_URL`) | off | ClickHouse HTTP endpoint, e.g. `http://127.0.0.1:8123`. `user:pass@` in the URL is sent as basic auth; `?database=` passes through. Pass a URL with a password through the environment variable: a command line is readable by any local user |
| `--telemetry.client-name` | `--node-id` (`node`), `ethlambda@<hostname>` (`beacon`) | `meta_client_name` on every row; requires the URL |

`meta_network_name` is the network's `CONFIG_NAME` on `beacon` (`unknown` when a
loaded network directory has none) and `lean` on `node`.

In a container, set `--telemetry.client-name` (or the container's hostname):
Docker's default hostname is the container ID, so the `beacon` default would
change on every recreate and split one node's rows across names. Only
`http`/`https` URLs are accepted; ClickHouse's native port (9000) is not this
interface. A rejected URL is never echoed back, since it may hold a password.

## Columns

| Column | Content |
|---|---|
| `event_date_time` | Wall clock of the event, nanoseconds |
| `stage` | Which point in the block's life (below) |
| `slot`, `slot_start_date_time` | The block's slot and when it started |
| `time_into_slot_ms` | Offset from the slot start; NULL outside the two slots after it (catch-up, backfill) |
| `block_root` | `0x`-prefixed |
| `source` | Blocks: `gossip`, `sync`, `replay`. Columns: `gossip`, `by_root`, `by_range`, `local`, `recheck` |
| `verdict` | `el_verdict` rows only: `Valid`, `Optimistic`, `Invalid` |
| `column_index` | `column_*` rows only |

## Stages

Block rows are written once a block's import finishes (imported by its own
state transition, or failed); a block that never leaves a hold has no rows, and
a re-delivery of a block already stored writes none. Silver's names are used
where the meaning matches; every other section of the
[import timing](./metrics.md#block-import-timing) is written as
`<section>_start` and `<section>_end`. A block that arrived by a path the import
timing does not measure (one this node built, or one re-delivered after its slot
had not started) writes no rows.

| Stage | Meaning |
|---|---|
| `received` | The block came off the wire (gossip) or was handed to the chain actor (req/resp) |
| `da_available` | The data-availability check passed for a block that needed columns. A block with nothing to wait for (no blobs, or gloas, whose data gates the envelope instead) writes `da_check_end` instead |
| `el_sent`, `el_verdict` | `engine_newPayload` sent and answered; only when an execution client answered |
| `stf_done` | The state transition finished |
| `attestable` | The new head including the block is computed, as in Silver. Beacon recomputes the head once per arriving block, after the whole import cascade, so every block that cascade imported gets the same time; lean updates its head per block |
| `failed` | The import failed; `stf_done` and lean's `attestable` are then written as `stf_end` and `fc_head_end` |
| `column_recv`, `column_validated` | A data column arrived, and passed validation. Written only for a column that passed (or, for `column_recv`, was judged to wait for its block), as Silver does, so rejected columns and re-delivered stored ones write nothing. At least once per block, column and stage: a column delivered again while it waits, or two copies passing at once, write again, so take the earliest. A column that waited writes `column_validated` with source `recheck`, so join the two on block root and column index, not on source. By-root and by-range answers stamp every column with the moment the whole answer reached the handler. A gossip-accepted column's `column_validated` comes after the verdict's trip back through the p2p actor; a checked one's when its check finished |
| `cascade_*`, `prune_*`, `get_head_*`, `fcu_*` | Once per arrival, filed under the arriving block, when that block was imported in that cascade |

ethlambda waits for the execution client before the state transition, so
`el_sent` to `stf_done` covers both; `stf_start` separates them.

`source` and `verdict` are ethlambda's own values on every row, not Silver's
(`Gossip`, `Rpc`, `Syncing`, ...); a query shared with Silver's rows must
match both.

## Known gaps

- A held block keeps its arrival marks (`received`, `decode_end`,
  `queue_end`, `defer_*`, `admit_*`, the starts of its waits) across the
  hold, but the sections after them (`guards_*`, `da_check_*`, the import
  itself) are the final pass's: an earlier pass's failed check is not
  written.
- A block re-delivered while held reports the last delivery as `received`,
  not the first (the import timing histogram does the same).
- Some blocks released from a hold carry no timings and write no rows, e.g.
  one held again by the execution client after its columns arrived. A block
  the execution client could not judge, or that is not an optimistic
  candidate, writes no rows either.
- An ancestor read back from storage (mainly after a restart) reports that
  read as its `received`.
- On gloas the payload goes to the execution client with its envelope, not
  the block, so gloas blocks have no `el_*` rows; a gloas block held for its
  parent's payload has no wait section of its own.
- Lean's `attestable` is the end of its head update plus the bookkeeping an
  import ends with (events, eviction, table sizes), sub-millisecond in
  practice.

## A query to start from

Per-block arrival to attestable, in milliseconds:

```sql
SELECT block_root, any(slot) AS slot,
       (toUnixTimestamp64Nano(minIf(event_date_time, stage = 'attestable'))
      - toUnixTimestamp64Nano(minIf(event_date_time, stage = 'received'))) / 1e6 AS total_ms
FROM block_events
WHERE meta_client_name = 'ethlambda@<host>' AND event_date_time > now() - INTERVAL 1 HOUR
GROUP BY block_root
HAVING countIf(stage = 'attestable') > 0
ORDER BY slot DESC
LIMIT 50
```

## Retention

The table has no TTL. Set one as an operator, e.g.
`ALTER TABLE block_events MODIFY TTL toDateTime(event_date_time) + INTERVAL 14 DAY`.
