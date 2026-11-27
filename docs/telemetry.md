# Block telemetry (ClickHouse)

With `--telemetry.clickhouse-url`, a node writes one row for each start and
end of a section in each block's life, and per data column arrival, to a
ClickHouse table named `block_events`. The table layout is
[Silver](https://github.com/gattaca-com/silver)'s, so both clients' rows can
share one table; the stage names are ethlambda's own (see [Stages](#stages)).

Rows are batched and sent over ClickHouse's HTTP interface on a one second
tick, with one request in flight at a time, since ClickHouse writes a part per
insert. A full request's worth of backlog goes out without waiting for the next
tick. A failed request is retried on a later tick, with the backlog capped so an
unreachable ClickHouse costs bounded memory (the oldest rows are dropped first).
A batch ClickHouse rejects as malformed (HTTP 400) is dropped instead, since
retrying it would block every later row. Refusals are logged at `warn` on the
first and then at most once a minute, with the batches and rows dropped since
the last report, so a table whose schema the rows do not fit stays visible. A
row field the table lacks is ignored rather than refusing the batch
(`input_format_skip_unknown_fields`), so a table created by an older layout
still takes the columns it has.

On a graceful shutdown the writer sends what is still pending before the node
exits, waiting at most 12 seconds; rows it cannot deliver are counted as
dropped.

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
loaded network directory has none) and `lean-<genesis time>` on `node` (the
genesis Unix time in seconds), so lean devnets sharing one table, or one devnet
reset with a new genesis, stay apart.

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
| `source` | Blocks: `gossip`, `sync` (`replay` comes only from the offline benchmark and replay commands, which never install telemetry). Columns: `gossip`, `by_root`, `by_range`, `local`, `recheck` |
| `verdict` | `el_end` rows: `Valid`, `Optimistic`, `Invalid`. `import_end` rows: `Imported`, `Failed`. NULL on every other row |
| `column_index` | `column_*` rows only |

## Stages

Block rows are written once a block's import finishes (imported by its own
state transition, or failed); a block that never leaves a hold has no rows, and
a re-delivery of a block already stored writes none. Every row starts or ends a
section, `x_start` and `x_end`, and the time it took is the one minus the
other. Most sections are the [import timing](./metrics.md#block-import-timing)'s
own, under the same name (`cl`, `store`, `stf`, `writer_wait`, ...); the
others map onto it as follows. `import` is its `total`. Its `store` row
excludes `writer_wait`. Beacon's per-block `fc_head` is the arrival's
`get_head`. `el` is the request itself, whose `el_wait` row reports only the
wait the transition did not hide. The only block that writes no rows is lean's locally built one, which
crossed no wire and carries no source. A block re-delivered after waiting for
its slot reports under its original source and adds `defer_start` and
`defer_end`. On `beacon`, a proposal handed over by a validator client enters
as `gossip`, starting at the hand-off, with no `decode_*` rows.

| Stage | Meaning |
|---|---|
| `import_start`, `import_end` | The whole import, the log line's end to end: from the block coming off the wire (gossip) or reaching the chain actor (req/resp) to the last section written. `import_end` carries the outcome in `verdict`: `Imported` or `Failed` |
| `decode_*`, `queue_*` | Decompressing and decoding the block, gossip only; then the chain actor's mailbox, for every source. `decode_end` and `queue_start` are one instant, and so are `import_start` and the first of `decode_start` and `queue_start` |
| `da_check_start`, `da_check_end` | The data-availability check. Ending it is no claim that the block needed data: one with no blobs, or a gloas block (whose data gates the envelope instead), is checked too. A block that needed columns has `column_*` rows |
| `el_start`, `el_end` | Beacon, the execution client's half: `engine_newPayload` sent and answered; only when an execution client answered. `el_end` carries the verdict in `verdict` |
| `cl_start`, `cl_end` | Beacon, the consensus half: the block's state transition, computed ahead of `fork_choice::on_block` (below) |
| `store_start`, `store_end` | Beacon: `fork_choice::on_block` after the verdict, given that transition: the store writes and fork-choice bookkeeping (below) |
| `stf_start`, `stf_end` | Lean: the state transition |
| `fc_head_start`, `fc_head_end` | The head computation that made the block attestable. Lean updates its head per block, so every imported block writes its own. Beacon recomputes the head once per arriving block, after the whole import cascade, and writes that computation under every block the cascade imported and the new head includes, so they share its instants. A block imported onto a losing branch never became attestable and writes none, nor does any block when the head computation failed (it moved nothing) |
| `column_start`, `column_end` | A data column arrived, and passed validation. Written only for a column that passed (or, for `column_start`, was judged to wait for its block), so rejected columns and re-delivered stored ones write nothing. At least once per block, column and stage: a column delivered again while it waits, or two copies passing at once in separate deliveries, write again, so take the earliest. A copy repeated within one delivery (one peer's answer, say) is dropped unchecked and writes nothing. A column that waited writes `column_end` with source `recheck`, so join the two on block root and column index, not on source. By-root and by-range answers stamp every column with the moment the whole answer reached the handler. A gossip-accepted column's `column_end` comes after the verdict's trip back through the p2p actor; a checked one's when its check finished, which is when the KZG sub-batch it was verified in (at most 16 of its block's columns) finished, not when its block's last one did |
| `cascade_*`, `prune_*`, `get_head_*`, `fcu_*` | Once per arrival, filed under the arriving block, when that block was imported in that cascade. `get_head_*` is written whether or not the head computation succeeded |
| everything else | The [import timing](./metrics.md#block-import-timing) section of the same name |

A beacon block's state transition is computed ahead of `on_block`, for every
block. With an execution client, ethlambda sends `engine_newPayload` first and
computes the transition while the request is in flight: `el_start`..`el_end`
is the request, `cl_start`..`cl_end` the transition, and the two start a moment
apart. The import continues once both are done, so whichever ends later is what
it waited for. A block nobody asks about (no execution client, or no payload to
ask about: pre-merge or gloas) writes `cl_*` rows with no `el_*` rows beside
them. Only a block `speculate_transition` declined writes no `cl_*` rows; it is
one `on_block` refuses before any transition.

`store_start`..`store_end` is `on_block` given that transition: the store
writes and the fork-choice bookkeeping that must not happen before the verdict
(the block, its post-state and its fork-choice node; timeliness and the
proposer boost, which can walk the head; gloas's payload attestations; the
checkpoints and the unrealized justification), plus the `writer_wait` nested
inside it. At an epoch's first block the transition also makes two passes over
the registry that `on_block` used to make after it: the balances of the new
checkpoint, and the unslashed target balances its unrealized justification is
weighed with. The block's state-transition time is the two spans added together
(less `writer_wait`), the import's log line's `cl` and `store` rows. The
transition is kept
only for a verdict that agrees with it: after an `Invalid` verdict
`store_start`..`store_end` runs it again, and both spans are transitions the
import paid for.

The table layout is Silver's, but the stage names are ethlambda's own, so a
query over both clients' rows has to map between them. Silver's `received`,
`da_available`, `el_sent`, `el_verdict`, `stf_done` and `attestable` are
roughly `import_start`, `da_check_end`, `el_start`, `el_end`, `store_end` (or
lean's `stf_end`) and `fc_head_end` here. `source` and `verdict` hold
ethlambda's own values too, not Silver's (`Gossip`, `Rpc`, `Syncing`, ...).
The table's DDL is still Silver's verbatim, so the `verdict` column's own
comment names `el_verdict` alone.

The Grafana dashboards that read these rows are generated by the scripts in
`tooling/grafana-beacon`, which make every stage predicate match the old name
and the new one, so they read rows of either naming.

Rows written before this naming carry the earlier one: Silver's names above,
`stf_start` with `stf_done` or `stf_end` for beacon's `on_block`,
`stf_spec_start` and `stf_spec_end` (some nightly builds) for `cl_*`,
`failed` for a failed import, `column_recv` and `column_validated` for
`column_*`, and no `decode_start`, `queue_start` or `import_end`. A query
spanning them must match both.

## Every stage written

| Group | Stages |
|---|---|
| Per block, in order | `import_start`, `decode_start`, `decode_end`, `queue_start`, `queue_end`, `defer_start`, `defer_end`, `admit_start`, `admit_end`, `guards_start`, `guards_end`, `preamble_start`, `preamble_end`, `parent_wait_start`, `parent_wait_end`, `cascade_wait_start`, `cascade_wait_end`, `da_check_start`, `da_check_end`, `columns_wait_start`, `columns_wait_end`, `verify_struct_start`, `verify_struct_end`, `verify_crypto_start`, `verify_crypto_end`, `cl_start`, `cl_end`, `stf_start`, `stf_end`, `store_start`, `store_end`, `writer_wait_start`, `writer_wait_end`, `db_write_start`, `db_write_end`, `fc_head_start` and `fc_head_end` (lean), `block_atts_start`, `block_atts_end`, `import_end` |
| Per block, with an execution client | `el_start`, `el_end`, which run alongside `cl_start`..`cl_end` |
| Per block on the new head (beacon) | `fc_head_start`, `fc_head_end` |
| Per arrival | `cascade_start`, `cascade_end`, `prune_start`, `prune_end`, `get_head_start`, `get_head_end`, `fcu_start`, `fcu_end` |
| Per column | `column_start`, `column_end` |

Only the stages a block actually crossed are written. `admit_*` is the chain
actor's admission section; it is written here and listed in no other doc.

## Known gaps

- On a node with a validator client, its own beacon proposals appear under
  `source = 'gossip'` with near-zero arrival latency. Filter them out by their
  missing `decode_*` rows when comparing with another client.

- A held block keeps its arrival marks (`import_start`, `decode_*`,
  `queue_*`, `defer_*`, `admit_*`, the starts of its waits) across the
  hold, but the sections after them (`guards_*`, `da_check_*`, the import
  itself) are the final pass's: an earlier pass's failed check is not
  written.
- A block re-delivered while held reports the last delivery as its
  `import_start`, not the first (the import timing histogram does the same).
- Some blocks released from a hold carry no timings and write no rows, e.g.
  one held again by the execution client after its columns arrived. A block
  the execution client could not judge, or that is not an optimistic
  candidate, writes no rows either.
- An ancestor read back from storage (mainly after a restart) reports that
  read as its `import_start`.
- On gloas the payload goes to the execution client with its envelope, not
  the block, so gloas blocks have no `el_*` rows; a gloas block held for its
  parent's payload has no wait section of its own.
- Lean's `fc_head_end` is the end of its head update plus the bookkeeping an
  import ends with (events, eviction, table sizes), sub-millisecond in
  practice; beacon's `block_atts_end` takes the same bookkeeping.

## A query to start from

Per-block arrival to attestable, in milliseconds:

```sql
SELECT block_root, any(slot) AS slot,
       (toUnixTimestamp64Nano(minIf(event_date_time, stage = 'fc_head_end'))
      - toUnixTimestamp64Nano(minIf(event_date_time, stage = 'import_start'))) / 1e6 AS total_ms
FROM block_events
WHERE meta_client_name = 'ethlambda@<host>' AND event_date_time > now() - INTERVAL 1 HOUR
GROUP BY block_root
HAVING countIf(stage = 'fc_head_end') > 0
ORDER BY slot DESC
LIMIT 50
```

## Retention

The table has no TTL. Set one as an operator, e.g.
`ALTER TABLE block_events MODIFY TTL toDateTime(event_date_time) + INTERVAL 14 DAY`.
