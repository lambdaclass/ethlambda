#!/usr/bin/env python3
"""Generate the "Beacon client comparison" dashboard (uid client-compare): ethlambda vs Lighthouse
vs Silver on mainnet, block by block, from eth-4's ClickHouse (datasource ethlambda-ch).

  ethlambda  eth-4, default.block_events (meta_client_name $eth_client)
  Lighthouse eth-2, OTLP spans in default.otel_traces, reshaped by the parameterized view
             default.lighthouse_block_events(from_ms, to_ms)
  Silver     eth-5, default.silver_block_events: a remote() table reading eth-5's
             silver-clickhouse block_events live (meta_client_name $silver_client, the hostname)

Every ClickHouse panel builds on one CTE, so all three clients are compared in SQL: `blocks` holds
one row per (client, block) with the client's delta, and `compared` one row per block that every
selected client has, with the winner (lowest delta). Layout follows ethrex's L1 client comparison.

Usage: gen-compare-dashboard.py <out.json>
"""
import json
import sys

import stage_names

CH = {"type": "grafana-clickhouse-datasource", "uid": "ethlambda-ch"}
PROM = {"type": "prometheus", "uid": "lean64-prom"}

# Display name, Prometheus node label (None: no process metrics), colour.
CLIENTS = [
    ("ethlambda", "beacon-eth4", "#16a34a"),
    ("Lighthouse", "beacon-eth2", "#3b82f6"),
    ("Silver", None, "#a855f7"),
]
NAMES = [c[0] for c in CLIENTS]

# Silver's version is not readable live: its Beacon API answers a placeholder ("silver/v0.0.1"),
# it exports no metrics, and its ClickHouse rows carry none. This is `silver --version` on eth-5
# (~/silver-mainnet/bin/silver); update it when Silver is upgraded.
SILVER_VERSION = "v0.1.0-alpha.6 (c95e752)"
# (client, PromQL giving the running version in label `v`, legend). Instant queries, so each shows the
# version running at the end of the time range.
VERSIONS = [
    ("ethlambda", 'label_replace(lean_node_info{node="beacon-eth4"}, "v", "$1", "version", "ethlambda/([^/]+)/.*")',
     "ethlambda {{v}}"),
    ("Lighthouse", 'label_replace(lighthouse_info{node="beacon-eth2"}, "v", "$1", "version", "Lighthouse/(.*)")',
     "Lighthouse {{v}}"),
    ("Silver", "vector(1)", f"Silver {SILVER_VERSION}"),
]

GENESIS = 1606824023  # mainnet; every source here is a mainnet node
WINDOW_FILTER = "event_date_time BETWEEN $__fromTime - INTERVAL 1 MINUTE AND $__toTime + INTERVAL 1 MINUTE"
SOURCES = [
    ("ethlambda", "block_events", f"{WINDOW_FILTER} AND meta_client_name = '${{eth_client}}'"),
    ("Lighthouse", "lighthouse_block_events(from_ms = ${__from}, to_ms = ${__to})", "1"),
    ("Silver", "silver_block_events", f"{WINDOW_FILTER} AND meta_client_name = '${{silver_client}}'"),
]


def ms_between(a, b):
    return (f"(toUnixTimestamp64Nano(minIfOrNull(event_date_time, stage = '{b}'))"
            f" - toUnixTimestamp64Nano(minIfOrNull(event_date_time, stage = '{a}'))) / 1e6")


def ns(stage, agg="min"):
    """The stage's time in ns since the epoch (earliest by default)."""
    return f"toUnixTimestamp64Nano({agg}IfOrNull(event_date_time, stage = '{stage}'))"


# Silver's two waits for data, ms. Held before its checks until the columns arrived (RPC blocks):
SILVER_HOLD = (f"coalesce(greatest(0, if({ns('da_available', 'max')} < {ns('el_sent')}, "
               f"({ns('da_available', 'max')} - {ns('received')}) / 1e6, 0)), 0)")
# Held after the STF until the columns arrived. A block that did not wait announces its post-state and
# its import in one message, so its stf_done IS its attestable; one that waited announces the post-state
# (stf_done) and later the import (attestable), with one da_available between them, the release.
SILVER_HELD = (f"coalesce(greatest(0, (least({ns('attestable')}, {ns('da_available', 'max')})"
               f" - {ns('stf_done')}) / 1e6), 0)")

# Time each client's import sat waiting for the block's blobs/columns, in its own terms:
#   ethlambda   its columns_wait section (written only when it waited; before the STF)
#   Lighthouse  da_check -> da_wait_end, only when the import was deferred until the data arrived
#               (it fetches blobs from the EL while executing, so this is usually 0)
#   Silver      held before its checks until the data arrived, plus the post-state parked after
#               the STF until the columns arrived (Silver's own dashboard ends that second wait at
#               attestable, which adds its import and head recompute, ~0.3 ms)
BLOB_WAIT = {
    "ethlambda": f"coalesce({ms_between('columns_wait_start', 'columns_wait_end')}, 0)",
    "Lighthouse": f"coalesce({ms_between('da_check', 'da_wait_end')}, 0)",
    "Silver": f"{SILVER_HOLD}\n      + {SILVER_HELD}",
}


NULL_MS = "CAST(NULL, 'Nullable(Float64)')"
# The steps from received to attestable, in ms, defined so that each means the same in both clients
# (checked against both codebases, 2026-11-03). pre + blob wait + proc + el_wait = received -> attestable.
#   pre_ms      received -> engine_newPayload sent, minus the wait for blobs before it: decode, gossip
#               checks with the proposer signature, the hop to the import, the DA check
#   proc_ms     the request -> attestable, minus the waits for blobs and for the EL: state transition
#               (state root included), fork-choice import with the block's votes, head recompute.
#               ethlambda also writes the post-state to disk here; Silver persists off the critical path
#   stf_ms      of which the state transition: ethlambda's runs alongside the EL call (stf_spec_*);
#               Silver stamps it only for blocks held for columns (el_sent -> stf_done)
#   import_ms   of which the import and head: ethlambda from the later of the verdict and its
#               transition; Silver from the release by the columns, again only for held blocks
#   el_wait_ms  waiting for the EL verdict once the transition was done; Silver never waits for it
STEP_COLS = ["pre_ms", "proc_ms", "stf_ms", "import_ms", "el_wait_ms"]
STEPS = {
    "ethlambda": {
        "pre_ms": f"({ns('el_sent')} - {ns('received')}) / 1e6 - {BLOB_WAIT['ethlambda']}",
        "proc_ms": "coalesce(stf_ms, 0) + import_ms",
        "stf_ms": f"({ns('stf_spec_end')} - {ns('stf_spec_start')}) / 1e6",
        # greatest/least skip NULLs here (ClickHouse 25.8): no speculation counts from the verdict.
        "import_ms": f"({ns('attestable')} - greatest({ns('el_verdict')}, {ns('stf_spec_end')})) / 1e6",
        "el_wait_ms": f"greatest(0, ({ns('el_verdict')} - coalesce({ns('stf_spec_end')}, {ns('el_sent')})) / 1e6)",
    },
    "Silver": {
        "pre_ms": f"({ns('el_sent')} - {ns('received')}) / 1e6 - {SILVER_HOLD}",
        "proc_ms": f"({ns('attestable')} - {ns('el_sent')}) / 1e6 - {SILVER_HELD}",
        "stf_ms": f"if({ns('stf_done')} < {ns('attestable')}, ({ns('stf_done')} - {ns('el_sent')}) / 1e6, NULL)",
        "import_ms": (f"if({ns('stf_done')} < {ns('attestable')}, ({ns('attestable')} - greatest({ns('stf_done')}, "
                      f"least({ns('attestable')}, {ns('da_available', 'max')}))) / 1e6, NULL)"),
        "el_wait_ms": "toFloat64(0)",
    },
    "Lighthouse": {c: NULL_MS for c in STEP_COLS},
}


def first(stage):
    return f"minIfOrNull(event_date_time, stage = '{stage}')"


# Every client's `attestable` is the end of the head recompute that includes the block (checked against
# each codebase, 2026-11-04), and it is where every delta on the dashboard ends:
#   ethlambda   the end of the head recompute after the import cascade (its get_head_end, written as
#               `attestable` for every block the cascade imported). Since nightly 0b62d9a (2026-11-05)
#               a block is imported before the EL answers and is optimistic at that recompute, so its
#               `attestable` is written when the VALID answer is applied instead, always the later of
#               the two (nightly 4117c5a; the rows from 21:15 to 21:55 UTC that day lack the EL)
#   Lighthouse  the end of the get_head inside import_block, where the block goes into the early
#               attester cache. import_block goes on to write block, columns and state to its DB
#               (persist_blocks_and_blobs, p99 ~635 ms), which no other client has on this path, so
#               the end of import_block is not used
#   Silver      its `Applied` (in fork choice, new head published), before the EL verdict comes back
#
# When the state transition (state root included) was done, in each client's terms:
#   ethlambda   stf_spec_end where present: the transition it ran alongside a waited-for EL call. Its
#               `stf_done` there is the end of on_block_speculative, after the EL verdict. Since nightly
#               0b62d9a (2026-11-05) the live node no longer waits for the EL, writes no stf_spec_*,
#               and its `stf_done` is the transition alone
#   Lighthouse  stf_done: end of update_tree_hash_cache (state root), alongside the EL call
#   Silver      stf_done, only for blocks held for columns: an unheld block announces its post-state
#               and its import in one message, so its stf_done IS its attestable
STF_DONE_AT = {
    "ethlambda": f"coalesce({first('stf_spec_end')}, {first('stf_done')})",
    "Lighthouse": first("stf_done"),
    "Silver": f"if({first('stf_done')} < {first('attestable')}, {first('stf_done')}, NULL)",
}
# The "STF only" comparison's end point: STF_DONE_AT, except that Silver counts on every block. For an
# unheld block its stf_done is the same instant as its attestable, so there it also covers its import
# (in fork choice, head published), which is the only finer stamp Silver has.
STF_ONLY_AT = {**STF_DONE_AT, "Silver": first("stf_done")}


def steps_sql(steps):
    return ",\n      ".join(f"toNullable(toFloat64({steps[c]})) AS {c}" for c in STEP_COLS)


def per_block(src, where, blob_wait, stf_done_at, stf_only_at, steps):
    return f"""SELECT
      block_root,
      maxOrNull(slot) AS slot,
      anyIf(source, stage = 'received') AS source,
      minIfOrNull(event_date_time, stage = 'received') AS received,
      minIfOrNull(time_into_slot_ms, stage = 'received') AS arrival_ms,
      minIfOrNull(time_into_slot_ms, stage = 'attestable') AS attestable_ms,
      {ms_between('received', 'attestable')} AS recv_attestable_ms,
      {ms_between('el_sent', 'el_verdict')} AS el_ms,
      {ms_between('received', 'el_verdict')} AS el_verdict_ms,
      (toUnixTimestamp64Nano({stf_done_at}) - toUnixTimestamp64Nano({first('received')})) / 1e6 AS stf_done_ms,
      (toUnixTimestamp64Nano({stf_only_at}) - toUnixTimestamp64Nano({first('received')})) / 1e6 AS stf_only_ms,
      {blob_wait} AS blob_wait_ms,
      {steps_sql(steps)}
    FROM {src}
    WHERE {where}
    GROUP BY block_root"""


_union = "\n    UNION ALL\n".join(
    f"    SELECT '{name}' AS client, * FROM (\n"
    f"    {per_block(src, where, BLOB_WAIT[name], STF_DONE_AT[name], STF_ONLY_AT[name], STEPS[name])}\n    )"
    for name, src, where in SOURCES)

# `delta_ms` is what "delta" means everywhere on the dashboard: received -> attestable, the same
# point in every client (see STF_DONE_AT above).
# `att_ms` is received -> attestable, but not before the EL verdict: Silver marks a block attestable
# before the verdict comes back; ethlambda and Lighthouse wait for it, so for them it equals delta_ms.
# It is the dashboard's first comparison. The second is `stf_only_ms` (STF_ONLY_AT above).
def cte_for(col):
    """The CTE with `compared` (one row per block every selected client has `col` for, with the winner:
    lowest `col`) built on `col`. Every panel but the per-comparison win rates uses delta_ms."""
    # Every client of a block in `blocks` has a delta; another column can still be missing for one.
    only_with = "" if col == "delta_ms" else f"    WHERE {col} IS NOT NULL\n"
    return f"""WITH
  per_client AS (
{_union}
  ),
  blocks AS (
    SELECT *,
      toDateTime({GENESIS} + 12 * slot) AS slot_start,
      recv_attestable_ms AS delta_ms,
      greatest(recv_attestable_ms, coalesce(el_verdict_ms, recv_attestable_ms)) AS att_ms
    FROM per_client
    WHERE client IN (${{clients:singlequote}})
      AND received BETWEEN $__fromTime AND $__toTime
      AND ('${{gossip_only}}' = 'false' OR lower(source) = 'gossip')
      AND delta_ms IS NOT NULL
  ),
  compared AS (
    SELECT block_root, any(slot) AS slot, any(slot_start) AS slot_start,
      argMin(client, {col}) AS winner,
      min({col}) AS best_ms,
      max({col}) AS worst_ms,
      arrayElement(arraySort(groupArray({col})), 2) - min({col}) AS lead_ms
    FROM blocks
{only_with}    GROUP BY block_root
    HAVING count() = length([${{clients:singlequote}}])
  )
"""


CTE = cte_for("delta_ms")


# Per data column, for the step comparison: each client's custody columns (not the same indices: each
# node custodies its own), arrival -> validated, and when the block's last one arrived.
COLS_CTE = f""",
  cols AS (
    SELECT client, block_root, column_index,
      minIfOrNull(event_date_time, stage = 'column_recv') AS recv,
      minIfOrNull(event_date_time, stage = 'column_validated') AS validated
    FROM (
      SELECT 'ethlambda' AS client, block_root, column_index, stage, event_date_time FROM block_events
      WHERE {WINDOW_FILTER} AND meta_client_name = '${{eth_client}}' AND stage IN ('column_recv', 'column_validated')
      UNION ALL
      SELECT 'Silver' AS client, block_root, column_index, stage, event_date_time FROM silver_block_events
      WHERE {WINDOW_FILTER} AND meta_client_name = '${{silver_client}}' AND stage IN ('column_recv', 'column_validated'))
    GROUP BY client, block_root, column_index
  ),
  col_blocks AS (
    SELECT c.client AS client, c.block_root AS block_root, any(b.slot_start) AS slot_start,
      quantile(0.5)((toUnixTimestamp64Nano(c.validated) - toUnixTimestamp64Nano(c.recv)) / 1e6) AS col_validate_ms,
      (toUnixTimestamp64Nano(max(c.recv)) - toUnixTimestamp64Nano(any(b.received))) / 1e6 AS last_col_ms
    FROM cols AS c INNER JOIN blocks AS b ON b.client = c.client AND b.block_root = c.block_root
    GROUP BY c.client, c.block_root
  )
"""
PAIR = ["ethlambda", "Silver"]
PAIR_SQL = "('ethlambda', 'Silver')"

# The step table's rows: (name, how both clients measure it, per-block value). Rows 2, 4, 7 and 8 add up
# to row 9 for every block.
STEP_ROWS = [
    ("Arrival, ms into the slot", "received. ethlambda: libp2p hands the gossip message over; Silver: "
     "its network tile takes it in. Different hosts and peers, so mostly network", "arrival_ms"),
    ("Checks before the EL request", "received to engine_newPayload sent, minus waiting for blobs: decode, "
     "gossip checks with the proposer signature, DA check", "pre_ms"),
    ("EL newPayload round trip", "engine_newPayload sent to answered", "el_ms"),
    ("State transition + import + head", "EL request to attestable, minus the waits for blobs and the EL. "
     "ethlambda also writes the post-state to disk here, Silver persists later", "proc_ms"),
    ("↳ of which: state transition", "with the state root check. ethlambda: run alongside the EL call; "
     "Silver: only blocks held for columns (the only ones it stamps)", "stf_ms"),
    ("↳ of which: import + head", "fork-choice import, block votes, head recompute. Silver: only blocks "
     "held for columns", "import_ms"),
    ("Waiting for the EL verdict", "after the state transition was done. Silver never waits: it is "
     "attestable before the verdict", "el_wait_ms"),
    ("Waiting for blobs", "ethlambda: columns_wait, before the transition. Silver: held before its checks "
     "+ held after the transition until the columns arrived", "blob_wait_ms"),
    ("Total: received to attestable", "head recomputed with the block; rows 2 + 4 + 7 + 8, block by block",
     "recv_attestable_ms"),
]
COL_ROWS = [
    ("Data column: arrival to validated", "median over the custody columns of each block (each node "
     "custodies its own columns)", "col_validate_ms"),
    ("Last custody column vs the block", "ms after the block arrived; negative: every column came first",
     "last_col_ms"),
]


def step_rows_sql(rows, start):
    def lit(t):
        return "'" + t.replace("'", "") + "'"
    tuples = ",\n    ".join(f"({start + i}, {lit(n)}, {lit(m)}, toNullable(toFloat64({v})))"
                            for i, (n, m, v) in enumerate(rows))
    return f"[\n    {tuples}]"


def step_table_select(src, rows, start):
    return f"""SELECT s.1 AS ord, s.2 AS step,
  quantileIfOrNull(0.5)(s.4, client = 'ethlambda') AS `ethlambda p50`,
  quantileIfOrNull(0.5)(s.4, client = 'Silver') AS `Silver p50`,
  `ethlambda p50` - `Silver p50` AS `ethlambda − Silver`,
  quantileIfOrNull(0.9)(s.4, client = 'ethlambda') AS `ethlambda p90`,
  quantileIfOrNull(0.9)(s.4, client = 'Silver') AS `Silver p90`,
  countIf(client = 'ethlambda' AND s.4 IS NOT NULL) AS `ethlambda n`,
  countIf(client = 'Silver' AND s.4 IS NOT NULL) AS `Silver n`,
  s.3 AS `measured as`
FROM {src} ARRAY JOIN {step_rows_sql(rows, start)} AS s
WHERE client IN {PAIR_SQL}
GROUP BY s.1, s.2, s.3"""


def per_client_cols(expr):
    """One column per client: expr.format(c=<that client's condition>)."""
    return ",\n  ".join(f"{expr.format(c=f'client = {chr(39)}{n}{chr(39)}')} AS `{n}`" for n in NAMES)


def win_cols(scale=""):
    return ",\n  ".join(f"{scale}countIf(winner = '{n}'){'/ count()' if scale else ''} AS `{n}`" for n in NAMES)


def target(ref, sql, fmt=1):
    return {"refId": ref, "datasource": CH, "editorType": "sql",
            "queryType": "table" if fmt == 1 else "timeseries", "format": fmt, "rawSql": sql}


def prom(ref, expr, legend):
    return {"refId": ref, "datasource": PROM, "expr": expr, "legendFormat": legend, "range": True}


def color_overrides():
    return [{"matcher": {"id": "byName", "options": n},
             "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": col}}]}
            for n, _, col in CLIENTS]


_next = [0]


def pid():
    _next[0] += 1
    return _next[0]


def row(title, y, collapsed=False, panels=None):
    return {"type": "row", "id": pid(), "title": title, "collapsed": collapsed,
            "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}, "panels": panels or []}


def ts_panel(title, desc, sql, gp, unit="ms", stack=False, log=False, points=False, ds=CH, targets=None,
             sort_by=None, sort_desc=False):
    """`sort_by` names a legend calc ("Median", "Mean") to rank the legend by, best client first."""
    custom = {"drawStyle": "points" if points else "line", "lineWidth": 1 if points else 2,
              "pointSize": 5, "showPoints": "always" if points else "never",
              "fillOpacity": 60 if stack else 5, "spanNulls": not points}
    if stack:
        custom["stacking"] = {"mode": "normal", "group": "A"}
    if log:
        custom["scaleDistribution"] = {"type": "log", "log": 10}
    # displayName: the ClickHouse plugin names each frame after its refId, which Grafana would
    # otherwise prepend to the series name ("A ethlambda").
    defaults = {"unit": unit, "decimals": 1, "custom": custom}
    if ds is CH:
        defaults["displayName"] = "${__field.name}"
    if stack:
        defaults.update({"min": 0, "max": 100})
    return {"type": "timeseries", "id": pid(), "title": title, "description": desc,
            "datasource": ds, "gridPos": gp,
            "fieldConfig": {"defaults": defaults, "overrides": color_overrides()},
            "options": {"legend": dict({"displayMode": "table", "placement": "bottom",
                                        "calcs": ["mean"] if stack else ["median", "p90", "max"]},
                                       **({"sortBy": sort_by, "sortDesc": sort_desc} if sort_by else {})),
                        "tooltip": {"mode": "multi", "sort": "desc"}},
            "targets": targets or [target("A", sql, fmt=0)]}


# The X field of a per-block panel. Field defaults reach the X field too, so it takes back a plain integer,
# a linear scale (a log Y must not bend the slot axis) and no `min` (one of 0 would stretch the axis from
# slot 0 and pile every block onto one spot).
SLOT_AXIS = {"matcher": {"id": "byName", "options": "slot"},
             "properties": [{"id": "unit", "value": "none"}, {"id": "decimals", "value": 0},
                            {"id": "custom.scaleDistribution", "value": {"type": "linear"}},
                            {"id": "custom.axisLabel", "value": "Block (slot)"}]}


def per_block_sql(cols):
    """One row per block, by slot: the slot, then `cols` (one column per client)."""
    return CTE + "SELECT any(slot) AS slot,\n  " + cols + "\nFROM blocks GROUP BY block_root ORDER BY slot"


def block_trend(title, desc, sql, gp, y_label, unit="ms", log=False):
    """A trend panel drawn like ethrex's "Block Time": the block's slot on the X axis, each client's
    points joined by a line, and the legend's mean, max, p95 and p99 over the blocks shown (best mean
    first). `sql` returns (slot, one column per client) ordered by slot."""
    custom = {"drawStyle": "line", "lineInterpolation": "linear", "lineWidth": 2, "pointSize": 7,
              "showPoints": "always", "fillOpacity": 0, "axisPlacement": "left", "axisLabel": y_label,
              # A block a client has no value for breaks its line rather than being bridged: in the sparse
              # series (blob waits, Silver's STF done) a bridge would join blocks that are not adjacent. A
              # slot with no block has no row at all, so the line still crosses it.
              "spanNulls": False}
    if log:
        custom["scaleDistribution"] = {"type": "log", "log": 10}
    defaults = {"unit": unit, "decimals": 1, "custom": custom, "displayName": "${__field.name}"}
    return {"type": "trend", "id": pid(), "title": title, "description": desc,
            "datasource": CH, "gridPos": gp,
            "fieldConfig": {"defaults": defaults, "overrides": [SLOT_AXIS] + color_overrides()},
            "options": {"xField": "slot",
                        "legend": {"displayMode": "list", "placement": "bottom", "showLegend": True,
                                   "calcs": ["mean", "max", "p95", "p99"], "sortBy": "Mean", "sortDesc": False},
                        "tooltip": {"mode": "multi", "sort": "desc"}},
            "targets": [target("A", sql)]}


ROWS_TO_FIELDS = {"id": "rowsToFields", "options": {"mappings": [
    {"fieldName": "client", "handlerKey": "field.name"},
    {"fieldName": "value", "handlerKey": "field.value"}]}}


def bargauge(title, desc, sql, gp, unit="ms", maxv=None):
    """`sql` returns (client, value) rows in display order, best first."""
    defaults = {"unit": unit, "decimals": 1, "min": 0, "color": {"mode": "fixed"}}
    if maxv is not None:
        defaults["max"] = maxv
    return {"type": "bargauge", "id": pid(), "title": title, "description": desc,
            "datasource": CH, "gridPos": gp,
            "fieldConfig": {"defaults": defaults, "overrides": color_overrides()},
            "options": {"displayMode": "gradient", "orientation": "horizontal", "showUnfilled": True,
                        "valueMode": "color", "namePlacement": "left",
                        "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}},
            "transformations": [ROWS_TO_FIELDS],
            "targets": [target("A", sql)]}


def win_share(cond="1", cte=CTE):
    """(client, % of the compared blocks matching cond it won), most wins first; zero-win clients kept."""
    return (cte + "SELECT client, 100 * countIf(winner = client) / count() AS value\n"
            "FROM compared ARRAY JOIN [${clients:singlequote}] AS client\n"
            f"WHERE {cond}\nGROUP BY client\nORDER BY value DESC")


ABOUT = """### What we run

Three mainnet beacon nodes on identical hosts (Ryzen 7 9700X, 62 GiB, same OVH datacenter), each paired with its own ethrex v30.0.1:

| client | host | where its rows come from |
|---|---|---|
| **ethlambda** (nightly) | ethlambda-4 | its own `block_events` rows (`--telemetry.clickhouse-url`), `meta_client_name = $eth_client` |
| **Lighthouse** v8.3.2 | ethlambda-2 | its OpenTelemetry spans (`--telemetry-collector-url`) in `otel_traces`, reshaped by the view `lighthouse_block_events` |
| **Silver** | ethlambda-5 | `silver_telemetry` rows in eth-5's ClickHouse, read live through the remote table `silver_block_events`, `meta_client_name = $silver_client` |

### How we measure

**Received → attestable** (the first comparison) is each client's own time from receiving a block to the later of **attestable** and its engine_newPayload verdict: the first moment it could attest to the block with its payload validated. Attestable is the end of the head recompute that includes the block. For ethlambda, the head recompute after its import cascade (`get_head_end`), or, for a block it imported before the EL answered (the live node since 2026-11-05), the moment the VALID answer was applied, which always comes later; for Lighthouse, the `get_head` inside `import_block`, where the block enters its early attester cache (`import_block` then writes the block, its columns and the state to disk, which is left out); for Silver, its `Applied` (in fork choice, new head published), which comes before the EL verdict on ~90% of blocks, so there the verdict sets the number.

**STF only** (the second comparison) is received → the end of the state transition, state root included, leaving out everything after it: the EL verdict, the import and the head recompute. ethlambda's `stf_done` (its `stf_spec_end` before 2026-11-05, when the transition ran alongside a waited-for EL call), Lighthouse's end of `update_tree_hash_cache`, Silver's `stf_done`, which for a block not held for columns is the same instant as its `attestable` (Silver stamps its transition and its import together, so there it also covers the import). ethlambda's includes any wait for custody columns, since it runs the transition only once they are in; Silver runs its transition first and waits after.

**Delta (Δ)**, which the block weight, per-client and per-block sections compare, is received → attestable without the EL verdict: the first comparison's number for ethlambda and Lighthouse, lower for Silver.

**Waiting for blobs** is the time a client's import sat waiting for the block's blobs/columns, in its own terms: ethlambda's `columns_wait` section (before its state transition); for Lighthouse, only an import deferred until the data arrived (it fetches blobs from the EL while it executes the block); for Silver, the hold before its checks plus the wait after its state transition until the columns arrived. A block counts as having waited above 1 ms.

**Step by step** splits received → attestable for ethlambda and Silver into steps defined from both codebases, so each covers the same work; the table's *measured as* column says where they still differ (Silver stamps its state transition apart from its import only for blocks held for columns).

The **win rates** are worked out twice, once on received → attestable and once on STF only: a block is **compared** only when every selected client has that number for it; the **winner** is the lowest, **lead** how far ahead of the runner-up it was. A block is **heavy** when the slowest selected client took at least $heavy_ms by that number. The per-client table's wins are on Δ.

**State transition done** is when the transition, state root included, finished: ethlambda's `stf_spec_end` (run alongside the EL call), Lighthouse's end of `update_tree_hash_cache` (also alongside the EL call), Silver's `stf_done` only for blocks held for columns (an unheld block reports its transition and its import as one instant).

Caveats: each client times itself (no common observer; each host's NTP offset is under 0.2 ms). `received` is where each client first sees the gossip message: ethlambda when libp2p hands it over (before snappy decode), Silver when its network tile takes it in, Lighthouse when its beacon processor picks it up, after its network thread decoded the block. Lighthouse's processor queue averages ~3 µs, so the untimed decode is the whole difference (for scale, ethlambda's decode plus gossip checks take ~1.8 ms p50). ethlambda's `attestable` is the head recompute after the whole import cascade, or the applied VALID answer when that came later. ethlambda's rows from 21:15 to 21:55 UTC on 2026-11-05 have no EL verdict and an `attestable` before it (fixed in nightly 4117c5a), so there its received → attestable leaves out the EL. Lighthouse's `attestable` needs a recent, non-optimistic import (no early attester cache otherwise), so a block its EL answered SYNCING for, or one imported several slots late, has no Δ. Rows are kept 14 days. Generated by `~/metrics-beacon/gen-compare-dashboard.py` on ethlambda-4."""

def aggs(v):
    """(label, whole-range aggregate, per-client aggregate template) over column v."""
    return [("avg", f"avg({v})", f"avgIfOrNull({v}, {{c}})"),
            ("p50", f"quantile(0.5)({v})", f"quantileIfOrNull(0.5)({v}, {{c}})"),
            ("p95", f"quantile(0.95)({v})", f"quantileIfOrNull(0.95)({v}, {{c}})"),
            ("p99", f"quantile(0.99)({v})", f"quantileIfOrNull(0.99)({v}, {{c}})")]


# (row title, column, panel label, what the column measures). The two comparisons the dashboard leads
# with: the whole path to attestable, EL included, then the state transition alone.
DELTA_ROWS = [
    ("Received → attestable, EL wait included: the later of attestable and the engine_newPayload verdict, "
     "each client's own clock",
     "att_ms", "Received → attestable", "Received → the later of attestable and the engine_newPayload verdict"),
    ("STF only: received → state transition done (state root included), each client's own clock",
     "stf_only_ms", "STF only", "Received → the end of the state transition, state root included"),
]
# The win rates, once per comparison above: (name in titles, column, what a client must have for a block
# to be compared, in descriptions).
WIN_ROWS = [
    ("received → attestable", "att_ms", "a received → attestable time (EL wait included)"),
    ("STF only", "stf_only_ms", "an STF-only time"),
]


def win_group(panels, y, win_name, win_col, win_what):
    """One comparison's win rates on its own `compared`: share of blocks won, over time, on heavy and
    light blocks, and how many were compared. Returns the next free y."""
    cte = cte_for(win_col)
    panels.append(row(f"Who wins each block, {win_name}: lowest among the selected clients", y)); y += 1
    panels.append({
        "type": "piechart", "id": pid(),
        "title": f"Win rate, {win_name}: share of compared blocks each client was fastest",
        "description": f"Per block that every selected client has {win_what} for: the client with the "
                       "lowest wins it.",
        "datasource": CH, "gridPos": {"h": 8, "w": 12, "x": 0, "y": y},
        "fieldConfig": {"defaults": {"unit": "none", "displayName": "${__field.name}"},
                        "overrides": color_overrides()},
        "options": {"pieType": "donut", "displayLabels": ["percent"],
                    "legend": {"displayMode": "table", "placement": "right", "showLegend": True,
                               "values": ["value", "percent"], "sortBy": "Value", "sortDesc": True},
                    "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                    "tooltip": {"mode": "multi"}},
        "transformations": [ROWS_TO_FIELDS],
        "targets": [target("A", cte + "SELECT client, countIf(winner = client) AS value\n"
                                     "FROM compared ARRAY JOIN [${clients:singlequote}] AS client\n"
                                     "GROUP BY client\nORDER BY value DESC")]})
    share_sql = (cte + "SELECT toStartOfInterval(slot_start, INTERVAL ${window}) AS time,\n  "
                 + win_cols("100 * ") + "\nFROM compared GROUP BY time ORDER BY time")
    panels.append(ts_panel(f"Win share over time, {win_name} (%), per window",
                           "Share of the compared blocks in each $window window that each client won; the "
                           "stack adds up to 100%.", share_sql,
                           {"h": 8, "w": 12, "x": 12, "y": y}, unit="percent", stack=True,
                           sort_by="Mean", sort_desc=True))
    y += 8
    for i, (label, cond) in enumerate([("heavy blocks (slowest ≥ $heavy_ms)", "worst_ms >= ${heavy_ms}"),
                                       ("light blocks (slowest < $heavy_ms)", "worst_ms < ${heavy_ms}")]):
        panels.append(bargauge(f"Win rate on {label}, {win_name}",
                               "Share of these compared blocks each client won, most wins first. Heavy "
                               f"and light go by the slowest client's {win_what}.",
                               win_share(cond, cte), {"h": 6, "w": 9, "x": 9 * i, "y": y},
                               unit="percent", maxv=100))
    stat_sql = (cte + "SELECT count() AS `compared`, countIf(worst_ms >= ${heavy_ms}) AS `heavy`,\n"
                "  countIf(worst_ms < ${heavy_ms}) AS `light`,\n"
                "  (SELECT uniqExact(block_root) FROM blocks) AS `seen by any`\nFROM compared")
    panels.append({
        "type": "stat", "id": pid(), "title": f"Blocks compared, {win_name}",
        "description": f"Blocks every selected client has {win_what} for (compared), split by weight; "
                       "'seen by any' counts blocks at least one selected client has.",
        "datasource": CH, "gridPos": {"h": 6, "w": 6, "x": 18, "y": y},
        "fieldConfig": {"defaults": {"unit": "none", "decimals": 0,
                                     "color": {"mode": "fixed", "fixedColor": "text"}}, "overrides": []},
        "options": {"colorMode": "none", "graphMode": "none", "justifyMode": "auto", "orientation": "vertical",
                    "textMode": "value_and_name",
                    "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}},
        "targets": [target("A", stat_sql)]})
    y += 6
    return y


def block_weight_panel(panels, y):
    """The block weight vs Δ scatter, under the first win rates as before. Returns the next free y."""
    XLABEL = "el_median_ms"
    xy_sql = (CTE + f"SELECT median(el_ms) AS `{XLABEL}`,\n  "
              + ",\n  ".join(f"maxIf(delta_ms, client = '{n}') AS `{n}`" for n in NAMES)
              + f"\nFROM blocks GROUP BY block_root HAVING `{XLABEL}` IS NOT NULL")
    panels.append({
        # pluginVersion: without it Grafana runs the old-to-new xychart migration on this
        # provisioned panel, which turns a manual series list into "Err".
        "type": "xychart", "id": pid(), "pluginVersion": "12.3.2",
        "title": "Block weight vs delta: EL newPayload time (X, median of the clients) vs each client's Δ (Y)",
        "description": "One point per client per block. These tables carry no gas figure, so the median of the "
                       "clients' own engine_newPayload times stands in for how heavy the block was. Y is log scale.",
        "datasource": CH, "gridPos": {"h": 9, "w": 24, "x": 0, "y": y},
        "fieldConfig": {"defaults": {"unit": "ms", "decimals": 1, "color": {"mode": "palette-classic"},
                                     "custom": {"show": "points", "pointShape": "circle", "pointSize": {"fixed": 4},
                                                "pointStrokeWidth": 0, "fillOpacity": 50, "axisPlacement": "auto",
                                                "axisLabel": "Δ (ms)", "hideFrom": {"legend": False, "tooltip": False, "viz": False},
                                                "scaleDistribution": {"type": "log", "log": 10}}},
                        "overrides": color_overrides() + [
                            {"matcher": {"id": "byName", "options": XLABEL},
                             "properties": [{"id": "custom.scaleDistribution", "value": {"type": "linear"}},
                                            {"id": "custom.axisLabel",
                                             "value": "EL newPayload, median of the clients (ms)"},
                                            {"id": "min", "value": 0}]}]},
        "options": {"mapping": "manual",
                    "series": [{"frame": {"matcher": {"id": "byIndex", "options": 0}},
                                "x": {"matcher": {"id": "byName", "options": XLABEL}},
                                "y": {"matcher": {"id": "byName", "options": n}}} for n in NAMES],
                    "legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
                    "tooltip": {"mode": "single", "sort": "none"}},
        "targets": [target("A", xy_sql)]})
    y += 9
    return y


def build():
    panels = []
    y = 0
    colors = {n: col for n, _, col in CLIENTS}
    panels.append({
        "type": "stat", "id": pid(), "title": "Versions",
        "description": "Each client's version at the end of the time range. ethlambda and Lighthouse come from "
                       "their own Prometheus info metrics (lean_node_info, lighthouse_info). Silver's is fixed in "
                       "the generator from `silver --version`: its Beacon API reports a placeholder and it exports "
                       "no metrics.",
        "datasource": PROM, "gridPos": {"h": 3, "w": 24, "x": 0, "y": y},
        "fieldConfig": {"defaults": {"color": {"mode": "fixed", "fixedColor": "text"}},
                        "overrides": [{"matcher": {"id": "byFrameRefID", "options": chr(65 + i)},
                                       "properties": [{"id": "color",
                                                       "value": {"mode": "fixed", "fixedColor": colors[n]}}]}
                                      for i, (n, _, _) in enumerate(VERSIONS)]},
        "options": {"textMode": "name", "colorMode": "background", "graphMode": "none", "justifyMode": "center",
                    "orientation": "vertical", "wideLayout": True, "showPercentChange": False,
                    "text": {"titleSize": 22, "valueSize": 22},
                    "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}},
        "targets": [{"refId": chr(65 + i), "datasource": PROM, "expr": expr, "legendFormat": legend,
                     "instant": True, "range": False}
                    for i, (_, expr, legend) in enumerate(VERSIONS)]})
    y += 3
    about = {"type": "text", "id": pid(), "title": "What we run & how we measure",
             "gridPos": {"h": 14, "w": 24, "x": 0, "y": y + 1},
             "options": {"mode": "markdown", "content": ABOUT}}
    panels.append(row("What we run & how we measure  (click to expand)", y, collapsed=True, panels=[about]))
    y += 1

    # Delta per client, then attestable delta: rolling and whole-range quantiles.
    for row_title, col, name, what in DELTA_ROWS:
        panels.append(row(row_title, y)); y += 1
        for i, (label, _, agg) in enumerate(aggs(col)):
            sql = (CTE + f"SELECT toStartOfInterval(slot_start, INTERVAL ${{window}}) AS time,\n  "
                   f"{per_client_cols(agg)}\nFROM blocks GROUP BY time ORDER BY time")
            panels.append(ts_panel(f"{name} {label} (ms), per window",
                                   f"{what}, {label} over the blocks in each $window window.",
                                   sql, {"h": 8, "w": 6, "x": 6 * i, "y": y}, sort_by="Median"))
        y += 8
        for i, (label, agg, _) in enumerate(aggs(col)):
            sql = CTE + f"SELECT client, {agg} AS value\nFROM blocks\nGROUP BY client\nORDER BY value"
            panels.append(bargauge(f"{name} {label}, whole range (ms)", f"{what}, {label} over every block in "
                                   "the range, lowest (best) first.",
                                   sql, {"h": 6, "w": 6, "x": 6 * i, "y": y}))
        y += 6

    # Winners, once per comparison the dashboard leads with (WIN_ROWS), each on its own `compared`,
    # with the block weight vs Δ scatter under the first, where it was.
    y = win_group(panels, y, *WIN_ROWS[0])
    y = block_weight_panel(panels, y)
    y = win_group(panels, y, *WIN_ROWS[1])

    # Waiting for blobs.
    panels.append(row("Waiting for blobs: time the import sat waiting for the block's blobs/columns", y)); y += 1
    waited = "blob_wait_ms > 1"
    for i, (title, desc, expr, order) in enumerate([
        ("Blocks that waited for blobs (%)", "Share of the client's blocks whose import waited more than 1 ms "
         "for data, fewest first.", f"100 * countIf({waited}) / count()", "ASC"),
        ("Wait when waiting, p50 (ms)", "Median wait over the blocks that waited, shortest first "
         "(0 = never waited).", f"ifNull(quantileIfOrNull(0.5)(blob_wait_ms, {waited}), 0)", "ASC"),
        ("Wait when waiting, p95 (ms)", "95th percentile wait over the blocks that waited, shortest first "
         "(0 = never waited).", f"ifNull(quantileIfOrNull(0.95)(blob_wait_ms, {waited}), 0)", "ASC"),
        ("Average blob wait per block (ms)", "Total wait divided by every block, including those that did "
         "not wait: what the wait adds to Δ on average.", "avg(blob_wait_ms)", "ASC"),
    ]):
        sql = CTE + f"SELECT client, {expr} AS value\nFROM blocks\nGROUP BY client\nORDER BY value {order}"
        unit = "percent" if "%" in title else "ms"
        panels.append(bargauge(title, desc, sql, {"h": 6, "w": 6, "x": 6 * i, "y": y}, unit=unit,
                               maxv=100 if unit == "percent" else None))
    y += 6
    wait_sql = per_block_sql(",\n  ".join(
        f"if(maxIf(blob_wait_ms, client = '{n}') > 1, maxIf(blob_wait_ms, client = '{n}'), NULL) AS `{n}`"
        for n in NAMES))
    panels.append(block_trend("Blob wait per block (ms)", "One point per block that waited more than 1 ms (the "
                              "rest are left out, so the legend's figures are over the blocks that waited). "
                              "Log scale.", wait_sql, {"h": 12, "w": 12, "x": 0, "y": y}, "blob wait", log=True))
    share_wait_sql = (CTE + "SELECT toStartOfInterval(slot_start, INTERVAL ${window}) AS time,\n  "
                      + ",\n  ".join(f"100 * countIf(client = '{n}' AND {waited}) / nullIf(countIf(client = '{n}'), 0) AS `{n}`"
                                     for n in NAMES)
                      + "\nFROM blocks GROUP BY time ORDER BY time")
    panels.append(ts_panel("Blocks that waited for blobs (%), per window", "Share of each client's blocks in "
                           "the $window window whose import waited for data.", share_wait_sql,
                           {"h": 12, "w": 12, "x": 12, "y": y}, unit="percent", sort_by="Median"))
    y += 12

    # Step by step, ethlambda vs Silver.
    panels.append(row("Step by step: ethlambda vs Silver, each step measured the same way in both", y)); y += 1
    steps_sql = (CTE + COLS_CTE + "SELECT ord AS `#`, * EXCEPT ord FROM (\n" + step_table_select("blocks", STEP_ROWS, 1)
                 + "\nUNION ALL\n" + step_table_select("col_blocks", COL_ROWS, len(STEP_ROWS) + 1)
                 + "\n) ORDER BY ord")
    panels.append({
        "type": "table", "id": pid(), "title": "Each step, ethlambda vs Silver (ms)",
        "description": "Median (p50) and p90 of each step over the blocks both clients' rows cover; n = blocks "
                       "with that step. The steps are defined from both codebases so each covers the same work "
                       "('measured as' says where they still differ). ethlambda − Silver > 0: ethlambda slower.",
        "datasource": CH, "gridPos": {"h": 19, "w": 24, "x": 0, "y": y},
        "fieldConfig": {"defaults": {"unit": "suffix: ms", "decimals": 1, "custom": {"align": "auto"}},
                        "overrides": [
                            {"matcher": {"id": "byName", "options": "#"},
                             "properties": [{"id": "unit", "value": "none"}, {"id": "decimals", "value": 0},
                                            {"id": "custom.width", "value": 45}]},
                            {"matcher": {"id": "byName", "options": "step"},
                             "properties": [{"id": "custom.width", "value": 270}]},
                            {"matcher": {"id": "byName", "options": "measured as"},
                             "properties": [{"id": "unit", "value": "string"},
                                            {"id": "custom.cellOptions", "value": {"type": "auto", "wrapText": True}}]},
                            {"matcher": {"id": "byRegexp", "options": "^(ethlambda|Silver) n$"},
                             "properties": [{"id": "unit", "value": "none"}, {"id": "decimals", "value": 0},
                                            {"id": "custom.width", "value": 100}]},
                            {"matcher": {"id": "byRegexp", "options": "^(ethlambda|Silver) p[0-9]+$"},
                             "properties": [{"id": "custom.width", "value": 125}]},
                            {"matcher": {"id": "byRegexp", "options": "^ethlambda .*"},
                             "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "#16a34a"}},
                                            {"id": "custom.cellOptions", "value": {"type": "color-text"}}]},
                            {"matcher": {"id": "byRegexp", "options": "^Silver .*"},
                             "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "#a855f7"}},
                                            {"id": "custom.cellOptions", "value": {"type": "color-text"}}]},
                            {"matcher": {"id": "byName", "options": "ethlambda − Silver"},
                             "properties": [{"id": "custom.width", "value": 150},
                                            {"id": "color", "value": {"mode": "thresholds"}},
                                            {"id": "thresholds", "value": {"mode": "absolute", "steps": [
                                                {"color": "#16a34a", "value": None},
                                                {"color": "#ef4444", "value": 0.05}]}},
                                            {"id": "custom.cellOptions", "value": {"type": "color-text"}}]},
                        ]},
        "options": {"showHeader": True, "cellHeight": "sm"},
        "targets": [target("A", steps_sql)]})
    y += 19
    seg_colors = [("checks before the EL request", "#64748b"), ("waiting for blobs", "#f59e0b"),
                  ("state transition + import + head", "#0ea5e9"), ("waiting for the EL verdict", "#ef4444")]
    stack_sql = (CTE + "SELECT client,\n  avg(pre_ms) AS `checks before the EL request`,\n"
                 "  avg(blob_wait_ms) AS `waiting for blobs`,\n  avg(proc_ms) AS `state transition + import + head`,\n"
                 f"  avg(el_wait_ms) AS `waiting for the EL verdict`\nFROM blocks WHERE client IN {PAIR_SQL}\n"
                 "GROUP BY client ORDER BY avg(recv_attestable_ms)")
    panels.append({
        "type": "barchart", "id": pid(), "title": "Where the time goes: average ms per block, received → attestable",
        "description": "Averages add up, so each bar is the client's average received → attestable, split into "
                       "the steps of the table above (hover for the numbers).",
        "datasource": CH, "gridPos": {"h": 6, "w": 24, "x": 0, "y": y},
        "fieldConfig": {"defaults": {"unit": "suffix: ms", "decimals": 1, "displayName": "${__field.name}",
                                     "custom": {"fillOpacity": 85, "lineWidth": 0}},
                        "overrides": [{"matcher": {"id": "byName", "options": n},
                                       "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]}
                                      for n, c in seg_colors]},
        "options": {"orientation": "horizontal", "stacking": "normal", "xField": "client", "showValue": "never",
                    "barWidth": 0.7, "groupWidth": 0.7, "fullHighlight": False,
                    "legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
                    "tooltip": {"mode": "multi", "sort": "none"}},
        "targets": [target("A", stack_sql)]})
    y += 6
    pair_cols = lambda v: ",\n  ".join(f"quantileIfOrNull(0.5)({v}, client = '{n}') AS `{n}`" for n in PAIR)
    for i, (title, desc, src, v) in enumerate([
        ("Checks before the EL request, p50 (ms)", "received → engine_newPayload sent, minus waiting for blobs.",
         "blocks", "pre_ms"),
        ("EL newPayload round trip, p50 (ms)", "engine_newPayload sent → answered.", "blocks", "el_ms"),
        ("State transition + import + head, p50 (ms)", "EL request → attestable, minus the waits for blobs and "
         "the EL.", "blocks", "proc_ms"),
        ("Data column arrival → validated, p50 (ms)", "Median over each block's custody columns.", "col_blocks",
         "col_validate_ms"),
    ]):
        sql = (CTE + (COLS_CTE if src == "col_blocks" else "")
               + f"SELECT toStartOfInterval(slot_start, INTERVAL ${{window}}) AS time,\n  {pair_cols(v)}\n"
               f"FROM {src} WHERE client IN {PAIR_SQL} GROUP BY time ORDER BY time")
        panels.append(ts_panel(title, desc + " Per $window window.", sql, {"h": 8, "w": 6, "x": 6 * i, "y": y},
                               sort_by="Median"))
    y += 8

    # Block by block.
    panels.append(row("Block by block", y)); y += 1
    complete = "count() = length([${clients:singlequote}])"
    table_sql = (CTE + "SELECT\n  any(slot) AS slot,\n  "
                 + ",\n  ".join(f"maxIf(delta_ms, client = '{n}') AS `{n} Δ`" for n in NAMES)
                 + f",\n  if({complete}, argMin(client, delta_ms), '') AS winner,\n"
                 f"  if({complete}, arrayElement(arraySort(groupArray(delta_ms)), 2) - min(delta_ms), NULL) AS `lead`,\n"
                 "  block_root\n"
                 + "\nFROM blocks\nGROUP BY block_root\nORDER BY slot DESC, block_root\nLIMIT 1000")
    client_map = {"type": "value", "options": {
        n: {"text": n, "color": col, "index": i} for i, (n, _, col) in enumerate(CLIENTS)}}
    winner_map = [client_map, {"type": "special", "options": {"match": "empty", "result": {"text": "—", "index": 9}}}]
    overrides = [
        {"matcher": {"id": "byName", "options": "slot"},
         "properties": [{"id": "unit", "value": "none"}, {"id": "decimals", "value": 0},
                        {"id": "custom.width", "value": 100},
                        {"id": "links", "value": [{"title": "beaconcha.in", "targetBlank": True,
                                                   "url": "https://beaconcha.in/slot/${__value.raw}"}]}]},
        # Without the string unit Grafana reads the 0x root as a hex number.
        {"matcher": {"id": "byName", "options": "block_root"},
         "properties": [{"id": "unit", "value": "string"}, {"id": "custom.inspect", "value": True}]},
        {"matcher": {"id": "byName", "options": "winner"},
         "properties": [{"id": "unit", "value": "string"}, {"id": "mappings", "value": winner_map},
                        {"id": "custom.cellOptions", "value": {"type": "color-background", "mode": "basic"}},
                        {"id": "custom.width", "value": 110}]},
        {"matcher": {"id": "byName", "options": "lead"},
         "properties": [{"id": "custom.width", "value": 90}]},
    ] + [
        {"matcher": {"id": "byRegexp", "options": f"^{n} .*"},
         "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": col}},
                        {"id": "custom.cellOptions", "value": {"type": "color-text"}}]}
        for n, _, col in CLIENTS
    ] + [
        {"matcher": {"id": "byName", "options": f"{n} Δ"},
         "properties": [{"id": "custom.width", "value": 130}]}
        for n in NAMES
    ]
    panels.append({
        "type": "table", "id": pid(), "title": "Block by block (newest first)",
        "description": "One row per block. Δ = delta (ms): received → attestable. winner = lowest Δ, set "
                       "only when every selected client has the block; lead = how many ms ahead of the runner-up. "
                       "The slot links to beaconcha.in.",
        "datasource": CH, "gridPos": {"h": 16, "w": 24, "x": 0, "y": y},
        "fieldConfig": {"defaults": {"unit": "ms", "decimals": 1,
                                     "custom": {"align": "auto", "filterable": True}},
                        "overrides": overrides},
        "options": {"showHeader": True, "cellHeight": "sm"},
        "targets": [target("A", table_sql)]})
    y += 16

    # Summary.
    panels.append(row("Summary per client", y)); y += 1
    summary_sql = (CTE + """SELECT client,
  count() AS blocks,
  quantile(0.5)(arrival_ms) AS `arrival p50`,
  quantile(0.5)(delta_ms) AS `Δ p50`,
  quantile(0.9)(delta_ms) AS `Δ p90`,
  quantile(0.99)(delta_ms) AS `Δ p99`,
  quantile(0.5)(el_ms) AS `EL p50`,
  quantile(0.9)(el_ms) AS `EL p90`,
  quantile(0.5)(stf_done_ms) AS `recv→stf_done p50`,
  quantile(0.5)(el_verdict_ms) AS `recv→EL verdict p50`,
  quantile(0.5)(att_ms) AS `attestable Δ p50`,
  quantile(0.5)(attestable_ms) AS `attestable p50`,
  quantile(0.9)(attestable_ms) AS `attestable p90`,
  100 * countIf(blob_wait_ms > 1) / count() AS `waited for blobs %`,
  quantileIf(0.5)(blob_wait_ms, blob_wait_ms > 1) AS `blob wait p50`
FROM blocks
GROUP BY client
ORDER BY `Δ p50`""")
    wins_sql = CTE + "SELECT winner AS client, count() AS wins, 100 * count() / (SELECT count() FROM compared) AS `win %`\nFROM compared GROUP BY winner"
    panels.append({
        "type": "table", "id": pid(), "title": "Per client, blocks received in the range",
        "description": "arrival/attestable are ms into the slot; Δ and the recv→ columns are ms from the client's "
                       "own 'received'. 'blocks' is coverage: fewer blocks means missing rows, not speed. "
                       "wins / win % are over the compared blocks.",
        "datasource": CH, "gridPos": {"h": 6, "w": 24, "x": 0, "y": y},
        "fieldConfig": {"defaults": {"unit": "ms", "decimals": 1, "custom": {"align": "auto"}},
                        "overrides": [
                            {"matcher": {"id": "byRegexp", "options": "^(blocks|wins)$"},
                             "properties": [{"id": "unit", "value": "none"}, {"id": "decimals", "value": 0}]},
                            {"matcher": {"id": "byRegexp", "options": "^(win %|waited for blobs %)$"},
                             "properties": [{"id": "unit", "value": "percent"}]},
                            {"matcher": {"id": "byRegexp", "options": "^(arrival|attestable) p[0-9]+$"},
                             "properties": [{"id": "unit", "value": "suffix: ms"}, {"id": "decimals", "value": 0}]},
                            {"matcher": {"id": "byName", "options": "client"},
                             "properties": [{"id": "mappings", "value": [client_map]},
                                            {"id": "custom.cellOptions", "value": {"type": "color-text"}}]}]},
        "options": {"showHeader": True, "cellHeight": "sm"},
        "transformations": [{"id": "joinByField", "options": {"byField": "client", "mode": "outer"}},
                            {"id": "renameByRegex", "options": {"regex": "^(.+) [A-B]$", "renamePattern": "$1"}}],
        "targets": [target("A", summary_sql), target("B", wins_sql)]})
    y += 6

    # Per block, the block's slot on the X axis.
    panels.append(row("Per block", y)); y += 1
    series = [
        ("Δ per block (ms)", "Each client's delta (received → attestable) per block.", "delta_ms", True, "ms",
         "received → attestable"),
        ("Attestable, ms into the slot", "When the block became attestable, from the start of its slot.",
         "attestable_ms", False, "suffix: ms", "attestable, into the slot"),
        ("Arrival, ms into the slot", "'received', from the start of the slot. Mostly network; Lighthouse's is its "
         "processor pick-up, after its network thread decoded the block (the decode is not timed).",
         "arrival_ms", False, "suffix: ms", "arrival, into the slot"),
        ("EL newPayload round trip (ms)", "el_sent → el_verdict, as each client timed it.", "el_ms", True, "ms",
         "EL round trip"),
        ("Received → state transition done (ms)", "Transition with the state root, run alongside the EL call. "
         "ethlambda: stf_spec_end; Lighthouse: end of update_tree_hash_cache; Silver: only blocks held for "
         "columns (it stamps no separate transition end for the others).", "stf_done_ms", True, "ms",
         "received → STF done"),
        ("Received → EL verdict (ms)", "From 'received' to the engine_newPayload answer.", "el_verdict_ms", True,
         "ms", "received → EL verdict"),
    ]
    for i, (title, desc, col, log, unit, y_label) in enumerate(series):
        sql = per_block_sql(",\n  ".join(f"maxIf({col}, client = '{n}') AS `{n}`" for n in NAMES))
        panels.append(block_trend(title, desc, sql, {"h": 12, "w": 12, "x": 12 * (i % 2), "y": y}, y_label,
                                  unit=unit, log=log))
        if i % 2:
            y += 12

    # Process & network (Prometheus).
    panels.append(row("Process & network (Prometheus; Silver exports no process metrics)", y)); y += 1
    rss = [prom(chr(65 + i), f'process_resident_memory_bytes{{node="{node}"}}', n)
           for i, (n, node, _) in enumerate(CLIENTS) if node]
    cpu = [prom(chr(65 + i), f'rate(process_cpu_seconds_total{{node="{node}"}}[$__rate_interval])', n)
           for i, (n, node, _) in enumerate(CLIENTS) if node]
    peers = [prom("A", 'sum(lean_connected_peers{node="beacon-eth4"})', "ethlambda"),
             prom("B", 'libp2p_peers{node="beacon-eth2"}', "Lighthouse"),
             prom("C", 'silver_peers_connected{node="silver-eth5"}', "Silver")]
    panels.append(ts_panel("Process memory (RSS)", "Resident set of the beacon node process.", None,
                           {"h": 8, "w": 8, "x": 0, "y": y}, unit="bytes", ds=PROM, targets=rss))
    panels.append(ts_panel("Process CPU (cores)", "CPU seconds per second of the beacon node process.", None,
                           {"h": 8, "w": 8, "x": 8, "y": y}, unit="none", ds=PROM, targets=cpu))
    panels.append(ts_panel("Connected peers", "libp2p peers each node reports.", None,
                           {"h": 8, "w": 8, "x": 16, "y": y}, unit="none", ds=PROM, targets=peers))
    y += 8

    # Lighthouse internals (collapsed).
    lh_ts = """SELECT min(Timestamp) AS time,
  sumIf(Duration, SpanName = 'verify_gossip_block') / 1e6 AS `gossip verify`,
  sumIf(Duration, SpanName = 'signature_verify') / 1e6 AS `signature verify`,
  sumIf(Duration, SpanName = 'per_block_processing') / 1e6 AS `per_block_processing`,
  sumIf(Duration, SpanName = 'update_tree_hash_cache') / 1e6 AS `state root (tree hash)`,
  sumIf(Duration, SpanName = 'execution_payload_verification') / 1e6 AS `EL newPayload`,
  sumIf(Duration, SpanName = 'import_block') / 1e6 AS `import_block`,
  sumIf(Duration, SpanName = 'lh_recompute_head_at_slot') / 1e6 AS `recompute head`,
  maxIf(Duration, ParentSpanId = '') / 1e6 AS `whole trace`
FROM otel_traces
WHERE ServiceName = 'lighthouse-eth2'
  AND Timestamp BETWEEN $__fromTime - INTERVAL 1 MINUTE AND $__toTime + INTERVAL 1 MINUTE
  AND TraceId IN (
    SELECT TraceId FROM otel_traces
    WHERE ServiceName = 'lighthouse-eth2' AND ParentSpanId = ''
      AND SpanName = 'lh_process_gossip_block'
      AND Timestamp BETWEEN $__fromTime AND $__toTime)
GROUP BY TraceId
ORDER BY time"""
    lh_table = """SELECT SpanName AS span,
  count() AS calls,
  quantile(0.5)(Duration) / 1e6 AS `p50`,
  quantile(0.9)(Duration) / 1e6 AS `p90`,
  quantile(0.99)(Duration) / 1e6 AS `p99`,
  sum(Duration) / 1e6 AS `total`
FROM otel_traces
WHERE ServiceName = 'lighthouse-eth2' AND $__timeFilter(Timestamp)
GROUP BY span
ORDER BY total DESC
LIMIT 40"""
    lh1 = ts_panel("Lighthouse: spans per gossip block (ms)", "One point per gossip block (trace rooted at "
                   "lh_process_gossip_block). EL newPayload overlaps the state transition.", lh_ts,
                   {"h": 9, "w": 24, "x": 0, "y": y + 1}, log=True, points=True)
    lh1["fieldConfig"]["overrides"] = []
    lh1["options"]["legend"]["placement"] = "right"
    lh2 = {"type": "table", "id": pid(), "title": "Lighthouse: every span in the range",
           "description": "All exported spans (blocks, columns, req/resp, backfill), by total time. ms.",
           "datasource": CH, "gridPos": {"h": 10, "w": 24, "x": 0, "y": y + 10},
           "fieldConfig": {"defaults": {"unit": "ms", "decimals": 2, "custom": {"align": "auto"}},
                           "overrides": [{"matcher": {"id": "byName", "options": "calls"},
                                          "properties": [{"id": "unit", "value": "none"},
                                                         {"id": "decimals", "value": 0}]}]},
           "options": {"showHeader": True, "cellHeight": "sm"},
           "targets": [target("A", lh_table)]}
    panels.append(row("Lighthouse internals (OpenTelemetry spans)  (click to expand)", y, collapsed=True,
                      panels=[lh1, lh2]))

    def custom_var(name, label, opts, default):
        return {"name": name, "label": label, "type": "custom", "hide": 0, "multi": False, "includeAll": False,
                "query": ", ".join(f"{t} : {v}" for t, v in opts),
                "options": [{"selected": v == default, "text": t, "value": v} for t, v in opts],
                "current": {"selected": True, "text": dict((v, t) for t, v in opts)[default], "value": default}}

    templating = {"list": [
        {"name": "clients", "label": "Clients", "type": "custom", "hide": 0, "multi": True, "includeAll": False,
         "query": ",".join(NAMES),
         "options": [{"selected": True, "text": n, "value": n} for n in NAMES],
         "current": {"selected": True, "text": NAMES, "value": NAMES}},
        custom_var("window", "Window", [("5m", "5 minute"), ("10m", "10 minute"), ("30m", "30 minute"),
                                        ("1h", "1 hour")], "10 minute"),
        custom_var("heavy_ms", "Heavy block: slowest ≥", [("50 ms", "50"), ("100 ms", "100"), ("200 ms", "200")],
                   "100"),
        custom_var("gossip_only", "Gossip blocks only", [("true", "true"), ("false", "false")], "true"),
        {"name": "eth_client", "label": "ethlambda client name", "type": "textbox", "hide": 0,
         "query": "beacon-eth4", "current": {"selected": False, "text": "beacon-eth4", "value": "beacon-eth4"}},
        {"name": "silver_client", "label": "Silver client name", "type": "textbox", "hide": 0,
         "query": "ethlambda-5", "current": {"selected": False, "text": "ethlambda-5", "value": "ethlambda-5"}},
    ]}
    return {
        "uid": "client-compare",
        "title": "Beacon client comparison",
        "description": "ethlambda vs Lighthouse vs Silver on mainnet, block by block, from ClickHouse. "
                       "Generated by ~/metrics-beacon/gen-compare-dashboard.py on ethlambda-4.",
        "tags": ["beacon", "mainnet", "clickhouse", "lighthouse", "silver"],
        "timezone": "utc", "editable": False, "graphTooltip": 1, "refresh": "1m",
        "time": {"from": "now-6h", "to": "now"}, "schemaVersion": 39, "version": 1,
        "templating": templating, "annotations": {"list": []},
        "links": [{"title": "Beacon Follower", "type": "link", "url": "/d/beacon-follower/beacon-follower"},
                  {"title": "Silver (eth-5)", "type": "link", "url": "/d/silver-eth5"}],
        "panels": panels,
    }


if __name__ == "__main__":
    with open(sys.argv[1], "w") as f:
        # ethlambda's stage names before and after its rename (#917).
        json.dump(stage_names.apply(build()), f, indent=1, ensure_ascii=False)
        f.write("\n")
