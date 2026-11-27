#!/usr/bin/env python3
"""Generates the lean64 Grafana dashboard for the Silver + ethrex mainnet node on ethlambda-5.

Usage: gen-silver-dashboard.py <out.json>

Silver exports no Prometheus metrics, so its status panels read the json_exporter series
(job "silver"), which are derived from the standard Beacon API. Its block processing panels
read the per-stage block events silver_telemetry writes to ClickHouse on eth-5 (datasource
uid silver-ch). ethrex and host panels read ethrex's own /metrics (job "ethrex") and
node_exporter (job "node").
"""

import json
import sys

DS = {"type": "prometheus", "uid": "${ds_prom}"}
CH = {"type": "grafana-clickhouse-datasource", "uid": "silver-ch"}

# One row per block from silver_telemetry's block_events (one row per stage event), with the
# step durations Silver's own web UI derives (crates/dashboard/web/trace.js):
#   hold      received -> validate start: waiting for the block's data before validation
#   validate  -> el_sent: consensus checks, then the payload goes to the EL
#   apply     el_sent -> stf_done: state transition
#   da_wait   stf_done -> attestable: post-state parked until the data columns arrived
#   total     received -> attestable (= hold + validate + apply + da_wait)
# and two paths that run alongside: el (el_sent -> EL verdict) and da (first column ->
# data available). Rows are read a minute beyond the range so blocks at its edges are whole.
NS = "(toUnixTimestamp64Nano({b}) - toUnixTimestamp64Nano({a})) / 1e6"
# Silver's rows only (meta_client_name is its hostname): an ethlambda node may write its own
# block_events rows into the same table (--telemetry.clickhouse-url; eth-4's go to its own
# ClickHouse instead), and grouping by root across clients would mix the two.
SILVER_CLIENT = "ethlambda-5"
BLOCKS = f"""(
  SELECT
    received, slot, source, verdict, block_root, arrival_ms, attestable_ms,
    {NS.format(a="received", b="validate_from")} AS hold_ms,
    {NS.format(a="validate_from", b="el_sent")} AS validate_ms,
    {NS.format(a="el_sent", b="coalesce(stf_done, attestable)")} AS apply_ms,
    {NS.format(a="stf_done", b="attestable")} AS da_wait_ms,
    {NS.format(a="received", b="attestable")} AS total_ms,
    {NS.format(a="el_sent", b="el_verdict_at")} AS el_ms,
    {NS.format(a="coalesce(first_column, da_available)", b="da_available")} AS da_ms
  FROM (
    SELECT
      block_root,
      maxOrNull(slot) AS slot,
      anyIf(source, stage = 'received') AS source,
      minIfOrNull(event_date_time, stage = 'received') AS received,
      minIfOrNull(time_into_slot_ms, stage = 'received') AS arrival_ms,
      minIfOrNull(event_date_time, stage = 'el_sent') AS el_sent,
      minIfOrNull(event_date_time, stage = 'el_verdict') AS el_verdict_at,
      argMinIf(verdict, event_date_time, stage = 'el_verdict') AS verdict,
      minIfOrNull(event_date_time, stage = 'stf_done') AS stf_done,
      minIfOrNull(event_date_time, stage = 'attestable') AS attestable,
      minIfOrNull(time_into_slot_ms, stage = 'attestable') AS attestable_ms,
      maxIfOrNull(event_date_time, stage = 'da_available') AS da_available,
      minIfOrNull(event_date_time, stage = 'column_recv') AS first_column,
      if(da_available IS NOT NULL AND el_sent IS NOT NULL AND da_available < el_sent,
         greatest(received, da_available), received) AS validate_from
    FROM block_events
    WHERE event_date_time BETWEEN $__fromTime - INTERVAL 1 MINUTE
                              AND $__toTime + INTERVAL 1 MINUTE
      AND meta_client_name = '{SILVER_CLIENT}'
    GROUP BY block_root
  )
  WHERE received BETWEEN $__fromTime AND $__toTime
)"""
CL = 'node="silver-eth5"'
EL = 'node="ethrex-silver-eth5"'
HOST = 'node="host-eth5"'
# Mainnet genesis (1606824023) and 12 s slots / 32-slot epochs. floor() takes only an instant
# vector, hence the scalar(vector()) round trip.
WALL_SLOT = "scalar(floor(vector((time() - 1606824023) / 12)))"
WALL_EPOCH = "scalar(floor(vector((time() - 1606824023) / 384)))"

panel_id = 0
panels = []


def next_id():
    global panel_id
    panel_id += 1
    return panel_id


def target(expr, legend="", instant=False, ref="A"):
    return {
        "refId": ref,
        "datasource": DS,
        "expr": expr,
        "legendFormat": legend,
        "editorMode": "code",
        "range": not instant,
        "instant": instant,
    }


def row(title, y):
    panels.append({
        "type": "row", "id": next_id(), "title": title, "collapsed": False,
        "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}, "panels": [],
    })


def stat(title, expr, x, y, w=3, h=4, unit="none", steps=None, mappings=None,
         description="", decimals=None):
    defaults = {
        "unit": unit,
        "mappings": mappings or [],
        "thresholds": {"mode": "absolute",
                       "steps": steps or [{"color": "green", "value": None}]},
        "color": {"mode": "thresholds"},
    }
    if decimals is not None:
        defaults["decimals"] = decimals
    panels.append({
        "type": "stat", "id": next_id(), "title": title, "description": description,
        "datasource": DS, "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "colorMode": "value", "graphMode": "area", "textMode": "value",
            "justifyMode": "auto",
        },
        "targets": [target(expr, instant=True)],
    })


def series(title, targets, x, y, w=12, h=8, unit="none", description="", stepped=False,
           min_zero=True):
    custom = {"lineWidth": 1, "fillOpacity": 10, "showPoints": "never",
              "spanNulls": False}
    if stepped:
        custom["lineInterpolation"] = "stepAfter"
    defaults = {"unit": unit, "custom": custom}
    if min_zero:
        defaults["min"] = 0
    panels.append({
        "type": "timeseries", "id": next_id(), "title": title, "description": description,
        "datasource": DS, "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {"legend": {"displayMode": "list", "placement": "bottom",
                               "showLegend": True},
                    "tooltip": {"mode": "multi", "sort": "none"}},
        "targets": [target(e, legend, ref=chr(ord("A") + i))
                    for i, (e, legend) in enumerate(targets)],
    })


def ch_target(sql, table=False, ref="A"):
    # grafana-clickhouse-datasource 4.x: format 0 = time series, 1 = table.
    return {
        "refId": ref,
        "datasource": CH,
        "editorType": "sql",
        "queryType": "table" if table else "timeseries",
        "format": 1 if table else 0,
        "rawSql": sql,
    }


def ch_stat(title, sql, x, y, w=4, h=4, unit="ms", steps=None, description="",
            decimals=1):
    panels.append({
        "type": "stat", "id": next_id(), "title": title, "description": description,
        "datasource": CH, "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "fieldConfig": {"defaults": {
            "unit": unit, "decimals": decimals, "mappings": [],
            "thresholds": {"mode": "absolute",
                           "steps": steps or [{"color": "green", "value": None}]},
            "color": {"mode": "thresholds"},
        }, "overrides": []},
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "colorMode": "value", "graphMode": "none", "textMode": "value",
            "justifyMode": "auto",
        },
        "targets": [ch_target(sql, table=True)],
    })


def ch_series(title, sql, x, y, w=12, h=9, unit="ms", description="", bars=False,
              stack=False, points=False, threshold=None, min_interval=None):
    custom = {"lineWidth": 1, "fillOpacity": 70 if bars else 10, "spanNulls": False,
              "drawStyle": "bars" if bars else ("points" if points else "line"),
              "showPoints": "always" if points else "never", "pointSize": 3,
              "stacking": {"mode": "normal" if stack else "none", "group": "A"}}
    defaults = {"unit": unit, "min": 0, "custom": custom}
    if threshold is not None:
        custom["thresholdsStyle"] = {"mode": "line+area"}
        defaults["thresholds"] = {"mode": "absolute", "steps": [
            {"color": "transparent", "value": None}, {"color": "red", "value": threshold}]}
    panels.append({
        "type": "timeseries", "id": next_id(), "title": title, "description": description,
        "datasource": CH, "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {"legend": {"displayMode": "table", "placement": "bottom",
                               "showLegend": True, "calcs": ["mean", "max"]},
                    "tooltip": {"mode": "multi", "sort": "none"}},
        "targets": [ch_target(sql)],
    })
    if min_interval:
        # Floor for $__timeInterval: percentiles need several blocks (one per 12 s) per bucket.
        panels[-1]["interval"] = min_interval


def yes_no(zero_text, zero_color, one_text, one_color):
    return [{"type": "value", "options": {
        "0": {"text": zero_text, "color": zero_color, "index": 0},
        "1": {"text": one_text, "color": one_color, "index": 1},
    }}]


# --- Silver (CL) -------------------------------------------------------------------------
row("Silver (CL): read from its Beacon API through json_exporter", 0)
y = 1
stat("Head lag (slots)", f"{WALL_SLOT} - silver_head_slot{{{CL}}}", 0, y,
     steps=[{"color": "green", "value": None}, {"color": "red", "value": 3}],
     description="Wall-clock slot minus /eth/v1/node/syncing head_slot. 0 or 1 is healthy "
                 "(the head sits 1 behind until each slot's block arrives).")
stat("Sync distance", f"silver_sync_distance{{{CL}}}", 3, y,
     steps=[{"color": "green", "value": None}, {"color": "red", "value": 3}],
     description="sync_distance as Silver reports it.")
stat("Optimistic", f"silver_is_optimistic{{{CL}}}", 6, y,
     mappings=yes_no("no", "green", "yes", "orange"),
     description="Yes while ethrex has not validated the head (expected during ethrex's "
                 "snap sync).")
stat("EL", f"silver_el_offline{{{CL}}}", 9, y,
     mappings=yes_no("online", "green", "OFFLINE", "red"),
     description="el_offline from /eth/v1/node/syncing.")
stat("Peers", f"silver_peers_connected{{{CL}}}", 12, y,
     steps=[{"color": "red", "value": None}, {"color": "orange", "value": 10},
            {"color": "green", "value": 30}],
     description="connected from /eth/v1/node/peer_count.")
stat("Finality lag (epochs)", f"{WALL_EPOCH} - silver_finalized_epoch{{{CL}}}", 15, y,
     steps=[{"color": "green", "value": None}, {"color": "orange", "value": 4},
            {"color": "red", "value": 6}],
     description="Wall-clock epoch minus the head state's finalized epoch. 2 is normal "
                 "on mainnet.")
stat("Head slot", f"silver_head_slot{{{CL}}}", 18, y)
stat("API scrapes up", f'min(up{{job="silver",{CL}}})', 21, y,
     mappings=yes_no("DOWN", "red", "up", "green"),
     description="All three json_exporter probes of Silver's API answered.")
y += 4
series("Head lag (slots)", [(f"{WALL_SLOT} - silver_head_slot{{{CL}}}", "head lag")], 0, y)
series("Peers", [(f"silver_peers_connected{{{CL}}}", "connected"),
                 (f"silver_peers_connecting{{{CL}}}", "connecting"),
                 (f"silver_peers_disconnecting{{{CL}}}", "disconnecting")], 12, y)
y += 8
series("Finality and justification lag (epochs)",
       [(f"{WALL_EPOCH} - silver_finalized_epoch{{{CL}}}", "finalized"),
        (f"{WALL_EPOCH} - silver_current_justified_epoch{{{CL}}}", "current justified"),
        (f"{WALL_EPOCH} - silver_previous_justified_epoch{{{CL}}}", "previous justified")],
       0, y)
series("Sync flags (1 = true)",
       [(f"silver_is_optimistic{{{CL}}}", "optimistic"),
        (f"silver_is_syncing{{{CL}}}", "syncing"),
        (f"silver_el_offline{{{CL}}}", "EL offline")], 12, y, stepped=True)
y += 8

# --- Silver block processing (ClickHouse) ------------------------------------------------
STEPS_DOC = ("Steps, in order: wait for data (block held until its data arrived, before "
             "validation), validate (consensus checks until the payload is sent to the EL), "
             "apply (state transition), wait for data after the STF (post-state parked until "
             "the columns arrived). They add up to arrival -> attestable. 'EL verdict' "
             "(newPayload round trip) and 'data availability' (first column to all columns) "
             "run alongside them. Source: silver_telemetry stage events in ClickHouse.")
row("Silver block processing: arrival -> attestable and each step "
    "(ClickHouse, from silver_telemetry)", y)
y += 1
ch_stat("Blocks", f"SELECT count() FROM {BLOCKS}", 0, y, unit="none", decimals=0,
        description="Blocks first received in the time range.")
ch_stat("Arrival -> attestable, p50", f"SELECT quantile(0.5)(total_ms) FROM {BLOCKS}", 4, y,
        description=STEPS_DOC)
ch_stat("Arrival -> attestable, p99", f"SELECT quantile(0.99)(total_ms) FROM {BLOCKS}", 8, y,
        steps=[{"color": "green", "value": None}, {"color": "orange", "value": 250},
               {"color": "red", "value": 1000}], description=STEPS_DOC)
ch_stat("Arrival -> attestable, max", f"SELECT max(total_ms) FROM {BLOCKS}", 12, y,
        steps=[{"color": "green", "value": None}, {"color": "orange", "value": 500},
               {"color": "red", "value": 2000}], description=STEPS_DOC)
ch_stat("Arrival into slot, p50", f"SELECT quantile(0.5)(arrival_ms) FROM {BLOCKS}", 16, y,
        description="When blocks reached the node, counted from the slot start. Set by the "
                    "network and the proposer, not by Silver.")
ch_stat("Attestable by 4 s", "SELECT countIf(attestable_ms <= 4000) / "
        f"countIf(attestable_ms IS NOT NULL) FROM {BLOCKS}", 20, y, unit="percentunit",
        steps=[{"color": "red", "value": None}, {"color": "orange", "value": 0.95},
               {"color": "green", "value": 0.99}],
        description="Share of blocks attestable within 4 s of their slot start, the "
                    "attestation deadline.")
y += 4
ch_series("Arrival -> attestable per block, by step", f"""SELECT
  received AS time,
  hold_ms AS "wait for data (before validate)",
  validate_ms AS "validate",
  apply_ms AS "apply (STF)",
  da_wait_ms AS "wait for data (after STF)"
FROM {BLOCKS}
ORDER BY time""", 0, y, w=24, h=10, bars=True, stack=True, description=STEPS_DOC)
y += 10
ch_series("Arrival -> attestable, percentiles per interval", f"""SELECT
  $__timeInterval(received) AS time,
  quantile(0.5)(total_ms) AS p50,
  quantile(0.9)(total_ms) AS p90,
  quantile(0.99)(total_ms) AS p99,
  max(total_ms) AS max
FROM {BLOCKS}
GROUP BY time
ORDER BY time""", 0, y, description=STEPS_DOC, min_interval="5m")
ch_series("Time into slot per block", f"""SELECT
  received AS time,
  arrival_ms AS "arrival",
  attestable_ms AS "attestable"
FROM {BLOCKS}
ORDER BY time""", 12, y, points=True, threshold=4000,
          description="Arrival and attestable time, counted from each block's slot start. "
                      "The red band is past the 4 s attestation deadline.")
y += 9
for i, (q, label) in enumerate([(0.5, "p50"), (0.99, "p99")]):
    ch_series(f"Each step, {label} per interval", f"""SELECT
  $__timeInterval(received) AS time,
  quantile({q})(hold_ms) AS "wait for data (before validate)",
  quantile({q})(validate_ms) AS "validate",
  quantile({q})(apply_ms) AS "apply (STF)",
  quantile({q})(da_wait_ms) AS "wait for data (after STF)",
  quantile({q})(el_ms) AS "EL verdict",
  quantile({q})(da_ms) AS "data availability"
FROM {BLOCKS}
GROUP BY time
ORDER BY time""", 12 * i, y, h=13, description=STEPS_DOC, min_interval="5m")
y += 13
table_sql = f"""SELECT
  slot,
  received AS time,
  source,
  verdict AS "EL verdict status",
  arrival_ms AS "arrival into slot",
  hold_ms AS "wait for data (before validate)",
  validate_ms AS "validate",
  apply_ms AS "apply (STF)",
  da_wait_ms AS "wait for data (after STF)",
  total_ms AS "arrival -> attestable",
  attestable_ms AS "attestable into slot",
  el_ms AS "EL verdict",
  da_ms AS "data availability",
  block_root AS root
FROM {BLOCKS}
ORDER BY slot DESC
LIMIT 50"""
panels.append({
    "type": "table", "id": next_id(), "title": "Latest 50 blocks", "description": STEPS_DOC,
    "datasource": CH, "gridPos": {"h": 11, "w": 24, "x": 0, "y": y},
    "fieldConfig": {"defaults": {"unit": "ms", "decimals": 1,
                                 "custom": {"align": "auto", "cellOptions": {"type": "auto"}}},
                    "overrides": [
                        {"matcher": {"id": "byName", "options": "slot"},
                         "properties": [{"id": "unit", "value": "none"},
                                        {"id": "decimals", "value": 0}]},
                        {"matcher": {"id": "byName", "options": "time"},
                         "properties": [{"id": "unit", "value": "dateTimeAsIso"}]},
                        {"matcher": {"id": "byName", "options": "arrival -> attestable"},
                         "properties": [{"id": "custom.cellOptions",
                                         "value": {"type": "color-background",
                                                   "mode": "basic"}},
                                        {"id": "thresholds", "value": {
                                            "mode": "absolute", "steps": [
                                                {"color": "green", "value": None},
                                                {"color": "orange", "value": 250},
                                                {"color": "red", "value": 1000}]}}]},
                    ]},
    "options": {"showHeader": True, "cellHeight": "sm"},
    "targets": [ch_target(table_sql, table=True)],
})
y += 11

# --- ethrex (EL) -------------------------------------------------------------------------
row("ethrex (EL): full panels in the Ethrex L1 dashboard (node ethrex-silver-eth5)", y)
y += 1
stat("Up", f'up{{job="ethrex",{EL}}}', 0, y,
     mappings=yes_no("DOWN", "red", "up", "green"))
stat("Peers", f"ethrex_p2p_peer_count{{{EL}}}", 3, y,
     steps=[{"color": "red", "value": None}, {"color": "green", "value": 5}])
stat("Block number", f"block_number{{{EL}}}", 6, y,
     description="Appears once ethrex has finished snap sync and executes blocks.")
stat("Snap pivot block", f"ethrex_sync_pivot_block{{{EL}}}", 9, y)
stat("Sync stage", f"ethrex_sync_stage{{{EL}}}", 12, y,
     description="ethrex_sync_stage as exported (numeric snap-sync stage).")
stat("Data dir", f"datadir_size_bytes{{{EL}}}", 15, y, unit="bytes")
stat("RSS", f"process_resident_memory_bytes{{{EL}}}", 18, y, unit="bytes")
stat("CPU (cores)", f"rate(process_cpu_seconds_total{{{EL}}}[2m])", 21, y, decimals=2)
y += 4
series("Snap sync: downloaded / inserted (per second)",
       [(f"rate(ethrex_sync_accounts_downloaded{{{EL}}}[2m])", "accounts downloaded"),
        (f"rate(ethrex_sync_accounts_inserted{{{EL}}}[2m])", "accounts inserted"),
        (f"rate(ethrex_sync_storage_downloaded{{{EL}}}[2m])", "storage downloaded"),
        (f"rate(ethrex_sync_storage_inserted{{{EL}}}[2m])", "storage inserted"),
        (f"rate(ethrex_sync_bytecodes_downloaded{{{EL}}}[2m])", "bytecodes downloaded"),
        (f"rate(ethrex_sync_headers_downloaded{{{EL}}}[2m])", "headers downloaded")],
       0, y, unit="ops")
series("Data dir size", [(f"datadir_size_bytes{{{EL}}}", "datadir")], 12, y, unit="bytes")
y += 8
series("ethrex peers", [(f"ethrex_p2p_peer_count{{{EL}}}", "peers"),
                        (f"ethrex_sync_snap_peers{{{EL}}}", "snap peers")], 0, y)
series("ethrex CPU and memory",
       [(f"rate(process_cpu_seconds_total{{{EL}}}[2m])", "CPU cores"),
        (f"process_resident_memory_bytes{{{EL}}} / 2^30", "RSS GiB")], 12, y)
y += 8

# --- Host --------------------------------------------------------------------------------
row("Host ethlambda-5 (node_exporter; Silver has no per-process metrics)", y)
y += 1
series("CPU busy",
       [(f'1 - avg(rate(node_cpu_seconds_total{{{HOST},mode="idle"}}[2m]))', "busy")],
       0, y, w=8, unit="percentunit")
series("Memory",
       [(f"node_memory_MemTotal_bytes{{{HOST}}} - node_memory_MemAvailable_bytes{{{HOST}}}",
         "used"),
        (f"node_memory_MemTotal_bytes{{{HOST}}}", "total")], 8, y, w=8, unit="bytes")
series("Root disk used",
       [(f'1 - node_filesystem_avail_bytes{{{HOST},mountpoint="/"}} / '
         f'node_filesystem_size_bytes{{{HOST},mountpoint="/"}}', "used")],
       16, y, w=8, unit="percentunit")
y += 8
series("Network",
       [(f'rate(node_network_receive_bytes_total{{{HOST},device="enp6s0"}}[2m]) * 8', "rx"),
        (f'rate(node_network_transmit_bytes_total{{{HOST},device="enp6s0"}}[2m]) * 8', "tx")],
       0, y, w=12, unit="bps")
series("Disk I/O",
       [(f"sum(rate(node_disk_read_bytes_total{{{HOST}}}[2m]))", "read"),
        (f"sum(rate(node_disk_written_bytes_total{{{HOST}}}[2m]))", "write")],
       12, y, w=12, unit="Bps")

dashboard = {
    "uid": "silver-eth5",
    "title": "Silver + ethrex (eth-5)",
    "description": "Silver (gattaca-com/silver) mainnet CL paired with ethrex on ethlambda-5.",
    "tags": ["beacon", "mainnet", "silver"],
    "schemaVersion": 39,
    "editable": False,
    "refresh": "30s",
    "time": {"from": "now-6h", "to": "now"},
    "timezone": "utc",
    "templating": {"list": [{
        "name": "ds_prom", "label": "Datasource", "type": "datasource",
        "query": "prometheus", "hide": 0, "refresh": 1, "regex": "/^Prometheus$/",
    }]},
    "links": [
        {"title": "Ethrex L1 (this EL)", "type": "link", "icon": "dashboard",
         "url": "/d/ethrex-l1?var-network=mainnet&var-node=ethrex-silver-eth5",
         "keepTime": True, "targetBlank": False, "asDropdown": False,
         "includeVars": False, "tags": [], "tooltip": ""},
        {"title": "Beacon Follower", "type": "link", "icon": "dashboard",
         "url": "/d/beacon-follower", "keepTime": True, "targetBlank": False,
         "asDropdown": False, "includeVars": False, "tags": [], "tooltip": ""},
    ],
    "panels": panels,
}

with open(sys.argv[1], "w") as f:
    json.dump(dashboard, f, indent=2)
    f.write("\n")
print(f"{len(panels)} panels")
