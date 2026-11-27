#!/usr/bin/env python3
"""Generates the lean64 Grafana dashboard that compares two ethlambda beacon nodes, A and B.

Usage: gen-ethlambda-ab.py <out.json>

Two single-select variables, `a` and `b`, each name one beacon node (the Prometheus `node`
label on job "beacon"). Every panel draws exactly one A series family and one B series
family, A always blue and B always orange, and a row of B / A ratios says at a glance which
side is faster. The header shows each side's version, network and uptime, so comparing two
builds, or a node against itself on another network, is visible rather than silent.

Per-block timings come from ethlambda-4's ClickHouse (datasource ethlambda-ch), where every
ethlambda beacon node writes its `block_events` rows (`--telemetry.clickhouse-url`) under
`--telemetry.client-name`, set to its `node` label, so `a`/`b` filter both Prometheus and
ClickHouse. The SQL is gen-dashboards.py's `ch_blocks`, imported, so the two dashboards cannot
disagree about what a step means. A node with no rows there draws no ClickHouse line.
"""

import importlib.util
import json
import os
import sys

_spec = importlib.util.spec_from_file_location(
    "gen_dashboards", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "gen-dashboards.py"))
_gd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_gd)
ch_blocks = _gd.ch_blocks

DS = {"type": "prometheus", "uid": "${ds_prom}"}
CH = _gd.CH  # ethlambda-4's ClickHouse, where every ethlambda node writes its rows
# (label, template variable, colour)
SIDES = [("A", "a", "blue"), ("B", "b", "orange")]
WIN = "$win"

panel_id = 0
panels = []


def next_id():
    global panel_id
    panel_id += 1
    return panel_id


def sel(var, extra=""):
    return f'job="beacon", node="${var}"' + (f", {extra}" if extra else "")


def side_overrides():
    """A blue, B orange, p99 dashed: the same pairing on every panel."""
    out = [{"matcher": {"id": "byRegexp", "options": f"^{label} .*"},
            "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": colour}}]}
           for label, _, colour in SIDES]
    out.append({"matcher": {"id": "byRegexp", "options": ".*p99.*"},
                "properties": [{"id": "custom.lineStyle",
                                "value": {"fill": "dash", "dash": [10, 10]}}]})
    return out


def prom(expr, legend, ref, instant=False, fmt=None):
    t = {"refId": ref, "datasource": DS, "expr": expr, "legendFormat": legend,
         "editorMode": "code", "range": not instant, "instant": instant}
    if fmt:
        t["format"] = fmt
    return t


def row(title, y):
    panels.append({"type": "row", "id": next_id(), "title": title, "collapsed": False,
                   "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}, "panels": []})


def stat(title, targets, x, y, w, h=4, unit="none", decimals=None, text_mode="value_and_name",
         steps=None, description="", colour_by_side=True, mappings=None):
    defaults = {"unit": unit, "mappings": mappings or [], "noValue": "–",
                "thresholds": {"mode": "absolute",
                               "steps": steps or [{"color": "text", "value": None}]},
                "color": {"mode": "thresholds"}}
    if decimals is not None:
        defaults["decimals"] = decimals
    panels.append({
        "type": "stat", "id": next_id(), "title": title, "description": description,
        "datasource": DS, "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "fieldConfig": {"defaults": defaults,
                        "overrides": side_overrides() if colour_by_side else []},
        "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                    "colorMode": "value", "graphMode": "none", "textMode": text_mode,
                    "justifyMode": "auto", "orientation": "vertical", "wideLayout": True},
        "targets": targets,
    })


def per_side_stat(title, expr_of, x, y, w, **kw):
    """One value per side; expr_of(var) builds the side's query."""
    targets = [prom(expr_of(var), f"{label} · ${var}", label, instant=True)
               for label, var, _ in SIDES]
    stat(title, targets, x, y, w, **kw)


RATIO_STEPS = [{"color": "green", "value": None}, {"color": "text", "value": 0.95},
               {"color": "orange", "value": 1.05}, {"color": "red", "value": 1.5}]


def ratio_stat(title, expr_of, x, y, w=4, description=""):
    """B / A of a lower-is-better quantity: under 1 means B is faster or lighter."""
    expr = f"({expr_of('b')}) / (({expr_of('a')}) > 0)"
    stat(title, [prom(expr, "B / A", "A", instant=True)], x, y, w, unit="suffix:×",
         decimals=2, text_mode="value", steps=RATIO_STEPS, colour_by_side=False,
         description=(description + " " if description else "") +
         "B divided by A over the `win` window: under 1 (green) B is lower, over 1.05 "
         "(orange) B is higher.")


def series(title, exprs, x, y, w=12, h=8, unit="s", description="", log=False,
           stepped=False, min_zero=True):
    """exprs: [(expr_of(var), suffix)], drawn once per side."""
    custom = {"lineWidth": 1, "fillOpacity": 0, "showPoints": "never", "spanNulls": True}
    if log:
        custom["scaleDistribution"] = {"type": "log", "log": 10}
    if stepped:
        custom["lineInterpolation"] = "stepAfter"
    defaults = {"unit": unit, "custom": custom}
    if min_zero and not log:
        defaults["min"] = 0
    targets, ref = [], 0
    for label, var, _ in SIDES:
        for expr_of, suffix in exprs:
            legend = f"{label} · ${var}" + (f" {suffix}" if suffix else "")
            targets.append(prom(expr_of(var), legend, chr(ord("A") + ref)))
            ref += 1
    panels.append({
        "type": "timeseries", "id": next_id(), "title": title, "description": description,
        "datasource": DS, "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "fieldConfig": {"defaults": defaults, "overrides": side_overrides()},
        "options": {"legend": {"displayMode": "table", "placement": "bottom",
                               "showLegend": True, "calcs": ["mean", "max", "lastNotNull"]},
                    "tooltip": {"mode": "multi", "sort": "none"}},
        "targets": targets,
    })


def by_label_table(title, label, expr_of, x, y, w=12, h=12, unit="s", description=""):
    """One row per `label` value: A, B, B / A. expr_of(var) must return one series per value."""
    targets = [prom(expr_of(var), "", ref, instant=True, fmt="table")
               for ref, (_, var, _) in zip("AB", SIDES)]
    panels.append({
        "type": "table", "id": next_id(), "title": title, "description": description,
        "datasource": DS, "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "fieldConfig": {
            "defaults": {"unit": unit, "decimals": 2,
                         "custom": {"align": "auto", "cellOptions": {"type": "auto"}}},
            "overrides": [
                {"matcher": {"id": "byName", "options": "A"},
                 "properties": [{"id": "displayName", "value": "A · ${a}"},
                                {"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}},
                                {"id": "custom.cellOptions", "value": {"type": "color-text"}}]},
                {"matcher": {"id": "byName", "options": "B"},
                 "properties": [{"id": "displayName", "value": "B · ${b}"},
                                {"id": "color", "value": {"mode": "fixed", "fixedColor": "orange"}},
                                {"id": "custom.cellOptions", "value": {"type": "color-text"}}]},
                {"matcher": {"id": "byName", "options": "B / A"},
                 "properties": [{"id": "unit", "value": "suffix:×"},
                                {"id": "thresholds", "value": {"mode": "absolute",
                                                               "steps": RATIO_STEPS}},
                                {"id": "color", "value": {"mode": "thresholds"}},
                                {"id": "custom.cellOptions", "value": {"type": "color-text"}}]},
            ]},
        "options": {"showHeader": True, "cellHeight": "sm",
                    "footer": {"show": False, "reducer": ["sum"], "fields": ""},
                    "sortBy": [{"displayName": label, "desc": False}]},
        "transformations": [
            {"id": "merge", "options": {}},
            {"id": "calculateField",
             "options": {"mode": "binary", "alias": "B / A", "replaceFields": False,
                         "binary": {"left": "Value #B", "operator": "/",
                                    "right": "Value #A"}}},
            {"id": "organize",
             "options": {"excludeByName": {"Time": True},
                         "renameByName": {"Value #A": "A", "Value #B": "B"},
                         "indexByName": {label: 0, "Value #A": 1, "Value #B": 2,
                                         "B / A": 3}}},
        ],
        "targets": targets,
    })


def hist_q(metric, q, extra=""):
    return lambda v: (f"histogram_quantile({q}, sum by (le) "
                      f"(rate({metric}_bucket{{{sel(v, extra)}}}[{WIN}]))) >= 0")


def mean(metric, extra=""):
    return lambda v: (f"sum(rate({metric}_sum{{{sel(v, extra)}}}[{WIN}])) / "
                      f"(sum(rate({metric}_count{{{sel(v, extra)}}}[{WIN}])) > 0)")


def mean_by(metric, label, extra=""):
    """Mean per `label` value over the dashboard range, for the per-phase tables."""
    return lambda v: (f"sum by ({label}) (increase({metric}_sum{{{sel(v, extra)}}}[$__range])) / "
                      f"(sum by ({label}) (increase({metric}_count{{{sel(v, extra)}}}[$__range])) > 0)")


def gauge(metric, extra="", agg="sum"):
    return lambda v: f"{agg}({metric}{{{sel(v, extra)}}})"


def cpu(v):
    return f"sum(rate(process_cpu_seconds_total{{{sel(v)}}}[{WIN}]))"


IMPORT = "lean_block_import_phase_seconds"
GOSSIP_TOTAL = 'phase="total", source="gossip"'
HEAD = "lean_beacon_head_compute_time_seconds"
FCR = "lean_beacon_fast_confirmation_time_seconds"
AGG = "lean_beacon_aggregate_processing_seconds"
NEWPAYLOAD = "lean_engine_new_payload_seconds"

y = 0
# --- Which nodes ---------------------------------------------------------------------------
row("Nodes", y)
y += 1
stat("Build", [prom(f"lean_node_info{{{sel(var)}}}",
                    f"{label} · ${var} · {{{{network}}}} · {{{{version}}}}", label, instant=True)
               for label, var, _ in SIDES],
     0, y, w=10, text_mode="name",
     description="`lean_node_info`: each side's network and build. Check these before "
                 "reading anything else; a different network makes every number below "
                 "incomparable.")
per_side_stat("Up for", lambda v: f"time() - max(lean_node_start_time_seconds{{{sel(v)}}})",
              10, y, w=4, unit="dtdurations",
              description="Time since the process started. A fresh restart (or a fresh "
                          "checkpoint sync) runs colder caches than a node that has been up "
                          "for days.")
per_side_stat("Head behind wall clock",
              lambda v: (f"max(lean_current_slot{{{sel(v)}}}) - "
                         f"max(lean_head_slot{{{sel(v)}}})"),
              14, y, w=3, unit="none", decimals=0,
              steps=[{"color": "green", "value": None}, {"color": "orange", "value": 2},
                     {"color": "red", "value": 8}],
              colour_by_side=False, description="Slots between the wall clock and the head.")
per_side_stat("Peers", gauge("lean_connected_peers"), 17, y, w=3, decimals=0)
per_side_stat("Sync", lambda v: f'max(lean_node_sync_status{{{sel(v, "status=" + chr(34) + "synced" + chr(34))}}})',
              20, y, w=4, colour_by_side=False,
              mappings=[{"type": "value", "options": {
                  "1": {"text": "synced", "color": "green"},
                  "0": {"text": "not synced", "color": "red"}}}])
y += 4

# --- Headline ratios -----------------------------------------------------------------------
row("B / A at a glance (window: $win; under 1 = B lower)", y)
y += 1
ratio_stat("Block import p50", hist_q(IMPORT, 0.5, GOSSIP_TOTAL), 0, y,
           description="Gossip blocks, wire to post-state.")
ratio_stat("Block import p99", hist_q(IMPORT, 0.99, GOSSIP_TOTAL), 4, y)
ratio_stat("Head compute, mean", mean(HEAD), 8, y)
ratio_stat("Fast confirmation, mean", mean(FCR), 12, y)
ratio_stat("CPU", cpu, 16, y, description="Cores used.")
ratio_stat("Resident memory", gauge("process_resident_memory_bytes"), 20, y)
y += 4

# --- Block import --------------------------------------------------------------------------
row("Block import", y)
y += 1
series("Block import, gossip (p50 solid, p99 dashed)",
       [(hist_q(IMPORT, 0.5, GOSSIP_TOTAL), "p50"), (hist_q(IMPORT, 0.99, GOSSIP_TOTAL), "p99")],
       0, y, w=12, h=9,
       description="`lean_block_import_phase_seconds{phase=\"total\",source=\"gossip\"}`: wire "
                   "to post-state for blocks that imported, holds included. Bucket-interpolated, "
                   "so a 1 s step in the buckets shows as a jump.")
by_label_table("Import phases, mean per event (gossip, dashboard range)", "phase",
               mean_by(IMPORT, "phase", 'source="gossip"'), 12, y, w=12, h=18,
               description="Mean of each section over the whole time range. Per-block and "
                           "per-arrival sections (arrival, cascade, get_head, fcu) are both "
                           "listed and are not additive; `total` is the whole import. "
                           "See docs/metrics.md, Block Import Timing.")
y += 9
series("State transition per imported block",
       [(lambda v: (f'sum(rate(lean_beacon_stf_phase_seconds_sum{{{sel(v, "context=" + chr(34) + "import" + chr(34))}}}[{WIN}])) / ('
                    f'sum(rate(lean_beacon_stf_phase_seconds_count{{{sel(v, "context=" + chr(34) + "import" + chr(34) + ", phase=" + chr(34) + "block_header" + chr(34))}}}[{WIN}])) > 0)'), "")],
       0, y, w=12, h=9,
       description="Every STF section's time for imported blocks, divided by the blocks "
                   "(each crosses block_header once). The table below splits it per section.")
y += 9
by_label_table("STF sections, mean per block (import, dashboard range)", "phase",
               mean_by("lean_beacon_stf_phase_seconds", "phase", 'context="import"'),
               0, y, w=12, h=12)
by_label_table("Gossip validation, mean per message (dashboard range)", "kind",
               mean_by("lean_beacon_gossip_validation_seconds", "kind"), 12, y, w=12, h=12,
               description="Time the p2p layer spent judging one message, per topic.")
y += 12

# --- Per-slot work -------------------------------------------------------------------------
row("Fork choice and per-slot work", y)
y += 1
series("Head computation (p50 solid, p99 dashed)",
       [(hist_q(HEAD, 0.5), "p50"), (hist_q(HEAD, 0.99), "p99")], 0, y, w=8)
series("Fast confirmation per slot (p50 solid, p99 dashed)",
       [(hist_q(FCR, 0.5), "p50"), (hist_q(FCR, 0.99), "p99")], 8, y, w=8)
series("Aggregate processing (p50 solid, p99 dashed)",
       [(hist_q(AGG, 0.5), "p50"), (hist_q(AGG, 0.99), "p99")], 16, y, w=8)
y += 8
series("Block wait in the chain actor's mailbox (p50 solid, p99 dashed)",
       [(hist_q(IMPORT, 0.5, 'phase="queue", source="gossip"'), "p50"),
        (hist_q(IMPORT, 0.99, 'phase="queue", source="gossip"'), "p99")], 0, y, w=12,
       description="The `queue` import phase: a gossip block waiting behind the chain "
                   "actor's other work (slot ticks, aggregates, columns) before its import "
                   "starts.")
series("Reorgs per hour",
       [(lambda v: f"sum(increase(lean_fork_choice_reorgs_total{{{sel(v)}}}[1h])) or vector(0)", "")],
       12, y, w=12, unit="none")
y += 8

# --- Execution client ----------------------------------------------------------------------
row("Execution client", y)
y += 1
series("engine_newPayload, valid answers (p50 solid, p99 dashed)",
       [(hist_q(NEWPAYLOAD, 0.5, 'outcome="valid"'), "p50"),
        (hist_q(NEWPAYLOAD, 0.99, 'outcome="valid"'), "p99")], 0, y, w=12,
       description="Mostly the execution client's own speed: compare it before blaming the "
                   "consensus side for a slower import.")
series("newPayload answers without a verdict, per hour",
       [(lambda v: (f"sum(increase(lean_engine_new_payload_answers_total"
                    f"{{{sel(v, 'outcome!=' + chr(34) + 'valid' + chr(34))}}}[1h])) or vector(0)"), "")],
       12, y, w=12, unit="none")
y += 8

# --- Network -------------------------------------------------------------------------------
row("Network", y)
y += 1
series("Connected peers", [(gauge("lean_connected_peers"), "")], 0, y, w=8, unit="none")
series("Gossip block arrival into slot (p50 solid, p99 dashed)",
       [(hist_q("lean_gossip_block_arrival_delay_seconds", 0.5), "p50"),
        (hist_q("lean_gossip_block_arrival_delay_seconds", 0.99), "p99")], 8, y, w=8,
       description="Set by the network and the proposer more than by the node, but a side "
                   "with worse peers sees blocks later.")
series("Gossip messages validated per second",
       [(lambda v: f"sum(rate(lean_beacon_gossip_validation_total{{{sel(v)}}}[{WIN}]))", "")],
       16, y, w=8, unit="ops")
y += 8

# --- Resources -----------------------------------------------------------------------------
row("Resources", y)
y += 1
series("CPU, cores used", [(cpu, "")], 0, y, w=6, unit="none")
series("Resident memory", [(gauge("process_resident_memory_bytes"), "")], 6, y, w=6,
       unit="bytes")
series("Database size", [(gauge("lean_table_bytes"), "")], 12, y, w=6, unit="bytes",
       min_zero=False)
series("Threads", [(gauge("process_threads"), "")], 18, y, w=6, unit="none")
y += 8

# --- Actor runtime -------------------------------------------------------------------------
row("Actor runtime (spawned; only builds with spawned 0.6.0 metrics have these)", y)
y += 1
series("Actor queue wait (p50 solid, p99 dashed)",
       [(hist_q("spawned_queue_wait_seconds", 0.5), "p50"),
        (hist_q("spawned_queue_wait_seconds", 0.99), "p99")], 0, y, w=8, log=True,
       description="Enqueue to handler start, summed over the chain and P2P actors. "
                   "See the Actor runtime (spawned) dashboard.")
series("Actor handler duration (p50 solid, p99 dashed)",
       [(hist_q("spawned_handler_duration_seconds", 0.5), "p50"),
        (hist_q("spawned_handler_duration_seconds", 0.99), "p99")], 8, y, w=8, log=True)
series("Actor busy time",
       [(lambda v: (f"({mean('spawned_handler_duration_seconds')(v)}) * "
                    f"sum(rate(spawned_messages_handled_total{{{sel(v)}}}[{WIN}]))"), "")],
       16, y, w=8, unit="percentunit",
       description="Handler time per second of wall clock across the node's actors.")
y += 8

# --- Per-block timings (ClickHouse) --------------------------------------------------------
row("Per-block timings (ClickHouse)", y)
y += 1


def ch_target(sql, ref):
    return {"refId": ref, "datasource": CH, "editorType": "sql",
            "queryType": "timeseries", "format": 0, "rawSql": sql}


def ch_ab_series(title, column, quantiles, x, y, w=12, h=9, description=""):
    targets = []
    for i, (label, var, _) in enumerate(SIDES):
        blocks = ch_blocks(f"meta_client_name = '${{{var}}}'")
        cols = ",\n  ".join(f'quantile({q})({column}) AS "{label} · ${{{var}}} p{round(q * 100)}"'
                            for q in quantiles)
        sql = (f"SELECT\n  $__timeInterval(received) AS time,\n  {cols}\n"
               f"FROM {blocks}\nGROUP BY time\nORDER BY time")
        targets.append(ch_target(sql, "AB"[i]))
    panels.append({
        "type": "timeseries", "id": next_id(), "title": title, "description": description,
        "datasource": CH, "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "interval": "1m",
        "fieldConfig": {"defaults": {"unit": "ms", "min": 0,
                                     "custom": {"lineWidth": 1, "fillOpacity": 0,
                                                "showPoints": "never", "spanNulls": True}},
                        "overrides": side_overrides()},
        "options": {"legend": {"displayMode": "table", "placement": "bottom",
                               "showLegend": True, "calcs": ["mean", "max"]},
                    "tooltip": {"mode": "multi", "sort": "none"}},
        "targets": targets,
    })


CH_NOTE = ("From each node's `block_events` rows in ethlambda-4's ClickHouse "
           "(`--telemetry.clickhouse-url`, named by its node label). A node that does not "
           "write there draws no line; beacon-eth5's rows start 2026-11-06 22:11 UTC. ")
ch_ab_series("Arrival -> attestable (p50 solid, p99 dashed)", "total_ms",
             (0.5, 0.99), 0, y,
             description=CH_NOTE + "Wire arrival to the head that makes the block attestable.")
ch_ab_series("STF + EL step (p50 solid, p99 dashed)", "exec_ms", (0.5, 0.99),
             12, y, description=CH_NOTE + "engine_newPayload and the speculative state "
                                          "transition side by side, then the import.")
y += 9
ch_ab_series("Before the STF (p50 solid, p99 dashed)", "before_ms", (0.5, 0.99),
             0, y, description=CH_NOTE + "Decode, actor queue, admission and checks.")
ch_ab_series("Head step (p50 solid, p99 dashed)", "head_ms", (0.5, 0.99), 12, y,
             description=CH_NOTE + "Block attestations, then the head recomputation.")
y += 9

# --- Variables -----------------------------------------------------------------------------
NODES = 'label_values(lean_node_info{job="beacon"}, node)'


def node_var(name, label, default):
    return {"name": name, "label": label, "type": "query", "datasource": DS,
            "definition": NODES,
            "query": {"qryType": 1, "query": NODES, "refId": f"{name}-query"},
            "refresh": 2, "sort": 1, "multi": False, "includeAll": False, "hide": 0,
            "current": {"selected": True, "text": default, "value": default}, "options": []}


WINDOWS = ["5m", "15m", "1h"]
templating = [
    {"name": "ds_prom", "label": "Datasource", "type": "datasource",
     "query": "prometheus", "hide": 0, "refresh": 1, "regex": "/^Prometheus$/"},
    node_var("a", "A (blue)", "beacon-eth4"),
    node_var("b", "B (orange)", "beacon-eth5"),
    {"name": "win", "label": "Rate window", "type": "custom", "query": ",".join(WINDOWS),
     "multi": False, "includeAll": False, "hide": 0,
     "current": {"selected": True, "text": "15m", "value": "15m"},
     "options": [{"selected": w == "15m", "text": w, "value": w} for w in WINDOWS]},
]

dashboard = {
    "uid": "ethlambda-ab",
    "title": "ethlambda A/B",
    "description": "Two ethlambda beacon nodes side by side: pick A and B (blue and orange "
                   "on every panel), read the B / A ratios first.",
    "tags": ["beacon", "mainnet", "ethlambda", "compare"],
    "schemaVersion": 39,
    "editable": False,
    "refresh": "1m",
    "time": {"from": "now-6h", "to": "now"},
    "timezone": "utc",
    "graphTooltip": 1,
    "templating": {"list": templating},
    "links": [
        {"title": "Beacon Follower", "type": "link", "icon": "dashboard",
         "url": "/d/beacon-follower", "keepTime": True, "targetBlank": False,
         "asDropdown": False, "includeVars": False, "tags": [], "tooltip": ""},
        {"title": "Actor runtime (spawned)", "type": "link", "icon": "dashboard",
         "url": "/d/spawned-actors", "keepTime": True, "targetBlank": False,
         "asDropdown": False, "includeVars": False, "tags": [], "tooltip": ""},
    ],
    "panels": panels,
}

# ethlambda's stage names before and after its rename (#917).
_gd.stage_names.apply(dashboard)
with open(sys.argv[1], "w") as f:
    json.dump(dashboard, f, indent=2)
    f.write("\n")
print(f"{len(panels)} panels")
