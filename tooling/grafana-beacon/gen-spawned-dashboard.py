#!/usr/bin/env python3
"""Generates the lean64 Grafana dashboard for spawned-concurrency's actor runtime metrics.

Usage: gen-spawned-dashboard.py <out.json>

spawned 0.6.0's `metrics` feature exports a fixed set of process-wide `spawned_*` series
(no per-actor or per-message labels: every series sums all actors in the process). Both
ethlambda (job "beacon", appended to its /metrics) and ethrex (job "ethrex") serve the same
names, so one dashboard covers both: the `client` variable picks ethlambda, ethrex or both
(mapped to the job), and `node` narrows within it. Nodes show up here as soon as they run a
build with the feature on.

The histograms are timed on a 1-in-N sample (`timing_sample_every`): ethlambda times every
message, ethrex one in 16. Quantiles and means are unaffected, but `rate(_sum)` is not, so
busy time and queue occupancy are derived as mean x throughput, which holds for any N.
Buckets are spawned's fixed powers of two from 1 us, so quantiles are good to about 2x.
`_max` is a lifetime maximum (never reset), shown as such.
"""

import json
import sys

DS = {"type": "prometheus", "uid": "${ds_prom}"}
# (name shown in the Client picker, Prometheus job its nodes are scraped under)
CLIENTS = [("ethlambda", "beacon"), ("ethrex", "ethrex")]
SEL ='job=~"$client", node=~"$node"'
W = "2m"  # rate window: 4 scrapes at the beacon/ethrex jobs' 30 s interval

panel_id = 0
panels = []


def next_id():
    global panel_id
    panel_id += 1
    return panel_id


def target(expr, legend="", instant=False, ref="A", fmt=None):
    t = {
        "refId": ref,
        "datasource": DS,
        "expr": expr,
        "legendFormat": legend,
        "editorMode": "code",
        "range": not instant,
        "instant": instant,
    }
    if fmt:
        t["format"] = fmt
    return t


def row(title, y, repeat=None):
    p = {
        "type": "row", "id": next_id(), "title": title, "collapsed": False,
        "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}, "panels": [],
    }
    if repeat:
        p["repeat"] = repeat
    panels.append(p)


def stat(title, expr, x, y, w=3, h=5, unit="none", steps=None, description="",
         decimals=None, legend="{{node}}"):
    defaults = {
        "unit": unit,
        "mappings": [], "noValue": "–",
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
            "colorMode": "value", "graphMode": "none", "textMode": "value_and_name",
            "justifyMode": "auto", "orientation": "horizontal",
        },
        "targets": [target(expr, legend, instant=True)],
    })


def series(title, targets, x, y, w=12, h=8, unit="none", description="", stepped=False,
           log=False, bars=False, interval=None, steps=None):
    custom = {"lineWidth": 1, "fillOpacity": 70 if bars else 10, "showPoints": "never",
              "spanNulls": False, "drawStyle": "bars" if bars else "line"}
    if stepped:
        custom["lineInterpolation"] = "stepAfter"
    if log:
        custom["scaleDistribution"] = {"type": "log", "log": 10}
    defaults = {"unit": unit, "custom": custom}
    if not log:
        defaults["min"] = 0
    if steps:
        custom["thresholdsStyle"] = {"mode": "line"}
        defaults["thresholds"] = {"mode": "absolute", "steps": steps}
    p = {
        "type": "timeseries", "id": next_id(), "title": title, "description": description,
        "datasource": DS, "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {"legend": {"displayMode": "table", "placement": "bottom",
                               "showLegend": True, "calcs": ["mean", "max", "lastNotNull"]},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
        "targets": [target(e, legend, ref=chr(ord("A") + i))
                    for i, (e, legend) in enumerate(targets)],
    }
    if interval:
        p["interval"] = interval
    panels.append(p)


def heatmap(title, metric, x, y, w=12, h=9, description=""):
    panels.append({
        "type": "heatmap", "id": next_id(), "title": title, "description": description,
        "datasource": DS, "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "interval": W,
        "fieldConfig": {"defaults": {"custom": {"scaleDistribution": {"type": "linear"}}},
                        "overrides": []},
        "options": {
            "calculate": False,
            "cellGap": 1,
            "color": {"mode": "scheme", "scheme": "Oranges", "scale": "exponential",
                      "exponent": 0.5, "steps": 64, "fill": "dark-orange", "reverse": False},
            "yAxis": {"axisPlacement": "left", "unit": "s", "reverse": False},
            "rowsFrame": {"layout": "auto"},
            "cellValues": {"unit": "short"},
            "filterValues": {"le": 1e-9},
            "tooltip": {"mode": "single", "yHistogram": True, "showColorScale": False},
            "legend": {"show": True},
            "exemplars": {"color": "rgba(255,0,255,0.7)"},
        },
        "targets": [target(
            f'sum by (le) (increase({metric}_bucket{{job=~"$client", node=~"$node"}}[$__interval]))',
            "{{le}}", fmt="heatmap")],
    })


def quantile(metric, q):
    return (f"histogram_quantile({q}, sum by (le, node) "
            f"(rate({metric}_bucket{{{SEL}}}[{W}]))) >= 0")


def mean(metric):
    return (f"sum by (node) (rate({metric}_sum{{{SEL}}}[{W}])) / "
            f"(sum by (node) (rate({metric}_count{{{SEL}}}[{W}])) > 0)")


def rate(metric):
    return f"sum by (node) (rate({metric}{{{SEL}}}[{W}]))"


def latency_targets(metric):
    return [(quantile(metric, 0.5), "{{node}} p50"),
            (quantile(metric, 0.99), "{{node}} p99"),
            (mean(metric), "{{node}} mean")]


HANDLED = "spawned_messages_handled_total"
QW = "spawned_queue_wait_seconds"
HD = "spawned_handler_duration_seconds"
RL = "spawned_request_latency_seconds"
# Mean x throughput (Little's law): correct whatever the timing sample rate is.
BUSY = f"({mean(HD)}) * {rate(HANDLED)}"
QUEUED = f"({mean(QW)}) * {rate(HANDLED)}"
PANICS = (f"sum by (node) (increase(spawned_handlers_panicked_total{{{SEL}}}[$__range])) + "
          f"sum by (node) (increase(spawned_actors_exited_panic_total{{{SEL}}}[$__range]))")
TIMEOUTS = f"sum by (node) (increase(spawned_requests_timed_out_total{{{SEL}}}[$__range]))"
RED_ABOVE_0 = [{"color": "green", "value": None}, {"color": "red", "value": 1}]
MAX_STEPS = [{"color": "green", "value": None}, {"color": "yellow", "value": 0.1},
             {"color": "red", "value": 1}]

y = 0
# --- Overview ----------------------------------------------------------------------------
row("Overview", y)
y += 1
stat("Messages handled/s", rate(HANDLED), 0, y, unit="ops", decimals=0,
     description="Messages taken off actor mailboxes per second, all actors in the process.")
stat("Actors alive", f"spawned_actors_active{{{SEL}}}", 3, y,
     description="Actors started and not yet exited.")
stat("Handler busy", BUSY, 6, y, unit="percentunit",
     description="Handler time per second of wall clock, summed over every actor: 100% is "
                 "one actor's worth of continuous work. Mean handler duration x messages "
                 "handled/s, so it holds for any timing sample rate.")
stat(f"Queue wait p99 ({W})", quantile(QW, 0.99), 9, y, unit="s",
     steps=[{"color": "green", "value": None}, {"color": "yellow", "value": 0.01},
            {"color": "red", "value": 0.1}],
     description="99th percentile of enqueue -> handler start. A message waiting here is "
                 "stuck behind its actor's other work.")
stat("Worst queue wait (since start)", f"{QW}_max{{{SEL}}}", 12, y, unit="s",
     steps=MAX_STEPS,
     description="spawned's lifetime maximum (never reset): the one place a rare stall too "
                 "short-lived for p99 shows up. Only timed messages count.")
stat("Worst handler (since start)", f"{HD}_max{{{SEL}}}", 15, y, unit="s", steps=MAX_STEPS,
     description="Longest single handler run since the process started (never reset).")
stat("Panics (range)", PANICS, 18, y, steps=RED_ABOVE_0, decimals=0,
     description="Handler panics plus actors that exited by panicking, over the dashboard's "
                 "time range.")
stat("Request timeouts (range)", TIMEOUTS, 21, y, steps=RED_ABOVE_0, decimals=0,
     description="`call`s that hit their timeout, over the dashboard's time range. ethlambda "
                 "makes no `call`s, so it reads 0.")
y += 5

# --- Latency -----------------------------------------------------------------------------
row("Latency (power-of-two buckets from 1 µs: quantiles are good to about 2x)", y)
y += 1
series("Queue wait", latency_targets(QW), 0, y, w=8, h=9, unit="s", log=True,
       description="Enqueue to handler start: the time a message spent behind its actor's "
                   "other work. A rising p99 here with handler duration steady means a "
                   "mailbox is backing up.")
series("Handler duration", latency_targets(HD), 8, y, w=8, h=9, unit="s", log=True,
       description="Handler dispatch to completion, awaited time included.")
series("Request latency (call)", latency_targets(RL), 16, y, w=8, h=9, unit="s", log=True,
       description="Caller-side `call` lifetime to reply, timeout or actor stop. ethlambda's "
                   "actors are driven by `send` only, so it has no series here.")
y += 9
series("Lifetime maxima (each step is a new record)",
       [(f"{QW}_max{{{SEL}}}", "{{node}} queue wait"),
        (f"{HD}_max{{{SEL}}}", "{{node}} handler"),
        (f"{RL}_max{{{SEL}}}", "{{node}} request")],
       0, y, w=24, h=8, unit="s", stepped=True, log=True,
       description="spawned's `_max` series are process-lifetime maxima, never reset, so "
                   "this is a staircase: a step marks when a new worst case happened. They "
                   "fall back only on restart.")
y += 8

# --- Throughput & backlog ----------------------------------------------------------------
row("Throughput and backlog", y)
y += 1
series("Messages enqueued and handled",
       [(rate("spawned_messages_enqueued_total"), "{{node}} enqueued"),
        (rate(HANDLED), "{{node}} handled"),
        (rate("spawned_handlers_completed_total"), "{{node}} handlers completed")],
       0, y, unit="ops", log=True,
       description="Accepted sends, handler starts and handlers that ran to completion, per "
                   "second. On a healthy node the three lines lie on top of each other; a gap "
                   "between them is a backlog building or handlers failing. Log scale: ethrex "
                   "handles an order of magnitude more than ethlambda.")
series("Handler busy time", [(BUSY, "{{node}}")], 12, y, unit="percentunit",
       description="Handler time per second of wall clock, summed over every actor (100% is "
                   "one actor busy full-time). Mean handler duration x messages handled/s.")
y += 8
series("Mailbox backlog",
       [(QUEUED, "{{node}} avg queued (Little's law)"),
        (f"spawned_mailbox_depth{{{SEL}}}", "{{node}} depth at scrape")],
       0, y, unit="short",
       description="Average messages waiting, as mean queue wait x messages handled/s, next "
                   "to the mailbox-depth gauge. The gauge is a point sample every 30 s and "
                   "nearly always reads 0; the average and the queue-wait quantiles are the "
                   "real backlog signal.")
series("In flight at scrape",
       [(f"spawned_handlers_active{{{SEL}}}", "{{node}} handlers running"),
        (f"spawned_requests_active{{{SEL}}}", "{{node}} calls awaiting reply")],
       12, y, unit="short", stepped=True,
       description="Point-sampled gauges: handlers mid-run and `call`s not yet resolved at "
                   "the moment of the scrape.")
y += 8

# --- Requests ----------------------------------------------------------------------------
row("Requests (call) and replies", y)
y += 1
series("Calls",
       [(rate("spawned_requests_started_total"), "{{node}} started"),
        (rate("spawned_requests_replied_total"), "{{node}} replied"),
        (rate("spawned_replies_sent_total"), "{{node}} replies sent")],
       0, y, unit="ops",
       description="`call`s started and answered, and replies the actors sent (a reply can "
                   "also answer a raw receiver, so the two can differ).")
series("Calls not answered",
       [(f"sum by (node) (increase(spawned_requests_timed_out_total{{{SEL}}}[$__interval]))",
         "{{node}} timed out"),
        (f"sum by (node) (increase(spawned_requests_actor_stopped_total{{{SEL}}}[$__interval]))",
         "{{node}} actor stopped"),
        (f"sum by (node) (increase(spawned_requests_cancelled_total{{{SEL}}}[$__interval]))",
         "{{node}} cancelled"),
        (f"sum by (node) (increase(spawned_reply_receivers_dropped_total{{{SEL}}}[$__interval]))",
         "{{node}} reply receiver dropped")],
       12, y, bars=True, interval=W,
       description="Events per bar (2 min). Timed out: no reply before the call's timeout. "
                   "Actor stopped: the actor exited first. Cancelled: the caller's future was "
                   "dropped. Reply receiver dropped: the actor replied to nobody.")
y += 8

# --- Failures & lifecycle ----------------------------------------------------------------
row("Failures and actor lifecycle", y)
y += 1
series("Handler and delivery failures",
       [(f"sum by (node) (increase(spawned_handlers_panicked_total{{{SEL}}}[$__interval]))",
         "{{node}} handler panicked"),
        (f"sum by (node) (increase(spawned_handlers_aborted_total{{{SEL}}}[$__interval]))",
         "{{node}} handler aborted"),
        (f"sum by (node) (increase(spawned_messages_rejected_total{{{SEL}}}[$__interval]))",
         "{{node}} send rejected"),
        (f"sum by (node) (increase(spawned_messages_discarded_total{{{SEL}}}[$__interval]))",
         "{{node}} discarded at stop")],
       0, y, w=8, bars=True, interval=W,
       description="Events per bar (2 min). Aborted: the handler future was dropped before "
                   "finishing. Rejected: a send to an actor that had already stopped. "
                   "Discarded: still queued when its actor stopped.")
series("Actors alive", [(f"spawned_actors_active{{{SEL}}}", "{{node}}")], 8, y, w=8,
       unit="short", stepped=True)
series("Actor starts and exits",
       [(f"sum by (node) (increase(spawned_actors_spawned_total{{{SEL}}}[$__interval]))",
         "{{node}} spawned"),
        (f"sum by (node) (increase(spawned_actors_exited_normal_total{{{SEL}}}[$__interval]))",
         "{{node}} exit normal"),
        (f"sum by (node) (increase(spawned_actors_exited_shutdown_total{{{SEL}}}[$__interval]))",
         "{{node}} exit shutdown"),
        (f"sum by (node) (increase(spawned_actors_exited_panic_total{{{SEL}}}[$__interval]))",
         "{{node}} exit panic"),
        (f"sum by (node) (increase(spawned_actors_exited_kill_total{{{SEL}}}[$__interval]))",
         "{{node}} exit kill")],
       16, y, w=8, bars=True, interval=W,
       description="Events per bar (2 min). ethrex starts and stops short-lived actors "
                   "continuously; ethlambda spawns its two at startup and nothing after.")
y += 8

# --- Distributions, one row per node -----------------------------------------------------
row("Distribution: $node", y, repeat="node")
y += 1
stat("Timing sample: 1 in N",
     f"{rate(HANDLED)} / (sum by (node) (rate({QW}_count{{{SEL}}}[{W}])) > 0)", 0, y, w=4, h=9,
     decimals=0,
     steps=[{"color": "blue", "value": None}],
     description="Messages handled per message timed: spawned's `timing_sample_every`, "
                 "which it does not export, recovered from its counters. 1 means every "
                 "message is timed (ethlambda); ethrex runs 16. The latency quantiles and "
                 "means do not depend on it; a sum of timings would be N times too small.")
heatmap("Queue wait distribution", QW, 4, y, w=10,
        description="Timed messages per bucket per 2 min (see the timing sample).")
heatmap("Handler duration distribution", HD, 14, y, w=10,
        description="Timed handler runs per bucket per 2 min (see the timing sample).")
y += 9

templating = [
    {"name": "ds_prom", "label": "Datasource", "type": "datasource",
     "query": "prometheus", "hide": 0, "refresh": 1, "regex": "/^Prometheus$/"},
    # The client picker: each client's name stands for the Prometheus job its nodes are
    # scraped under (ethlambda's beacon followers are job "beacon"). Multi-select so the two
    # can be compared; ethlambda alone by default, since ethrex's ~15x message rate and ~50x
    # actor count flatten ethlambda's lines on a shared axis.
    {"name": "client", "label": "Client", "type": "custom",
     "query": ", ".join(f"{text} : {job}" for text, job in CLIENTS),
     "multi": True, "includeAll": True, "allValue": "|".join(job for _, job in CLIENTS),
     "hide": 0,
     "current": {"selected": True, "text": [CLIENTS[0][0]], "value": [CLIENTS[0][1]]},
     "options": [{"selected": i == 0, "text": text, "value": job}
                 for i, (text, job) in enumerate(CLIENTS)]},
    {"name": "node", "label": "Node", "type": "query", "datasource": DS,
     "definition": 'label_values(spawned_actors_active{job=~"$client"}, node)',
     "query": {"qryType": 1,
               "query": 'label_values(spawned_actors_active{job=~"$client"}, node)',
               "refId": "node-query"},
     "refresh": 2, "sort": 1, "multi": True, "includeAll": True, "hide": 0,
     "current": {"selected": True, "text": ["All"], "value": ["$__all"]}, "options": []},
]

dashboard = {
    "uid": "spawned-actors",
    "title": "Actor runtime (spawned)",
    "description": "spawned-concurrency's process-wide actor metrics (mailboxes, queue wait, "
                   "handler time, calls, lifecycle) for every ethlambda and ethrex node that "
                   "exports them. No per-actor labels: each series sums the whole process.",
    "tags": ["beacon", "ethrex", "mainnet", "spawned"],
    "schemaVersion": 39,
    "editable": False,
    "refresh": "30s",
    "time": {"from": "now-3h", "to": "now"},
    "timezone": "utc",
    "templating": {"list": templating},
    "links": [
        {"title": "Beacon Follower", "type": "link", "icon": "dashboard",
         "url": "/d/beacon-follower", "keepTime": True, "targetBlank": False,
         "asDropdown": False, "includeVars": False, "tags": [], "tooltip": ""},
        {"title": "Ethrex L1", "type": "link", "icon": "dashboard",
         "url": "/d/ethrex-l1", "keepTime": True, "targetBlank": False,
         "asDropdown": False, "includeVars": False, "tags": [], "tooltip": ""},
    ],
    "panels": panels,
}

with open(sys.argv[1], "w") as f:
    json.dump(dashboard, f, indent=2)
    f.write("\n")
print(f"{len(panels)} panels")
