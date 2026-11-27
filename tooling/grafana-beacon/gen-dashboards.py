#!/usr/bin/env python3
"""Build the Beacon Follower additions and the Ethrex L1 dashboard.

Usage: gen.py <beacon-follower.json in> <ethrex_dashboard.json in> <out dir>

Idempotent: rows this script owns are dropped from the beacon dashboard before
being rebuilt, so re-running it on its own output gives the same result.
"""
import copy
import json
import re
import sys

import stage_names

ETHREX_UID = "ethrex-l1"
BEACON_UID = "beacon-follower"

# ---------------------------------------------------------------- helpers


def target(ds, expr, legend, ref):
    return {
        "refId": ref,
        "datasource": ds,
        "expr": expr,
        "legendFormat": legend,
        "editorMode": "code",
        "range": True,
    }


def timeseries(ds, title, description, exprs, unit, *, w=12, h=7, stack=None,
               fill=0, repeat=None, overrides=None, minv=None, maxv=None,
               step=False, no_value=None, threshold=None):
    custom = {
        "drawStyle": "line",
        "lineWidth": 1,
        "fillOpacity": fill if not stack else 60,
        "showPoints": "never",
        "spanNulls": True,
        "thresholdsStyle": {"mode": "off"},
    }
    if stack:
        custom["stacking"] = {"group": "A", "mode": stack}
    if step:
        custom["lineInterpolation"] = "stepAfter"
    steps = [{"color": "text", "value": None}]
    if threshold is not None:
        steps.append({"color": "red", "value": threshold})
        custom["thresholdsStyle"] = {"mode": "dashed"}
    defaults = {
        "unit": unit,
        "custom": custom,
        "thresholds": {"mode": "absolute", "steps": steps},
        "color": {"mode": "palette-classic"},
    }
    if minv is None and stack:
        minv = 0
    if minv is not None:
        defaults["min"] = minv
    if maxv is not None:
        defaults["max"] = maxv
    if no_value:
        defaults["noValue"] = no_value
    panel = {
        "type": "timeseries",
        "title": title,
        "description": description,
        "datasource": ds,
        "gridPos": {"h": h, "w": w, "x": 0, "y": 0},
        "fieldConfig": {"defaults": defaults, "overrides": overrides or []},
        "options": {
            "legend": {"displayMode": "list", "placement": "bottom",
                       "showLegend": True, "calcs": []},
            "tooltip": {"mode": "multi", "sort": "desc"},
        },
        "targets": [target(ds, e, l, chr(ord("A") + i))
                    for i, (e, l) in enumerate(exprs)],
    }
    if repeat:
        panel.update({"repeat": repeat, "repeatDirection": "h",
                      "maxPerRow": 3})
        panel["gridPos"]["w"] = 24
    return panel


def unstacked_line(matcher_id, pattern, color=None, dashed=False):
    """Override that pulls matching series out of a stack as a plain line."""
    props = [
        {"id": "custom.stacking", "value": {"group": "A", "mode": "none"}},
        {"id": "custom.fillOpacity", "value": 0},
        {"id": "custom.lineWidth", "value": 2},
    ]
    if dashed:
        props.append({"id": "custom.lineStyle",
                      "value": {"fill": "dash", "dash": [10, 10]}})
    if color:
        props.append({"id": "color",
                      "value": {"mode": "fixed", "fixedColor": color}})
    return {"matcher": {"id": matcher_id, "options": pattern},
            "properties": props}


def row(title, panels, next_id, y):
    """A collapsed row holding `panels`, laid out left to right from y + 1."""
    x, cy, line_h = 0, y + 1, 0
    for p in panels:
        w, h = p["gridPos"]["w"], p["gridPos"]["h"]
        if x + w > 24:
            x, cy, line_h = 0, cy + line_h, 0
        p["gridPos"].update({"x": x, "y": cy})
        p["id"] = next_id()
        x += w
        line_h = max(line_h, h)
    return {"type": "row", "title": title, "collapsed": True,
            "gridPos": {"h": 1, "w": 24, "x": 0, "y": y},
            "id": next_id(), "panels": panels}


def id_allocator(doc):
    used = set()

    def walk(ps):
        for p in ps:
            if "id" in p:
                used.add(p["id"])
            walk(p.get("panels", []))
    walk(doc["panels"])
    counter = [max(used, default=0)]

    def nxt():
        counter[0] += 1
        return counter[0]
    return nxt


def hist(metric, sel, q, by="node"):
    return (f"histogram_quantile({q}, sum by ({by}, le) "
            f"(rate({metric}_bucket{{{sel}}}[5m])))")


def mean(metric, sel, by="node", window="5m"):
    return (f"sum by ({by}) (rate({metric}_sum{{{sel}}}[{window}])) / "
            f"sum by ({by}) (rate({metric}_count{{{sel}}}[{window}]))")


def ratio(metric, sel, num, by="node", window="30m"):
    return (f"sum by ({by}) (rate({metric}{{{sel}, {num}}}[{window}])) / "
            f"sum by ({by}) (rate({metric}{{{sel}}}[{window}]))")


# ------------------------------------------------------- beacon dashboard

DS = {"type": "prometheus", "uid": "${ds_prom}"}
B = 'job="beacon", node=~"$node"'
EL = 'job="ethrex", node=~"ethrex-(${el:pipe})"'
HOST = 'job="node", node=~"host-(${host:pipe})"'
NOT_DEPLOYED = "Not exported by the running build"
NONE_IN_RANGE = "None in this time range"


def beacon_rows():
    """(title, panels) for every row this script adds, in display order."""
    ts = lambda *a, **k: timeseries(DS, *a, **k)  # noqa: E731
    rows = []

    rows.append(("Gossip validation", [
        ts("Gossip verdicts by outcome: $node",
           "Every beacon gossip message gets one verdict. `queue` hands the "
           "message to the chain actor for a later verdict. The dashed line "
           "counts verdicts reported after gossipsub had already evicted the "
           "message, which means validation took longer than the cache "
           "window (only builds from main export it).",
           [(f"sum by (outcome) (rate(lean_beacon_gossip_validation_total{{{B}}}[5m]))",
             "{{outcome}}"),
            (f"sum(rate(lean_beacon_gossip_verdict_expired_total{{{B}}}[5m]))",
             "verdict after eviction")],
           "suffix: msg/s", stack="normal", repeat="node",
           overrides=[unstacked_line("byName", "verdict after eviction",
                                     "red", dashed=True)]),
        ts("Rejects by topic and reason: $node",
           "Rejected messages penalize the sender's gossipsub score. A "
           "steady reject rate on one topic usually means a rule disagrees "
           "with other clients.",
           [(f"sum by (kind, reason) (rate(lean_beacon_gossip_validation_total{{{B}, outcome=\"reject\"}}[5m])) > 0",
             "{{kind}}: {{reason}}")],
           "suffix: msg/s", no_value=NONE_IN_RANGE, repeat="node"),
        ts("Ignores by topic and reason, duplicates excluded: $node",
           "Ignored messages are dropped without a penalty. `already_seen` "
           "and `already_stored` are left out because duplicates dominate "
           "and are expected.",
           [(f"sum by (kind, reason) (rate(lean_beacon_gossip_validation_total{{{B}, outcome=\"ignore\", reason!~\"already_seen|already_stored\"}}[5m])) > 0",
             "{{kind}}: {{reason}}")],
           "suffix: msg/s", no_value=NONE_IN_RANGE, repeat="node"),
        ts("Validation latency p99 by topic: $node",
           "Time from a message's arrival to its verdict. Gossipsub evicts "
           "an unvalidated message from its cache after about 4.2 s "
           "(dashed line), so a verdict later than that is lost.",
           [(hist("lean_beacon_gossip_validation_seconds", B, 0.99, "kind"),
             "{{kind}}")],
           "s", repeat="node", threshold=4.2),
        ts("Messages received by topic: $node",
           "Messages that decoded, stacked by topic. Lines are messages "
           "dropped before validation, by cause.",
           [(f"sum by (topic) (rate(lean_beacon_gossip_messages_total{{{B}, result=\"decoded\"}}[5m]))",
             "{{topic}}"),
            (f"sum by (result) (rate(lean_beacon_gossip_messages_total{{{B}, result!=\"decoded\"}}[5m])) > 0",
             "dropped: {{result}}")],
           "suffix: msg/s", stack="normal", repeat="node",
           overrides=[unstacked_line("byRegexp", "/^dropped/", dashed=True)]),
    ]))

    rows.append(("Attestation aggregates", [
        ts("Aggregates applied, share of all received",
           "Share of gossip aggregates that reached fork choice. The rest "
           "were invalid or added no new attesters (`known_subset`).",
           [(ratio("lean_beacon_aggregate_total", B, 'outcome="applied"'),
             "{{node}}")],
           "percentunit", minv=0, maxv=1),
        ts("Aggregates held for their own slot",
           "Aggregates that arrived early and wait until their slot has "
           "passed before fork choice may apply them.",
           [(f"lean_beacon_aggregates_deferred{{{B}}}", "{{node}}")],
           "none"),
        ts("Aggregate end to end, arrival to fork choice",
           "Time from an aggregate arriving on the wire to it reaching fork "
           "choice.",
           [(hist("lean_beacon_aggregate_end_to_end_seconds", B, 0.99), "{{node}} p99"),
            (hist("lean_beacon_aggregate_end_to_end_seconds", B, 0.5), "{{node}} p50")],
           "s", w=24),
        ts("Aggregate outcomes: $node",
           "What happened to each gossip aggregate the chain actor handled.",
           [(f"sum by (outcome) (rate(lean_beacon_aggregate_total{{{B}}}[5m]))",
             "{{outcome}}")],
           "suffix: agg/s", stack="normal", repeat="node"),
        ts("Aggregate stage time, mean: $node",
           "Mean time per stage. Decoding runs once per received copy, the "
           "other stages once per aggregate the actor handles, so the stages "
           "do not add up to the end-to-end line.",
           [(mean("lean_beacon_aggregate_decode_seconds", B, by=""), "decode"),
            (mean("lean_beacon_aggregate_mailbox_wait_seconds", B, by=""), "mailbox wait"),
            (mean("lean_beacon_aggregate_processing_seconds", B, by=""), "processing"),
            (mean("lean_beacon_aggregate_end_to_end_seconds", B, by=""), "end to end")],
           "s", repeat="node"),
    ]))

    cache = lambda m, name: (ratio(m, B, 'result!="hit"', by=""), name)  # noqa: E731
    rows.append(("Epoch processing and caches", [
        ts("Epoch precompute time",
           "Time one epoch precompute worker takes.",
           [(hist("lean_beacon_epoch_precompute_seconds", B, 0.99), "{{node}} p99"),
            (mean("lean_beacon_epoch_precompute_seconds", B), "{{node}} mean")],
           "s"),
        ts("Justified balances build time",
           "Time to build the justified checkpoint's balances that fork "
           "choice weighs votes with.",
           [(hist("lean_beacon_justified_balances_build_seconds", B, 0.99), "{{node}} p99"),
            (mean("lean_beacon_justified_balances_build_seconds", B), "{{node}} mean")],
           "s"),
        ts("Epoch precompute workers started, per hour",
           "Workers started by what triggered them. `timer` starts ahead of "
           "the epoch boundary; `head` starts when a head change needs one.",
           [(f"sum by (node, trigger) (increase(lean_beacon_epoch_precompute_started_total{{{B}}}[1h]))",
             "{{node}} {{trigger}}")],
           "none"),
        ts("Validated BLS pubkeys cached",
           "Entries in the process-wide pubkey cache.",
           [(f"lean_beacon_pubkey_cache_entries{{{B}}}", "{{node}}")],
           "short"),
        ts("Cache miss ratio: $node",
           "Misses over all lookups, 30 min window. For the committee cache "
           "an `unkeyable` lookup counts as a miss.",
           [cache("lean_beacon_pubkey_cache_lookups_total", "pubkey"),
            cache("lean_beacon_committee_cache_lookups_total", "committee"),
            cache("lean_beacon_epoch_precompute_lookups_total", "epoch precompute"),
            cache("lean_beacon_justified_balances_lookups_total", "justified balances"),
            cache("lean_beacon_total_active_balance_lookups_total", "total active balance")],
           "percentunit", minv=0, repeat="node"),
        ts("State cache miss ratio by lookup: $node",
           "Misses over all lookups for each storage method and state kind, "
           "30 min window. A miss on `get_state` rebuilds a state from a "
           "snapshot and diffs.",
           [(ratio("lean_state_cache_lookups_total", B, 'result="miss"', by="kind, method"),
             "{{method}} ({{kind}})")],
           "percentunit", minv=0, repeat="node"),
    ]))

    rows.append(("Data availability", [
        ts("Columns stored and rejected",
           "Data column sidecars verified and written, against those "
           "rejected for any reason.",
           [(f"sum by (node) (rate(lean_data_columns_stored_total{{{B}}}[5m]))", "{{node}} stored"),
            (f"sum by (node) (rate(lean_data_columns_rejected_total{{{B}}}[5m]))", "{{node}} rejected")],
           "suffix: col/s"),
        ts("KZG batch verification, per sidecar",
           "Time to batch-verify one sidecar's cells against its "
           "commitments.",
           [(hist("lean_data_column_kzg_verify_seconds", B, 0.99), "{{node}} p99"),
            (hist("lean_data_column_kzg_verify_seconds", B, 0.5), "{{node}} p50")],
           "s"),
        ts("Blocks and sidecars on hold",
           "Blocks waiting for their custody columns, and unverified "
           "sidecars parked until their block's parent has a post-state.",
           [(f"lean_blocks_held_for_columns{{{B}}}", "{{node}} blocks held for columns"),
            (f"lean_sidecars_awaiting_parent{{{B}}}", "{{node}} sidecars awaiting parent")],
           "none"),
        ts("Gloas payload holds",
           "Blocks waiting for their FULL parent's payload envelope, and "
           "envelopes waiting for their block or their custody columns. "
           "Zero before the Gloas fork.",
           [(f"lean_blocks_awaiting_parent_payload{{{B}}}", "{{node}} blocks awaiting parent payload"),
            (f"lean_envelopes_awaiting_block{{{B}}}", "{{node}} envelopes awaiting block"),
            (f"lean_envelopes_awaiting_columns{{{B}}}", "{{node}} envelopes awaiting columns")],
           "none"),
        ts("Column rejects by reason: $node",
           "Rejected sidecars by reason. Dashed lines are column lookups "
           "abandoned (only builds from main export them).",
           [(f"sum by (reason) (rate(lean_data_columns_rejected_total{{{B}}}[5m])) > 0",
             "{{reason}}"),
            (f"sum by (reason) (rate(lean_data_column_fetch_failures_total{{{B}}}[5m])) > 0",
             "fetch abandoned: {{reason}}")],
           "suffix: col/s", no_value=NONE_IN_RANGE, repeat="node",
           overrides=[unstacked_line("byRegexp", "/^fetch abandoned/", dashed=True)]),
    ]))

    rows.append(("Block arrival and req/resp", [
        ts("Gossip block arrival delay",
           "Absolute delay between a gossip block's arrival and the start "
           "of the slot it was due in.",
           [(hist("lean_gossip_block_arrival_delay_seconds", B, 0.99), "{{node}} p99"),
            (hist("lean_gossip_block_arrival_delay_seconds", B, 0.5), "{{node}} p50")],
           "s"),
        ts("Gossip blocks arriving outside their slot",
           "Share of gossip blocks that arrived after their slot ended or "
           "before it started, 30 min window.",
           [(ratio("lean_gossip_block_arrival_total", B, 'position="after"'), "{{node}} after"),
            (ratio("lean_gossip_block_arrival_total", B, 'position="before"'), "{{node}} before")],
           "percentunit", minv=0),
        ts("Req/resp requests by protocol: $node",
           "Requests sent and received together (the metric has no "
           "direction label).",
           [(f"sum by (protocol) (rate(lean_reqresp_request_size_bytes_count{{{B}, compression=\"snappy\"}}[5m]))",
             "{{protocol}}")],
           "reqps", stack="normal", repeat="node"),
        ts("Req/resp response bytes by protocol: $node",
           "Snappy-compressed response bytes, sent and received together.",
           [(f"sum by (protocol) (rate(lean_reqresp_response_chunk_size_bytes_sum{{{B}, compression=\"snappy\"}}[5m]))",
             "{{protocol}}")],
           "Bps", stack="normal", repeat="node"),
    ]))

    rows.append(("Peer scoring and discovery", [
        ts("Gossipsub mesh delivery scoring",
           "1 while gossipsub scores mesh message deliveries; 0 while the "
           "head lags or scoring is warming up.",
           [(f"lean_gossipsub_mesh_delivery_scoring{{{B}}}", "{{node}}")],
           "none", minv=0, maxv=1, step=True),
        ts("Score disconnects and Status digest mismatches, per minute",
           "Peers dropped for a gossipsub score below the graylist "
           "threshold, and Status requests carrying a fork digest that is "
           "not ours.",
           [(f"sum by (node) (rate(lean_gossipsub_score_disconnects_total{{{B}}}[5m])) * 60",
             "{{node}} score disconnect"),
            (f"sum by (node) (rate(lean_beacon_status_digest_mismatch_total{{{B}}}[5m])) * 60",
             "{{node}} digest mismatch")],
           "none"),
        ts("Discovery dials per minute",
           "Peers dialed because discv5 found them.",
           [(f"sum by (node) (rate(lean_discovered_peers_dialed_total{{{B}}}[5m])) * 60",
             "{{node}}")],
           "none"),
        ts("QUIC share of new connections",
           "Connections established over QUIC as a share of all, 30 min "
           "window. The rest fell back to TCP.",
           [(ratio("lean_peer_connections_by_transport_total", B, 'transport="quic"'),
             "{{node}}")],
           "percentunit", minv=0, maxv=1),
        ts("Peers by gossipsub score band: $node",
           "Connected peers per score band. Bands are thresholds, so a peer "
           "below the graylist threshold is also below the others.",
           [(f"sum by (band) (lean_gossipsub_peers_by_score{{{B}}})", "{{band}}")],
           "none", repeat="node"),
        ts("Connection attempts by result, per minute: $node",
           "Inbound and outbound connection attempts by how they ended.",
           [(f"sum by (direction, result) (rate(lean_peer_connection_events_total{{{B}}}[5m])) * 60",
             "{{direction}} {{result}}")],
           "none", repeat="node"),
    ]))

    rows.append(("Storage and process", [
        ts("Database size by table: $node",
           "Key plus value bytes per storage table.",
           [(f"sum by (table) (lean_table_bytes{{{B}}})", "{{table}}")],
           "bytes", stack="normal", repeat="node"),
        ts("Database growth over the previous 24 h",
           "All tables' bytes now minus 24 h ago. A restart onto a fresh "
           "data directory shows as a drop.",
           [(f"sum by (node) (lean_table_bytes{{{B}}}) - sum by (node) (lean_table_bytes{{{B}}} offset 1d)",
             "{{node}}")],
           "bytes"),
        ts("Host filesystem used",
           "Used share of each ext4 filesystem, computed like df's Use%. "
           "The host-disk-full alert fires at 95 % (dashed line).",
           [(f"100 * (node_filesystem_size_bytes{{{HOST}, fstype=\"ext4\"}} - node_filesystem_free_bytes{{{HOST}, fstype=\"ext4\"}}) / "
             f"(node_filesystem_size_bytes{{{HOST}, fstype=\"ext4\"}} - node_filesystem_free_bytes{{{HOST}, fstype=\"ext4\"}} + node_filesystem_avail_bytes{{{HOST}, fstype=\"ext4\"}})",
             "{{node}} {{mountpoint}}")],
           "percent", minv=0, maxv=100, threshold=95),
        ts("State writer, time per state",
           "Time the background writer spends encoding, diffing and "
           "committing one state.",
           [(hist("lean_state_write_seconds", B, 0.99), "{{node}} p99"),
            (hist("lean_state_write_seconds", B, 0.5), "{{node}} p50")],
           "s"),
        ts("State writer queue depth",
           "States handed to the background writer and not yet committed. "
           "A climbing value means the writer cannot keep up.",
           [(f"lean_state_write_queue_depth{{{B}}}", "{{node}}")],
           "none"),
        ts("Resident memory",
           "Process RSS. beacon-eth5 embeds ethrex, so its process includes "
           "the execution client.",
           [(f"process_resident_memory_bytes{{{B}}}", "{{node}}")],
           "bytes"),
        ts("CPU, cores used",
           "Process CPU time per second.",
           [(f"rate(process_cpu_seconds_total{{{B}}}[5m])", "{{node}}")],
           "none"),
        ts("Open file descriptors, share of limit",
           "Open descriptors over the process limit.",
           [(f"process_open_fds{{{B}}} / process_max_fds{{{B}}}", "{{node}}")],
           "percentunit", minv=0),
        ts("Threads",
           "OS threads in the process.",
           [(f"process_threads{{{B}}}", "{{node}}")],
           "none"),
    ]))

    engine = lambda method: (  # noqa: E731
        f"sum by (node) (rate(rpc_request_duration_seconds_sum{{{EL}, namespace=\"engine\", method=~\"{method}\"}}[5m])) / "
        f"sum by (node) (rate(rpc_request_duration_seconds_count{{{EL}, namespace=\"engine\", method=~\"{method}\"}}[5m]))")
    new_payload = f'{B}, outcome!="no_verdict"'
    rows.append(("Execution layer (ethrex)", [
        ts("Engine newPayload latency, mean",
           "Mean time the paired ethrex takes to answer `engine_newPayload*`, "
           "which block import waits on. Full EL view: "
           f"[Ethrex L1](/d/{ETHREX_UID}).",
           [(engine("engine_newPayload.*"), "{{node}}")], "s"),
        ts("Engine newPayload as the beacon node timed it",
           "Time from the beacon node sending `engine_newPayload` to the "
           "answer, retry ladder included (`lean_engine_new_payload_seconds`): "
           "a block's payload before gloas, an envelope's from gloas on. The "
           "import runs the state transition meanwhile, so this is not what "
           "the import waited (that is the `engine` section under Block "
           "import). Answers only: `no_verdict` is left out.",
           [(hist("lean_engine_new_payload_seconds", new_payload, 0.5), "{{node}} p50"),
            (hist("lean_engine_new_payload_seconds", new_payload, 0.9), "{{node}} p90"),
            (hist("lean_engine_new_payload_seconds", new_payload, 0.99), "{{node}} p99"),
            (mean("lean_engine_new_payload_seconds", new_payload), "{{node}} mean")],
           "s", no_value=NOT_DEPLOYED),
        ts("Engine forkchoiceUpdated latency, mean",
           "Mean time the paired ethrex takes to answer "
           "`engine_forkchoiceUpdated*`.",
           [(engine("engine_forkchoiceUpdated.*"), "{{node}}")], "s"),
        ts("EL execution throughput",
           "Gas per second of the last block ethrex executed.",
           [(f"gigagas{{{EL}}}", "{{node}}")], "suffix: Ggas/s"),
        ts("EL peers",
           "Execution-layer devp2p peers.",
           [(f"ethrex_p2p_peer_count{{{EL}}}", "{{node}}")], "none"),
        ts("EL datadir size",
           "Bytes the ethrex data directory uses.",
           [(f"datadir_size_bytes{{{EL}}}", "{{node}}")], "bytes"),
        ts("Blocks the execution client did not clear, per hour",
           "Blocks not imported because ethrex gave no verdict, or because "
           "they were not optimistic-import candidates.",
           [(f"sum by (node) (increase(lean_engine_no_verdict_total{{{B}}}[1h]))",
             "{{node}} no verdict"),
            (f"sum by (node) (increase(lean_engine_not_optimistic_candidate_total{{{B}}}[1h]))",
             "{{node}} not an optimistic candidate")],
           "none", no_value=NOT_DEPLOYED),
    ]))
    rows.append(clickhouse_row())
    return rows


# ------------------------------------------- per-block timings (ClickHouse)

# ethlambda's block telemetry (`--telemetry.clickhouse-url`, docs/telemetry.md)
# goes into a `block_events` table in Silver's layout on eth-4's own ClickHouse
# (container ethlambda-clickhouse, ~/ethlambda-clickhouse), datasource uid
# ethlambda-ch. A node writes its rows under `--telemetry.client-name`, set to
# its Prometheus `node` label (beacon-eth4, ...), which the `client` variable
# lists. Silver's rows stay in eth-5's ClickHouse (uid silver-ch), so the
# comparison panels mix the two datasources.
CH = {"type": "grafana-clickhouse-datasource", "uid": "ethlambda-ch"}
SILVER_CH = {"type": "grafana-clickhouse-datasource", "uid": "silver-ch"}
MIXED = {"type": "datasource", "uid": "-- Mixed --"}
# Silver's own rows (meta_client_name is its hostname), for the comparisons.
SILVER_CLIENT = "ethlambda-5"
CH_NS = "(toUnixTimestamp64Nano({b}) - toUnixTimestamp64Nano({a})) / 1e6"
CH_CLIENT = "meta_client_name = '${client}'"
CH_SILVER = f"meta_client_name = '{SILVER_CLIENT}'"
CH_DOC = (
    "Per-block timings the node wrote to ClickHouse (`--telemetry.clickhouse-url`, "
    "Silver's `block_events` layout, ClickHouse on eth-4). Steps, in order, adding up to arrival -> "
    "attestable: **before the STF** (decode, actor queue, admission and checks), **wait "
    "for columns** (held until its custody columns arrived), **STF + EL** "
    "(`engine_newPayload` and the speculative state transition run side by side, then the "
    "import that uses the verdict), **head** (block attestations, then the head "
    "recomputation that makes the block attestable). Failed blocks and blocks still held "
    "have no row. Pick the node with the `ClickHouse node` variable.")


def ch_blocks(client_filter):
    """One row per block, with the steps that add up to arrival -> attestable.

    Rows are read a minute beyond the range so blocks at its edges are whole,
    and each stage takes its earliest row: delivery is at least once. Works on
    Silver's rows too (received, el_sent, el_verdict, stf_done, attestable).
    """
    ns = CH_NS.format
    return f"""(
  SELECT
    received, slot, source, verdict, block_root, arrival_ms, attestable_ms,
    {ns(a="received", b="exec_start")} - columns_wait_ms AS before_ms,
    columns_wait_ms,
    {ns(a="exec_start", b="stf_done")} AS exec_ms,
    {ns(a="stf_done", b="attestable")} AS head_ms,
    {ns(a="received", b="attestable")} AS total_ms,
    {ns(a="el_sent", b="el_verdict_at")} AS el_ms,
    {ns(a="stf_spec_start", b="stf_spec_end")} AS stf_spec_ms,
    {ns(a="stf_start", b="stf_done")} AS stf_ms,
    {ns(a="get_head_start", b="get_head_end")} AS get_head_ms
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
      minIfOrNull(event_date_time, stage = 'stf_spec_start') AS stf_spec_start,
      minIfOrNull(event_date_time, stage = 'stf_spec_end') AS stf_spec_end,
      minIfOrNull(event_date_time, stage = 'stf_start') AS stf_start,
      minIfOrNull(event_date_time, stage = 'stf_done') AS stf_done,
      minIfOrNull(event_date_time, stage = 'attestable') AS attestable,
      minIfOrNull(time_into_slot_ms, stage = 'attestable') AS attestable_ms,
      minIfOrNull(event_date_time, stage = 'columns_wait_start') AS columns_wait_start,
      minIfOrNull(event_date_time, stage = 'columns_wait_end') AS columns_wait_end,
      minIfOrNull(event_date_time, stage = 'get_head_start') AS get_head_start,
      minIfOrNull(event_date_time, stage = 'get_head_end') AS get_head_end,
      coalesce(el_sent, stf_spec_start, stf_start) AS exec_start,
      coalesce({ns(a="columns_wait_start", b="columns_wait_end")}, 0) AS columns_wait_ms
    FROM block_events
    WHERE event_date_time BETWEEN $__fromTime - INTERVAL 1 MINUTE
                              AND $__toTime + INTERVAL 1 MINUTE
      AND {client_filter}
      AND column_index IS NULL
    GROUP BY block_root
  )
  WHERE received BETWEEN $__fromTime AND $__toTime AND attestable IS NOT NULL
)"""


def ch_target(sql, table=False, ref="A", ds=CH):
    # grafana-clickhouse-datasource 4.x: format 0 = time series, 1 = table.
    return {
        "refId": ref,
        "datasource": ds,
        "editorType": "sql",
        "queryType": "table" if table else "timeseries",
        "format": 1 if table else 0,
        "rawSql": sql,
    }


def ch_stat(title, sql, *, unit="ms", decimals=1, steps=None, description=CH_DOC):
    return {
        "type": "stat", "title": title, "description": description,
        "datasource": CH, "gridPos": {"h": 4, "w": 4, "x": 0, "y": 0},
        "fieldConfig": {"defaults": {
            "unit": unit, "decimals": decimals, "mappings": [],
            "thresholds": {"mode": "absolute",
                           "steps": steps or [{"color": "green", "value": None}]},
            "color": {"mode": "thresholds"},
        }, "overrides": []},
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "",
                              "values": False},
            "colorMode": "value", "graphMode": "none", "textMode": "value",
            "justifyMode": "auto",
        },
        "targets": [ch_target(sql, table=True)],
    }


def ch_series(title, sqls, *, w=12, h=9, description=CH_DOC, bars=False,
              stack=False, points=False, threshold=None, min_interval=None):
    custom = {"lineWidth": 1, "fillOpacity": 70 if bars else 10,
              "spanNulls": False,
              "drawStyle": "bars" if bars else ("points" if points else "line"),
              "showPoints": "always" if points else "never", "pointSize": 3,
              "stacking": {"mode": "normal" if stack else "none", "group": "A"}}
    defaults = {"unit": "ms", "min": 0, "custom": custom,
                "color": {"mode": "palette-classic"}}
    if threshold is not None:
        custom["thresholdsStyle"] = {"mode": "line+area"}
        defaults["thresholds"] = {"mode": "absolute", "steps": [
            {"color": "transparent", "value": None},
            {"color": "red", "value": threshold}]}
    # A query is SQL on CH, or (SQL, datasource) for another ClickHouse.
    queries = [q if isinstance(q, tuple) else (q, CH) for q in sqls]
    datasources = {ds["uid"] for _, ds in queries}
    panel = {
        "type": "timeseries", "title": title, "description": description,
        "datasource": CH if datasources == {CH["uid"]} else MIXED,
        "gridPos": {"h": h, "w": w, "x": 0, "y": 0},
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {"legend": {"displayMode": "table", "placement": "bottom",
                               "showLegend": True, "calcs": ["mean", "max"]},
                    "tooltip": {"mode": "multi", "sort": "none"}},
        "targets": [ch_target(sql, ref=chr(ord("A") + i), ds=ds)
                    for i, (sql, ds) in enumerate(queries)],
    }
    if min_interval:
        # Floor for $__timeInterval: a percentile needs several blocks (one
        # per 12 s) per bucket.
        panel["interval"] = min_interval
    return panel


def ch_quantiles(column, client_filter, label, qs=(0.5, 0.9)):
    cols = ",\n  ".join(f'quantile({q})({column}) AS "{label} p{round(q * 100)}"'
                        for q in qs)
    return f"""SELECT
  $__timeInterval(received) AS time,
  {cols}
FROM {ch_blocks(client_filter)}
GROUP BY time
ORDER BY time"""


def clickhouse_row():
    blocks = ch_blocks(CH_CLIENT)
    steps = ('before_ms AS "before the STF",\n'
             '  columns_wait_ms AS "wait for columns",\n'
             '  exec_ms AS "STF + EL",\n'
             '  head_ms AS "head"')
    alongside = ('el_ms AS "EL round trip (newPayload)",\n'
                 '  stf_spec_ms AS "STF, speculative",\n'
                 '  stf_ms AS "import after the verdict",\n'
                 '  get_head_ms AS "get_head"')

    def q(expr):
        # `steps`/`alongside` as quantiles: wrap each aliased column.
        out = []
        for line in expr.split(",\n"):
            col, alias = line.strip().split(" AS ")
            out.append(f"quantile({{q}})({col}) AS {alias}")
        return ",\n  ".join(out)

    panels = [
        ch_stat("Blocks: $client", f"SELECT count() FROM {blocks}",
                unit="none", decimals=0,
                description="Blocks first received in the time range that "
                            "became attestable. " + CH_DOC),
        ch_stat("Arrival -> attestable, p50",
                f"SELECT quantile(0.5)(total_ms) FROM {blocks}"),
        ch_stat("Arrival -> attestable, p99",
                f"SELECT quantile(0.99)(total_ms) FROM {blocks}",
                steps=[{"color": "green", "value": None},
                       {"color": "orange", "value": 250},
                       {"color": "red", "value": 1000}]),
        ch_stat("Arrival -> attestable, max", f"SELECT max(total_ms) FROM {blocks}",
                steps=[{"color": "green", "value": None},
                       {"color": "orange", "value": 500},
                       {"color": "red", "value": 2000}]),
        ch_stat("Arrival into slot, p50",
                f"SELECT quantile(0.5)(arrival_ms) FROM {blocks}",
                description="When blocks reached the node, counted from the "
                            "slot start. Set by the network and the proposer, "
                            "not by the node."),
        ch_stat("Attestable by 4 s",
                "SELECT countIf(attestable_ms <= 4000) / "
                f"countIf(attestable_ms IS NOT NULL) FROM {blocks}",
                unit="percentunit",
                steps=[{"color": "red", "value": None},
                       {"color": "orange", "value": 0.95},
                       {"color": "green", "value": 0.99}],
                description="Share of blocks attestable within 4 s of their "
                            "slot start, the attestation deadline."),
        ch_series("Arrival -> attestable per block, by step: $client", [f"""SELECT
  received AS time,
  {steps}
FROM {blocks}
ORDER BY time"""], w=24, h=10, bars=True, stack=True),
        ch_series("Arrival -> attestable, percentiles per interval", [f"""SELECT
  $__timeInterval(received) AS time,
  quantile(0.5)(total_ms) AS p50,
  quantile(0.9)(total_ms) AS p90,
  quantile(0.99)(total_ms) AS p99,
  max(total_ms) AS max
FROM {blocks}
GROUP BY time
ORDER BY time"""], min_interval="5m"),
        ch_series("Time into slot per block", [f"""SELECT
  received AS time,
  arrival_ms AS "arrival",
  attestable_ms AS "attestable"
FROM {blocks}
ORDER BY time"""], points=True, threshold=4000,
                  description="Arrival and attestable time, counted from each "
                              "block's slot start. The red band is past the "
                              "4 s attestation deadline."),
    ]
    for quant, label in [(0.5, "p50"), (0.99, "p99")]:
        cols = q(steps + ",\n" + alongside).replace("{q}", str(quant))
        panels.append(ch_series(f"Each step, {label} per interval", [f"""SELECT
  $__timeInterval(received) AS time,
  {cols}
FROM {blocks}
GROUP BY time
ORDER BY time"""], h=11, min_interval="5m"))
    compare = (
        "Same blocks, two clients on mainnet: this node and Silver on eth-5 "
        "(its own rows, in eth-5's ClickHouse). Arrival depends on each node's "
        "peers, so compare processing (arrival -> attestable) for the client "
        "and time into slot for the result.")
    panels += [
        ch_series("Arrival -> attestable vs Silver",
                  [ch_quantiles("total_ms", CH_CLIENT, "${client}"),
                   (ch_quantiles("total_ms", CH_SILVER, "silver"), SILVER_CH)],
                  w=8, min_interval="5m", description=compare),
        ch_series("Attestable into slot vs Silver",
                  [ch_quantiles("attestable_ms", CH_CLIENT, "${client}"),
                   (ch_quantiles("attestable_ms", CH_SILVER, "silver"), SILVER_CH)],
                  w=8, min_interval="5m", description=compare),
        ch_series("Arrival into slot vs Silver",
                  [ch_quantiles("arrival_ms", CH_CLIENT, "${client}"),
                   (ch_quantiles("arrival_ms", CH_SILVER, "silver"), SILVER_CH)],
                  w=8, min_interval="5m", description=compare),
    ]
    table_sql = f"""SELECT
  slot,
  received AS time,
  source,
  verdict AS "EL verdict status",
  arrival_ms AS "arrival into slot",
  before_ms AS "before the STF",
  columns_wait_ms AS "wait for columns",
  exec_ms AS "STF + EL",
  head_ms AS "head",
  total_ms AS "arrival -> attestable",
  attestable_ms AS "attestable into slot",
  el_ms AS "EL round trip",
  stf_spec_ms AS "STF, speculative",
  get_head_ms AS "get_head",
  block_root AS root
FROM {blocks}
ORDER BY slot DESC
LIMIT 50"""
    panels.append({
        "type": "table", "title": "Latest 50 blocks: $client",
        "description": CH_DOC, "datasource": CH,
        "gridPos": {"h": 11, "w": 24, "x": 0, "y": 0},
        "fieldConfig": {"defaults": {
            "unit": "ms", "decimals": 1,
            "custom": {"align": "auto", "cellOptions": {"type": "auto"}}},
            "overrides": [
                {"matcher": {"id": "byName", "options": "slot"},
                 "properties": [{"id": "unit", "value": "none"},
                                {"id": "decimals", "value": 0}]},
                {"matcher": {"id": "byName", "options": "time"},
                 "properties": [{"id": "unit", "value": "dateTimeAsIso"}]},
                {"matcher": {"id": "byName", "options": "arrival -> attestable"},
                 "properties": [
                     {"id": "custom.cellOptions",
                      "value": {"type": "color-background", "mode": "basic"}},
                     {"id": "thresholds", "value": {
                         "mode": "absolute", "steps": [
                             {"color": "green", "value": None},
                             {"color": "orange", "value": 250},
                             {"color": "red", "value": 1000}]}}]},
            ]},
        "options": {"showHeader": True, "cellHeight": "sm"},
        "targets": [ch_target(table_sql, table=True)],
    })
    panels.append(timeseries(
        DS, "Telemetry rows written to ClickHouse: $node",
        "What became of the node's `block_events` rows "
        "(`lean_telemetry_rows_total`): inserted, or dropped (channel full, "
        "backlog past its cap, or a batch ClickHouse refused). Insert "
        "failures count failed requests, retried ones included; a rising "
        "count with no inserted rows means the node cannot reach or log in "
        "to ClickHouse.",
        [(f"sum by (node, outcome) (rate(lean_telemetry_rows_total{{{B}}}[5m]))",
          "{{node}} {{outcome}}"),
         (f"sum by (node) (rate(lean_telemetry_insert_failures_total{{{B}}}[5m]))",
          "{{node}} insert failures")],
        "ops", w=24, no_value="Telemetry off on every selected node"))
    return ("Per-block processing (ClickHouse)", panels)


def ch_client_var():
    q = ("SELECT DISTINCT meta_client_name FROM block_events "
         "WHERE event_date_time > now() - INTERVAL 1 DAY "
         "ORDER BY meta_client_name")
    return {
        "name": "client", "label": "ClickHouse node", "type": "query",
        "datasource": CH, "definition": q, "query": q,
        "multi": False, "includeAll": False, "hide": 0, "refresh": 2,
        "sort": 1,
        "current": {"selected": True, "text": "beacon-eth4",
                    "value": "beacon-eth4"},
    }


def hidden_var(name, label, regex):
    query = 'label_values(lean_head_slot{job="beacon", node=~"$node"}, node)'
    return {
        "name": name, "label": label, "type": "query", "datasource": DS,
        "definition": query,
        "query": {"qryType": 1, "query": query, "refId": f"{name}-query"},
        "regex": regex, "multi": True, "includeAll": True,
        "current": {"selected": True, "text": ["All"], "value": ["$__all"]},
        "hide": 2, "refresh": 1, "sort": 1,
    }


def build_beacon(doc):
    doc = copy.deepcopy(doc)
    titles = {t for t, _ in beacon_rows()}
    doc["panels"] = [p for p in doc["panels"]
                     if not (p["type"] == "row" and p["title"] in titles)]

    # The eth-5 ethrex target serves the embedded node's lean_* series too,
    # so an unscoped `node` lists ethrex-eth5 and `.+` double-counts it.
    for v in doc["templating"]["list"]:
        if v["name"] == "node":
            q = 'label_values(lean_head_slot{job="beacon"}, node)'
            v["definition"] = q
            v["query"]["query"] = q
            v["allValue"] = "beacon-.+"
    doc["templating"]["list"] = [v for v in doc["templating"]["list"]
                                 if v["name"] not in ("el", "host", "client")]
    doc["templating"]["list"] += [
        hidden_var("el", "EL node suffix", "/^beacon-(.+)$/"),
        hidden_var("host", "Host", r"/^beacon-(eth\d+)/"),
        ch_client_var(),
    ]

    links = [l for l in doc.get("links", []) if l.get("title") != "Ethrex L1"]
    links.append({"title": "Ethrex L1", "type": "link", "icon": "dashboard",
                  "url": f"/d/{ETHREX_UID}", "keepTime": True,
                  "targetBlank": False, "asDropdown": False,
                  "includeVars": False, "tags": [], "tooltip": ""})
    doc["links"] = links

    nxt = id_allocator(doc)
    y = max(p["gridPos"]["y"] + p["gridPos"]["h"] for p in doc["panels"])
    for title, panels in beacon_rows():
        doc["panels"].append(row(title, panels, nxt, y))
        y += 1
    return doc


# ------------------------------------------------------- ethrex dashboard

EDS = {"type": "prometheus", "uid": "${DS_PROMETHEUS}"}
E = 'job=~"$job", node=~"$node"'
EHOST = 'job="node", node=~"host-(${host:pipe})"'
INSTANCE_SEL = 'instance=~"$instance(:\\\\d+)?$"'


def ethrex_rows():
    ts = lambda *a, **k: timeseries(EDS, *a, **k)  # noqa: E731
    rows = []
    rows.append(("Block pipeline (last block)", [
        ts("Per-block phase times: $node",
           "Phase times of the last block ethrex processed.",
           [(f"execution_ms{{{E}}}", "execution"),
            (f"merkle_ms{{{E}}}", "merkleization"),
            (f"store_ms{{{E}}}", "storage"),
            (f"validate_ms{{{E}}}", "validation"),
            (f"warmer_ms{{{E}}}", "warmer")],
           "ms", repeat="node"),
        ts("Merkleization overlap: $node",
           "Merkle work done while execution ran, against the queue drained "
           "after execution finished.",
           [(f"merkle_concurrent_ms{{{E}}}", "concurrent with execution"),
            (f"merkle_drain_ms{{{E}}}", "drain after execution")],
           "ms", repeat="node"),
        ts("Merkle work done concurrently",
           "Share of merkle work that overlapped execution.",
           [(f"merkle_overlap_pct{{{E}}}", "{{node}}")], "percent", minv=0),
        ts("Warmer finish relative to execution",
           "Positive when the warmer finished before execution, negative "
           "when it finished late.",
           [(f"warmer_early_ms{{{E}}}", "{{node}}")], "ms"),
        ts("Execution throughput distribution",
           "Block execution throughput quantiles over 30 min. The p10 line "
           "tracks the slow blocks.",
           [(f"histogram_quantile(0.5, sum by (node, le) (rate(gigagas_histogram_bucket{{{E}}}[30m])))", "{{node}} p50"),
            (f"histogram_quantile(0.1, sum by (node, le) (rate(gigagas_histogram_bucket{{{E}}}[30m])))", "{{node}} p10")],
           "suffix: Ggas/s", w=24),
    ]))
    rows.append(("Transactions", [
        ts("Transactions per second",
           "TPS as ethrex reports it.",
           [(f"transactions_per_second{{{E}}}", "{{node}}")], "none"),
        ts("Transactions per block",
           "Transaction count of the last block.",
           [(f"transaction_count{{{E}}}", "{{node}}")], "none"),
        ts("Transactions by type: $node",
           "Executed transactions per second, by type.",
           [(f"sum by (tx_type) (rate(transactions_tracker{{{E}}}[5m]))", "{{tx_type}}")],
           "suffix: tx/s", stack="normal", repeat="node"),
        ts("Transaction execution errors, per hour",
           "Errors raised while executing transactions, by kind.",
           [(f"sum by (node, tx_error) (increase(transaction_errors_count{{{E}}}[1h]))",
             "{{node}} {{tx_error}}")],
           "none", w=24),
    ]))
    rows.append(("Reorgs", [
        ts("Reorgs attempted per hour",
           "Reorgs ethrex attempted, of any depth.",
           [(f"sum by (node) (increase(ethrex_reorg_depth_count{{{E}}}[1h]))", "{{node}}")],
           "none"),
        ts("Reorg depth",
           "Depth of attempted reorgs.",
           [(f"histogram_quantile(0.99, sum by (node, le) (rate(ethrex_reorg_depth_bucket{{{E}}}[1h])))", "{{node}} p99"),
            (mean("ethrex_reorg_depth", E, window="1h"), "{{node}} mean")],
           "suffix: blocks"),
        ts("Deep reorgs per hour",
           "Deep reorgs started, completed, and aborted.",
           [(f"sum by (node) (increase(ethrex_deep_reorg_attempts_total{{{E}}}[1h]))", "{{node}} attempts"),
            (f"sum by (node) (increase(ethrex_deep_reorg_success_total{{{E}}}[1h]))", "{{node}} successes"),
            (f"sum by (node) (increase(ethrex_deep_reorg_aborts_total{{{E}}}[1h]))", "{{node}} aborts")],
           "none"),
        ts("First-commit reconciliation time",
           "Duration of the first-commit reconciliation after a reorg.",
           [(f"histogram_quantile(0.99, sum by (node, le) (rate(ethrex_reorg_reconcile_duration_seconds_bucket{{{E}}}[1h])))", "{{node}} p99"),
            (mean("ethrex_reorg_reconcile_duration_seconds", E, window="1h"), "{{node}} mean")],
           "s"),
        ts("Reorg journal span",
           "Blocks covered by the state history column family.",
           [(f"ethrex_reorg_journal_length{{{E}}}", "{{node}}")],
           "suffix: blocks", w=8),
        ts("Reorg overlay size",
           "Key plus value bytes of the installed overlay. Zero when no "
           "reorg is in progress.",
           [(f"ethrex_reorg_overlay_bytes{{{E}}}", "{{node}}")], "bytes", w=8),
        ts("Reorg overlay entries",
           "Entries in the installed overlay.",
           [(f"ethrex_reorg_overlay_entries{{{E}}}", "{{node}}")], "none", w=8),
    ]))
    rows.append(("Storage (RocksDB)", [
        ts("Live SST bytes by column family: $node",
           "On-disk SST bytes per column family.",
           [(f"sum by (cf) (ethrex_db_cf_size_bytes{{{E}}})", "{{cf}}")],
           "bytes", stack="normal", repeat="node"),
        ts("Pending compaction bytes by column family: $node",
           "Estimated compaction write debt per column family.",
           [(f"sum by (cf) (ethrex_db_cf_pending_compaction_bytes{{{E}}}) > 0", "{{cf}}")],
           "bytes", no_value=NONE_IN_RANGE, repeat="node"),
        ts("Total live SST bytes",
           "Live SST bytes across all column families.",
           [(f"ethrex_db_total_live_sst_bytes{{{E}}}", "{{node}}")], "bytes"),
        ts("Space amplification",
           "Total SST bytes, including data not yet compacted, over the "
           "estimated live data bytes.",
           [(f"sum by (node) (ethrex_db_cf_total_sst_bytes{{{E}}}) / sum by (node) (ethrex_db_cf_live_data_bytes{{{E}}})",
             "{{node}}")],
           "suffix: x"),
        ts("Running compactions",
           "RocksDB compactions in progress.",
           [(f"ethrex_db_running_compactions{{{E}}}", "{{node}}")], "none", w=8),
        ts("Memtable bytes",
           "Memtable bytes across all column families.",
           [(f"sum by (node) (ethrex_db_cf_memtable_bytes{{{E}}})", "{{node}}")],
           "bytes", w=8),
        ts("SST files",
           "Live SST files across all column families.",
           [(f"sum by (node) (ethrex_db_cf_num_files{{{E}}})", "{{node}}")],
           "none", w=8),
        ts("Block cache usage and capacity",
           "Shared block cache bytes in use and pinned, against its "
           "capacity.",
           [(f"ethrex_db_block_cache_usage_bytes{{{E}}}", "{{node}} used"),
            (f"ethrex_db_block_cache_pinned_bytes{{{E}}}", "{{node}} pinned"),
            (f"ethrex_db_block_cache_capacity_bytes{{{E}}}", "{{node}} capacity")],
           "bytes"),
        ts("History backfill frontier",
           "Lowest block with full chain data on disk.",
           [(f"ethrex_db_backfill_frontier_block{{{E}}}", "{{node}}")], "none"),
    ]))
    rows.append(("P2P messages and discovery", [
        ts("Incoming P2P messages by type: $node",
           "devp2p messages received per second.",
           [(f"sum by (msg_type) (rate(ethrex_p2p_incoming_messages{{{E}}}[5m])) > 0", "{{msg_type}}")],
           "suffix: msg/s", no_value=NONE_IN_RANGE, repeat="node"),
        ts("Outgoing P2P messages by type: $node",
           "devp2p messages sent per second.",
           [(f"sum by (msg_type) (rate(ethrex_p2p_outgoing_messages{{{E}}}[5m])) > 0", "{{msg_type}}")],
           "suffix: msg/s", no_value=NONE_IN_RANGE, repeat="node"),
        ts("Discovery messages: $node",
           "discv4 and discv5 messages per second, both directions.",
           [(f"sum(rate(ethrex_discv4_incoming_messages{{{E}}}[5m]))", "discv4 in"),
            (f"sum(rate(ethrex_discv4_outgoing_messages{{{E}}}[5m]))", "discv4 out"),
            (f"sum(rate(ethrex_discv5_incoming_messages{{{E}}}[5m]))", "discv5 in"),
            (f"sum(rate(ethrex_discv5_outgoing_messages{{{E}}}[5m]))", "discv5 out")],
           "suffix: msg/s", repeat="node"),
        ts("Kademlia operation time, p99",
           "Peer table insert and full-scan durations.",
           [(f"histogram_quantile(0.99, sum by (node, le) (rate(ethrex_kademlia_insert_contact_duration_seconds_bucket{{{E}}}[5m])))", "{{node}} insert_contact"),
            (f"histogram_quantile(0.99, sum by (node, le) (rate(ethrex_kademlia_iter_contacts_duration_seconds_bucket{{{E}}}[5m])))", "{{node}} iter_contacts")],
           "s", w=24),
    ]))
    rows.append(("Block access lists (EIP-7928)", [
        ts("BAL-carrying blocks per hour",
           "Blocks processed that carried a block access list.",
           [(f"sum by (node) (increase(bal_blocks_total{{{E}}}[1h]))", "{{node}}")],
           "none"),
        ts("BAL size",
           "RLP-encoded block access list size, 30 min quantiles.",
           [(f"histogram_quantile(0.99, sum by (node, le) (rate(bal_size_bytes_histogram_bucket{{{E}}}[30m])))", "{{node}} p99"),
            (f"histogram_quantile(0.5, sum by (node, le) (rate(bal_size_bytes_histogram_bucket{{{E}}}[30m])))", "{{node}} p50")],
           "bytes"),
        ts("Latest BAL: accounts and storage slots",
           "Accounts, and unique storage slots read or written, in the most "
           "recent block access list.",
           [(f"bal_account_count{{{E}}}", "{{node}} accounts"),
            (f"bal_slot_count{{{E}}}", "{{node}} slots")],
           "none", w=24),
    ]))
    return rows


def convert_instance(expr):
    """Re-key an upstream query from `instance` to our `node` label."""
    if "node_cpu_seconds_total" in expr or "node_memory_" in expr:
        expr = expr.replace(INSTANCE_SEL, EHOST)
    expr = expr.replace(INSTANCE_SEL, 'node=~"$node"')
    # Upstream sizes these windows for a ~5 s scrape; lean64 scrapes every 30 s,
    # so an 18 s window rarely holds the two samples increase() needs.
    expr = expr.replace("[18s]", "[2m]")
    expr = re.sub(r"\bwithout\s*\(\s*instance\s*\)", "without(instance, node)", expr)
    expr = re.sub(r"\b(by|on)\s*\(\s*instance\b", r"\1 (node", expr)
    return expr


def build_ethrex(src):
    doc = copy.deepcopy(src)
    doc.pop("id", None)
    doc["uid"] = ETHREX_UID
    doc["title"] = "Ethrex L1"
    doc["links"] = [{"title": "Beacon Follower", "type": "link",
                     "icon": "dashboard", "url": f"/d/{BEACON_UID}",
                     "keepTime": True, "targetBlank": False,
                     "asDropdown": False, "includeVars": False, "tags": [],
                     "tooltip": ""}]

    # No ethrex logs reach lean64-loki, and no consensus client here exports
    # eth_con_fork_current.
    doc["panels"] = [p for p in doc["panels"]
                     if p.get("title") not in ("Logs", "Consensus Fork")]

    def walk(ps):
        for p in ps:
            walk(p.get("panels", []))
            if p.get("repeat") == "instance":
                p["repeat"] = "node"
            if "title" in p:
                p["title"] = p["title"].replace("$instance", "$node")
            for t in p.get("targets", []):
                if "expr" in t:
                    t["expr"] = convert_instance(t["expr"])
                if "legendFormat" in t:
                    t["legendFormat"] = re.sub(r"\{\{\s*instance\s*\}\}", "{{node}}",
                                               t["legendFormat"])
    walk(doc["panels"])

    client = next(p for p in doc["panels"] if p.get("title") == "Execution Client")
    client["gridPos"]["w"] = 24
    organize = client["transformations"][0]["options"]
    organize["indexByName"]["node"] = organize["indexByName"].pop("instance")
    organize["renameByName"] = {"node": "Node"}

    tv = doc["templating"]["list"]
    by = {v["name"]: v for v in tv}
    ds = by["DS_PROMETHEUS"]
    ds["regex"] = "/^Prometheus$/"
    ds["current"] = {"text": "Prometheus", "value": "lean64-prom"}
    network = by["network"]
    nq = 'label_values(ethrex_info{job=~"$job"}, network)'
    network.update({"definition": nq, "datasource": EDS,
                    "current": {"text": ["mainnet"], "value": ["mainnet"]}})
    network["query"] = {"qryType": 1, "query": nq, "refId": "network-query"}
    node = by["instance"]
    node_q = 'label_values(ethrex_info{job=~"$job", network=~"$network"}, node)'
    node.update({"name": "node", "label": "Node", "definition": node_q,
                 "regex": "", "datasource": EDS, "multi": True,
                 "includeAll": True,
                 "current": {"text": ["All"], "value": ["$__all"]}})
    node["query"] = {"qryType": 1, "query": node_q, "refId": "node-query"}
    host_q = 'label_values(ethrex_info{job=~"$job", node=~"$node"}, node)'
    host = {"name": "host", "label": "Host", "type": "query", "datasource": EDS,
            "definition": host_q,
            "query": {"qryType": 1, "query": host_q, "refId": "host-query"},
            "regex": r"/^ethrex-(eth\d+)/", "multi": True, "includeAll": True,
            "current": {"selected": True, "text": ["All"], "value": ["$__all"]},
            "hide": 2, "refresh": 1, "sort": 1}
    doc["templating"]["list"] = [ds, by["job"], network, node, host]

    nxt = id_allocator(doc)
    y = max(p["gridPos"]["y"] + (1 if p["type"] == "row" else p["gridPos"]["h"])
            for p in doc["panels"])
    for title, panels in ethrex_rows():
        doc["panels"].append(row(title, panels, nxt, y))
        y += 1

    leftover = json.dumps(doc)
    assert "$instance" not in leftover and "DS_LOKI" not in leftover, \
        "unconverted instance/loki reference"
    return doc


def main():
    beacon_in, ethrex_in, out = sys.argv[1:4]
    # ethlambda's stage names before and after its rename (#917).
    beacon = stage_names.apply(build_beacon(json.load(open(beacon_in))))
    ethrex = build_ethrex(json.load(open(ethrex_in)))
    json.dump(beacon, open(f"{out}/beacon-follower.json", "w"), indent=2)
    json.dump(ethrex, open(f"{out}/ethrex-l1.json", "w"), indent=2)


if __name__ == "__main__":
    main()
