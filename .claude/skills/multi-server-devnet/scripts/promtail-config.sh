#!/bin/bash
# OPERATOR-side: emit one host's promtail.yml to stdout. promtail discovers the
# devnet's node containers via the Docker daemon API (docker_sd) and ships their
# stdout/stderr to the central Loki. Reading via the daemon API (not the json
# files) makes it immune to docker's log-rotation: promtail consumes the live
# stream, so --log-opt max-size/max-file rotation never races it.
#
# Labels mirror prometheus-config.sh so logs and metrics share a vocabulary:
#   network      per-devnet label (Grafana filters on this) — SAME value as the
#                host's prometheus.yml network label
#   node         container name (<client>_N, e.g. zeam_8 — reflects the client)
#   client_type  derived from the container-name prefix (self-maintaining)
#   instance     this host's address
#   stream       stdout|stderr
# Only containers named <client>_[0-9]+ are kept (infra has no _<digit> suffix).
#
# Pipe into `ssh host 'sudo tee /opt/lean-quickstart/observability/promtail.yml'`.
# That file is a single-file bind-mount: overwrite with tee (preserves inode),
# then `sudo docker restart promtail` — never sed -i (inode trap, see operations.md).
#
# Usage: promtail-config.sh <NETWORK> <HOST_IP> <LOKI_PUSH_URL> [N:client ...]
#   NETWORK        per-devnet label value (e.g. devnet-<server>)
#   HOST_IP        this host's address used as the `instance` label
#   LOKI_PUSH_URL  central Loki push endpoint
#                  (e.g. http://10.0.0.4:3100/loki/api/v1/push)
#   N:client       accepted for call-site compatibility but IGNORED now that
#                  client_type is derived from the container-name prefix
set -eu
python3 - "$@" <<'PY'
import sys
net, host_ip, push_url = sys.argv[1], sys.argv[2], sys.argv[3]
# Canary N:client args (sys.argv[4:]) are accepted for call-site compatibility
# but no longer used: client_type is derived from the container-name prefix.

out = [
    'server:',
    '  http_listen_port: 9080',
    '  grpc_listen_port: 0',
    '',
    'positions:',
    '  filename: /promtail-data/positions.yaml',
    '',
    'clients:',
    f'  - url: {push_url}',
    '',
    'scrape_configs:',
    '  - job_name: ethlambda-logs',
    '    docker_sd_configs:',
    '      - host: unix:///var/run/docker.sock',
    '        refresh_interval: 10s',
    '    relabel_configs:',
    "      # keep only devnet node containers (<client>_N); infra has no _<digit> suffix",
    "      - source_labels: ['__meta_docker_container_name']",
    "        regex: '/([a-z]+_[0-9]+)'",
    '        action: keep',
    "      - source_labels: ['__meta_docker_container_name']",
    "        regex: '/(.*)'",
    '        target_label: node',
    "      # client_type derived from the container-name prefix (self-maintaining:",
    "      # no per-node overrides now that the name encodes the client)",
    "      - source_labels: ['node']",
    "        regex: '([a-z]+)_[0-9]+'",
    '        target_label: client_type',
    "        replacement: '${1}'",
    "      - source_labels: ['__meta_docker_container_log_stream']",
    '        target_label: stream',
    '      - target_label: instance',
    f"        replacement: '{host_ip}'",
    '      - target_label: network',
    f"        replacement: '{net}'",
]
# Drop backlog: docker_sd has no "since", so on first start (empty positions)
# promtail replays each container's FULL retained history (the 600m x N json
# files can reach back days), which Loki rejects as "too old" (>retention) and
# rate-limits. This stage ships only the last hour forward; persisted positions
# mean the one-time backlog read happens once. Trade-off: a promtail outage
# longer than 1h loses the excess on recovery (docker logs + Loki remain the
# buffers). older_than uses the docker log timestamp, so steady-state (current)
# lines are never dropped.
PIPELINE = [
    '    pipeline_stages:',
    '      # 1. drop the first-start backlog (docker_sd has no "since"; see header)',
    '      - drop:',
    '          older_than: 1h',
    '          drop_counter_reason: backlog_too_old',
    '      # 2. strip ANSI color/style escapes from the client pretty-logger output',
    "      - replace:",
    "          expression: '(\\x1b\\[[0-9;]*m)'",
    "          replace: ''",
    '      # 3. merge multi-line events (e.g. fork-choice tree dumps): a line that does NOT',
    '      #    start with a timestamp is a continuation of the previous entry. Runs after',
    '      #    ANSI strip so firstline anchors on the bare timestamp; state is per-stream',
    '      #    (node label), so containers never bleed into each other.',
    "      - multiline:",
    "          firstline: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}'",
    '          max_wait_time: 3s',
    '          max_lines: 1024',
    '      # 4. lift the tracing level (token after the timestamp) into a low-card label;',
    '      #    also lets Grafana colourise the logs panel by level. Lines with no level',
    '      #    (multi-line dumps) simply get no level label.',
    "      - regex:",
    "          expression: '^\\S+\\s+(?P<level>TRACE|DEBUG|INFO|WARN|ERROR)\\b'",
    '      - labels:',
    '          level:',
    '      # 5. attach high-cardinality fields as STRUCTURED METADATA (NOT labels):',
    '      #    filterable in Grafana/LogQL (e.g. | slot="123") without exploding the',
    '      #    stream cardinality. Wrapped in a match so only lines that actually carry',
    '      #    key=value fields pay the logfmt cost. logfmt mapping is explicit, so the',
    '      #    non-logfmt prefix (timestamp/level/target) is ignored.',
    '      - match:',
    "          selector: '{network=~\".+\"} |= \"=\"'",
    '          stages:',
    '            - logfmt:',
    '                mapping:',
    '                  slot:',
    '                  validator:',
    '                  proposer:',
    '                  block_root:',
    '                  parent_root:',
    '                  target_slot:',
    '                  target_root:',
    '                  source_slot:',
    '                  source_root:',
    '                  attestation_count:',
    '                  peer_id:',
    '            - structured_metadata:',
    '                slot:',
    '                validator:',
    '                proposer:',
    '                block_root:',
    '                parent_root:',
    '                target_slot:',
    '                target_root:',
    '                source_slot:',
    '                source_root:',
    '                attestation_count:',
    '                peer_id:',
]
out += PIPELINE
out.append('')
print('\n'.join(out))
PY
