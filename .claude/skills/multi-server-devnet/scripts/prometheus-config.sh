#!/bin/bash
# OPERATOR-side: emit one devnet's per-host prometheus.yml to stdout.
# Scrapes nodes 0..NODES-1 (metrics 9200+n) with a per-devnet `network` label
# and per-node `client_type`, plus the host's node_exporter (systemd, on
# HOST_IP:9122 — installed separately via lambdaclass/monitoring-stack) and
# cadvisor (docker, 172.17.0.1:9098), and remote-writes to
# the central Prometheus. Pipe into `ssh host 'sudo tee .../prometheus.yml'`.
#
# Usage: prometheus-config.sh <NETWORK> <NODES> <HOST_IP> <CENTRAL_WRITE_URL> [N:client ...]
#   NETWORK            label value (e.g. devnet-foo) — Grafana filters on this
#   NODES              validator count
#   HOST_IP            this host's address used as the `instance` label
#   CENTRAL_WRITE_URL  remote_write target (e.g. http://10.0.0.4:9099/api/v1/write)
#   N:client           optional canary node->client_type overrides
set -eu
python3 - "$@" <<'PY'
import sys
net, nodes, host_ip, central = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
canary = dict(s.split(':', 1) for s in sys.argv[5:])
out = ['global:', '  scrape_interval: 15s', '', 'scrape_configs:']
for n in range(nodes):
    c = canary.get(str(n), 'ethlambda')
    out += [f"  - job_name: '{c}_{n}'", '    static_configs:',
            f"      - targets: ['172.17.0.1:{9200+n}']", '        labels:',
            "          type: 'app'", f"          instance: '{host_ip}'",
            f"          network: '{net}'", f"          client_type: '{c}'"]
out += ["  - job_name: 'node_exporter'", '    static_configs:',
        f"      - targets: ['{host_ip}:9122']", '        labels:',
        "          type: 'node'", f"          instance: '{host_ip}'", f"          network: '{net}'",
        "  - job_name: 'cadvisor'", '    static_configs:',
        "      - targets: ['172.17.0.1:9098']", '        labels:',
        "          type: 'docker'", f"          instance: '{host_ip}'", f"          network: '{net}'",
        '    metric_relabel_configs:', '      - source_labels: [name]',
        "        regex: '([a-z]+)_.*'", '        target_label: client_type',
        "        replacement: '$1'",
        'remote_write:', f'  - url: {central}', '']
print('\n'.join(out))
PY
