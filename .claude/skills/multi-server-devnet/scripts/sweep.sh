#!/bin/bash
# Run from the OPERATOR machine. Audit ALL independent devnets at once via the
# central Prometheus (the one Grafana reads): per devnet `network`, prints head /
# justified / finalized slot and the client mix. This is the fast cross-devnet
# health check — one query, no per-node ssh.
#
# Env:
#   CENTRAL_PROM_URL  central Prometheus base, e.g. http://10.0.0.4:9099 (required;
#                     normally comes from devnet.env, see devnet.env.example)
#
# For a single devnet's per-node detail (running state, stuck node), ssh the host
# and read /tmp/start-devnet.log + curl 127.0.0.1:$((9200+n))/metrics directly.
set -u
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/devnet-env.sh"
devnet_load_env || exit 1
P=${CENTRAL_PROM_URL:?set CENTRAL_PROM_URL to the central Prometheus base url}

q(){ curl -s -m 5 "$P/api/v1/query" --data-urlencode "query=$1"; }

for metric in lean_head_slot lean_latest_justified_slot lean_latest_finalized_slot; do
  echo "$metric:"
  q "max by (network) ($metric)" | python3 -c '
import json,sys
rs=json.load(sys.stdin).get("data",{}).get("result",[])
for r in sorted(rs, key=lambda x: x["metric"].get("network","")):
    print("  ", r["metric"].get("network","?"), r["value"][1])'
done

echo "client mix per devnet (running app targets):"
q 'count by (network, client_type) (up{type="app"} == 1)' | python3 -c '
import json,sys
rows={}
for r in json.load(sys.stdin).get("data",{}).get("result",[]):
    m=r["metric"]; rows.setdefault(m.get("network","?"),{})[m.get("client_type","?")]=r["value"][1]
for net in sorted(rows): print("  ", net, rows[net])'
