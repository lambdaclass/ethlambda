#!/bin/bash
# Per-host: (re)launch this devnet's metrics scrapers.
#
#   prometheus  scrapes the devnet's nodes (172.17.0.1:9200+n) + node_exporter +
#               cadvisor from /opt/lean-quickstart/observability/prometheus.yml
#               (generate it with prometheus-config.sh) and remote-writes to the
#               central Prometheus. Local retention is short on purpose: the
#               central prom is the long-term store.
#   cadvisor    per-container CPU + memory on :9098 (per-container network/fs is
#               meaningless under --network host -- use node_exporter for those).
#
# node_exporter is NOT here: it is a systemd service installed from
# lambdaclass/monitoring-stack (binds <tailscale_ip>:9122), not a container.
# Log shipping is start-promtail.sh. The CENTRAL prometheus/grafana/loki stack is
# a separate one-time deployment (see references/operations.md).
#
# Safe on a live devnet: neither container is a gossip peer, so no 60s backoff.
#
# Usage (on host):  start-observability.sh
#   RECREATE=1  replace containers that already exist. Without it an existing
#               prometheus/cadvisor is LEFT ALONE: it may have been created with
#               different flags (retention, ports), and silently rewriting a live
#               scraper's configuration is not something to do as a side effect.
#               To pick up a prometheus.yml change you only need
#               `sudo docker restart prometheus` (single-file bind mount -- see
#               the inode trap in references/operations.md).
#   PROM_IMG / CADVISOR_IMG / PROM_PORT / CADVISOR_PORT / PROM_RETENTION
set -u
OBS=${OBS:-/opt/lean-quickstart/observability}
PROM_IMG=${PROM_IMG:-prom/prometheus:v3.1.0}
CADVISOR_IMG=${CADVISOR_IMG:-gcr.io/cadvisor/cadvisor:v0.49.1}
PROM_PORT=${PROM_PORT:-9090}
CADVISOR_PORT=${CADVISOR_PORT:-9098}
PROM_RETENTION=${PROM_RETENTION:-2d}
CFG="$OBS/prometheus.yml"

exists(){ [ -n "$(sudo docker ps -aq --filter "name=^${1}$")" ]; }
keep_or_replace(){  # $1 = container name -> 0 = go ahead and (re)create
  if exists "$1"; then
    if [ -z "${RECREATE:-}" ]; then
      echo "SKIP $1: already exists (RECREATE=1 to replace; 'docker restart $1' to reload its config)"
      return 1
    fi
    sudo docker rm -f "$1" >/dev/null 2>&1
  fi
  return 0
}

if [ ! -f "$CFG" ]; then
  echo "ERROR: $CFG missing -- generate it first:"
  echo "  prometheus-config.sh NETWORK NODES HOST_IP CENTRAL_WRITE_URL [N:client ...] | ssh host 'sudo tee $CFG'"
  exit 1
fi
sudo mkdir -p "$OBS/prometheus-data"

if keep_or_replace prometheus; then
  # --network host so it can reach the nodes' metrics ports, the host's
  # node_exporter, and the central prometheus over the same routes the operator uses.
  sudo docker run -d --restart unless-stopped --name prometheus --network host \
    --memory 2g --memory-swap 4g --log-opt max-size=50m --log-opt max-file=3 \
    -v "$CFG":/etc/prometheus/prometheus.yml \
    -v "$OBS/prometheus-data":/prometheus \
    "$PROM_IMG" \
    --config.file=/etc/prometheus/prometheus.yml \
    --storage.tsdb.path=/prometheus \
    --storage.tsdb.retention.time="$PROM_RETENTION" \
    --web.listen-address=":$PROM_PORT" >/dev/null \
    && echo "prometheus started ($PROM_IMG, :$PROM_PORT, retention $PROM_RETENTION)" \
    || echo "FAIL to start prometheus"
fi

if keep_or_replace cadvisor; then
  sudo docker run -d --restart unless-stopped --name cadvisor \
    -p "$CADVISOR_PORT":8080 --privileged --device /dev/kmsg \
    --memory 1g --memory-swap 2g --log-opt max-size=50m --log-opt max-file=3 \
    -v /:/rootfs:ro -v /var/run:/var/run:ro -v /sys:/sys:ro \
    -v /var/lib/docker/:/var/lib/docker:ro -v /dev/disk/:/dev/disk:ro \
    "$CADVISOR_IMG" >/dev/null \
    && echo "cadvisor started ($CADVISOR_IMG, :$CADVISOR_PORT)" \
    || echo "FAIL to start cadvisor"
fi

echo
echo "verify:  curl -s 127.0.0.1:$PROM_PORT/api/v1/targets | grep -o '\"health\":\"[a-z]*\"' | sort | uniq -c"
echo "         (every node job should be 'up'; check job/client_type labels per scrapeUrl)"
