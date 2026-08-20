#!/bin/bash
# Per-host: (re)launch the promtail log shipper. Reads /opt/lean-quickstart/
# observability/promtail.yml (push the generated file there first with
# promtail-config.sh | ssh ... tee) and ships node-container logs to the central
# Loki. Safe to run on a live devnet: promtail is NOT a gossip peer, so there is
# no 60s backoff and no devnet impact — it only reads the Docker socket.
#
# Usage (on host):  start-promtail.sh
#   PROMTAIL_IMG env overrides the image (default pinned to the Loki version).
set -u
OBS=/opt/lean-quickstart/observability
IMG=${PROMTAIL_IMG:-grafana/promtail:3.4.2}
CFG="$OBS/promtail.yml"

if [ ! -f "$CFG" ]; then echo "ERROR: $CFG missing (generate + push it first)"; exit 1; fi
sudo mkdir -p "$OBS/promtail-data"

sudo docker rm -f promtail >/dev/null 2>&1
# --user root: read the docker socket. Cap promtail's own logs too.
sudo docker run -d --restart unless-stopped --name promtail --network host --user root \
  --memory 512m --memory-swap 1g --memory-reservation 128m \
  --log-opt max-size=50m --log-opt max-file=3 \
  -v "$CFG":/etc/promtail/config.yml:ro \
  -v "$OBS/promtail-data":/promtail-data \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  "$IMG" -config.file=/etc/promtail/config.yml >/dev/null \
  && echo "promtail started ($IMG)" || echo "FAIL to start promtail"
