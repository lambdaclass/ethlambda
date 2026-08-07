#!/bin/bash
# HOST-side: retire this host's slice of a cross-server devnet, in the order that
# keeps the GENESIS_TIME countdown honest (the data wipe is the step that scales
# with chain age, so it runs BEFORE the operator stamps the new genesis).
#
# Usage (on host): teardown.sh
#   Env: KEEP_GENESIS=1 (default) archives /opt/lean-quickstart/genesis to
#        genesis.bak-<ts> instead of deleting it -- that dir holds the retired
#        chain's hash-sig keys, which are deliberately preserved for reuse.
#        STAGED=/opt/lean-quickstart/genesis-new is promoted into place if present.
set -u
LQ=${LQ:-/opt/lean-quickstart}
GENESIS=$LQ/genesis
STAGED=${STAGED:-$LQ/genesis-new}
DATA=$LQ/data
TS=$(date +%Y%m%d-%H%M%S)
log(){ echo "$(date '+%H:%M:%S') $*"; }

# 1. containers: `--restart unless-stopped` respawns them, so clear the policy first
cids=$(sudo docker ps -aq --filter "name=_[0-9]" | tr '\n' ' ')
if [ -n "$cids" ]; then
  log "clearing restart policy on $(echo $cids | wc -w) containers"
  for c in $cids; do sudo docker update --restart=no "$c" >/dev/null; done
  log "removing containers"
  sudo docker rm -f $cids >/dev/null
else
  log "no node containers found"
fi

# 2. archive the retired genesis (holds the old chain's hash-sig keys -- KEEP)
if [ -d "$GENESIS" ]; then
  sudo mv "$GENESIS" "$GENESIS.bak-$TS"
  log "archived genesis -> $GENESIS.bak-$TS ($(sudo du -sh "$GENESIS.bak-$TS" | cut -f1), keys kept)"
fi

# 3. promote the staged genesis (config.yaml GT is re-stamped + reshipped after the wipe)
if [ -d "$STAGED" ]; then
  sudo mv "$STAGED" "$GENESIS"
  PK=$(sudo grep -m1 -o 'attestation_pubkey: "[0-9a-f]*"' "$GENESIS/config.yaml" | sed 's/.*"\(.*\)"/\1/')
  log "promoted staged genesis (pubkey $(( ${#PK} / 2 ))B, GT $(sudo awk '/GENESIS_TIME:/{print $2}' "$GENESIS/config.yaml") -- stale until reship)"
fi

# 4. the slow part: wipe every node DB so nothing resumes an old chain
if [ -d "$DATA" ]; then
  log "wiping $(sudo du -sh "$DATA" | cut -f1) of node data..."
  sudo rm -rf "$DATA"/node_*
  log "wiped; remaining: $(sudo du -sh "$DATA" 2>/dev/null | cut -f1)"
fi
log "=== teardown complete; ready for genesis reship + start-range.sh ==="
