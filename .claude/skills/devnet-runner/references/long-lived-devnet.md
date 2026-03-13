# Long-Lived Devnets

Running a persistent devnet with detached containers that survive SSH disconnects and support rolling restarts to upgrade images without losing chain state.

## When to Use

- Running a devnet on a remote server that should persist across SSH sessions
- Upgrading node images mid-devnet without resetting genesis
- Testing checkpoint sync and rolling restart procedures

## Overview

`spin-node.sh` runs containers with `docker run --rm` (foreground, auto-remove) and kills all containers on exit. This is fine for short test runs but not for long-lived devnets.

The alternative: start containers directly with `docker run -d --restart unless-stopped`. Containers are decoupled from any parent process and survive SSH disconnects, script exits, and host reboots.

## Starting a Long-Lived Devnet

### Step 1: Generate genesis

Use `spin-node.sh` to generate genesis config, keys, and ENR records, then immediately stop it:

```bash
cd lean-quickstart && NETWORK_DIR=local-devnet ./spin-node.sh --node all --generateGenesis
# Press Ctrl-C after nodes start (genesis is already generated)
```

Or, if you want to avoid starting containers at all, update `GENESIS_TIME` in `config.yaml` manually:

```bash
GENESIS=/path/to/lean-quickstart/local-devnet/genesis
GENESIS_TIME=$(($(date +%s) + 30))
sed -i "s/^GENESIS_TIME:.*/GENESIS_TIME: $GENESIS_TIME/" $GENESIS/config.yaml
```

### Step 2: Start all containers detached

Start all nodes simultaneously so the gossipsub mesh forms correctly:

```bash
GENESIS=/path/to/lean-quickstart/local-devnet/genesis
DATA=/path/to/lean-quickstart/local-devnet/data
IMAGE=ghcr.io/lambdaclass/ethlambda:devnet3

# Clean data dirs
for d in ethlambda_0 ethlambda_1 ethlambda_2 ethlambda_3; do
  rm -rf "$DATA/$d/"*
done

# Start each node (adjust ports, node-id, aggregator flag per validator-config.yaml)
docker run -d --restart unless-stopped --name ethlambda_0 --network host \
  -v $GENESIS:/config -v $DATA/ethlambda_0:/data \
  $IMAGE \
  --custom-network-config-dir /config \
  --gossipsub-port 9001 --node-id ethlambda_0 \
  --node-key /config/ethlambda_0.key \
  --metrics-address 0.0.0.0 --metrics-port 8081

# Repeat for other nodes, adding --is-aggregator to the aggregator node
```

Do NOT include `--checkpoint-sync-url` in the initial start. Nodes start from genesis.

### Step 3: Verify

Wait ~50 seconds (30s genesis offset + 20s for finalization to start), then check:

```bash
for n in 0 1 2 3; do
  printf "ethlambda_$n: "
  docker logs --tail 15 ethlambda_$n 2>&1 | grep "Finalized:" | tail -1
done
```

All nodes should show the same finalized slot advancing.

## Rolling Restart Procedure

To upgrade a node's image without losing chain state. Restart one node at a time; the network continues finalizing with the remaining nodes.

### Critical: 60-Second Wait

After stopping a node, **wait at least 60 seconds** before starting the replacement. This allows the gossipsub backoff timer on other nodes to expire. Without this wait, the restarted node's GRAFT requests are rejected and it never joins the gossip mesh, meaning it won't receive blocks or attestations via gossip.

### Restart Order

1. Non-aggregator nodes first
2. Aggregator node last (while it's offline, blocks are produced with `attestation_count=0` and finalization stalls)

### Per-Node Procedure

For each node:

```bash
GENESIS=/path/to/lean-quickstart/local-devnet/genesis
DATA=/path/to/lean-quickstart/local-devnet/data
NEW_IMAGE=ghcr.io/lambdaclass/ethlambda:new-tag

# 1. Pull the new image first (minimizes downtime)
docker pull $NEW_IMAGE

# 2. Pick a healthy peer's API port as checkpoint source
#    (any running node that is NOT the one being restarted)
#    ethlambda serves /lean/v0/states/finalized on --api-port (default 5052)
CHECKPOINT_SOURCE_PORT=5052  # e.g., ethlambda_3's API port

# 3. Stop and remove the container
docker rm -f ethlambda_0
rm -rf "$DATA/ethlambda_0/"*

# 4. Wait 60 seconds for gossipsub backoff to expire
sleep 60

# 5. Start with new image + checkpoint sync
docker run -d --restart unless-stopped --name ethlambda_0 --network host \
  -v $GENESIS:/config -v $DATA/ethlambda_0:/data \
  $NEW_IMAGE \
  --custom-network-config-dir /config \
  --gossipsub-port 9001 --node-id ethlambda_0 \
  --node-key /config/ethlambda_0.key \
  --metrics-address 0.0.0.0 --metrics-port 8081 \
  --checkpoint-sync-url http://127.0.0.1:$CHECKPOINT_SOURCE_PORT/lean/v0/states/finalized
```

### Verification After Each Node

Wait ~20 seconds, then verify:

```bash
# Check the restarted node receives blocks via gossip (not just req-resp)
docker logs --tail 20 ethlambda_0 2>&1 | grep "Received block from gossip"

# Check finalization matches other nodes
for n in 0 1 2 3; do
  printf "ethlambda_$n: "
  docker logs --tail 15 ethlambda_$n 2>&1 | grep "Finalized:" | tail -1
done
```

**Only proceed to the next node after confirming:**
- The restarted node shows "Received block from gossip" (not just BlocksByRoot)
- No "NoPeersSubscribedToTopic" warnings in recent logs
- Finalized slot matches other nodes

## Monitoring Stack

If Prometheus and Grafana were previously started via `spin-node.sh --metrics`, restart them separately since they're managed by docker-compose:

```bash
cd lean-quickstart/metrics && docker compose -f docker-compose-metrics.yaml up -d
```

## Troubleshooting

### Restarted node shows "NoPeersSubscribedToTopic" persistently

The 60-second wait was not long enough, or was skipped. Stop the node, wait 60s, and start again.

### Finalization stalls after restarting the aggregator

Expected behavior. Finalization resumes once the aggregator catches up to head and starts aggregating attestations again. This typically takes 10-20 seconds after the node starts.

### Chain doesn't progress after restarting all nodes

If all nodes were restarted from genesis (no checkpoint sync) with a stale `GENESIS_TIME`, the slot gap from genesis to current time may not satisfy 3SF-mini justifiability rules. Regenerate genesis with a fresh timestamp.

### "genesis time mismatch" or "validator count mismatch"

The checkpoint source is running a different genesis than the restarting node. Ensure both use the same genesis config directory (`-v $GENESIS:/config`).

### "HTTP request failed" or connection refused

The checkpoint source node is down or unreachable. Verify with `curl`:
```bash
curl -s http://127.0.0.1:<api-port>/lean/v0/health
# Should return: {"status":"healthy","service":"lean-spec-api"}
```

### Container name conflict on start

The old container wasn't fully removed. Use `docker rm -f <name>` before `docker run`.

### "Fallback pruning (finalization stalled)" after catch-up

Normal during catch-up. The node accumulated blocks faster than finalization can advance. Resolves once fully caught up.
