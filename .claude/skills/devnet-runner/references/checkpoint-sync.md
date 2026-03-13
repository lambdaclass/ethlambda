# Checkpoint Sync in Devnets

Restarting a node with checkpoint sync instead of replaying from genesis. Useful for testing checkpoint sync itself, upgrading a node's image mid-devnet, or recovering a crashed node.

## When to Use

- Testing checkpoint sync behavior (interop, verification, catch-up)
- Replacing a node's Docker image mid-run (e.g., testing a new build)
- Recovering a node that fell behind or crashed

## Prerequisites

- A running devnet with at least one healthy node to serve the checkpoint state
- The checkpoint source node's API must be reachable (`--api-port`, default 5052)

## Key Concepts

**ethlambda runs separate API and metrics servers.** The API (`/lean/v0/...`, including health and states) is served on `--api-port` (default 5052). Prometheus metrics (`/metrics`) and pprof are served on `--metrics-port` (default 5054). Both share the bind address `--http-address` (default `127.0.0.1`).

**Checkpoint sync URL format (uses the API port):**
```
http://<host>:<api-port>/lean/v0/states/finalized
```

**The node must have the same genesis config.** Checkpoint sync verifies the downloaded state against the local genesis config (genesis time, validator pubkeys, validator count). The `--custom-network-config-dir` must point to the same genesis used by the rest of the devnet.

## Restart Procedure

**Restart nodes one at a time.** Wait for each node to fully sync and rejoin consensus before restarting the next. 3SF-mini requires 2/3+ of validators to vote in order to justify checkpoints and advance finalization. If 1/3 or more validators are offline simultaneously, finalization stalls until enough nodes come back online.

### Step 1: Choose the node to restart

Any node can be restarted, but be aware that restarting the aggregator node will stop finalization and attestation inclusion in blocks until it catches back up to head. Check which node is the aggregator in `validator-config.yaml`:
```yaml
# In lean-quickstart/<network-dir>/genesis/validator-config.yaml
validators:
  - name: "ethlambda_0"
    isAggregator: false
  - name: "ethlambda_2"
    isAggregator: true     # restarting this stops finalization until it catches up
```

### Step 2: Identify a checkpoint source

Pick any other running node's API port as the checkpoint source. For ethlambda, the API is served on `--api-port` (default 5052). For other clients, the API may share the `metricsPort` from `validator-config.yaml`.

For local devnets (host networking), the URL is:
```
http://127.0.0.1:<api-port>/lean/v0/states/finalized
```

Verify the endpoint is reachable:
```bash
curl -s http://127.0.0.1:<api-port>/lean/v0/health
# Should return: {"status":"healthy","service":"lean-spec-api"}
```

### Step 3: Update the Docker image tag (if changing versions)

Edit `lean-quickstart/client-cmds/<client>-cmd.sh` and change the image tag in `node_docker` before restarting:
```bash
# In lean-quickstart/client-cmds/ethlambda-cmd.sh, change:
node_docker="ghcr.io/lambdaclass/ethlambda:local \
# To:
node_docker="ghcr.io/lambdaclass/ethlambda:devnet3 \
```

### Step 4: Pull the new Docker image

**Pull the image before restarting** to minimize how long the node is absent from the network. If you skip this, `spin-node.sh` will pull during restart, adding minutes of downtime where the node misses proposer slots and attestation duties:
```bash
docker pull <image>:<new_tag>
```

### Step 5: Restart with checkpoint sync

```bash
cd lean-quickstart && NETWORK_DIR=local-devnet ./spin-node.sh \
  --restart-client <node_name> \
  --checkpoint-sync-url http://127.0.0.1:<source_api_port>/lean/v0/states/finalized
```

This automatically:
1. Stops the existing container
2. Clears the data directory
3. Pulls the Docker image (skipped if already present locally)
4. Restarts with `--checkpoint-sync-url` passed to the node

If `--checkpoint-sync-url` is omitted, it defaults to `https://leanpoint.leanroadmap.org/lean/v0/states/finalized` (the public checkpoint provider).

Multiple nodes can be restarted at once with comma-separated names:
```bash
--restart-client ethlambda_0,ethlambda_3
```

### Step 6: Verify the node synced

```bash
docker logs --tail 20 <node_name>
```

Look for:
- "Block imported successfully" messages catching up to the current slot
- "Fork Choice Tree" showing finalized/justified/head slots close to the network's current state
- No error messages about verification failures or SSZ decode errors

## Troubleshooting

### "genesis time mismatch" or "validator count mismatch"
The checkpoint source is running a different genesis than the restarting node. Ensure both use the same genesis config directory.

### "HTTP request failed" or connection refused
The checkpoint source node is down or unreachable. Verify with `curl` that the source endpoint returns a healthy response.

### Node exits immediately after start
Check `docker logs <node_name>` for verification errors. Checkpoint sync exits on any failure without modifying the database, so it's safe to retry.

### Node syncs but doesn't finalize
If the restarted node is the aggregator, attestations won't be aggregated and blocks will be produced with `attestation_count=0` until it catches back up to head. Finalization resumes once the aggregator is fully synced and participating in consensus again.

### "Fallback pruning (finalization stalled)" after catch-up
Normal during catch-up. The node accumulated blocks faster than finalization can advance. This resolves once the node is fully caught up and participating in consensus.
