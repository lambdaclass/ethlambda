---
name: devnet-runner
description: Manage local development networks (devnets) for lean consensus multi-client testing. This skill should be used when the user asks to run a devnet, start or stop devnet nodes, spin up a local testnet, configure validator nodes, regenerate genesis files, change Docker image tags, collect or dump node logs, troubleshoot devnet issues, restart a node with checkpoint sync, run a long-lived devnet with detached containers, or perform rolling restarts to upgrade images.
---

# Devnet Runner

Manage local development networks for lean consensus testing.

## Prerequisites

The `lean-quickstart` directory must exist at the repo root. If missing:
```bash
make lean-quickstart
```

## Default Behavior

When starting a devnet, **always**:
1. **Update validator config** - Edit `lean-quickstart/local-devnet/genesis/validator-config.yaml` to include ONLY the nodes that will run. Remove entries for nodes that won't be started (unless the user explicitly asks to keep them). Validator indices are assigned to ALL nodes in the config; if a node is in the config but not running, its validators will miss their proposer slots. To control which nodes run, always edit this config file rather than using `--node <specific>`, since `--node` does NOT reassign validators and causes missed slots.
2. **Update client image tags** - If the user specifies a tag (e.g., "use devnet1 tag"), edit the relevant `lean-quickstart/client-cmds/{client}-cmd.sh` file to update the `node_docker` image tag.
3. **Use run-devnet-with-timeout.sh** - This script runs all nodes in the config with a timeout, dumps logs, then stops them.
4. Run for **20 slots** unless the user specifies otherwise.
5. The script automatically dumps all node logs to `<node_name>.log` files in the repo root and stops the nodes when the timeout expires.

## Timing Calculation

Total timeout = startup buffer + genesis offset + (slots x 4 seconds)

| Component | Local Mode | Ansible Mode |
|-----------|------------|--------------|
| Startup buffer | 10s | 10s |
| Genesis offset | 30s | 360s |
| Per slot | 4s | 4s |

**Examples (local mode):**
- 20 slots: 10 + 30 + (20 x 4) = **120s**
- 50 slots: 10 + 30 + (50 x 4) = **240s**
- 100 slots: 10 + 30 + (100 x 4) = **440s**

## Quick Start (Default Workflow)

**Step 1: Configure nodes** - Edit `lean-quickstart/local-devnet/genesis/validator-config.yaml` to keep only the nodes you want to run. See `references/validator-config.md` for the full schema and field reference.

**Step 2: Update image tags (if needed)** - Edit `lean-quickstart/client-cmds/{client}-cmd.sh` to change the Docker image tag in `node_docker`. See `references/clients.md` for current default tags.

**Step 3: Run the devnet**
```bash
# Start devnet with fresh genesis, capture logs directly (20 slots = 120s)
.claude/skills/devnet-runner/scripts/run-devnet-with-timeout.sh 120
```

## Manual Commands

All `spin-node.sh` commands must be run from within `lean-quickstart/`:

```bash
# Stop all nodes
cd lean-quickstart && NETWORK_DIR=local-devnet ./spin-node.sh --node all --stop

# Run for custom duration (e.g., 50 slots = 240s with genesis offset)
.claude/skills/devnet-runner/scripts/run-devnet-with-timeout.sh 240

# Start without timeout (press Ctrl+C to stop)
cd lean-quickstart && NETWORK_DIR=local-devnet ./spin-node.sh --node all --generateGenesis
```

## Command-Line Flags

| Flag | Description |
|------|-------------|
| `--node <name\|all>` | **Required.** Node(s) to start. Use `all` to start all nodes in config |
| `--generateGenesis` | Regenerate genesis files. Implies `--cleanData` |
| `--cleanData` | Clean data directories before starting |
| `--stop` | Stop running nodes instead of starting them |
| `--forceKeyGen` | Force regeneration of hash-sig validator keys |
| `--validatorConfig <path>` | Custom config path (default: `$NETWORK_DIR/genesis/validator-config.yaml`) |
| `--dockerWithSudo` | Run docker commands with `sudo` |

## Changing Docker Image Tags

To use a specific tag for certain clients, edit the `lean-quickstart/client-cmds/{client}-cmd.sh` files before running.

**Example:** Change zeam from `devnet1` to `local`:
```bash
# In lean-quickstart/client-cmds/zeam-cmd.sh, find:
node_docker="--security-opt seccomp=unconfined blockblaz/zeam:devnet1 node \

# Change to:
node_docker="--security-opt seccomp=unconfined blockblaz/zeam:local node \
```

See `references/clients.md` for current default images, tags, and known compatibility issues.

## Validator Configuration

**ethlambda note:** ethlambda uses separate API (`--api-port`, default 5052) and metrics (`--metrics-port`, default 5054) HTTP servers. The `metricsPort` from config maps to `--metrics-port`; the API port must be configured separately in `ethlambda-cmd.sh`.

See `references/validator-config.md` for the full schema, field reference, adding/removing nodes, port allocation guide, and local vs ansible deployment differences.

## Log Collection

### View Live Logs
```bash
docker logs zeam_0           # View current logs
docker logs -f zeam_0        # Follow/stream logs
```

### Dump Logs to Files

**Automatic:** When using `run-devnet-with-timeout.sh`, logs are automatically dumped to `<node_name>.log` files in the repo root before stopping.

**Single node (manual):**
```bash
docker logs zeam_0 > zeam_0.log 2>&1
```

**All running nodes (manual):**
```bash
for node in $(docker ps --format '{{.Names}}' | grep -E '^(zeam|ream|qlean|lantern|lighthouse|grandine|ethlambda)_'); do
  docker logs "$node" > "${node}.log" 2>&1
done
```

### Data Directory Logs

Client-specific data and file-based logs are stored at:
```
lean-quickstart/local-devnet/data/<node_name>/
```

## Common Troubleshooting

### Nodes Won't Start

1. Check if containers are already running:
   ```bash
   docker ps | grep -E 'zeam|ream|qlean|lantern|lighthouse|grandine|ethlambda'
   ```
2. Stop existing nodes first:
   ```bash
   cd lean-quickstart && NETWORK_DIR=local-devnet ./spin-node.sh --node all --stop
   ```

### Nodes Not Finding Peers

1. Verify all nodes are using the same genesis:
   ```bash
   cd lean-quickstart && NETWORK_DIR=local-devnet ./spin-node.sh --node all --generateGenesis
   ```
2. Check `nodes.yaml` was generated with correct ENR records

### Genesis Mismatch Errors

Regenerate genesis for all nodes:
```bash
cd lean-quickstart && NETWORK_DIR=local-devnet ./spin-node.sh --node all --generateGenesis --forceKeyGen
```

### Port Conflicts

Check if ports are in use:
```bash
lsof -i :9001  # Check QUIC port
lsof -i :8081  # Check metrics port
lsof -i :5052  # Check ethlambda API port (if using default)
```

### Stale Containers Cause Genesis Mismatch

If you see `UnknownSourceBlock` or `OutOfMemory` deserialization errors, a container from a previous run may still be running with old genesis.

**Fix:** Always clean up before starting a new devnet:
```bash
docker rm -f zeam_0 ethlambda_0 ream_0 qlean_0 lantern_0 grandine_0 2>/dev/null
```

Or use `run-devnet-with-timeout.sh` which handles cleanup automatically.

### Docker Permission Issues

```bash
cd lean-quickstart && NETWORK_DIR=local-devnet ./spin-node.sh --node all --dockerWithSudo
```

## Scripts

| Script | Description |
|--------|-------------|
| `scripts/run-devnet-with-timeout.sh <seconds>` | Run devnet for specified duration, dump logs to repo root, then stop |

## Long-Lived Devnets and Rolling Restarts

For persistent devnets on remote servers (e.g., `ssh admin@ethlambda-1`), use detached containers instead of `spin-node.sh`. This allows rolling restarts to upgrade images without losing chain state.

**Key points:**
- Start containers with `docker run -d --restart unless-stopped` (not `spin-node.sh`)
- Rolling restart: stop one node, **wait 60 seconds** (gossipsub backoff), start with new image + checkpoint sync
- Restart non-aggregator nodes first, aggregator last
- Checkpoint sync URL uses the API port: `http://127.0.0.1:<api-port>/lean/v0/states/finalized`

See `references/long-lived-devnet.md` for the full procedure, including starting the devnet, rolling restart steps, verification, and troubleshooting.

## Testing Network Instability

Use `docker pause` to simulate validator failures and observe consensus degradation (finalization stalls, attestation backlog, block processing time increases).

**Quick start:**
```bash
# Pause 2 non-aggregator nodes (causes loss of supermajority, finalization stalls)
docker pause ethlambda_0 ethlambda_1

# Recover
docker unpause ethlambda_0 ethlambda_1
```

See `references/instability-testing.md` for detailed scenarios, data extraction scripts, and analysis procedures.

## Reference

- `references/clients.md`: Client-specific details (images, ports, known issues)
- `references/validator-config.md`: Full config schema, field reference, adding/removing nodes, port allocation
- `references/long-lived-devnet.md`: Persistent devnets with detached containers and rolling restarts
- `references/instability-testing.md`: Simulating validator failures, non-finality, and measuring block processing under load
