---
name: devnet-runner
description: Manage local development networks for lean consensus testing. Use when users want to (1) Configure a devnet with validator nodes, (2) Start/stop devnet nodes, (3) Regenerate genesis files, (4) Collect and dump node logs to files, (5) Troubleshoot devnet issues.
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
1. **Update validator config** - Edit `lean-quickstart/local-devnet/genesis/validator-config.yaml` to include ONLY the nodes that will run. Remove entries for nodes that won't be started (unless the user explicitly asks to keep them). This is critical because validator indices are assigned to ALL nodes in the config - if a node is in the config but not running, its validators will miss their proposer slots.
2. **Update client image tags** - If the user specifies a tag (e.g., "use devnet1 tag"), edit the relevant `lean-quickstart/client-cmds/{client}-cmd.sh` file to update the `node_docker` image tag.
3. **Use run-devnet-with-timeout.sh** - This script runs all nodes in the config with a timeout, dumps logs, then stops them. Do NOT use `--node <specific>` to select nodes - this does not reassign validators.
4. Run for **20 slots** unless the user specifies otherwise
5. The script automatically dumps all node logs to `<node_name>.log` files in the repo root and stops the nodes when the timeout expires

**Important:** Only use `--node <specific>` (e.g., `--node zeam_0,ream_0`) if the user explicitly requests it. This flag starts only the specified nodes but does NOT reassign their validators, causing missed slots.

This ensures consistent test runs, clean logs without spurious warnings, and captured output for debugging.

## Timing Calculation

Total timeout = startup buffer + genesis offset + (slots × 4 seconds)

| Component | Local Mode | Ansible Mode |
|-----------|------------|--------------|
| Startup buffer | 10s | 10s |
| Genesis offset | 30s | 360s |
| Per slot | 4s | 4s |

**Examples (local mode):**
- 20 slots: 10 + 30 + (20 × 4) = **120s**
- 50 slots: 10 + 30 + (50 × 4) = **240s**
- 100 slots: 10 + 30 + (100 × 4) = **440s**

## Quick Start (Default Workflow)

**Step 1: Configure nodes** - Edit `lean-quickstart/local-devnet/genesis/validator-config.yaml` to keep only the nodes you want to run. Remove all other validator entries. This is critical because validator indices are assigned based on all nodes in the config - if a node is in the config but not running, its validators will miss their slots.

**Step 2: Update image tags (if needed)** - Edit `lean-quickstart/client-cmds/{client}-cmd.sh` to change the Docker image tag in `node_docker`.

**Step 3: Run the devnet**
```bash
# Start devnet with fresh genesis, capture logs directly (20 slots = 120s)
.claude/skills/devnet-runner/scripts/run-devnet-with-timeout.sh 120

# Stop any remaining nodes (cleanup)
cd lean-quickstart && NETWORK_DIR=local-devnet ./spin-node.sh --node all --stop 2>/dev/null || true
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

### Using --node to Select Specific Nodes (Advanced)

**WARNING:** Only use `--node <specific>` if the user explicitly requests it. This flag does NOT reassign validators - nodes not selected will still have validators assigned to them in the genesis, causing missed slots.

```bash
# Only use if explicitly requested by user
cd lean-quickstart && NETWORK_DIR=local-devnet ./spin-node.sh --node zeam_0,ream_0
```

For normal operation, always modify `validator-config.yaml` to include only the nodes you want, then use `run-devnet-with-timeout.sh` or `--node all`.

## Command-Line Flags

| Flag | Description |
|------|-------------|
| `--node <name\|all>` | **Required.** Node(s) to start. Use `all` to start all nodes in config. **Note:** Using specific node names (e.g., `--node zeam_0,ream_0`) does NOT reassign validators - use only if explicitly requested |
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

**Current default tags:**
| Client | Image | Default Tag |
|--------|-------|-------------|
| zeam | blockblaz/zeam | devnet1 |
| ream | ghcr.io/reamlabs/ream | latest |
| ethlambda | ghcr.io/lambdaclass/ethlambda | local |
| qlean | qdrvm/qlean-mini | 3a96a1f |
| lantern | piertwo/lantern | v0.0.1 |
| lighthouse | hopinheimer/lighthouse | latest |
| grandine | sifrai/lean | unstable |

## Configuration Workflow

### Validator Config File Structure

The config file is at `lean-quickstart/local-devnet/genesis/validator-config.yaml`. This is the **single source of truth** for all node configurations.

**Important:** Only include clients that will actually run in the devnet. If a configured validator is offline from the start, it will miss its proposer slots and affect consensus progress. Only include offline validators if you specifically want to test behavior with missing nodes.

**Full schema:**
```yaml
shuffle: roundrobin              # Proposer selection algorithm (roundrobin = deterministic turns)
deployment_mode: local           # 'local' (localhost) or 'ansible' (remote servers)

config:
  activeEpoch: 18                # Log2 of active signing epochs for hash-sig keys (2^18)
  keyType: "hash-sig"            # Post-quantum signature scheme

validators:
  - name: "zeam_0"               # Node identifier: <client>_<index>
    privkey: "bdf953adc..."      # 64-char hex P2P private key (libp2p identity)
    enrFields:
      ip: "127.0.0.1"            # Node IP (127.0.0.1 for local, real IP for ansible)
      quic: 9001                 # QUIC/UDP port for P2P communication
    metricsPort: 8081            # Prometheus metrics endpoint port
    count: 1                     # Number of validator indices assigned to this node
```

**Field reference:**

| Field | Required | Description |
|-------|----------|-------------|
| `shuffle` | Yes | Proposer selection algorithm. Use `roundrobin` for deterministic turn-based proposing |
| `deployment_mode` | Yes | `local` or `ansible` - determines genesis time offset and config directory |
| `config.activeEpoch` | Yes | Exponent for hash-sig active epochs (e.g., 18 means 2^18 signatures per period) |
| `config.keyType` | Yes | Always `hash-sig` for post-quantum support |
| `name` | Yes | Format: `<client>_<index>`. Client name determines which `client-cmds/*.sh` script runs |
| `privkey` | Yes | 32-byte hex string (64 chars). Used for P2P identity and ENR generation |
| `enrFields.ip` | Yes | IP address. Use `127.0.0.1` for local, real IPs for ansible |
| `enrFields.quic` | Yes | QUIC port. Must be unique per node in local mode |
| `metricsPort` | Yes | Prometheus metrics port. Must be unique per node in local mode |
| `count` | Yes | Number of validator indices. Sum of all counts = total validators |

### Adding a New Validator Node

1. **Choose a unique node name** following `<client>_<index>` convention:
   ```
   zeam_0, zeam_1, ream_0, qlean_0, lantern_0, lighthouse_0, grandine_0, ethlambda_0
   ```

2. **Generate a P2P private key** (64-char hex):
   ```bash
   openssl rand -hex 32
   ```

3. **Assign unique ports** (for local mode):
   - QUIC: 9001, 9002, 9003... (increment for each node)
   - Metrics: 8081, 8082, 8083... (increment for each node)

4. **Add the entry to `lean-quickstart/local-devnet/genesis/validator-config.yaml`:**
   ```yaml
   validators:
     # ... existing nodes ...

     - name: "newclient_0"
       privkey: "<your-64-char-hex-key>"
       enrFields:
         ip: "127.0.0.1"          # Use real IP for ansible
         quic: 9008               # Next available port
       metricsPort: 8088          # Next available port
       count: 1
   ```

5. **Regenerate genesis with new keys:**
   ```bash
   cd lean-quickstart && NETWORK_DIR=local-devnet ./spin-node.sh --node all --generateGenesis --forceKeyGen
   ```

### Removing a Validator Node

1. **Delete the node entry** from `lean-quickstart/local-devnet/genesis/validator-config.yaml`

2. **Regenerate genesis** (required because genesis state must reflect new validator set):
   ```bash
   cd lean-quickstart && NETWORK_DIR=local-devnet ./spin-node.sh --node all --generateGenesis
   ```
   Note: `--forceKeyGen` is NOT needed when removing - existing keys for remaining indices are reused.

### Port Allocation Guide (Local Mode)

When running multiple nodes locally, each needs unique ports:

| Node | QUIC Port | Metrics Port |
|------|-----------|--------------|
| zeam_0 | 9001 | 8081 |
| ream_0 | 9002 | 8082 |
| qlean_0 | 9003 | 8083 |
| lantern_0 | 9004 | 8084 |
| lighthouse_0 | 9005 | 8085 |
| grandine_0 | 9006 | 8086 |
| ethlambda_0 | 9007 | 8087 |

For **ansible mode**, all nodes can use the same ports (9001, 8081) since they run on different machines.

### Local vs Ansible Deployment

| Aspect | Local | Ansible |
|--------|-------|---------|
| Config file | `lean-quickstart/local-devnet/genesis/validator-config.yaml` | `lean-quickstart/ansible-devnet/genesis/validator-config.yaml` |
| `deployment_mode` | `local` | `ansible` |
| IP addresses | `127.0.0.1` for all | Real server IPs |
| Ports | Must be unique per node | Same port, different machines |
| Genesis offset | +30 seconds | +360 seconds |

## Node Lifecycle Commands

### Start Nodes

**Preferred method:** Use `run-devnet-with-timeout.sh` after configuring `validator-config.yaml`:
```bash
# Edit lean-quickstart/local-devnet/genesis/validator-config.yaml to include only nodes you want, then:
.claude/skills/devnet-runner/scripts/run-devnet-with-timeout.sh 120
```

**Alternative (no timeout):**
```bash
# All nodes in config
cd lean-quickstart && NETWORK_DIR=local-devnet ./spin-node.sh --node all

# Fresh start with new genesis
cd lean-quickstart && NETWORK_DIR=local-devnet ./spin-node.sh --node all --generateGenesis
```

**Advanced (only if explicitly requested):** Start specific nodes without modifying config. Note: validators will NOT be reassigned.
```bash
cd lean-quickstart && NETWORK_DIR=local-devnet ./spin-node.sh --node zeam_0,ream_0
```

### Stop Nodes
```bash
# Via script
cd lean-quickstart && NETWORK_DIR=local-devnet ./spin-node.sh --node all --stop

# Or press Ctrl+C in the terminal running spin-node.sh
```

### Clean and Restart
```bash
cd lean-quickstart && NETWORK_DIR=local-devnet ./spin-node.sh --node all --cleanData
```

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

**Follow and save simultaneously:**
```bash
docker logs -f zeam_0 2>&1 | tee zeam_0.log
```

**With timestamps:**
```bash
docker logs -t zeam_0 > zeam_0.log 2>&1
```

### Data Directory Logs

Client-specific data and file-based logs are stored at:
```
lean-quickstart/local-devnet/data/<node_name>/
```
Example: `lean-quickstart/local-devnet/data/zeam_0/`

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
```

Update ports in `lean-quickstart/local-devnet/genesis/validator-config.yaml` if needed.

### Docker Permission Issues

Run with sudo:
```bash
cd lean-quickstart && NETWORK_DIR=local-devnet ./spin-node.sh --node all --dockerWithSudo
```

### Stale Containers Cause Genesis Mismatch

If you see `UnknownSourceBlock` or `OutOfMemory` deserialization errors, a container from a previous run may still be running with old genesis.

**Fix:** Always clean up before starting a new devnet:
```bash
docker rm -f zeam_0 ethlambda_0 ream_0 qlean_0 lantern_0 grandine_0 2>/dev/null
```

Or use `run-devnet-with-timeout.sh` which handles cleanup automatically.

### Time-Based Stop

Use the `run-devnet-with-timeout.sh` script for timed runs. Remember to include genesis offset (30s local, 360s ansible) + startup buffer (10s):

```bash
# 20 slots: 10 + 30 + 80 = 120s
.claude/skills/devnet-runner/scripts/run-devnet-with-timeout.sh 120

# 50 slots: 10 + 30 + 200 = 240s
.claude/skills/devnet-runner/scripts/run-devnet-with-timeout.sh 240

# 100 slots: 10 + 30 + 400 = 440s
.claude/skills/devnet-runner/scripts/run-devnet-with-timeout.sh 440
```

**Formula:** duration = 10 + 30 + (slots × 4) seconds (local mode)

## Scripts

| Script | Description |
|--------|-------------|
| `scripts/run-devnet-with-timeout.sh <seconds>` | Run devnet for specified duration, dump logs to repo root, then stop |

## Reference

See `references/clients.md` for client-specific details (images, ports, configurations).
