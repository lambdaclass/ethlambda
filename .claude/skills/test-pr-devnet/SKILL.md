---
name: test-pr-devnet
description: Test ethlambda PR changes in multi-client devnet. Use when users want to (1) Test a branch/PR with other Lean clients, (2) Validate BlocksByRoot or P2P protocol changes, (3) Test sync recovery with pause/unpause, (4) Verify cross-client interoperability, (5) Run integration tests before merging.
disable-model-invocation: true
---

# Test PR in Devnet

Test ethlambda branch changes in a multi-client local devnet with zeam (Zig), ream (Rust), qlean (C++), and ethlambda.

## Quick Start

```bash
# Test current branch (basic interoperability, ~60-90s)
.claude/skills/test-pr-devnet/scripts/test-branch.sh

# Test with sync recovery (BlocksByRoot validation, ~90-120s)
.claude/skills/test-pr-devnet/scripts/test-branch.sh --with-sync-test

# Test specific branch
.claude/skills/test-pr-devnet/scripts/test-branch.sh my-feature-branch

# Check status while running
.claude/skills/test-pr-devnet/scripts/check-status.sh

# Cleanup when done
.claude/skills/test-pr-devnet/scripts/cleanup.sh
```

## What It Does

1. **Builds branch-specific Docker image** tagged as `ghcr.io/lambdaclass/ethlambda:<branch-name>`
2. **Updates lean-quickstart config** to use new image (backs up original)
3. **Starts 4-node devnet** with fresh genesis (zeam, ream, qlean, ethlambda)
4. **Optionally tests sync recovery** by pausing/unpausing nodes
5. **Analyzes results** and provides summary
6. **Leaves devnet running** for manual inspection

## Prerequisites

| Requirement | Location | Check |
|-------------|----------|-------|
| lean-quickstart | `/Users/mega/lean_consensus/lean-quickstart` | `ls $LEAN_QUICKSTART` |
| Docker running | - | `docker ps` |
| Git repository | ethlambda root | `git branch` |

## Test Scenarios

### Basic Interoperability (~60-90s)

**Goal:** Verify ethlambda produces blocks and reaches consensus with other clients

**Success criteria:**
- ✅ No errors in ethlambda logs
- ✅ All 4 nodes at same head slot
- ✅ Finalization advancing (every 6-12 slots)
- ✅ Each validator produces blocks for their slots

### Sync Recovery (~90-120s)

**Goal:** Test BlocksByRoot request/response when nodes fall behind

**Usage:** Add `--with-sync-test` flag

**What happens:**
1. Devnet runs for 10s (~2-3 slots)
2. Pauses `zeam_0` and `qlean_0`
3. Network progresses 20s (~5 slots)
4. Unpauses nodes → nodes sync

**Success criteria:**
- ✅ Inbound BlocksByRoot requests logged
- ✅ Successful responses sent
- ✅ Paused nodes sync to current head

## Configuration Changes

The skill modifies `lean-quickstart/client-cmds/ethlambda-cmd.sh` to use your branch's Docker image.

**Automatic backup:** Creates `ethlambda-cmd.sh.backup`

**Restore methods:**
```bash
# 1. Cleanup script (recommended)
.claude/skills/test-pr-devnet/scripts/cleanup.sh

# 2. Manual restore
mv $LEAN_QUICKSTART/client-cmds/ethlambda-cmd.sh.backup \
   $LEAN_QUICKSTART/client-cmds/ethlambda-cmd.sh

# 3. Git restore (if no uncommitted changes)
cd $LEAN_QUICKSTART && git checkout client-cmds/ethlambda-cmd.sh
```

## Manual Workflow (Alternative to Script)

If you need fine-grained control:

### 1. Build Image

```bash
cd /Users/mega/lean_consensus/ethlambda
BRANCH=$(git rev-parse --abbrev-ref HEAD)
docker build \
    --build-arg GIT_COMMIT=$(git rev-parse HEAD) \
    --build-arg GIT_BRANCH=$BRANCH \
    -t ghcr.io/lambdaclass/ethlambda:$BRANCH .
```

### 2. Update Configuration

Edit `$LEAN_QUICKSTART/client-cmds/ethlambda-cmd.sh` line 17:
```bash
node_docker="ghcr.io/lambdaclass/ethlambda:<your-branch> \
```

### 3. Start Devnet

```bash
cd $LEAN_QUICKSTART
NETWORK_DIR=local-devnet ./spin-node.sh --node all --generateGenesis --metrics
```

### 4. Test Sync (Optional)

```bash
# Create sync gap
docker pause zeam_0 qlean_0
sleep 20  # Network progresses

# Test recovery
docker unpause zeam_0 qlean_0
sleep 10  # Wait for sync
```

### 5. Check Results

```bash
# Quick status
.claude/skills/test-pr-devnet/scripts/check-status.sh

# Detailed analysis (use devnet-log-review skill in lean-quickstart)
cd $LEAN_QUICKSTART
.claude/skills/devnet-log-review/scripts/analyze-logs.sh
```

## Protocol Compatibility

| Client | Status | Gossipsub | BlocksByRoot |
|--------|--------|-----------|--------------|
| ream | ✅ Full | ✅ Full | ✅ Full |
| zeam | ✅ Full | ✅ Full | ⚠️ Limited |
| qlean | ✅ Full | ✅ Full | ⚠️ Limited |
| ethlambda | ✅ Full | ✅ Full | ✅ Full |

**Notes:**
- zeam/qlean BlocksByRoot errors are expected (not a blocker)
- ream ↔ ethlambda BlocksByRoot should work perfectly
- All clients use Gossipsub for block propagation

## Verification Checklist

| Check | Command | Expected |
|-------|---------|----------|
| All nodes running | `docker ps --filter "name=_0"` | 4 containers |
| Peers connected | `docker logs ethlambda_0 \| grep "Received status request" \| wc -l` | > 10 |
| Blocks produced | `docker logs ethlambda_0 \| grep "Published block" \| wc -l` | > 0 |
| No errors | `docker logs ethlambda_0 \| grep ERROR \| wc -l` | 0 |

## Troubleshooting

### Build Fails
```bash
docker ps  # Check Docker running
docker system prune -a  # Clean cache if needed
```

### Nodes Won't Start
```bash
# Clean and retry
docker stop zeam_0 ream_0 qlean_0 ethlambda_0 2>/dev/null
docker rm zeam_0 ream_0 qlean_0 ethlambda_0 2>/dev/null
cd $LEAN_QUICKSTART
NETWORK_DIR=local-devnet ./spin-node.sh --node all --generateGenesis
```

### Genesis Mismatch
```bash
cd $LEAN_QUICKSTART
NETWORK_DIR=local-devnet ./spin-node.sh --node all --cleanData --generateGenesis
```

### Image Tag Not Updated
```bash
# Verify the change
grep "node_docker=" $LEAN_QUICKSTART/client-cmds/ethlambda-cmd.sh
# Should show your branch name, not :local
```

### Port Already in Use
```bash
docker stop $(docker ps -q --filter "name=_0") 2>/dev/null || true
```

## Debugging

### P2P Request/Response Debugging

```bash
# Check inbound BlocksByRoot handling
docker logs ethlambda_0 2>&1 | grep "Received BlocksByRoot request"
docker logs ethlambda_0 2>&1 | grep "Responding to BlocksByRoot"

# Check outbound BlocksByRoot requests
docker logs ethlambda_0 2>&1 | grep "Sending BlocksByRoot request"
docker logs ethlambda_0 2>&1 | grep "Received BlocksByRoot response"

# Check for protocol errors
docker logs ethlambda_0 2>&1 | grep -E "Outbound request failed|protocol.*not.*support"

# Count requests/responses
docker logs ethlambda_0 2>&1 | grep "Received BlocksByRoot request" | wc -l
```

### Devnet Status Checks

```bash
# Check all nodes are running
docker ps --format "{{.Names}}: {{.Status}}" --filter "name=_0"

# Get current chain status (zeam)
docker logs zeam_0 2>&1 | tail -100 | grep "CHAIN STATUS" | tail -1

# Get fork choice updates (ethlambda)
docker logs ethlambda_0 2>&1 | grep "Fork choice head updated" | tail -5

# Check peer connectivity
docker logs ethlambda_0 2>&1 | grep "Received status request" | wc -l
```

### Common Investigation Patterns

```bash
# Verify ethlambda is proposing blocks
docker logs ethlambda_0 2>&1 | grep "We are the proposer"

# Compare finalized slots across clients
for node in zeam_0 ream_0 ethlambda_0; do
    echo "$node:"
    docker logs "$node" 2>&1 | grep -i "finalized" | tail -1
done

# Check peer discovery
docker logs ethlambda_0 2>&1 | grep -i "peer\|connection" | head -20
```

## References

- **[ethlambda CLAUDE.md](../../CLAUDE.md)** - Development workflow, detailed debugging commands
- **[lean-quickstart devnet-log-review](../../../lean-quickstart/.claude/skills/devnet-log-review/SKILL.md)** - Comprehensive log analysis
