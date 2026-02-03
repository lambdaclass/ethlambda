#!/bin/bash
set -euo pipefail

# Test ethlambda branch in multi-client devnet
# Usage: ./test-branch.sh [branch-name] [--with-sync-test]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ETHLAMBDA_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
LEAN_QUICKSTART="${LEAN_QUICKSTART:-/Users/mega/lean_consensus/lean-quickstart}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
BRANCH_NAME=""
WITH_SYNC_TEST=false

# First positional arg is branch name (if not a flag)
for arg in "$@"; do
    if [[ "$arg" == "--with-sync-test" ]]; then
        WITH_SYNC_TEST=true
    elif [[ -z "$BRANCH_NAME" ]]; then
        BRANCH_NAME="$arg"
    fi
done

# Default to current branch if not specified
if [[ -z "$BRANCH_NAME" ]]; then
    BRANCH_NAME=$(git -C "$ETHLAMBDA_ROOT" rev-parse --abbrev-ref HEAD)
fi

echo -e "${BLUE}=== ethlambda Devnet Testing ===${NC}"
echo ""
echo "Branch: $BRANCH_NAME"
echo "Sync test: $WITH_SYNC_TEST"
echo "ethlambda root: $ETHLAMBDA_ROOT"
echo "lean-quickstart: $LEAN_QUICKSTART"
echo ""

# Validate prerequisites
echo "Validating prerequisites..."

if [[ ! -d "$LEAN_QUICKSTART" ]]; then
    echo -e "${RED}✗ Error: lean-quickstart not found at $LEAN_QUICKSTART${NC}"
    echo "  Set LEAN_QUICKSTART environment variable or clone it:"
    echo "  git clone https://github.com/blockblaz/lean-quickstart.git"
    exit 1
fi

if [[ ! -f "$LEAN_QUICKSTART/spin-node.sh" ]]; then
    echo -e "${RED}✗ Error: spin-node.sh not found in lean-quickstart${NC}"
    exit 1
fi

if ! docker info &>/dev/null; then
    echo -e "${RED}✗ Error: Docker is not running${NC}"
    echo "  Start Docker Desktop or docker daemon"
    exit 1
fi

if [[ ! -d "$ETHLAMBDA_ROOT/.git" ]]; then
    echo -e "${RED}✗ Error: Not in a git repository${NC}"
    echo "  Run this script from ethlambda repository root"
    exit 1
fi

echo -e "${GREEN}✓ Prerequisites validated${NC}"
echo ""

# Step 1: Build Docker image
echo -e "${BLUE}[1/6] Building Docker image...${NC}"
cd "$ETHLAMBDA_ROOT"
GIT_COMMIT=$(git rev-parse HEAD)

docker build \
    --build-arg GIT_COMMIT="$GIT_COMMIT" \
    --build-arg GIT_BRANCH="$BRANCH_NAME" \
    -t "ghcr.io/lambdaclass/ethlambda:$BRANCH_NAME" \
    .

echo -e "${GREEN}✓ Image built: ghcr.io/lambdaclass/ethlambda:$BRANCH_NAME${NC}"
echo ""

# Step 2: Update ethlambda-cmd.sh
echo -e "${BLUE}[2/6] Updating lean-quickstart config...${NC}"
ETHLAMBDA_CMD="$LEAN_QUICKSTART/client-cmds/ethlambda-cmd.sh"

# Backup original
cp "$ETHLAMBDA_CMD" "$ETHLAMBDA_CMD.backup"

# Update docker tag
sed -i.tmp "s|ghcr.io/lambdaclass/ethlambda:[^ ]*|ghcr.io/lambdaclass/ethlambda:$BRANCH_NAME|" "$ETHLAMBDA_CMD"
rm "$ETHLAMBDA_CMD.tmp"

echo -e "${GREEN}✓ Updated $ETHLAMBDA_CMD${NC}"
echo "  (Backup saved as $ETHLAMBDA_CMD.backup)"
echo ""

# Step 3: Stop any existing devnet
echo -e "${BLUE}[3/6] Cleaning up existing devnet...${NC}"
cd "$LEAN_QUICKSTART"
NETWORK_DIR=local-devnet ./spin-node.sh --node all --stop 2>/dev/null || true
docker rm -f zeam_0 ream_0 qlean_0 ethlambda_0 2>/dev/null || true

echo -e "${GREEN}✓ Cleanup complete${NC}"
echo ""

# Step 4: Start devnet
echo -e "${BLUE}[4/6] Starting devnet...${NC}"
echo "This will take ~40 seconds (genesis generation + startup)"
echo ""

# Run devnet in background
NETWORK_DIR=local-devnet ./spin-node.sh --node all --generateGenesis --metrics > /tmp/devnet-$BRANCH_NAME.log 2>&1 &
DEVNET_PID=$!

# Wait for nodes to start (check docker ps)
echo -n "Waiting for nodes to start"
for i in {1..40}; do
    sleep 1
    echo -n "."
    if [[ $(docker ps --filter "name=_0" --format "{{.Names}}" | wc -l) -eq 4 ]]; then
        echo ""
        echo -e "${GREEN}✓ All 4 nodes running${NC}"
        break
    fi
done
echo ""

# Show node status
docker ps --format "  {{.Names}}: {{.Status}}" --filter "name=_0"
echo ""

# Step 5: Sync recovery test (optional)
if [[ "$WITH_SYNC_TEST" == "true" ]]; then
    echo -e "${BLUE}[5/6] Testing sync recovery...${NC}"

    # Let devnet run for a bit
    echo "Letting devnet run for 10 seconds..."
    sleep 10

    # Pause nodes
    echo "Pausing zeam_0 and qlean_0..."
    docker pause zeam_0 qlean_0
    echo -e "${YELLOW}⏸  Nodes paused${NC}"

    # Wait for network to progress
    echo "Network progressing for 20 seconds (~5 slots)..."
    sleep 20

    # Unpause
    echo "Unpausing nodes..."
    docker unpause zeam_0 qlean_0
    echo -e "${GREEN}▶  Nodes resumed${NC}"

    # Wait for sync
    echo "Waiting 10 seconds for sync recovery..."
    sleep 10

    echo -e "${GREEN}✓ Sync recovery test complete${NC}"
    echo ""
else
    echo -e "${BLUE}[5/6] Skipping sync recovery test${NC}"
    echo "Use --with-sync-test to enable"
    echo ""

    # Just let it run for a bit
    echo "Letting devnet run for 30 seconds..."
    sleep 30
fi

# Step 6: Analyze results
echo -e "${BLUE}[6/6] Analyzing results...${NC}"
echo ""

# Quick status check
echo "=== Quick Status ==="
echo ""

# Check each node
for node in zeam_0 ream_0 qlean_0 ethlambda_0; do
    if docker ps --format "{{.Names}}" | grep -q "^$node$"; then
        echo -e "${GREEN}✓${NC} $node: Running"
    else
        echo -e "${RED}✗${NC} $node: Not running"
    fi
done
echo ""

# Check ethlambda specifics
echo "=== ethlambda Status ==="
echo ""

# Get latest head
LATEST_HEAD=$(docker logs ethlambda_0 2>&1 | grep "Fork choice head updated" | tail -1 || echo "No head updates found")
echo "$LATEST_HEAD"
echo ""

# Count peer interactions
PEER_COUNT=$(docker logs ethlambda_0 2>&1 | grep "Received status request" | wc -l | tr -d ' ')
echo "Peer interactions: $PEER_COUNT"

# Count blocks
BLOCKS_PUBLISHED=$(docker logs ethlambda_0 2>&1 | grep "Published block" | wc -l | tr -d ' ')
echo "Blocks published: $BLOCKS_PUBLISHED"

# Count errors
ERROR_COUNT=$(docker logs ethlambda_0 2>&1 | grep -c "ERROR" || echo "0")
if [[ "$ERROR_COUNT" -eq 0 ]]; then
    echo -e "Errors: ${GREEN}$ERROR_COUNT${NC}"
else
    echo -e "Errors: ${RED}$ERROR_COUNT${NC}"
fi
echo ""

# BlocksByRoot stats (if sync test was run)
if [[ "$WITH_SYNC_TEST" == "true" ]]; then
    echo "=== BlocksByRoot Activity ==="
    echo ""

    INBOUND=$(docker logs ethlambda_0 2>&1 | grep "Received BlocksByRoot request" | wc -l | tr -d ' ')
    RESPONSES=$(docker logs ethlambda_0 2>&1 | grep "Responding to BlocksByRoot" | wc -l | tr -d ' ')
    OUTBOUND=$(docker logs ethlambda_0 2>&1 | grep "Sending BlocksByRoot request" | wc -l | tr -d ' ')

    echo "Inbound requests: $INBOUND"
    echo "Responses sent: $RESPONSES"
    echo "Outbound requests: $OUTBOUND"
    echo ""
fi

# Final verdict
echo "=== Test Result ==="
echo ""
if [[ "$ERROR_COUNT" -eq 0 ]] && [[ "$PEER_COUNT" -gt 0 ]]; then
    echo -e "${GREEN}✓ PASSED${NC} - Devnet running successfully"
else
    echo -e "${YELLOW}⚠ CHECK LOGS${NC} - Some issues detected"
fi
echo ""

# Next steps
echo "=== Next Steps ==="
echo ""
echo "Check detailed logs:"
echo "  docker logs ethlambda_0 2>&1 | less"
echo ""
echo "Run log analysis:"
echo "  cd $LEAN_QUICKSTART"
echo "  .claude/skills/devnet-log-review/scripts/analyze-logs.sh"
echo ""
echo "Stop devnet:"
echo "  cd $LEAN_QUICKSTART"
echo "  NETWORK_DIR=local-devnet ./spin-node.sh --node all --stop"
echo ""
echo "Restore config:"
echo "  mv $ETHLAMBDA_CMD.backup $ETHLAMBDA_CMD"
echo ""

# Keep devnet running
echo -e "${YELLOW}Devnet is still running. Stop it when done testing.${NC}"
