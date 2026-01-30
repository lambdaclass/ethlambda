#!/bin/bash

# Cleanup devnet and restore configurations

LEAN_QUICKSTART="${LEAN_QUICKSTART:-/Users/mega/lean_consensus/lean-quickstart}"
ETHLAMBDA_CMD="$LEAN_QUICKSTART/client-cmds/ethlambda-cmd.sh"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Devnet Cleanup ===${NC}"
echo ""

# Stop devnet
echo "Stopping devnet..."
cd "$LEAN_QUICKSTART"
NETWORK_DIR=local-devnet ./spin-node.sh --node all --stop 2>/dev/null || true

# Force remove containers
echo "Removing containers..."
docker rm -f zeam_0 ream_0 qlean_0 ethlambda_0 2>/dev/null || true

echo -e "${GREEN}✓ Devnet stopped${NC}"
echo ""

# Restore config if backup exists
if [[ -f "$ETHLAMBDA_CMD.backup" ]]; then
    echo "Restoring ethlambda-cmd.sh..."
    mv "$ETHLAMBDA_CMD.backup" "$ETHLAMBDA_CMD"
    echo -e "${GREEN}✓ Config restored${NC}"
else
    echo "No backup found, skipping config restore"
fi

echo ""
echo "Cleanup complete!"
