#!/bin/bash

# Quick devnet status check

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Devnet Status ===${NC}"
echo ""

# Check running nodes
echo "Running nodes:"
docker ps --format "  {{.Names}}: {{.Status}}" --filter "name=_0"
echo ""

# Check each node's latest status
for node in zeam_0 ream_0 qlean_0 ethlambda_0; do
    if docker ps --format "{{.Names}}" | grep -q "^$node$"; then
        echo -e "${GREEN}$node${NC}:"

        case $node in
            zeam_0)
                docker logs zeam_0 2>&1 | tail -100 | grep "CHAIN STATUS" | tail -1 | sed 's/^/  /'
                ;;
            ethlambda_0)
                docker logs ethlambda_0 2>&1 | grep "Fork choice head updated" | tail -1 | sed 's/^/  /'
                ;;
            *)
                echo "  (check logs manually)"
                ;;
        esac
        echo ""
    fi
done

# Check peer connectivity
if docker ps --format "{{.Names}}" | grep -q "^ethlambda_0$"; then
    PEERS=$(docker logs ethlambda_0 2>&1 | grep "Received status request" | wc -l | tr -d ' ')
    echo "ethlambda peer interactions: $PEERS"
    echo ""
fi

# Quick error check
echo "Error counts:"
for node in zeam_0 ream_0 qlean_0 ethlambda_0; do
    if docker ps --format "{{.Names}}" | grep -q "^$node$"; then
        COUNT=$(docker logs "$node" 2>&1 | grep -c "ERROR" || echo "0")
        if [[ "$COUNT" -eq 0 ]]; then
            echo -e "  $node: ${GREEN}$COUNT${NC}"
        else
            echo -e "  $node: ${RED}$COUNT${NC}"
        fi
    fi
done
