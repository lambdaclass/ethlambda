#!/bin/bash
# Run devnet for a specified number of seconds, dump logs before stopping
#
# Usage: ./run-devnet-with-timeout.sh <seconds>
# Must be run from the ethlambda repo root (where lean-quickstart/ is)

if [ -z "$1" ]; then
    echo "Usage: $0 <seconds>"
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
QUICKSTART_DIR="$REPO_ROOT/lean-quickstart"

if [ ! -d "$QUICKSTART_DIR" ]; then
    echo "Error: lean-quickstart not found at $QUICKSTART_DIR"
    echo "Run 'make lean-quickstart' first to clone it."
    exit 1
fi

cd "$QUICKSTART_DIR"
NETWORK_DIR=local-devnet ./spin-node.sh --node all --generateGenesis 2>&1 | tee "$REPO_ROOT/devnet.log" &
PID=$!
sleep "$1"

# Dump logs from all running node containers before stopping
echo "Dumping node logs..."
for node in $(docker ps --format '{{.Names}}' | grep -E '^(zeam|ream|qlean|lantern|lighthouse|grandine|ethlambda)_'); do
  docker logs "$node" > "$REPO_ROOT/${node}.log" 2>&1
  echo "  Dumped ${node}.log"
done

kill $PID 2>/dev/null
wait $PID 2>/dev/null
