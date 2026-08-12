#!/usr/bin/env bash
# Submit one transaction to ONE node; show a DIFFERENT node included it.
# Repeatable: walks the pre-signed nonces and skips any already spent.
set -uo pipefail
NODES=16
TXDIR=/tmp/demo-txs

head_slot() { curl -s -m 5 "http://127.0.0.1:$((5052 + ${1:-0}))/lean/v0/node/syncing" \
  | grep -o '"head_slot":[0-9]*' | grep -o '[0-9]*'; }

H=$(head_slot 0)
TARGET=$(( H % NODES ))     # the node that just proposed: furthest from proposing again

RAW=""; USED=""
for f in "$TXDIR"/tx-*.hex; do
  CAND=$(tr -d '\n\r ' < "$f")
  RESP=$(curl -sS -m 10 -X POST -H 'content-type: application/json' \
    -d "{\"raw\": \"$CAND\"}" "http://127.0.0.1:$((5052 + TARGET))/lean/v0/admin/el/tx" 2>&1)
  case "$RESP" in
    *tx_hash*)          RAW="$CAND"; USED="$f"; break ;;
    *"Nonce"*|*"nonce"*) continue ;;                      # already spent, try the next
    *)                  echo "submit failed: $RESP"; exit 1 ;;
  esac
done
[ -n "$RAW" ] && echo "head slot $H -> submitted $(basename "$USED") to node $TARGET only" \
  || { echo "all $(ls "$TXDIR" | wc -l) pre-signed nonces are spent; regenerate with more"; exit 1; }
echo "  tx_hash: $(echo "$RESP" | grep -o '"tx_hash":"[^"]*"' | cut -d'"' -f4)"

NEEDLE=$(echo "${RAW#0x}" | tr 'A-Z' 'a-z')
echo "  waiting for inclusion..."
for _ in $(seq 1 15); do
  sleep 4
  for s in $(seq "$H" $((H + 15))); do
    B=$(curl -s -m 5 "http://127.0.0.1:5052/lean/v0/blocks/$s" 2>/dev/null)
    if [ -n "$B" ] && echo "$B" | tr 'A-Z' 'a-z' | grep -q "$NEEDLE"; then
      echo "$B" | TARGET="$TARGET" python3 -c "
import sys,json,os
d=json.load(sys.stdin); p=d['body']['execution_payload']; t=os.environ['TARGET']
print(f\"  INCLUDED in slot {d['slot']} by node {d['proposer_index']}\")
print(f\"  submitted to node {t}  ->  included by node {d['proposer_index']}\")
print(f\"  elBlock {int(p['blockNumber'],16)}  gasUsed {int(p['gasUsed'],16)}  txs {len(p['transactions'])}\")"
      exit 0
    fi
  done
done
echo "  not found within the window"; exit 1
