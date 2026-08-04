#!/bin/bash
# HOST-side: summarise this host's slice of a cross-server devnet. The skill's
# host-check.sh assumes nodes 0..N-1; a host owning 32-63 needs a range.
# Usage: check-range.sh START END
set -u
START=$1; END=$2
printf "%-12s %-8s %6s %6s %6s %5s %4s %6s\n" NODE STATUS HEAD JUST FIN PEERS AGG RESTRT
bad=0
for n in $(seq "$START" "$END"); do
  c=$(sudo docker ps -a --format '{{.Names}}' | grep -E "_${n}$" | head -1)
  [ -z "$c" ] && { printf "%-12s %-8s\n" "node_$n" MISSING; bad=1; continue; }
  st=$(sudo docker inspect "$c" --format '{{.State.Status}}')
  rs=$(sudo docker inspect "$c" --format '{{.RestartCount}}')
  m=$(curl -s --max-time 3 "localhost:$((9200+n))/metrics" 2>/dev/null)
  g(){ echo "$m" | awk -v k="$1" '$1==k{printf "%d", $2; exit}'; }
  head=$(g lean_head_slot); just=$(g lean_latest_justified_slot); fin=$(g lean_latest_finalized_slot)
  agg=$(g lean_is_aggregator); peers=$(echo "$m" | grep -c '^lean_connected_peers')
  printf "%-12s %-8s %6s %6s %6s %5s %4s %6s\n" "node_$n" "$st" "${head:--}" "${just:--}" "${fin:--}" "$peers" "${agg:-0}" "$rs"
  [ "$st" != running ] && bad=1
  [ -z "$head" ] && bad=1
done
exit $bad
