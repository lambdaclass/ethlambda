#!/bin/bash
# Per-host: is every node of THIS devnet up and following the chain?
#
# The local counterpart to sweep.sh. sweep.sh reads the CENTRAL Prometheus, which
# is unavailable exactly when it matters most (this host's remote_write is down, or
# the central stack lives on a host that went dark). This one talks only to
# 127.0.0.1, so it works on a host that is otherwise cut off, and it is the check
# to run right after start-devnet.sh / cs-restart.sh / convert.sh.
#
# Client-agnostic: every lean client exports the same `lean_*` metrics, so a
# converted node reports in the same columns.
#
# Usage (on host):  host-check.sh [NODES]
#   NODES  expected node count; indices 0..NODES-1 with no container are reported
#          as MISSING. Omit to probe only the containers that exist.
#
# Exit status: 0 all good, 1 something needs attention (container not running or
# missing, metrics unreachable, or a head lagging this host's best by more than the
# sync-gate threshold -- past which the node stops attesting and proposing).
set -u
LAG_THRESHOLD=${LAG_THRESHOLD:-4}   # SYNC_LAG_THRESHOLD, crates/blockchain/src/sync_status.rs
EXPECTED=${1:-}

# Scrape one node's own metrics port. lean_connected_peers is one series PER PEER,
# so the peer count is the number of non-zero series.
probe(){ # $1 = node index -> "head just fin sync agg peers"
  curl -s -m 3 "http://127.0.0.1:$((9200+$1))/metrics" 2>/dev/null | awk '
    /^lean_head_slot[ {]/             { head=$NF }
    /^lean_latest_justified_slot[ {]/ { just=$NF }
    /^lean_latest_finalized_slot[ {]/ { fin=$NF }
    /^lean_is_aggregator[ {]/         { agg=($NF==1?"yes":"no") }
    /^lean_node_sync_status\{/        { if ($NF==1) { match($0,/status="[^"]+"/)
                                        sync=substr($0,RSTART+8,RLENGTH-9) } }
    /^lean_connected_peers[ {]/       { if ($NF!=0) peers++ }
    END { printf "%s %s %s %s %s %s", (head==""?"-":head), (just==""?"-":just),
                 (fin==""?"-":fin), (sync==""?"-":sync), (agg==""?"-":agg), peers+0 }'
}

# One TSV record per node: idx name status restarts head just fin sync agg peers.
# Node containers are <client>_<index>; infra (prometheus/promtail/cadvisor) has no
# _<digit> suffix and is skipped.
records=""
add_record(){ records="${records}$1"$'\n'; }

seen=""
while read -r nm status; do
  idx=${nm##*_}
  case "$nm" in *_*) ;; *) continue ;; esac
  case "$idx" in ''|*[!0-9]*) continue ;; esac
  seen="$seen $idx"
  rs=$(sudo docker inspect -f '{{.RestartCount}}' "$nm" 2>/dev/null)
  add_record "$(printf '%s\t%s\t%s\t%s\t%s' "$idx" "$nm" "$status" "${rs:--}" "$(probe "$idx")")"
done < <(sudo docker ps -a --format '{{.Names}} {{.Status}}')

# Expected-but-absent indices
if [ -n "$EXPECTED" ]; then
  for i in $(seq 0 $((EXPECTED-1))); do
    case " $seen " in *" $i "*) ;; *) add_record "$(printf '%s\t-\tMISSING (no container)\t-\t- - - - - -' "$i")" ;; esac
  done
fi
[ -n "${records//[$'\n'	 ]/}" ] || { echo "no devnet node containers found"; exit 1; }

records=$(printf '%s' "$records" | grep -v '^$' | sort -n)
best=$(printf '%s\n' "$records" | awk -F'\t' '{split($5,f," "); if (f[1]+0>m && f[1] ~ /^[0-9]+$/) m=f[1]} END{print m+0}')

printf '%-5s %-14s %-22s %3s %9s %9s %9s %-8s %4s %5s\n' \
       NODE CONTAINER "DOCKER STATUS" RS HEAD JUST FIN SYNC AGG PEERS
bad=0
while IFS=$'\t' read -r idx nm status rs vals; do
  read -r h j f s a p <<<"$vals"
  flag=""
  case "$status" in Up*) ;; *) bad=1 ;; esac
  case "$h" in
    ''|-|*[!0-9]*) [ "$nm" != "-" ] && flag="  <- no metrics"; bad=1 ;;
    *) [ $((best - h)) -gt "$LAG_THRESHOLD" ] && {
         flag="  <- lags best head by $((best - h)) (>$LAG_THRESHOLD: duties suppressed)"; bad=1; } ;;
  esac
  printf '%-5s %-14s %-22s %3s %9s %9s %9s %-8s %4s %5s%s\n' \
         "$idx" "$nm" "${status:0:22}" "$rs" "$h" "$j" "$f" "$s" "$a" "$p" "$flag"
done <<<"$records"

echo
echo "best head on this host: $best  (cross-devnet view: sweep.sh / Grafana)"
[ "$bad" = 0 ] && echo "OK: all nodes up, reporting, and within $LAG_THRESHOLD slots of the best head"
exit "$bad"
