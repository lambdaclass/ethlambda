#!/bin/bash
# Select servers from the deployment's inventory by tag.
#
#   inventory.sh [--tag T]... [--not-tag T]... [--field F] [--file P] [--count]
#
# Lookup order, first hit wins: --file, $DEVNET_INVENTORY, ./devnet.inventory,
# <scripts dir>/devnet.inventory. Copy devnet.inventory.example to
# devnet.inventory (gitignored) and fill it in; that file documents the format.
#
#   --tag T       keep rows carrying T. Repeatable, and a single argument may hold
#                 several whitespace-separated tags. All of them must match (AND).
#   --not-tag T   drop rows carrying T. Same repeat/multi-value rules.
#   --field F     name | ip | tags | nodes | subnets | all. Default prints name +
#                 ip aligned; `all` prints every column aligned.
#   --count       print how many rows matched, nothing else.
#
# `validator` is a DERIVED tag: "has a devnet-* tag and is not tagged aggregator".
# It is computed, not read, so it can never disagree with the aggregator tag.
# `--tag validator` is exactly `--tag <that devnet> --not-tag aggregator`.
#
# An unknown tag is an ERROR, not an empty result. A typo ('devnet5' for
# 'devnet-5') that quietly returns no hosts turns `for h in $(inventory.sh ...)`
# into a loop that does nothing and reports success, which is the same class of
# failure devnet-env.sh guards against: acting on the wrong deployment, silently.
# A tag that IS known but matches nothing is likewise exit 1 -- a real fleet has
# no empty groups, so an empty match means the inventory is stale.
set -u

usage() { sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

file=""; field="default"; count=0
tags=(); nottags=()

while [ $# -gt 0 ]; do
  case $1 in
    --tag)     [ $# -ge 2 ] || { echo "$1 needs a value" >&2; exit 2; }
               # Split on whitespace so --tag 'devnet-5 aggregator' is two tags.
               for t in $2; do tags+=("$t"); done; shift 2 ;;
    --not-tag) [ $# -ge 2 ] || { echo "$1 needs a value" >&2; exit 2; }
               for t in $2; do nottags+=("$t"); done; shift 2 ;;
    --field)   [ $# -ge 2 ] || { echo "$1 needs a value" >&2; exit 2; }
               field=$2; shift 2 ;;
    --file)    [ $# -ge 2 ] || { echo "$1 needs a value" >&2; exit 2; }
               file=$2; shift 2 ;;
    --count)   count=1; shift ;;
    -h|--help) usage 0 ;;
    *)         echo "unknown argument: $1" >&2; usage 2 ;;
  esac
done

case $field in
  name|ip|tags|nodes|subnets|all|default) ;;
  *) echo "--field $field: expected name|ip|tags|nodes|subnets|all" >&2; exit 2 ;;
esac

# An explicit path that doesn't exist is a typo, not a reason to fall back to some
# other inventory and act on the wrong fleet -- same rule devnet-env.sh applies.
if [ -n "$file" ]; then
  [ -f "$file" ] || { echo "--file $file does not exist" >&2; exit 2; }
elif [ -n "${DEVNET_INVENTORY:-}" ]; then
  file=$DEVNET_INVENTORY
  [ -f "$file" ] || { echo "DEVNET_INVENTORY=$file does not exist" >&2; exit 2; }
else
  dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  for candidate in "./devnet.inventory" "$dir/devnet.inventory"; do
    [ -f "$candidate" ] && { file=$candidate; break; }
  done
  [ -n "$file" ] || {
    echo "no inventory file found (tried \$DEVNET_INVENTORY, ./devnet.inventory, $dir/devnet.inventory)" >&2
    echo "copy $dir/devnet.inventory.example to $dir/devnet.inventory and fill it in" >&2
    exit 2
  }
fi

awk -v want="${tags[*]-}" -v nowant="${nottags[*]-}" \
    -v field="$field" -v docount="$count" -v src="$file" '
  # Tags are matched against ",a,b," so "agg" never matches "aggregator".
  function hastag(t, x) {
    if (x == "validator")
      return (index(t, ",devnet-") > 0 && index(t, ",aggregator,") == 0)
    return index(t, "," x ",") > 0
  }
  BEGIN { nw = split(want, W, " "); nn = split(nowant, NW, " ") }

  { sub(/^[[:space:]]+/, "") }
  /^#/ || /^$/ { next }

  {
    if (NF < 3) {
      # Named rather than skipped in silence: a row the parser drops is a host
      # that vanishes from every tag it belonged to.
      printf "%s:%d: ignoring '\''%s'\'', need at least name/ip/tags\n", src, FNR, $0 > "/dev/stderr"
      next
    }
    name = $1; ip = $2; tags = $3
    nodes   = (NF >= 4 ? $4 : "-")
    subnets = (NF >= 5 ? $5 : "-")
    t = "," tags ","

    # Every literal tag in the file, so a typo can be told from a real absence.
    n = split(tags, TT, ",")
    for (i = 1; i <= n; i++) if (TT[i] != "") seen[TT[i]] = 1

    for (i = 1; i <= nw; i++) if (!hastag(t, W[i])) next
    for (i = 1; i <= nn; i++) if ( hastag(t, NW[i])) next

    m++
    N[m] = name; I[m] = ip; T[m] = tags; O[m] = nodes; S[m] = subnets
    if (length(name)  > wN) wN = length(name)
    if (length(ip)    > wI) wI = length(ip)
    if (length(tags)  > wT) wT = length(tags)
    if (length(nodes) > wO) wO = length(nodes)
  }

  END {
    bad = 0
    for (i = 1; i <= nw; i++)
      if (W[i] != "validator" && !(W[i] in seen)) {
        printf "no such tag in %s: %s\n", src, W[i] > "/dev/stderr"; bad = 1
      }
    for (i = 1; i <= nn; i++)
      if (NW[i] != "validator" && !(NW[i] in seen)) {
        printf "no such tag in %s: %s\n", src, NW[i] > "/dev/stderr"; bad = 1
      }
    if (bad) {
      printf "known tags: " > "/dev/stderr"
      for (k in seen) printf "%s ", k > "/dev/stderr"
      printf "(+ derived: validator)\n" > "/dev/stderr"
      exit 2
    }

    if (docount) { print m + 0; exit (m ? 0 : 1) }

    for (i = 1; i <= m; i++) {
      if      (field == "name")    print N[i]
      else if (field == "ip")      print I[i]
      else if (field == "tags")    print T[i]
      else if (field == "nodes")   print O[i]
      else if (field == "subnets") print S[i]
      else if (field == "all")
        printf "%-*s  %-*s  %-*s  %-*s  %s\n", wN, N[i], wI, I[i], wT, T[i], wO, O[i], S[i]
      else
        printf "%-*s  %s\n", wN, N[i], I[i]
    }

    if (m == 0) {
      printf "no host in %s matches%s%s\n", src, \
        (nw ? " tags: " want : ""), (nn ? " not: " nowant : "") > "/dev/stderr"
      exit 1
    }
  }
' "$file"
