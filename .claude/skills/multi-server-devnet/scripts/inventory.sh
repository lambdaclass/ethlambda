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
# It is computed from the row, never read from it, so it can never disagree with
# the aggregator tag; writing it literally in the file is an error rather than a
# second opinion. `--tag validator` is `--tag <that devnet> --not-tag aggregator`.
# Set DEVNET_TAG_PREFIX if a fleet names its chains something other than devnet-*.
#
# An unknown `--tag` is an ERROR, not an empty result. A typo ('devnet5' for
# 'devnet-5') that quietly returns no hosts turns `for h in $(inventory.sh ...)`
# into a loop that does nothing and reports success, which is the same class of
# failure devnet-env.sh guards against: acting on the wrong deployment, silently.
# An EMPTY --tag value is an error for the mirror-image reason: an unset variable
# in `--tag "$DEVNET"` would drop the filter and return the whole fleet, exit 0,
# including hosts on other chains. A tag that IS known but matches nothing is
# exit 1 -- a real fleet has no empty groups, so that means a stale inventory.
#
# `--not-tag` is deliberately NOT checked against the file: an exclusion that
# matches nothing is well-defined, and demanding the tag exist would break the
# documented `--tag <devnet> --not-tag aggregator` on any fleet whose aggregator
# role is currently unassigned.
set -u

# Sliced from the header block above, ending at the first non-comment line, so
# editing the comment can't silently truncate --help.
help_text() { awk 'NR == 1 { next } !/^#/ { exit } { sub(/^# ?/, ""); print }' "$0"; }

# Help goes to stdout for -h, but to stderr on the error path: callers capture
# this script's stdout ($(inventory.sh --field name)), so help text printed there
# becomes a list of "hosts" to ssh into.
usage() {
  code=${1:-0}
  if [ "$code" = 0 ]; then help_text; else help_text >&2; fi
  exit "$code"
}

# Whitespace-split a tag argument into SPLIT with globbing OFF: a tag is data, and
# `--tag 'devnet-*'` must not expand against whatever happens to sit in the cwd.
split_tags() {
  case $2 in
    *[![:space:]]*) ;;
    *) echo "$1 needs a non-empty value (an empty tag would match every host)" >&2
       exit 2 ;;
  esac
  set -f; SPLIT=($2); set +f
}

file=""; field="default"; count=0
tags=(); nottags=()

while [ $# -gt 0 ]; do
  case $1 in
    --tag)     [ $# -ge 2 ] || { echo "$1 needs a value" >&2; exit 2; }
               # Split on whitespace so --tag 'devnet-5 aggregator' is two tags.
               split_tags "$1" "$2"; tags+=("${SPLIT[@]}"); shift 2 ;;
    --not-tag) [ $# -ge 2 ] || { echo "$1 needs a value" >&2; exit 2; }
               split_tags "$1" "$2"; nottags+=("${SPLIT[@]}"); shift 2 ;;
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

if [ -n "$file" ]; then
  # An explicit path that doesn't exist is a typo, not a reason to fall back to
  # some other inventory and act on the wrong fleet.
  [ -f "$file" ] || { echo "--file $file does not exist" >&2; exit 2; }
else
  # Same ladder, from the same helper, that finds devnet.env: two config files of
  # one deployment should not have two ideas of where they live. Sourcing only
  # defines functions.
  dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  . "$dir/devnet-env.sh"
  file=$(devnet_find_file devnet.inventory DEVNET_INVENTORY); rc=$?
  # rc 2 means DEVNET_INVENTORY names a file that isn't there, already reported.
  [ "$rc" -eq 2 ] && exit 2
  [ "$rc" -eq 0 ] || {
    echo "no inventory file found (tried \$DEVNET_INVENTORY, ./devnet.inventory, $dir/devnet.inventory)" >&2
    echo "copy $dir/devnet.inventory.example to $dir/devnet.inventory and fill it in" >&2
    exit 2
  }
fi

# Only the derived `validator` tag depends on how chains are named, so a fleet
# that doesn't use devnet-* can say so instead of getting an empty answer.
chain_prefix=${DEVNET_TAG_PREFIX:-devnet-}

awk -v want="${tags[*]-}" -v nowant="${nottags[*]-}" -v chain="$chain_prefix" \
    -v field="$field" -v docount="$count" -v src="$file" '
  # Tags are matched against ",a,b," so "agg" never matches "aggregator". A
  # DERIVED tag is computed from the row instead: it carries some chain tag and
  # is not disqualified by a role tag.
  function hastag(t, x) {
    if (x in DPREFIX)
      return (index(t, "," DPREFIX[x]) > 0 && !hastag(t, DEXCLUDE[x]))
    return index(t, "," x ",") > 0
  }

  # `for (k in a)` walks a hash order, and these lists get read by a human next to
  # their own typo. Insertion sort: the tag list is a few dozen entries at most.
  function sortkeys(a, out,   i, j, n, v) {
    n = 0
    for (i in a) out[++n] = i
    for (i = 2; i <= n; i++) {
      v = out[i]
      for (j = i - 1; j >= 1 && out[j] > v; j--) out[j+1] = out[j]
      out[j+1] = v
    }
    return n
  }

  BEGIN {
    nw = split(want, W, " "); nn = split(nowant, NW, " ")
    # One entry per derived tag: the tag PREFIX a row must carry, and the tag that
    # disqualifies it. Adding a derived tag is a line here, not a new branch.
    DPREFIX["validator"] = chain; DEXCLUDE["validator"] = "aggregator"
  }

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

    # A space inside the tags column (or a trailing comment on a data row) shifts
    # every later field: $3 loses tags, and a ROLE lands in nodes. Unlike a short
    # row, which only drops one host, that silently reassigns roles and hands a
    # word to a caller expecting a count -- so refuse the whole file instead.
    if (nodes !~ /^([0-9]+|-)$/ || subnets !~ /^([0-9]+|-)$/) {
      printf "%s:%d: nodes/subnets must be a number or '\''-'\'', got '\''%s'\'' '\''%s'\''", \
        src, FNR, nodes, subnets > "/dev/stderr"
      printf " -- a space in the tags column shifts the columns right\n" > "/dev/stderr"
      malformed = 1; next
    }
    t = "," tags ","

    # Every literal tag in the file, so a typo can be told from a real absence,
    # and where it was first written, so both can be pointed at a line.
    n = split(tags, TT, ",")
    for (i = 1; i <= n; i++) if (TT[i] != "") {
      if (!(TT[i] in seen)) seenrow[TT[i]] = FNR
      seen[TT[i]] = 1
      if (substr(TT[i], 1, length(chain)) == chain) chainseen = 1
    }

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
    # Answering from a file whose columns do not line up would mean answering
    # about tags that were never written; the row numbers are already on stderr.
    if (malformed) {
      printf "%s: refusing to answer from a file that does not parse\n", src > "/dev/stderr"
      exit 2
    }

    bad = 0

    # A derived tag written as a literal is the exact disagreement the derivation
    # exists to rule out: the row would claim one thing and the computation
    # another. Say which line, rather than ignoring what the operator wrote.
    nd = sortkeys(DPREFIX, D)
    for (i = 1; i <= nd; i++)
      if (D[i] in seen) {
        printf "%s:%d: '\''%s'\'' is a DERIVED tag (%s* and not %s), remove it from the file\n", \
          src, seenrow[D[i]], D[i], DPREFIX[D[i]], DEXCLUDE[D[i]] > "/dev/stderr"
        bad = 1
      }

    for (i = 1; i <= nw; i++) {
      if (W[i] in DPREFIX) {
        # Derived, so never "unknown" -- but if no row carries a chain tag it can
        # never match, and that is a stale inventory, not a query to answer.
        if (!chainseen) {
          printf "no %s* tag in %s, so %s matches nothing (set DEVNET_TAG_PREFIX?)\n", \
            chain, src, W[i] > "/dev/stderr"
          bad = 1
        }
        continue
      }
      if (!(W[i] in seen)) {
        printf "no such tag in %s: %s\n", src, W[i] > "/dev/stderr"; bad = 1
      }
    }

    if (bad) {
      printf "known tags: " > "/dev/stderr"
      nk = sortkeys(seen, K)
      # A derived name that leaked into the file is listed as derived, not twice.
      for (i = 1; i <= nk; i++) if (!(K[i] in DPREFIX)) printf "%s ", K[i] > "/dev/stderr"
      printf "(+ derived:" > "/dev/stderr"
      for (i = 1; i <= nd; i++) printf " %s", D[i] > "/dev/stderr"
      printf ")\n" > "/dev/stderr"
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
