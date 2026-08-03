#!/bin/bash
# Sourced helper (not executed): load the deployment's operator-specific values from
# an env file so they don't have to be retyped on every invocation.
#
#   . "$SCRIPT_DIR/devnet-env.sh"; devnet_load_env
#
# Lookup order, first hit wins: $DEVNET_ENV, ./devnet.env, <scripts dir>/devnet.env.
# Copy devnet.env.example -> devnet.env and fill it in (devnet.env is gitignored,
# since it names your hosts and may point at a webhook file).
#
# A value already set in the environment WINS over the file, so a one-off
# `PROM_DS_UID=other ./deploy-finality-alert.sh` still overrides. Only simple
# `KEY=value` / `export KEY=value` lines are read; `#` comments and blanks skipped.
devnet_load_env() {
  local dir file line key val
  dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  file=""
  if [ -n "${DEVNET_ENV:-}" ]; then
    # An explicit path that doesn't exist is a typo, not a reason to silently fall
    # back to some other devnet.env and deploy against the wrong deployment.
    [ -f "$DEVNET_ENV" ] || { echo "DEVNET_ENV=$DEVNET_ENV does not exist" >&2; return 1; }
    file=$DEVNET_ENV
  else
    for candidate in "./devnet.env" "$dir/devnet.env"; do
      [ -f "$candidate" ] && { file=$candidate; break; }
    done
  fi
  [ -n "$file" ] || return 0

  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    line=${line#export }
    key=${line%%=*}
    val=${line#*=}
    # skip anything that isn't a plain shell name (comment tails, malformed lines)
    case "$key" in ''|*[!A-Za-z0-9_]*) continue ;; esac
    val=${val%\"} val=${val#\"}
    val=${val%\'} val=${val#\'}
    # file provides defaults only: keep an already-set value
    if eval "[ -z \"\${$key:-}\" ]"; then eval "export $key=\$val"; fi
  done < "$file"
  echo "loaded deployment env from $file" >&2
}
