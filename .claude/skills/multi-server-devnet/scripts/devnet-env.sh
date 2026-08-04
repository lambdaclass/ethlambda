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
# `PROM_DS_UID=other ./deploy-finality-alert.sh` still overrides.
#
# Only simple `KEY=value` / `export KEY=value` lines are read. Blank lines and `#`
# comments are skipped, as is a `# comment` tail following an UNQUOTED value; a
# quoted value keeps its contents verbatim, `#` included. Leading indentation is
# fine. A line that looks like an assignment but whose name isn't usable is
# reported on stderr rather than dropped in silence, because a config line that
# goes unread is how you deploy against the wrong deployment.
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
    line=${line#"${line%%[![:space:]]*}"}          # ltrim, so an indented line is read
    case "$line" in ''|'#'*) continue ;; esac
    case "$line" in *=*) ;; *) continue ;; esac     # not an assignment at all
    case "$line" in export[[:space:]]*)
      line=${line#export}; line=${line#"${line%%[![:space:]]*}"} ;;
    esac
    key=${line%%=*}
    val=${line#*=}
    # Must be a name the shell can assign: a leading digit or any punctuation makes
    # `export` fail with its own confusing error, and skipping in silence would hide
    # the operator's typo. Name it and move on.
    case "$key" in ''|[0-9]*|*[!A-Za-z0-9_]*)
      echo "$file: ignoring '$key=...', not a variable name" >&2; continue ;;
    esac
    # Quotes, when present, DELIMIT the value, so a '#' or a trailing space inside
    # them survives. Unquoted, a `# comment` tail is dropped: it used to end up
    # inside the value, and for SERVERS that means sweep.sh ssh-ing to a host '#'.
    case $val in
      \"*) val=${val#\"}; val=${val%%\"*} ;;
      \'*) val=${val#\'}; val=${val%%\'*} ;;
      *)   val=${val%%[[:space:]]#*}                # comment tail
           val=${val%"${val##*[![:space:]]}"} ;;    # rtrim what it left behind
    esac
    # File provides defaults only: keep an already-set value. No eval anywhere --
    # `${!key}` is bash indirect expansion, and `export` gets ONE quoted
    # name=value word, so a multi-word value (SERVERS="host-a host-b") arrives
    # whole and nothing in it is ever reparsed as shell.
    [ -n "${!key:-}" ] || export "$key=$val"
  done < "$file"
  echo "loaded deployment env from $file" >&2
}
