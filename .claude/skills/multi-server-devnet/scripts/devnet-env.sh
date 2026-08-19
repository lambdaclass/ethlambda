#!/bin/bash
# Sourced helper (not executed): load the deployment's operator-specific values from
# an env file so they don't have to be retyped on every invocation.
#
#   . "$SCRIPT_DIR/devnet-env.sh"; devnet_load_env
#
# Also provides devnet_find_file, the file-lookup ladder both this and
# inventory.sh use.
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

# Resolve one of the deployment's config files. First hit wins: the path in $2 (an
# env var NAME), ./<name>, <scripts dir>/<name>. Prints the path on stdout.
# Returns 1 when nothing exists, and 2 when the env var names a path that doesn't
# -- an explicit path that isn't there is a typo, not a licence to fall back to
# another deployment's file. Shared with inventory.sh so devnet.env and
# devnet.inventory can't end up with two ideas of where they live.
devnet_find_file() {
  local name=$1 envvar=$2 dir explicit candidate
  dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  explicit=${!envvar:-}
  if [ -n "$explicit" ]; then
    [ -f "$explicit" ] || { echo "$envvar=$explicit does not exist" >&2; return 2; }
    printf '%s\n' "$explicit"; return 0
  fi
  for candidate in "./$name" "$dir/$name"; do
    [ -f "$candidate" ] && { printf '%s\n' "$candidate"; return 0; }
  done
  return 1
}

devnet_load_env() {
  local file line key val rc
  file=$(devnet_find_file devnet.env DEVNET_ENV); rc=$?
  [ "$rc" -eq 2 ] && return 1        # DEVNET_ENV names a missing file: reported
  [ "$rc" -eq 0 ] || return 0        # no env file at all is not an error

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
