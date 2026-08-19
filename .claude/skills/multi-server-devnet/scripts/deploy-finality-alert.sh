#!/bin/bash
# Deploy the per-devnet "lost finality" Grafana alert to the central metrics host.
#
# Renders grafana-finality-alert.yaml.template (Slack webhook + Grafana base URL +
# central-prometheus datasource uid), pushes it into Grafana's provisioning/alerting
# dir on the metrics host, and reloads Grafana. The rendered file (with the real
# webhook) is written to a temp file and removed locally; only the host keeps a copy.
#
# Nothing about the deployment is hardcoded: every host-specific value comes from the
# env. Unlike the dashboards, a provisioned ALERT RULE cannot use a datasource
# template variable — it needs a concrete uid — hence PROM_DS_UID.
#
# The five values below normally come from devnet.env (see devnet.env.example) so
# they don't have to be retyped; anything exported in the shell overrides the file.
#
# Usage:
#   deploy-finality-alert.sh [WEBHOOK_FILE]            # values from devnet.env
#   METRICS_HOST=user@host GRAFANA_PROV_DIR=/path/to/grafana-provisioning \
#   GRAFANA_CONTAINER=<grafana container> GRAFANA_BASE_URL=http://host:3000 \
#   PROM_DS_UID=<central prometheus datasource uid> \
#     deploy-finality-alert.sh [WEBHOOK_FILE]          # or fully explicit
#
#   WEBHOOK_FILE  file holding the Slack webhook url (default ./webhook.txt, or
#                 WEBHOOK_FILE from devnet.env). It is a SECRET — keep it out of git
#                 (the repo .gitignore covers webhook.txt).
#   DRY_RUN=1     render + validate locally and print the plan; ship nothing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/devnet-env.sh"
devnet_load_env || exit 1

METRICS_HOST=${METRICS_HOST:?ssh target of the central metrics host, e.g. user@host}
GRAFANA_PROV_DIR=${GRAFANA_PROV_DIR:?grafana provisioning dir on the metrics host}
GRAFANA_CONTAINER=${GRAFANA_CONTAINER:?grafana container name on the metrics host}
GRAFANA_BASE_URL=${GRAFANA_BASE_URL:?grafana base url for the alert dashboard link, e.g. http://host:3000}
PROM_DS_UID=${PROM_DS_UID:?grafana datasource uid of the central prometheus}
WEBHOOK_FILE="${1:-${WEBHOOK_FILE:-webhook.txt}}"

TEMPLATE="$SCRIPT_DIR/grafana-finality-alert.yaml.template"
REMOTE_ALERT_DIR="${GRAFANA_PROV_DIR%/}/alerting"

[[ -f "$WEBHOOK_FILE" ]] || { echo "webhook file not found: $WEBHOOK_FILE" >&2; exit 1; }
[[ -f "$TEMPLATE" ]] || { echo "template not found: $TEMPLATE" >&2; exit 1; }

# Render without echoing the secret. `|` delimiter avoids the URL's `/` chars.
WEBHOOK="$(tr -d '\n\r' < "$WEBHOOK_FILE")"
RENDERED="$(mktemp)"
trap 'rm -f "$RENDERED"' EXIT
sed -e "s|__SLACK_WEBHOOK_URL__|${WEBHOOK}|" \
    -e "s|__GRAFANA_BASE_URL__|${GRAFANA_BASE_URL%/}|" \
    -e "s|__PROM_DS_UID__|${PROM_DS_UID}|g" "$TEMPLATE" > "$RENDERED"

# Fail before touching the host if a placeholder survived (renders as a broken
# provisioning file that Grafana silently ignores).
if grep -q '__[A-Z_]*__' "$RENDERED"; then
  echo "unsubstituted placeholder(s) left in the rendered alert:" >&2
  grep -o '__[A-Z_]*__' "$RENDERED" | sort -u >&2
  exit 1
fi

if [[ -n "${DRY_RUN:-}" ]]; then
  echo "DRY_RUN: would install as $REMOTE_ALERT_DIR/finality-alerts.yaml on $METRICS_HOST"
  echo "DRY_RUN: would restart container $GRAFANA_CONTAINER"
  # webhook redacted: the point of the dry run is the structure, not the secret
  sed "s|${WEBHOOK}|<redacted-webhook>|" "$RENDERED"
  exit 0
fi

echo "Pushing finality alert to $METRICS_HOST ..."
scp -q "$RENDERED" "$METRICS_HOST:/tmp/finality-alerts.yaml"
ssh "$METRICS_HOST" "sudo mkdir -p '$REMOTE_ALERT_DIR' \
  && sudo mv /tmp/finality-alerts.yaml '$REMOTE_ALERT_DIR/finality-alerts.yaml' \
  && sudo chmod 644 '$REMOTE_ALERT_DIR/finality-alerts.yaml' \
  && sudo docker restart '$GRAFANA_CONTAINER' >/dev/null \
  && echo 'Grafana restarted; alert provisioned.'"
