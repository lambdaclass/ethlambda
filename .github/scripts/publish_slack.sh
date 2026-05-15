#!/usr/bin/env bash
#
# POSTs a Slack Block Kit payload to an incoming webhook.
#
# Required env:
#   SLACK_WEBHOOK   Incoming-webhook URL. Read from the env (not argv) so it
#                   doesn't leak into the process list.
#
# Usage: publish_slack.sh <payload_file>

set -euo pipefail

PAYLOAD_FILE="${1:?payload file required}"

if [[ -z "${SLACK_WEBHOOK:-}" ]]; then
    echo "::error::SLACK_WEBHOOK resolved to an empty value — check the secret configured for this trigger (scheduled vs manual)"
    exit 1
fi

curl --fail-with-body -X POST "$SLACK_WEBHOOK" \
    -H 'Content-Type: application/json; charset=utf-8' \
    --data @"$PAYLOAD_FILE"
