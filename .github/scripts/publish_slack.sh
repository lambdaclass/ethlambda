#!/usr/bin/env bash
#
# POSTs a Slack Block Kit payload to an incoming webhook.
#
# Usage: publish_slack.sh <webhook_url> <payload_file>

set -euo pipefail

WEBHOOK_URL="${1:?webhook URL required}"
PAYLOAD_FILE="${2:?payload file required}"

if [[ -z "$WEBHOOK_URL" ]]; then
    echo "::error::Slack webhook URL resolved to an empty value — check the secret configured for this trigger (scheduled vs manual)"
    exit 1
fi

curl --fail-with-body -X POST "$WEBHOOK_URL" \
    -H 'Content-Type: application/json; charset=utf-8' \
    --data @"$PAYLOAD_FILE"
