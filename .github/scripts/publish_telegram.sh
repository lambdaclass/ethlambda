#!/usr/bin/env bash
#
# POSTs the contents of a file as an HTML-formatted Telegram message.
#
# Required env:
#   TELEGRAM_BOT_TOKEN          Bot token used to authenticate the request.
#   TELEGRAM_ETHLAMBDA_CHAT_ID  Destination chat ID.
#
# Usage: publish_telegram.sh <message_file>

set -euo pipefail

MESSAGE_FILE="${1:?message file required}"

if [[ -z "${TELEGRAM_BOT_TOKEN:-}" ]]; then
    echo "::error::TELEGRAM_BOT_TOKEN secret is not set — skipping Telegram post"
    exit 1
fi

if [[ -z "${TELEGRAM_ETHLAMBDA_CHAT_ID:-}" ]]; then
    echo "::error::TELEGRAM_ETHLAMBDA_CHAT_ID resolved to an empty value — check that the appropriate secret is configured for this trigger (scheduled vs manual)"
    exit 1
fi

curl --fail-with-body -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d chat_id="$TELEGRAM_ETHLAMBDA_CHAT_ID" \
    -d parse_mode=HTML \
    --data-urlencode text="$(cat "$MESSAGE_FILE")"
