#!/usr/bin/env bash
#
# Counts Rust lines of code in the ethlambda workspace and produces report
# files for Slack, Telegram, and the GitHub Actions step summary.
#
# Inputs (optional):
#   loc_report.json.old   Previous run's report — used to compute deltas.
#
# Outputs:
#   loc_report.json            Machine-readable report for caching.
#   loc_report_slack.json      Slack Block Kit payload (daily message).
#   loc_report_telegram.txt    Telegram HTML body (weekly message).
#   loc_report_github.txt      Plain-text block for the workflow step summary.

set -euo pipefail

OLD_REPORT="loc_report.json.old"
NEW_REPORT="loc_report.json"

count_loc() {
    # Count Rust lines of code under $1. Excludes common non-product folders.
    # If the path has no Rust files, returns 0.
    # `-t Rust` (short form) is accepted by tokei v12 and v14.
    tokei "$1" -t Rust --output json \
        -e tests -e benches -e examples 2>/dev/null \
        | jq '.Rust.code // 0'
}

# Enumerate workspace members through cargo so the list stays in sync
# with Cargo.toml automatically.
CRATE_DIRS=$(
    cargo metadata --no-deps --format-version 1 \
        | jq -r '.packages[] | .manifest_path | sub("/Cargo.toml$"; "")' \
        | sort
)

CRATES_JSON='[]'
TOTAL=0
while IFS= read -r dir; do
    [[ -z "$dir" ]] && continue
    rel="${dir#"$PWD/"}"
    src="${dir}/src"
    if [[ -d "$src" ]]; then
        loc=$(count_loc "$src")
    else
        loc=0
    fi
    TOTAL=$((TOTAL + loc))
    CRATES_JSON=$(jq --arg path "$rel" --argjson loc "$loc" \
        '. + [{path: $path, loc: $loc}]' <<< "$CRATES_JSON")
done <<< "$CRATE_DIRS"

CRATES_JSON=$(jq 'sort_by(-.loc)' <<< "$CRATES_JSON")

jq -n --argjson total "$TOTAL" --argjson crates "$CRATES_JSON" \
    '{total: $total, crates: $crates}' > "$NEW_REPORT"

# Resolve previous totals (defaulting to current → zero deltas on first run).
OLD_TOTAL=$TOTAL
OLD_CRATES_JSON=$CRATES_JSON
if [[ -f "$OLD_REPORT" ]]; then
    OLD_TOTAL=$(jq '.total' "$OLD_REPORT")
    OLD_CRATES_JSON=$(jq '.crates' "$OLD_REPORT")
fi

format_diff() {
    local cur=$1 old=$2
    if   (( cur > old )); then echo "(+$((cur - old)))"
    elif (( cur < old )); then echo "(-$((old - cur)))"
    else echo ""
    fi
}

TOTAL_DIFF=$(format_diff "$TOTAL" "$OLD_TOTAL")
COMMIT_SHA=${GITHUB_SHA:-$(git rev-parse HEAD)}
SHORT_SHA=${COMMIT_SHA:0:7}
DATE_UTC=$(date -u +"%Y-%m-%d")

# Build per-crate annotated rows once and reuse for every format.
ROWS_JSON=$(jq --argjson old "$OLD_CRATES_JSON" '
    map(
        . as $c
        | ($old | map(select(.path == $c.path)) | .[0].loc // 0) as $old_loc
        | . + {
            old_loc: $old_loc,
            diff: ($c.loc - $old_loc)
        }
    )
' <<< "$CRATES_JSON")

format_diff_jq='
    def diff_str:
        if   . > 0 then "(+" + (. | tostring) + ")"
        elif . < 0 then "(-" + ((. | -.) | tostring) + ")"
        else "" end;
'

# GitHub step summary (plain text inside a code block).
{
    echo '```'
    echo "ethlambda lines of code  (${DATE_UTC}, ${SHORT_SHA})"
    echo "============================================"
    echo "Total Rust LoC: ${TOTAL} ${TOTAL_DIFF}"
    echo
    echo "Per-crate"
    echo "---------"
    jq -r "$format_diff_jq"'
        .[] | "\(.path): \(.loc) \(.diff | diff_str)"
    ' <<< "$ROWS_JSON"
    echo
    echo "Excluded folders: tests/, benches/, examples/"
    echo '```'
} > loc_report_github.txt

# Slack Block Kit payload.
CRATES_MRKDWN=$(jq -r "$format_diff_jq"'
    map("*\(.path)*: \(.loc) \(.diff | diff_str)") | join("\n")
' <<< "$ROWS_JSON")

SUMMARY_TEXT=$(printf '*Total Rust LoC:* %s %s\n_Date:_ %s • _Commit:_ `%s`' \
    "$TOTAL" "$TOTAL_DIFF" "$DATE_UTC" "$SHORT_SHA")

jq -n \
    --arg summary "$SUMMARY_TEXT" \
    --arg crates  "$CRATES_MRKDWN" \
    '{
        blocks: [
            { type: "header",  text: { type: "plain_text", text: "Daily ethlambda LoC Report" } },
            { type: "divider" },
            { type: "section", text: { type: "mrkdwn", text: $summary } },
            { type: "header",  text: { type: "plain_text", text: "Per-crate" } },
            { type: "section", text: { type: "mrkdwn", text: $crates } },
            { type: "context", elements: [
                { type: "mrkdwn", text: "_Excluded folders: tests/, benches/, examples/_" }
            ]}
        ]
    }' > loc_report_slack.json

# Telegram (HTML parse mode).
{
    echo "<b>Weekly ethlambda LoC Report</b>"
    echo "Date: ${DATE_UTC} • Commit: <code>${SHORT_SHA}</code>"
    echo
    echo "<b>Total Rust LoC:</b> ${TOTAL} ${TOTAL_DIFF}"
    echo
    echo "<b>Per-crate</b>"
    jq -r "$format_diff_jq"'
        .[] | "<b>\(.path)</b>: \(.loc) \(.diff | diff_str)"
    ' <<< "$ROWS_JSON"
    echo
    echo "<i>Excluded folders: tests/, benches/, examples/</i>"
} > loc_report_telegram.txt
