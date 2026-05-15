#!/usr/bin/env python3
"""
Counts Rust lines of code in the ethlambda workspace via cargo-warloc and
produces report files for Slack, Telegram, and the GitHub Actions step summary.

`cargo warloc` reports per-file `main`/`tests` line counts using a Rust AST
parser, so inline `#[cfg(test)]` blocks are correctly classified as test code.

Inputs (optional):
  loc_report.json.old   Previous run's report. Used to compute deltas.

Outputs:
  loc_report.json            Machine-readable report for caching.
  loc_report_slack.json      Slack Block Kit payload (daily).
  loc_report_telegram.txt    Telegram HTML body (weekly).
  loc_report_github.txt      Plain-text block for the workflow step summary.
"""

from __future__ import annotations

import html
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


# Crates whose entire contents are test infrastructure and should never
# appear in the "no tests" totals or per-crate listing.
TEST_ONLY_CRATES = frozenset({
    "crates/common/test-fixtures",
})

# Individual files that are test infrastructure but live next to production
# code inside an otherwise-production crate. Their lines are folded into the
# owning crate's `tests` bucket.
TEST_ONLY_FILES = frozenset({
    "crates/net/rpc/src/test_driver.rs",
})


def _run(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True)


def warloc_by_file() -> dict:
    return json.loads(_run(["cargo", "warloc", "--by-file", "-o", "json"]))


def workspace_crates() -> list[str]:
    md = json.loads(_run(["cargo", "metadata", "--no-deps", "--format-version", "1"]))
    cwd = os.getcwd() + "/"
    crates = []
    for pkg in md["packages"]:
        path = pkg["manifest_path"][: -len("/Cargo.toml")]
        if path.startswith(cwd):
            path = path[len(cwd):]
        crates.append(path)
    # Sort longest first so longest-prefix match wins when grouping files.
    crates.sort(key=len, reverse=True)
    return crates


def group_by_crate(by_file: dict, crates: list[str]) -> dict[str, dict[str, int]]:
    buckets = {c: {"main": 0, "tests": 0} for c in crates}
    for raw_path, stats in by_file["files"].items():
        path = raw_path[2:] if raw_path.startswith("./") else raw_path
        owner = next((c for c in crates if path.startswith(c + "/")), None)
        if owner is None:
            continue
        is_test_only = owner in TEST_ONLY_CRATES or path in TEST_ONLY_FILES
        if is_test_only:
            # All lines from this file/crate count as tests.
            buckets[owner]["tests"] += stats["main"]["code"] + stats["tests"]["code"]
        else:
            buckets[owner]["main"] += stats["main"]["code"]
            buckets[owner]["tests"] += stats["tests"]["code"]
    return buckets


def format_diff(cur: int, old: int) -> str:
    if cur > old:
        return f"(+{cur - old})"
    if cur < old:
        return f"(-{old - cur})"
    return ""


def main() -> None:
    by_file = warloc_by_file()
    crates = workspace_crates()
    buckets = group_by_crate(by_file, crates)

    rows = [
        {"path": c, "main": b["main"], "tests": b["tests"]}
        for c, b in buckets.items()
    ]
    rows.sort(key=lambda r: -r["main"])

    total_main = sum(r["main"] for r in rows)
    total_tests = sum(r["tests"] for r in rows)
    total_with_tests = total_main + total_tests

    new_report = {
        "total_main": total_main,
        "total_tests": total_tests,
        "total_with_tests": total_with_tests,
        "crates": rows,
    }
    Path("loc_report.json").write_text(json.dumps(new_report))

    # Resolve previous values (default = current → blank deltas on first run).
    old_path = Path("loc_report.json.old")
    if old_path.exists():
        old = json.loads(old_path.read_text())
        old_main = old.get("total_main", total_main)
        old_with = old.get("total_with_tests", total_with_tests)
        old_crates = {c["path"]: c["main"] for c in old.get("crates", [])}
    else:
        old_main = total_main
        old_with = total_with_tests
        old_crates = {r["path"]: r["main"] for r in rows}

    main_diff = format_diff(total_main, old_main)
    with_diff = format_diff(total_with_tests, old_with)

    sha = os.environ.get("GITHUB_SHA") or _run(["git", "rev-parse", "HEAD"]).strip()
    short = sha[:7]
    date_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    per_crate = []
    for r in rows:
        # Test-only crates fold their lines into the tests bucket and have
        # main == 0; skip them in the per-crate "no tests" listing.
        if r["main"] == 0:
            continue
        old_loc = old_crates.get(r["path"], r["main"])
        per_crate.append({
            "path": r["path"],
            "loc": r["main"],
            "diff": format_diff(r["main"], old_loc),
        })

    # --- GitHub step summary -------------------------------------------------
    gh_lines = [
        "```",
        f"ethlambda lines of code  ({date_utc}, {short})",
        "============================================",
        "",
        "Per-crate (no tests)",
        "--------------------",
    ]
    gh_lines += [f"{r['path']}: {r['loc']} {r['diff']}".rstrip() for r in per_crate]
    gh_lines += [
        "",
        f"Total Rust LoC (no tests):   {total_main} {main_diff}".rstrip(),
        f"Total Rust LoC (with tests): {total_with_tests} {with_diff}".rstrip(),
        "```",
    ]
    Path("loc_report_github.txt").write_text("\n".join(gh_lines) + "\n")

    # --- Slack Block Kit ------------------------------------------------------
    per_crate_slack = "\n".join(
        f"*{r['path']}*: {r['loc']} {r['diff']}".rstrip() for r in per_crate
    )
    totals_slack = (
        f"*Total (no tests):* {total_main} {main_diff}".rstrip()
        + "\n"
        + f"*Total (with tests):* {total_with_tests} {with_diff}".rstrip()
    )
    slack_payload = {
        "blocks": [
            {"type": "header",
             "text": {"type": "plain_text", "text": "Daily ethlambda LoC Report"}},
            {"type": "section",
             "text": {"type": "mrkdwn",
                      "text": f"_Date:_ {date_utc} • _Commit:_ `{short}`"}},
            {"type": "divider"},
            {"type": "header",
             "text": {"type": "plain_text", "text": "Per-crate (no tests)"}},
            {"type": "section",
             "text": {"type": "mrkdwn", "text": per_crate_slack}},
            {"type": "divider"},
            {"type": "section",
             "text": {"type": "mrkdwn", "text": totals_slack}},
        ]
    }
    Path("loc_report_slack.json").write_text(json.dumps(slack_payload))

    # --- Telegram (HTML parse mode) ------------------------------------------
    def esc(s: str) -> str:
        return html.escape(s, quote=False)

    tg_lines = [
        "<b>Weekly ethlambda LoC Report</b>",
        f"Date: {date_utc} • Commit: <code>{esc(short)}</code>",
        "",
        "<b>Per-crate (no tests)</b>",
    ]
    tg_lines += [
        f"<b>{esc(r['path'])}</b>: {r['loc']} {r['diff']}".rstrip()
        for r in per_crate
    ]
    tg_lines += [
        "",
        f"<b>Total Rust LoC (no tests):</b>   {total_main} {main_diff}".rstrip(),
        f"<b>Total Rust LoC (with tests):</b> {total_with_tests} {with_diff}".rstrip(),
    ]
    Path("loc_report_telegram.txt").write_text("\n".join(tg_lines) + "\n")


if __name__ == "__main__":
    main()
