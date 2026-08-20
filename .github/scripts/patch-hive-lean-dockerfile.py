#!/usr/bin/env python3
"""Patch Hive's Lean simulator Dockerfile for CI.

The pinned Hive Dockerfile uses unauthenticated GitHub API `ADD` instructions
as cache-busters for commit/release metadata. GitHub-hosted runners can hit the
anonymous API rate limit there before Hive starts. Replace those remote fetches
with local metadata stubs; the build still downloads the actual pinned assets
through the later `git clone`/`curl` steps.
"""

from __future__ import annotations

import pathlib
import sys


REPLACEMENTS = {
    "ADD ${LEAN_SPEC_DEVNET4_COMMIT_METADATA_URL} /tmp/devnet4-commit.json":
        'RUN printf \'{"sha":"%s"}\\n\' "$devnet4_tag" > /tmp/devnet4-commit.json',
    "ADD ${LEAN_SPEC_DEVNET5_COMMIT_METADATA_URL} /tmp/devnet5-commit.json":
        'RUN printf \'{"sha":"%s"}\\n\' "$devnet5_tag" > /tmp/devnet5-commit.json',
    "ADD ${LEAN_SPEC_TESTS_METADATA_URL} /tmp/lean-spec-tests-commit.json":
        'RUN printf \'{"sha":"%s"}\\n\' "$lean_spec_tests_ref" > /tmp/lean-spec-tests-commit.json',
    "ADD ${LEAN_SPEC_FIXTURES_METADATA_URL} /tmp/devnet5-lean-spec-fixtures-release.json":
        'RUN printf \'{"tag_name":"%s"}\\n\' "$lean_spec_fixtures_tag" > /tmp/devnet5-lean-spec-fixtures-release.json',
    "ADD ${LEAN_SPEC_DEVNET5_KEYS_METADATA_URL} /tmp/devnet5-keys-release.json":
        'RUN printf \'{"tag_name":"%s"}\\n\' "$devnet5_keys_tag" > /tmp/devnet5-keys-release.json',
}


def main() -> int:
    dockerfile = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "src/simulators/lean/Dockerfile")
    content = dockerfile.read_text()

    missing = [needle for needle in REPLACEMENTS if needle not in content]
    if missing:
        print("Hive Lean Dockerfile did not contain expected metadata ADD line(s):", file=sys.stderr)
        for needle in missing:
            print(f"- {needle}", file=sys.stderr)
        return 1

    for needle, replacement in REPLACEMENTS.items():
        content = content.replace(needle, replacement)

    if "ADD ${LEAN_SPEC_" in content:
        print("Hive Lean Dockerfile still contains a remote Lean metadata ADD", file=sys.stderr)
        return 1

    dockerfile.write_text(content)
    print(f"Patched {dockerfile} to avoid unauthenticated GitHub API metadata fetches")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
