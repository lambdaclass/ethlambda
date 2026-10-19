#!/usr/bin/env bash
#
# Sign every release asset in a directory with minisign, writing `<file>.minisig`
# beside each one, and verify each signature against the committed public key.
#
# Ported from ethrex's sign-stateless-artifacts.sh, so the two release pipelines
# sign and verify the same way.
#
# Usage: sign-release-assets.sh <asset-dir>
#
# Environment:
#   MINISIGN_SECRET_KEY     minisign secret key, as stored in the repo secret.
#                           Empty means "no key configured" (see below).
#   MINISIGN_PASSWORD       password for the secret key (empty for a `-W` key).
#   REQUIRE_SIGNATURE       "true" fails when no key is configured, rather than
#                           warning and leaving the assets unsigned.
#   TRUSTED_COMMENT_SUFFIX  appended to each signature's trusted comment, e.g.
#                           the tag and commit. It is signed, so it is a
#                           provenance claim rather than a label.
#   PUBLIC_KEY              the committed public key (default
#                           .github/minisign.pub).
set -euo pipefail

ASSET_DIR="${1:?usage: sign-release-assets.sh <asset-dir>}"
PUBLIC_KEY="${PUBLIC_KEY:-.github/minisign.pub}"
MINISIGN_SECRET_KEY="${MINISIGN_SECRET_KEY:-}"
MINISIGN_PASSWORD="${MINISIGN_PASSWORD:-}"
TRUSTED_COMMENT_SUFFIX="${TRUSTED_COMMENT_SUFFIX:-}"

if [ -z "$MINISIGN_SECRET_KEY" ]; then
  if [ "${REQUIRE_SIGNATURE:-false}" = "true" ]; then
    echo "::error::MINISIGN_SECRET_KEY is not set; refusing to publish unsigned assets"
    exit 1
  fi
  echo "::warning::MINISIGN_SECRET_KEY is not set; the assets are left unsigned"
  exit 0
fi

# Consumers verify against the key in the repository, published apart from the
# release it authenticates. A key shipped only inside the release proves
# nothing, since whoever can replace the assets can replace it too.
if [ ! -f "$PUBLIC_KEY" ]; then
  echo "::error::no public key at $PUBLIC_KEY to verify the signatures against; see RELEASE.md"
  exit 1
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
umask 077
printf '%s\n' "$MINISIGN_SECRET_KEY" > "$work_dir/minisign.key"

# `minisign -R` reads the password from stdin exactly as `-S` does.
if ! printf '%s\n' "$MINISIGN_PASSWORD" \
  | minisign -R -s "$work_dir/minisign.key" -p "$work_dir/minisign.pub" > /dev/null 2>&1; then
  echo "::error::could not derive a public key from MINISIGN_SECRET_KEY (wrong MINISIGN_PASSWORD, or not a minisign key)"
  exit 1
fi

# A key file is a comment line plus the base64 key; compare the key alone.
key_line() {
  grep -v '^untrusted comment:' "$1" | tr -d '[:space:]'
}
derived="$(key_line "$work_dir/minisign.pub")"
committed="$(key_line "$PUBLIC_KEY")"
if [ "$derived" != "$committed" ]; then
  echo "::error::MINISIGN_SECRET_KEY does not match $PUBLIC_KEY (derived $derived, committed $committed): the key was rotated in one place only"
  exit 1
fi

assets=()
while IFS= read -r -d '' file; do
  assets+=("$file")
done < <(find "$ASSET_DIR" -maxdepth 1 -type f ! -name '*.minisig' -print0 | sort -z)

if [ "${#assets[@]}" -eq 0 ]; then
  echo "::error::no assets to sign in $ASSET_DIR"
  exit 1
fi

for file in "${assets[@]}"; do
  name="$(basename "$file")"
  # The asset name leads the trusted comment, so it can be checked against the
  # file a consumer downloaded.
  trusted_comment="$name${TRUSTED_COMMENT_SUFFIX:+ $TRUSTED_COMMENT_SUFFIX}"
  printf '%s\n' "$MINISIGN_PASSWORD" \
    | minisign -S -s "$work_dir/minisign.key" -m "$file" -x "$file.minisig" -t "$trusted_comment" > /dev/null
  # The check a consumer runs, so a broken signature fails here, not for them.
  minisign -V -p "$PUBLIC_KEY" -m "$file" -x "$file.minisig" > /dev/null
  echo "signed and verified: $name"
done
