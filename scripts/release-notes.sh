#!/usr/bin/env bash
# Print the GitHub Release body for one version.
#
# Usage: scripts/release-notes.sh <version> [<tag>]      e.g. 1.5.0 v1.5.0
#
# The body comes from the first source that exists:
#   1. docs/releases/<version>.md, the note written for readers.
#   2. The CHANGELOG.md section under "## [<version>]".
#   3. A one-line pointer at CHANGELOG.md.
#
# The Release title already reads "soc-ai <version>", so a leading H1 is
# dropped. A relative link in the note resolves against docs/releases/, which
# the Release page cannot do, so "../" links become absolute URLs at the tag.
# GitHub refuses a body over 125,000 characters (the 1.5.0 CHANGELOG section
# was 189,000). A longer body is cut at a line boundary, and a footer points at
# the full file. RELEASE_BODY_LIMIT overrides the cut point for tests.
set -euo pipefail

ver="${1:?usage: release-notes.sh <version> [<tag>]}"
tag="${2:-v$ver}"
repo="${GITHUB_REPOSITORY:-nuk3s/soc-ai}"
limit="${RELEASE_BODY_LIMIT:-120000}"

here="$(cd "$(dirname "$0")/.." && pwd)"
note="$here/docs/releases/$ver.md"
body="$(mktemp)"
trap 'rm -f "$body" "$body.cut"' EXIT

if [ -s "$note" ]; then
  sed -e '1{/^# /d}' \
      -e "s#!\[\([^]]*\)\](\.\./#![\1](https://raw.githubusercontent.com/$repo/$tag/docs/#g" \
      -e "s#\](\.\./#](https://github.com/$repo/blob/$tag/docs/#g" \
      "$note" | sed '/./,$!d' > "$body"
else
  awk -v ver="$ver" 'index($0,"## [" ver "]")==1{grab=1;next} grab&&/^## \[/{exit} grab{print}' \
    "$here/CHANGELOG.md" > "$body"
fi

if [ -z "$(tr -d '[:space:]' < "$body")" ]; then
  printf 'Release %s. See CHANGELOG.md.\n' "$tag" > "$body"
fi

if [ "$(wc -c < "$body")" -gt "$limit" ]; then
  head -c "$limit" "$body" | sed '$d' > "$body.cut"
  printf '\n\n_Cut for length. The full text is in [CHANGELOG.md](https://github.com/%s/blob/%s/CHANGELOG.md)._\n' \
    "$repo" "$tag" >> "$body.cut"
  mv "$body.cut" "$body"
fi

cat "$body"
