#!/usr/bin/env bash
# commit-msg hook: a commit message follows ASD-STE100. An em dash or an en
# dash marks an aside, and STE has no asides. The hook rejects the message and
# names the line.
set -euo pipefail
file="${1:?commit message file}"
if grep -nP '[\x{2014}\x{2013}]' "$file" | grep -v '^[0-9]*:#' >/dev/null; then
  echo "commit-msg: the message contains an em dash or an en dash. Use a period or a comma." >&2
  grep -nP '[\x{2014}\x{2013}]' "$file" | grep -v '^[0-9]*:#' | sed 's/^/  /' >&2
  exit 1
fi
