#!/usr/bin/env bash
# Deploy the working tree to a source-run host: rsync, reinstall the package,
# restart the systemd unit, wait for the app to answer.
#
# This exists because the range is NOT the Docker deployment. `scripts/deploy.sh`
# builds an image and keeps its data in named volumes; here the app runs from the
# synced tree under a service user, with its SQLite database inside the very
# directory rsync writes to. The two hosts therefore need different excludes, and
# a command typed from memory gets it wrong:
#
#   On 2026-09-07 a hand-written `rsync -a --delete` without `--exclude=/data/`
#   replaced the range's live database with the dev box's copy — 87 dev/demo
#   investigation rows, a stale migration head, and two config overrides that
#   silently turned PCAP fetch on. There was no WAL and no host backup. The
#   range's own dogfood history was gone.
#
# So the excludes below are load-bearing, and every one of them names what it is
# protecting. Anything living ONLY on the target must appear here.
set -euo pipefail

# Same precedence as scripts/deploy.sh, different file, so neither host's address
# reaches the published repo.
_root="$(cd "$(dirname "$0")/.." && pwd)"
_target_file="${_root}/.range-target"
TARGET="${1:-${SOC_AI_RANGE_TARGET:-$([ -f "$_target_file" ] && head -1 "$_target_file" || echo 'root@REPLACE-WITH-RANGE-HOST')}}"
DEST="${2:-/opt/soc-ai}"
# The unit runs as this user. rsync -a preserves the DEV box's ownership, so
# without the chown below the service loses write access to its own database and
# dies at startup with "attempt to write a readonly database".
SVC_USER="${SOC_AI_RANGE_USER:-soc-ai}"

# Build the SPA before syncing. The deploy ships frontend/dist as-is, so a
# tree whose tests and typecheck are green can still ship yesterday's bundle
# -- which is exactly what happened on 2026-09-16: four verified UI fixes
# deployed, every pixel measurement came back identical, and the cause was a
# dist/ nobody had rebuilt. `tsc --noEmit` and vitest do not write dist/.
( cd "${_root}/frontend" && npm run build >/dev/null 2>&1 ) || { echo "frontend build failed" >&2; exit 1; }
echo "frontend built"

case "${TARGET}" in
  *REPLACE-WITH-RANGE-HOST*)
    echo "No range target. Pass one, set SOC_AI_RANGE_TARGET, or write ${_target_file}." >&2
    exit 2
    ;;
esac

rsync -az --delete \
  `#  the tester's guide is gitignored, so a deploy from a fresh worktree has none;` \
  `#  protect the range's copy from --delete (a protect rule does not block a transfer)` \
  --filter='P /frontend/dist/guide/' \
  --exclude='.env' --exclude='.env.*' \
  `#  the live SQLite DB + the decision signing key. Root-anchored so it cannot` \
  `#  match soc_ai/enrichment/data/, which must ship.` \
  --exclude='/data/' \
  `#  the grid query helper the range docs tell everyone to use; untracked here` \
  --exclude='bench_es.py' \
  --exclude='certs/' --exclude='.ssh/' \
  --exclude='.venv/' --exclude='evals/' \
  --exclude='node_modules/' --exclude='.git/' \
  --exclude='.cache/' \
  --exclude='.coverage*' --exclude='.pytest_cache/' --exclude='.mypy_cache/' \
  --exclude='.ruff_cache/' --exclude='__pycache__/' --exclude='.worktrees/' \
  --exclude='.superpowers/' --exclude='.claude/' --exclude='.remember/' \
  ./ "${TARGET}:${DEST}/"

# Stamp the commit into the range's .env, the way scripts/deploy.sh does for
# production. The unit reads .env through EnvironmentFile, so the app reports
# the commit in GET /api/v1/about and in the console About section. The range
# has no git binary, so nothing else names the build it runs. The sed drops
# only an older SOC_AI_COMMIT line and keeps every other line. A last line with
# no newline gets one first, so the new line never joins it.
COMMIT="$(git -C "${_root}" rev-parse HEAD)"
ssh "${TARGET}" "cd ${DEST} && touch .env && sed -i '/^SOC_AI_COMMIT=/d' .env && \
  if [ -s .env ] && [ -n \"\$(tail -c1 .env)\" ]; then echo >> .env; fi && \
  printf 'SOC_AI_COMMIT=%s\n' '${COMMIT}' >> .env"
echo "commit ${COMMIT} stamped"

# Ownership, reinstall, restart, then WAIT for a real answer. A restart that
# returns 0 says systemd accepted the job, not that the app started; the unit
# above exits 3 on a failed startup and would otherwise deploy "successfully".
# The locked dependency set, with the optional extras the range runs. The
# range has no uv, so the lock is exported here and installed there with pip.
# A plain "pip install .[ml]" on the range would copy the project into
# site-packages beside the editable install, and the console script would
# then import that copy: the OQL primer path broke that way on 2026-10-05.
uv export --extra postgres --extra ml --no-dev --no-hashes --no-emit-project \
  -o /tmp/soc-ai-range-requirements.txt --quiet
rsync -az /tmp/soc-ai-range-requirements.txt "${TARGET}:${DEST}/requirements-range.txt"

ssh "${TARGET}" "set -e
  chown -R ${SVC_USER}:${SVC_USER} ${DEST}
  cd ${DEST} && .venv/bin/python -m pip install -q -r requirements-range.txt
  cd ${DEST} && .venv/bin/python -m pip install -e . --no-deps -q
  # An editable install must be the only soc_ai on the path.
  test ! -d .venv/lib/python3.12/site-packages/soc_ai || { echo 'a non-editable soc_ai copy sits in site-packages' >&2; exit 1; }
  systemctl restart soc-ai
  ok=0
  for i in \$(seq 1 20); do
    if curl -ksf https://127.0.0.1:8443/healthz >/dev/null || curl -sf http://127.0.0.1:8443/healthz >/dev/null; then ok=1; break; fi
    sleep 3
  done
  if [ \"\$ok\" != 1 ]; then
    echo 'DEPLOY HEALTHCHECK FAILED: app did not answer /healthz after ~60s' >&2
    journalctl -u soc-ai -n 20 --no-pager >&2 || true
    exit 1
  fi
  echo 'healthy'"
