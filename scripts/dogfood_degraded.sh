#!/usr/bin/env bash
# Stand up a throwaway soc-ai instance and walk it through five Security Onion
# grid states, screenshotting every screen and every action worth clicking.
#
# Pipeline (self-contained, repeatable, leak-free by construction — same shape
# as scripts/demo/run_demo_capture.sh, which is the pattern this follows):
#   1. seed_demo.py           — fresh SQLite store with TEST-NET-only demo data
#   2. mock_es.py             — local mock of Elasticsearch + the LLM gateway,
#                               with --degraded-control so ONE running app can be
#                               walked through every failure with no restart
#   3. uvicorn                — the real soc-ai app, cwd'd OUTSIDE the repo so it
#                               can NEVER read a developer .env; every setting is
#                               passed explicitly and points only at 127.0.0.1
#                               mocks / reserved example.com hosts
#   4. dogfood_degraded.mjs   — Playwright, full-page shots + per-screen network
#                               and timing records
#
# Usage:
#   scripts/dogfood_degraded.sh                       # all five states
#   STATES=healthy,down scripts/dogfood_degraded.sh   # a subset
#   NO_ACTIONS=1 scripts/dogfood_degraded.sh          # reads only (fast smoke)
#   SCREENS=alerts,hosts scripts/dogfood_degraded.sh  # re-shoot a few screens
#
# Output: /tmp/degraded-dogfood/<state>/<screen>.png
#         /tmp/degraded-dogfood/<state>/<screen>-after-<action>.png
#         /tmp/degraded-dogfood/<state>/network.json
#
# NEVER point this at a deployed instance. The whole exercise depends on the
# grid being a mock we can break on demand, and on every alert, IP and hostname
# being synthetic.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$REPO/.venv/bin/python"
WORK="${WORK:-/tmp/degraded-dogfood}"
DATA="$WORK/data"
ES_PORT="${ES_PORT:-19207}"
APP_PORT="${APP_PORT:-8907}"
# Past webui_grid_timeout_s (12s) by a wide margin, so a route that HAS the
# budget answers 503 and a route that skipped it burns the ES retry budget.
STALL_SECONDS="${STALL_SECONDS:-40}"

mkdir -p "$WORK"

# Pre-flight: a server already on $APP_PORT is a STALE app from a previous run
# (its SQLite fd points at the about-to-be-reseeded database), and a stale mock
# would leave the grid stuck in whatever state that run died in.
# A port still busy is USUALLY the previous state's app finishing its shutdown,
# not a stale instance: running the states back to back (one invocation each, so
# every state gets a pristine store) puts a teardown and the next pre-flight in
# the same second. Erroring there SKIPS A WHOLE STATE, and a skipped state is
# the worst possible outcome — the screenshots simply aren't there, and anyone
# reading the set later takes the absence for "that screen was fine". So wait,
# briefly, and only then call it stale.
wait_for_free() {
  local port="$1" path="$2" what="$3" hint="$4"
  for _ in $(seq 1 40); do  # 40 x 0.5s = 20s
    curl -fsS "http://127.0.0.1:$port$path" >/dev/null 2>&1 || return 0
    sleep 0.5
  done
  echo "ERROR: something still serves :$port after 20s — kill the stale $what first" >&2
  echo "       ($hint usually does it)" >&2
  exit 1
}
wait_for_free "$APP_PORT" "/healthz" "app" "pkill -f 'uvicorn soc_ai.main'"
wait_for_free "$ES_PORT" "/" "mock grid" "pkill -f 'mock_es.py'"

if [[ ! -d "$REPO/frontend/dist" ]]; then
  echo "ERROR: frontend/dist is missing — run 'npm --prefix frontend run build' first" >&2
  exit 1
fi
# Playwright's NODE package is not a frontend dependency (the repo's own browser
# tests use the Python one from pyproject). Installed unsaved, exactly as the
# older scripts/ui-walkthrough.mjs already assumes.
if [[ ! -f "$REPO/frontend/node_modules/playwright/index.js" ]]; then
  echo "ERROR: node playwright is missing. Install it (unsaved, so package.json stays clean):" >&2
  echo "       npm --prefix frontend install --no-save playwright" >&2
  echo "       npx --prefix frontend playwright install chromium" >&2
  exit 1
fi

echo "== seeding a throwaway store =="
"$PY" "$REPO/scripts/demo/seed_demo.py" --data-dir "$DATA"

echo "== starting mock grid on :$ES_PORT (degraded control ON, stall ${STALL_SECONDS}s) =="
"$PY" "$REPO/scripts/demo/mock_es.py" --port "$ES_PORT" \
  --degraded-control --stall-seconds "$STALL_SECONDS" &
MOCK_PID=$!

echo "== starting soc-ai on :$APP_PORT (cwd=$WORK, no .env reachable) =="
(
  cd "$WORK"
  env -i \
    PATH="/usr/bin:/bin" \
    HOME="$WORK" \
    SOC_AI_DATA_DIR="$DATA" \
    SO_HOST="https://securityonion.demo.example.com" \
    SO_USERNAME="soc-ai@demo.example.com" \
    SO_PASSWORD="demo-password-unused" \
    ES_HOSTS="http://127.0.0.1:$ES_PORT" \
    LITELLM_BASE_URL="http://127.0.0.1:$ES_PORT" \
    NOTIFY_WEBHOOK_URL="https://hooks.example.com/soc-ai-dogfood-placeholder" \
    "$PY" -m uvicorn soc_ai.main:app --host 127.0.0.1 --port "$APP_PORT" \
      >"$WORK/app.log" 2>&1
) &
APP_PID=$!

cleanup() {
  # Kill the app's whole subtree, not just the subshell wrapper: uvicorn is a
  # CHILD of $APP_PID, and killing only the wrapper orphans it — the orphan keeps
  # :$APP_PORT bound with an fd to the old database and silently serves stale
  # data to the NEXT run.
  pkill -TERM -P "$APP_PID" 2>/dev/null || true
  kill "$APP_PID" "$MOCK_PID" 2>/dev/null || true
  wait "$APP_PID" "$MOCK_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "== waiting for the app =="
for _ in $(seq 1 90); do
  if curl -fsS "http://127.0.0.1:$APP_PORT/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.5
  if ! kill -0 "$APP_PID" 2>/dev/null; then
    echo "app died — see $WORK/app.log" >&2
    exit 1
  fi
done

echo "== walking the states =="
BASE="http://127.0.0.1:$APP_PORT" \
MOCK="http://127.0.0.1:$ES_PORT" \
MANIFEST="$WORK/manifest.json" \
OUT="$WORK" \
  node "$REPO/scripts/dogfood_degraded.mjs"

echo "done. shots + network.json under $WORK/<state>/"
