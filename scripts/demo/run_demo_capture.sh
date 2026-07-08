#!/usr/bin/env bash
# Regenerate the public docs screenshots from a LOCAL, SYNTHETIC demo instance.
#
# Pipeline (self-contained, repeatable, leak-free by construction):
#   1. seed_demo.py   — fresh SQLite store with TEST-NET-only demo data
#   2. mock_es.py     — local mock of Elasticsearch + the LLM gateway
#   3. uvicorn        — the real soc-ai app, cwd'd OUTSIDE the repo so it can
#                       NEVER read a developer .env; every setting is passed
#                       explicitly below and points only at 127.0.0.1 mocks /
#                       reserved example.com hosts
#   4. capture.mjs    — Playwright shots at 1440x900 @2x (2880x1800 PNGs)
#
# Usage:
#   scripts/demo/run_demo_capture.sh            # capture to /tmp/soc-ai-demo/shots
#   scripts/demo/run_demo_capture.sh --install  # ... then copy into docs/img/
#
# NEVER point this at a deployed instance — the whole point is that no real
# alert, IP, or hostname can appear in the published imagery.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PY="$REPO/.venv/bin/python"
WORK=/tmp/soc-ai-demo
DATA="$WORK/data"
SHOTS="$WORK/shots"
ES_PORT="${ES_PORT:-19200}"
APP_PORT="${APP_PORT:-8901}"

mkdir -p "$WORK"
rm -rf "$SHOTS"

# Pre-flight: a server already on $APP_PORT is a STALE app from a previous
# run (its SQLite fd points at the about-to-be-deleted database, so the
# capture would screenshot a mix of old and new data). Refuse loudly.
if curl -fsS "http://127.0.0.1:$APP_PORT/healthz" >/dev/null 2>&1; then
  echo "ERROR: something already serves :$APP_PORT — kill the stale demo app first" >&2
  echo "       (pkill -f 'uvicorn soc_ai.main' usually does it)" >&2
  exit 1
fi

echo "== seeding demo store =="
"$PY" "$REPO/scripts/demo/seed_demo.py" --data-dir "$DATA"

echo "== starting mock ES/LLM on :$ES_PORT =="
"$PY" "$REPO/scripts/demo/mock_es.py" "$ES_PORT" &
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
    NOTIFY_WEBHOOK_URL="https://hooks.example.com/soc-ai-demo-placeholder" \
    "$PY" -m uvicorn soc_ai.main:app --host 127.0.0.1 --port "$APP_PORT" \
      >"$WORK/app.log" 2>&1
) &
APP_PID=$!

cleanup() {
  # Kill the app's whole subtree, not just the subshell wrapper: uvicorn is a
  # CHILD of $APP_PID, and killing only the wrapper orphans it — the orphan
  # keeps :$APP_PORT bound with an fd to the deleted database and silently
  # serves stale data to the NEXT capture run.
  pkill -TERM -P "$APP_PID" 2>/dev/null || true
  kill "$APP_PID" "$MOCK_PID" 2>/dev/null || true
  wait "$APP_PID" "$MOCK_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "== waiting for the app =="
for i in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$APP_PORT/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.5
  if ! kill -0 "$APP_PID" 2>/dev/null; then
    echo "app died — see $WORK/app.log" >&2
    exit 1
  fi
done

echo "== capturing screenshots =="
BASE="http://127.0.0.1:$APP_PORT" OUT="$SHOTS" MANIFEST="$WORK/manifest.json" \
  node "$REPO/scripts/demo/capture.mjs"

if [[ "${1:-}" == "--install" ]]; then
  echo "== installing into docs/img =="
  for f in screenshot-alerts screenshot-investigation screenshot-investigations \
           screenshot-dashboard screenshot-hunt; do
    if [[ -f "$SHOTS/$f.png" ]]; then
      cp "$SHOTS/$f.png" "$REPO/docs/img/$f.png"
      echo "  installed docs/img/$f.png"
    fi
  done
fi

echo "done. shots: $SHOTS"
