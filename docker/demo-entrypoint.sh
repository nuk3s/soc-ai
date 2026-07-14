#!/bin/sh
# docker/demo-entrypoint.sh — PUBLIC DEMO CONTAINER ONLY (SOC_AI_DEMO=true).
#
# Single container, two processes:
#   1. the bundled mock Elasticsearch/LiteLLM endpoint on 127.0.0.1:9200 —
#      loopback only, never published; the ONE ES path the demo egress guard
#      (soc_ai/demo/guard.py) sanctions. It serves the sanitized alerts[]
#      documents from the packaged soc_ai/demo/fixtures.json (fail-soft: a
#      missing fixture file serves an empty grid, and the app boots anyway).
#   2. the real app, in read-only demo mode.
#
# TLS: none here, deliberately. The hosted demo sits behind the platform edge
# (Render/Fly terminate TLS and forward plain HTTP), so uvicorn starts WITHOUT
# the --ssl-* flags the image's default CMD uses. The listen port comes from
# $PORT (set by the platform; Render defaults to 10000) or falls back to 8080
# for docker-compose.demo.yml.
#
# Ordering: the mock binds its socket in milliseconds while the app spends
# seconds on DB migrations first — and the elasticsearch client connects
# lazily with retries, so even a lost race only delays the first alerts
# query; it never fails startup.
set -eu

# Refuse to run outside demo mode: this entrypoint pairs with the read-only
# middleware + egress guard. Without the flag it would start a NORMAL app
# with whatever (placeholder) env it was given.
case "${SOC_AI_DEMO:-}" in
  1 | true | TRUE | True | yes | on) ;;
  *)
    echo "demo-entrypoint: SOC_AI_DEMO=true is required (this entrypoint only serves the read-only demo)" >&2
    exit 1
    ;;
esac

python /opt/soc-ai/scripts/demo/mock_es.py --port 9200 \
  --fixtures /opt/soc-ai/soc_ai/demo/fixtures.json &
mock_pid=$!

# Supervise the mock. /healthz is pure app liveness — it never probes ES — so a
# mock that dies after startup would leave the app reporting healthy while
# silently serving empty grids. Watch the mock process; if it exits, stop the
# app (PID 1 after the exec below) so the platform restarts the whole container
# instead of showing a broken demo. Detached so it can't block the exec.
( while kill -0 "$mock_pid" 2>/dev/null; do sleep 5; done
  echo "demo-entrypoint: mock ES (pid $mock_pid) exited — stopping the app" >&2
  kill 1 2>/dev/null ) &

# exec so uvicorn is PID 1 and receives the platform's SIGTERM directly for a
# clean shutdown. "$@" is a passthrough for ad-hoc uvicorn flags; it is empty
# under docker-compose.demo.yml and render.yaml (neither passes extra args).
exec python -m uvicorn soc_ai.main:app --host 0.0.0.0 --port "${PORT:-8080}" "$@"
