#!/usr/bin/env bash
# first-verdict-timer.sh — measure the spec's day-1 bar on a fresh host:
# git clone → a first completed AI verdict, target ≤ 30 minutes.
#
# Run from the repo root AFTER filling setup.conf (see setup.conf.example).
# It times: setup.sh --auto (build + start + doctor), then polls until the
# first completed investigation appears — kick one off by clicking
# Investigate in the UI, or let the setup-time auto-triage opt-in do it.
#
# Release gate: run once per release on a fresh VM, one run per LLM route;
# record both times in the release notes.
#
# Exit contract: 0 = PASS (a verdict landed within the 1800s bar), 1 = no
# measurement (setup.sh failed, or no verdict inside the 60-minute window),
# 2 = OVER BAR (a verdict landed, but later than 1800s).
set -euo pipefail
cd "$(dirname "$0")/.."

t0=$(date +%s)
./setup.sh --auto \
  || { echo "TIMER: setup.sh failed at $(( $(date +%s) - t0 ))s"; exit 1; }
t_setup=$(( $(date +%s) - t0 ))
echo "TIMER: setup complete at ${t_setup}s"

# Read effective values from the generated .env: it intentionally carries
# duplicate keys (example base + appended managed block) — LAST value wins.
pw=$(grep '^BOOTSTRAP_ADMIN_PASSWORD=' .env | tail -1 | cut -d= -f2- | tr -d '\r') || true
port=$(grep '^SOC_AI_PORT=' .env | tail -1 | cut -d= -f2- | tr -d '\r') || true
port=${port:-8443}
base="https://localhost:${port}"

jar=$(mktemp); trap 'rm -f "$jar"' EXIT
_pw_json=${pw//\\/\\\\}
_pw_json=${_pw_json//\"/\\\"}
curl -fsk -c "$jar" -m 10 -X POST "${base}/api/v1/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${_pw_json}\"}" >/dev/null \
  || { echo "TIMER: login failed (changed admin password?)"; exit 1; }

# Count COMPLETED investigations via `status=complete`, not by grepping the
# `verdict` field. Verified against soc_ai/api/webui/routes_investigations.py:
# InvestigationRowOut.verdict is typed `str` (never null) and is populated by
# _shared._verdict(), which renders a not-yet-decided run as the literal
# string "untriaged" — so a naive `"verdict":"[a-z_]+"` count would match a
# still-RUNNING row too, stopping the clock the instant an investigation
# starts rather than when it finishes. `status` only reads "complete" once a
# real verdict lands — `_row_status()` downgrades a verdict-less "complete"
# row to "error" — so filtering on it server-side and reading the SQL-counted
# `total` (InvestigationListOut.total, counted over the filtered set, not the
# page) is the correct signal, and stays correct regardless of how many
# investigations exist (unlike counting regex matches inside a
# `limit`-capped page of rows).
count_verdicts(){
  curl -fsk -b "$jar" -m 10 "${base}/api/v1/investigations?status=complete&limit=1" \
    | grep -oE '"total":[0-9]+' | cut -d: -f2 || echo 0
}
baseline=$(count_verdicts)
echo "TIMER: waiting for a completed verdict (baseline: ${baseline})."
echo "TIMER: click Investigate on any alert now, or wait for the auto-triage sweep."

deadline=$(( t0 + 3600 ))
while [[ $(date +%s) -lt $deadline ]]; do
  n=$(count_verdicts)
  if [[ $n -gt $baseline ]]; then
    total=$(( $(date +%s) - t0 ))
    echo "TIMER: verdict #$(( baseline + 1 )) at ${total}s ($(( total / 60 ))m$(( total % 60 ))s) — bar is 1800s"
    # Exit: 0 PASS, 2 OVER BAR (see the contract note in the header) — never
    # conflate "too slow" with "never happened" (exit 1, below).
    if [[ $total -le 1800 ]]; then
      echo "TIMER: PASS"; exit 0
    else
      echo "TIMER: OVER BAR"; exit 2
    fi
  fi
  sleep 10
done
echo "TIMER: no verdict within 60 minutes"; exit 1
