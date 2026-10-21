#!/usr/bin/env bash
# Run one arm of the backtest replay against a running soc-ai. The runbook
# is docs/dev/eval-arms.md and the design record is
# docs/dev/specs/2026-10-08-swarm-triage-experiment-design.md.
#
#   scripts/eval/backtest-arm.sh <arm> <strategy> [window-days] [sample-size] [min-severity]
#
# Sets investigator_strategy on the running instance through the config
# override API, starts a backtest of the sample, polls until it ends,
# fetches the result and writes it to
# ${SOC_AI_ARMS_DIR:-evals/arms}/<arm>/backtest-<ts>.json. Restores
# investigator_strategy to "single" when it is done, even on failure or an
# interrupt (a trap on EXIT).
#
# window-days defaults to 30 and sample-size to 40, the backtest replay's
# 40 closed production alerts. min-severity is optional.
#
# ALERT_IDS_FILE, when set, names a file with one alert id per line. The
# started backtest then replays exactly those alerts: the request carries
# alert_ids and omits sample_size. Every arm writes the alert ids its own
# run replayed to <out_dir>/backtest-<ts>.ids, one per line, so arm A's
# file (run with no ALERT_IDS_FILE, a sampled window) feeds arms B to E:
#
#   scripts/eval/backtest-arm.sh A single
#   ALERT_IDS_FILE=evals/arms/A/backtest-<ts>.ids \
#     scripts/eval/backtest-arm.sh B spend
#
# With no ALERT_IDS_FILE, POST /api/v1/backtest takes no seed and no alert
# id list, so two calls can sample a different window of alerts.
#
# BASE_URL and SOC_AI_API_TOKEN come from the environment only, never from
# a flag, and this script never prints either of them.
#
# DRY_RUN=1 prints the steps this script would run and runs none of them.
#
# Exit codes: 0 the result was written. 2 a usage error, or BASE_URL/
# SOC_AI_API_TOKEN is unset. 1 a step failed; the strategy is still
# restored to single.
set -euo pipefail

usage() {
  echo "usage: $0 <arm> <strategy> [window-days] [sample-size] [min-severity]" >&2
  exit 2
}

[[ $# -ge 2 && $# -le 5 ]] || usage
arm="$1"
strategy="$2"
window_days="${3:-30}"
sample_size="${4:-40}"
min_severity="${5:-}"

known_strategies=(single spend ensemble advocates planes)
known=0
for s in "${known_strategies[@]}"; do
  [[ "$s" == "$strategy" ]] && known=1
done
if [[ $known -eq 0 ]]; then
  echo "backtest-arm: strategy is one of: ${known_strategies[*]}." >&2
  usage
fi

if [[ -z "${BASE_URL:-}" ]]; then
  echo "backtest-arm: BASE_URL is not set." >&2
  exit 2
fi
if [[ -z "${SOC_AI_API_TOKEN:-}" ]]; then
  echo "backtest-arm: SOC_AI_API_TOKEN is not set." >&2
  exit 2
fi
if [[ -n "${ALERT_IDS_FILE:-}" && ! -f "${ALERT_IDS_FILE}" ]]; then
  echo "backtest-arm: ALERT_IDS_FILE does not name a file: $ALERT_IDS_FILE" >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
helper=(python3 "$script_dir/backtest_arm.py")
out_dir="${SOC_AI_ARMS_DIR:-evals/arms}/$arm"
mkdir -p "$out_dir"

restore() {
  echo "backtest-arm: restoring investigator_strategy to single"
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    echo "DRY_RUN: ${helper[*]} set-strategy single"
    return 0
  fi
  if ! "${helper[@]}" set-strategy single; then
    echo "backtest-arm: restore to single failed. Set it back by hand." >&2
  fi
}
trap restore EXIT

start_args=("$window_days" "$sample_size" "$min_severity")
if [[ -n "${ALERT_IDS_FILE:-}" ]]; then
  start_args+=(--alert-ids-file "$ALERT_IDS_FILE")
fi

if [[ -n "${ALERT_IDS_FILE:-}" ]]; then
  echo "backtest-arm: arm $arm, strategy $strategy, window ${window_days}d, alert ids $ALERT_IDS_FILE"
else
  echo "backtest-arm: arm $arm, strategy $strategy, window ${window_days}d, sample $sample_size"
fi

if [[ "${DRY_RUN:-0}" == "1" ]]; then
  echo "DRY_RUN: ${helper[*]} set-strategy $strategy"
  echo "DRY_RUN: ${helper[*]} start ${start_args[*]}"
  echo "DRY_RUN: ${helper[*]} poll"
  echo "DRY_RUN: ${helper[*]} get <backtest-id> > $out_dir/backtest-<ts>.json"
  echo "DRY_RUN: ${helper[*]} ids < $out_dir/backtest-<ts>.json > $out_dir/backtest-<ts>.ids"
  exit 0
fi

"${helper[@]}" set-strategy "$strategy" >/dev/null

start_out="$("${helper[@]}" start "${start_args[@]}")"
refused="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("refused") or "")' "$start_out")"
if [[ -n "$refused" ]]; then
  echo "backtest-arm: the start call was refused: $refused" >&2
fi

status_out="$("${helper[@]}" poll)"
backtest_id="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("backtest_id") or "")' "$status_out")"
if [[ -z "$backtest_id" ]]; then
  echo "backtest-arm: no backtest id after polling. Nothing fetched." >&2
  exit 1
fi

ts="$(date -u +%Y-%m-%dT%H%M%SZ)"
result_path="$out_dir/backtest-$ts.json"
"${helper[@]}" get "$backtest_id" >"$result_path"
echo "backtest-arm: result written to $result_path"

ids_path="$out_dir/backtest-$ts.ids"
"${helper[@]}" ids <"$result_path" >"$ids_path"
echo "backtest-arm: replayed alert ids written to $ids_path"
