#!/usr/bin/env bash
# Run one arm of the two-arm synthetic eval. The runbook is docs/dev/eval-arms.md.
#
#   scripts/eval/run-arm.sh <arm-name> [repeats] [concurrency]
#
# Run it from the install directory as the service user. It runs three steps:
# synth-clean, a local validate-batch over every synth scenario, synth-clean.
# The local batch makes no oracle call, and no data leaves the host. The batch
# lands in ${SOC_AI_ARMS_DIR:-evals/arms}/<arm-name>/batch-<ts>/.
#
# repeats defaults to 5 and concurrency to 4.
#
# SOC_AI_CLI is the command line that runs soc-ai. The default is "soc-ai". A
# second checkout passes its own interpreter line. NAME=VALUE words come first:
#
#   SOC_AI_CLI="PYTHONPATH=<checkout> <install>/.venv/bin/python -m soc_ai.cli"
#
# Run one arm at a time. synth-clean deletes every synthetic document, the
# plants of a running arm too.
#
# Exit codes: 0 the batch ran and the grid is clean. 2 a usage error. 3 the
# first synth-clean failed, and no batch ran. 4 the last synth-clean failed.
# Any other code is the exit code of validate-batch.
set -euo pipefail

usage() {
  echo "usage: $0 <arm-name> [repeats] [concurrency]" >&2
  exit 2
}

[[ $# -ge 1 && $# -le 3 ]] || usage
arm="$1"
repeats="${2:-5}"
concurrency="${3:-4}"
if [[ ! "$arm" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "run-arm: an arm name holds letters, digits, '.', '_' and '-'." >&2
  usage
fi
if [[ ! "$repeats" =~ ^[1-9][0-9]*$ || ! "$concurrency" =~ ^[1-9][0-9]*$ ]]; then
  echo "run-arm: repeats and concurrency are positive integers." >&2
  usage
fi

read -r -a cli <<<"${SOC_AI_CLI:-soc-ai}"
if [[ ${#cli[@]} -eq 0 ]]; then
  echo "run-arm: SOC_AI_CLI is empty." >&2
  usage
fi
out="${SOC_AI_ARMS_DIR:-evals/arms}/$arm"

# env runs the command line, with any NAME=VALUE words of SOC_AI_CLI set first.
soc_ai() {
  env "${cli[@]}" "$@"
}

closing_clean() {
  if soc_ai synth-clean; then
    return 0
  fi
  echo "run-arm: synth-clean failed after the batch. Synthetic documents stay in logs-synth-*." >&2
  echo "run-arm: run '${cli[*]} synth-clean' before the next arm." >&2
  return 1
}

# The INT and TERM trap below calls this function.
# shellcheck disable=SC2329
on_signal() {
  echo "run-arm: interrupted. The plants of this arm are removed now." >&2
  closing_clean || true
  exit 130
}

mkdir -p "$out"
echo "run-arm: arm $arm, $repeats repeats, concurrency $concurrency, output $out"
echo "run-arm: soc-ai command line: ${cli[*]}"

if ! soc_ai synth-clean; then
  echo "run-arm: synth-clean failed before the batch. No batch ran." >&2
  echo "run-arm: check SOC_AI_CLI, the .env in this directory and the grid." >&2
  exit 3
fi

trap on_signal INT TERM
batch_rc=0
soc_ai validate-batch \
  --oql "event.dataset:suricata.alert" \
  --n 1 \
  --synth-set all \
  --repeats "$repeats" \
  --no-meta \
  --concurrency "$concurrency" \
  --max-consecutive-failures 15 \
  --local \
  --out-dir "$out" || batch_rc=$?
trap - INT TERM

clean_rc=0
closing_clean || clean_rc=4

# batch-<ts> names sort in time order, so the last match is this run's batch.
batch_dir=""
for dir in "$out"/batch-*/; do
  [[ -d "$dir" ]] && batch_dir="${dir%/}"
done
if [[ -n "$batch_dir" ]]; then
  echo "run-arm: batch directory: $batch_dir"
  echo "run-arm: compare it with: scripts/eval/compare-arms.py <batch-dir-A> $batch_dir"
fi

if [[ $batch_rc -ne 0 ]]; then
  echo "run-arm: validate-batch exited with $batch_rc." >&2
  exit "$batch_rc"
fi
exit "$clean_rc"
