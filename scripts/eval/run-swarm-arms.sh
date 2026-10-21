#!/usr/bin/env bash
# Run the swarm triage experiment's named arms in order. The runbook is
# docs/dev/eval-arms.md and the design record is
# docs/dev/specs/2026-10-08-swarm-triage-experiment-design.md.
#
#   scripts/eval/run-swarm-arms.sh [arm ...]
#
# Each named arm runs through scripts/eval/run-arm.sh with 5 repeats and
# its own scripts/eval/arms/<arm>.env. The batch lands in
# ${SOC_AI_ARMS_DIR:-evals/arms}/<arm>/batch-<ts>/, and the arm's own run
# log is ${SOC_AI_ARMS_DIR:-evals/arms}/<arm>/run.log. A failed arm is
# logged and this script still runs the next arm. With no arm named, it
# runs all five: A B C D E.
#
# Run it detached, since the full set is many batches:
#
#   nohup scripts/eval/run-swarm-arms.sh > evals/arms/run-swarm-arms.log 2>&1 &
#
# SOC_AI_CLI and SOC_AI_ARMS_DIR carry through to run-arm.sh unchanged; see
# its own header for their meaning.
#
# DRY_RUN=1 prints the run-arm.sh command for each arm and runs none of
# them.
#
# Exit code: 0 every named arm's run-arm.sh exited 0. 1 at least one arm
# failed; the summary at the end names which.
set -uo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
run_arm="$script_dir/run-arm.sh"
repeats=5
concurrency=4
arms_dir="${SOC_AI_ARMS_DIR:-evals/arms}"

if [[ $# -gt 0 ]]; then
  arms=("$@")
else
  arms=(A B C D E)
fi

mkdir -p "$arms_dir"

failed=()
echo "run-swarm-arms: arms ${arms[*]}, $repeats repeats, concurrency $concurrency, output $arms_dir"

for arm in "${arms[@]}"; do
  arm_dir="$arms_dir/$arm"
  log="$arm_dir/run.log"
  mkdir -p "$arm_dir"
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "run-swarm-arms: arm $arm started $started, log $log"

  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    echo "DRY_RUN: SOC_AI_ARMS_DIR=$arms_dir $run_arm $arm $repeats $concurrency >> $log 2>&1"
    rc=0
  else
    SOC_AI_ARMS_DIR="$arms_dir" "$run_arm" "$arm" "$repeats" "$concurrency" >>"$log" 2>&1
    rc=$?
  fi

  ended="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "run-swarm-arms: arm $arm ended $ended, exit $rc"
  if [[ $rc -ne 0 ]]; then
    failed+=("$arm")
  fi
done

if [[ ${#failed[@]} -gt 0 ]]; then
  echo "run-swarm-arms: failed arms: ${failed[*]}" >&2
  exit 1
fi
echo "run-swarm-arms: every arm finished. Compare them with scripts/eval/compare-arms.py."
exit 0
