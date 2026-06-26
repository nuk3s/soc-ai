#!/usr/bin/env bash
# Deploy the working tree to the lab VM, then uv-sync + restart.
#
# Excludes are load-bearing: NEVER sync .env (clobbers prod creds), data/ (the
# prod SQLite DB at /opt/soc-ai/data/soc-ai.db — wiping it loses investigations /
# config_overrides / users / chat), or .ssh/ (the so_pcap SSH key for PCAP fetch).
# The dev box has none of these dirs (gitignored), so WITHOUT the excludes
# rsync --delete deletes them on the VM. See reference_vm_deploy.
#
# node_modules/ is excluded (huge, not needed on the VM) but frontend/dist/ IS
# synced — the FastAPI app serves that built React bundle at /app.
set -euo pipefail

# Deploy target precedence: $1 arg → $SOC_AI_DEPLOY_TARGET env → ./.deploy-target
# file (gitignored, so the real host stays out of the public repo) → a loud
# placeholder. This keeps the lab's deploy a no-arg `scripts/deploy.sh` while the
# published repo carries no environment-specific host.
_target_file="$(cd "$(dirname "$0")/.." && pwd)/.deploy-target"
TARGET="${1:-${SOC_AI_DEPLOY_TARGET:-$([ -f "$_target_file" ] && head -1 "$_target_file" || echo 'soc-ai@REPLACE-WITH-DEPLOY-HOST')}}"
DEST="${2:-/opt/soc-ai}"

rsync -az --delete \
  --exclude='.env' --exclude='.env.*' \
  --exclude='data/' \
  --exclude='.ssh/' \
  --exclude='.venv/' --exclude='evals/' \
  --exclude='node_modules/' --exclude='.git/' \
  --exclude='.coverage*' --exclude='.pytest_cache/' --exclude='.mypy_cache/' \
  --exclude='.ruff_cache/' --exclude='__pycache__/' --exclude='.worktrees/' \
  --exclude='.superpowers/' --exclude='.claude/' --exclude='.remember/' \
  ./ "${TARGET}:${DEST}/"

ssh "${TARGET}" "cd ${DEST} && uv sync -q && sudo systemctl restart soc-ai && sleep 4 \
  && systemctl is-active soc-ai && curl -ks https://127.0.0.1:8443/healthz && echo"
