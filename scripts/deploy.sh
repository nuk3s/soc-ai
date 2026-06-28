#!/usr/bin/env bash
# Deploy the working tree to the lab VM and (re)build the Docker stack.
#
# Canonical deployment is Docker (docker compose). This rsyncs the working tree
# to the VM, then `docker compose up -d --build` rebuilds the image and replaces
# the running container. Named volumes (the SQLite DB, blocklists, etc.) survive
# the rebuild, so data persists across deploys.
#
# Excludes are load-bearing — these live ONLY on the VM; the dev box doesn't have
# them (gitignored), so without the excludes `rsync --delete` would wipe them:
#   .env                          prod creds
#   /data/                        root-anchored prod SQLite dir (legacy host path).
#                                 NOTE: soc_ai/enrichment/data/ still ships — the
#                                 anchor keeps an unanchored 'data/' from matching it.
#   .ssh/                         so_pcap SSH key source
#   certs/                        TLS cert/key + the mounted so_pcap key (compose mounts ./certs)
#   docker-compose.override.yml   box-local mounts (e.g. the PCAP key)
#
# node_modules/ is excluded (huge); frontend/dist/ IS synced and baked into the image.
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
  --exclude='/data/' \
  --exclude='.ssh/' \
  --exclude='certs/' \
  --exclude='docker-compose.override.yml' \
  --exclude='.venv/' --exclude='evals/' \
  --exclude='node_modules/' --exclude='.git/' \
  --exclude='.coverage*' --exclude='.pytest_cache/' --exclude='.mypy_cache/' \
  --exclude='.ruff_cache/' --exclude='__pycache__/' --exclude='.worktrees/' \
  --exclude='.superpowers/' --exclude='.claude/' --exclude='.remember/' \
  ./ "${TARGET}:${DEST}/"

# Rebuild + replace the container, then wait for the app to answer on 8443.
ssh "${TARGET}" "cd ${DEST} && sudo docker compose up -d --build && \
  for i in \$(seq 1 20); do curl -ksf https://127.0.0.1:8443/healthz && break; sleep 3; done && echo"
