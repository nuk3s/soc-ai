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
#   caddy-root.crt                the Caddy CA root that scripts/tls-proxy.sh exports on the VM
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
  `#  a backup archive left beside the compose file. Two of them vanished on` \
  `#  2026-10-05 when a deploy ran minutes after the backup.` \
  --exclude='*.tar.gz' --exclude='/backups/' \
  --exclude='.ssh/' \
  --exclude='certs/' --exclude='caddy-root.crt' \
  --exclude='docker-compose.override.yml' \
  --exclude='.venv/' --exclude='evals/' \
  --exclude='node_modules/' --exclude='.git/' \
  --exclude='.coverage*' --exclude='.pytest_cache/' --exclude='.mypy_cache/' \
  --exclude='.ruff_cache/' --exclude='__pycache__/' --exclude='.worktrees/' \
  --exclude='.superpowers/' --exclude='.claude/' --exclude='.remember/' \
  ./ "${TARGET}:${DEST}/"

# Tag the build with the date and the commit, and stamp the image with the
# commit, so the VM never runs an image called ":latest". Both values go into
# the VM's .env, so a later plain `docker compose up -d` (the TLS script, a
# restart by hand) keeps the same tag and never pulls the public release image
# over the deployed build. The three newest dev tags stay; older ones go.
COMMIT="$(git -C "$(dirname "$0")/.." rev-parse HEAD)"
TAG="dev-$(date -u +%Y%m%d)-${COMMIT:0:8}"
ssh "${TARGET}" "cd ${DEST} && touch .env && sed -i '/^SOC_AI_IMAGE_TAG=/d;/^SOC_AI_COMMIT=/d' .env && \
  printf 'SOC_AI_IMAGE_TAG=%s\nSOC_AI_COMMIT=%s\n' '${TAG}' '${COMMIT}' >> .env"

# Rebuild + replace the container, then wait for the app to answer on 8443.
# The health-wait must FAIL the deploy if the app never comes up — a bare
# `for … break` loop always exits 0, so a container that crash-loops would be
# reported as a successful deploy. Track success explicitly and exit non-zero.
ssh "${TARGET}" "cd ${DEST} && sudo docker compose up -d --build && \
  ok=0; for i in \$(seq 1 20); do if curl -ksf https://127.0.0.1:8443/healthz >/dev/null || curl -sf http://127.0.0.1:8443/healthz >/dev/null; then ok=1; break; fi; sleep 3; done; \
  if [ \"\$ok\" != 1 ]; then echo 'DEPLOY HEALTHCHECK FAILED: app did not answer /healthz after ~60s' >&2; exit 1; fi; \
  echo 'healthy'; \
  sudo docker images ghcr.io/nuk3s/soc-ai --format '{{.Tag}}' | grep '^dev-' | sort -r | tail -n +4 | xargs -r -I{} sudo docker rmi ghcr.io/nuk3s/soc-ai:{} >/dev/null 2>&1 || true"
