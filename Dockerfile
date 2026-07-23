# syntax=docker/dockerfile:1
# ─────────────────────────────────────────────────────────────────────────────
# soc-ai — multi-stage build
#
# Stage 1 (builder):  installs uv, creates a venv, and syncs production deps.
# Stage 2 (frontend): builds the React SPA bundle (frontend/dist).
# Stage 3 (runtime):  copies the venv + source + SPA into a slim Python 3.12
#                     image and runs as a non-root user.
#
# Nothing secret (no .env, no certs, no data) is baked into the image.
# All mutable state is injected at runtime via bind-mounts and volumes:
#   - /opt/soc-ai/.env          (read-only bind from the host)
#   - /etc/soc-ai/cert.pem      (read-only bind)
#   - /etc/soc-ai/key.pem       (read-only bind)
#   - /var/lib/soc-ai/data      (named volume — SQLite DB lives here)
#   - /var/lib/soc-ai/blocklists  (named volume — optional, survives restarts)
#   - /var/lib/soc-ai/maxmind     (named volume — optional GeoIP .mmdb files)
#   - /var/lib/soc-ai/cloud_prefixes (named volume — optional cloud prefix JSON)
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: dependency build ─────────────────────────────────────────────────
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim@sha256:e5b65587bce7de595f299855d7385fe7fca39b8a74baa261ba1b7147afa78e58 AS builder
# ^ pinned by digest (supply-chain hardening, mirrors the SHA-pinned GitHub
#   Actions in release.yml); tag above is for humans only — bump both
#   together when refreshing. Resolve a new digest with:
#     docker buildx imagetools inspect ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /build

# Copy only the files uv needs to resolve and lock deps.
# uv sync --no-install-project means it installs deps but not the project
# package itself; we copy the full source in the runtime stage.
COPY pyproject.toml uv.lock ./

# Sync production deps (no dev extras) into /build/.venv.
# --frozen: honour the lock file exactly (no re-resolution).
# --no-install-project: don't attempt to install the not-yet-copied source.
# --no-dev: skip [dependency-groups.dev].
RUN uv sync --frozen --no-install-project --no-dev


# ── Stage 2: frontend build (React SPA → /fe/dist) ────────────────────────────
# Built here and copied into the runtime image at /opt/soc-ai/frontend/dist —
# where main.py's FRONTEND_DIST resolves, so FastAPI serves the SPA at /app.
FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS frontend
# ^ digest-pinned (see the builder stage's FROM comment above); tag: 22-bookworm-slim.

WORKDIR /fe

# Install against the lockfile first (cached unless package*.json changes).
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

# Build the production bundle (tsc -b && vite build → /fe/dist).
COPY frontend/ ./
RUN npm run build


# ── Stage 3: runtime ─────────────────────────────────────────────────────────
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS runtime
# ^ digest-pinned (see the builder stage's FROM comment above); tag: 3.12-slim.

# ── OS-level deps ─────────────────────────────────────────────────────────────
# curl: HEALTHCHECK; ca-certificates: trust chain for outbound HTTPS;
# openssh-client: the PCAP tool (soc_ai/tools/get_pcap.py) shells out to `ssh` to
# run tcpdump on the Security Onion sensor — without it, t_get_pcap fails with
# "ssh: not found" (the host having ssh masked this on non-container installs).
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates openssh-client \
    && rm -rf /var/lib/apt/lists/*

# ── Non-root user ─────────────────────────────────────────────────────────────
RUN groupadd --gid 1000 soc-ai \
    && useradd --uid 1000 --gid soc-ai --no-create-home --shell /sbin/nologin soc-ai

# ── Directory layout ──────────────────────────────────────────────────────────
# /opt/soc-ai          — application source
# /var/lib/soc-ai/...  — runtime-writable data (mounted as volumes)
# /etc/soc-ai          — TLS cert + key (mounted read-only by the host)
RUN mkdir -p \
        /opt/soc-ai \
        /var/lib/soc-ai/data \
        /var/lib/soc-ai/blocklists \
        /var/lib/soc-ai/maxmind \
        /var/lib/soc-ai/cloud_prefixes \
        /etc/soc-ai \
    && chown -R soc-ai:soc-ai \
        /opt/soc-ai \
        /var/lib/soc-ai \
        /etc/soc-ai

# ── Copy venv from builder ─────────────────────────────────────────────────────
COPY --from=builder --chown=soc-ai:soc-ai /build/.venv /opt/soc-ai/.venv

# ── Copy application source ────────────────────────────────────────────────────
# soc_ai/ package (contains migrations in soc_ai/store/migrations/ and the
# CLI-only soc_ai/store/alembic.ini — the app runs migrations programmatically
# from Path(__file__), so the ini is only for the `alembic` CLI:
#   alembic -c soc_ai/store/alembic.ini upgrade head
# pyproject.toml: read by some tooling; harmless to include.
COPY --chown=soc-ai:soc-ai soc_ai/       /opt/soc-ai/soc_ai/
COPY --chown=soc-ai:soc-ai pyproject.toml /opt/soc-ai/pyproject.toml

# runbooks/: the shipped starter-pack markdown (runbooks/starter-pack/*.md).
# POST /runbooks/starter-pack resolves it as parent-of-package (soc_ai/store/
# runbook_pack.py:STARTER_PACK_DIR → /opt/soc-ai/runbooks) — same layout trick
# as the frontend bundle below. Without this COPY the endpoint 404s honestly.
COPY --chown=soc-ai:soc-ai runbooks/     /opt/soc-ai/runbooks/

# Demo packaging (inert in normal deployments — the default CMD below never
# touches it). mock_es.py + its demo_dataset import are the bundled loopback
# Elasticsearch/LLM stand-in that docker/demo-entrypoint.sh starts on
# 127.0.0.1:9200; ONLY these two files are un-ignored in .dockerignore — the
# rest of scripts/ never ships in the image. The entrypoint itself is selected
# explicitly by docker-compose.demo.yml / render.yaml.
COPY --chown=soc-ai:soc-ai scripts/demo/mock_es.py scripts/demo/demo_dataset.py \
     /opt/soc-ai/scripts/demo/
COPY --chmod=0755 --chown=soc-ai:soc-ai docker/demo-entrypoint.sh \
     /opt/soc-ai/docker/demo-entrypoint.sh

# ── Copy the built React SPA ───────────────────────────────────────────────────
# FastAPI serves this at /app (mounted only when the dir exists). Without it the
# app still boots and the JSON API works, but /app 404s.
COPY --from=frontend --chown=soc-ai:soc-ai /fe/dist /opt/soc-ai/frontend/dist

WORKDIR /opt/soc-ai

# ── Environment ───────────────────────────────────────────────────────────────
# PATH: venv bin dir takes precedence over system Python.
# PYTHONPATH: makes soc_ai importable without an editable install — hatchling
#   (the build backend) is not a runtime dep, so we skip pip install entirely.
# pydantic-settings reads .env relative to cwd (/opt/soc-ai) — WORKDIR above.
# TLS + data-dir defaults match the compose volume mount paths; all can be
# overridden in .env without rebuilding the image.
ENV PATH="/opt/soc-ai/.venv/bin:$PATH" \
    PYTHONPATH="/opt/soc-ai" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SOC_AI_HOST="0.0.0.0" \
    SOC_AI_PORT="8443" \
    SOC_AI_TLS_CERT="/etc/soc-ai/cert.pem" \
    SOC_AI_TLS_KEY="/etc/soc-ai/key.pem" \
    SOC_AI_DATA_DIR="/var/lib/soc-ai/data" \
    BLOCKLIST_DATA_DIR="/var/lib/soc-ai/blocklists" \
    MAXMIND_DATA_DIR="/var/lib/soc-ai/maxmind" \
    CLOUD_PREFIX_DATA_DIR="/var/lib/soc-ai/cloud_prefixes" \
    HOME="/var/lib/soc-ai"

# Console entry point. Stage 1's `uv sync --no-install-project` installs deps but
# NOT the project, so pyproject's [project.scripts] `soc-ai` is never generated in
# the venv — yet the docs and operator muscle-memory expect `soc-ai <cmd>` (backup,
# restore, blocklists refresh, audit verify, doctor) to work in-container (e.g.
# `docker exec soc-ai soc-ai backup`). Ship a tiny wrapper on PATH that runs the
# CLI through the venv python; PYTHONPATH (set above) makes soc_ai importable.
RUN printf '#!/opt/soc-ai/.venv/bin/python\nimport sys\nfrom soc_ai.cli import main\nsys.exit(main())\n' \
      > /usr/local/bin/soc-ai \
    && chmod 0755 /usr/local/bin/soc-ai

USER soc-ai

EXPOSE 8443

# ── Health check ──────────────────────────────────────────────────────────────
# /healthz is served over HTTPS with a self-signed cert; -k skips verify.
# Interval is generous (30s) so a slow cold-start (DB migration + bootstrap)
# doesn't flip the container unhealthy before the server is ready.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -fsk https://127.0.0.1:8443/healthz || exit 1

# ── Default command ───────────────────────────────────────────────────────────
# Invoked as `python -m uvicorn`, NOT the `uvicorn` console script: the venv is
# built at /build/.venv (Stage 1) and copied to /opt/soc-ai/.venv, so the
# script's baked-in shebang (#!/build/.venv/bin/python) is dead — but the venv
# python + the uvicorn module are both fine. Cert/key paths come from ENV above.
CMD ["sh", "-c", \
     "exec python -m uvicorn soc_ai.main:app \
        --host 0.0.0.0 \
        --port 8443 \
        --ssl-certfile \"${SOC_AI_TLS_CERT}\" \
        --ssl-keyfile \"${SOC_AI_TLS_KEY}\" \
        --ssl-ciphers 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM'"]
