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
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

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
FROM node:20-bookworm-slim AS frontend

WORKDIR /fe

# Install against the lockfile first (cached unless package*.json changes).
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

# Build the production bundle (tsc -b && vite build → /fe/dist).
COPY frontend/ ./
RUN npm run build


# ── Stage 3: runtime ─────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# ── OS-level deps ─────────────────────────────────────────────────────────────
# curl: HEALTHCHECK; ca-certificates: trust chain for outbound HTTPS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
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
        --ssl-keyfile \"${SOC_AI_TLS_KEY}\""]
