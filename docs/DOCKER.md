# Docker Deployment

This guide covers running soc-ai as a Docker container. It is an alternative to (or can
eventually replace) the rsync + systemd path described in [DEPLOYMENT.md](DEPLOYMENT.md).

---

## Quick start

> **The fast path is `./setup.sh`** in the repo root — a guided installer that
> does everything below (installs Docker if needed, writes `.env`, generates the
> cert + secrets, brings the stack up, seeds enrichment). The steps here are the
> manual equivalent / reference.

### 1. Populate `.env`

Copy `.env.example` to `.env` in the repo root and fill in all required values. The full
field reference is in `soc_ai/config.py`; the minimum required set is:

> **Security Onion account requirements** (which login/role each feature needs, and the
> audit-log grant that ack/escalate silently depends on) live in
> [SECURITY-ONION-SETUP.md](SECURITY-ONION-SETUP.md) — read it before your first write-back.

```ini
# Security Onion grid
SO_HOST=https://your-so-grid
SO_USERNAME=analyst@yourorg.example.com
SO_PASSWORD=<analyst-password>
SO_VERIFY_SSL=false

# Elasticsearch (same creds as SO)
ES_HOSTS=https://your-so-grid:9200
ES_USERNAME=${SO_USERNAME}
ES_PASSWORD=${SO_PASSWORD}
ES_VERIFY_SSL=false

# LiteLLM gateway
LITELLM_BASE_URL=https://your-litellm-gateway
LITELLM_API_KEY=sk-<your-token>

# Server — must match the paths you mount below
SOC_AI_HOST=0.0.0.0
SOC_AI_PORT=8443
SOC_AI_TLS_CERT=/etc/soc-ai/cert.pem
SOC_AI_TLS_KEY=/etc/soc-ai/key.pem

# Config-console secret encryption (required; see note below)
CONFIG_SECRET_KEY=<fernet-key>
```

The `.env` file is bind-mounted read-only into the container at runtime. It is listed in
`.dockerignore` and is never baked into an image layer.

#### CONFIG_SECRET_KEY

`CONFIG_SECRET_KEY` is required to use the admin config console's Danger Zone (persisting
encrypted secret overrides to the DB). Generate a key once and keep it in `.env`:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

When unset, the config console still works for non-secret settings, but secret fields
(passwords, API keys) cannot be edited via the UI.

---

### 2. Generate a TLS cert pair

uvicorn terminates TLS directly — no reverse proxy is needed. Create a `certs/` directory
in the repo root and generate a self-signed cert (or drop in your CA-signed pair):

```bash
mkdir -p ./certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -subj "/CN=soc-ai" \
  -addext "subjectAltName=DNS:soc-ai.local,IP:<your-host-ip>" \
  -keyout ./certs/key.pem \
  -out    ./certs/cert.pem
# The container runs as uid 1000 and must be able to READ these (openssl writes
# the key 0600 owned by you):
chmod 644 ./certs/cert.pem ./certs/key.pem
```

The compose file bind-mounts `./certs/cert.pem` → `/etc/soc-ai/cert.pem` and
`./certs/key.pem` → `/etc/soc-ai/key.pem` (both read-only). The container's `SOC_AI_TLS_CERT`
and `SOC_AI_TLS_KEY` env vars point at these paths by default; override in `.env` if you
mount them elsewhere.

> **SELinux hosts (Fedora / RHEL / Rocky / podman):** the cert/key bind mounts
> already ship with the `,Z` relabel suffix (`:ro,Z`) so they work out of the box;
> without it the container gets `Permission denied` even at mode 644. If you add
> your own bind mounts on an SELinux host, append `,Z` to them too. On non-SELinux
> hosts the suffix is a harmless no-op.

---

### 3. Build and start

```bash
docker compose up -d
```

Watch startup (DB migration runs automatically on first boot):

```bash
docker compose logs -f soc-ai
```

Health check:

```bash
curl -k https://localhost:8443/healthz
# → {"status":"ok","version":"1.0.0","so_auth":"kratos",...}
```

---

### 4. Open the web UI

Browse to **`https://<host>:8443/app`** and log in with the bootstrap admin
(username `admin`, the `BOOTSTRAP_ADMIN_PASSWORD` from your `.env`). First visit
will prompt you to accept the self-signed cert.

The image serves two surfaces on the same port (bare `/` redirects to `/app`):

| Path        | What                                                |
|-------------|-----------------------------------------------------|
| `/app`      | the React console (alerts, investigations, config)  |
| `/api/v1/*` | the JSON API the console (and integrations) use     |

---

## Required mounts summary

| Host path / volume       | Container path                      | Mode | Purpose                                    |
|--------------------------|-------------------------------------|------|--------------------------------------------|
| `./certs/cert.pem`       | `/etc/soc-ai/cert.pem`              | ro   | TLS certificate                            |
| `./certs/key.pem`        | `/etc/soc-ai/key.pem`               | ro   | TLS private key                            |
| `.env` (via `env_file`)  | `/opt/soc-ai/.env` (bind by Docker) | ro   | All configuration + secrets                |
| `soc_ai_data` (volume)   | `/var/lib/soc-ai/data`              | rw   | SQLite DB + session store                  |
| `soc_ai_blocklists` (vol)| `/var/lib/soc-ai/blocklists`        | rw   | URLhaus/Feodo/Tor/internal blocklist cache |
| `soc_ai_maxmind` (vol)   | `/var/lib/soc-ai/maxmind`           | rw   | MaxMind GeoLite2 .mmdb files               |
| `soc_ai_cloud_prefixes`  | `/var/lib/soc-ai/cloud_prefixes`    | rw   | AWS/GCP/Azure/Cloudflare prefix JSON       |

The four named volumes are created automatically by `docker compose up`. They persist across
`docker compose down` (data is only deleted with `docker compose down -v`).

---

## Seeding enrichment data

Blocklists, GeoIP, and cloud prefixes are populated by the `python -m soc_ai blocklists refresh` CLI
command. Run it once after first boot and then on a weekly schedule:

```bash
# Initial seed (runs inside the container, writes to the mounted volumes)
docker compose run --rm soc-ai python -m soc_ai blocklists refresh

# Or as a cron job on the host (via docker exec):
docker exec soc-ai python -m soc_ai blocklists refresh
```

MaxMind GeoLite2 requires a free license key (`MAXMIND_LICENSE_KEY` in `.env`); without it
the refresh skips GeoIP but everything else still works.

---

## Updating

One command:

```bash
git pull && docker compose up -d --build
```

That rebuilds the image and recreates the container. Nothing else is required.
Specifically:

- **The database migrates itself.** Schema migrations run automatically when the
  container starts (inside a transaction, so a failure rolls back cleanly). You
  never run `alembic` by hand.
- **Your data stays put.** The SQLite DB, sessions, and enrichment caches live in
  named Docker volumes, which survive container replacement. Only
  `docker compose down -v` deletes them.
- **Your `.env` keeps working.** Unknown keys are ignored, so a setting that was
  removed or renamed in a new version won't stop the container from booting.

Verify the new build is healthy:

```bash
docker compose ps                          # soc-ai should be "healthy"
curl -k https://localhost:8443/healthz      # → {"status":"ok","version":"…"}
```

### Back up before a major upgrade (optional, cheap)

The whole state is one SQLite file. Copy it out first if you want a restore point:

```bash
docker compose cp soc-ai:/var/lib/soc-ai/data/soc-ai.db ./soc-ai.db.bak
```

### Rolling back

Check out the previous tag and rebuild — the volumes are untouched, and the
schema only ever moves forward, so older code reads a newer DB fine for the
additive changes a patch release makes:

```bash
git checkout v1.0.0 && docker compose up -d --build
```

### What "no breaking updates" means here

Within a major version, an update will not require a manual migration or a change
to your `.env`. New settings ship with safe defaults, renamed settings keep their
old name as an alias (e.g. `HEAVY_MODEL` still works after the rename to
`ANALYST_MODEL`), and migrations are additive. Anything that genuinely can't keep
that promise waits for the next major version and gets called out in
[CHANGELOG.md](../CHANGELOG.md).

---

## Relationship to rsync + systemd

The Docker path and the rsync + systemd path (described in `DEPLOYMENT.md`) are equivalent
in production capability. Choose based on your preferences:

| Concern          | systemd (DEPLOYMENT.md)          | Docker (this guide)                       |
|------------------|----------------------------------|-------------------------------------------|
| Isolation        | OS user + systemd hardening      | Container namespace                       |
| Updates          | rsync + `uv sync` + restart      | `docker compose build` + `up -d`          |
| Data persistence | Host filesystem                  | Named Docker volumes                      |
| TLS              | Host cert paths in `.env`        | `./certs/` bind-mount                     |
| Enrichment data  | `/var/lib/soc-ai/...` on host    | Named volumes (same CLI command to seed)  |
| Port binding     | Direct (uvicorn on :8443)        | Direct (port-mapped to :8443)             |

The Docker path is slightly easier to reason about for upgrades (the image is immutable;
state is in volumes) and avoids the SELinux caveats on Fedora hosts. Both paths are
supported.

---

## Gotchas worth knowing before your first hunt

These bite people on a real install. None of them show up in `/healthz` (which only
checks that the server is up — it never touches your upstreams), so they surface as a
*failed first hunt*, not a failed boot.

### Upstream TLS trust (self-signed SO / ES / LiteLLM / MISP)

The container image ships only the public CA bundle. If any upstream uses a self-signed
or internal-CA certificate (typical for a lab Security Onion, Elasticsearch, LiteLLM, or
MISP), the very first hunt fails with `CERTIFICATE_VERIFY_FAILED` in
`docker compose logs soc-ai` — even though `/healthz` is green. Fix it in `.env`:

```ini
SO_VERIFY_SSL=false        # Security Onion web API (Kratos)
ES_VERIFY_SSL=false        # Elasticsearch
LITELLM_VERIFY_SSL=false   # LiteLLM gateway
```

Better than verify-off, for SO and MISP you can point at the CA file instead (bind-mount
the CA into the container and reference it):

```ini
SO_CA_BUNDLE=/etc/soc-ai/so-ca.pem
MISP_CA_BUNDLE=/etc/soc-ai/misp-ca.pem
```

**Elasticsearch has no CA-bundle option** — for ES it's `ES_VERIFY_SSL=false` or a cert
the container's public bundle already trusts. (If you bind-mount a CA file, add the `,Z`
SELinux relabel suffix like the cert mounts do.)

### Port 8443 collides with Security Onion's own nginx

A stock Security Onion manager already runs nginx on 8443 (and you may have an earlier
soc-ai there too). If you deploy soc-ai on or near the SO box, remap the **host** side of
the port mapping with `SOC_AI_PORT` in `.env`:

```ini
SOC_AI_PORT=9443    # host side; the container still listens on 8443 internally
```

Then open the new port on hosts with a firewall / SELinux:

```bash
sudo firewall-cmd --add-port=9443/tcp --permanent && sudo firewall-cmd --reload
```

### Hostname upstreams don't resolve inside the bridge network

A URL like `https://litellm.example.com:4000` that resolves *on the host* (via the host's
`/etc/hosts` or a local resolver) will **not** resolve inside the container's bridge
network — the host's `/etc/hosts` does not propagate into the container. The first hunt
then fails with a DNS/connection error. Three ways out:

- Use an **IP address** in `.env` (simplest): `LITELLM_BASE_URL=https://10.0.0.5:4000`.
- Add an `extra_hosts:` entry to the `soc-ai` service in `docker-compose.yml`:
  ```yaml
      extra_hosts:
        - "litellm.example.com:10.0.0.5"
  ```
- Point the names at **real DNS** the container can reach.

### PCAP is off by default (key mount is commented out)

The `./certs/so_pcap` SSH-key bind mount in `docker-compose.yml` is **commented out** by
default, so live PCAP retrieval is disabled. To enable it:

1. Uncomment the mount line in `docker-compose.yml` (keep the trailing `,Z` SELinux suffix):
   ```yaml
       - ./certs/so_pcap:/etc/soc-ai/so_pcap:ro,Z
   ```
2. Drop a **de-privileged sensor SSH key** at `./certs/so_pcap` and make it readable by
   the in-container uid 1000: `chmod 644 ./certs/so_pcap`.
3. Set in `.env`:
   ```ini
   PCAP_ENABLED=true
   SO_SSH_HOST=<sensor-host-or-ip>
   SO_SSH_KEY=/etc/soc-ai/so_pcap
   ```

(soc-ai fails fast at startup if `PCAP_ENABLED=true` but `SO_SSH_HOST` is empty.) See
[SECURITY-ONION-SETUP.md](SECURITY-ONION-SETUP.md) for why this is an SSH key, not an
ES/SO role.

### Blocklist refresh has no scheduler in the Docker path

The systemd path can run a timer, but the Docker stack ships **no scheduler** for
enrichment refresh. Without one, blocklists / GeoIP / cloud prefixes go stale. Add a host
cron (or any scheduler) that execs the refresh on a cadence:

```cron
# /etc/cron.d/soc-ai-blocklists — weekly refresh, Sundays 03:17
17 3 * * 0  root  docker compose -f /opt/soc-ai/docker-compose.yml exec -T soc-ai python -m soc_ai blocklists refresh
```

### 1 GB memory cap can OOM-kill a runaway hunt

`docker-compose.yml` sets a `1G` memory limit (under cgroup v2 this is a hard cap, not a
hint). A pathological hunt that accumulates a lot of tool output can hit it and get the
container **OOM-killed** (it then restarts via `restart: unless-stopped`). If you see the
container restarting mid-hunt, raise `deploy.resources.limits.memory` in
`docker-compose.yml`.

---

## Troubleshooting

**Container exits immediately after start**
Check that `.env` exists and `SOC_AI_TLS_CERT` / `SOC_AI_TLS_KEY` point at files that are
actually mounted. `docker compose logs soc-ai` will show the pydantic-settings validation
error if a required field is missing.

**Health check failing**
The default `start_period` is 60s to allow the DB migration to run on first boot. If it
consistently fails, check `docker compose logs soc-ai` for the uvicorn startup traceback.

**First "Hunt with AI" in the userscript fails with `TypeError: Failed to fetch`**
The browser has not trusted the self-signed cert yet. Visit `https://<host>:8443/healthz`
once in the same browser, accept the cert warning, then retry. See DEPLOYMENT.md §11.

**Enrichment returns no GeoIP / ASN data**
Either `MAXMIND_LICENSE_KEY` is not set in `.env`, or the blocklist refresh has not been
run. Run: `docker compose run --rm soc-ai python -m soc_ai blocklists refresh`.
