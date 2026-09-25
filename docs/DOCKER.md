# Docker deployment

This guide covers how to run soc-ai as a Docker container. It is an alternative to the
rsync + systemd path in [DEPLOYMENT.md](DEPLOYMENT.md), and it can replace that path later.

---

## Quick start

> **The fast path is `./setup.sh`** in the repo root. That guided installer does
> everything below. It installs Docker if the host needs it, writes `.env`,
> generates the certificate and the secrets, starts the stack, and seeds the
> enrichment data. The steps here are the manual equivalent, for reference.

### 1. Populate `.env`

Copy `.env.example` to `.env` in the repo root. Fill in every required value.
`soc_ai/config.py` holds the full field reference. The minimum set is:

> The Security Onion account requirements live in
> [SECURITY-ONION-SETUP.md](SECURITY-ONION-SETUP.md). That page says which login and
> role each feature needs. It also covers the audit-log grant that ack and escalate
> silently depend on. Read it before your first write-back.

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

Docker bind-mounts the `.env` file read-only into the container at runtime.
`.dockerignore` lists the file, so no image layer ever holds it.

#### CONFIG_SECRET_KEY

The Danger Zone in the admin config console needs `CONFIG_SECRET_KEY`. The key encrypts a
secret override before soc-ai stores it in the database. Generate a key once and keep it
in `.env`:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Without the key, the config console still works for a non-secret setting. You cannot edit
a secret field such as a password or an API key in the UI.

---

### 2. Generate a TLS cert pair

uvicorn terminates TLS directly, so you need no reverse proxy. Create a `certs/` directory
in the repo root. Generate a self-signed certificate there, or copy in your CA-signed pair:

```bash
mkdir -p ./certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -subj "/CN=soc-ai" \
  -addext "subjectAltName=DNS:soc-ai.local,IP:<your-host-ip>" \
  -keyout ./certs/key.pem \
  -out    ./certs/cert.pem
# The container runs as uid 1000 and must be able to READ these. Keep the cert
# world-readable (0644) but the private key group-readable only (0640) so it
# isn't world-readable:
chmod 644 ./certs/cert.pem
chmod 640 ./certs/key.pem
```

The compose file bind-mounts `./certs/cert.pem` to `/etc/soc-ai/cert.pem` and
`./certs/key.pem` to `/etc/soc-ai/key.pem`. Both mounts are read-only. The
`SOC_AI_TLS_CERT` and `SOC_AI_TLS_KEY` variables in the container point at these paths by
default. Override them in `.env` if you mount the files elsewhere.

> **SELinux hosts: Fedora, RHEL, Rocky and podman.** The certificate and key bind
> mounts already ship with the `,Z` relabel suffix (`:ro,Z`), so they work at once.
> Without that suffix the container gets `Permission denied`, even at mode 644. Append
> `,Z` to your own bind mounts on an SELinux host too. On a host without SELinux the
> suffix does nothing.

#### Replacing the TLS cert

To swap the self-signed pair for a certificate from your internal CA or from Let's
Encrypt, copy the new files to the same mounted paths. Then restart the container.
soc-ai reads the certificate and the key once at startup, so a swap does nothing
until you restart:

```bash
cp your-ca-cert.pem  ./certs/cert.pem   # the full chain (leaf + intermediates)
cp your-ca-key.pem   ./certs/key.pem
chmod 644 ./certs/cert.pem
chmod 640 ./certs/key.pem
docker compose restart soc-ai
```

Keep the filenames `cert.pem` and `key.pem`, because the compose mounts and the
`SOC_AI_TLS_CERT` and `SOC_AI_TLS_KEY` variables point at them. You can also update both
to match new names. On an SELinux host the `,Z` relabel applies automatically at the next
start.

---

### 3. Build and start

```bash
docker compose up -d
```

Watch the startup. The database migration runs automatically on the first boot:

```bash
docker compose logs -f soc-ai
```

Run the liveness check. It says whether the server answers:

```bash
curl -k https://localhost:8443/healthz
# → {"status":"alive","checks":"none — liveness only, no dependency is probed. …",
#    "version":"1.5.0","so_auth":"kratos",...}
```

This check probes nothing. It stays green with an unreachable grid, a dead model
gateway and no analyst model configured. The container healthcheck polls it, so
`docker ps` reporting `healthy` means the process is up. It says nothing about
the install. For that, run the doctor:

```bash
docker compose exec soc-ai python -m soc_ai doctor
```

---

### 4. Open the web UI

Open `https://<host>:8443/app` and log in as the bootstrap admin. The
username is `admin`. Use `BOOTSTRAP_ADMIN_PASSWORD` from `.env` if you set it.
Otherwise soc-ai generated the password and printed it once to the container log.
Recover it with:

```bash
docker compose logs soc-ai | grep -i password
```

The first visit prompts you to accept the self-signed certificate.

The image serves two surfaces on the same port. Bare `/` redirects to `/app`.

| Path        | What                                                |
|-------------|-----------------------------------------------------|
| `/app`      | The React console: alerts, investigations, config   |
| `/api/v1/*` | The JSON API that the console and integrations use  |

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
| `soc_ai_evals` (vol)     | `/var/lib/soc-ai/evals`             | rw   | Nightly quality-eval bundles + critiques   |

`soc_ai_evals` holds the per-alert bundles and the oracle critiques behind every point on
the Quality card of the dashboard. They are the only evidence for or against a regression
alarm, and nothing regenerates them. Without the volume they live in the container
filesystem, and every recreate deletes them.

`docker compose up` creates the 5 named volumes automatically. They survive
`docker compose down`. Only `docker compose down -v` deletes the data.

---

## Seeding enrichment data

The `python -m soc_ai blocklists refresh` CLI command populates the blocklists, the GeoIP
data and the cloud prefixes. Run it once after the first boot. Then run it on a weekly
schedule:

```bash
# Initial seed (runs inside the container, writes to the mounted volumes)
docker compose run --rm soc-ai python -m soc_ai blocklists refresh

# Or as a cron job on the host (via docker exec):
docker exec soc-ai python -m soc_ai blocklists refresh
```

MaxMind GeoLite2 needs a free license key. Set `MAXMIND_LICENSE_KEY` in `.env`. Without
the key the refresh skips GeoIP, and everything else still works.

---

## Updating

**Back up first.** Migrations run automatically at startup, and soc-ai does not
support a schema downgrade. An old image cannot roll back a bad upgrade against a
migrated database. You restore from a snapshot instead. Take a snapshot before
every upgrade. See [Backup and restore](#backup-and-restore) for the full command:

```bash
docker exec soc-ai python -m soc_ai backup --out /var/lib/soc-ai/data/backup.tar.gz
docker cp soc-ai:/var/lib/soc-ai/data/backup.tar.gz \
  ./soc-ai-preupgrade-$(date -u +%Y%m%dT%H%M%SZ).tar.gz
docker exec soc-ai rm /var/lib/soc-ai/data/backup.tar.gz
```

Then update with one command:

```bash
git pull && docker compose up -d --build
```

That command rebuilds the image and recreates the container. Nothing else is
needed:

- **The database migrates itself.** A schema migration runs automatically at
  container start. It runs inside a transaction, so a failure rolls back cleanly.
  You never run `alembic` by hand.
- **Your data stays put.** The SQLite DB, the sessions and the enrichment caches
  live in named Docker volumes. A volume survives a container replacement. Only
  `docker compose down -v` deletes one.
- **Your `.env` keeps working.** soc-ai ignores an unknown key, so a setting that
  a new version removed or renamed does not stop the container from booting.
- **A new release can add a volume.** `docker compose up -d` reads the mounts
  from `docker-compose.yml` in the repo, so a `git pull` picks a new one up on
  its own. If you maintain your own compose file, diff it against the repo file
  after every upgrade. A mount that you did not copy across raises no error. It
  writes into the container filesystem and loses the data on the next recreate.

!!! warning "Upgrading from 1.2.7 or earlier: one new volume"

    This release adds a fifth named volume, `soc_ai_evals`, mounted at
    `/var/lib/soc-ai/evals`. It holds the nightly quality-eval bundles. Those
    bundles are the per-alert artifacts and the oracle critiques behind every
    point on the Verdict quality card of the dashboard. They are the only
    evidence for or against a regression alarm. Before this release soc-ai wrote
    them inside the container, so every `docker compose up -d` deleted them.

    With the repo compose file, the upgrade command above is all you need. It has
    two consequences:

    - **The bundles written before the upgrade are gone.** They lived on the
      container filesystem that the upgrade recreate replaces. The trend rows
      survive, because they live in the DB. Only the artifacts that they point at
      are lost. Nothing regenerates them, so you can no longer adjudicate an
      alarm from before the upgrade against its critiques.
    - **A hand-maintained compose file needs the mount added.** Add
      `soc_ai_evals:/var/lib/soc-ai/evals` under the service, and
      `soc_ai_evals:` in the top-level `volumes:` block. Mount it at that exact
      path. The image creates `/var/lib/soc-ai/evals` as uid 1000, and a volume
      mounted at a path the image never created comes up root-owned. The nightly
      run detects that, keeps running against `./evals`, and logs
      `cannot use … for eval bundles (not writable by this user)`.

Verify the new build:

```bash
docker compose ps                          # soc-ai should be "healthy" — i.e. ALIVE
curl -k https://localhost:8443/healthz      # → {"status":"alive","version":"…"}
docker compose exec soc-ai python -m soc_ai doctor   # the actual verdict
```

The first two commands say the process came back. Only the doctor says the
install still works. The doctor is the check that touches Elasticsearch, the
Security Onion API, the model gateway and the audit-write grant.

### Backup and restore

`soc-ai backup` snapshots the store through the SQLite backup API, so it is safe
while the app is running. Do not `docker cp` the bare `.db` file out of a live
container. The store runs WAL journaling, and a raw copy of a hot database
can tear pages. The archive carries the DB snapshot, the app-owned sidecar files
next to it, and a manifest that records the schema migration head. The sidecar
files are the decision-record signing key and the pinned sensor `known_hosts`.

```bash
# Back up — the app can stay running.
docker exec soc-ai python -m soc_ai backup --out /var/lib/soc-ai/data/backup.tar.gz
docker cp soc-ai:/var/lib/soc-ai/data/backup.tar.gz \
  ./soc-ai-backup-$(date -u +%Y%m%dT%H%M%SZ).tar.gz
docker exec soc-ai rm /var/lib/soc-ai/data/backup.tar.gz
```

The backup excludes the enrichment caches by default. Those caches are the
blocklists, MaxMind and the cloud prefixes. `soc-ai blocklists refresh` downloads
them again, and they dwarf the DB. Add `--full` to include them. That is worth
doing on an air-gapped host.

#### Scheduling backups (with retention)

The Docker stack ships no in-app scheduler for backups, the same as for the
blocklist refresh. Add a host cron job or a systemd timer. The script below
snapshots the store into a dated file on the host. It then deletes anything older
than 14 days:

```bash
#!/usr/bin/env bash
# /usr/local/bin/soc-ai-backup.sh — nightly backup with N-day retention.
set -euo pipefail
DEST=/var/backups/soc-ai            # host dir; must exist and be writable by cron
RETAIN_DAYS=14
COMPOSE=/opt/soc-ai/docker-compose.yml
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$DEST"
docker compose -f "$COMPOSE" exec -T soc-ai \
  python -m soc_ai backup --out /var/lib/soc-ai/data/backup.tar.gz
docker compose -f "$COMPOSE" cp soc-ai:/var/lib/soc-ai/data/backup.tar.gz \
  "$DEST/soc-ai-backup-$STAMP.tar.gz"
docker compose -f "$COMPOSE" exec -T soc-ai rm /var/lib/soc-ai/data/backup.tar.gz
# Retention: delete backups older than RETAIN_DAYS.
find "$DEST" -name 'soc-ai-backup-*.tar.gz' -type f -mtime "+$RETAIN_DAYS" -delete
```

```cron
# /etc/cron.d/soc-ai-backup — nightly backup, 02:47
47 2 * * *  root  /usr/local/bin/soc-ai-backup.sh >/var/log/soc-ai-backup.log 2>&1
```

Store the backups off the box, because they hold the decision-record signing key,
the pinned sensor `known_hosts` and the full store (password hashes, encrypted
secrets). The archive is written mode `0600` regardless of the umask; keep it that
way wherever you copy it. The one-shot `bootstrap-admin-password.txt` is never
packed. Test a restore at regular intervals. An untested backup is not a recovery
plan.

Restore refuses every dangerous step without `--yes`. It does not overwrite an
existing store, and it prints exactly what it would replace. It does not restore
under an app that looks live. An app looks live if its write-ahead log has recent
activity. Restore also refuses an archive made by a newer soc-ai, with `--yes` or
without it, because soc-ai does not support a schema downgrade. An older archive
is always fine, because the app migrates it to head at the next startup.

```bash
# Restore — stop the app first, run the restore in a one-off container.
docker cp ./soc-ai-backup-<stamp>.tar.gz soc-ai:/var/lib/soc-ai/data/restore.tar.gz
docker compose stop soc-ai
docker compose run --rm soc-ai \
  python -m soc_ai restore /var/lib/soc-ai/data/restore.tar.gz --yes
docker compose up -d soc-ai
docker exec soc-ai rm /var/lib/soc-ai/data/restore.tar.gz
```

### Rolling back

Check out the previous tag and rebuild. The volumes stay untouched, and the
schema only ever moves forward. Older code therefore reads a newer DB correctly
for the additive changes that a patch release makes:

```bash
git checkout v1.2.0 && docker compose up -d --build
```

### What "no breaking updates" means here

Inside one major version, an update needs no manual migration and no change to
your `.env`. A new setting ships with a safe default. A renamed setting keeps its
old name as an alias, so `HEAVY_MODEL` still works after the rename to
`ANALYST_MODEL`. A migration is additive. Any change that genuinely cannot keep
that promise waits for the next major version, and
[CHANGELOG.md](https://github.com/nuk3s/soc-ai/blob/main/CHANGELOG.md) calls it
out.

---

## Relationship to rsync + systemd

The Docker path and the rsync + systemd path have the same production capability.
`DEPLOYMENT.md` describes the second one. Choose on your preference:

| Concern          | systemd (DEPLOYMENT.md)          | Docker (this guide)                       |
|------------------|----------------------------------|-------------------------------------------|
| Isolation        | OS user + systemd hardening      | Container namespace                       |
| Updates          | rsync + `uv sync` + restart      | `docker compose build` + `up -d`          |
| Data persistence | Host filesystem                  | Named Docker volumes                      |
| TLS              | Host cert paths in `.env`        | `./certs/` bind-mount                     |
| Enrichment data  | `/var/lib/soc-ai/...` on host    | Named volumes (same CLI command to seed)  |
| Port binding     | Direct (uvicorn on :8443)        | Direct (port-mapped to :8443)             |

The Docker path is easier to reason about for an upgrade, because the image is
immutable and the state lives in volumes. It also avoids the SELinux caveats on a
Fedora host. soc-ai supports both paths.

---

## Traps to know before your first hunt

These problems hit people on a real install. `/healthz` shows none of them,
because it only checks that the server is up and never touches an upstream. Each
one appears as a *failed first hunt* and not as a failed boot.

### Upstream TLS trust (self-signed SO / ES / LiteLLM / MISP)

The container image ships the public CA bundle only. A lab Security Onion,
Elasticsearch, LiteLLM or MISP often uses a self-signed certificate or an
internal-CA certificate. The first hunt then fails with
`CERTIFICATE_VERIFY_FAILED` in `docker compose logs soc-ai`, and `/healthz` stays
green. Fix it in `.env`:

```ini
SO_VERIFY_SSL=false        # Security Onion web API (Kratos)
ES_VERIFY_SSL=false        # Elasticsearch
LITELLM_VERIFY_SSL=false   # LiteLLM gateway
```

For SO and MISP, point at the CA file instead. That is better than a disabled
check. Bind-mount the CA into the container and reference it:

```ini
SO_CA_BUNDLE=/etc/soc-ai/so-ca.pem
MISP_CA_BUNDLE=/etc/soc-ai/misp-ca.pem
```

**Elasticsearch has no CA-bundle option.** For ES you use `ES_VERIFY_SSL=false`,
or a certificate that the container's public bundle already trusts. Add the `,Z`
SELinux relabel suffix to a CA bind-mount, the same as the cert mounts do.

### Port 8443 collides with Security Onion's own nginx

A stock Security Onion manager already runs nginx on 8443. An earlier soc-ai can
also sit there. If you deploy soc-ai on the SO box or near it, remap the host side
of the port mapping with `SOC_AI_PORT` in `.env`:

```ini
SOC_AI_PORT=9443    # host side; the container still listens on 8443 internally
```

Then open the new port on a host with a firewall or SELinux:

```bash
sudo firewall-cmd --add-port=9443/tcp --permanent && sudo firewall-cmd --reload
```

### Docker publishes the port *past* firewalld

Docker inserts its own iptables and nftables rules ahead of firewalld. The default
`"${SOC_AI_PORT}:8443"` mapping binds `0.0.0.0`. A published port is therefore
reachable from any host that can route to this box, even if firewalld shows the
port closed. `firewall-cmd --list-ports` does not list it, and adding or
removing a firewalld rule does not change its reachability. To restrict who can
reach the admin console, work at the Docker layer:

- **Bind a specific host IP** in `.env`, so Docker does not publish the port on
  every interface. Two examples are localhost only behind a reverse proxy, and
  your mgmt LAN only:

  ```ini
  SOC_AI_PORT=127.0.0.1:8443    # host side; container still listens on :8443
  ```

  Any `IP:PORT` form that Docker's port mapping accepts works here.
- Or add a rule to the `DOCKER-USER` iptables chain to filter source
  addresses. Docker evaluates that chain before its own publish rules.

An audit of the host firewall alone wrongly reports that the console is closed.

### Hostname upstreams don't resolve inside the bridge network

A URL such as `https://litellm.example.com:4000` can resolve *on the host*,
through the host's `/etc/hosts` file or a local resolver. It does not resolve
inside the container's bridge network, because the host's `/etc/hosts` does not
propagate into the container. The first hunt then fails with a DNS error or a
connection error. There are 3 ways out:

- Use an IP address in `.env`. This is the simplest way:
  `LITELLM_BASE_URL=https://10.0.0.5:4000`.
- Add an `extra_hosts:` entry to the `soc-ai` service in `docker-compose.yml`:
  ```yaml
      extra_hosts:
        - "litellm.example.com:10.0.0.5"
  ```
- Point the names at real DNS that the container can reach.

### PCAP is off by default (key mount is commented out)

The `./certs/so_pcap` SSH-key bind mount in `docker-compose.yml` is commented out
by default, so live PCAP retrieval is off. To turn it on:

1. Uncomment the mount line in `docker-compose.yml`. Keep the trailing `,Z` SELinux suffix:
   ```yaml
       - ./certs/so_pcap:/etc/soc-ai/so_pcap:ro,Z
   ```
2. Put a de-privileged sensor SSH key at `./certs/so_pcap`. Make it readable
   by the in-container uid 1000 with `chmod 644 ./certs/so_pcap`.
3. Set in `.env`:
   ```ini
   PCAP_ENABLED=true
   SO_SSH_HOST=<sensor-host-or-ip>
   SO_SSH_KEY=/etc/soc-ai/so_pcap
   ```

soc-ai fails fast at startup if `PCAP_ENABLED=true` and `SO_SSH_HOST` is empty.
See [SECURITY-ONION-SETUP.md](SECURITY-ONION-SETUP.md) for the reason this needs
an SSH key and not an ES or SO role.

### Blocklist refresh has no scheduler in the Docker path

The systemd path can run a timer. The Docker stack ships no scheduler for the
enrichment refresh. Without one, the blocklists, the GeoIP data and the cloud
prefixes go stale. Add a host cron job, or any scheduler, that execs the refresh
at an interval:

```cron
# /etc/cron.d/soc-ai-blocklists — weekly refresh, Sundays 03:17
17 3 * * 0  root  docker compose -f /opt/soc-ai/docker-compose.yml exec -T soc-ai python -m soc_ai blocklists refresh
```

### The profile sweep needs no timer

soc-ai runs the profile sweep inside the app. The sweep compares each host with
its own baseline, records what departs as an observation, and forms a lead from
what accumulates. It runs every 60 minutes by default, and the floor is 15
minutes. Set the interval in Config → Hunting → *Minutes between profile
sweeps*. Turn the sweep off with *Run the profile sweep* in the same section.
Both settings apply live, with no restart.

The sweep skips a demo deployment, and it skips a sweep while Elasticsearch is
down. It makes no model call.

Do not add a host cron job for it. Two schedulers run the same sweep twice and
double the query load on Security Onion. `soc-ai priors --record` stays
available for a run by hand.

### The nightly quality micro-eval: schedule it in-app or from host cron

`soc-ai eval-nightly` investigates a handful of real alerts. It lands one row in
the local quality trend, on the dashboard's Verdict quality card. It alarms
through the notification webhook if the new point regresses against its own
history. It turns "the verdicts were validated once" into "the verdicts are
measured every night". That is the tripwire for a silent degradation after a swap
of the inference engine or the analyst model.

The simplest schedule is in-app. Open Config → Quality → *Nightly quality eval*.
It runs daily at the configured UTC hour. The dashboard card also has a Run now
button, and it shares the same single-flight run. The in-app
scheduler skips its slot if a snapshot already landed today, for example because
a host cron beat it to it. A host cron does not skip its slot, so pick ONE
scheduler: the toggle, or this host cron:

```cron
# /etc/cron.d/soc-ai-quality — nightly micro-eval, 02:17
17 2 * * *  root  docker compose -f /opt/soc-ai/docker-compose.yml exec -T soc-ai python -m soc_ai eval-nightly
```

The mode is automatic and honest about egress. With `oracle_enabled` on, each run
is oracle-graded. That mode makes one cloud call per alert, and the agreement
rate joins the trend. Otherwise the run uses zero-egress local mode, with no
oracle at all. The trend then carries the fallback and error rates, the verdict
distribution and the latency, and the dashboard card labels which mode measured
each point.

Force either mode with `--graded` or `--local`. Tune the sample size
`quality_nightly_n` and the alarm threshold `quality_alarm_drop` live in the
config console's Quality section.

Each run also writes a `batch-<timestamp>/` bundle to `/var/lib/soc-ai/evals`, on
the `soc_ai_evals` volume. The bundle holds the per-alert artifacts, the oracle
critiques and a `report.md`. Read one if a point alarms. The critiques say *why*
the oracle disagreed, and the dashboard card prints the path of the run that
fired:

```bash
docker exec soc-ai ls /var/lib/soc-ai/evals
docker exec soc-ai cat /var/lib/soc-ai/evals/batch-<timestamp>/report.md
```

`--out-dir` overrides the location. Without it the bundles follow the data dir.
That is what keeps them on a volume and out of the container.

### 1 GB memory cap can OOM-kill a runaway hunt

`docker-compose.yml` sets a `1G` memory limit. Under cgroup v2 that is a hard
cap, not a hint. A pathological hunt that accumulates a lot of tool output can
reach the cap, and the kernel then OOM-kills the container. The container
restarts through `restart: unless-stopped`. If the container restarts in the
middle of a hunt, raise `deploy.resources.limits.memory` in
`docker-compose.yml`.

---

## Troubleshooting

**Run the doctor first.** `docker exec soc-ai python -m soc_ai doctor` checks the whole
dependency surface: the config, the store and its migration head, Security Onion,
Elasticsearch, the audit grant, the gateway and the model fitness. It prints a pass and
fail table with a fix hint on every failing line. Start there, before the per-symptom
entries below.

**Container exits immediately after start**
Check that `.env` exists. Check that `SOC_AI_TLS_CERT` and `SOC_AI_TLS_KEY` point at files
that you mounted. `docker compose logs soc-ai` shows the pydantic-settings
validation error if a required field is missing.

**Health check failing**
The default `start_period` is 60s, so the DB migration can run on the first boot. If the
check fails every time, read `docker compose logs soc-ai` for the uvicorn startup
traceback.

**First page load fails with `TypeError: Failed to fetch`**
The browser does not trust the self-signed cert yet. Visit
`https://<host>:8443/healthz` once in the same browser. Accept the cert warning, then try
again. See DEPLOYMENT.md §10.

**Enrichment returns no GeoIP / ASN data**
Either `.env` has no `MAXMIND_LICENSE_KEY`, or nobody ran the blocklist refresh. Run
`docker compose run --rm soc-ai python -m soc_ai blocklists refresh`.
