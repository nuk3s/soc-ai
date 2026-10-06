# Docker deployment

This guide covers how to run soc-ai as a Docker container. It is an alternative to the
rsync + systemd path in [DEPLOYMENT.md](DEPLOYMENT.md), and it can replace that path later.

---

## Quick start

> **The fast path is `./setup.sh`** in the repo root. That guided installer does
> everything below. It installs Docker if the host needs it, writes `.env`,
> generates the certificate and the secrets, starts the stack, and seeds the
> enrichment data. The steps here are the manual equivalent, for reference.

### 1. The `.env` file

Copy `.env.example` to `.env` in the repo root. Fill in every required value.
`soc_ai/config.py` holds the full field reference. The minimum set is:

> The Security Onion account requirements live in
> [SECURITY-ONION-SETUP.md](SECURITY-ONION-SETUP.md). That page says which login and
> role each feature needs. It also covers the audit-log grant. Ack and escalate fail
> without it, and they show no error. Read it before your first write-back.

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

# Server: must match the paths you mount below
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

The Danger Zone on the Config screen needs `CONFIG_SECRET_KEY`. The key encrypts a
secret override before soc-ai stores it in the database. Generate a key once and keep it
in `.env`:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Without the key, the Config screen still works for a non-secret setting. You cannot edit a
password, an API key or another secret field in the console.

---

### 2. TLS paths

soc-ai has two TLS paths.

The proxy path is the production path. Caddy terminates TLS in front of soc-ai and renews
the certificate on its own. soc-ai serves plain HTTP inside the compose network. Use this
path for a public name or for Caddy's own CA in a lab. It also suits an ACME CA of your own
or a certificate from your own CA. One command, `scripts/tls-proxy.sh enable <domain>`, sets
it up.

The direct path is the default after `setup.sh`. uvicorn terminates TLS with a certificate
file and a key file. Use it for a lab, or if a proxy is not an option. soc-ai validates
the files at start. The TLS panel on the Config screen and `soc-ai doctor` report them.
soc-ai warns 30, 14 and 7 days before expiry.

#### The proxy path: Caddy in front of soc-ai

One command sets it up. It takes the domain and an optional certificate source:

```bash
scripts/tls-proxy.sh enable soc-ai.example.com                    # Let's Encrypt, the default
scripts/tls-proxy.sh enable soc-ai.example.com internal           # Caddy's own CA
scripts/tls-proxy.sh enable soc-ai.example.com cert.pem key.pem   # your own certificate and key
scripts/tls-proxy.sh enable soc-ai.example.com acme \
  https://ca.example.com/acme/local/directory ca-root.pem          # your own ACME CA
```

- `auto`, the default: automatic HTTPS from Let's Encrypt. The name must resolve to this
  host on the public internet. Ports 80 and 443 must be reachable from the internet.
- `internal`: a certificate from Caddy's own CA. The script exports the root as
  `./caddy-root.crt` and prints the trust steps.
- `<cert.pem> <key.pem>`: a certificate from your own CA. The certificate file holds the
  full chain: the leaf first, then each issuer. The script copies the two files into
  `./certs/` as `proxy-cert.pem` and `proxy-key.pem`. To install a renewed pair, run the same
  command with the new files. The script copies them and reloads Caddy.
- `acme <directory-url> <root.pem>`: a certificate from an ACME CA on your network, for
  example step-ca or a Caddy `acme_server`. Caddy obtains the certificate and renews it with
  no key copy. The URL is the https ACME directory of the CA. The root file is the CA root
  certificate. Caddy trusts it for the connection to the CA. The script copies it into
  `./certs/acme-ca-root.pem` and writes
  `SOC_AI_CADDY_TLS=import acme_ca <directory-url> /certs/acme-ca-root.pem`. The `acme_ca`
  snippet in the `Caddyfile` turns that line into the `ca` and `ca_root` settings. The CA
  must reach this host on port 80 or 443 under the domain name to validate the order. After
  the start the script checks that the served chain ends at the root file. Clients need the
  same root in their trust store. Use this source if a fleet already trusts a private CA.

The script backs up `.env` to `.env.bak-<stamp>` and then changes these settings:

- `SOC_AI_TLS_CERT` and `SOC_AI_TLS_KEY` become blank. soc-ai serves plain HTTP inside the
  compose network.
- `SOC_AI_BIND=127.0.0.1`. Port 8443 stays on the host loopback.
- `SOC_AI_DOMAIN=<domain>` and `SOC_AI_CADDY_TLS=<the tls directive>`. The Caddy container
  receives these two variables and no soc-ai secret.
- `COMPOSE_PROFILES=proxy`. The `caddy` service in `docker-compose.yml` sits under the
  `proxy` profile. This line keeps Caddy in every later `docker compose up -d`.
- `PROXY_TRUSTED_IPS=<the subnet of the compose network>`. The script reads the subnet with
  `docker network inspect`. soc-ai trusts the forwarded headers from that subnet. It skips
  every trusted hop when it reads the client address, so the block must not cover the
  addresses your analysts connect from.

Then it runs `docker compose up -d`, waits up to 120 s for the certificate, and prints the
URL and a health check. The health check does not verify the certificate. For `acme`, a
second check verifies the chain against the root file. `--dry-run` before the verb prints
the changes and the commands and changes nothing.

The self-signed pair in `./certs/` stays. The main stack still mounts the two files, and the
direct path needs them again after `disable`.

For `internal`, trust the root on each client. The script prints these steps:

```bash
# Fedora, RHEL
sudo cp caddy-root.crt /etc/pki/ca-trust/source/anchors/soc-ai-caddy.crt && sudo update-ca-trust
# Debian, Ubuntu
sudo install -m644 caddy-root.crt /usr/local/share/ca-certificates/soc-ai-caddy.crt && sudo update-ca-certificates
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain caddy-root.crt
# Windows
certutil -addstore -f Root caddy-root.crt
```

Browsers on those hosts trust it after a restart. Firefox needs its own import under Settings,
Certificates.

`scripts/tls-proxy.sh status` prints the mode, the domain, the source and one health check.
`scripts/tls-proxy.sh disable` restores the direct path. It puts the certificate paths back,
removes the five proxy settings, stops and removes Caddy, and starts soc-ai with TLS on 8443.
Caddy's data volume stays, with its CA.

`setup.sh` asks the same question. `HTTPS_DOMAIN` in `setup.conf`, with `HTTPS_CA=auto` or
`HTTPS_CA=internal`, makes the installer run the command for you.

Caddy reloads a changed certificate without downtime. To reload a changed `Caddyfile`:

```bash
docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile
```

`soc-ai doctor` reports `TLS terminates at the proxy` on this path. With podman-compose, pass
`--profile proxy` on each compose command. It does not read `COMPOSE_PROFILES` from `.env`.

#### The direct path: TLS termination in soc-ai

Create a `certs/` directory in the repo root. Generate a self-signed certificate there, or
copy in your CA-signed pair:

```bash
mkdir -p ./certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -subj "/CN=soc-ai" \
  -addext "subjectAltName=DNS:soc-ai.local,IP:<your-host-ip>" \
  -keyout ./certs/key.pem \
  -out    ./certs/cert.pem
# The container runs as uid 1000. It reads these files through a bind mount
# that carries no ACLs. Keep the cert world-readable, mode 0644. Give the
# private key to gid 1000 and make it group-readable, mode 0640. The container
# can then read the key, and the host does not expose it to every user. If you
# cannot chgrp on this host, use 0644. The container boots with that mode too.
chmod 644 ./certs/cert.pem
chgrp 1000 ./certs/key.pem && chmod 640 ./certs/key.pem
```

The compose file bind-mounts `./certs/cert.pem` to `/etc/soc-ai/cert.pem` and
`./certs/key.pem` to `/etc/soc-ai/key.pem`. Both mounts are read-only. The
`SOC_AI_TLS_CERT` and `SOC_AI_TLS_KEY` variables in the container point at these paths by
default. Override them in `.env` if you mount the files elsewhere.

> **SELinux hosts: Fedora, RHEL, Rocky and podman.** The certificate and key bind
> mounts already ship with the `,Z` relabel suffix, as `:ro,Z`. They work at once.
> Without that suffix the container gets `Permission denied`, even at mode 644. Append
> `,Z` to your own bind mounts on an SELinux host too. On a host without SELinux the
> suffix does nothing.

#### TLS certificate replacement

You can replace the self-signed pair with a certificate from your internal CA or from
Let's Encrypt. Copy the new files to the same mounted paths. Then restart the container.
soc-ai reads the certificate and the key once at start. A new file has no effect until
you restart:

```bash
cp your-ca-cert.pem  ./certs/cert.pem   # the full chain (leaf + intermediates)
cp your-ca-key.pem   ./certs/key.pem
chmod 644 ./certs/cert.pem
chgrp 1000 ./certs/key.pem && chmod 640 ./certs/key.pem   # readable by the container uid
docker compose restart soc-ai
```

Keep the filenames `cert.pem` and `key.pem`, because the compose mounts and the
`SOC_AI_TLS_CERT` and `SOC_AI_TLS_KEY` variables point at them. You can also update both
to match new names. On an SELinux host the `,Z` relabel applies automatically at the next
start.

After the swap, open Config and check the TLS panel, or run `soc-ai doctor`. Both inspect
the files on disk. They do not read the files that soc-ai loaded at start. The panel says
"Restart soc-ai to load them" until you restart.
`GET /api/v1/config/tls` returns the same record.

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
# → {"status":"alive","checks":"None. This is a liveness probe only. It probes no dependency. …",
#    "version":"1.5.0","so_auth":"kratos",...}
```

This check probes nothing. It stays green with an unreachable grid, a dead model
gateway and no analyst model configured. The container healthcheck polls it. A
`healthy` state in `docker ps` means only that the process is up. It says nothing
about the install. For that, run the doctor:

```bash
docker compose exec soc-ai python -m soc_ai doctor
```

---

### 4. Open the web UI

Open `https://<host>:8443/app` and log in as the bootstrap admin. The
username is `admin`. Use `BOOTSTRAP_ADMIN_PASSWORD` from `.env` if you set it.
Otherwise soc-ai generates the password at the first start and writes it once to
a sidecar file in the data volume, mode `0600`. Read it with:

```bash
docker exec soc-ai cat /var/lib/soc-ai/data/bootstrap-admin-password.txt
```

The container log names that file and holds no password. If the data directory
is not writable at startup, the password goes to the log.
`docker compose logs soc-ai` shows it then. Change the password after the first
login. Then delete the file if it is still there.

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

`soc_ai_evals` holds the per-alert bundles and the Oracle critiques behind every point on
the Quality card of the dashboard. They are the only evidence for or against a regression
alarm, and nothing regenerates them. Without the volume they live in the container
filesystem, and every recreate deletes them.

`docker compose up` creates the 5 named volumes automatically. They survive
`docker compose down`. Only `docker compose down -v` deletes the data.

---

## Enrichment data

The `python -m soc_ai blocklists refresh` CLI command populates the blocklists and the
cloud prefixes. Run it once after the first boot. Then run it on a weekly schedule:

```bash
# Initial seed (runs inside the container, writes to the mounted volumes)
docker compose run --rm soc-ai python -m soc_ai blocklists refresh

# Or as a cron job on the host (via docker exec):
docker exec soc-ai python -m soc_ai blocklists refresh
```

### GeoIP and ASN data

No command in soc-ai downloads the MaxMind GeoLite2 databases. They need a MaxMind
account, and they arrive as a tarball. Fetch them with your free license key. Then
copy the two files into the `soc_ai_maxmind` volume:

```bash
docker cp GeoLite2-City.mmdb soc-ai:/var/lib/soc-ai/maxmind/
docker cp GeoLite2-ASN.mmdb soc-ai:/var/lib/soc-ai/maxmind/
docker compose restart soc-ai
```

soc-ai opens the files at startup. The restart is necessary for that reason. Uid 1000
must be able to read the files, the same as every other mount. Without them, GeoIP and
ASN enrichment report nothing. Everything else still works. `MAXMIND_LICENSE_KEY` in
`.env` triggers no download. The Data sources page only shows whether a key is on file.
[BLOCKLISTS.md](BLOCKLISTS.md#maxmind-geoip) has the full procedure.

---

## Update

**Back up first.** Migrations run automatically at startup, and soc-ai does not
support a schema downgrade. An old image cannot roll back a bad upgrade against a
migrated database. To undo a bad upgrade, restore from a snapshot. Take a snapshot before
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
- **Your data stays in place.** The SQLite DB, the sessions and the enrichment caches
  live in named Docker volumes. A volume survives a container replacement. Only
  `docker compose down -v` deletes one.
- **Your `.env` keeps working.** soc-ai ignores an unknown key, so a setting that
  a new version removed or renamed does not stop the container from booting.
- **A new release can add a volume.** `docker compose up -d` reads the mounts
  from `docker-compose.yml` in the repo, so a `git pull` picks a new one up on
  its own. If you maintain your own compose file, diff it against the repo file
  after every upgrade. A mount that you did not copy across raises no error. It
  writes into the container filesystem and loses the data on the next recreate.

!!! warning "One new volume for an upgrade from 1.2.7 or earlier"

    This release adds a fifth named volume, `soc_ai_evals`, mounted at
    `/var/lib/soc-ai/evals`. It holds the nightly quality-eval bundles. Those
    bundles are the per-alert artifacts and the Oracle critiques behind every
    point on the Verdict quality card of the dashboard. They are the only
    evidence for or against a regression alarm. Before this release soc-ai wrote
    them inside the container, so every `docker compose up -d` deleted them.

    With the repo compose file, the upgrade command above is all you need. It has
    two consequences:

    - **The bundles written before the upgrade are gone.** They lived on the
      container filesystem that the upgrade recreate replaces. The trend rows
      survive, because they live in the DB. Only the artifacts that they point at
      are lost. Nothing regenerates them, so you can no longer check an alarm
      from before the upgrade against its critiques.
    - **A hand-maintained compose file needs the mount added.** Add
      `soc_ai_evals:/var/lib/soc-ai/evals` under the service, and
      `soc_ai_evals:` in the top-level `volumes:` block. Mount it at that exact
      path. The image creates `/var/lib/soc-ai/evals` as uid 1000. A volume at a
      path that the image never created comes up root-owned. The nightly
      run detects that, keeps running against `./evals`, and logs
      `cannot use … for eval bundles (not writable by this user)`.

Verify the new build:

```bash
docker compose ps                          # soc-ai should be "healthy", which means ALIVE
curl -k https://localhost:8443/healthz      # → {"status":"alive","version":"…"}
docker compose exec soc-ai python -m soc_ai doctor   # the actual verdict
```

The first two commands say the process came back. Only the doctor says the
install still works. The doctor is the check that touches Elasticsearch, the
Security Onion API, the model gateway and the audit-write grant.

### Backup and restore

With the store in PostgreSQL, `soc-ai backup` refuses. See [PostgreSQL](#postgresql).

`soc-ai backup` snapshots the store through the SQLite backup API, so it is safe
while the app is running. Do not `docker cp` the bare `.db` file out of a live
container. The store runs WAL journaling, and a raw copy of a hot database
can tear pages. The archive carries the DB snapshot, the app-owned sidecar files
next to it, and a manifest that records the schema migration head. The sidecar
files are the decision-record signing key and the pinned sensor `known_hosts`.

```bash
# Back up. The app can stay running.
docker exec soc-ai python -m soc_ai backup --out /var/lib/soc-ai/data/backup.tar.gz
docker cp soc-ai:/var/lib/soc-ai/data/backup.tar.gz \
  ./soc-ai-backup-$(date -u +%Y%m%dT%H%M%SZ).tar.gz
docker exec soc-ai rm /var/lib/soc-ai/data/backup.tar.gz
```

The backup excludes the enrichment caches by default. Those caches are the
blocklists, the MaxMind databases and the cloud prefixes. They are much larger than
the DB. Add `--full` to include them. Do that on an air-gapped host, where nothing
can fetch them again.

`soc-ai blocklists refresh` downloads the blocklists and the cloud prefixes again.
The `.mmdb` files come back by hand, the same way they arrived. See
[Enrichment data](#enrichment-data).

#### Backup schedule and retention

The Docker stack ships no in-app scheduler for backups, the same as for the
blocklist refresh. Add a host cron job or a systemd timer. The script below
snapshots the store into a dated file on the host. It then deletes anything older
than 14 days:

```bash
#!/usr/bin/env bash
# /usr/local/bin/soc-ai-backup.sh: nightly backup with N-day retention.
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
# /etc/cron.d/soc-ai-backup: nightly backup, 02:47
47 2 * * *  root  /usr/local/bin/soc-ai-backup.sh >/var/log/soc-ai-backup.log 2>&1
```

Store the backups off the box. They hold the decision-record signing key, the pinned
sensor `known_hosts` and the full store. The store holds the password hashes and the
encrypted secrets. soc-ai writes the archive with mode `0600`, whatever the umask.
Keep that mode wherever you copy it. The archive never packs the one-shot
`bootstrap-admin-password.txt`. Test a restore at regular intervals.

Restore refuses every dangerous step without `--yes`. It does not overwrite an
existing store, and it prints exactly what it would replace. It does not restore
under an app that looks live. An app looks live if its write-ahead log has recent
activity. Restore also refuses an archive from a newer soc-ai, even with `--yes`.
soc-ai does not support a schema downgrade. An older archive is always fine, because
the app migrates it to head at the next startup.

```bash
# Restore. Stop the app first, then run the restore in a one-off container.
docker cp ./soc-ai-backup-<stamp>.tar.gz soc-ai:/var/lib/soc-ai/data/restore.tar.gz
docker compose stop soc-ai
docker compose run --rm soc-ai \
  python -m soc_ai restore /var/lib/soc-ai/data/restore.tar.gz --yes
docker compose up -d soc-ai
docker exec soc-ai rm /var/lib/soc-ai/data/restore.tar.gz
```

### Rollback

Check out the previous tag and rebuild. The volumes stay untouched, and the
schema only ever moves forward. Older code therefore reads a newer DB correctly
for the additive changes that a patch release makes:

```bash
git checkout v1.2.0 && docker compose up -d --build
```

### The "no breaking updates" promise

Inside one major version, an update needs no manual migration and no change to
your `.env`. A new setting ships with a safe default. A renamed setting keeps its
old name as an alias, so `HEAVY_MODEL` still works after the rename to
`ANALYST_MODEL`. A migration is additive. A change that cannot keep that promise
waits for the next major version.
[CHANGELOG.md](https://github.com/nuk3s/soc-ai/blob/main/CHANGELOG.md) names it.

---

## PostgreSQL

soc-ai keeps its store in SQLite by default. SQLite has one writer. At corporate scale, the
scheduler, the sweeps and the console contend for that writer. The compose file carries an
optional `postgres` service for that case. [DEPLOYMENT.md, "PostgreSQL"](DEPLOYMENT.md#13-postgresql)
lists what changes and the limits.

The service sits under the `postgres` profile, so a plain `docker compose up -d` does not start
it. It publishes no port. soc-ai reaches it on the compose network as `postgres:5432`. Its data
lives in the `soc_ai_postgres` volume. At start, soc-ai waits up to 60 s for the server to accept
connections.

### A fresh install

`./setup.sh` asks "Keep the store in PostgreSQL?". On a fresh install, the answer yes writes
three lines to `.env`:

```bash
SOC_AI_POSTGRES_PASSWORD='<generated>'
SOC_AI_DATABASE_URL='postgresql+asyncpg://soc_ai:<generated>@postgres:5432/soc_ai'
COMPOSE_PROFILES=postgres
```

The server keeps the password it started with. Do not change `SOC_AI_POSTGRES_PASSWORD` after the
first start. `scripts/tls-proxy.sh` keeps `postgres` in `COMPOSE_PROFILES` when it adds or removes
`proxy`. setup.sh offers PostgreSQL on a fresh install only. On a host with a `.env`, the SQLite
store can hold data, so a move is a copy. The steps follow.

### Migration of an existing store

Stop soc-ai and back up the SQLite store first.

```bash
docker compose stop soc-ai
docker compose run --rm soc-ai \
  python -m soc_ai backup --out /var/lib/soc-ai/data/before-postgres.tar.gz
```

Add `postgres` to the `COMPOSE_PROFILES` line in `.env`. Write the line if it is absent. With
the proxy path on, the line reads `COMPOSE_PROFILES=proxy,postgres`. Do not set
`SOC_AI_DATABASE_URL` yet. The copy reads the SQLite store that the settings name. Then add a
password and start the server alone.

```bash
echo "SOC_AI_POSTGRES_PASSWORD=$(openssl rand -hex 24)" >> .env
docker compose up -d postgres
```

Run the copy with `--dry-run` in a one-off container, then without it. The password goes in
`PGPASSWORD`. The URL then holds no password.

```bash
PW=$(grep '^SOC_AI_POSTGRES_PASSWORD=' .env | tail -1 | cut -d= -f2)
docker compose run --rm -e PGPASSWORD="$PW" soc-ai \
  python -m soc_ai store migrate --dry-run --to postgresql+asyncpg://soc_ai@postgres:5432/soc_ai
docker compose run --rm -e PGPASSWORD="$PW" soc-ai \
  python -m soc_ai store migrate --to postgresql+asyncpg://soc_ai@postgres:5432/soc_ai
```

The dry run prints the rows per table and lists each stored value that PostgreSQL refuses. The
copy writes every table in one transaction and reports the counts that the target holds. Then
point soc-ai at the new store, start it and run the doctor.

```bash
echo "SOC_AI_DATABASE_URL=postgresql+asyncpg://soc_ai:${PW}@postgres:5432/soc_ai" >> .env
docker compose up -d soc-ai
docker compose exec soc-ai python -m soc_ai doctor
```

The SQLite file stays in the `soc_ai_data` volume. soc-ai does not read it while
`SOC_AI_DATABASE_URL` is set.

### PostgreSQL store backup

`soc-ai backup` refuses a PostgreSQL store and names `pg_dump`. Dump the database from the
service. Back up the `soc_ai_data` volume with the dump. It holds the signing key and
`known_hosts`.

```bash
docker compose exec -T postgres \
  pg_dump --username=soc_ai --format=custom soc_ai > "soc-ai-$(date -u +%Y%m%dT%H%M%SZ).dump"
```

## Comparison with rsync and systemd

The Docker path and the rsync + systemd path have the same production capability.
`DEPLOYMENT.md` describes the second one. Choose the path that you prefer:

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

## Install traps

These problems occur on real installs. `/healthz` shows none of them, because it
only checks that the server is up. It never touches an upstream. Each problem
appears as a failed first hunt. The boot succeeds.

### Upstream TLS trust

This trap applies to Security Onion, Elasticsearch, LiteLLM and MISP.

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

For SO, ES and MISP, point at the CA file. That is better than a disabled
check. Bind-mount the CA into the container and reference it:

```ini
SO_CA_BUNDLE=/etc/soc-ai/so-ca.pem
ES_CA_BUNDLE=/etc/soc-ai/es-ca.pem
MISP_CA_BUNDLE=/etc/soc-ai/misp-ca.pem
```

Add the `,Z` SELinux relabel suffix to a CA bind-mount, the same as the cert mounts.
The LiteLLM client takes no CA file. For it, use `LITELLM_VERIFY_SSL=false` or a
certificate that the container's public bundle already trusts.

### Port 8443 conflict with the Security Onion nginx

A stock Security Onion manager already runs nginx on 8443. An earlier soc-ai can
also sit there. If soc-ai runs on the SO box or near it, remap the host port with
`SOC_AI_PORT` in `.env`:

```ini
SOC_AI_PORT=9443    # host side; the container still listens on 8443 internally
```

Then open the new port on a host with a firewall or SELinux:

```bash
sudo firewall-cmd --add-port=9443/tcp --permanent && sudo firewall-cmd --reload
```

### Docker port publication and firewalld

Docker inserts its own iptables and nftables rules ahead of firewalld. The
`"${SOC_AI_BIND:-0.0.0.0}:${SOC_AI_PORT:-8443}:8443"` mapping binds `0.0.0.0` by
default. A published port is therefore reachable from any host that can route to
this box. That holds even if firewalld shows the port closed.
`firewall-cmd --list-ports` does not list it. A firewalld rule that you add or
remove does not change its reachability. To restrict who can reach the console,
work at the Docker layer:

- **Bind a specific host IP** with `SOC_AI_BIND` in `.env`. Docker then does not
  publish the port on every interface. For localhost only, behind a reverse proxy:

  ```ini
  SOC_AI_BIND=127.0.0.1    # host side. The container still listens on :8443
  ```

  For the address of your management LAN: `SOC_AI_BIND=203.0.113.5`. `SOC_AI_PORT`
  stays a plain port number. The container reads the same `.env`. An `IP:PORT`
  value there fails validation before the app listens.
- Or add a rule to the `DOCKER-USER` iptables chain to filter source
  addresses. Docker evaluates that chain before its own publish rules.

An audit of the host firewall alone wrongly reports that the console is closed.

### Hostname resolution in the bridge network

A URL such as `https://litellm.example.com:4000` can resolve *on the host*,
through the host's `/etc/hosts` file or a local resolver. It does not resolve
inside the container's bridge network, because the host's `/etc/hosts` does not
propagate into the container. The first hunt then fails with a DNS error or a
connection error. There are 3 fixes:

- Use an IP address in `.env`. This is the simplest way:
  `LITELLM_BASE_URL=https://203.0.113.5:4000`.
- Add an `extra_hosts:` entry to the `soc-ai` service in `docker-compose.yml`:
  ```yaml
      extra_hosts:
        - "litellm.example.com:203.0.113.5"
  ```
- Point the names at real DNS that the container can reach.

### PCAP key mount

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
[SECURITY-ONION-SETUP.md](SECURITY-ONION-SETUP.md) says why this path needs an SSH key.
It uses no ES role and no SO role.

### Blocklist refresh schedule

The systemd path can run a timer. The Docker stack ships no scheduler for the
enrichment refresh. Without one, the blocklists and the cloud prefixes go stale.
Add a host cron job or another scheduler that runs the refresh at an interval:

```cron
# /etc/cron.d/soc-ai-blocklists: weekly refresh, Sundays 03:17
17 3 * * 0  root  docker compose -f /opt/soc-ai/docker-compose.yml exec -T soc-ai python -m soc_ai blocklists refresh
```

### Profile sweep schedule

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

### Nightly quality micro-eval schedule

`soc-ai eval-nightly` investigates a handful of real alerts. It lands one row in
the local quality trend, on the dashboard's Verdict quality card. It alarms
through the notification webhook if the new point regresses against its own
history. The verdicts then get a measurement every night. A drop in quality after
a change of the inference engine or of the model shows on the next point.

The simplest schedule is in-app. Open Config → Quality → *Nightly quality eval*.
It runs daily at the configured UTC hour. The dashboard card also has a Run now
button, and it shares the same single-flight run. The in-app scheduler skips its
slot if a snapshot already landed today, for example from a host cron. A host cron
does not skip its slot, so pick ONE scheduler: the toggle, or this host cron:

```cron
# /etc/cron.d/soc-ai-quality: nightly micro-eval, 02:17
17 2 * * *  root  docker compose -f /opt/soc-ai/docker-compose.yml exec -T soc-ai python -m soc_ai eval-nightly
```

soc-ai picks the mode. With `oracle_enabled` on, the Oracle grades each run. That
mode makes one cloud call per alert, and the agreement rate joins the trend.
Otherwise the run uses zero-egress local mode, with no Oracle call at all. The trend
then carries the fallback and error rates, the verdict distribution and the latency.
The dashboard card labels which mode measured each point.

Force either mode with `--graded` or `--local`. Tune the sample size
`quality_nightly_n` and the alarm threshold `quality_alarm_drop` live, in the
Quality section of the Config screen.

Each run also writes a `batch-<timestamp>/` bundle to `/var/lib/soc-ai/evals`, on
the `soc_ai_evals` volume. The bundle holds the per-alert artifacts, the Oracle
critiques and a `report.md`. Read one if a point alarms. The critiques say *why*
the Oracle disagreed, and the dashboard card prints the path of the run that
fired:

```bash
docker exec soc-ai ls /var/lib/soc-ai/evals
docker exec soc-ai cat /var/lib/soc-ai/evals/batch-<timestamp>/report.md
```

`--out-dir` overrides the location. Without it the bundles follow the data dir.
That is what keeps them on a volume and out of the container.

### Memory cap of 1 GB

`docker-compose.yml` sets a `1G` memory limit. Under cgroup v2 that limit is a
hard cap. A pathological hunt that accumulates a lot of tool output can
reach the cap, and the kernel then OOM-kills the container. The container
restarts through `restart: unless-stopped`. If the container restarts in the
middle of a hunt, raise `deploy.resources.limits.memory` in
`docker-compose.yml`.

---

## Troubleshooting

**Run the doctor first.** `docker exec soc-ai python -m soc_ai doctor` checks the whole
dependency surface. It covers the config, the store and its migration head, Security Onion,
Elasticsearch, the audit grant, the gateway and the model fitness. It prints a pass and
fail table with a fix hint on every failing line. Start there, before the per-symptom
entries below.

**Container exits immediately after start**
Check that `.env` exists. Check that `SOC_AI_TLS_CERT` and `SOC_AI_TLS_KEY` point at files
that you mounted. `docker compose logs soc-ai` shows the pydantic-settings
validation error if a required field is missing.

**Health check fails**
The default `start_period` is 60s, so the DB migration can run on the first boot. If the
check fails every time, read `docker compose logs soc-ai` for the uvicorn startup
traceback.

**First page load fails with `TypeError: Failed to fetch`**
The browser does not trust the self-signed cert yet. Visit
`https://<host>:8443/healthz` once in the same browser. Accept the cert warning, then try
again. See DEPLOYMENT.md §10.

**Enrichment returns no GeoIP / ASN data**
The `soc_ai_maxmind` volume has no `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`. No
command fetches them. `MAXMIND_LICENSE_KEY` alone changes nothing. Copy the files in
as [Enrichment data](#enrichment-data) shows. Then restart.
