# Deployment

> **This page is the systemd path, without Docker.** Most users want the guided
> `./setup.sh` installer or the container path in [DOCKER.md](DOCKER.md). Start
> there, unless you need a bare rsync, systemd and uv deploy. This guide installs
> soc-ai under a system user, with a hardened systemd unit and a uv-managed venv.

This is the end-to-end deployment guide for soc-ai against a real Security Onion
3.x grid. The procedure produces a working install on a fresh VM in 30 minutes
or less.

> **The addresses below are example values. Substitute your own.** The
> `203.0.113.x` and `198.51.100.x` addresses are RFC 5737 documentation ranges.
> `<soc-ai-host>`, `<so-host>` and `<vm-host>` are placeholders.

The shape of the install is:

```
                    ┌──────────────────────────────────┐
                    │ Security Onion manager (SO 3.0.0)│
                    │ 198.51.100.10  (<so-host>)       │
                    │   - Kratos auth (/auth/...)      │
                    │   - Elasticsearch :9200          │
                    │   - Web UI :443                  │
                    └────────────┬─────────────────────┘
                                 │ ES basic auth (analyst creds)
                                 │ HTTPS w/ self-signed cert
                                 │
       ┌─────────────────────────┴─────────────────────────┐
       │ soc-ai VM (Fedora 43)                             │
       │ 203.0.113.20  (<soc-ai-host>)                     │
       │   - systemd unit (hardened)                       │
       │   - uvicorn :8443 (HTTPS, self-signed)            │
       │   - venv at /opt/soc-ai/.venv (system Python 3.12)│
       │   - .env with all creds + index patterns          │
       └─────────────────────────┬─────────────────────────┘
                                 │ HTTPS to LiteLLM gateway
                                 │
                    ┌────────────┴─────────────────────┐
                    │ LiteLLM gateway                  │
                    │ https://your-litellm-gateway     │
                    │   - soc-ai-analyst → (operator alias)│
                    │   - soc-ai-embed   → (optional)     │
                    └──────────────────────────────────┘
```

---

## 1. Prerequisites

- **A VM** that runs Fedora 43, or any modern Linux, with sudo. The v1 lab used
  4 vCPU, 8 GB RAM and 20 GB disk. Adjust that for your concurrent
  investigation load.
- **Network reachability** from the soc-ai VM to:
  - Port `:9200` on the SO manager, for Elasticsearch
  - Port `:443` on the SO manager, for the web UI and Kratos
  - The HTTPS endpoint of the LiteLLM gateway
  - An embeddings model on the gateway, `RAG_EMBED_MODEL`. This one is optional.
    Add it if you want semantic runbook search above the built-in keyword
    ranking.
- **Security Onion 3.0.0** with a non-default analyst account whose password you
  know. The SO grid creates that account for you.
- **A LiteLLM gateway** with the analyst model alias `soc-ai-analyst`
  configured. You can also set `ANALYST_MODEL` to any model that the gateway
  serves. You need a bearer token for the gateway.

---

## 2. VM setup

```bash
# On a fresh Fedora 43 VM:
sudo dnf install -y python3.12 git
# uv is the project manager (uv lock + uv sync handle deps).
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create the runtime user.
sudo useradd -r -m -d /opt/soc-ai -s /bin/bash soc-ai

# Pull the repo. Clone it, or rsync it from your dev box. rsync also works for
# the first install if the VM has no deploy key.
sudo mkdir -p /opt/soc-ai && sudo chown soc-ai:soc-ai /opt/soc-ai
# From the dev box. NEVER rsync .env. You set it up on the VM in §3, and an
# rsync of it pushes the config of the dev box to prod. Keep .git, so that
# /opt/soc-ai is a real checkout. Drop the venv, the eval artifacts and the caches.
rsync -av \
    --exclude=.venv --exclude=.env --exclude='.env.*' \
    --exclude=evals/ --exclude='.coverage*' \
    --exclude=.pytest_cache --exclude=.mypy_cache --exclude=.ruff_cache \
    --exclude=__pycache__ --exclude=.worktrees --exclude=.claude --exclude=.superpowers \
    <repo-checkout>/ soc-ai@<vm-host>:/opt/soc-ai/
```

> **SELinux trap on Fedora 43:** the managed Python of uv lives in
> `$HOME/.local/share/uv/python/...`. That path has an SELinux context that
> systemd refuses to exec from. Use the system `python3.12` from `/usr/bin`.
> The first lab install found this trap.

```bash
# As the soc-ai user on the VM:
ssh soc-ai@<vm-host>
cd /opt/soc-ai
uv venv --python /usr/bin/python3.12
uv sync  # populates /opt/soc-ai/.venv
```

---

## 3. Configuration

Copy `.env.example` to `.env`. Then fill it in:

```ini
# --- Security Onion grid -----------------------------------------------
SO_HOST=https://198.51.100.10
SO_USERNAME=analyst@yourorg.example.com
SO_PASSWORD=<analyst-password>
SO_VERIFY_SSL=false

# --- Connect API (Pro feature, OPTIONAL) -------------------------------
# Not required: ack/escalate/comment go through SO's always-available web API
# (e.g. POST /api/events/ack) with the analyst's Kratos session, so writes work
# on an OSS grid. Set these only if you specifically want Connect API OAuth
# (SO Pro grids with Hydra). Leave empty otherwise.
SO_CLIENT_ID=
SO_CLIENT_SECRET=

# --- Elasticsearch (analyst creds; same user as SO_USERNAME) -----------
ES_HOSTS=https://198.51.100.10:9200
ES_USERNAME=${SO_USERNAME}
ES_PASSWORD=${SO_PASSWORD}
ES_VERIFY_SSL=false

# --- LiteLLM gateway ---------------------------------------------------
LITELLM_BASE_URL=https://your-litellm-gateway
LITELLM_API_KEY=sk-<your-token>
LITELLM_VERIFY_SSL=true
ANALYST_MODEL=soc-ai-analyst
# ANALYST_MODEL is THE model the analyst agent uses for every triage. It is a
# LiteLLM alias or a real model id that your gateway serves. Model IDs drift, so
# probe /v1/models on your LiteLLM instance again to confirm what it resolves to.
# HEAVY_MODEL is still accepted as a deprecated alias. The optional Oracle second
# opinion is off by default. Turn it on with ORACLE_ENABLED=true.

# --- Index patterns ----------------------------------------------------
# SO 3.x stores Suricata/Zeek events + alerts in Elastic data streams named
# `logs-*` (e.g. `.ds-logs-suricata.alerts-so-...`). The events pattern is:
#   - single-node grid:           logs-*
#   - multi-node / distributed:   *:logs-*   (cross-cluster search)
# `setup.sh` auto-detects the cluster prefix during its ES validation step and
# writes the concrete pattern for you. The old `*:so-*` default is WRONG for
# both shapes. It matches the old-style `so-*` admin indices, such as so-case and
# so-detection. It misses the `logs-*` data streams where the alerts live, so the
# alert queue in the console comes up empty on a healthy grid.
#
# Keep the data-stream form. `logs-*` matches data-stream NAMES; Elasticsearch
# expands each to its hidden backing indices (`.ds-<stream>-<date>-<gen>`).
# Writing `.ds-…` instead pins the Elastic Agent namespace segment by hand:
#   .ds-logs-*-so-*       SO's own integrations (suricata, zeek, soc, kratos)
#   .ds-logs-*-default-*  Elastic's stock ones: system.auth, system.syslog,
#                         endpoint, winlog. The login/syslog evidence.
#   logs-synth-*          soc-ai's synthetic / eval data.
# Anything you leave off that list is invisible, and nothing warns you. See
# SECURITY-ONION-SETUP.md → Troubleshooting, "soc-ai cannot see logs that exist
# in SO".
EVENTS_INDEX_PATTERN=logs-*
# Cases / detections / playbooks live in the old-style `so-*` admin indices.
# Single-node: so-case* / so-detection* / so-playbook*. Multi-node: prefix each
# with `*:` (e.g. *:so-case*).
CASES_INDEX_PATTERN=so-case*
DETECTIONS_INDEX_PATTERN=so-detection*
PLAYBOOKS_INDEX_PATTERN=so-playbook*

# --- Server ------------------------------------------------------------
SOC_AI_HOST=0.0.0.0
SOC_AI_PORT=8443
SOC_AI_TLS_CERT=/etc/soc-ai/cert.pem
SOC_AI_TLS_KEY=/etc/soc-ai/key.pem
LOG_LEVEL=INFO

# --- Agent execution limits --------------------------------------------
# These are the built-in defaults. Tune them from real audit data.
AGENT_TOOL_CALLS_LIMIT=25
AGENT_REQUEST_LIMIT=18
SYNTHESIS_CONFIDENCE_FLOOR=0.6
```

Lock down the permissions:
```bash
sudo chmod 600 /opt/soc-ai/.env
sudo chown soc-ai:soc-ai /opt/soc-ai/.env
```

---

## 4. TLS certificate, self-signed for the lab

```bash
sudo mkdir -p /etc/soc-ai
cd /etc/soc-ai
sudo openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -subj "/CN=$(hostname -f)" \
  -addext "subjectAltName=DNS:soc-ai.local,IP:203.0.113.20" \
  -keyout key.pem -out cert.pem
sudo chmod 640 key.pem cert.pem
sudo chgrp soc-ai key.pem cert.pem
```

In production, replace it with a certificate from your internal CA or from Let's
Encrypt.

For a browser-trusted certificate with renewal, run Caddy on the host in front of soc-ai.
In `/opt/soc-ai/.env`, leave `SOC_AI_TLS_CERT` and `SOC_AI_TLS_KEY` blank. Set
`SOC_AI_HOST=127.0.0.1` and `PROXY_TRUSTED_IPS=127.0.0.1`. soc-ai then serves plain HTTP
on `127.0.0.1:8443`. Copy the `Caddyfile` from the repository root to
`/etc/caddy/Caddyfile`. Replace `{$SOC_AI_DOMAIN}` with the site name. Replace
`{$SOC_AI_CADDY_TLS}` with the `tls` directive, or delete that line. Change
`reverse_proxy soc-ai:8443` to `reverse_proxy 127.0.0.1:8443`. Then run
`sudo systemctl reload caddy`. See [DOCKER.md](DOCKER.md), TLS paths, for the `tls`
choices. For an ACME CA of your own, copy the `acme_ca` snippet from the `Caddyfile` too.

---

## 5. systemd service

Use the hardened unit file from the repo:

```bash
sudo cp /opt/soc-ai/scripts/systemd/soc-ai.service /etc/systemd/system/soc-ai.service
sudo systemctl daemon-reload
sudo systemctl enable --now soc-ai
sudo systemctl status soc-ai
```

The unit applies the safe hardening set: `PrivateTmp`, `ProtectSystem=full`,
`ProtectHome=read-only`, `NoNewPrivileges`, restricted address families,
`MemoryDenyWriteExecute`, and dropped capabilities. See
`scripts/systemd/soc-ai.service` for the full list and the rationale.

The unit sets `UMask=0077`, so each file the service makes is readable by the service user only.
The SQLite store holds the password hashes. soc-ai makes the store file and its WAL files mode
0600 and the data directory mode 0700. It also tightens an older 0644 store when it opens it.
A copy of the unit from an older release has no `UMask` line. Copy the unit again after an
update, then run `sudo systemctl daemon-reload`.

> **Do not use `ProtectSystem=strict`.** It makes /opt read-only. That breaks
> the symlink-based venv layout of uv.

---

## 6. Firewall

```bash
sudo firewall-cmd --add-port=8443/tcp --permanent
sudo firewall-cmd --reload
```

---

## 7. Audit-index role grant on the SO manager

Run this step one time. The default SO `analyst` role lacks `auto_configure` and
`create_index` on `soc-ai-audit-*`. As a result, every audit write from the
orchestrator fails with a 403. You can verify that in `journalctl -u soc-ai`. A
read-only investigation still completes, without its forensic trail. A write does not.

soc-ai ships with `AUDIT_FAIL_CLOSED=true`. Under that setting, soc-ai aborts every
acknowledge, escalate-to-case and add-comment until the grant exists. The tool result
reads `aborted: ...`. Nothing reaches Security Onion without an audit record. Run the
script below before the first write-back. soc-ai drops the audit event and lets the
action through only if `AUDIT_FAIL_CLOSED=false`.

To grant access to the audit index:

```bash
ssh <admin>@<so-manager> 'sudo bash -s' \
  < /opt/soc-ai/scripts/setup-audit-index.sh
```

The script grants the missing privileges to the `analyst` role. It also
creates today's audit index.

---

## 8. Reasoning trace on the gateway

**This optional section applies only if your gateway serves a reasoning model that
emits `<think>`.** The setup is specific to the model. soc-ai carries the `<think>`
traces of a model into the SSE stream as `model_response.reasoning_trace` payloads. If
your `ANALYST_MODEL` emits no reasoning, skip this section. Nothing breaks.

To turn it on, configure the LiteLLM and vLLM gateway to split `<think>` into the
`reasoning_content` field on the response. Set these:

- The vLLM serving arguments `--enable-reasoning --reasoning-parser <parser>`.
  `<parser>` must match the reasoning model that you serve. Each model family has
  its own parser, so check the `--reasoning-parser` choices in your vLLM build.
- The LiteLLM config key `merge_reasoning_content_in_choices: false`.

Verify it with a direct curl:

```bash
curl -ks -X POST "$LITELLM_BASE_URL/v1/chat/completions" \
  -H "Authorization: Bearer $LITELLM_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"'"$ANALYST_MODEL"'","messages":[
        {"role":"system","content":"detailed thinking on"},
        {"role":"user","content":"think out loud, then answer 2+2"}]}' \
  | jq '.choices[0].message | {reasoning_content, content}'
```

If `reasoning_content` is not empty, soc-ai picks it up automatically.

---

## 9. Verification

```bash
# Liveness check from any host that can reach the soc-ai VM. This says the
# server answered and nothing else. It probes no upstream:
curl -k https://<soc-ai-host>:8443/healthz
# → {"status":"alive","version":"1.5.0","so_auth":"kratos",...}

# The health verdict, which does touch every upstream:
uv run soc-ai doctor

# Or use the CLI:
uv run soc-ai healthz --url https://<soc-ai-host>:8443

# Real triage from the terminal:
uv run soc-ai triage <alert_id> --url https://<soc-ai-host>:8443
```

The shipped default `API_AUTH_REQUIRED=true` makes these commands authenticate
too, the same as a browser. Pass `--token scai_...`, or set `SOC_AI_API_TOKEN`.
Mint a token in the console under Config → API tokens. Without a token, `healthz`
and `triage` get a 401, and the CLI prints a one-line reminder of the fix.

With `API_AUTH_REQUIRED=false`, the doctor row "authentication" lists the addresses that listen
on `SOC_AI_PORT`. The doctor reads them from `/proc/net/tcp` and `/proc/net/tcp6`. A listener on
an address other than loopback reads WARN, because another host can call the API with no login.
The start log line names the bind only under `soc-ai serve`. Under the systemd unit and the
container, uvicorn holds the bind. The line then says "The bind is the server's".

A sample of a successful SSE transcript follows. It comes from alert
KDG7CZ4BVBs3R9hXQbPY, with verdict=false_positive and confidence=0.7:

```
session_start  alert_id='KDG7CZ4BVBs3R9hXQbPY'
alert_context  low 'ET INFO CMS Hosting Domain in DNS Lookup (storyblok .com)' …
tool_call      t_query_zeek_logs({"community_id":"1:EJY2WE2P…",…})
tool_result    t_query_zeek_logs → [{...}]
tool_call      t_enrich_ip({"ip":"3.166.135.86"})
tool_result    t_enrich_ip → {…}
investigation_transcript  round=1 evidence=2 open_questions=2
   A low-severity DNS informational alert was generated for a host …
usage          phase=investigator round=1 tools=3 reqs=4 tokens=24566/555
usage          phase=synthesizer  round=1 tools=0 reqs=1 tokens=1651/272
triage_report  FALSE_POSITIVE  confidence=0.7
   The alert triggered on a DNS query for a-us.storyblok.com …
   citations: alert-KDG7CZ4BVBs3R9hXQbPY, event-lTG7CZ4BVBs3R9hXaLP3
   → ack_alert (Alert is benign DHCP traffic; can be acknowledged…)
done           recommended_count=1 rounds=1
```

---

## 10. Common errors and fixes

| Symptom | Cause | Fix |
|---|---|---|
| `audit log write failed (event dropped) … indices:admin/auto_create … unauthorized for [analyst]` | The audit-index role grant is missing. `AUDIT_FAIL_CLOSED=true` is the default. Under it, soc-ai aborts every ack, escalate and comment until the grant lands. | Run `scripts/setup-audit-index.sh` on the SO manager. |
| `ContextWindowExceededError … input_tokens 65537` | The accumulated tool results exceeded the 64K serving window. | Lower `AGENT_TOOL_CALLS_LIMIT`. Its default is 25. Or raise `SYNTHESIS_CONFIDENCE_FLOOR`, so the retask happens later. |
| "writes fail with `Kratos login flow init failed`" | The Kratos auth prefix is wrong for SO 3.0. | Set `SO_KRATOS_PATH_PREFIX=/auth`. That is the default. A write uses the SO web API and the Kratos session. It does not use the Connect API. |
| The service does not start after a code update | The venv is out of sync. | `cd /opt/soc-ai && uv sync && sudo systemctl restart soc-ai`. |

---

## 11. Update

```bash
# From the dev box. CRITICAL: --exclude=.env (and .env.*) so you do NOT
# overwrite the VM's prod config; keep .git so the VM stays a clean checkout
# at the pushed HEAD; drop the venv, eval artifacts and local caches/cruft.
rsync -av \
    --exclude=.venv --exclude=.env --exclude='.env.*' \
    --exclude=evals/ --exclude='.coverage*' \
    --exclude=.pytest_cache --exclude=.mypy_cache --exclude=.ruff_cache \
    --exclude=__pycache__ --exclude=.worktrees --exclude=.claude --exclude=.superpowers \
    <repo-checkout>/ soc-ai@<vm-host>:/opt/soc-ai/

# On the VM:
ssh soc-ai@<vm-host> '
  cd /opt/soc-ai
  uv sync  # only if pyproject.toml / uv.lock changed
  sudo systemctl restart soc-ai
  sleep 3 && curl -ks https://localhost:8443/healthz
'
```

---

## 12. Authentication notes

soc-ai authenticates to ES directly with the analyst basic-auth credentials. It
needs no separate ES service account.

The write tools are `ack_alert`, `escalate_to_case` and `add_case_comment`. They
go through the Security Onion web API with the analyst's Kratos session
cookie. They use the same always-available routes that the SO web UI itself
uses:

| Tool | Routes |
| --- | --- |
| `ack_alert` | `POST /api/events/ack`. This is the bell icon on an alert row. |
| `escalate_to_case` | `POST /api/case/` then `POST /api/case/events` |
| `add_case_comment` | `POST /api/case/comments` |

These routes work on an OSS grid. They do not need the licensed Connect API.
The `/connect/*` paths of that API are an nginx alias for `/api/*`. A grid
without the `api` feature never serves them. SO 3.0.0 mounts Kratos under
`/auth/...`. The default `SO_KRATOS_PATH_PREFIX=/auth` matches it.

soc-ai still accepts `SO_CLIENT_ID` and `SO_CLIENT_SECRET` for an environment
that prefers Connect API OAuth on an SO Pro grid with Hydra. They are optional.
The default web-API path covers ack, escalate and comment without
SO Pro. See [SECURITY-ONION-SETUP.md](SECURITY-ONION-SETUP.md) for the full
account and role breakdown. It covers the `soc-ai-audit-*` Elasticsearch write
grant. Under `AUDIT_FAIL_CLOSED=true`, ack and escalate depend on that grant.

### Reverse proxy and `PROXY_TRUSTED_IPS`

If you put a reverse proxy in front of soc-ai, set `PROXY_TRUSTED_IPS` to the IP
addresses of the proxy. nginx, Caddy and Traefik are examples of such a proxy. An
example value is `PROXY_TRUSTED_IPS=203.0.113.10`. `PROXY_TRUSTED_IPS` takes addresses
and CIDR blocks.

The login throttle and the API rate limit are keyed per client IP address.
Without this setting, the proxy's own socket IP address stands in for every
client, so all users share one bucket. A few failed logins across the team can
then lock everyone out until the cooldown expires.

soc-ai trusts `X-Forwarded-For` and `X-Forwarded-Proto` only from a peer on this
list. Any client can forge these headers. Leave the list empty if clients connect
directly.

---

## 13. PostgreSQL

soc-ai keeps its store in SQLite by default. SQLite has one writer. At corporate scale, the
scheduler, the sweeps and the console contend for that writer. Set `SOC_AI_DATABASE_URL` to keep
the store in PostgreSQL. The same migration chain builds both stores, and soc-ai runs it at each
start on both.

### Differences from SQLite

| Item | SQLite | PostgreSQL |
| --- | --- | --- |
| Store | `soc-ai.db` in `SOC_AI_DATA_DIR` | The database that `SOC_AI_DATABASE_URL` names |
| Writers | One at a time | Many. The pool keeps `SOC_AI_DATABASE_POOL_SIZE` connections, 10 by default |
| Migrations at start | One transaction. soc-ai checks foreign keys by hand | One transaction under an advisory lock, so two starts do not race |
| Timestamps | Naive UTC | Naive UTC. The session runs in UTC |
| Runbook search | FTS5 BM25 | The keyword ranker |
| Chat memory | FTS5 BM25 | PostgreSQL text search, without an index |
| Backup | `soc-ai backup` | `pg_dump` |
| Start order | None | soc-ai waits up to 60 s for the server to accept connections |

The data directory still holds the decision-record signing key, the pinned sensor
`known_hosts` and the bootstrap credential. Keep it on a persistent disk.

### Requirements

- A PostgreSQL server. CI tests soc-ai on PostgreSQL 17.
- The asyncpg driver. The container image includes it. On the systemd path, run
  `uv sync --extra postgres`.
- An empty database and a role that owns it. soc-ai creates the tables at the first start.

```sql
CREATE ROLE soc_ai LOGIN PASSWORD 'change-me';
CREATE DATABASE soc_ai OWNER soc_ai;
```

Then set the URL in `.env`. `postgresql://` means the same driver.

```bash
SOC_AI_DATABASE_URL=postgresql+asyncpg://soc_ai:change-me@db.example.test:5432/soc_ai
```

soc-ai treats the value as a secret, because the URL holds the password. A log line or a doctor
row shows the URL without the password.

### Migration from SQLite to PostgreSQL

`soc-ai store migrate --to <url>` copies every table of the configured store into an empty store.
It copies in foreign key order and in one transaction. It moves each PostgreSQL sequence past the
highest copied key. It then counts every table on both sides and reports the counts that the
target holds. A failure rolls the copy back.

1. Stop soc-ai.

   ```bash
   sudo systemctl stop soc-ai
   ```

2. Back up the SQLite store.

   ```bash
   cd /opt/soc-ai
   uv run soc-ai backup --out /var/backups/soc-ai-before-postgres.tar.gz
   ```

3. Create the empty database. Do not start soc-ai on it yet. The first start writes the admin
   user, and the copy refuses a target that holds rows.

4. Run the copy with `--dry-run`. Put the password in `PGPASSWORD`. The password then stays out of
   the process list and the shell history.

   ```bash
   read -rs PGPASSWORD && export PGPASSWORD
   uv run soc-ai store migrate --dry-run \
     --to postgresql+asyncpg://soc_ai@db.example.test:5432/soc_ai
   ```

   The dry run reads both stores and writes nothing. It prints the rows per table. It also lists
   each stored value that PostgreSQL refuses. PostgreSQL refuses text longer than its column,
   text with a NUL character, an integer outside 32 bits and a row with no parent row. SQLite
   accepts all four. Fix or delete those rows in the SQLite store, then run the dry run again.

5. Run the copy.

   ```bash
   uv run soc-ai store migrate \
     --to postgresql+asyncpg://soc_ai@db.example.test:5432/soc_ai
   ```

6. Set `SOC_AI_DATABASE_URL` in `.env`, then start soc-ai and run the doctor. The `store` row
   names the PostgreSQL URL and the migration head.

   ```bash
   sudo systemctl start soc-ai
   uv run soc-ai doctor
   ```

7. Keep the SQLite file and the backup until you trust the new store. soc-ai does not read them
   while `SOC_AI_DATABASE_URL` is set.

The command exits with one of three codes:

- 0: the copy finished, or the dry run found nothing that stops the copy.
- 1: the copy failed. The target then holds no copied row.
- 2: the command refused to copy. It refuses a URL that it cannot use and a source behind the
  migration head of this build. It also refuses a target that holds rows and a source value
  that the target cannot hold.

`--from <url>` names another source store.

### PostgreSQL store backup

`soc-ai backup` and `soc-ai restore` act on a SQLite store only. With `SOC_AI_DATABASE_URL` set,
both refuse and name `pg_dump`. They would otherwise back up or restore a SQLite file that soc-ai
no longer reads. Pass `--data-dir` to act on a SQLite store on purpose.

```bash
pg_dump --format=custom --file="soc-ai-$(date -u +%Y%m%dT%H%M%SZ).dump" \
  --dbname=postgresql://soc_ai@db.example.test:5432/soc_ai
```

Back up the data directory with the dump. Restore the dump into an empty database with
`pg_restore`, then start soc-ai.

### Migration back to SQLite

The copy works in both directions. Stop soc-ai and move any old `soc-ai.db` out of
`SOC_AI_DATA_DIR`. Name the PostgreSQL store with `--from` and the SQLite file in the data
directory with `--to`. Then remove `SOC_AI_DATABASE_URL` from `.env` and start soc-ai.

```bash
uv run soc-ai store migrate \
  --from postgresql+asyncpg://soc_ai@db.example.test:5432/soc_ai \
  --to sqlite:////var/lib/soc-ai/data/soc-ai.db
```

### Limits

- Runbook search on PostgreSQL uses the keyword ranker, the same ranker as a SQLite build without
  FTS5.
- Chat memory on PostgreSQL has no text-search index. Each retrieval reads the whole chat
  projection.
- PostgreSQL refuses text with a NUL character, text longer than its column and an integer
  outside 32 bits. SQLite stores all three. A write of such a value fails on PostgreSQL.
