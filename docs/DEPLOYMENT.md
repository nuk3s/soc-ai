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

## 2. Set up the VM

```bash
# On a fresh Fedora 43 VM:
sudo dnf install -y python3.12 git
# uv is the project manager (uv lock + uv sync handle deps).
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create the runtime user.
sudo useradd -r -m -d /opt/soc-ai -s /bin/bash soc-ai

# Pull the repo. (Clone it, or rsync from your dev box — rsync works just
# as well for the initial bootstrap if the VM has no deploy key.)
sudo mkdir -p /opt/soc-ai && sudo chown soc-ai:soc-ai /opt/soc-ai
# From the dev box. NEVER rsync .env — it's set up separately on the VM
# (see §3); rsyncing it would push the dev box's config to prod. Keep .git
# so /opt/soc-ai is a real checkout; drop the venv, eval artifacts and caches.
rsync -av \
    --exclude=.venv --exclude=.env --exclude='.env.*' \
    --exclude=evals/ --exclude='.coverage*' \
    --exclude=.pytest_cache --exclude=.mypy_cache --exclude=.ruff_cache \
    --exclude=__pycache__ --exclude=.worktrees --exclude=.claude --exclude=.superpowers \
    <repo-checkout>/ soc-ai@<vm-host>:/opt/soc-ai/
```

> **SELinux trap on Fedora 43:** the managed Python of uv lives in
> `$HOME/.local/share/uv/python/...`. That path has an SELinux context that
> systemd refuses to exec from. Use the system `python3.12` from `/usr/bin`
> instead. Phase 1 found this.

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
# ANALYST_MODEL is THE model the analyst agent uses for every triage — a LiteLLM
# alias or a real model id your gateway serves. Model IDs drift — re-probe
# /v1/models on your LiteLLM instance to confirm what it resolves to. (HEAVY_MODEL
# is still accepted as a deprecated alias.) The optional Oracle second opinion is
# off by default; enable it with ORACLE_ENABLED=true.

# --- Index patterns ----------------------------------------------------
# SO 3.x stores Suricata/Zeek events + alerts in Elastic data streams named
# `logs-*` (e.g. `.ds-logs-suricata.alerts-so-...`). The events pattern is:
#   - single-node grid:           logs-*
#   - multi-node / distributed:   *:logs-*   (cross-cluster search)
# `setup.sh` auto-detects the cluster prefix during its ES validation step and
# writes the concrete pattern for you. The old `*:so-*` default is WRONG for
# both shapes — it matches the old-style `so-*` admin indices (so-case,
# so-detection), not the `logs-*` data streams where alerts live, so the alerts
# console comes up empty on a healthy grid.
#
# Keep the data-stream form. `logs-*` matches data-stream NAMES; Elasticsearch
# expands each to its hidden backing indices (`.ds-<stream>-<date>-<gen>`).
# Writing `.ds-…` instead pins the Elastic Agent namespace segment by hand:
#   .ds-logs-*-so-*       SO's own integrations (suricata, zeek, soc, kratos)
#   .ds-logs-*-default-*  Elastic's stock ones — system.auth, system.syslog,
#                         endpoint, winlog. The login/syslog evidence.
#   logs-synth-*          soc-ai's synthetic / eval data.
# Anything you leave off that list is invisible and nothing warns you. See
# SECURITY-ONION-SETUP.md → Troubleshooting, "soc-ai can't see logs that
# clearly exist in SO".
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
# These are the built-in defaults; tune from real audit data once landed.
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

> **Do not use `ProtectSystem=strict`.** It makes /opt read-only. That breaks
> the symlink-based venv layout of uv.

---

## 6. Firewall

```bash
sudo firewall-cmd --add-port=8443/tcp --permanent
sudo firewall-cmd --reload
```

---

## 7. Audit-index role grant (one-time, on the SO manager)

The default SO `analyst` role lacks `auto_configure` and `create_index` on
`soc-ai-audit-*`. The audit logger of the orchestrator therefore drops every
event silently with a 403. You can verify that in `journalctl -u soc-ai`. An
audit failure is not fatal, because the investigation still completes. You do
lose the forensic trail.

To unlock the audit index:

```bash
ssh <admin>@<so-manager> 'sudo bash -s' \
  < /opt/soc-ai/scripts/setup-audit-index.sh
```

The script grants the missing privileges to the `analyst` role. It also
bootstraps the audit index for today.

---

## 8. Reasoning trace (LiteLLM/vLLM config, optional, model-specific)

**This section applies only if your gateway serves a reasoning model that emits
`<think>`.** soc-ai carries the `<think>` traces of a model into the SSE stream
as `model_response.reasoning_trace` payloads. If your `ANALYST_MODEL` emits no
reasoning, skip this section. Nothing breaks.

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
# server answered and nothing else — it probes no upstream:
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
Mint a token in the web UI under Config → API tokens. Without a token, `healthz`
and `triage` get a 401, and the CLI prints a one-line reminder of the fix
alongside it.

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

## 10. Common errors + fixes

| Symptom | Cause | Fix |
|---|---|---|
| `audit log write failed (event dropped) … indices:admin/auto_create … unauthorized for [analyst]` | The audit-index role grant is missing. | Run `scripts/setup-audit-index.sh` on the SO manager. |
| `ContextWindowExceededError … input_tokens 65537` | The accumulated tool results blew the 64K serving window. | Lower `AGENT_TOOL_CALLS_LIMIT`. Its default is 25. Or raise `SYNTHESIS_CONFIDENCE_FLOOR`, so the retask happens later. |
| "writes fail with `Kratos login flow init failed`" | The Kratos auth prefix is wrong for SO 3.0. | Set `SO_KRATOS_PATH_PREFIX=/auth`. That is the default. A write uses the SO web API and the Kratos session, and not the Connect API. |
| Service won't start after pulling new code | The venv is out of sync. | `cd /opt/soc-ai && uv sync && sudo systemctl restart soc-ai`. |

---

## 11. Updating

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
cookie. They use the same always-available routes that the SO web console itself
uses:

| Tool | Routes |
| --- | --- |
| `ack_alert` | `POST /api/events/ack`. This is the bell icon on an alert row. |
| `escalate_to_case` | `POST /api/case/` then `POST /api/case/events` |
| `add_case_comment` | `POST /api/case/comments` |

These routes work on an OSS grid. They do not need the licensed Connect API.
The `/connect/*` paths of that API are an nginx alias for `/api/*`, and a grid
without the `api` feature never serves them at all. SO 3.0.0 mounts Kratos under
`/auth/...`, and that is the default, `SO_KRATOS_PATH_PREFIX=/auth`.

soc-ai still accepts `SO_CLIENT_ID` and `SO_CLIENT_SECRET` for an environment
that prefers Connect API OAuth on an SO Pro grid with Hydra. They are optional.
The default web-API path covers ack, escalate and comment without
SO Pro. See [SECURITY-ONION-SETUP.md](SECURITY-ONION-SETUP.md) for the full
account and role breakdown. It covers the `soc-ai-audit-*` Elasticsearch write
grant that ack and escalate silently depend on under `AUDIT_FAIL_CLOSED=true`.

### Behind a reverse proxy: set `PROXY_TRUSTED_IPS`

If you put a reverse proxy in front of soc-ai, set `PROXY_TRUSTED_IPS` to the IP
addresses of the proxy. nginx, Caddy and Traefik are examples of such a proxy. An
example value is `PROXY_TRUSTED_IPS=203.0.113.10`.

The login throttle and the API rate limit are keyed per client IP address.
Without this setting, the proxy's own socket IP address stands in for every
client, so all users share one bucket. A handful of failed logins across the team
can then lock everyone out until the cooldown expires.

soc-ai trusts `X-Forwarded-For` and `X-Forwarded-Proto` only from a peer on this
list, because an arbitrary client could forge them. Leave the list empty if
clients connect directly.
