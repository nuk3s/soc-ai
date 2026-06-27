# Deployment

> **This is the non-Docker (systemd) path.** Most users want the guided
> `./setup.sh` installer or the container path in
> [DOCKER.md](DOCKER.md) — start there unless you specifically need a bare
> rsync + systemd + uv deploy. This guide installs under a system user with a
> hardened systemd unit and a uv-managed venv.

End-to-end deployment guide for soc-ai against a real Security Onion 3.0.0
grid. The procedure should produce a working install in ≤30 minutes against
a fresh VM.

> **Addresses below are example/placeholder values — substitute your own.**
> The `203.0.113.x` / `198.51.100.x` IPs are RFC 5737 documentation ranges,
> and `<soc-ai-host>` / `<so-host>` / `<vm-host>` are placeholders.

The shape of the install:

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
                    │   - soc-ai-embed   → Qwen3 (v1.1)   │
                    └──────────────────────────────────┘
```

---

## 1. Prereqs

- **A VM** running Fedora 43 (or any modern Linux) with sudo. v1 lab
  used 4 vCPU / 8 GB RAM / 20 GB disk — adjust based on concurrent
  investigation load.
- **Network reachability** from the soc-ai VM to:
  - The SO manager's port `:9200` (Elasticsearch)
  - The SO manager's port `:443` (web UI / Kratos)
  - The LiteLLM gateway's HTTPS endpoint
  - (Optional, v1.1) A Qdrant instance for RAG runbooks
- **Security Onion 3.0.0** with a non-default analyst account whose
  password you know (the SO grid creates this for you).
- **A LiteLLM gateway** preconfigured with the analyst model alias
  `soc-ai-analyst` (or set `ANALYST_MODEL` to any model it serves). Bearer token
  for the gateway.

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

> **SELinux gotcha (Fedora 43):** uv's managed Python lives in
> `$HOME/.local/share/uv/python/...` which is in an SELinux context
> systemd refuses to exec from. Use the system `python3.12` from
> `/usr/bin` instead (Phase 1 finding).

```bash
# As the soc-ai user on the VM:
ssh soc-ai@<vm-host>
cd /opt/soc-ai
uv venv --python /usr/bin/python3.12
uv sync  # populates /opt/soc-ai/.venv
```

---

## 3. Configuration

Copy `.env.example` to `.env` and populate:

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
# SO 3.0 stores Suricata/Zeek events + alerts in Elastic data streams named
# `logs-*` (e.g. `.ds-logs-suricata.alerts-so-...`). The events pattern is:
#   - single-node grid:           logs-*
#   - multi-node / distributed:   *:logs-*   (cross-cluster search)
# `setup.sh` auto-detects the cluster prefix during its ES validation step and
# writes the concrete pattern for you. The old `*:so-*` default is WRONG for
# both shapes — it matches the old-style `so-*` admin indices (so-case,
# so-detection), not the `logs-*` data streams where alerts live, so the alerts
# console comes up empty on a healthy grid.
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
# Generous defaults; tune from real audit data once landed.
AGENT_TOOL_CALLS_LIMIT=100
AGENT_REQUEST_LIMIT=50
SYNTHESIS_CONFIDENCE_FLOOR=0.6
```

Lock down perms:
```bash
sudo chmod 600 /opt/soc-ai/.env
sudo chown soc-ai:soc-ai /opt/soc-ai/.env
```

---

## 4. TLS cert (self-signed for the lab)

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

For production, replace with a cert from your internal CA / Let's Encrypt.

---

## 5. systemd service

Use the hardened unit file from the repo:

```bash
sudo cp /opt/soc-ai/scripts/systemd/soc-ai.service /etc/systemd/system/soc-ai.service
sudo systemctl daemon-reload
sudo systemctl enable --now soc-ai
sudo systemctl status soc-ai
```

The unit applies the safe hardening set: `PrivateTmp`,
`ProtectSystem=full`, `ProtectHome=read-only`, `NoNewPrivileges`,
restricted address families, `MemoryDenyWriteExecute`, dropped
capabilities, etc. See `scripts/systemd/soc-ai.service` for the full
list and rationale.

> **Don't use `ProtectSystem=strict`** — it makes /opt read-only,
> which breaks uv's symlink-based venv layout.

---

## 6. Firewall

```bash
sudo firewall-cmd --add-port=8443/tcp --permanent
sudo firewall-cmd --reload
```

---

## 7. Audit-index role grant (one-time, on the SO manager)

The default SO `analyst` role lacks `auto_configure` + `create_index`
on `soc-ai-audit-*`, so the orchestrator's audit logger silently
drops every event with a 403 (verifiable in `journalctl -u soc-ai`).
Audit failures are non-fatal — investigations still complete — but
you lose the forensic trail.

To unlock the audit index:

```bash
ssh <admin>@<so-manager> 'sudo bash -s' \
  < /opt/soc-ai/scripts/setup-audit-index.sh
```

The script grants the `analyst` role the missing privileges and
bootstraps today's audit index.

---

## 8. Reasoning trace (LiteLLM/vLLM config, optional, model-specific)

**Optional — only relevant if your gateway serves a `<think>`-emitting
reasoning model.** soc-ai is plumbed to surface a model's `<think>` traces
into the SSE stream as `model_response.reasoning_trace` payloads. If your
`ANALYST_MODEL` doesn't emit reasoning, skip this section — nothing breaks.

To light it up, the LiteLLM/vLLM gateway needs to be configured to split
`<think>` into the `reasoning_content` field on the response. Specifically:

- vLLM serving args: `--enable-reasoning --reasoning-parser <parser>`, where
  `<parser>` matches the reasoning model you serve (each model family has its
  own parser; check your vLLM build's `--reasoning-parser` choices).
- LiteLLM config: `merge_reasoning_content_in_choices: false`.

Verify by direct curl:

```bash
curl -ks -X POST "$LITELLM_BASE_URL/v1/chat/completions" \
  -H "Authorization: Bearer $LITELLM_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"'"$ANALYST_MODEL"'","messages":[
        {"role":"system","content":"detailed thinking on"},
        {"role":"user","content":"think out loud, then answer 2+2"}]}' \
  | jq '.choices[0].message | {reasoning_content, content}'
```

If `reasoning_content` is non-empty, soc-ai will pick it up
automatically.

---

## 9. Userscript (Tampermonkey)

Browser-side install for the side-panel UI:

1. Install Tampermonkey (Chrome / Firefox / Edge).
2. Click the Tampermonkey icon → "Create a new script…"
3. Paste `userscript/soc-ai.user.js` from the repo. Save.
4. Click the script in the dashboard, set your soc-ai URL via the
   userscript's settings (or accept the default
   `https://localhost:8443`).
5. Visit `https://<your-so-manager>/#/alerts`.
6. Click "🔍 Hunt with AI" on any row. The side panel streams the
   investigation.

Detailed userscript notes (the fetch+XHR interception architecture,
ES `_id` resolution, expand-panel fallback) live in `userscript/README.md`.

---

## 10. Verification

```bash
# Health check from any host that can reach the soc-ai VM:
curl -k https://<soc-ai-host>:8443/healthz
# → {"status":"ok","version":"1.0.0","so_auth":"kratos",...}

# Or use the CLI:
uv run soc-ai healthz --url https://<soc-ai-host>:8443

# Real triage from the terminal:
uv run soc-ai triage <alert_id> --url https://<soc-ai-host>:8443
```

Sample successful SSE transcript (alert KDG7CZ4BVBs3R9hXQbPY,
verdict=false_positive, confidence=0.7):

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
approval_required ack_alert  token='…'
done           recommended_count=1 rounds=1
```

---

## 11. Common errors + fixes

| Symptom | Cause | Fix |
|---|---|---|
| `audit log write failed (event dropped) … indices:admin/auto_create … unauthorized for [analyst]` | Missing audit-index role grant | Run `scripts/setup-audit-index.sh` on the SO manager. |
| `ContextWindowExceededError … input_tokens 65537` | Tool result accumulation blew the 64K serving window | Either: cap `AGENT_TOOL_CALLS_LIMIT` (default 100) lower, set `SYNTHESIS_CONFIDENCE_FLOOR` higher (so retask happens later). |
| Userscript "Could not find a matching alert (rule.uuid=…)" | Userscript loaded after SO's first /api/events/ fetched (cache empty) | Hard-refresh (Ctrl-F5). The userscript installs at @run-at document-start; refreshing puts it before the SO bundle. |
| `TypeError: Failed to fetch` (userscript console; surfaces in the panel as a generic connection error) on first "Hunt with AI" | Browser hasn't trusted the self-signed cert, so the cross-origin request never reaches the server — it is *not* an HTTP 403 | Visit `https://<soc-ai-host>:8443/healthz` once in the same browser and accept the cert, then retry. |
| "writes fail with `Kratos login flow init failed`" | Kratos auth prefix wrong for SO 3.0 | Set `SO_KRATOS_PATH_PREFIX=/auth` (the default). Writes use the SO web API + Kratos session, not the Connect API. |
| Service won't start after pulling new code | venv out of sync | `cd /opt/soc-ai && uv sync && sudo systemctl restart soc-ai`. |

---

## 12. Updating

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

## 13. Authentication notes

soc-ai authenticates to ES directly using the analyst basic-auth
credentials — no separate ES service account is needed.

The write tools (`ack_alert`, `escalate_to_case`,
`add_case_comment`) go through Security Onion's **web API** using the
analyst's Kratos session cookie — e.g. `ack_alert` posts to
`POST /api/events/ack`, the same always-available endpoint the SO web
UI uses when you click the bell icon on an alert. This path works on
an OSS grid; it does **not** require the paywalled Connect API. SO
3.0.0 mounts Kratos under `/auth/...`, which is the default
(`SO_KRATOS_PATH_PREFIX=/auth`).

`SO_CLIENT_ID` + `SO_CLIENT_SECRET` (Connect API OAuth, SO Pro grids
with Hydra) remain accepted for environments that prefer it, but they
are **optional** — the default web-API path covers ack/escalate/comment
without SO Pro. See [SECURITY-ONION-SETUP.md](SECURITY-ONION-SETUP.md)
for the full account/role breakdown (including the `soc-ai-audit-*`
Elasticsearch write grant that ack/escalate silently depend on under
`AUDIT_FAIL_CLOSED=true`).
