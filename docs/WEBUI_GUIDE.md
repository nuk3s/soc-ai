# soc-ai web UI: operator guide

The soc-ai web UI is a self-hosted triage console for Security Onion alerts. It
runs on the soc-ai host at **`https://<host>:8443/app`** behind session auth.
This guide is a practical reference for the analyst/operator surfaces.

![An investigation in the console](img/screenshot-investigation.png)

> **Front door is `/app`**, the React console. It is the only web surface;
> bare `/` redirects to `/app/alerts` and login lands there. (The legacy
> server-rendered `/ui` console has been removed.)

> **First run / self-signed cert:** the UI serves over HTTPS with a self-signed
> cert. Visit the base URL once and accept the cert warning before signing in;
> otherwise the browser refuses the connection with an opaque `TypeError: Failed
> to fetch`.

## Sign in

`/app/login`: username + password. Two roles:

- **analyst**: full triage console (alerts, hunts, investigations).
- **admin**: everything an analyst can do **plus** the config console (`/app/config`).

The first admin (`admin`) is bootstrapped on first start; its generated password
is written **once** to a locked-down sidecar file,
`<soc_ai_data_dir>/bootstrap-admin-password.txt` (mode `0600`) — not to the
service log, which is often readable by the same audience the credential must
stay secret from. Read it for your deploy path:

```bash
# Docker deploy (default data dir /var/lib/soc-ai/data)
docker exec soc-ai cat /var/lib/soc-ai/data/bootstrap-admin-password.txt
# systemd / host-venv deploy
cat "$SOC_AI_DATA_DIR/bootstrap-admin-password.txt"
```

Only if the data dir was not writable at startup does soc-ai fall back to
logging the plaintext (`journalctl -u soc-ai | grep -i password` /
`docker compose logs soc-ai | grep -i password`); on the normal path the log
holds only a pointer line, not the password.

Change it after first login (Config → Users → reset password), then **delete the
sidecar file** — it is no longer needed and should not linger on the volume.

## Triage console (`/app/alerts`)

![The alert queue with AI verdicts inline](img/screenshot-alerts.png)

The main pane: Security-Onion-style alert groups (by rule), newest first.

- **Filter / sort:** time range, severity, sort order, and a free-text OQL box.
- **Expand a group:** click a group row to load its recent events.
- **Hunt:** start an AI investigation for an alert/group. Hunts run as
  **background tasks**: they survive closing the drawer, run concurrently, and
  every run is recorded. Live progress (phase / elapsed / tools called /
  enrichments) streams into the drawer.
- **Verdict badges:** each group/alert shows its latest investigation verdict
  (true_positive / false_positive / needs_more_info / running / error). A dashed
  badge with an "inherited" tooltip means the verdict was inherited from a
  **similar** alert (same rule, same src/dst pair, within the inherit window),
  visible at both the individual and **group** level.
- **Permalinks:** every investigation has a shareable URL
  (`/app/investigation/{id}`), created even while a hunt is still running.
- **⚡ Auto-triage:** sweep the current view and hunt everything not already
  covered. Use the **severity checkboxes** (default critical + high) to choose
  which severities it acts on. A single run is capped (`auto_triage_max_targets`,
  default 25) so one click can't spawn dozens of hunts; uncovered overflow is
  picked up by the next run. The status chip shows hunted/total/skipped + the
  chosen severities.

## Investigations (`/app/investigations`)

![The investigations list with verdicts and confidence](img/screenshot-investigations.png)

A list of all past + in-flight investigations (verdict, rule, when, who started
it) with permalinks. Use it to review history and find a prior verdict.

**Stale-run reaping:** investigations left `running` by a crash/restart/network
drop are cleaned up automatically. On startup every orphaned `running` row is
marked `error` (its worker died with the previous process), and a periodic sweep
marks any run still `running` past `investigation_reaper_minutes` (default 30).
No manual SQL needed to clear orphans.

## Runbooks (`/app/runbooks`)

The authoring space for your team's own triage guidance, the corpus the
investigation agent searches (its `lookup_runbook` tool) and cites in verdicts.
Reading is open to analysts; creating/editing/deleting is admin-gated.

- **Editor**: title, markdown content (with a write/preview toggle), tags, and
  **linked rules**: detection rule names/UUIDs this runbook applies to. A
  rule-link is the strongest retrieval signal: when that rule fires, this
  runbook wins.
- **Import files…**: bulk-import existing `.md` procedures from your wiki or
  repo. Optional YAML front-matter (`title:`, `tags:`, `rules:`) is parsed
  leniently: malformed metadata is ignored and the body still imports; the
  title falls back to the first `#` heading, then the filename.
- **Load starter pack**: seeds ten generic, vendor-neutral SOC runbooks shipped
  with the repo (`runbooks/starter-pack/`). Idempotent by title, so it never
  duplicates or overwrites a runbook you already have, so it's safe to re-run
  after upgrades. Edit the seeded copies freely; your edits stick.
- When the optional **Retrieval (RAG)** embeddings tier is configured, each row
  shows its embed status (`embedded` / `not embedded` / `stale embedding`);
  the catch-up pass lives at Config → Retrieval → "Re-embed runbooks".

The Config page keeps a compact summary (count + manage link) next to the
Retrieval settings.

## Config console (`/app/config`, admin only)

In-UI configuration. A non-admin who reaches it gets a clean 403 (no login loop).

### Settings sections (Oracle / Agent / PCAP)

Editable, **non-secret** runtime settings. Each row shows a **source badge**:

- `env`: the value comes from `.env` (the default).
- `db`: an admin override is set (stored in the `config_overrides` table).

Changes are **hot-applied**: saving persists the override *and* mutates the live
settings, so it takes effect on the **next investigation with no restart**. The
overrides are re-applied at startup, so they survive restarts. Editable keys:

- **Oracle**: `oracle_enabled` (the cloud frontier-model second opinion;
  everything sent to it is sanitized first), `oracle_model`, and the escalation
  thresholds (`oracle_escalate_*`). This is the home for the Oracle toggle.
- **Agent**: `investigate_when_unsure` (run the bounded investigation loop when
  the fast round-1 verdict isn't evidence-backed).
- **PCAP**: `pcap_enabled` (fetch + decode raw packets on demand via the SO
  sensor's Suricata pcap ring).

### Connection (Danger Zone)

LLM gateway, Security Onion, and Elasticsearch connection details default to the
values in `.env` on the host, with **secrets masked** (`••••••`) and never
echoed back. They are **not** read-only, though: the **Danger Zone** panel lets
an admin override the connection identity and credentials — `so_host`,
`so_username`, `so_password`, `so_verify_ssl`, the SSH-pivot fields
(`so_ssh_host` / `so_ssh_user` / `so_ssh_key`), `es_hosts`, `es_username`,
`es_password`, `es_verify_ssl`, `litellm_base_url`, `litellm_api_key`, and
`internal_cidrs`. Each write requires a **typed confirmation** (retype the key
name) and is **Fernet-encrypted at rest** (needs `CONFIG_SECRET_KEY`). Because
these repoint startup-built clients they are **not** hot: an override takes
effect on the **next restart**. Since an admin session can repoint the gateway
or grid from here — sending every alert's enriched context to a different
endpoint — treat the admin role and `/app/config` as trust-sensitive, not just
"agent knobs".

- **Test connection** buttons probe the **LiteLLM gateway** (`GET /v1/models`,
  reports model count) and **Elasticsearch** (`ping`, reports cluster + version).
  Results are inline ✓/✗ and never contain a secret.

### API keys

A separate **API keys** panel (rendered next to Data sources, not in the normal
settings groups) holds the enrichment-provider secrets: `shodan_api_key`,
`greynoise_api_key`, `misp_api_key`, `maxmind_license_key`, `abuse_ch_auth_key`,
and `crawl4ai_token`. These are **write-only** (Fernet-encrypted at rest, never
rendered back), **hot-applied** (read fresh on each enrichment call — no restart
and no typed confirm), and also need `CONFIG_SECRET_KEY` to persist.

### Users

Add users (username / password ≥ 8 / role), enable/disable, reset password
(shown **once**), and change role. Guards: you can't disable your own account,
and you can't disable or demote the **last enabled admin**.

### API tokens

Mint API tokens (the `scai_…` value is shown **once** at creation, so copy it then;
only its hash is stored) and revoke them. Tokens are for programmatic API
access (automation / integrations) once `API_AUTH_REQUIRED` is enabled.

## Safety model (recap)

Every **read** tool the agent uses is read-only. Every **write** tool (anything
that changes Security Onion state: ack, escalate-to-case, comment) is something
the agent can only *recommend*; you execute it with a click from the report,
and every execution is audited. The one bounded exception is the
confidence-gated auto-acknowledge for low-stakes false positives
(`auto_ack_fp_enabled`), which never touches critical or malware-class alerts. See [SAFETY_MODEL.md](SAFETY_MODEL.md) and the
agent capability surface in [AGENT_TOOLS.md](AGENT_TOOLS.md).
