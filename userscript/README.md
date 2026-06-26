# soc-ai Tampermonkey userscript

Browser-side userscript that injects a **🔍 Hunt with AI** button into
Security Onion's web UI, opens a side panel that streams the soc-ai triage
assistant's analysis, and surfaces approval prompts for write actions.

Tested against **Security Onion 3.0.0** (Elastic-native datastreams, hash-based
SPA routing). Works in Tampermonkey, Greasemonkey, Violentmonkey, and
Userscripts (Safari).

## Installation

### Step 1 — Trust the soc-ai self-signed TLS cert in your browser

This is the most common cause of "I clicked the button and nothing happens."
The browser blocks fetch / SSE to a self-signed cert URL until you've
explicitly trusted it.

Open a new tab and navigate directly to your soc-ai server's healthz endpoint:

```
https://<soc-ai-host>:8443/healthz
```

You'll get a cert warning. Click **Advanced** → **Proceed to `<soc-ai-host>` (unsafe)**.
You should then see a small JSON response:

```json
{"status":"ok","version":"1.0.0","so_auth":"kratos","misp_configured":false,"pending_approvals":0}
```

Once you've done this in any tab, the cert is trusted for the session and the
userscript's fetches from the SO web UI will succeed.

### Step 2 — Install the userscript

1. Install a userscript manager:
   - **Tampermonkey** (recommended): https://www.tampermonkey.net/
   - Greasemonkey, Violentmonkey, or Userscripts (Safari) all also work.
2. Open `userscript/soc-ai.user.js` in this directory.
3. Click **"Install"** when your userscript manager prompts. Or drag the file
   into your manager's dashboard.

> **Updating from an earlier version?** Tampermonkey caches the install
> metadata (including the `@match` directives), so a file change isn't
> automatically picked up. **Delete the old version first**, then install
> the new one. The version number in the script header (currently
> `@version 0.8.2`) is bumped whenever the install metadata or behavior
> changes — see the changelog table at the bottom of this file.

### Step 3 — Configure the soc-ai endpoint

The script ships with a default of `https://localhost:8443`. To point it at
your soc-ai server:

1. Open the SO web UI (`https://your-so-grid/`) in your browser.
2. Look for the floating **🔍 soc-ai** button in the bottom-right. Click any
   "Hunt with AI" button on an alert row to open the side panel.
3. In the side panel header, click the **⚙** (gear) icon.
4. Enter your soc-ai server URL: e.g. `https://<soc-ai-host>:8443`.

The setting is stored per-script in your userscript manager's storage. You can
also set it from the Tampermonkey menu: **soc-ai: set server URL**.

### Step 3b — Set an API token (if `API_AUTH_REQUIRED=true`)

If your soc-ai deployment has API auth enabled (recommended), the script must
send a bearer token or every call returns `401`:

1. In the soc-ai **config console → API Tokens**, mint a token (shown once,
   `scai_…`).
2. In Tampermonkey's menu (the extension icon → soc-ai), click **soc-ai: set
   API token** and paste it.

The token is sent as `Authorization: Bearer scai_…` on every request and stored
per-script. If your deployment leaves auth off (default), skip this — no token,
no header, and the script works the same as before.

### Step 4 — Verify the script loaded

Open the SO web UI, hit `F12` (or `Cmd-Option-I` on Mac) to open the dev
tools, switch to the **Console** tab. You should see:

```
[soc-ai] userscript loaded on https://<so-host>/...
[soc-ai] booted; soc_ai_url = https://<soc-ai-host>:8443
```

If you don't see those lines, the script didn't load — check that
Tampermonkey shows it as enabled (the toolbar icon turns dark red when
no scripts are running on the current page).

## Usage

1. Browse to **Alerts**, **Hunt**, **Cases**, or **Dashboards** in the SO
   web UI.
2. Each alert row should have a small gradient **🔍 Hunt with AI** button
   on its right side. There's also a floating **🔍 soc-ai** launcher in the
   bottom-right of every page that always works (paste an alert ID
   manually if row buttons aren't visible).
3. Click the button — the side panel opens and streams the agent's
   investigation in real time:
   - **tool_call / tool_result** rows (collapsed by default — click to
     expand)
   - **model_response** rows with optional collapsed `<think>` reasoning
     trace
   - The final **triage report** with verdict, confidence, summary,
     citations
   - One **approval_required** card per recommended write action
4. For each recommended action, click **Approve** to execute (POSTs to
   `/approve`) or **Reject** to feed a synthetic refusal back to the agent.
   The buttons are idempotent — double-click is safe; the second
   submission returns `already_decided` rather than executing twice.

## How alert IDs get resolved (v0.5.0)

SO 3.0.0's Vue/Vuetify alerts grid never embeds the ES `_id` in the
rendered DOM (cells hold field values; `item-key="id"` lives only in
JS state). The userscript resolves the `_id` for the row you clicked
in three layered steps:

1. **`/api/events/` interception (primary).** The script installs at
   `@run-at document-start` and patches both `window.fetch` and
   `XMLHttpRequest.prototype.send` (SO uses Axios → XHR). When SO's
   frontend pulls the alerts list, the script clones the response, reads
   each `event.id`, and stashes it in an in-memory `Map` keyed by the
   row-visible fields (`@timestamp + rule.uuid + 5-tuple`). On click,
   the row's context is rebuilt with the same key and the cached `_id`
   is used. This is the snappy path — sub-millisecond resolution, no
   extra HTTP, no UI animation.
2. **Expand-panel fallback.** If the cache misses (rare race: row added
   after the page-load that patched fetch, or the analyst clicked
   before the first `/api/events/` returned), the script clicks the
   row's `events_item_expand_alerts` button, waits for the detail
   panel to render, and reads the `soc_id` field from it. SO surfaces
   `soc_id` in the expand panel as the literal ES `_id` for that
   alert.
3. **Manual prompt (last resort).** If both fail (e.g. a future SO
   release moves the expand toggle), the script prompts you to paste
   the `_id` directly. Should be unreachable in practice.

The script does **not** call soc-ai's `/find-alert` resolver — that
endpoint heuristically searches ES by row context (rule.uuid +
timestamp window), which is wrong when many alerts share a rule. The
endpoint is kept on the server as a backstop for non-browser callers
(CLI, MCP, future v2 webui).

You can see what the cache picked up by opening dev tools → Console
and looking for lines like:

```
[soc-ai] cached 7 alert ids from xhr https://.../api/events/?... (total: 7)
[soc-ai] resolved KDG7CZ4BVBs3R9hXQbPY from cache
```

## Troubleshooting

### Tampermonkey shows "no scripts running" on the alerts page

Most common on hash-routed SPAs (SO 3.0.0 uses
`https://host/#/alerts...`). Tampermonkey strips the URL hash before
applying `@match`, so older patterns like `https://*/alerts*` never fire.
The current script uses `@match https://*/*` to load on every HTTPS page;
make sure you've reinstalled v0.5.0 or later.

### Side panel says "HTTP 0" or fails to connect

You haven't trusted the soc-ai self-signed cert yet — go back to Step 1.
After accepting the cert, refresh the SO page and try again.

### "Could not find a matching alert (rule.uuid=…)" prompt appears

Means both the cache lookup and the expand-panel fallback came back
empty for the row you clicked. Check the dev-tools console:

- If you don't see any `[soc-ai] cached N alert ids from xhr ...`
  lines, the userscript may have loaded after SO's first
  `/api/events/` request fired — hard-refresh (Ctrl-F5) so the patch
  installs at `document-start` before the SO bundle loads.
- If the cache populated but the lookup missed, the row's timestamp
  on screen probably differs from the payload's `@timestamp` by more
  than a millisecond (rare; usually a row recently added by a live
  refresh). Re-click; the next `/api/events/` will refresh the cache.

### Buttons don't appear on alert rows but the floating launcher works

The row-injection selectors are heuristic and may not catch every SO
deployment's DOM. The floating bottom-right button always works — paste
an alert `_id` manually. To improve row injection in the next release,
right-click any alert row → **Inspect** → in the Elements panel,
right-click the highlighted row element → **Copy** → **Copy outerHTML**.
Send the HTML and we'll add the right selectors / data-* attributes.

### CORS errors in the console

The soc-ai server ships with permissive CORS (`Access-Control-Allow-Origin: *`)
for v1 lab use. If you see CORS errors:
- Confirm soc-ai is on v1.x with the CORS middleware (commit `5236b11` or
  later).
- Confirm the soc-ai URL is **HTTPS** if your SO grid is HTTPS — browsers
  block mixed content (HTTPS page → HTTP fetch).

### "Hunt with AI" button text appears multiple times on the same row

Suggests the script is double-injecting on DOM mutations. Hard-refresh
the page (Cmd-Shift-R / Ctrl-F5) to clear the duplicate observers.

## Configurable URL via Tampermonkey storage

The soc-ai URL is stored in `GM_setValue('SOC_AI_URL', ...)` (Tampermonkey
per-script storage). To override programmatically (e.g. for testing
multiple environments), use Tampermonkey's storage editor or run this in
the dev console **on a page where the script is loaded**:

```js
GM_setValue('SOC_AI_URL', 'https://soc-ai.your-grid:8443')
```

(Tampermonkey only exposes `GM_*` symbols inside the userscript's sandbox,
not in the page's regular console — use Tampermonkey's editor for the
session-storage UI instead.)

## Security notes

- The script runs in a Shadow DOM, so its CSS won't conflict with the SO
  web UI's styles.
- The script only talks to the configured soc-ai URL plus the SO web UI
  it was injected into (no external services).
- The soc-ai server is responsible for all SO grid authentication; the
  userscript only carries the alert ID forward.
- Per-script Tampermonkey storage means the configured URL doesn't leak
  to other websites.

## Versioning

| Version | Highlights                                                        |
| ------- | ----------------------------------------------------------------- |
| 0.1.0   | Initial userscript.                                               |
| 0.2.0   | Hash-route compat (`@match https://*/*`), CORS-friendly, console diagnostics. |
| 0.3.0   | Smarter alert-ID auto-detection (data-* attrs + ES `_id`-shape filter); prompt-and-correct fallback when detection grabs a column label. |
| 0.4.0   | Row-context POST to soc-ai `/find-alert` to resolve the ES `_id` from rule.uuid + 5-tuple + timestamp (heuristic; superseded by 0.5.0). |
| 0.5.0   | Real ES `_id` resolution: `@run-at document-start` + fetch/XHR patch caches every `event.id` from `/api/events/`, keyed by row-visible fields. Expand-panel `soc_id` fallback. No more `/find-alert` from the userscript path — heuristic resolution was returning the wrong alert when rule.uuid had many matches. |
| 0.6.0   | Merged status-strip + verdict-card UI: status strip (live phase, elapsed timer, segmented progress bar, "now: <tool>"), verdict card with rationale-as-headline, compact one-line activity timeline (collapsible), footer KPIs + cumulative-tokens SVG sparkline + 64K context-window % meter. Header `debug` toggle swaps body for raw JSON dump. |
| 0.6.1   | Perf: instant click feedback (panel opens before resolve work runs), cheap MutationObserver filter (drop `querySelector` descent, add 2s periodic backstop), capped activity + debug panes at 200 rows each. Fixes 5s click-to-feedback latency and 3+s freeze on SO row un-expand. |
| 0.7.0   | Synth-first pipeline rendering: timeline now handles `enriched_alert_context`, `decision_template_match`, Phase-D `targeted_dispatch`/`targeted_tool_result`, and the post-synth validators (`citation_validation`, `citation_cap`, `template_ceiling`, `verdict_floor_rewrite`) — previously these went blank since the panel only knew the legacy investigator events. Error-recovery: a `triage_report` after an `error` (synth-first fail-open fallback) clears the stuck warning and shows the recovered verdict. |
| 0.7.1   | Render the `icmp_solicited_downgrade` event — shows when a true_positive was downgraded to false_positive because the alert was a solicited internal ICMP echo reply (benign ping), so the analyst sees why a scary-labelled BPFDoor-style alert was de-escalated. |
| 0.7.2   | Footer KPIs no longer stick at `🛠 0` / `📊 0` on synth-first runs: tokens now populate (the pipeline emits `usage` events again, which it had stopped doing) and the tools KPI reflects prefetch evidence-gathering (pivots + enriched indicators) since the synth fast path makes no agent tool calls. |
| 0.7.3   | First-run cert wall is now actionable: when the `/investigate` fetch throws (`TypeError: Failed to fetch` / `Load failed` / `NetworkError` — the untrusted self-signed cert), the panel hint now names the exact URL to visit and accept (`<soc-ai>/healthz`) instead of a generic "network/socket failure". |
| 0.7.4   | The footer `🛠 N tools` KPI is now clickable — it expands a breakdown of what actually ran: prefetch pivots (with per-pivot event counts), enriched indicators (with IOC-hit counts), any Phase-D dispatch, and legacy investigator tool calls. Makes the synth-first "tools" count (which is really evidence-gathering, not agent tool calls) legible at a glance. |
| 0.7.5   | #tools KPI count now equals the breakdown rows (was: sum of pivot events vs. per-field rows) |
| 0.8.0   | **API token support** — sends `Authorization: Bearer scai_…` on every soc-ai call so the script works against a deployment with `API_AUTH_REQUIRED=true`. Token is set via the new Tampermonkey menu commands "soc-ai: set API token" / "soc-ai: set server URL" (mint the token in the config console → API Tokens). Backward-compatible: no token → no header → works against open deployments. New `@grant GM_registerMenuCommand`. |
| 0.8.1   | Metadata only: `@namespace` points at the public repo URL. No behavior or `@match` change. |
| 0.8.2   | Metadata only: `@namespace` resolved to the real public repo (`github.com/nuk3s/soc-ai`). No behavior or `@match` change. |
