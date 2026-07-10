# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/) from 1.0 onward.

## [Unreleased]

### Added

- **A first-class Runbooks page** (`/app/runbooks`, in the sidebar): search,
  markdown editor with preview, tags and linked rules, multi-file `.md` import
  with lenient front-matter parsing, and embed-status chips when the semantic
  tier is on. Ships with a **starter pack of ten vendor-neutral SOC runbooks**
  (`runbooks/starter-pack/`) loadable in one click — idempotent, never
  overwrites your own. The old Config section is now a compact signpost.
- **Chat-transcript memory (context, never evidence).** When investigation
  memory is on, synthesis also recalls relevant excerpts from past analyst↔AI
  chats (investigation and hunt threads) via a new local full-text index.
  Excerpts are hard-framed as context only — user statements are labeled as
  unverified operator opinion on every line, transcript-grounded citations are
  rejected by the evidence gate, and excerpts ride the full egress-redaction
  path. New hot setting `memory_include_chat` (effective only with
  `memory_enabled`).
- **`soc-ai doctor`** — one command that checks the whole dependency surface
  in ~15 seconds: config, database + migration head, FTS5 availability,
  Security Onion and Elasticsearch auth vs reachability, gateway + configured
  models, the model-fitness probe, egress posture, and blocklist freshness —
  each with a concrete fix hint. `--json` for automation; the bug-report
  template asks for its output.
- **Published container image on GHCR.** Every `v*` tag now builds the
  Dockerfile (linux/amd64 + linux/arm64) and pushes
  `ghcr.io/nuk3s/soc-ai:{version}` + `:latest`, gated on the full CI suite
  passing first (`.github/workflows/release.yml`). `./setup.sh --prebuilt`
  (or `docker compose pull soc-ai && docker compose up -d`) runs the published
  image with no local build; `SOC_AI_IMAGE_TAG` pins a version. Plain
  `docker compose up`/`up --build` still builds from source, unchanged — note
  the compose image name is now `ghcr.io/nuk3s/soc-ai` (was `soc-ai:latest`),
  so the next `up` on an existing install rebuilds once under the new name.
- **Contributor surface.** A root `CONTRIBUTING.md` (dev setup, the exact CI
  gates, the browser-smoke how-to, and privacy-first scope guidance citing
  the safety model), structured GitHub issue forms (the bug form asks for
  `soc-ai doctor --json` output), and a PR checklist mirroring the CI gates.
- **Runbook retrieval upgraded to full-text search, with an optional semantic
  tier.** Runbook lookup (both the agent tool and the console) now uses SQLite
  FTS5/BM25 ranking — built into the SQLite already shipped, zero new
  dependencies, zero egress; installs whose SQLite lacks FTS5 fall back to the
  previous scorer transparently. For large corpora, a new "Retrieval (RAG)"
  config section can point `rag_embed_model` / `rag_rerank_model` at your
  OpenAI-compatible gateway (both off by default): embeddings are stored
  locally, retrieval blends keyword and semantic hits, and a "Re-embed
  runbooks" button (plus `POST /api/v1/config/rag/reembed`) refreshes the
  index. The egress-policy page lists the retrieval gateway as a destination
  when enabled.
- **Investigation memory (opt-in, off by default).** With `memory_enabled` on,
  verdict synthesis sees up to `memory_max_items` prior verdicts for similar
  alerts — matched deterministically (same rule + source/destination overlap,
  most-specific match first, `memory_window_days` window), no embeddings, no
  new services. Prior outcomes are explicitly framed as context, never
  evidence: they cannot be cited, fallback-produced verdicts are excluded, the
  block passes through the analyst egress guard, and a `prior_outcomes`
  timeline event records exactly what was recalled. Leave it off until you've
  evaluated anchoring effects on your own alert mix.
- **Analyst-path redaction preview.** The redaction preview panel gains an
  "Analyst path" tab: pick any past completed investigation and see exactly
  what a cloud analyst model would receive — the rebuilt synthesis prompt,
  original vs redacted under your current identifier config, with per-category
  redaction counts and an explicit banner when analyst redaction is currently
  off. Read-only, nothing is sent anywhere
  (`GET /api/v1/analyst/redaction-preview/{id}`).

- **Redaction previews highlight exactly what was redacted.** Both the Oracle
  sample and the Analyst path preview now mark every internal value (amber, in
  the original pane) and every opaque label (green, in the sanitized pane),
  with hover tooltips naming the counterpart and a per-category span count.
  The replacement pairs come from the sanitizer's own mapping, filtered to
  what the preview actually redacted — never the whole identifier config.

### Changed

- **RAG model settings are dropdowns** fed by your gateway's model list, with
  an explicit "(off)" and an "Other…" escape hatch for unlisted ids.
- **Config page section navigation snaps instantly** instead of a slow smooth
  scroll.
- **Hunt template affordance reads positively**: templates your grid can run
  are highlighted; ones needing missing telemetry keep their flag (wording
  inverted from "dimmed").
- **Machine-generated hunt titles stay short**: the agent is instructed to
  keep finding/chart titles to ~8 words, a deterministic 90-character clamp
  backstops it, and the hunt page wraps to two lines before ellipsizing.
- **The app loads faster**: route-level code splitting cut the initial
  JavaScript bundle from ~1 MB to ~214 kB; screens load on first visit.
- **Banner wording corrected** to match the safety model: "can run on
  self-hosted models" and "nothing leaves your network without your consent".
- **The demo dataset exercises every headline feature** (failed retries,
  pipeline-fallback chips, hunt diffs, redaction preview with highlighting,
  runbooks, assignment states, memory recalls) and the README screenshots are
  regenerated from it.

### Fixed

- **An open tab now survives a redeploy.** Previously a deploy replaced the
  app's content-hashed chunks and an already-open tab could go blank on its
  next navigation (stale chunk → 404 → the whole page unmounted) until a hard
  refresh. Now: a failed chunk load auto-reloads the page exactly once (never
  loops), an error card inside the still-mounted shell backstops anything
  else, `index.html` is served `no-cache`, and the app checks for a newer
  build every minute (and on focus) — showing a "soc-ai was updated — reload
  for the latest" banner instead of silently running old code.
- **The browser E2E now actually runs in CI.** The `browser-smoke` GitHub
  Actions job referenced tests that were excluded from the public repository,
  so it failed on every run. The Playwright smoke and the demo-stack harness
  it drives now ship publicly (all demo data is RFC 5737 TEST-NET fiction).
- **Alerts-queue layout fixes** from a full visual audit: action buttons no
  longer overlap the "last seen" column on assigned rows, the assignment
  state chip no longer clips ("OWN…"), the severity tag no longer touches the
  source IP, and the destination port is no longer printed twice — which also
  fixes the source/destination entity pivots, which previously navigated to a
  port-suffixed value the entity page could not match.
- **The analyst redaction preview's "events missing" state no longer logs a
  browser console error** — it is a normal 200 response with a status field
  instead of an HTTP 409, and the panel shows the server's explanation for
  both non-previewable states.

## [1.0.8] - 2026-07-07

Trust, workflow, and threat-hunting release. This one is about honesty (the UI
now tells you when a verdict came from the fallback, not the model, and when a
hunt finding isn't backed by evidence), analyst throughput (assignment states,
keyboard triage, bulk transparency), a much deeper Hunt Console (scheduling,
templates, charts, run-to-run diffing, per-entity pages), and a hardened,
inspectable egress boundary (fail-closed redaction + a policy page).

### Added

- **Model-fitness check on the config page.** A probe reports whether the
  configured analyst model and context window are actually large enough for
  reliable triage, surfaced as a config chip — so an under-provisioned model is
  caught up front instead of showing up as silently poor verdicts.
- **Assignment / triage states for alerts.** An analyst can take ownership of an
  alert and move it through owned → in-review → done. Every state change is
  audited, so a shift handoff shows who has what and where it stands.
- **Keyboard-driven triage on the Alerts screen.** `j`/`k` to move, `o` to open,
  `a` to ack, `e` to escalate, `i` to investigate, `x` to select, and `?` for
  the shortcut cheatsheet — full-speed keyboard triage without leaving the list.
- **Opt-in notification webhooks** (`webui_notifications`, off by default). When
  enabled, soc-ai can POST a notification to a secret webhook URL on the events
  you choose; with the feature off there is zero outbound traffic. Useful for
  wiring triage events into chat/on-call without adding a cloud dependency.
- **Scheduled hunts.** A hunt objective can run on a recurring schedule
  (`hunt_schedules_enabled`) instead of only on demand, so recurring threat
  hunts run themselves and land in the console for review.
- **Hunt template library.** A curated set of starter hunt objectives you can
  launch with one click, so common hunts don't have to be re-typed from scratch.
- **Run-to-run hunt diffing.** A completed hunt is automatically diffed against
  the previous completed run of the same objective — new, resolved, and
  persisting findings are called out, so you see what *changed* since last time.
- **Charts in hunt reports.** The hunt agent can render charts from its
  findings, and each chart must cite the evidence behind it (uncited, empty, or
  runaway charts are dropped) — visual summaries you can still trace to data.
- **Per-entity pages.** `/app/entity/<host-or-ip-or-user>` gives every entity a
  single page aggregating the hunt findings that name it, so you can pivot from
  a name to everything the system has seen about it.
- **Feedback distillation for detection tuning.** Analyst overrides roll up
  per-rule into suggestions for which detections are noisy or miscalibrated.
  Nothing is auto-applied — a rule that has ever produced a true positive is
  never suggested for suppression — it's decision support, not an auto-action.
- **Egress-policy page.** A config page that shows exactly what categories of
  data can leave the box under the current settings, plus best-effort 7-day
  egress counts, so the trust boundary is inspectable instead of implied.
- **Cloud egress sanitizer for the analyst model** (`analyst_cloud_redaction`,
  opt-in, off by default). For deployments that point `analyst_model` at a
  cloud provider: every payload sent to the analyst model — enriched alert
  context, prompts (investigation, hunt, chat), and all tool results — has
  internal IPs/hostnames/usernames replaced with stable opaque labels
  (`IP_01`, `HOST_02`, …) using the same reversible redaction tunnel as the
  Oracle path; model outputs (verdicts, rationales, reasoning traces, hunt
  reports, chat replies) are label-restored before storage/display, and tool
  arguments coming from the model are restored before hitting Elasticsearch so
  the agent loop keeps working. Costs some verdict quality (the model reasons
  over opaque labels). See `docs/SAFETY_MODEL.md` → "Cloud analyst models".

### Changed

- **Fallback verdicts are now labelled as fallbacks.** When the deterministic
  pipeline (not the LLM) produces a verdict — because the model was unavailable
  or failed a gate — that verdict carries an explicit `pipeline_fallback`
  marker, gets its own chip and filter in the UI, and is excluded from the
  model-accuracy KPI. You can always tell whether a call was the model's or the
  fallback's, and the accuracy number reflects only the model.
- **Alerts show their last triage attempt.** Each alert badge now surfaces the
  most recent attempt (including reruns), so a rerun is visible rather than
  silently overwriting the prior result.
- **Bulk actions explain what they skipped.** Bulk rehunt and the auto-triage
  sweep now report per-item skip reasons instead of silently passing over
  alerts, so a bulk run is auditable at a glance.
- **Hunt findings must cite evidence.** A finding (or chart) that doesn't cite
  real supporting evidence is dropped by a citation gate rather than rendered —
  the console shows substantiated findings only.
- **Auto-acknowledge of high-confidence false positives is now ON by default**
  (`auto_ack_fp_enabled`). Both gates are unchanged — the confidence threshold
  (default 0.7) and the high-stakes guard (critical/high-severity or
  malware/exploit-class alerts are never auto-acked) — and every unattended ack
  is audited. Set `auto_ack_fp_enabled` to false (env or config console) to
  require a human click for every acknowledgement. Existing installs with a
  saved config-console override keep their setting.
- **Inherited verdicts now acknowledge their alerts.** An auto-triage sweep
  that skips a cluster because it inherits a qualifying false-positive verdict
  (same rule + source + destination within the inherit window) now acks those
  events in Security Onion. Previously the inherited verdict was display-only
  and the alerts lingered unacked forever.

### Security

- **Analyst-model redaction now fails closed.** Before any payload is sent to a
  cloud analyst model, the composed string is re-scanned for un-redacted
  internal identifiers; if residue is found, the request is blocked
  (`egress_blocked` audit event) and the deterministic fallback verdict is used
  instead of leaking. Redaction is no longer best-effort — a redaction miss
  stops the egress rather than letting it through.

### Fixed

- **The same flow is no longer investigated twice minutes apart.** The sweep
  planner now sees pairs with an in-flight investigation — the pair-verdict
  check is complete-only by design, so a newer event id in the same cluster
  used to launch a duplicate investigation while the first run was still
  executing (most visible with a short `webui_inherit_window_days`).

### Removed

- **The dead approval-gate machinery.** `POST /approve` (both the legacy
  prefix-less route and `/api/v1/approve`), the in-memory `ApprovalGate`
  (plus `GET /sessions/{id}`, which only listed its pending tokens), the
  `pending_approvals` field on `/healthz`, and the `socai_pending_approvals`
  metric are gone. Nothing could create a pending approval since the
  synth-first pipeline landed — the agent recommends write actions in the
  report and the analyst executes them through the actions API
  (`POST /api/v1/investigations/{id}/actions/{index}/execute`), which remains
  the single audited write path (`execute_write_tool`). Historical
  `approval_request`/`approval_required` events still render in old
  investigation timelines, permanently non-actionable.

## [1.0.7] - 2026-07-04

### Fixed

- **Acknowledge / escalate writes to Security Onion no longer fail after ~10
  minutes.** SO 3.0 expires its CSRF (srv) token 600 seconds after login and
  signals an expired token with a `400`, which the previous 401-only refresh
  never caught, so any write more than ten minutes after login (and every
  unattended auto-ack) failed. The token is now refreshed proactively and on a
  `400`, so ack, escalate-to-case, and auto-ack work for the life of the session.
- **Investigation timeline reads cleanly.** Tool-call rows show a short, plain
  title (`Host summary: 10.0.0.5 — 699 events`) instead of raw JSON; a disabled
  online lookup shows a neutral `skipped` line rather than a configuration notice;
  write actions group under Decision, not Tool calls; the full result stays in the
  row's expander.
- **The "Model reasoning" panel now appears on every investigation**, not only the
  ones that ran the deep investigation loop.
- **Source → destination no longer truncates** on the investigation view or the
  investigations list.
- **The acknowledge action reflects an alert that was already acknowledged**
  (elsewhere, or by an earlier run), and advisory-action executions are persisted
  so a reload never re-offers an escalate that already opened a case.
- **The hunt agent writes valid OQL** — the primer and parser errors now state the
  exact supported pipe stages (`groupby`, `sortby`, `head`, `count`) and that there
  is no `fields`/projection stage, ending a class of parse failures.
- Comma-separated environment values for the Oracle privacy gate and
  `PROXY_TRUSTED_IPS` load correctly instead of failing settings validation at
  startup.
- Phase-D targeted evidence tools (the Elasticsearch-query family) no longer fail
  to dispatch; several evidence-gate and audit events that were being dropped are
  now recorded.
- `X-Forwarded-Proto` is trusted only from a proxy listed in `PROXY_TRUSTED_IPS`,
  matching the existing `X-Forwarded-For` rule, so a client cannot forge the
  `Secure` cookie flag.
- A batch of web-console correctness fixes: idle polling no longer freezes the live
  views, terminal statuses render correctly, and a duplicate-key warning in the
  API-token list is gone.

### Added

- **Self-consistency vote on the final verdict**, off by default
  (`VERDICT_CONSISTENCY_SAMPLES=1`). Set it to 2–5 to run the final synthesis
  several times and majority-vote; a split lands the new `inconclusive` verdict.
- **CLI authentication:** `soc-ai triage` / `healthz` accept `--token` (or
  `SOC_AI_API_TOKEN`) and a `--verify` / `--cafile` TLS option, so the CLI works
  against the shipped secure default.
- A documentation-accuracy check in CI that keeps the agent-tools reference and the
  audit-event list in sync with the code.
- The online-enrichment tools (Shodan, GreyNoise, CVE lookup) register only when
  `ALLOW_ONLINE_ENRICHMENT` is on, so the agent never spends a tool call on a
  disabled lookup.

### Security

- Dependency updates clearing known CVEs: starlette, python-multipart, pyjwt,
  aiohttp, cryptography, idna, joserfc, and pydantic-ai.

### Changed

- The web API implementation was reorganised into a package of route modules
  (internal refactor; every endpoint path and response is unchanged).
- Documentation pass across the README and guides for clarity, and the console
  screenshots were regenerated against the current UI.

## [1.0.6] - 2026-07-03

### Removed

- **Retired the Tampermonkey userscript** ("Hunt with AI" in the Security Onion
  alerts view). soc-ai is now driven entirely from its own web console at `/app`
  (open a detection and **Investigate**, or sweep the queue with auto-triage) and
  the Hunt Console — no browser extension to install or keep updated. The API's
  cross-origin (CORS) support remains, config-gated and off by default, for
  programmatic clients and integrations. Existing userscript installs keep calling
  the API until you remove them; nothing server-side changed.

## [1.0.5] - 2026-07-03

Patch: a scheduler fresh-boot fix and green public CI.

### Fixed

- **Auto-triage scheduler fires its first sweep on a freshly-booted host.** The
  "last swept" marker used a `0.0` sentinel compared against `time.monotonic()`,
  whose epoch is arbitrary and near-zero right after boot — so on a fresh host the
  first enabled wake read as "just swept" and skipped the sweep for up to one
  interval. It now uses a `None` sentinel, so the first enabled wake always fires.
  (Also fixes a CI test that was green only on long-uptime machines.)

### CI

- Workflows updated to Node 24-native action versions (`actions/checkout@v6`,
  `actions/setup-python@v6`, `actions/setup-node@v6`,
  `actions/upload-pages-artifact@v4`), clearing the Node 20 deprecation warnings.

## [1.0.4] - 2026-07-03

Slow-stack resilience + detection release: bounded timeouts everywhere, a
malware-label payload gate, stronger hunts, and a settled-verdict action bar.

### Added

- **Wall-clock timeouts for a slow stack.** Dedicated, tunable knobs bound every
  long-running path so a slow gateway degrades gracefully instead of hanging:
  `hunt_run_timeout_s` (a hung hunt concludes with a grounded PARTIAL report, not
  an error), `hunt_chat_turn_timeout_s`, `investigation_run_timeout_s`, and a
  per-turn `investigation_turn_timeout_s` on every primary investigator/synthesizer
  model call (a hung turn concludes with the round-1 verdict from evidence already
  gathered).
- **Stronger hunts.** The hunt agent now plans inventory-first (uses only datasets
  that actually exist), reasons about correlation patterns (kill-chain sequencing,
  cross-host attacker-indicator fan-out, beacon/DNS-tunnel decisiveness), and ships
  prominent lateral-movement + behavioral OQL recipes (Kerberoasting, PsExec,
  completed-SSH, RITA beacon / DNS-tunnel summaries).
- **First-run "not connected" banner.** The Dashboard shows a clear banner when
  Security Onion / the model gateway is unreachable, instead of silently-empty lists.
- **Settled-verdict action bar.** A completed investigation always offers
  Acknowledge / Escalate even when the agent recommended no actions, backed by a
  new `POST /alerts/escalate-group` endpoint (same auth/CSRF as ack-group).
- **Reliability metrics.** `investigation_fallback_verdicts_total` and
  `investigation_zero_tool_verdicts_total` in `/metrics` — early warning for
  fallback-verdict rate and QVOD-style zero-tool escalations.

### Changed / Fixed

- **Malware-label payload gate.** A `true_positive` on a malware-signalling rule
  name is coerced to `needs_more_info` (→ investigated) unless corroborated by a
  concrete IOC hit or a cited decisive typed pivot value (JA3/hash/SPN/RPC) — the
  rule label alone is not corroboration (the BPFDoor false-escalation pattern). The
  solicited-ICMP defense and real tool-evidence still stand.
- **Fast-path reputation for domains.** The cheap fast-path now reputation-gates an
  external destination *domain* (SNI/Host/DNS, port-stripped), not just external
  IPs — an unknown or blocklisted domain forces the full investigation.
- **Sharper citations.** A citation resolves semantically only on a distinctive
  token (stop-word filtered, length/word-boundary checked), so a verdict can't
  "cite" the bundle by echoing a generic word — while short domains/IPs still
  resolve.

## [1.0.3] - 2026-07-03

Dogfood + detection + resilience release: 11 dogfood fixes from live use, a docs
site, operator runbooks, and one-click "request more info", plus dataset-agnostic
grid discovery, behavioral-summary detections (beaconing + DNS tunneling), and a
sweep of resilience / effectiveness / performance / flow hardening (from
autonomous sessions).

### Added

- **The agent discovers what's in your Elastic.** Dataset-agnostic grid
  inventory (ambient, TTL-cached) plus on-demand `describe_dataset` /
  `field_values` tools, so hunts and chat reason over whatever datasets a
  deployment actually ships — not a hardcoded Zeek list. Network-only today,
  host-log ready.
- **Behavioral-summary detections.** When the deployment surfaces a derived
  connection/DNS summary (e.g. RITA-style beacon scoring or a DNS-tunnel
  aggregate), the agent reads it as decisive evidence: a periodic beacon profile
  (regular timing + constant payloads) or a high-entropy, TXT/NULL-dominant DNS
  channel is now a `true_positive` on its own, even behind an ET HUNTING /
  Informational alert. These per-host rollups carry only `source.ip` (not a
  `community_id` or `host.name`), so a dedicated IP-keyed prefetch pivot fetches
  them alongside the five typed pivots — otherwise the decisive signal never
  reaches the agent. Verified on the synth eval: a Cobalt Strike beacon that read
  as a false positive on the alert alone now escalates once the beacon profile is
  in context.

- **Operator runbooks.** A local runbook store (Config → Runbooks) the triage
  agent can cite: the `lookup_runbook` tool searches your own guidance
  (rule-link > tag > keyword) and grounds verdicts in it. Purely local — never
  written to Security Onion.
- **One-click "request more info."** A `needs_more_info` investigation can be
  re-launched with its open questions threaded in as a focus hint, so the fresh
  run targets the gaps instead of re-deriving from scratch.
- **Chat about a hunt.** Hunts now have the same follow-up chat thread as
  investigations (read-only — a hunt chat never acks or escalates).
- **Canned hunts.** Six one-to-three-click preset hunts for routine, high-payoff
  sweeps (beaconing, new-external-service, rare-process, etc.).
- **Documentation site.** A Material for MkDocs site (quickstart, config, hunts,
  backtest, security posture) published via GitHub Pages.
- **Delete hunts** from the Hunt Console.

### Changed / Fixed

- **Internal-identifier discovery no longer over-claims.** A single-label suffix
  is treated as internal only if it is not a public TLD (fixes "the entire `.com`
  is internal"), and per-device Windows mDNS `<guid>.local` names are dropped
  instead of flooding the identifier list.
- **Auto-ack of false positives now leaves an audit trail** and its coupling to
  investigation completion is documented (a benign FP is acked when the
  investigation that judged it completes, not on a separate schedule).
- **Timezone-correct "when."** Investigation/hunt/runbook timestamps serialize
  with an explicit UTC offset, fixing the "a 1-hour-old run shows 8h ago" skew
  (the browser was parsing naive UTC as local time).
- **Inheritance is legible.** An inherited verdict shows which investigation it
  came from and when; re-running an investigation now correctly clears the
  "inherited" pill on that alert.
- **Alerts grid** uses the space between IPs and verdict for timestamps, a
  copyable short alert-id, and a "fired N×" count.
- **Config apply is explicit.** A sticky "Apply changes (N)" bar with dirty-state
  tracking replaces the ambiguous auto-apply.
- **Hunt UI** brought to parity with investigations (collapsible sections,
  confidence ring, consistent panels).
- **Hardening (self-review):** runbook content + list fields are size-bounded and
  the runbook search working-set is capped; a second hunt-chat turn is rejected
  while one is still pending (no orphaned pending rows).
- **Auto-triage can't be stalled by a hung run.** Each investigation in a sweep
  is bounded by a wall-clock backstop (`auto_triage_per_target_timeout_s`); a
  hung LLM stream is now counted as a failure and the sweep moves on instead of
  wedging behind it.
- **Oracle retries use full jitter.** The second-opinion path's backoff is now a
  randomized draw (matching the primary transport), so many concurrent
  investigations don't retry in lockstep and re-hammer the gateway as it recovers.
- **Confidence floor is stricter.** The "grounded catch" confidence floor now
  fires only on a cited decisive pivot *value* (a JA3/hash/SPN/…), not the mere
  presence of a correlated pivot id — a raise has to be earned by real signal.
- **Recall: decisive Zeek evidence surfaces.** SSH logins, low-and-slow exfil
  duration, Kerberos/SMB/DCE-RPC lateral chains, and the beacon/DNS aggregates
  above are extracted and cited rather than silently dropped before the agent
  sees them.
- **Follow-ups on any verdict.** Residual open questions (and the focused
  "request more info" action) now show on `true_positive` / `false_positive`
  investigations too, not only `needs_more_info`.
- **Faster bulk re-investigate.** The re-hunt endpoint fetches all target
  investigations in one query instead of one round-trip per id (was an N+1).
- **Quieter UI.** The Investigations re-investigate/delete status line
  auto-dismisses; idle screens stop polling at terminal state.

## [1.0.2] - 2026-07-02

Trust + reliability release: make the pipeline resilient and the trust story
provable (from an autonomous review + direction-brainstorm session).

### Added

- **Model reasoning visible on every investigation.** A collapsible "Model
  reasoning" panel surfaces the agent's per-turn `<think>` traces (previously
  captured but dropped by the timeline) — the "show your work" explainability an
  analyst needs to defend a verdict.
- **Signed decision-record exports.** The audit export now carries a real Ed25519
  detached signature + public key (verifiable by an external auditor with the
  public key alone), alongside the existing sha256 checksum. New
  `GET /decision-record/public-key`.
- **Benign synthetic eval scenarios + escalation precision.** The synth catalogue
  gained a benign (false-positive) class, so the eval now reports precision and a
  true-negative rate — answering the "does it call obvious FPs malicious?" test,
  not just recall.

### Changed / Fixed

- **Resilient LLM gateway transport.** The primary model path (investigator /
  synthesizer / hunt / chat) now retries transient gateway failures (429/502/503/
  504 + connection/read/timeout) with jittered exponential backoff, honoring
  Retry-After — parity with the Oracle path. Bursty gateway 502s previously
  errored investigations, hunts, and eval batches outright.

## [1.0.1] - 2026-07-01

Highlights: the **Hunt Console** and a **backtest harness** land, and a full
correctness / security / performance review hardened the engine.

### Security

- **`web_search` refuses all internal identifiers, not just RFC1918 IPv4.** A
  shared internal-identifier guard (also used by `crawl_page` and online
  enrichment) now blocks internal FQDNs, known internal hostnames, IPv6, and every
  non-globally-routable IP class (CGNAT, benchmark, loopback, link-local) from
  reaching public search engines.
- **API tokens are bound to their creator's account** — disabling the operator who
  minted a token now rejects that token, matching session auth.
- HSTS is emitted behind a TLS-terminating reverse proxy (honors
  `X-Forwarded-Proto`); the login throttle and rate limiter are proxy-aware via an
  opt-in `PROXY_TRUSTED_IPS`; chat input is length-capped; the Oracle
  redaction-preview endpoint is admin-gated; the decision-record export is
  described honestly as an integrity checksum (not a signature).

### Fixed

- **Hard evidence gate restored.** The zero-tool-verdict gate was silently
  defeated by a part-type miscount (the model's own text/reasoning counted as
  "tool evidence"); it now counts only real tool results, so an ungrounded
  true/false-positive correctly falls back to `needs_more_info`.
- **Investigations and hunts conclude gracefully at their budget** instead of
  erroring with no result — a hunt that reaches its exploration budget now
  synthesizes a grounded partial report.
- Background worker tasks are cancelled on shutdown (no use-after-close on the ES
  or DB clients); several unbounded per-rule queries are now bounded; MaxMind
  lookups no longer block the event loop; the web console stops polling once a
  hunt/backtest is idle and no longer races stale responses.

### Added

- **Hunt Console — estate-wide, objective-driven hunting.** Give it a hunting
  objective in plain English and it turns the same read-only agent loose across
  many hosts and a time window, then reports **findings + a narrative** mapped to
  MITRE ATT&CK — rather than a single-alert verdict. Read-only (no acks, no case
  edits), runs on a bounded budget, and lands a grounded partial report if cut
  short.
- **Backtest harness — "prove it on my last N days."** Samples your already-
  dispositioned Security Onion alerts, replays soc-ai's triage against them, and
  scores agreement, false-positive-toil cleared, and a prominent **missed true
  positives** count — so you can measure the assistant before you trust it.
- **In-UI admin config console** — Oracle toggle, data sources, agent tools, API
  tokens, detection tuning, and the Oracle **redaction preview**, applied without
  a restart where possible.
- **Internal-identifier discovery + management.** soc-ai now learns a
  deployment's internal identifiers from its own Security Onion data instead of
  assuming them. A new admin **Internal identifiers** config section manages
  internal domain **suffixes**, bare internal **hostnames**, and internal
  **subnets (CIDRs)** as a single list of detected / manual / muted / always-on
  entries with provenance (host + event counts, last-seen). A background
  discovery job (a config-console **schedule toggle** (in-process scheduler)
  plus the `discover-internal-identifiers` CLI and a **"Scan now"** button)
  infers candidates from
  Elasticsearch: domain suffixes and hostnames tied to internal hosts, and
  RFC1918 subnets seen in traffic but not yet in `internal_cidrs`.
  - High-confidence internal domain/host identifiers are activated automatically
    (the fail-safe direction for egress redaction is to over-redact); a **public
    registrable domain is never auto-activated** (suggestion only). **CIDRs are
    suggest-first** — discovered subnets are always muted suggestions, because a
    CIDR is two-directional and changes triage classification; the operator
    un-mutes to activate.
  - The merged effective set (env/reserved config ∪ active − muted) feeds the
    Oracle egress sanitizer (suffixes/hosts) and the internal-vs-external IP
    classification (CIDRs, applied consistently across triage downgrades and
    Phase-A enrichment). Reserved special-use suffixes (`.lan/.local/.internal/
    .corp`) are always redacted and cannot be muted away (defense-in-depth);
    behavior is unchanged for deployments with no managed entries.
- **Config console surfacing.** Non-secret operational settings that were
  previously env-only (model/index/alerts-query patterns, agent tuning, the new
  discovery knobs) are now visible and editable in the admin config console with
  a source badge and hot-apply/restart indicator. Secrets remain set/unset-only.

### Fixed

- Removed a hardcoded lab-specific internal domain from the eval sanitizer's
  default suffix list — it was redundant (`.lan` already covers it) and a
  developer-environment leak. Internal domains are now discovered/configured per
  deployment rather than assumed.

## [1.0.0] - 2026-06-23

The first public release. Highlights:

### Added

- **React web UI (`/app`)** — a single-page console for the full triage loop:
  alerts grouped by detection, an investigation drawer + permalink with a live
  timeline, entity graph, host context, recommended actions, and a scoped chat.
  Served directly by the backend.
- **Agentic investigation loop** — the agent investigates with read tools
  (event/Zeek search, IP/domain/hash enrichment, PCAP fetch + decode, playbooks,
  cases, web search) and synthesizes an evidence-cited verdict; a human approval
  gate guards every write action.
- **Oracle second opinion** — optional escalation to a stronger cloud model with
  field-aware egress sanitization.
- **Config console** — admin settings (hot-applied), user + API-token
  management, and a Fernet-encrypted secrets Danger Zone.
- **Upstream health indicator** — live ES / LLM / PCAP status, including a
  detector that flags a broken sensor-PCAP user and points to the fix.
- **Tampermonkey userscript** — "Hunt with AI" from inside the SO web UI.
- **Docker** — multi-stage image (builds the SPA) + compose for `docker compose up`.

### Security

- API auth (session cookie or bearer token), CORS scoped to the SO host, OQL
  field-whitelist validation, and secret-safe logging/rendering throughout.
- **Oracle egress redaction — free-text credential usernames.** Usernames that
  appear only in a free-text field in an explicit credential context
  (`user=jdoe`, `username: svc-bak`, `DOMAIN\jdoe`) are now tokenised before the
  payload is sent to the cloud second-opinion model; previously such a name
  could egress verbatim. Universal built-in accounts and public emails are left
  intact. The independent residue gate gained a matching check and fails closed
  on any miss. The client now warns once when the Oracle is enabled but no
  organization-specific internal names are configured, and
  `oracle_internal_suffixes` is threaded from the active settings so a runtime
  override is honored. Credential usernames are redacted in place only (not
  globally propagated) so a free-text match cannot corrupt a public IOC.
- **Oracle redaction — ReDoS hardening.** The suffix-FQDN and email redaction
  patterns had unbounded quantifiers that could backtrack catastrophically on a
  long hyphenated run in attacker-controlled free text (e.g. `payload_printable`).
  Quantifiers are now bounded to DNS/RFC length limits — multi-second worst case
  reduced to milliseconds, with no change to matching for valid hostnames/emails.
- **Security-audit hardening pass.** A full audit (no critical findings — the
  human-approval gate is unbypassable by the agent, OQL→Elasticsearch is
  injection-proof, and the SSH/PCAP path is argument-injection-safe) drove a
  round of edge hardening:
  - **SSRF**: the `crawl_page` host guard now resolves DNS and checks every
    resolved address against private/loopback/link-local/reserved ranges, not
    just the hostname string (closing the resolve-to-internal and octal/hex-IP
    bypasses).
  - **ReDoS**: bounded the quantifiers in the eval-path sanitizer (the prod
    Oracle path was already bounded).
  - **MISP over TLS** is now verified by default (`MISP_VERIFY_SSL`, optional CA
    bundle) instead of hardcoded-insecure.
  - **Tamper-evident audit log**: records are hash-chained (`seq`/`prev_hash`/
    `hash`) with a verify path; SO-mutating writes fail **closed** when the audit
    write fails (`AUDIT_FAIL_CLOSED`, default on); the approver identity is
    resolved and recorded; redaction defaults on and covers soc-ai's own secret
    shapes (`scai_`, bearer, session token, `password=`).
  - **CSRF**: cookie-authenticated state-changing requests now require a
    same-origin (or allowlisted) `Origin`/`Referer`; bearer-token (userscript)
    requests are exempt.
  - **Login throttle** (per-IP/username lockout), **security response headers**
    (nosniff / DENY / no-referrer / HSTS), **CORS fails closed** when
    unconfigured, **leading-wildcard OQL** is rejected (grid-DoS guard),
    **SSH known-hosts** persist (key-swap detection), and auto-ack of false
    positives is **capped** to low-stakes alerts (a prompt-injected verdict can
    no longer auto-acknowledge a malware/exploit/high-severity alert).

[Unreleased]: https://github.com/nuk3s/soc-ai/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/nuk3s/soc-ai/releases/tag/v1.0.0
