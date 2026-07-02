# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/) from 1.0 onward.

## [Unreleased]

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
