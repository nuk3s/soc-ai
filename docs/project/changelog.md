# Changelog

The full changelog lives in the repository, and GitHub renders it:

[:octicons-arrow-right-24: **CHANGELOG.md on GitHub**](https://github.com/nuk3s/soc-ai/blob/main/CHANGELOG.md)

The format is based on [Keep a Changelog](https://keepachangelog.com/), and the project
follows [Semantic Versioning](https://semver.org/) from 1.0 onward.

## Highlights

- **1.5.2**: The TLS release. A Caddy overlay terminates TLS in front of soc-ai and renews the
  certificate. On the direct path, soc-ai validates its certificate and shows it on the Config
  screen and in `soc-ai doctor`. It warns 30, 14 and 7 days before the certificate expires. `PROXY_TRUSTED_IPS`
  accepts CIDR blocks. See the [1.5.2 release notes](../releases/1.5.2.md).
- **1.5.1**: The review release. A review of the full repository produced 61 fixes. Each fix has
  a test that failed before the fix. The changes are in the evidence gates, the Oracle redaction,
  the egress guard, the pcap tool, the installer and the console. See the
  [1.5.1 release notes](../releases/1.5.1.md).
- **1.5.0**: The hunting release. soc-ai now looks for the attacks that raise no alert. An
  analytic finds a hit. Hits on one entity form a lead. A lead starts its own hunt. A hunt
  reaches a verdict. The Hunts page holds that pipeline. The Needs-you strip names what waits
  on you. The profile sweep runs in the app. An investigation is more accurate. Every write to
  a Security Onion 3.3 grid works again.
- **1.4.0**: The trust release. An analyst can check soc-ai's judgement. The eval scores the
  whole hunt journey and says which step broke. The journey is: plant an attack, hunt, promote,
  verdict. Synthetic runs are marked everywhere they appear. A verdict must rest on evidence the
  run retrieved. The release closes the deterministic half of the most serious finding of the
  1.3.2 audit.
- **1.3.2**: An adversarial security audit of the whole product, and the fixes it produced. The
  audit took four attacker positions: hostile telemetry, a rogue analyst, a stranger on the
  network, and a channel that carries data out. Every finding had a working reproduction before
  its fix.
- **1.3.1**: A critical dogfood of the 1.3 journey before the public release. It walked hunt,
  promote, investigate and draft on a live grid. It added correctness and performance passes.
- **1.3.0**: Three hunting capabilities that build on each other. A confirmed hunt finding becomes
  a full investigation. Behavioral-analytics tools show the findings worth confirming. A
  confirmed finding becomes a drafted detection that you review and export.
- **1.2.9**: The front-door release. The installer asks how you will reach a model. It redacts
  the cloud route by default. The doctor names each hidden trap and its fix. Config opens on a
  few day-one decisions. The full set is 109. An Operate hub gives the trust instruments one
  page that says what each proves.
- **1.2.8**: The degraded-grid release. It defines what soc-ai says when Security Onion is down,
  saturated, stalled or answering with half its shards. A blind sensor never reads as a calm
  network. The upgrade applies seven migrations.
- **1.2.7**: The lesser-model release. soc-ai adapts to the analyst backend behind the gateway
  by configuration and measurement, with no code change. Failed pipeline runs explain
  themselves.
- **1.2.6**: An About page shows the running version, the repo and license links, and a
  sidebar version line. Its GitHub update check is opt-in and off by default, so nothing
  leaves the box. The Config page is now a master-detail screen. It went from about 36
  screens to about 2. Settings search works on the page and in the command palette. An Apply
  bar names each staged change as a clickable chip. The identifier lists filter, page and
  bulk-edit.
- **1.2.5**: A visual refresh of the alert workspace. It added design-token theming and a
  filter bar that turns into bulk actions without shifting the table. It added toast
  notifications with a one-click clear, and freshness markers that flag a stalled poll. The
  release also holds a code-review remediation across the 1.2.x line and a batch of dogfood
  fixes. DNS-SD and SRV service records no longer pollute the auto-detected internal-domain
  inventory.
- **1.2.4**: A dogfood patch. The Hunt Console says when scheduled hunts are paused. The
  triage pipeline retries a transient grid error. Before, it dropped the investigation. The
  nightly regression alarm no longer pages on one flipped verdict at a small sample size. The
  config console groups the switch of each integration with its key.
- **1.2.3**: Per-alert verdict inheritance now respects the inherit window,
  `webui_inherit_window_days`. The alerts feed no longer puts the stale standing verdict of a
  rule on fresh alerts.
- **1.2.2**: A security and correctness patch from a full code review of 1.2.1. It covers
  evidence-gate integrity, Oracle redaction leaks, an opt-in and bounded auto-acknowledge, SSRF
  and denial-of-service caps, audit and auth hygiene, and supply-chain pinning.
- **1.2.1**: An accuracy patch. A pipeline error now records why each model retry failed. The
  schema accepts the stringified JSON that caused most of those failures. Hunts gained a
  telemetry-first scope. The corroboration gate credits Zeek evidence from broad queries, and a
  generic sweep no longer re-triages the alert stream. The release also refreshed the docs and
  published the roadmap.
- **1.2.0**: The dogfood release. A full analyst shift on the live deployment produced
  fourteen findings, and this release fixed all of them. It added notifications, entity
  search, a maintenance panel, and pipeline-error visibility with a one-click dismiss. It added
  group acknowledge and a deep re-run. The dashboard can schedule the verdict-quality eval.
- **1.1.1**: Re-hunt and multi-select on the Hunts page, and a hardening pass from a delta
  review.
- **1.1.0**: The measurement release. It added a nightly quality trend with a regression alarm
  and highlighted redaction previews. It added a runbooks workspace, so the agent grounds
  verdicts in your own procedures.
- **1.0.8**: Trust, workflow and hunting. A fallback verdict carries a label. A hunt finding
  must cite evidence. Assignment states and keyboard triage speed up the queue. Hunts gained a
  schedule.
- **1.0.7**: Fixes from the first week of production triage: SO write-token expiry, export
  auth, re-hunt caps, and CLI auth.
- **1.0.6**: The Tampermonkey userscript is retired. The console at `/app` and the Hunt
  Console now drive all of soc-ai.
- **1.0.5**: A patch. The auto-triage scheduler now fires its first sweep on a freshly booted
  host. The cause was a monotonic-clock sentinel bug. The CI workflow actions now run natively
  on Node 24.
- **1.0.4**: Slow-stack resilience and detection. Every long path has a wall-clock timeout,
  and a hunt or an investigation that hits it ends in a partial verdict. The release added a
  malware-label payload gate and a fast-path domain reputation. It added inventory-first hunts
  with correlation and lateral-movement recipes. It added a first-run "not connected" banner
  and an Acknowledge and Escalate bar on a settled verdict.
- **1.0.3**: Dogfood, detection and resilience. It added dataset-agnostic grid discovery, and
  behavioral-summary detections for beaconing and DNS tunneling. It added a docs site,
  operator runbooks, and a one-click "request more info" on any verdict. A sweep hardened
  resilience, performance and flow.
- **1.0.2**: Trust and reliability. The model reasoning is visible on every investigation.
  Decision-record exports are signed. Benign synthetic eval scenarios measure the precision
  and the true-negative rate. The gateway transport retries with backoff.
- **1.0.1**: The Hunt Console and a backtest harness. A full review of correctness, security
  and performance hardened the engine.
- **1.0.0**: The first public release: the triage engine and the always-on console.
