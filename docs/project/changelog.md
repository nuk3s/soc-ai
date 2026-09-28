# Changelog

The full, versioned changelog is maintained in the repository and rendered on GitHub:

[:octicons-arrow-right-24: **CHANGELOG.md on GitHub**](https://github.com/nuk3s/soc-ai/blob/main/CHANGELOG.md)

The format is based on [Keep a Changelog](https://keepachangelog.com/), and the project
follows [Semantic Versioning](https://semver.org/) from 1.0 onward.

## Recent highlights

- **1.5.0** — The hunting release: soc-ai now looks for the attacks that raise no alert. An
  analytic finds a hit, hits on one entity form a lead, a lead starts its own hunt, and a hunt
  reaches a verdict; the Hunts page holds that pipeline and the Needs-you strip names what waits
  on you. The profile sweep runs in the app, an investigation is more accurate, and every write to
  a Security Onion 3.3 grid works again.
- **1.4.0** — The trust release: whether soc-ai's judgement can be checked rather than taken on
  faith. The whole hunt journey (plant an attack, hunt, promote, verdict) is scored and says which
  step broke, synthetic runs are unmistakable everywhere they appear, a verdict must rest on
  evidence the run retrieved, and the deterministic half of the 1.3.2 audit's most serious
  finding is closed.
- **1.3.2** — An adversarial security audit of the whole product and the fixes it earned, from
  four attacker positions: hostile telemetry, a rogue analyst, a stranger on the network, and
  anything that could carry data out of the building. Every finding came with a working
  reproduction before it was fixed.
- **1.3.1** — A critical dogfood of the 1.3 journey before it went public: a live walk of
  hunt → promote → investigate → draft, plus correctness and performance passes.
- **1.3.0** — Three hunting capabilities that compound: a confirmed hunt finding becomes a
  first-class investigation, behavioral-analytics tools surface the findings worth confirming,
  and a confirmed finding becomes a drafted detection you review and export.
- **1.2.9** — The front-door release: the installer asks how you will reach a model and redacts
  the cloud route by default, the doctor names each silent trap with its fix attached, Config
  opens on a handful of day-one decisions instead of 109, and an Operate hub gives the trust
  instruments one page that says what each proves.
- **1.2.8** — The degraded-grid release: what soc-ai says when Security Onion is down, saturated,
  stalled or answering with half its shards is engineered so that a blind sensor is never reported
  as a calm network. Seven migrations, applied automatically on upgrade.
- **1.2.7** — The lesser-model release: soc-ai adapts to whatever analyst backend sits behind the
  gateway by configuration and measurement instead of code changes, and failed pipeline runs
  explain themselves.
- **1.2.6** — About page (running version, repo/license links, sidebar version line) with an opt-in, off-by-default GitHub update check that follows the zero-egress discipline; Config page rebuilt master-detail (~36 screens → ~2) with settings search in-page and in the command palette, an Apply bar that names each staged change as a clickable chip, and identifier lists that filter, page, and bulk-edit.
- **1.2.5** — Visual refresh of the alert workspace (design-token theming, a filter bar that morphs into bulk actions instead of shifting the table, toast notifications with a one-click clear, and freshness markers that flag a stalled poll), a code-review remediation across the 1.2.x line, and a batch of dogfood fixes. Also stops DNS-SD/SRV service records from polluting the auto-detected internal-domain inventory.
- **1.2.4** — Dogfood patch: the Hunt Console says plainly when scheduled hunts are paused, the triage pipeline retries a transient grid blip instead of dropping the investigation, the nightly regression alarm no longer pages on one flipped verdict at small sample sizes, and the config console groups each integration's switch with its key.
- **1.2.3** — Per-alert verdict inheritance now respects the configured inherit window (webui_inherit_window_days): the alerts feed no longer inherits a rule's stale standing verdict onto fresh alerts.
- **1.2.2** — Security and correctness patch from a full code review of 1.2.1: evidence-gate integrity, oracle-redaction leak fixes, opt-in/bound auto-acknowledge, SSRF and denial-of-service caps, audit and auth hygiene, and supply-chain pinning.
- **1.2.1** — Accuracy and honesty patch: pipeline errors now record *why* each
  model retry failed (and the schema tolerates the stringified-JSON wobble that
  caused most of them), hunts gained telemetry-first latitude (the corroboration
  gate credits Zeek evidence found through broad queries, and generic sweeps no
  longer re-triage the alert stream), plus a documentation refresh and the
  public roadmap.
- **1.2.0** — The dogfood release: a full analyst shift on the live deployment
  produced fourteen findings, and this release fixed all of them — notifications,
  entity search, a maintenance panel, pipeline-error visibility with one-click
  dismiss, group acknowledge, deep re-run, and the verdict-quality eval now
  schedulable straight from the dashboard.
- **1.1.1** — Re-hunt and multi-select on the Hunts page, plus a delta-review
  hardening pass.
- **1.1.0** — The measurement release: nightly quality trend with a regression
  alarm, highlighted redaction previews, and a real runbooks workspace so the
  agent grounds verdicts in your own procedures.
- **1.0.8** — Trust, workflow, and threat-hunting: fallback verdicts are labeled
  as such, hunt findings must cite evidence, assignment states and keyboard
  triage speed up the queue, and hunts gain scheduling.
- **1.0.7** — Fixes from the first week of production triage: SO write-token
  expiry, export auth, re-hunt caps, and CLI auth.
- **1.0.6** — Retired the Tampermonkey userscript; soc-ai is now driven entirely from its web console (`/app`) and the Hunt Console.
- **1.0.5** — Patch: the auto-triage scheduler now fires its first sweep on a
  freshly-booted host (a monotonic-clock sentinel bug), plus Node 24-native CI
  workflow actions.
- **1.0.4** — Slow-stack resilience + detection: wall-clock timeouts on every long path
  (hunts/investigations degrade gracefully to a partial verdict), a malware-label payload
  gate, fast-path domain reputation, inventory-first hunts with correlation + lateral-movement
  recipes, a first-run "not connected" banner, and a settled-verdict Acknowledge/Escalate bar.
- **1.0.3** — Dogfood + detection + resilience release: dataset-agnostic grid discovery,
  behavioral-summary detections (beaconing + DNS tunneling), a docs site, operator
  runbooks, one-click "request more info" on any verdict, and a sweep of resilience /
  performance / flow hardening.
- **1.0.2** — Trust + reliability release: model reasoning visible on every investigation,
  signed decision-record exports, benign synthetic eval scenarios (precision + true-negative
  rate), and a resilient LLM gateway transport with retry/backoff.
- **1.0.1** — The **Hunt Console** and a **backtest harness** land, alongside a full
  correctness / security / performance review that hardened the engine.
- **1.0.0** — First public release: the triage engine and the always-on web console.
