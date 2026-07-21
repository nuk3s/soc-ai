# Changelog

The full, versioned changelog is maintained in the repository and rendered on GitHub:

[:octicons-arrow-right-24: **CHANGELOG.md on GitHub**](https://github.com/nuk3s/soc-ai/blob/main/CHANGELOG.md)

The format is based on [Keep a Changelog](https://keepachangelog.com/), and the project
follows [Semantic Versioning](https://semver.org/) from 1.0 onward.

## Recent highlights

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
