# Changelog

The full, versioned changelog is maintained in the repository and rendered on GitHub:

[:octicons-arrow-right-24: **CHANGELOG.md on GitHub**](https://github.com/nuk3s/soc-ai/blob/main/CHANGELOG.md)

The format is based on [Keep a Changelog](https://keepachangelog.com/), and the project
follows [Semantic Versioning](https://semver.org/) from 1.0 onward.

## Recent highlights

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
