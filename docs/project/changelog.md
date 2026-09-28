# Changelog

The full, versioned changelog is maintained in the repository and rendered on GitHub:

[:octicons-arrow-right-24: **CHANGELOG.md on GitHub**](https://github.com/nuk3s/soc-ai/blob/main/CHANGELOG.md)

The format is based on [Keep a Changelog](https://keepachangelog.com/), and the project
follows [Semantic Versioning](https://semver.org/) from 1.0 onward.

## Recent highlights

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
- **1.2.6**: About page (running version, repo/license links, sidebar version line) with an opt-in, off-by-default GitHub update check that follows the zero-egress discipline; Config page rebuilt master-detail (~36 screens → ~2) with settings search in-page and in the command palette, an Apply bar that names each staged change as a clickable chip, and identifier lists that filter, page, and bulk-edit.
- **1.2.5**: Visual refresh of the alert workspace (design-token theming, a filter bar that morphs into bulk actions instead of shifting the table, toast notifications with a one-click clear, and freshness markers that flag a stalled poll), a code-review remediation across the 1.2.x line, and a batch of dogfood fixes. Also stops DNS-SD/SRV service records from polluting the auto-detected internal-domain inventory.
- **1.2.4**: Dogfood patch: the Hunt Console says plainly when scheduled hunts are paused, the triage pipeline retries a transient grid blip instead of dropping the investigation, the nightly regression alarm no longer pages on one flipped verdict at small sample sizes, and the config console groups each integration's switch with its key.
- **1.2.3**: Per-alert verdict inheritance now respects the configured inherit window (webui_inherit_window_days): the alerts feed no longer inherits a rule's stale standing verdict onto fresh alerts.
- **1.2.2**: Security and correctness patch from a full code review of 1.2.1: evidence-gate integrity, oracle-redaction leak fixes, opt-in/bound auto-acknowledge, SSRF and denial-of-service caps, audit and auth hygiene, and supply-chain pinning.
- **1.2.1**: Accuracy and honesty patch: pipeline errors now record *why* each
  model retry failed (and the schema tolerates the stringified-JSON wobble that
  caused most of them), hunts gained telemetry-first latitude (the corroboration
  gate credits Zeek evidence found through broad queries, and generic sweeps no
  longer re-triage the alert stream), plus a documentation refresh and the
  public roadmap.
- **1.2.0**: The dogfood release: a full analyst shift on the live deployment
  produced fourteen findings, and this release fixed all of them — notifications,
  entity search, a maintenance panel, pipeline-error visibility with one-click
  dismiss, group acknowledge, deep re-run, and the verdict-quality eval now
  schedulable straight from the dashboard.
- **1.1.1**: Re-hunt and multi-select on the Hunts page, plus a delta-review
  hardening pass.
- **1.1.0**: The measurement release: nightly quality trend with a regression
  alarm, highlighted redaction previews, and a real runbooks workspace so the
  agent grounds verdicts in your own procedures.
- **1.0.8**: Trust, workflow, and threat-hunting: fallback verdicts are labeled
  as such, hunt findings must cite evidence, assignment states and keyboard
  triage speed up the queue, and hunts gain scheduling.
- **1.0.7**: Fixes from the first week of production triage: SO write-token
  expiry, export auth, re-hunt caps, and CLI auth.
- **1.0.6**: Retired the Tampermonkey userscript; soc-ai is now driven entirely from its web console (`/app`) and the Hunt Console.
- **1.0.5**: Patch: the auto-triage scheduler now fires its first sweep on a
  freshly-booted host (a monotonic-clock sentinel bug), plus Node 24-native CI
  workflow actions.
- **1.0.4**: Slow-stack resilience + detection: wall-clock timeouts on every long path
  (hunts/investigations degrade gracefully to a partial verdict), a malware-label payload
  gate, fast-path domain reputation, inventory-first hunts with correlation + lateral-movement
  recipes, a first-run "not connected" banner, and a settled-verdict Acknowledge/Escalate bar.
- **1.0.3**: Dogfood + detection + resilience release: dataset-agnostic grid discovery,
  behavioral-summary detections (beaconing + DNS tunneling), a docs site, operator
  runbooks, one-click "request more info" on any verdict, and a sweep of resilience /
  performance / flow hardening.
- **1.0.2**: Trust + reliability release: model reasoning visible on every investigation,
  signed decision-record exports, benign synthetic eval scenarios (precision + true-negative
  rate), and a resilient LLM gateway transport with retry/backoff.
- **1.0.1**: The **Hunt Console** and a **backtest harness** land, alongside a full
  correctness / security / performance review that hardened the engine.
- **1.0.0**: First public release: the triage engine and the always-on web console.
