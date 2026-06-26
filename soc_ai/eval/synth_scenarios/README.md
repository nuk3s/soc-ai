# Synthetic-TP scenario catalogue

Hand-authored YAML scenarios that fabricate ECS-shaped Security Onion alerts
(plus supporting Zeek correlation events) for injection into the eval pipeline.

This directory contains the **data**. The loader, OpenSearch ingestion, and
escalation precision/recall scoring live in `soc_ai/eval/`.

## Why these exist

A quiet lab grid produces ~0 true-positive alerts by design (no live malicious
activity). Across several benign batches (130 alerts) the system emitted 0 `true_positive`
verdicts. We can't distinguish "system works correctly" from "system has an
architectural TP ceiling" without positive-class signal. These scenarios
provide that signal.

## Tiering

- **Easy (`e*`)** — multiple corroborating signals: IOC + obvious rule +
  asset-as-internal. Recall on this tier should approach 100%; if it doesn't,
  the pipeline is broken.
- **Medium (`m*`)** — behavior + weak IOC, requires cross-log correlation
  across Suricata + Zeek logs.
- **Hard (`h*`)** — pure behavioral, no IOC, requires Zeek-only reasoning.
  Floor for what counts as the system "having real signal-detection."

## File naming

`{tier-letter}{number}-{shortname}.yaml`, e.g. `e1-emotet-feodo-c2.yaml`.

## YAML schema (v1)

```yaml
id: e1-emotet-feodo-c2         # str: matches filename, stable identifier
name: "Emotet/Feodo C2 callback"
version: 1                      # int: bump when ground_truth changes
tier: easy                      # enum: easy | medium | hard
story: |
  Multi-line human-readable narrative.

attack:                         # list[str]: MITRE ATT&CK technique IDs
  - T1071.001
  - T1573

sigma_refs: []                  # list[str]: optional Sigma rule IDs

ground_truth:
  verdict: true_positive        # enum: true_positive | false_positive | needs_more_info
  confidence_min: 0.70          # float: floor for the verdict to count as agreement
  required_citation_kinds:      # list[str]: at least one of each must appear
    - blocklist_hit
    - typed_path
  expected_actions:             # list[dict]: action-shape assertions
    - kind: escalate
    - kind: isolate
      target_field: source.ip
  expected_field_reconciliation: false  # bool: must reconciliation be non-null?

events:                         # list[dict]: ECS events to render
  - index: logs-synth-suricata-alert    # logical index — loader maps to OpenSearch
    time_offset_seconds: 0              # int: relative to scenario_run_time
    is_triage_target: true              # bool: exactly one event has this True
    fields:                              # ECS-shaped doc fields
      "@timestamp": "{{ run_time }}"     # loader-substituted
      event.dataset: suricata.alert
      # ...full ECS payload here

rubric_notes: |                 # str: free-text for human reviewers
  Why this is the verdict; what signals the system MUST cite.
```

## Loader contract

The loader will:
1. Load each YAML, validate against the v1 schema.
2. Render each `events[].fields` map with placeholders (`{{ run_time }}`,
   `{{ community_id(...) }}`, scenario-scoped IP variables) substituted.
3. Ingest into `logs-synth-*` OpenSearch indices, where `*` matches the
   `index` logical name (e.g., `logs-synth-suricata-alert`).
4. Tag every ingested doc with `synth.scenario_id`, `synth.scenario_version`,
   `synth.expected_verdict`, `synth.attack_technique` for unambiguous join.
5. Make the triage-target alert ID known to the eval runner so
   `validate-batch --synth-set <name>` can sample it.

## Synth pollution kill-switch (mandatory)

Prod entrypoints MUST query with `NOT _exists_:synth.scenario_id` baked
into the OQL prefix. `validate-batch` with synth-set MUST refuse if any
non-`logs-synth-*` index returns docs with `synth.*` fields. The eval
runner MUST refuse to start if synth-tagged docs exist in prod indices.

## Authoring guidance

- Each scenario should have **1 triage-target alert** + 2-5 supporting
  Zeek/HTTP/DNS/SSL events that the triage system would find via
  `community_id` pivots.
- For Hard tier: the alert itself can be low-severity (Informational,
  Minor) — the verdict comes from the Zeek correlation, not the Suricata
  signature alone. This is the whole point.
- Use real ET Open / ET Pro rule names from the catalogue when known;
  mark `rule.signature` (SID) as illustrative if the exact SID is uncertain.
- Time offsets: alert at `t=0`. Supporting events typically `t=-30s` to
  `t=+10s`. Keep within a few minutes window — Zeek-Suricata correlation
  windows are usually short.
- IPs: internal in `10.0.0.0/24` (RFC1918). External destinations
  should be illustrative (e.g., `185.220.101.7` for Tor) — the loader can
  randomize if needed.

## Scoring

After a batch run, scores aggregate per `synth.scenario_id`:
- `escalation_precision = TP_count / (TP_count + FP_count)` over the synth stratum.
- `escalation_recall = TP_count / (TP_count + FN_count)` over the synth stratum.
- A verdict counts as "correct" iff `actual_verdict == ground_truth.verdict`
  AND `actual_confidence >= ground_truth.confidence_min` AND all
  `required_citation_kinds` appear in the report's citations.
- Wilson 95% CI reported alongside both metrics.

## Catalogue index

| File | Tier | Verdict | ATT&CK | Notes |
|---|---|---|---|---|
| `e1-emotet-feodo-c2.yaml` | easy | true_positive | T1071.001, T1573 | Feodo IP + JA3 + ET TROJAN |
| `e2-urlhaus-pe-delivery.yaml` | easy | true_positive | T1105 | URLhaus URL + PE MIME |
| `e3-tor-exit-ssh.yaml` | easy | true_positive | T1133 | Tor exit list + auth_success |
| `m1-cobalt-strike-beacon.yaml` | medium | true_positive | T1071.001, T1102 | JA3 + beacon jitter |
| `m2-dns-tunnel-exfil.yaml` | medium | true_positive | T1048.003 | Entropy + volume |
| `m3-quasar-rat-self-signed.yaml` | medium | true_positive | T1573.002 | Cert CN + port 4782 |
| `h1-kerberoasting.yaml` | hard | true_positive | T1558.003 | RC4 + SPN fan-out |
| `h2-psexec-smb-lateral.yaml` | hard | true_positive | T1021.002, T1543.003 | ADMIN$ + svcctl DCE-RPC |
| `h3-low-slow-exfil-r2.yaml` | hard | true_positive | T1041, T1567.002 | Conn-ratio + first-seen FQDN |
