# Synthetic-scenario catalogue

Hand-authored YAML scenarios that fabricate ECS-shaped Security Onion alerts
(plus supporting Zeek correlation events) for injection into the eval pipeline.
The catalogue carries both **true-positive** (`e*`/`m*`/`h*`) and **benign**
(`b*`, `verdict: false_positive`) scenarios so the synth stratum can report
escalation **precision** and **recall**, not recall alone.

**25 scenarios: 17 attacks + 8 benign twins.** The catalogue was widened from
9+4 on 2026-08-26 because the metric could not outrun its own noise: two runs
the same day read 5/9 then 6/9 strict recall with no code change between them,
individual scenarios swinging ±0.10 confidence purely on which investigative
path the model took. At n=9 one scenario is 11% of recall, so a single swing
moved the headline by 11 points and the observed delta sat inside the noise
band. Perfect recall on 9 attacks buys a 95% Wilson lower bound of 0.70; on 17
the same result claims 0.82. Widening is also the answer to the 2026-05-29
strategic review's standing warning that a small fixed set invites
Goodharting — diversity of attack CLASS matters more here than count.

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
- **Benign (`b*`)** — realistic but *alarming* benign traffic
  (`ground_truth.verdict: false_positive`). These are the negative class:
  a good analyst dispositions them as NOT an incident. They exist so the
  synth stratum can report **escalation precision** — the skeptic test
  ("did the system call an obvious FP malicious?"). Escalating a `b*`
  scenario to `true_positive` is scored as a false positive and drops
  precision; correctly closing it as benign is a true negative. `b*`
  scenarios span all three difficulty tiers (see `tier:`) and are
  deliberately paired with their TP twins (`b1`↔`m1` beacon, `b3`↔`h2` SMB
  lateral, `b4`↔`m2` DNS tunnel, `b5`↔`h6` WMI execution, `b6`↔`h3` bulk
  egress, `b7`↔`m6` DoH, `b8`↔`h4` directory replication) so the disposition
  turns on evidence, not shape.

  The strongest pairs put the SAME artifact on the wire on both sides and
  force the discrimination onto something else. `b8`/`h4` are byte-for-byte
  the same `DRSGetNCChanges` call — `t_dcerpc_histogram` flags both, because
  it matches operation names against a fixed dangerous set and has no notion
  of who is entitled to call them — so only the source's ROLE separates them.
  `b7`/`m6` are both measured by `t_beacon_profile` against a globally
  routable destination, so the sweep separates them on the statistic it
  actually computes (cv 1.89 vs 0.030), not on address class. A benign twin
  the instrument skips proves nothing about the instrument.

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
- **Exception — behaviors a measurement tool must SEE.** When a scenario's
  hunt story is a statistical pattern (beacon cadence, DNS entropy volume),
  plant enough **raw** rows to clear the measuring tool's actual thresholds,
  derived from the tool's code, not guessed. A pre-aggregated summary doc
  alone is invisible to a tool that aggregates raw events: `t_beacon_profile`
  needs >= 8 raw `zeek.conn` rows per src->dst pair with inter-arrival
  cv <= 0.15 to call a pair "periodic" — which is also what the real attack
  produces (a ~60s beacon over 30 minutes IS dozens of connections). See
  `m1-cobalt-strike-beacon.yaml` for the pattern (YAML anchors keep the
  repetition readable) and its rubric_notes for why this is fidelity, not
  tuning-to-pass.
- For Hard tier: the alert itself can be low-severity (Informational,
  Minor) — the verdict comes from the Zeek correlation, not the Suricata
  signature alone. This is the whole point.
- Use real ET Open / ET Pro rule names from the catalogue when known;
  mark `rule.signature` (SID) as illustrative if the exact SID is uncertain.
- Time offsets: alert at `t=0`. Supporting events typically `t=-30s` to
  `t=+10s`. Keep within a few minutes window — Zeek-Suricata correlation
  windows are usually short.
- IPs: internal in `10.0.0.0/24` (RFC1918). External destinations default to
  RFC 5737 documentation space (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`) and RFC 2606 names (`.example`).
- **Address CLASS decides tool visibility.** `t_beacon_profile` and
  `t_first_seen` drop non-globally-routable destinations — server-side by CIDR
  and again client-side through `is_internal_ip`, which treats RFC 5737
  documentation ranges as internal. A scenario whose detection path is either
  sweep is INVISIBLE with a documentation address, however cleanly it renders:
  the same class of defect as m1's pre-aggregated beacon. Those scenarios use a
  globally routable destination, and every one is listed with its reason in
  `ROUTABLE_ADDRESS_REASONS` (`tests/test_synth_catalogue.py`), which fails on
  any that isn't. Scenarios that do not depend on those sweeps use
  documentation space.

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
| `e4-password-spray-vpn.yaml` | easy | true_positive | T1110.003, T1078 | 104 usernames x 3 passwords, then one 302 + a 240 MB session |
| `e5-webshell-dmz-server.yaml` | easy | true_positive | T1505.003, T1059.004 | text/x-php into the webroot, POSTs to the new path, server dials out |
| `m1-cobalt-strike-beacon.yaml` | medium | true_positive | T1071.001, T1102 | JA3 + beacon jitter (31 raw conn rows) |
| `m2-dns-tunnel-exfil.yaml` | medium | true_positive | T1048.003 | Entropy + volume |
| `m3-quasar-rat-self-signed.yaml` | medium | true_positive | T1573.002 | Cert CN + port 4782 |
| `m4-lsass-dump-smb-transfer.yaml` | medium | true_positive | T1003.001, T1570 | procdump64.exe staged, then a 45 MB lsass.DMP back over SMB |
| `m5-cryptomining-stratum-pool.yaml` | medium | true_positive | T1496, T1571 | Stratum `mining.subscribe` payload + pool FQDN + 25 raw conn rows (cv 0.053) |
| `m6-doh-c2-channel.yaml` | medium | true_positive | T1071.004, T1572 | Plaintext DNS fell to zero; Go-client DoH beacon, 11 raw rows (cv 0.030) |
| `h1-kerberoasting.yaml` | hard | true_positive | T1558.003 | RC4 + SPN fan-out |
| `h2-psexec-smb-lateral.yaml` | hard | true_positive | T1021.002, T1543.003 | ADMIN$ + svcctl DCE-RPC |
| `h3-low-slow-exfil-r2.yaml` | hard | true_positive | T1041, T1567.002 | Conn-ratio + first-seen FQDN |
| `h4-dcsync-replication.yaml` | hard | true_positive | T1003.006, T1078.002 | DRSGetNCChanges from a WORKSTATION (replication twin of b8) |
| `h5-ransomware-staging.yaml` | hard | true_positive | T1083, T1074.002, T1486 | 1,843 files / 6 shares / 9 min, then one 3.2 GB archive written back |
| `h6-wmi-remote-exec-cradle.yaml` | hard | true_positive | T1047, T1059.001 | WMI ExecMethod, then the TARGET fetches a .ps1 (WMI twin of b5) |
| `b1-cdn-update-beacon.yaml` | easy | false_positive | — | Benign updater poll — periodic HTTPS, stock JA3, no blocklist (beacon twin of m1) |
| `b2-authorized-vuln-scanner.yaml` | medium | false_positive | — | Authorized OpenVAS scan — SQLi/traversal probes, scanner fan-out + UA |
| `b3-rmm-admin-lateral.yaml` | hard | false_positive | — | Sanctioned RMM patch push — signed ScreenConnect MSI + service create (lateral twin of h2) |
| `b4-av-dns-reputation.yaml` | medium | false_positive | — | AV cloud file-reputation DNS lookups — A-only qtype, fixed-length hex qnames, 3-value answer space, fleet-wide (tunnel twin of m2) |
| `b5-sanctioned-wmi-inventory.yaml` | hard | false_positive | — | Hourly SCCM inventory — same ExecMethod as h6, 41 targets, 412 days, zero novel egress downstream |
| `b6-backup-scheduled-transfer.yaml` | medium | false_positive | — | 41 GB nightly backup — 361/365 nights, 604-day-old SNI, 92 hosts, no resolver bypass (exfil twin of h3) |
| `b7-browser-doh.yaml` | medium | false_positive | — | Chrome secure-DNS — plaintext DNS continues, bursty cadence (cv 1.89) (DoH twin of m6) |
| `b8-dc-replication-partner.yaml` | hard | false_positive | — | Real DC-to-DC replication — identical DRSGetNCChanges, machine account, 803 days, bidirectional (DCSync twin of h4) |

## Known instrument gaps

Recorded here rather than silently carried, because a scenario that no tool
can surface reports a product failure forever (see the authoring guidance
above on behaviours a measurement tool must SEE).

- **`m2-dns-tunnel-exfil` and `b4-av-dns-reputation` are invisible to
  `t_dns_entropy_scan`.** Both encode the tunnel/lookup volume as a
  pre-aggregated `zeek.dns_summary` document plus ONE raw `zeek.dns` row. The
  sweep aggregates raw qnames and applies a `min_queries` noise floor
  (default 50) per registrable parent before a parent counts as scanned at
  all, so both parents are dropped and `parents_scanned` comes back 0. This is
  the same defect class m1 shipped with, on a different tool: the single-alert
  triage path still works (the summary document is a valid pivot), but neither
  scenario measures anything on the hunt path, and no scenario in the
  catalogue currently exercises the DNS analytic. The fix is the m1 fix —
  plant enough raw `zeek.dns` rows to clear the tool's ACTUAL thresholds
  (>= 50 queries under one parent, plus `entropy_mean >= 3.5` with either
  >= 500 subdomain-bearing queries or >= 200 unique subdomains, or
  `entropy_mean >= 4.2` on its own), derived from `soc_ai/tools/analytics.py`
  rather than guessed. Left for the owner of those two scenarios rather than
  folded into the 2026-08-26 widening, which added no scenario in that family.
