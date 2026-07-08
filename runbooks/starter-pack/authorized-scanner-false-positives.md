---
title: Authorized scanner false positives
tags: [scan, recon, false-positive, vulnerability-scanner]
rules:
  - "ET SCAN Nmap Scripting Engine User-Agent Detected"
  - "ET SCAN Behavioral Unusual Port 445 traffic Potential Scan or Infection"
  - "ET SCAN Suspicious inbound to mySQL port 3306"
---

# Authorized scanner false positives

Scan-class alerts (MITRE ATT&CK **T1046** Network Service Discovery,
**T1595** Active Scanning) are the highest-volume false-positive family in
most SOCs, because legitimate vulnerability scanners, asset-inventory tools,
and monitoring systems behave exactly like reconnaissance. The job here is
to separate *sanctioned* scanning from *unsanctioned* scanning quickly and
repeatably — not to suppress the rule family.

## Establish the source's identity

1. Is the source IP on the org's documented scanner list (vulnerability
   management appliances, monitoring pollers, asset discovery)? If your team
   keeps that list in a runbook or asset DB, cite it in the verdict.
2. Does the source's behavior match its role? An authorized scanner probes
   **many hosts across many ports on a schedule** (often nightly or weekly,
   from a fixed IP). Verify the schedule matches: an "authorized scanner"
   suddenly scanning at an unusual hour, or from a new IP, is not covered by
   the authorization.
3. Reverse DNS / asset ownership: scanner appliances are normally servers in
   a management subnet, not user workstations. **A workstation exhibiting
   scanner behavior is never a false positive on identity grounds alone** —
   that pattern is post-compromise discovery.

## Confirm the scan shape

Pivot on the source over the alert window and characterize:

- **Breadth**: distinct destination hosts and ports touched. Authorized
  scans are broad and indiscriminate; targeted attacker discovery is often
  narrow (a handful of high-value ports: 445, 3389, 22, 1433).
- **Follow-through**: an authorized scanner connects, grabs a banner, and
  moves on. Sessions that continue past service identification — logins
  attempted, shares enumerated, payloads delivered — are exploitation, not
  scanning, regardless of the source.
- **Credentialed scan artifacts**: authenticated vulnerability scans produce
  bursts of admin-looking activity (WMI, SSH logins, registry reads) from the
  scanner account. Verify the account used is the designated scan account.

## Verdict guidance

- **Dismiss** when source identity, schedule, and shape all match the
  sanctioned profile. Say *which* scanner and *which* schedule in the
  rationale so the dismissal is auditable.
- **Escalate** when the source is not a known scanner, when a known scanner
  runs outside its window or from a new address, or when there is any
  follow-through beyond banner grabbing.
- If the same sanctioned scanner keeps firing the same rule, recommend a
  tuning action (suppress that rule for that source) rather than another
  hundred manual dismissals — see the noisy-rule tuning runbook.
