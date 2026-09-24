---
title: Authorized scanner false positives
tags: [scan, recon, false-positive, vulnerability-scanner]
rules:
  - "ET SCAN Nmap Scripting Engine User-Agent Detected"
  - "ET SCAN Behavioral Unusual Port 445 traffic Potential Scan or Infection"
  - "ET SCAN Suspicious inbound to mySQL port 3306"
---

# Authorized scanner false positives

Scan-class alerts are the largest false-positive family in most security operations
centers. The MITRE ATT&CK techniques are **T1046** Network Service Discovery and
**T1595** Active Scanning. Vulnerability scanners, asset-inventory tools and monitoring
systems behave like reconnaissance. Separate sanctioned scanning from unsanctioned
scanning. Use a method that is quick and repeatable. Keep the rule family active.

## Establish the source's identity

**Warning: a workstation with scanner behavior is never a false positive on identity
grounds alone. That pattern is post-compromise discovery.**

1. Look for the source IP on the documented scanner list of your organization. The list
   covers vulnerability management appliances, monitoring pollers and asset discovery
   tools.
2. Cite the list in the verdict if your team keeps it in a runbook or an asset database.
3. Check that the behavior of the source matches its role. An authorized scanner probes
   **many hosts across many ports on a schedule**. The schedule is often nightly or
   weekly, from a fixed IP.
4. Verify that the scan matches the schedule. The authorization does not cover a scan at
   an unusual hour. The authorization does not cover a scan from a new IP.
5. Check the reverse DNS record and the asset ownership. Scanner appliances are normally
   servers in a management subnet. User workstations are not scanner appliances.

## Confirm the scan shape

Pivot on the source over the alert window. Describe the scan with these measures:

- **Breadth**: count the distinct destination hosts and ports. An authorized scan is
  broad and indiscriminate. Attacker discovery is often narrow. A narrow scan touches a
  few high-value ports: 445, 3389, 22, 1433.
- **Follow-through**: an authorized scanner connects, reads a banner and moves to the
  next host. A session that continues past service identification is exploitation.
  Attempted logins, enumerated shares and delivered payloads are exploitation from any
  source.
- **Credentialed scan artifacts**: an authenticated vulnerability scan produces bursts of
  administrative activity from the scanner account. The activity includes Windows
  Management Instrumentation (WMI) calls, SSH logins and registry reads. Verify that the
  scan used the designated scan account.

## Verdict guidance

- **Dismiss** the alert if the source identity, the schedule and the shape all match the
  sanctioned profile. Name the scanner and the schedule in the rationale. The dismissal
  is then auditable.
- **Escalate** the alert if the source is not a known scanner. Escalate if a known
  scanner runs outside its window or from a new address. Escalate if the session
  continues past banner collection.
- Recommend a tuning action if the same sanctioned scanner fires the same rule
  repeatedly. Suppress that rule for that source. A hundred manual dismissals are then
  unnecessary. Read the noisy rule tuning runbook.
