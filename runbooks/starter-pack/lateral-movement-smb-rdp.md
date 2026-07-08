---
title: Lateral movement triage (SMB / PsExec / RDP)
tags: [lateral-movement, smb, rdp, psexec, admin-shares]
rules:
  - "ET POLICY SMB2 NT Create AndX Request For an Executable File In A Temp Directory"
  - "ET POLICY RDP connection confirmed"
  - "ET INFO PsExec service created"
---

# Lateral movement triage (SMB / PsExec / RDP)

Lateral movement alerts (MITRE ATT&CK **T1021.001** RDP, **T1021.002**
SMB/Windows Admin Shares, **T1570** Lateral Tool Transfer, **T1569.002**
Service Execution) are hard because administrators and attackers use the
*same tools*. The discriminator is almost never the mechanism — it's the
who/where/when/what-next.

## Establish the actor context

- **Account**: which account authenticated for the SMB session or RDP logon?
  Is it an admin account expected to touch this target? A *user* workstation
  account authenticating to another workstation's admin share is abnormal in
  almost every environment.
- **Source**: is the source a management host/jump box (expected) or an
  ordinary workstation/server that has no business administering others?
  Workstation-to-workstation admin traffic is the classic worm/hands-on-
  keyboard pattern.
- **Time**: inside the admin's working pattern, or 03:00 on a weekend?
  Correlate with the admin's other activity — real admins generate parallel
  context (ticketing, VPN session, other managed hosts); an attacker using
  stolen credentials usually doesn't.

## Read the mechanism for intent

- **PsExec-style service execution**: look for a service creation on the
  target with a random or copied name and an executable dropped to ADMIN$
  just before. Legitimate software deployment does the same thing but from
  *deployment servers* with *consistent* service names, on many hosts at
  once. One-off random-name service from a workstation source = escalate.
- **SMB executable/script writes**: an .exe/.dll/.ps1/.bat written to an
  admin share (C$, ADMIN$) outside a deployment window is tool transfer.
  Capture the filename and hash; pivot the hash across the estate.
- **RDP**: a single interactive session is thin evidence alone. Chained RDP
  (A→B then B→C within minutes), first-ever source→target pairs, and RDP
  from a host that just received a suspicious file are the escalating
  shapes.

## Scope before verdict

Lateral movement is by definition ≥2 hosts. Pivot on the source and the
account: what *else* did they touch in ±2 hours? A source fanning out to
many targets (especially sequential IP order, or many failures then one
success) is discovery + movement, not administration. Build the host list —
the case needs the graph, not one edge.

## Verdict guidance

- **Escalate** random-name service creation, tool transfer to admin shares,
  workstation-sourced admin sessions, and any movement chain following
  another alert on the source (phish, beacon, credential access). Recommend
  isolating the source and reviewing the account's credentials.
- **Dismiss** documented deployment/patching activity (name the product and
  the deployment server), scheduled backup or inventory jobs, and help-desk
  remote support matching its normal source and hours.
- When unsure, check the target's next 30 minutes: new outbound connections,
  new services, or credential dumping artifacts settle the question.
