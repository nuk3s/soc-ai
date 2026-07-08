---
title: Brute force and password spray triage
tags: [brute-force, password-spray, credential-access, authentication]
rules:
  - "ET SCAN SSH BruteForce Tool with fake PUTTY version"
  - "ET INFO SMB2 NT Create AndX Request For an Executable File"
  - "ET SCAN RDP connection attempt from suspicious source"
---

# Brute force and password spray triage

Credential-access alerts (MITRE ATT&CK **T1110.001** Password Guessing,
**T1110.003** Password Spraying) come in two shapes with different triage
paths: **vertical** (many passwords against one account) and **horizontal /
spray** (one or two passwords against many accounts, deliberately staying
under lockout thresholds).

## Characterize the attempt pattern

Pivot on the source over a 6–24h window and count:

- **Distinct target accounts** and **attempts per account**. Many accounts ×
  few attempts = spray. One account × many attempts = brute force.
- **Timing**: sprays are often slow (one round per 30–60 min) to evade
  lockout policy. Don't let a low per-hour rate read as benign.
- **Account name quality**: attempts against *valid* usernames indicate the
  attacker already enumerated accounts (check for prior LDAP/SMB enumeration
  from the same source); attempts against generic names (admin, test,
  backup) look like an untargeted internet-wide campaign.

## The one question that decides severity

**Did any attempt succeed?** Correlate the failure burst with authentication
successes from the same source, for any targeted account, during and shortly
after the window. A failure storm followed by a success and then *silence*
from that source is the classic compromise signature — the attacker got in
and stopped guessing.

If a success is found, this is no longer a brute-force alert; treat it as an
account compromise: escalate, recommend credential reset and session
invalidation, and pivot to what that account did next (new logins, mail
rules, lateral movement).

## Source and target context

- External source, internet-facing service (VPN portal, mail, RDP, SSH):
  expected background noise at low volume, but sprays against valid
  usernames deserve escalation even with zero successes — they indicate
  targeting and a username list.
- **Internal source**: much higher concern. An internal host guessing
  passwords is either a misconfigured service (stale credentials in a
  scheduled task or connection pool — usually one account, regular interval,
  same failure code forever) or a compromised host performing credential
  access. The stale-credential case fails with the *same* account at the
  *same* interval; the attacker case rotates accounts.
- Service accounts and admin accounts as targets raise severity a tier.

## Verdict guidance

- **Dismiss** the stale-credential pattern (one internal source, one
  account, metronomic failures, no successes) and name the offending
  host/service so it gets fixed rather than re-triaged weekly.
- **Escalate** any success following a failure burst, any spray with valid
  usernames, and any internal source rotating through accounts.
- Recommend compensating checks in the rationale: lockout policy status for
  targeted accounts and MFA coverage for the service in question.
