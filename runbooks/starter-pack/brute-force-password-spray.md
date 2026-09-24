---
title: Brute force and password spray triage
tags: [brute-force, password-spray, credential-access, authentication]
rules:
  - "ET SCAN SSH BruteForce Tool with fake PUTTY version"
  - "ET INFO SMB2 NT Create AndX Request For an Executable File"
  - "ET SCAN RDP connection attempt from suspicious source"
---

# Brute force and password spray triage

Credential-access alerts come in two shapes. Each shape has its own triage path. The
MITRE ATT&CK techniques are **T1110.001** Password Guessing and **T1110.003** Password
Spraying. A **vertical** attempt tries many passwords against one account. A
**horizontal** attempt, also called a spray, tries 1 or 2 passwords against many
accounts. A spray stays below the lockout threshold on purpose.

## Characterize the attempt pattern

Pivot on the source over a window of 6 h to 24 h. Count these items:

- **Distinct target accounts** and **attempts per account**. Many accounts with few
  attempts each is a spray. One account with many attempts is a brute force attempt.
- **Timing**. A spray is often slow. It runs one round every 30 min to 60 min to evade
  the lockout policy. Do not read a low hourly rate as benign.
- **Account name quality**. Attempts against *valid* usernames show that the attacker
  enumerated the accounts first. Look for earlier Lightweight Directory Access Protocol
  (LDAP) or SMB enumeration from the same source. Attempts against generic names such as
  admin, test and backup indicate an untargeted internet-wide campaign.

## The one question that decides severity

**Did any attempt succeed?** Correlate the burst of failures with authentication
successes from the same source. Cover every targeted account during the window and
shortly after it. A failure storm, then a success, then silence from that source indicates a
compromise. The attacker gets access and stops the guessing.

Treat the alert as an account compromise if you find a success. The alert is no longer a
brute force alert. Escalate it. Recommend a credential reset and a session invalidation.
Pivot to the later activity of that account. Look for new logins, new mail rules and
lateral movement.

## Source and target context

- An external source against an internet-facing service is expected background noise at
  low volume. These services include the virtual private network portal, mail, Remote
  Desktop Protocol (RDP) and SSH. Escalate a spray against valid usernames even if no
  attempt succeeds. That spray shows targeting and a username list.
- An **internal source** is a much higher concern. An internal host that guesses
  passwords has two explanations. The first explanation is a misconfigured service with
  stale credentials in a scheduled task or a connection pool. That case uses the *same*
  account at the *same* interval and returns the same failure code every time. The second
  explanation is a compromised host that performs credential access. That case rotates
  through accounts.
- A service account or an admin account as the target raises the severity one tier.

## Verdict guidance

- **Dismiss** the stale-credential pattern. That pattern has one internal source, one
  account, failures at a regular interval and no successes. Name the host and the service
  so that the team repairs them. The alert then stops returning every week.
- **Escalate** a success that follows a burst of failures. Escalate a spray against valid
  usernames. Escalate an internal source that rotates through accounts.
- Recommend compensating checks in the rationale. Ask for the lockout policy status of
  the targeted accounts. Ask for the multi-factor authentication coverage of the service.
