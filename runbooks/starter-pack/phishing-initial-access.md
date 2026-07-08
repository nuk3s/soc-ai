---
title: Phishing-driven initial access triage
tags: [phishing, initial-access, email, credential-theft]
rules:
  - "ET PHISHING Possible Successful Generic Phish"
  - "ET INFO Executable Download from dotted-quad Host"
  - "ET MALWARE Windows executable sent when remote host claims to send an image"
---

# Phishing-driven initial access triage

Phishing (MITRE ATT&CK **T1566.001** Spearphishing Attachment, **T1566.002**
Spearphishing Link) alerts usually fire on the *network consequence* of a
click — a credential-harvesting page visit, a stage-two download — not on
the email itself. Triage works backwards to the lure and forwards to the
impact.

## Reconstruct the click chain

1. From the alert, identify the victim host/user and the first suspicious
   URL or download.
2. Walk the web/proxy/DNS history for that host in the preceding minutes:
   the classic chain is mail client → redirector (URL shortener, legitimate
   file-sharing or form service) → landing page → payload or credential form.
3. Note every domain in the chain. Attackers front their pages with
   reputable services precisely so the first hop looks dismissible.

## Decide which phish this is

- **Credential harvest**: page mimics a login (mail provider, SSO, bank).
  Look for a form POST shortly after page load. A POST means you must assume
  the credentials are gone — a GET-only visit with fast bounce may mean the
  user closed it.
- **Payload delivery**: a download follows the click. Capture filename,
  type, and hash. Executables, script files, ISO/IMG containers, and
  macro-bearing documents from fresh domains are near-certain malicious.
  Pivot the hash across the estate for other victims.

## Assess post-click impact

- Credential case: check the account's authentication activity after the
  click — new source IPs, impossible-travel logins, new MFA registrations,
  and new mail rules (**T1114** / auto-forwarding is the most common
  persistence after mailbox compromise).
- Payload case: watch the victim host for the follow-on beacon (see the
  beaconing runbook), new persistence, or lateral movement. A download with
  no subsequent execution artifacts may have been blocked — verify with the
  endpoint control before dismissing.

## Scope the campaign

One alert is rarely one victim. Pivot on the sender, the landing domain, and
the payload hash across all mail and web telemetry for the same day. List
every user who received the lure and every host that clicked — the case
should carry the full victim list, not the first reporter.

## Verdict guidance

- **Escalate** any confirmed form POST to a harvesting page (recommend
  password reset + session revocation + MFA check for affected accounts) and
  any executed payload (recommend host isolation).
- **Dismiss** when the "phish" is a security-awareness simulation (confirm
  against the simulation provider's domains/schedule) or a user visiting a
  flagged-but-benign marketing redirect with no form interaction and no
  download.
- Borderline click-no-POST cases: close as suspicious with a note to the
  user/helpdesk rather than silently dismissing.
