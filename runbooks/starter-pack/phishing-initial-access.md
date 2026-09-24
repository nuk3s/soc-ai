---
title: Phishing-driven initial access triage
tags: [phishing, initial-access, email, credential-theft]
rules:
  - "ET PHISHING Possible Successful Generic Phish"
  - "ET INFO Executable Download from dotted-quad Host"
  - "ET MALWARE Windows executable sent when remote host claims to send an image"
---

# Phishing-driven initial access triage

Phishing alerts usually fire on the *network consequence* of a click. The MITRE ATT&CK
techniques are **T1566.001** Spearphishing Attachment and **T1566.002** Spearphishing
Link. The consequence is a visit to a credential-harvesting page or a stage-two download.
The alert rarely fires on the email itself. Work backwards to the lure. Work forwards to
the impact.

## Reconstruct the click chain

1. Identify the victim host and the victim user from the alert.
2. Identify the first suspicious URL or download.
3. Walk the web, proxy and DNS history of that host for the preceding minutes. The
   classic chain runs from the mail client to a redirector. The redirector leads to a
   landing page. The landing page delivers a payload or a credential form. A redirector is
   a URL shortener, a legitimate file-sharing service or a form service.
4. Record every domain in the chain. Attackers put reputable services in front of their
   pages. The first hop then looks dismissible.

## Decide which phish this is

- **Credential harvest**. The page imitates a login page for a mail provider, a single
  sign-on service or a bank. Look for a form POST shortly after the page load. Assume
  that the credentials are gone if you find a POST. A visit with only a GET and a fast
  bounce can mean that the user closed the page.
- **Payload delivery**. A download follows the click. Record the filename, the type and
  the hash. Executables, script files, ISO and IMG containers, and macro-bearing
  documents from fresh domains are near-certain malicious. Pivot the hash across the
  network to find other victims.

## Assess the post-click impact

- **Credential harvest**. Check the authentication activity of the account after the
  click. Look for new source IP addresses, impossible-travel logins, new multi-factor
  authentication registrations and new mail rules. A new auto-forwarding rule is the most
  common persistence after a mailbox compromise. The MITRE ATT&CK technique is **T1114** Email
  Collection.
- **Payload delivery**. Watch the victim host for the follow-on beacon. Read the
  beaconing runbook. Watch for new persistence and for lateral movement. A download with
  no later execution artifacts can mean a block. Verify the block with the endpoint
  control before you dismiss the alert.

## Scope the campaign

One alert is rarely one victim. Pivot on the sender, the landing domain and the payload
hash. Cover all mail and web telemetry for the same day. List every user who received the
lure. List every host that clicked. The investigation carries the full victim list.

## Verdict guidance

- **Escalate** any confirmed form POST to a harvesting page. Recommend a password reset,
  a session revocation and a multi-factor authentication check for the affected accounts.
  Escalate any payload that ran. Recommend isolation of the host.
- **Dismiss** the alert if the phish is a security-awareness simulation. Confirm the
  simulation against the domains and the schedule of the provider. Dismiss the alert if a
  user visited a flagged but benign marketing redirect with no form interaction and no
  download.
- Close a borderline click with no POST as suspicious. Add a note to the user or the
  helpdesk. Do not dismiss the alert silently.
