---
title: DNS tunneling and anomaly triage
tags: [dns, tunneling, exfiltration, c2]
rules:
  - "ET MALWARE DNS Query to a Suspicious Long Domain"
  - "ET INFO Observed DNS Query to .top TLD"
---

# DNS tunneling and anomaly triage

DNS tunneling abuses the one protocol that almost every environment lets out. The MITRE
ATT&CK techniques are **T1071.004** Application Layer Protocol: DNS and **T1048**
Exfiltration Over Alternative Protocol. A tunnel encodes data into query names and
answers. The tunnel therefore lives in your resolver logs. Several legitimate products
also encode data in DNS and look like a tunnel. These products include endpoint detection
and response telemetry, antivirus telemetry, some content delivery network health checks
and anti-spam lookups.

## Confirm the tunnel shape

Pivot on the DNS activity of the suspected client for the last 24 h. Group the queries by
registered domain. The registered domain is the zone one level below the top-level
domain.

- **Volume to one zone**. A tunnel produces hundreds to thousands of queries to a single
  registered domain. Each query carries a **unique** subdomain label. A normal domain
  repeats its labels because caching works. A tunnel never repeats a label.
- **Label entropy and length**. An encoded label is long. Labels are often 30 to 63
  characters, and full names approach the ceiling of 253 characters. An encoded label has
  high entropy and mixes characters like base32 or base64. A human-named subdomain is a
  short dictionary word.
- **Record-type mix**. Heavy TXT, NULL or CNAME traffic from an endpoint is anomalous. A
  workstation asks for A and AAAA records most of the time. A flow to one zone that TXT
  records dominate is a strong tunnel indicator.
- **Response entropy**. A tunnel carries payloads downstream in the answers. A flood of
  NXDOMAIN responses with unique names indicates a domain generation algorithm. That
  algorithm needs a different runbook. The malware tries to find its command and control
  server. The malware does not talk through DNS.

## Assess the zone

- Check the age and the reputation of the registered domain. A tunnel typically uses a
  young, cheaply registered domain with wildcard resolution. Query a name that you invent
  under the zone. Wildcard behavior fits tunnel infrastructure if the authoritative server
  resolves the invented name.
- Check the fleet prevalence. Tunnel-like telemetry from a security agent goes to a
  vendor zone. **Every** protected host queries that vendor zone. One host alone that
  talks to the zone is the attacker pattern. Verify the zone against a list of known
  vendor domains before you dismiss the alert on prevalence alone.

## Check the resolver

Confirm that the client uses the *sanctioned* resolver. Queries sent directly to an
external resolver bypass your logging and your controls. Queries sent to a DNS over HTTPS
endpoint bypass them too. The MITRE ATT&CK technique is **T1572** Protocol Tunneling.
Examine a host that changed its resolver recently. Examine it whatever the query content
is.

## Verdict guidance

- **Escalate** a high-volume flow of unique labels to a young zone or a single-host zone.
  Escalate any flow that TXT or NULL records dominate and that no known product explains.
  Estimate the exfiltration volume for the notes of the investigation. Sum the bytes of
  the encoded labels.
- **Dismiss** a vendor telemetry zone. Name the vendor. Record the zone so that a future
  alert carries the context.
- Pivot to malware triage on the client for a storm of NXDOMAIN responses that fits a
  domain generation algorithm. The DNS traffic is a symptom. DNS is not the channel.
