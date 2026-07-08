---
title: DNS tunneling and anomaly triage
tags: [dns, tunneling, exfiltration, c2]
rules:
  - "ET MALWARE DNS Query to a Suspicious Long Domain"
  - "ET INFO Observed DNS Query to .top TLD"
---

# DNS tunneling and anomaly triage

DNS tunneling (MITRE ATT&CK **T1071.004** Application Layer Protocol: DNS,
**T1048** Exfiltration Over Alternative Protocol) abuses the one protocol
almost every environment lets out. Data is encoded into query names and
answers, so the tunnel lives in your resolver logs. The confounder: several
legitimate products (EDR/antivirus telemetry, some CDN health checks,
anti-spam lookups) also encode data in DNS and look tunnel-like.

## Confirm the tunnel shape

Pivot on the suspected client's DNS activity for the last 24 hours, grouped
by registered domain (the zone one level below the TLD):

- **Volume to one zone**: a tunnel produces hundreds-to-thousands of queries
  to a single registered domain, each with a **unique** subdomain label.
  Normal domains repeat (caching works); tunnels never repeat.
- **Label entropy and length**: encoded labels are long (often 30–63 chars
  per label, names near the 253-char ceiling) and high-entropy
  (base32/base64-ish character mixes). Human-named subdomains are short
  dictionary words.
- **Record-type mix**: heavy TXT, NULL, or CNAME traffic from an endpoint
  is anomalous — workstations overwhelmingly ask for A/AAAA. TXT-dominant
  flows to one zone are a strong tunnel indicator.
- **Response entropy**: tunnels carry payloads downstream in answers;
  NXDOMAIN floods with unique names suggest DGA rather than tunneling
  (different playbook — malware trying to *find* C2, not talk through DNS).

## Assess the zone

- Age and reputation of the registered domain: tunnels typically use young,
  cheaply registered domains with wildcard resolution. Query a name you
  invent under the zone — if the authoritative server resolves *anything*,
  that wildcard behavior fits tunneling infrastructure.
- Fleet prevalence: security agents tunnel-like telemetry goes to vendor
  zones queried by **every** protected host. One host alone talking to the
  zone is the attacker pattern; verify against a known-vendor-domain list
  before dismissing on prevalence alone.

## Check the escape hatch

Also confirm the client is using the *sanctioned* resolver. Queries sent
directly to external resolvers (or DoH endpoints, **T1572** Protocol
Tunneling) bypass your logging and controls — a host that switched resolvers
recently deserves scrutiny regardless of query content.

## Verdict guidance

- **Escalate** unique-label high-volume flows to a young or single-host zone,
  and anything TXT/NULL-dominant that isn't attributable to a known product.
  Estimate exfil volume (sum of encoded label bytes) for the case notes.
- **Dismiss** vendor telemetry zones (name the vendor), and record them so
  future alerts auto-contextualize.
- For DGA-shaped NXDOMAIN storms, pivot to malware triage on the client —
  the DNS is a symptom, not the channel.
