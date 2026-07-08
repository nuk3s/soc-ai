---
title: TLS and certificate anomaly triage
tags: [tls, ssl, certificate, ja3, encrypted-traffic]
rules:
  - "ET INFO Observed Self Signed SSL Certificate"
  - "ET MALWARE Observed Malicious SSL Cert (Cobalt Strike CnC)"
---

# TLS and certificate anomaly triage

TLS alerts fire on the *metadata* of encrypted sessions — certificates,
SNI, fingerprints — because the payload is opaque. That metadata is rich:
malware authors have to make TLS choices too (MITRE ATT&CK **T1573.002**
Asymmetric Cryptography, **T1071.001** Web Protocols), and their choices
differ from the commercial web's.

## Read the certificate

- **Issuer**: self-signed on an *internet* destination is the classic C2
  tell — virtually all legitimate public services use a real CA. Note that
  self-signed on *internal* services (appliances, dev boxes) is endemic and
  usually benign; the same certificate observation means different things by
  direction.
- **Subject/SAN quality**: default or gibberish subjects, mismatches between
  SNI and certificate names, and single-host SANs on supposed CDN traffic
  all raise the score.
- **Age and lifetime**: certificates issued *hours* before first contact,
  with long validity and free-CA issuance, fit freshly stood-up attack
  infrastructure. Also flag *expired* certificates that clients keep
  talking to — real browsers refuse; custom implants often don't validate.

## Read the connection around the certificate

- **Fingerprint rarity** (JA3/JA3S or equivalent client/server hello
  hashes, where available): a TLS client stack seen on exactly one host in
  the estate — while the fleet's browsers share a handful of common
  fingerprints — indicates a custom client. Match known-malware fingerprint
  lists but treat them as hints; fingerprints collide.
- **SNI anomalies**: missing SNI from a modern host, SNI that is a bare IP,
  or SNI/certificate/DNS disagreement (possible domain fronting, **T1090**
  Proxy).
- **Behavior**: combine with the beaconing checks — a self-signed cert
  destination visited every 60 seconds is a C2 call; the same cert on a
  one-time visit might be a misconfigured web host.

## Rule out the benign bulk

Most TLS-anomaly volume is: internal appliances and dev services
(self-signed by default), security products doing TLS inspection (their
resigning CA appears everywhere — learn its issuer string), VPN clients,
and IoT devices with vendor default certs. Fleet prevalence is the fastest
filter: a certificate seen from fifty hosts is infrastructure; from one
host, it's a lead.

## Verdict guidance

- **Escalate** self-signed/young/known-bad certificates on outbound
  connections that also show beacon cadence or rare-destination character.
  Include the certificate hash and destination in the case for blocking and
  retro-hunting.
- **Dismiss** internal appliance certs, inspection-CA artifacts, and
  documented dev systems — name the system, and prefer a scoped tuning rule
  over repeated dismissals.
- An *inbound* TLS anomaly (strange client fingerprint hitting your
  services) is reconnaissance/exploitation triage, not this runbook.
