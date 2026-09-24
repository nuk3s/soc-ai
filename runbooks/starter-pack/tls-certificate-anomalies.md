---
title: TLS and certificate anomaly triage
tags: [tls, ssl, certificate, ja3, encrypted-traffic]
rules:
  - "ET INFO Observed Self Signed SSL Certificate"
  - "ET MALWARE Observed Malicious SSL Cert (Cobalt Strike CnC)"
---

# TLS and certificate anomaly triage

TLS alerts fire on the *metadata* of an encrypted session because the payload is opaque.
The metadata covers certificates, the server name indication (SNI) and fingerprints. That
metadata is rich. Malware authors must make TLS choices too. Their choices differ from
the choices of the commercial web. The MITRE ATT&CK techniques are **T1573.002**
Asymmetric Cryptography and **T1071.001** Web Protocols.

## Read the certificate

- **Issuer**. A self-signed certificate on an *internet* destination is the classic
  indicator of command and control. Almost all legitimate public services use a real
  certificate authority. A self-signed certificate on an *internal* service is endemic
  and usually benign. Appliances and development hosts use self-signed certificates. The
  same certificate observation means a different thing in each direction.
- **Subject and SAN quality**. A default or meaningless subject raises the score. A
  mismatch between the SNI and the certificate names raises the score. A single-host
  subject alternative name (SAN) on supposed content delivery network traffic raises the
  score.
- **Age and lifetime**. A certificate issued *hours* before the first contact fits freshly
  built attack infrastructure. A long validity with issuance from a free certificate
  authority fits the same profile. Flag an *expired* certificate that a client still uses.
  Real browsers refuse an expired certificate. Many custom implants do not validate it.

## Read the connection around the certificate

- **Fingerprint rarity**. Use the JA3 and JA3S hashes of the client hello and the server
  hello where they are available. A TLS client stack seen on exactly one host in the
  network indicates a custom client. The browsers of the fleet share a handful of common
  fingerprints. Match the fingerprint against known-malware lists. Treat a match as a
  hint because fingerprints collide.
- **SNI anomalies**. A modern host with no SNI is an anomaly. An SNI that is a bare IP
  address is an anomaly. Disagreement between the SNI, the certificate and the DNS record
  is an anomaly. That disagreement can indicate domain fronting. The MITRE ATT&CK
  technique is **T1090** Proxy.
- **Behavior**. Combine these checks with the beaconing checks. A destination with a
  self-signed certificate that the host visits every 60 s is a command and control
  channel. The same certificate on a one-time visit can be a misconfigured web host.

## Rule out the benign bulk

Most TLS-anomaly volume comes from 4 sources:

- Internal appliances and development services. They are self-signed by default.
- Security products that inspect TLS. Their resigning certificate authority appears
  everywhere. Learn its issuer string.
- Virtual private network clients.
- Internet-of-things devices with the default certificate of the vendor.

Fleet prevalence is the fastest filter. A certificate seen from 50 hosts is
infrastructure. A certificate seen from one host is a lead.

## Verdict guidance

- **Escalate** a self-signed, young or known-bad certificate on an outbound connection.
  Escalate it if the connection also shows beacon cadence or a rare destination. Add the
  certificate hash and the destination to the investigation for blocking and
  retro-hunting.
- **Dismiss** an internal appliance certificate, an inspection-authority artifact or a
  documented development system. Name the system. Create a scoped tuning rule. Repeated
  dismissals are then unnecessary.
- An *inbound* TLS anomaly needs reconnaissance and exploitation triage. A strange client
  fingerprint that reaches your services is an inbound anomaly. This runbook does not
  cover it.
