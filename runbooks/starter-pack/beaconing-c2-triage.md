---
title: Beaconing / C2 callback triage
tags: [beacon, c2, command-and-control, malware]
rules:
  - "ET MALWARE Cobalt Strike Beacon Observed"
  - "ET CNC Feodo Tracker Reported CnC Server"
---

# Beaconing / C2 callback triage

Suspected command-and-control (MITRE ATT&CK **T1071** Application Layer
Protocol, **T1573** Encrypted Channel). The core question: is this host
talking to infrastructure an attacker controls, on a schedule that software
chose rather than a human?

## Confirm the periodicity first

A beacon is defined by cadence, not by any single connection. Pull all
connections from the source host to the destination over the last 24 hours
and look at the inter-arrival times:

- **Fixed interval with low jitter** (e.g. every 60s ±5%) is the strongest
  signal. Commodity frameworks default to sleep+jitter timers.
- Human browsing is bursty: clusters of requests, then long silence.
- Watch for interval changes after a reboot — an implant restarting resets
  its timer phase but keeps the interval.

If there are only one or two connections, this is not yet beaconing —
re-check with a longer window before escalating.

## Assess the destination

- Reputation: blocklists, passive DNS, ASN. Newly registered domains and
  hosting ASNs with no business relationship to the org raise the score.
- Rarity: how many *other* hosts in the estate talk to this destination?
  A destination unique to one workstation is far more suspicious than one
  the whole fleet uses (that pattern is usually telemetry or an update CDN).
- Port/protocol mismatch: TLS on a non-standard port, HTTP with an empty or
  generic User-Agent, or raw TCP with small fixed-size payloads.

## Assess the payload shape

Byte counts matter more than content when the channel is encrypted: a
heartbeat beacon sends small, similar-sized requests and receives small
responses; a tasking event shows one anomalously large download. Consistent
tiny uploads with occasional large pulls is the classic check-in/tasking
shape.

## Common benign explanations

Rule out before escalating: NTP and monitoring agents (fixed-interval by
design), antivirus/EDR cloud lookups, software update checks, SaaS client
keepalives (chat, mail sync), and smart devices phoning home. These are
periodic but go to well-known, fleet-wide destinations. Record confirmed
benign destinations as a tag or note so the next analyst doesn't redo the
work.

## Verdict guidance

- **Escalate** when periodicity + rare destination + payload shape agree, or
  when the destination is on a current threat-intel list. Recommend isolating
  the host and capturing PCAP before any remediation that would tip off the
  operator of the implant.
- **Dismiss** when the destination is fleet-common and attributable to a
  known product, and note the product so the detection can be tuned.
- **Stay suspicious** of single-connection alerts to rare destinations:
  mark for re-check rather than closing as FP.
