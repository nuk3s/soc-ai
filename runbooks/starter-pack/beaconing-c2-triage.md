---
title: Beaconing / C2 callback triage
tags: [beacon, c2, command-and-control, malware]
rules:
  - "ET MALWARE Cobalt Strike Beacon Observed"
  - "ET CNC Feodo Tracker Reported CnC Server"
---

# Beaconing / C2 callback triage

This runbook covers suspected command and control (C2) traffic. The MITRE ATT&CK
techniques are **T1071** Application Layer Protocol and **T1573** Encrypted Channel.
Answer two questions. Does the host talk to infrastructure that an attacker controls?
Does software choose the schedule of the connections? A person makes an irregular
schedule.

## Confirm the periodicity first

The cadence defines a beacon. A single connection does not define a beacon. Collect all
connections from the source host to the destination over the last 24 h. Measure the
inter-arrival times. Read the times against these patterns:

- A **fixed interval with low jitter** is the strongest indicator. For example, the host
  connects every 60 s with a jitter of 5 %. Commodity frameworks use sleep timers and
  jitter timers by default.
- Human browsing is irregular. It produces clusters of requests and then long silence.
- Look for a change of interval after a reboot. An implant that restarts resets the phase
  of its timer. The implant keeps the interval.

The traffic is not yet a beacon if the host made only 1 or 2 connections. Repeat the
check with a longer window before you escalate.

## Assess the destination

- Check the reputation of the destination. Use blocklists, passive DNS and the autonomous
  system number (ASN). A newly registered domain raises the score. A hosting ASN with no
  business relationship to the organization raises the score.
- Check the rarity of the destination. Count the other hosts in the network that talk to
  it. A destination unique to one workstation is more suspicious than a fleet-wide
  destination. A fleet-wide destination is usually telemetry or an update content
  delivery network (CDN).
- Look for a port mismatch or a protocol mismatch. TLS on a non-standard port is a
  mismatch. HTTP with an empty or generic User-Agent is a mismatch. Raw TCP with small
  fixed-size payloads is a mismatch.

## Assess the payload shape

Byte counts matter more than content if the channel is encrypted. A heartbeat beacon
sends small requests of similar size. It receives small responses. A tasking event shows
one download that is much larger than the others. Small consistent uploads with
occasional large downloads are the check-in and tasking shape.

## Common benign explanations

Rule out these sources before you escalate:

- Network Time Protocol (NTP) clients and monitoring agents. They use a fixed interval by
  design.
- Antivirus and endpoint detection and response (EDR) cloud lookups.
- Software update checks.
- Keepalive traffic from software-as-a-service clients such as chat and mail sync.
- Smart devices that connect to the servers of their vendor.

These sources are periodic. They reach well-known destinations that the whole fleet uses.
Record a confirmed benign destination as a tag or a note. The next analyst then does not
repeat the work.

## Verdict guidance

- **Escalate** if the periodicity, the rare destination and the payload shape agree.
  Escalate if the destination is on a current threat-intelligence list. Recommend
  isolation of the host. Remediation can alert the operator of the implant. Recommend a
  packet capture before any remediation.
- **Dismiss** if the destination is fleet-common and belongs to a known product. Name the
  product so that the team can tune the detection.
- Mark a single-connection alert to a rare destination for a re-check. Stay suspicious of
  that alert. Do not close it as a false positive.
