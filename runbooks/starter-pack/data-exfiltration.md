---
title: Data exfiltration triage
tags: [exfiltration, data-loss, upload, staging]
rules:
  - "ET POLICY Data POST to an image file (gif)"
  - "ET INFO MEGA file sharing service domain in DNS lookup"
---

# Data exfiltration triage

Exfiltration alerts depend on one asymmetry. Most endpoints download much more than they
upload. The MITRE ATT&CK techniques are **T1041** Exfiltration Over C2 Channel,
**T1567.002** Exfiltration to Cloud Storage and **T1030** Data Transfer Size Limits. A
host with an **upload** volume close to or above its download volume does something
unusual. Decide whether the transfer is sanctioned.

## Quantify the transfer

Pivot on the outbound flows of the source host. Cover the alert window and the 7 days
before it.

- **Total bytes out** per destination, and the ratio of upload to download. Establish the
  baseline of the host. Ask whether the upload of this week is 10 times the upload of
  last week.
- **Transfer shape**. One large sustained flow is a bulk copy. Many chunks of the same
  size are a rate-limited or chunked transfer under **T1030**. A slow constant trickle is
  a low-and-slow transfer over the command and control channel. A transfer split into
  uniform sizes is deliberate behavior. No normal application uploads in exact fixed-size
  pieces.
- **Timing**. A transfer during business hours by an interactive user differs from a bulk
  push at 03:00. Check whether anyone was logged in at the time of the transfer.

## Assess the destination

- Compare the sanctioned corporate storage of your organization against a **personal**
  instance of the same product. The domain often differs only in the tenant path or the
  subdomain. A well-known cloud service is not a reason to dismiss the alert. Consumer
  file-sharing services are a top exfiltration channel.
- Give escalation weight to a rare destination. An upload endpoint that the network sees
  for the first time is rare. An upload sent directly to an IP address is rare. A
  residential autonomous system number (ASN) or a virtual private server ASN is rare.
- Look for a protocol mismatch. FTP, SCP or rsync from a host that never used them is a
  mismatch. An HTTPS POST to a host that is not a web application of the organization is
  a mismatch.

## Look for staging behind the transfer

Exfiltration is the last step of a chain. The MITRE ATT&CK techniques are **T1074** Data
Staged and **T1560** Archive Collected Data. On the source host, look for recent large
archives in zip, rar or 7z format. These archives often carry a password. Look in the
temporary directories first. Look for access to file shares or databases that hold
high-value data shortly before the upload. An upload volume close to the archive size is
strong confirmation.

## Verdict guidance

- **Escalate** a transfer to an unsanctioned destination with staging evidence. Escalate
  any pattern of fixed-size chunks. Escalate an upload that follows another alert on the
  host, such as a beacon or lateral movement. Exfiltration over the command and control
  channel uses that same channel. Recommend a block of the destination. Recommend
  preservation of the staged archive before a cleanup removes it.
- **Dismiss** a verified backup. Name the product and the schedule. Dismiss operating
  system telemetry and application telemetry uploads. Dismiss a synchronization to the
  corporate cloud tenant after you confirm the tenant. Confirmation of the product alone
  is not enough.
- A departing employee who copies data to personal storage is a real and common case.
  Check whether the account belongs to a leaver. Escalate to the management channel and
  the human resources channel under your policy. Do not close the alert as authorized
  user activity.
