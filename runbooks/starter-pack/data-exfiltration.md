---
title: Data exfiltration triage
tags: [exfiltration, data-loss, upload, staging]
rules:
  - "ET POLICY Data POST to an image file (gif)"
  - "ET INFO MEGA file sharing service domain in DNS lookup"
---

# Data exfiltration triage

Exfiltration alerts (MITRE ATT&CK **T1041** Exfiltration Over C2 Channel,
**T1567.002** Exfiltration to Cloud Storage, **T1030** Data Transfer Size
Limits) hinge on one asymmetry: most endpoints are download-heavy. A host
whose **upload** volume rivals or exceeds its downloads is doing something
unusual — the question is whether it's sanctioned.

## Quantify the transfer

Pivot on the source host's outbound flows over the alert window and the
prior 7 days:

- **Total bytes out** per destination, and the up/down ratio. Establish the
  host's own baseline: is this week's upload 10× last week's?
- **Transfer shape**: one large sustained flow (bulk copy), many same-sized
  chunks (rate-limited/chunked exfil, T1030), or a slow constant trickle
  (low-and-slow over C2). Chunking into uniform sizes is deliberate
  behavior — no normal application uploads in exact fixed-size pieces.
- **Timing**: business-hours transfers by interactive users differ from
  03:00 bulk pushes when no one is logged in.

## Assess the destination

- Sanctioned corporate storage (your org's cloud tenant) vs **personal**
  instances of the same product — the domain often differs only in the
  tenant path or subdomain. "It went to a well-known cloud service" is not
  a dismissal; consumer file-sharing services are a top exfil channel.
- Rare destinations: first-seen-for-the-estate upload endpoints, direct-to-
  IP uploads, and residential/VPS ASNs deserve escalation weight.
- Protocol mismatch: FTP/SCP/rsync from hosts that never used them, or
  HTTPS POSTs to a host that isn't a web app the org uses.

## Look for staging behind the transfer

Exfiltration is the last step of a chain (**T1074** Data Staged, **T1560**
Archive Collected Data). On the source host, look for recent creation of
large archives (zip/rar/7z, often password-protected), especially in temp
directories, and access to file shares or databases holding the crown
jewels shortly before the upload. Upload volume ≈ archive size is strong
confirmation.

## Verdict guidance

- **Escalate** unsanctioned-destination transfers with staging evidence, any
  fixed-size-chunk pattern, and uploads following other alerts on the host
  (beaconing, lateral movement — exfil over C2 rides the same channel).
  Recommend blocking the destination and preserving the staged archive
  before it's cleaned up.
- **Dismiss** verified backups (name the product and schedule), OS/app
  telemetry uploads, and corporate-tenant cloud sync — after confirming the
  tenant, not just the product.
- Departing employees copying data to personal storage is a real and common
  case: if the account maps to a leaver, escalate to management/HR channels
  per policy rather than closing as "authorized user activity".
