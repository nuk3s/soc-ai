---
title: Cryptomining detection triage
tags: [cryptomining, coinminer, stratum, resource-hijacking]
rules:
  - "ET COINMINER Coinhive In-Browser Miner Detected"
  - "ET POLICY Cryptocurrency Miner Checkin"
---

# Cryptomining detection triage

Cryptomining (MITRE ATT&CK **T1496** Resource Hijacking) is low-severity in
impact terms but high-value as a *signal*: a miner on a server means someone
had code execution on that server. Never close a confirmed miner as "just
mining" without asking how it got there.

## Confirm the mining traffic

- **Stratum protocol**: the giveaway is JSON-RPC over a raw TCP socket with
  methods like `login`, `mining.subscribe`, `mining.authorize`, and
  recurring `job`/`submit` messages. Common ports: 3333, 4444, 5555, 14444,
  and anything advertised as "TLS stratum" — but pools listen anywhere, so
  match on the protocol shape, not the port.
- **Connection profile**: one long-lived outbound connection to a pool
  domain (often with `pool`, `mine`, or a coin name in the DNS), reconnecting
  immediately when cut, with small regular submissions upstream.
- **Browser miner** (in-page JavaScript): short-lived, tab-bound, stops when
  the user closes the page. Confirm whether the traffic outlives the
  browsing session — persistent mining after browser close means an
  installed miner, not a drive-by page.

## Establish how it got there

This is the real triage. Check, in order:

1. **What process/host profile is mining?** A user workstation with a
   game-adjacent bundled miner is a different incident than a Linux server
   or a container host mining.
2. **Recent access history on the host**: exposed services (Docker API,
   Kubernetes kubelet, Redis, Jenkins, SSH with weak credentials) are the
   dominant server-miner entry points. Look for exploit-shaped inbound
   traffic or anomalous logins in the days before the first pool
   connection.
3. **Persistence**: cron entries, systemd units, scheduled tasks, or
   re-spawning containers pinned to the miner. Miner operators routinely
   install competitors'-miner killers and re-infection cron jobs — cleanup
   that misses persistence lasts hours.
4. **Fleet scope**: pivot the pool domain/IP and any dropper hash across the
   estate. Server-side mining campaigns hit every host with the same exposed
   service.

## Verdict guidance

- **Escalate** any miner on a server, container platform, or cloud instance
  as a code-execution incident: the recommended actions are isolate,
  identify the entry vector, and close it — killing the miner process alone
  is not remediation. Include the pool destination for blocking.
- **Workstation bundled-adware miners** can be routed to standard endpoint
  cleanup, but verify persistence is removed and note the software that
  bundled it.
- **Dismiss** only when the "miner" is a false match (some rules fire on
  benign WebSocket or game traffic) — confirm by protocol shape above — or
  when it's a sanctioned research/lab host documented by your team.
