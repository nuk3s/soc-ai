---
title: Cryptomining detection triage
tags: [cryptomining, coinminer, stratum, resource-hijacking]
rules:
  - "ET COINMINER Coinhive In-Browser Miner Detected"
  - "ET POLICY Cryptocurrency Miner Checkin"
---

# Cryptomining detection triage

Cryptomining has a low severity in impact terms. The MITRE ATT&CK technique is **T1496**
Resource Hijacking. A miner has a high value as evidence. A miner on a server shows that
someone ran code on that server. Always ask how the miner arrived before you close a
confirmed miner.

## Confirm the mining traffic

- **Stratum protocol**. The strongest indicator is JSON-RPC over a raw TCP socket. The
  methods include `login`, `mining.subscribe` and `mining.authorize`. The session repeats
  `job` and `submit` messages. The common ports are 3333, 4444, 5555 and 14444. Some
  pools advertise a "TLS stratum" port. Pools listen on any port, so match on the shape
  of the protocol.
- **Connection profile**. A miner holds one long-lived outbound connection to a pool
  domain. The DNS name often contains `pool`, `mine` or the name of a coin. The miner
  reconnects immediately after a disconnection. It sends small regular submissions
  upstream.
- **Browser miner**. In-page JavaScript mining is short-lived and bound to the tab. It
  stops if the user closes the page. Confirm whether the traffic outlives the browsing
  session. Mining that continues after the browser closes means an installed miner.

## Establish how it got there

This step is the real triage. Check these items in order:

1. **Identify the process and the host profile that mine.** A user workstation with a
   miner bundled in a game is one incident. A Linux server or a container host that mines
   is a different incident.
2. **Review the recent access history of the host.** Exposed services are the main entry
   point for a server miner. These services include the Docker application programming
   interface, the Kubernetes kubelet, Redis, Jenkins and SSH with weak credentials. Look
   for exploit-shaped inbound traffic in the days before the first pool connection. Look
   for anomalous logins in the same period.
3. **Find the persistence.** Check cron entries, systemd units, scheduled tasks and
   containers that respawn with the miner. Miner operators install killers for competing
   miners and cron jobs for re-infection. A cleanup that misses the persistence lasts
   hours.
4. **Measure the fleet scope.** Pivot the pool domain, the pool IP and any dropper hash
   across the network. A server-side mining campaign hits every host with the same
   exposed service.

## Verdict guidance

- **Escalate** any miner on a server, a container platform or a cloud instance. Treat the
  alert as a code-execution incident. Recommend 3 actions: isolate the host, identify the
  entry vector and close the entry vector. A stop of the miner process alone is not
  remediation. Include the pool destination for blocking.
- Route a **workstation miner bundled with adware** to the standard endpoint cleanup.
  Verify that the cleanup removes the persistence. Name the software that bundled the
  miner.
- **Dismiss** the alert only if the miner is a false match. Some rules fire on benign
  WebSocket traffic or game traffic. Confirm a false match with the protocol shape above.
  Dismiss the alert if the host is a sanctioned research host or lab host that your team
  documents.
