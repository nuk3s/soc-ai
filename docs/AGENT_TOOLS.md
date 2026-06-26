# What the soc-ai agent can actually do

This is the complete capability surface of the triage agent: the tools it can
call, the enrichments applied to every alert before the agent runs, and the
guardrails.

> **Trust boundary:** every **read** tool is exposed read-only. Every **write**
> tool (anything that changes Security Onion state) is gated behind an explicit
> human **Approve/Reject** in the UI — the agent can *recommend* a write but
> never executes one on its own. See `docs/SAFETY_MODEL.md`.

## Read tools (no approval needed)

| Tool | What it does | Backing system |
|------|--------------|----------------|
| `query_events` | Run a **validated OQL** query against the SO events index (field-whitelisted; pipes/aggregations supported). General-purpose pivot. | Elasticsearch events index |
| `query_zeek_logs` | Pivot into Zeek/connection logs by `network.community_id` to see the underlying flow (duration, bytes, conn state). | Elasticsearch (Zeek datasets) |
| `query_cases` | Search existing SOC cases by free-text query (has this been seen/escalated before?). | SO cases index |
| `query_detections` | Search SOC detection rules by free-text query (what does this rule actually look for?). | SO detections index |
| `get_playbooks` | Pull response playbooks, optionally scoped to a given alert. | SO playbooks index |
| `lookup_runbook` | Retrieve internal runbook guidance (RAG). **Stub in v1** — wired in v1.1. | Qdrant (RAG) |
| `enrich_ip` | Enrich an IP locally: vendored blocklist hits, GeoIP/ASN (MaxMind), cloud-prefix tag, internal-vs-external classification (`INTERNAL_CIDRS`), + optional MISP. Internal IPs short-circuit the external-only lookups. | Vendored blocklists / MaxMind / MISP |
| `enrich_domain` | Enrich a domain via local blocklist lookup + optional MISP. | Vendored blocklists / MISP |
| `enrich_hash` | Enrich a file hash via local blocklist lookup + optional MISP. | Vendored blocklists / MISP |
| `get_pcap` / `t_get_pcap` | Fetch + decode the raw packets for a bidirectional flow (five-tuples, SNI, DNS qnames, HTTP hosts, inter-arrival beacon stats). SSHes into the SO sensor's Suricata pcap-log ring and runs a BPF-filtered tcpdump. **Heavier than Elastic** — used only when packet/protocol confirmation is the deciding evidence (C2 beacon, exfil, kerberoast, ET MALWARE/EXPLOIT rules). **Disabled by default** (`PCAP_ENABLED=false`); requires provisioning the sensor SSH key. | SSH + Suricata `/nsm/suripcap` |
| `web_search` / `t_web_search` | Search a self-hosted **SearXNG** instance to research an **external** indicator — domain reputation, what a host/service is, known-abuse reports — so a verdict rests on outside evidence, not a guess. **Privacy-guarded:** the query goes to public engines via SearXNG, so it must contain only external indicators; a query referencing an internal IP is refused. **Disabled by default** (`WEB_SEARCH_ENABLED=false`); needs `SEARXNG_URL` (and SearXNG's JSON API enabled). Configurable in the admin config console. | SearXNG |
| `crawl_page` / `t_crawl_page` | Deep-read the full content of an **external** web page via a self-hosted **crawl4ai** instance — used *after* `web_search` to read a promising result (a reputation/abuse/threat-intel page) in full instead of a snippet. Returns the page's readable markdown + title. **SSRF-guarded:** fetches server-side, so internal IPs/hosts/localhost are refused. **Disabled by default** (`CRAWL4AI_ENABLED=false`); needs `CRAWL4AI_URL`. Configurable in the admin config console. | crawl4ai |

> **Not a callable tool:** `get_alert_context` (fan-out across the 5 typed
> pivots — community_id flow, host, user, process, file) is **not** registered
> for the agent to call. It runs deterministically in the **prefetch** stage and
> its result is embedded directly in the agent's prompt, so the agent never has
> to (and cannot accidentally skip pulling) the alert picture. See the prefetch
> enrichments below.

## Write tools (require human approval in the UI)

| Tool | What it does |
|------|--------------|
| `ack_alert` | Acknowledge a SOC alert (optional comment). |
| `escalate_to_case` | Create a SOC case from an alert (title + description required). |
| `add_case_comment` | Append a comment to an existing SOC case. |

## Enrichments applied to every alert (before the agent runs)

These run locally in the **prefetch** stage — no LLM, no runtime egress — and
their results are handed to the agent as part of the alert context:

- **Blocklist match** — vendored threat feeds: URLhaus, ThreatFox, Feodo Tracker,
  Tor exit nodes (+ optional internal seed list). Flags src/dst IPs, domains, hashes.
- **GeoIP + ASN** — MaxMind lookup on external IPs (country, ASN, org).
- **Cloud-prefix tagging** — marks IPs belonging to known cloud providers.
- **Internal-CIDR classification** — labels each endpoint internal vs external
  using `INTERNAL_CIDRS`.
- **MISP IOC match** — if a MISP instance is configured (`MISP_URL`), indicators
  are checked against it.

The UI surfaces these on the alert context / investigation timeline so an analyst
can see exactly which enrichments fired.

## What the agent CANNOT do today (known gaps)

Several of these are on the v1.15 reliability track:

- **PCAP retrieval is disabled by default.** The `get_pcap` / `t_get_pcap` tool
  is wired but gated behind `PCAP_ENABLED=true` + a provisioned SSH key
  (`SO_SSH_KEY`). When disabled the tool returns a descriptive error dict without
  any network I/O. Once enabled the agent can fetch and decode the Suricata
  pcap-log ring buffer for bidirectional flows (SNI, DNS, HTTP hosts,
  inter-arrival timing, five-tuple stats).
- **No active host/network actions** beyond the three SO write tools (no isolate,
  no block, no firewall change).
- **`lookup_runbook` is a stub** in v1 (RAG lands in v1.1).
- Read tools run against whatever indices the deployment's index-pattern settings
  point at; off-pattern data is invisible to the agent.
