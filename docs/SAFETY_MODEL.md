# Safety model

> Status: shipped. Analyst-executed write actions, audit logger, and reasoning-trace
> plumbing are all live. Reasoning surfacing on the synth-first path depends on the
> analyst model emitting a `reasoning_content` field (gateway-config dependent).
> Blocklist license posture below.

## Tool classification

- Read tools: auto-executed, registered with `@tool(read_only=True)`.
- Write tools: registered with `@tool(read_only=False)`; never executed by the
  agent. The report *recommends* them and the analyst executes each one
  explicitly through the actions API
  (`POST /api/v1/investigations/{id}/actions/{index}/execute`) — the single
  write path, running through the audited `execute_write_tool`
  (`soc_ai/tools/write_exec.py`).

## Audit log hardening

Every LLM I/O and tool invocation is written to a date-stamped ES audit index
(`soc-ai-audit-YYYY.MM.dd`). Two hardening properties apply:

- **Tamper-evidence (hash chain):** each record carries `seq` (monotonic),
  `prev_hash`, and `hash` (SHA-256 over the canonicalised record content plus the
  previous record's hash). Any edit, reorder, insertion, or deletion of a record
  breaks the recomputed linkage. `soc_ai.audit.verify_chain(records)` recomputes
  the chain and reports the first broken `seq`. The chain head is held in memory
  and recovered from the most-recent record on startup, so it continues across
  restarts. The hash chain provides tamper-*evidence*, not tamper-*prevention*:
  it lets you detect that records were altered, but does not stop a privileged ES
  user from altering them.
- **Fail-closed for mutating writes:** with `AUDIT_FAIL_CLOSED=true` (default), an
  SO-state-changing action (ack/escalate/comment/auto-ack) is aborted if its
  audit record cannot be written. No acknowledged or escalated alert without an
  audit trail. Read/triage/enrichment audit writes stay fail-open.

**Deployment recommendation (least-privilege credential):** the audit index
currently shares soc-ai's read/write ES credential and lives on a cluster soc-ai
itself can write to and delete from, so a compromised soc-ai (or its credential)
could rewrite history despite the hash chain. To strengthen the trail, provision a
**distinct, least-privilege ES credential for the audit index** with `create`/
`create_doc`/`index` privileges on `soc-ai-audit-*` only (no `delete`, no
`manage`), and point the audit writer at it. Pair it with an **append-only /
read-only ILM (or data-stream) policy** on `soc-ai-audit-*` (ideally on a
separate monitoring cluster soc-ai's main credential cannot reach) so records
cannot be silently rewritten in place. The hash chain then provides tamper-
evidence on top of an index the application cannot edit, giving defence in depth.

## Out of scope

- Detection mutation tools (the agent may *suggest* rule tuning; a human applies it).
- VirusTotal / AlienVault OTX integrations.
- Auto-resolution of alerts; auto-creation of cases.

### Optional external-intel egress (opt-in, off by default)

The hunt and chat agents can reach a small set of external reputation services
(Shodan InternetDB, Shodan host with a paid key, GreyNoise, and the CIRCL CVE
database) plus SearXNG web search and crawl4ai page-fetch. These make outbound
calls to third parties, so they are an explicit egress surface: an IP / domain /
CVE the agent looks up leaves your network. Web search and crawl are gated behind
`WEB_SEARCH_ENABLED` / `CRAWL4AI_ENABLED` (both off by default); the Shodan /
GreyNoise / CVE lookups hit public endpoints when the agent chooses to call them.
None of them ever send alert payloads, only the single indicator being enriched.
Leave them unused on an air-gapped grid; the local vendored blocklists + GeoIP
cover the offline path.

## Cloud analyst models — egress redaction (opt-in)

By default soc-ai assumes `ANALYST_MODEL` points at a **local** model and sends
it the enriched alert context, prompts, and tool results verbatim. If you point
the analyst model at a cloud provider, set **`ANALYST_CLOUD_REDACTION=true`**
(also editable live in the config console, section *Agent*).

How it works: each investigation / hunt / chat turn gets one
`EgressGuard` (`soc_ai/agent/egress_guard.py`) holding a single reversible
label map — the same tunnel the Oracle path uses. Outbound, internal IPs,
hostnames, usernames, MACs, and internal-domain emails are replaced with
stable opaque labels (`IP_01`, `HOST_02`, …) in everything that crosses the
gateway: the enriched context JSON, every composed prompt (investigation,
hunt, chat, including the analyst's own question text), and every tool result
(each read tool is wrapped at registration). Inbound, tool arguments the model
sends (e.g. an OQL query citing `HOST_01`) are restored to real values before
they hit Elasticsearch, and the model's outputs — verdicts, rationales,
reasoning traces, hunt reports, chat replies — are label-restored before
storage/display. The identifier set is the same *effective* set the Oracle
uses: `ORACLE_INTERNAL_SUFFIXES` / `ORACLE_EXTRA_HOSTS` unioned with the
DB-managed discovered identifiers.

What it does NOT cover:

- **It is best-effort, not fail-closed.** Unlike the Oracle path there is no
  independent residue sweep that refuses to transmit — an internal FQDN on a
  public-looking suffix that you have not enumerated will egress verbatim
  (same caveat as the Oracle gate; configure your suffixes/hosts).
- **Verdict quality costs.** The model reasons over opaque labels — it cannot
  recognise `dc01` as a domain controller. Label cross-references are
  preserved, so behavioural reasoning still works.
- The Oracle second-opinion path keeps its own independent (fail-closed)
  sanitization pipeline; this knob does not change it.

Leave the knob off (the default) for a local analyst model — redaction is pure
overhead when nothing leaves your network.

## Vendored blocklist data — license posture

soc-ai's `BlocklistDB` consumes public IOC blocklists by default:

| Source | License | Default |
|---|---|---|
| abuse.ch URLhaus / ThreatFox / Feodo Tracker | CC0 | ✅ ON |
| Tor Project exit-node list | Public | ✅ ON |
| Operator-curated `internal_seed.yaml` | n/a | ✅ ON |
| Spamhaus DROP / EDROP | Free for **non-commercial** use only; commercial use requires a paid license | ⛔ OFF — opt-in |

**To enable Spamhaus** in your deployment:

1. Read the Spamhaus terms (https://www.spamhaus.org/legal/terms/) and confirm
   your deployment qualifies for non-commercial use, OR obtain a commercial
   license.
2. Set in `.env`:

   ```
   BLOCKLIST_SOURCES=urlhaus,threatfox,feodo,tor,internal_seed,spamhaus_drop
   SPAMHAUS_LICENSE_ACKNOWLEDGED=true
   ```

3. Run `soc-ai blocklists refresh`.

Without `SPAMHAUS_LICENSE_ACKNOWLEDGED=true`, the loader logs a WARNING
and skips the source (fail-open).
