# Safety model

> Status: shipped. The analyst-executed write actions, the audit logger and the
> reasoning-trace plumbing are all live. The synth-first path shows reasoning
> only if the analyst model emits a `reasoning_content` field, and that depends
> on the gateway config. The blocklist licenses are below.

## Tool classification

- A read tool auto-executes. soc-ai registers it with `@tool(read_only=True)`.
- A write tool is registered with `@tool(read_only=False)`. The agent never
  executes one. The report *recommends* it, and the analyst executes each one
  explicitly through the actions API at
  `POST /api/v1/investigations/{id}/actions/{index}/execute`. That route is the
  single write path, and it runs through the audited `execute_write_tool` in
  `soc_ai/tools/write_exec.py`.

## Audit log hardening

soc-ai writes every LLM input, every LLM output and every tool invocation to a
date-stamped ES audit index, `soc-ai-audit-YYYY.MM.dd`. That includes the
read tools an MCP client calls through `python -m soc_ai.mcp_server`. Each call
lands as a `tool_call` / `tool_result` pair under a `mcp-*` session id with
`user=mcp`. A grid query or an IOC lookup over stdio is as visible to
`soc-ai audit verify` as one that the agent made. These hardening properties
apply:

- **Tamper-evidence through a hash chain.** Each record carries a monotonic
  `seq`, a `prev_hash` and a `hash`. The `hash` is a SHA-256 over the
  canonicalised record content and the hash of the previous record. Any edit,
  reorder, insertion or deletion of a record breaks the recomputed linkage.
  `soc_ai.audit.verify_chain(records)` recomputes the chain and reports the first
  broken `seq`. `soc_ai.audit.verify_chain_detail` also reports what TYPE of
  break it is. A position that two writers claimed reads differently from a
  record whose content no longer matches its own hash. Read
  [Audit chain breaks](AUDIT-CHAIN.md).

    The hash chain shows that a record changed. It cannot stop the change. A
    privileged ES user can still alter records, and you can detect it.
- **The grid claims each position.** soc-ai writes each
  record with `op_type=create` at a deterministic `_id` that it derives from the
  `seq`. The first writer to reach a position takes it. Any other writer gets a
  version conflict and moves to the next position. Allocation and persistence are
  one atomic operation. That makes the chain safe in three cases. The first is a
  second process, such as a `soc-ai` command that cron runs beside the server.
  The second is a second logger in the same process. The third is a write whose
  acknowledgement never arrived. The in-memory head stays as a cache. soc-ai
  recovers it from the most recent record on startup, so the chain continues
  across restarts.
- **Somebody checks the chain.** A scheduled verification re-runs the chain check
  daily over the last 7 days. `AUDIT_VERIFY_SCHEDULE_ENABLED` controls it, and it
  is on by default. It reports a break to a human in 3 ways: an audit record,
  the notification webhook, and a standing entry on the in-app bell. soc-ai logs
  a verification that could not run, and it raises no alarm for it.
- **Epoch-aware verification.** A restart is a legitimate reason the chain cannot
  be linked all the way back. The `prev_hash` of a genesis record, at `seq=0`, is
  the all-zero hash by construction, so it never links to the epoch that came
  before it. A chain-head recovery bug from 2026-06-24 to 2026-08-16 turned that
  rare case into 134 of them, because it reset the head on every restart. The fix
  landed on 2026-08-17.

    `soc-ai audit verify` and the Diagnostics "Verify audit chain" control check
    each restart boundary as its own epoch. They do not report every boundary
    after the first as tamper. An all-clear that spans more than one epoch shows
    as a distinct state, amber and with no checkmark. It does not read as one
    unbroken chain, because nobody can prove cross-epoch linkage.
- **Fail-closed for mutating writes.** `AUDIT_FAIL_CLOSED=true` is the default.
  With it, soc-ai aborts an action that changes SO state if it cannot write the
  audit record for that action. Those actions are ack, escalate, comment and
  auto-ack. No alert is acknowledged or escalated without an audit trail. The
  audit writes for a read, a triage and an enrichment stay fail-open.

**Deployment recommendation: a least-privilege credential.** The audit index
shares the read and write ES credential of soc-ai. It lives on a cluster that
soc-ai itself can write to and delete from. A compromised soc-ai or a compromised
credential could therefore rewrite history despite the hash chain.

To strengthen the trail, provision a distinct, least-privilege ES credential for
the audit index. Give it the `create`, `create_doc` and `index` privileges
on `soc-ai-audit-*` only, with no `delete` and no `manage`. Point the audit
writer at that credential. Pair it with an append-only or read-only ILM policy
on `soc-ai-audit-*`. A data-stream policy also works. Then nobody can rewrite a
record in place. Put that policy on a separate monitoring cluster that the main
credential of soc-ai cannot reach. The hash chain then gives
tamper-evidence on top of an index that the application cannot edit. That is
defence in depth.

## Out of scope

- Detection mutation tools. The agent can *suggest* rule tuning, and a human
  applies it.
- VirusTotal / AlienVault OTX integrations.
- Auto-resolution of an alert. Auto-creation of a case.

## External-intel egress

This egress is optional and off by default. The hunt agent and the chat agent can
reach a small set of external reputation services. The services are Shodan InternetDB, Shodan host with a paid key,
GreyNoise, and the CIRCL CVE database. They can also reach SearXNG web search and
crawl4ai page-fetch. These calls go to a third party, so they are an explicit
egress surface. An IP address, a domain or a CVE that the agent looks up leaves
your network.

`WEB_SEARCH_ENABLED` and `CRAWL4AI_ENABLED` gate the web search and the crawl,
and both are off by default. The Shodan, GreyNoise and CVE lookups reach public
endpoints if the agent chooses to call them. None of them ever sends an alert
payload. Each one sends only the single indicator under enrichment. Leave them
unused on an air-gapped grid, because the local vendored blocklists and GeoIP
cover the offline path.

## Egress redaction for a cloud model

This redaction is opt-in. By default soc-ai assumes that `ANALYST_MODEL` points
at a local model. It then sends that model the enriched alert context, the
prompts and the tool results verbatim. If you point the analyst model at a cloud
provider, set `ANALYST_CLOUD_REDACTION=true`. The config console can also edit
it live, in section *Agent*.

Each investigation turn, hunt turn and chat turn gets one `EgressGuard` from
`soc_ai/agent/egress_guard.py`. The guard holds a single reversible label map. It
is the same tunnel that the Oracle path uses.

On the outbound side, soc-ai replaces internal IPs, hostnames, usernames, MACs
and internal-domain emails with stable opaque labels such as `IP_01` and
`HOST_02`. The replacement covers everything that crosses the gateway: the
enriched context JSON, every composed prompt and every tool result. A composed
prompt can belong to an investigation, a hunt or a chat. A composed prompt includes the analyst's own
question text. soc-ai wraps each read tool at registration.

On the inbound side, soc-ai restores the tool arguments that the model sends to
their real values before they reach Elasticsearch. An example is an OQL query
that cites `HOST_01`. soc-ai also restores the labels in the model's outputs
before it stores or displays them. Those outputs are the verdicts, the
rationales, the reasoning traces, the hunt reports and the chat replies. The
identifier set is the same *effective* set that the Oracle uses. It is
`ORACLE_INTERNAL_SUFFIXES` and `ORACLE_EXTRA_HOSTS`, together with the
discovered identifiers in the database.

The guard learns a host name from free text. The sources are a UNC path, a logon
name, an account domain, a NetBIOS name and a configured host name. A learned name joins
the learned set only if it looks like a host name. The name has at least 3
characters. It has no path separator, no run of dots and no dot at an end. It
is not a word on a small list of common English words. A name that fails this
rule is labelled where it stands. soc-ai does not write it into other fields,
and the residue sweep does not search for it elsewhere. Before this rule, the
Oracle refused cases on a 2-letter token from an ICMP payload dump. A name from
a structured field, such as `host.name`, always joins the learned set. If the
Oracle residue sweep refuses on a learned name, the refusal reason names the
rule and the field that the name came from. The reason never holds the name.

What redaction does NOT cover:

- **It is best-effort.** It does not fail closed. The Oracle path has an
  independent residue sweep that refuses to transmit, and this path has none.
  An internal FQDN on a public-looking suffix leaves verbatim if you did not list
  the suffix. The Oracle gate carries the same caveat. Configure your suffixes and
  hosts.
- **Verdict quality costs something.** The model reasons over opaque labels, so
  it cannot recognise `dc01` as a domain controller. soc-ai preserves the
  cross-references between labels, so behavioural reasoning still works.
- The Oracle second-opinion path keeps its own independent sanitization pipeline,
  and that pipeline fails closed. This knob does not change it.

Leave the knob off for a local analyst model. Off is the default. Redaction is
pure overhead if nothing leaves your network.

## Blocklist licenses

The `BlocklistDB` of soc-ai consumes public IOC blocklists by default:

| Source | License | Default |
|---|---|---|
| abuse.ch URLhaus / ThreatFox / Feodo Tracker | CC0 | ✅ ON |
| Tor Project exit-node list | Public | ✅ ON |
| Operator-curated `internal_seed.yaml` | n/a | ✅ ON |
| Spamhaus DROP / EDROP | Free for non-commercial use only; commercial use requires a paid license | ⛔ OFF, opt-in |

**To enable Spamhaus** in your deployment:

1. Read the Spamhaus terms at https://www.spamhaus.org/legal/terms/. Confirm that
   your deployment qualifies for non-commercial use, or obtain a commercial
   license.
2. Set in `.env`:

   ```
   BLOCKLIST_SOURCES=urlhaus,threatfox,feodo,tor,internal_seed,spamhaus_drop
   SPAMHAUS_LICENSE_ACKNOWLEDGED=true
   ```

3. Run `soc-ai blocklists refresh`.

Without `SPAMHAUS_LICENSE_ACKNOWLEDGED=true`, the loader logs a WARNING and skips
the source. This path fails open.
