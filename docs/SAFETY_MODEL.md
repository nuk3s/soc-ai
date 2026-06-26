# Safety model

> Status: shipped. Approval flow, audit logger, and reasoning-trace plumbing are all live.
> Reasoning surfacing on the synth-first path depends on the analyst model emitting a
> `reasoning_content` field (gateway-config dependent). Blocklist license posture below.

## Tool classification

- Read tools: auto-approved, registered with `@tool(read_only=True)`.
- Write tools: explicit user approval per call, registered with `@tool(read_only=False)`.

## Audit log hardening

Every LLM I/O and tool invocation is written to a date-stamped ES audit index
(`soc-ai-audit-YYYY.MM.dd`). Two hardening properties apply:

- **Tamper-evidence (hash chain).** Each record carries `seq` (monotonic),
  `prev_hash`, and `hash` (SHA-256 over the canonicalised record content plus the
  previous record's hash). Any edit, reorder, insertion, or deletion of a record
  breaks the recomputed linkage. `soc_ai.audit.verify_chain(records)` recomputes
  the chain and reports the first broken `seq`. The chain head is held in memory
  and recovered from the most-recent record on startup, so it continues across
  restarts. The hash chain provides tamper-*evidence*, not tamper-*prevention* —
  it lets you detect that records were altered, but does not stop a privileged ES
  user from altering them.
- **Fail-closed for mutating writes.** With `AUDIT_FAIL_CLOSED=true` (default), an
  SO-state-changing action (ack/escalate/comment/auto-ack) is aborted if its
  audit record cannot be written — no acknowledged or escalated alert without an
  audit trail. Read/triage/enrichment audit writes stay fail-open.

**Deployment recommendation (least-privilege credential).** The audit index
currently shares soc-ai's read/write ES credential and lives on a cluster soc-ai
itself can write to and delete from — so a compromised soc-ai (or its credential)
could rewrite history despite the hash chain. To strengthen the trail, provision a
**distinct, least-privilege ES credential for the audit index** with `create`/
`create_doc`/`index` privileges on `soc-ai-audit-*` only (no `delete`, no
`manage`), and point the audit writer at it. Pair it with an **append-only /
read-only ILM (or data-stream) policy** on `soc-ai-audit-*` — ideally on a
separate monitoring cluster soc-ai's main credential cannot reach — so records
cannot be silently rewritten in place. The hash chain then provides tamper-
evidence on top of an index the application cannot edit, giving defence in depth.

## Out of scope

- Detection mutation tools.
- External threat intel APIs (VT, OTX, Shodan, GreyNoise).
- Auto-resolution of alerts; auto-creation of cases.

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
